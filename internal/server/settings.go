package server

import (
	"fmt"
	"sort"
	"strings"

	"trove/internal/api"
	"trove/internal/auth"
	"trove/internal/config"
	"trove/internal/safe"
	"trove/internal/store"
	"trove/internal/validate"
)

// ruleSet returns the current submission rules. They are replaced as a
// whole when the owner changes the settings, so readers never see a
// half-updated rule set.
func (e *Engine) ruleSet() *validate.Rules { return e.rules.Load() }

// limitFiles is the current most-files-per-proposal limit.
func (e *Engine) limitFiles() int { return int(e.maxFiles.Load()) }

// Settings returns the folders and extensions currently in force.
func (e *Engine) Settings() api.Settings {
	e.mu.Lock()
	defer e.mu.Unlock()
	return api.Settings{
		AllowedDirs:       append([]string(nil), e.cfg.Validation.AllowedDirs...),
		AllowedExtensions: append([]string(nil), e.cfg.Validation.AllowedExtensions...),
		MaxFiles:          e.limitFiles(),
	}
}

func cleanList(in []string, trimSlash bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if trimSlash {
			s = strings.Trim(s, "/")
		}
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// UpdateSettings replaces the allowed folders and extensions. With dryRun
// it only validates and reports the conflicts with the existing KB and the
// open proposals (the Warnings field), without changing anything. Only the
// approver may do it. The change is validated, written to the audit log
// (fail closed: nothing changes if that fails), saved to
// data_dir/settings.json and then applied to the running rules.
func (e *Engine) UpdateSettings(a auth.Actor, req api.Settings, dryRun bool) (api.Settings, error) {
	if a.Role != auth.RoleApprover {
		return api.Settings{}, e.deny(a, "settings", "", "only the approver can change the settings")
	}
	dirs := cleanList(req.AllowedDirs, true)
	exts := cleanList(req.AllowedExtensions, false)
	if len(dirs) == 0 {
		return api.Settings{}, newErr(KindInvalid, "at least one folder is required")
	}
	if len(exts) == 0 {
		return api.Settings{}, newErr(KindInvalid, "at least one extension is required (for example .md)")
	}
	maxFiles := req.MaxFiles
	if maxFiles == 0 {
		maxFiles = e.limitFiles()
	}
	if maxFiles < 1 || maxFiles > config.MaxFilesCeiling {
		return api.Settings{}, newErr(KindInvalid, "max files must be between 1 and %d", config.MaxFilesCeiling)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	cand := e.cfg.Validation
	cand.AllowedDirs, cand.AllowedExtensions = dirs, exts
	lim := e.cfg.Limits
	lim.MaxFiles = maxFiles
	rs, err := validate.New(cand, lim)
	if err != nil {
		return api.Settings{}, newErr(KindInvalid, "%s", safe.Line(err.Error(), 300))
	}
	warnings := e.settingsWarnings(dirs, exts, maxFiles)
	if dryRun {
		return api.Settings{AllowedDirs: dirs, AllowedExtensions: exts, MaxFiles: maxFiles, Warnings: warnings}, nil
	}
	detail := fmt.Sprintf("dirs=%s exts=%s max_files=%d (was dirs=%s exts=%s max_files=%d)",
		strings.Join(dirs, ","), strings.Join(exts, ","), maxFiles,
		strings.Join(e.cfg.Validation.AllowedDirs, ","), strings.Join(e.cfg.Validation.AllowedExtensions, ","), e.limitFiles())
	if err := e.mustLog(a, "settings", "", "ok", safe.Line(detail, 900)); err != nil {
		return api.Settings{}, newErr(KindInternal, "audit log: %v", err)
	}
	if err := config.SaveSettings(e.cfg.DataDir, config.Settings{AllowedDirs: dirs, AllowedExtensions: exts, MaxFiles: maxFiles}); err != nil {
		e.logEvent(a, "settings", "", "failed", safe.Line(err.Error(), 300))
		return api.Settings{}, newErr(KindInternal, "saving settings: %v", err)
	}
	e.cfg.Validation = cand
	e.rules.Store(rs)
	e.maxFiles.Store(int64(maxFiles))
	return api.Settings{AllowedDirs: dirs, AllowedExtensions: exts, MaxFiles: maxFiles, Warnings: warnings}, nil
}

const maxSettingsWarnings = 20

func topDir(p string) string {
	if i := strings.IndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return ""
}

func extOf(p string) string {
	base := p[strings.LastIndexByte(p, '/')+1:]
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		return base[i:]
	}
	return ""
}

// settingsWarnings compares the new rules with the current KB tree and the
// open proposals. It is advisory: nothing here blocks a save. The caller
// holds e.mu.
func (e *Engine) settingsWarnings(dirs, exts []string, maxFiles int) []string {
	inDirs, inExts := map[string]bool{}, map[string]bool{}
	for _, d := range dirs {
		inDirs[d] = true
	}
	for _, x := range exts {
		inExts[x] = true
	}
	var out []string
	ctx, cancel := gitCtx()
	defer cancel()
	folders := map[string]int{}
	extFiles := map[string][]string{}
	if head, err := e.repo.Head(ctx); err == nil && head != "" {
		if tree, err := e.tree(ctx, head); err == nil {
			for p := range tree {
				if d := topDir(p); d != "" {
					folders[d]++
				}
				if x := extOf(p); x != "" && !inExts[x] {
					extFiles[x] = append(extFiles[x], p)
				}
			}
		}
	}
	names := make([]string, 0, len(folders))
	for d := range folders {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, d := range names {
		if !inDirs[d] {
			out = append(out, fmt.Sprintf("Folder %q has %d file(s) in the KB but is not in the allowed list: proposals can no longer change them. If you renamed it, keep the old name until the files are moved.", d, folders[d]))
		}
	}
	// Case collisions are checked against the folders that really exist and
	// against the other names of the new list, not against the old list that
	// this save replaces.
	for _, d := range dirs {
		for _, other := range append(append([]string(nil), names...), dirs...) {
			if other != d && strings.EqualFold(other, d) {
				out = append(out, fmt.Sprintf("Folder %q differs from %q only in letter case: they collide on Windows and macOS.", d, other))
				break
			}
		}
	}
	exNames := make([]string, 0, len(extFiles))
	for x := range extFiles {
		exNames = append(exNames, x)
	}
	sort.Strings(exNames)
	for _, x := range exNames {
		files := extFiles[x]
		sort.Strings(files)
		out = append(out, fmt.Sprintf("%d file(s) with extension %s exist in the KB (for example %s) but %s is not allowed: proposals can no longer change them.", len(files), x, files[0], x))
	}
	ids := make([]string, 0, len(e.props))
	for id := range e.props {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := e.props[id]
		if p.State != store.StatePending && p.State != store.StateDraft {
			continue
		}
		bad := map[string]bool{}
		for _, c := range p.Changes {
			if d := topDir(c.Path); d != "" && !inDirs[d] {
				bad[d] = true
			} else if x := extOf(c.Path); x != "" && !inExts[x] {
				bad[x] = true
			}
		}
		if len(p.Changes) > maxFiles {
			out = append(out, fmt.Sprintf("Proposal %s (%s, %s) changes %d file(s), more than the new limit of %d: it cannot be approved.", id, p.Agent, p.State, len(p.Changes), maxFiles))
		}
		if len(bad) > 0 {
			var list []string
			for k := range bad {
				list = append(list, k)
			}
			sort.Strings(list)
			out = append(out, fmt.Sprintf("Proposal %s (%s, %s) touches %s, which would no longer be allowed: it cannot be approved.", id, p.Agent, p.State, strings.Join(list, ", ")))
		}
	}
	if len(out) > maxSettingsWarnings {
		more := len(out) - maxSettingsWarnings
		out = append(out[:maxSettingsWarnings], fmt.Sprintf("... and %d more", more))
	}
	for i := range out {
		out[i] = safe.Line(out[i], 400)
	}
	return out
}
