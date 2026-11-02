package server

import (
	"fmt"
	"sort"
	"strings"

	"trove/internal/api"
	"trove/internal/auth"
	"trove/internal/config"
	"trove/internal/gitrepo"
	"trove/internal/safe"
	"trove/internal/store"
	"trove/internal/validate"
)

// RenameFolder renames a top-level folder of the knowledge base: every file
// below it moves in one commit, and the allowed folder list follows (the old
// name is replaced by the new one). It is an owner action, not a proposal:
// only the approver may do it, it is written to the audit log first (fail
// closed) and it never merges into an existing folder. With dryRun nothing
// changes and the response lists what would happen and the warnings.
func (e *Engine) RenameFolder(a auth.Actor, req api.RenameReq, dryRun bool) (api.RenameResp, error) {
	if a.Role != auth.RoleApprover {
		return api.RenameResp{}, e.deny(a, "folder-rename", "", "only the approver can rename a folder")
	}
	from := strings.Trim(strings.TrimSpace(req.From), "/")
	to := strings.Trim(strings.TrimSpace(req.To), "/")
	if from == "" || to == "" {
		return api.RenameResp{}, newErr(KindInvalid, "both the current and the new folder name are required")
	}
	if strings.Contains(from, "/") || strings.Contains(to, "/") {
		return api.RenameResp{}, newErr(KindInvalid, "only top-level folders can be renamed (no \"/\" in the names)")
	}
	if from == to {
		return api.RenameResp{}, newErr(KindInvalid, "the new name is the same as the current one")
	}
	if err := validate.CheckPathSyntax(to); err != nil {
		return api.RenameResp{}, newErr(KindInvalid, "new name: %s", safe.Line(err.Error(), 200))
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	ctx, cancel := gitCtx()
	defer cancel()
	head, err := e.repo.Head(ctx)
	if err != nil {
		return api.RenameResp{}, newErr(KindInternal, "%v", err)
	}
	if head == "" {
		return api.RenameResp{}, newErr(KindInvalid, "the knowledge base is empty")
	}
	tree, err := e.tree(ctx, head)
	if err != nil {
		return api.RenameResp{}, newErr(KindInternal, "%v", err)
	}

	prefix := from + "/"
	toPrefix := to + "/"
	idx := validate.NewPathIndex()
	var moved []string
	for p, ent := range tree {
		if strings.HasPrefix(p, prefix) {
			if !ent.IsRegular() {
				return api.RenameResp{}, newErr(KindInvalid, "%q is not a regular file, refusing to move it", safe.Line(p, 120))
			}
			moved = append(moved, p)
			continue
		}
		if p == to || strings.HasPrefix(p, toPrefix) {
			return api.RenameResp{}, newErr(KindConflict, "the folder %q already exists: merging folders is not supported", to)
		}
		idx.Add(p)
	}
	if len(moved) == 0 {
		return api.RenameResp{}, newErr(KindNotFound, "there is no folder %q in the knowledge base", from)
	}
	sort.Strings(moved)
	newPath := func(p string) string { return toPrefix + p[len(prefix):] }
	for _, p := range moved {
		np := newPath(p)
		if c := idx.Conflict(np); c != "" {
			return api.RenameResp{}, newErr(KindConflict, "%s: %s", safe.Line(np, 120), safe.Line(c, 200))
		}
		idx.Add(np)
	}

	// The allowed list follows the rename: old name out, new name in.
	dirs := make([]string, 0, len(e.cfg.Validation.AllowedDirs)+1)
	wasListed := false
	for _, d := range e.cfg.Validation.AllowedDirs {
		if d == from {
			wasListed = true
			continue
		}
		dirs = append(dirs, d)
	}
	dirs = append(dirs, to)
	dirs = cleanList(dirs, true)
	cand := e.cfg.Validation
	cand.AllowedDirs = dirs
	rs, err := validate.New(cand, e.cfg.Limits)
	if err != nil {
		return api.RenameResp{}, newErr(KindInvalid, "%s", safe.Line(err.Error(), 300))
	}

	resp := api.RenameResp{From: from, To: to, Files: len(moved)}
	if !wasListed {
		resp.Warnings = append(resp.Warnings, fmt.Sprintf("%q was not in the allowed folder list; %q will be added.", from, to))
	}
	for _, id := range sortedIDs(e.props) {
		p := e.props[id]
		if p.State != store.StatePending && p.State != store.StateDraft {
			continue
		}
		for _, c := range p.Changes {
			if topDir(c.Path) == from {
				resp.Warnings = append(resp.Warnings, fmt.Sprintf("Proposal %s (%s, %s) touches %s/: it becomes stale and the agent must redo it.", id, p.Agent, p.State, from))
				break
			}
		}
	}
	if m, err := e.repo.Grep(ctx, head, from+"/", 200); err == nil {
		seen := map[string]bool{}
		var files []string
		for _, x := range m {
			if !seen[x.Path] {
				seen[x.Path] = true
				files = append(files, x.Path)
			}
		}
		if len(files) > 0 {
			sort.Strings(files)
			show := files
			if len(show) > 5 {
				show = show[:5]
			}
			resp.Warnings = append(resp.Warnings, fmt.Sprintf("%d file(s) mention \"%s/\" (links or paths); they are NOT rewritten, update them by hand (for example %s).", len(files), from, strings.Join(show, ", ")))
		}
	}
	if len(resp.Warnings) > maxSettingsWarnings {
		resp.Warnings = resp.Warnings[:maxSettingsWarnings]
	}
	for i := range resp.Warnings {
		resp.Warnings[i] = safe.Line(resp.Warnings[i], 400)
	}
	if dryRun {
		return resp, nil
	}

	edits := make([]gitrepo.Edit, 0, 2*len(moved))
	want := map[string]bool{}
	var total int64
	for _, p := range moved {
		ent := tree[p]
		b, err := e.repo.ReadBlob(ctx, ent.ID)
		if err != nil {
			return api.RenameResp{}, newErr(KindInternal, "reading %s: %v", safe.Line(p, 120), err)
		}
		total += int64(len(b))
		if total > e.cfg.Limits.MaxImportBytes {
			return api.RenameResp{}, newErr(KindInvalid, "the folder is larger than %d bytes, refusing to move it in one step", e.cfg.Limits.MaxImportBytes)
		}
		np := newPath(p)
		edits = append(edits, gitrepo.Edit{Path: p, Delete: true}, gitrepo.Edit{Path: np, Mode: ent.Mode, Content: b})
		want[p], want[np] = true, true
	}
	topic := safe.OneLine(fmt.Sprintf("rename folder %s to %s", from, to), 200)
	msg := fmt.Sprintf("trove: %s\n\nMoved %d file(s) (owner action).\n\n%s: %s\n%s: %s\n", topic, len(moved), TrailerApprover, a.Name, TrailerTopic, topic)
	who := gitrepo.Ident{Name: e.cfg.BotName, Email: e.cfg.BotEmail}
	commit, err := e.repo.BuildCommit(ctx, head, edits, msg, who)
	if err != nil {
		return api.RenameResp{}, newErr(KindInternal, "building commit: %v", err)
	}
	got, err := e.repo.ChangedPaths(ctx, head, commit)
	if err != nil {
		return api.RenameResp{}, newErr(KindInternal, "checking commit: %v", err)
	}
	if !samePaths(got, want) {
		return api.RenameResp{}, newErr(KindConflict, "the commit would change other paths than the rename; nothing was applied")
	}
	if err := e.mustLog(a, "folder-rename-intent", "", "pending", safe.Line(fmt.Sprintf("%s -> %s files=%d commit=%s", from, to, len(moved), commit), 400)); err != nil {
		return api.RenameResp{}, newErr(KindInternal, "audit log not writable, nothing was applied: %v", err)
	}
	if err := e.repo.UpdateRef(ctx, commit, head); err != nil {
		e.logEvent(a, "folder-rename", "", "failed", "the branch moved; nothing was applied")
		return api.RenameResp{}, newErr(KindConflict, "the branch moved during the rename; nothing was applied")
	}
	resp.Commit = commit
	exts := append([]string(nil), e.cfg.Validation.AllowedExtensions...)
	if err := config.SaveSettings(e.cfg.DataDir, config.Settings{AllowedDirs: dirs, AllowedExtensions: exts, MaxFiles: e.limitFiles()}); err != nil {
		e.logEvent(a, "folder-rename", "", "settings-failed", safe.Line(err.Error(), 300))
		return api.RenameResp{}, newErr(KindInternal, "the folder was renamed (commit %s) but saving the allowed list failed: %v; fix the list in Settings", commit, err)
	}
	e.cfg.Validation = cand
	e.rules.Store(rs)
	e.logEvent(a, "folder-rename", "", "ok", safe.Line(fmt.Sprintf("%s -> %s files=%d commit=%s", from, to, len(moved), commit), 400))
	resp.Settings = api.Settings{AllowedDirs: dirs, AllowedExtensions: exts, MaxFiles: e.limitFiles()}
	return resp, nil
}

func sortedIDs(m map[string]*store.Proposal) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
