package server

import (
	"sort"
	"strings"
	"time"

	trove "trove"
	"trove/internal/api"
	"trove/internal/auth"
	"trove/internal/gitrepo"
	"trove/internal/safe"
	"trove/internal/store"
)

// History limits for GET /v1/history.
const (
	historyDefault = 200
	historyMax     = 1000
)

// About returns the running version and the embedded changelog.
func (e *Engine) About() api.AboutResp {
	return api.AboutResp{Version: trove.Version, Changelog: trove.Changelog}
}

// History lists what reached the knowledge base (every commit of the main
// history: approved proposals, imports, folder renames) and the rejected
// proposals, newest first. Owner only.
func (e *Engine) History(a auth.Actor, limit int) (api.HistoryResp, error) {
	if a.Role != auth.RoleApprover {
		return api.HistoryResp{}, newErr(KindForbidden, "only the owner can see the history")
	}
	if limit <= 0 {
		limit = historyDefault
	}
	if limit > historyMax {
		limit = historyMax
	}
	ctx, cancel := gitCtx()
	defer cancel()
	commits, err := e.repo.Log(ctx, limit+1)
	if err != nil {
		return api.HistoryResp{}, newErr(KindInternal, "%v", err)
	}
	out := api.HistoryResp{Entries: []api.HistoryEntry{}}
	if len(commits) > limit {
		commits, out.Truncated = commits[:limit], true
	}
	for _, c := range commits {
		out.Entries = append(out.Entries, commitEntry(c.ID, c.Message, c.Time, c.Files))
	}
	archived, err := e.store.LoadArchive()
	if err != nil {
		return api.HistoryResp{}, newErr(KindInternal, "%v", err)
	}
	for _, p := range archived {
		if p.State != store.StateRejected {
			continue
		}
		out.Entries = append(out.Entries, rejectedEntry(p))
	}
	sort.SliceStable(out.Entries, func(i, j int) bool { return out.Entries[i].Time.After(out.Entries[j].Time) })
	if len(out.Entries) > limit {
		out.Entries, out.Truncated = out.Entries[:limit], true
	}
	return out, nil
}

func validName(v []string) string {
	if len(v) > 0 && auth.ValidName(v[0]) {
		return v[0]
	}
	return ""
}

func first(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

var fileOps = map[string]string{"A": "added", "M": "modified", "D": "deleted"}

// commitEntry classifies a commit by its Trove trailers. Every value
// shown comes from a trailer Trove wrote itself or from the subject.
func commitEntry(id, msg string, when time.Time, files []gitrepo.FileStatus) api.HistoryEntry {
	t := parseTrailers(msg)
	subject, _, _ := strings.Cut(msg, "\n")
	subject = strings.TrimPrefix(strings.TrimSpace(subject), "trove: ")
	en := api.HistoryEntry{
		Kind:      "other",
		Time:      when,
		Topic:     safe.OneLine(subject, 200),
		Commit:    id,
		DecidedBy: validName(t[TrailerApprover]),
	}
	if v := first(t[TrailerTopic]); v != "" {
		en.Topic = safe.OneLine(v, 200)
	}
	switch {
	case len(t[TrailerProposal]) > 0 && store.ValidID(first(t[TrailerProposal])):
		en.Kind = "applied"
		en.Proposal = first(t[TrailerProposal])
		en.Agent = validName(t[TrailerAgent])
	case len(t[TrailerBootstrap]) > 0:
		en.Kind = "bootstrap"
	case strings.HasPrefix(subject, "import ("):
		en.Kind = "import"
	case strings.HasPrefix(en.Topic, "rename folder "):
		en.Kind = "rename"
	}
	for _, f := range files {
		op := fileOps[f.Status]
		if op == "" {
			op = "modified"
		}
		en.Files = append(en.Files, api.HistoryFile{Path: f.Path, Op: op})
	}
	return en
}

func rejectedEntry(p *store.Proposal) api.HistoryEntry {
	en := api.HistoryEntry{
		Kind:      "rejected",
		Time:      p.UpdatedAt,
		Topic:     safe.OneLine(p.Topic, 200),
		Proposal:  p.ID,
		Agent:     p.Agent,
		DecidedBy: p.DecidedBy,
		Reason:    p.Reason,
	}
	for _, c := range p.Changes {
		op := "write"
		if c.Op == store.OpDelete {
			op = "deleted"
		}
		en.Files = append(en.Files, api.HistoryFile{Path: c.Path, Op: op})
	}
	return en
}
