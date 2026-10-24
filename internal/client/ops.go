package client

import (
	"fmt"
	"sort"
	"strings"

	"trove/internal/api"
	"trove/internal/safe"
	"trove/internal/store"
)

// MaxSnapshotBytes bounds a sync download held in memory.
const MaxSnapshotBytes = 1 << 30

// UncoveredError lists local modifications that would be lost.
type UncoveredError struct{ Mods []Mod }

func (e *UncoveredError) Error() string {
	var b strings.Builder
	b.WriteString("the local mirror has modifications that are not part of a submitted proposal; refusing to overwrite them:")
	for _, m := range e.Mods {
		fmt.Fprintf(&b, "\n  %s %s", m.Kind, safe.Line(m.Path, 300))
	}
	b.WriteString("\nsubmit them, or revert them by hand, then sync again")
	return b.String()
}

// Sync downloads HEAD (or commit) into the mirror. It refuses when the
// mirror has modifications not covered by a submitted proposal, or
// unsupported files (symlinks).
func Sync(c *Client, w *Workspace, commit string) (string, error) {
	mods, problems, err := w.Modifications()
	if err != nil {
		return "", err
	}
	if len(problems) > 0 {
		return "", fmt.Errorf("unsupported files in the mirror:\n  %s", safe.Text(strings.Join(problems, "\n  "), 300, 0))
	}
	var uncovered []Mod
	for _, m := range mods {
		if m.Covered == "" {
			uncovered = append(uncovered, m)
		}
	}
	if len(uncovered) > 0 {
		return "", &UncoveredError{Mods: uncovered}
	}
	got, body, err := c.Snapshot(commit)
	if err != nil {
		return "", err
	}
	defer body.Close()
	files, _, err := ReadSnapshot(body, MaxSnapshotBytes)
	if err != nil {
		return "", err
	}
	if w.State.URL == "" {
		w.State.URL = c.BaseURL
	}
	if err := w.ApplySnapshot(got, files); err != nil {
		return "", err
	}
	return got, nil
}

// PendingChanges builds the change set for a submit: every uncovered local
// modification, optionally restricted to paths (files or folders).
func PendingChanges(w *Workspace, paths []string) ([]store.Change, error) {
	mods, problems, err := w.Modifications()
	if err != nil {
		return nil, err
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("unsupported files in the mirror:\n  %s", safe.Text(strings.Join(problems, "\n  "), 300, 0))
	}
	var changes []store.Change
	for _, m := range mods {
		if m.Covered != "" || !selected(m.Path, paths) {
			continue
		}
		if m.Kind == "deleted" {
			changes = append(changes, store.Change{Path: m.Path, Op: store.OpDelete})
			continue
		}
		b, err := w.ReadLocal(m.Path)
		if err != nil {
			return nil, err
		}
		changes = append(changes, store.Change{Path: m.Path, Op: store.OpPut, Content: string(b)})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes, nil
}

func selected(p string, filter []string) bool {
	if len(filter) == 0 {
		return true
	}
	for _, f := range filter {
		f = strings.Trim(strings.ReplaceAll(f, "\\", "/"), "/")
		if p == f || strings.HasPrefix(p, f+"/") {
			return true
		}
	}
	return false
}

// PickDraft returns the draft to use: the given id, or the only one open.
func PickDraft(w *Workspace, id string) (string, error) {
	if id != "" {
		if _, ok := w.State.Drafts[id]; !ok {
			return "", fmt.Errorf("draft %s was not opened from this mirror", id)
		}
		return id, nil
	}
	switch len(w.State.Drafts) {
	case 0:
		return "", fmt.Errorf("no open draft; run trove begin \"<topic>\" first")
	case 1:
		for d := range w.State.Drafts {
			return d, nil
		}
	}
	return "", fmt.Errorf("several open drafts; choose one with --draft")
}

// Begin opens a draft based on the mirror's synced commit.
func Begin(c *Client, w *Workspace, topic string, scope []string) (api.Summary, error) {
	if !w.Synced() {
		return api.Summary{}, fmt.Errorf("the mirror has not been synced yet; run trove sync first")
	}
	s, err := c.Begin(api.BeginReq{Topic: topic, Scope: scope, Base: w.State.Commit})
	if err != nil {
		return s, err
	}
	if w.State.Drafts == nil {
		w.State.Drafts = map[string]string{}
	}
	w.State.Drafts[s.ID] = s.Base
	return s, w.Save()
}

// Submit sends the local modifications as the content of a draft.
func Submit(c *Client, w *Workspace, draftID string, paths []string) (api.Summary, error) {
	id, err := PickDraft(w, draftID)
	if err != nil {
		return api.Summary{}, err
	}
	if base := w.State.Drafts[id]; base != w.State.Commit {
		return api.Summary{}, fmt.Errorf("draft %s is based on %s but the mirror is at %s; abort it and begin again", id, short(base), short(w.State.Commit))
	}
	changes, err := PendingChanges(w, paths)
	if err != nil {
		return api.Summary{}, err
	}
	if len(changes) == 0 {
		return api.Summary{}, fmt.Errorf("no local changes to submit")
	}
	s, err := c.Submit(id, changes)
	if err != nil {
		return s, err
	}
	if w.State.Submitted == nil {
		w.State.Submitted = map[string]map[string]string{}
	}
	rec := map[string]string{}
	for _, ch := range changes {
		if ch.Op == store.OpDelete {
			rec[ch.Path] = ""
		} else {
			rec[ch.Path] = sum([]byte(ch.Content))
		}
	}
	w.State.Submitted[id] = rec
	delete(w.State.Drafts, id)
	return s, w.Save()
}

// Forget removes a proposal from the mirror bookkeeping.
func Forget(w *Workspace, id string) error {
	delete(w.State.Drafts, id)
	delete(w.State.Submitted, id)
	return w.Save()
}

// Rebase supersedes a stale proposal, keeps a reference copy of its
// changes, syncs the mirror to the new base and registers the new draft.
func Rebase(c *Client, w *Workspace, id string) (api.RebaseResp, string, error) {
	res, err := c.Rebase(id)
	if err != nil {
		return res, "", err
	}
	ref, err := w.WriteReference(res.Old.ID, res.Old.Changes)
	if err != nil {
		return res, "", err
	}
	if w.State.Drafts == nil {
		w.State.Drafts = map[string]string{}
	}
	w.State.Drafts[res.New.ID] = res.New.Base
	if err := w.Save(); err != nil {
		return res, ref, err
	}
	if _, err := Sync(c, w, res.New.Base); err != nil {
		return res, ref, fmt.Errorf("new draft %s created, but sync failed: %w", res.New.ID, err)
	}
	delete(w.State.Submitted, id)
	return res, ref, w.Save()
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "(none)"
	}
	return s
}
