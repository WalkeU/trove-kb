package server

import (
	"fmt"
	"strings"

	"trove/internal/auth"
	"trove/internal/gitrepo"
	"trove/internal/store"
)

// TrailerBootstrap marks the first commit written by trove init (the
// welcome note), so it is never mistaken for an applied proposal.
const TrailerBootstrap = "Trove-Bootstrap"

// BootstrapWelcome is the trailer value of the welcome commit.
const BootstrapWelcome = "welcome"

// Bootstrap writes the first commit of an empty knowledge base: the
// welcome note created by trove init, which runs on the owner's side with
// the data directory opened directly (the instance lock keeps a running
// server out). Approver only, only while the branch does not exist, the
// files pass the same rules as a proposal, and it is audited fail closed
// like approve and import (bootstrap-intent line first).
func (e *Engine) Bootstrap(a auth.Actor, files []store.Change) (string, error) {
	if a.Role != auth.RoleApprover {
		return "", e.deny(a, "bootstrap", "", "only the approver can write the first commit")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ctx, cancel := gitCtx()
	defer cancel()
	head, err := e.repo.Head(ctx)
	if err != nil {
		return "", newErr(KindInternal, "%v", err)
	}
	if head != "" {
		e.logEvent(a, "bootstrap", "", "denied", "repository is not empty")
		return "", newErr(KindConflict, "the knowledge base is not empty; the welcome commit is only written into an empty one")
	}
	if len(files) == 0 {
		return "", newErr(KindInvalid, "no files")
	}
	if res := e.rules.Check(files, map[string]gitrepo.Entry{}, nil, nil); !res.OK() {
		return "", &Error{Kind: KindInvalid, Msg: "welcome files failed validation", Details: res.Errors}
	}
	var edits []gitrepo.Edit
	var paths []string
	for _, f := range files {
		if f.Op != store.OpPut {
			return "", newErr(KindInvalid, "%q: only new files", f.Path)
		}
		edits = append(edits, gitrepo.Edit{Path: f.Path, Content: []byte(f.Content)})
		paths = append(paths, f.Path)
	}
	if err := e.mustLog(a, "bootstrap-intent", "", "pending", "files="+strings.Join(paths, ",")); err != nil {
		return "", newErr(KindInternal, "audit log not writable, nothing was written: %v", err)
	}
	fail := func(err error) (string, error) {
		e.logEvent(a, "bootstrap", "", "failed", err.Error())
		return "", newErr(KindInternal, "%v", err)
	}
	// Names are restricted (auth.ValidName), so no value adds a trailer line.
	msg := fmt.Sprintf("trove: welcome note\n\nFirst commit, written by trove init for %s.\n\n%s: %s\n%s: %s\n",
		a.Name, TrailerBootstrap, BootstrapWelcome, TrailerApprover, a.Name)
	commit, err := e.repo.BuildCommit(ctx, "", edits, msg, gitrepo.Ident{Name: e.cfg.BotName, Email: e.cfg.BotEmail})
	if err != nil {
		return fail(fmt.Errorf("building commit: %w", err))
	}
	if err := e.repo.UpdateRef(ctx, commit, ""); err != nil {
		return fail(fmt.Errorf("branch was created concurrently: %w", err))
	}
	e.logEvent(a, "bootstrap", "", "ok", fmt.Sprintf("commit=%s files=%d", commit, len(edits)))
	return commit, nil
}

// onlyBootstrap reports whether the repository holds nothing but the
// welcome commit of trove init (used for a helpful import error).
func (e *Engine) onlyBootstrap() bool {
	ctx, cancel := gitCtx()
	defer cancel()
	if n, err := e.repo.CommitCount(ctx); err != nil || n != 1 {
		return false
	}
	l, err := e.repo.FindByTrailer(ctx, TrailerBootstrap, BootstrapWelcome)
	return err == nil && len(l) == 1 && contains(parseTrailers(l[0].Message)[TrailerBootstrap], BootstrapWelcome)
}
