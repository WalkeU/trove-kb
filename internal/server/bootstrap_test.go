package server

import (
	"path/filepath"
	"strings"
	"testing"

	"trove/internal/api"
	"trove/internal/audit"
	"trove/internal/store"
)

func welcomeFile(content string) []store.Change {
	return []store.Change{{Path: "INDEX.md", Op: store.OpPut, Content: content}}
}

const welcomeMD = "---\ntitle: Welcome\nupdated: 2026-01-01\nstatus: current\n---\n\nHello.\n"

func TestBootstrapWritesAuditedRootCommit(t *testing.T) {
	ev := newEnv(t, nil, nil)
	commit, err := ev.e.Bootstrap(owner, welcomeFile(welcomeMD))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := gitCtx()
	defer cancel()
	if head, _ := ev.e.repo.Head(ctx); head != commit {
		t.Fatalf("HEAD %s, want %s", head, commit)
	}
	if !ev.e.onlyBootstrap() {
		t.Fatal("the welcome commit is not recognized")
	}
	l, _ := ev.e.repo.FindByTrailer(ctx, TrailerBootstrap, BootstrapWelcome)
	tr := parseTrailers(l[0].Message)
	if !contains(tr[TrailerApprover], "owner") || len(tr[TrailerProposal]) != 0 {
		t.Errorf("trailers: %v", tr)
	}
	res, err := audit.VerifyFile(filepath.Join(ev.cfg.DataDir, "audit.jsonl"))
	if err != nil || res.Lines != 2 {
		t.Fatalf("audit: %d %v", res.Lines, err)
	}
	// An agent can work on top of it right away.
	if _, err := ev.e.Begin(agent1, api.BeginReq{Topic: "fix welcome"}); err != nil {
		t.Fatalf("begin after bootstrap: %v", err)
	}
}

func TestBootstrapRefusals(t *testing.T) {
	ev := newEnv(t, nil, nil)
	if _, err := ev.e.Bootstrap(agent1, welcomeFile(welcomeMD)); err == nil {
		t.Error("an agent wrote the first commit")
	}
	for name, files := range map[string][]store.Change{
		"no frontmatter": welcomeFile("# hi\n"),
		"secret":         welcomeFile(welcomeMD + "password=hunter2hunter2\n"),
		"bad folder":     {{Path: "secret-stuff/a.md", Op: store.OpPut, Content: welcomeMD}},
		"none":           nil,
	} {
		if name == "no frontmatter" {
			// INDEX.md is frontmatter-exempt; use a non-exempt name.
			files = []store.Change{{Path: "welcome.md", Op: store.OpPut, Content: "# hi\n"}}
		}
		if _, err := ev.e.Bootstrap(owner, files); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Never into a non-empty knowledge base.
	ev2 := newEnv(t, nil, map[string]string{"notes/a.md": welcomeMD})
	if _, err := ev2.e.Bootstrap(owner, welcomeFile(welcomeMD)); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("bootstrap on a non-empty knowledge base: %v", err)
	}
	if ev2.e.onlyBootstrap() {
		t.Error("an imported knowledge base counts as bootstrap-only")
	}
}

// After the welcome commit, import is refused with a pointer to --no-welcome.
func TestImportAfterBootstrapRefused(t *testing.T) {
	ev := newEnv(t, nil, nil)
	if _, err := ev.e.Bootstrap(owner, welcomeFile(welcomeMD)); err != nil {
		t.Fatal(err)
	}
	_, err := ev.e.Import(owner, "tar", tarOf(t, map[string]string{"notes/a.md": welcomeMD}))
	if err == nil || !strings.Contains(err.Error(), "--no-welcome") {
		t.Fatalf("import after bootstrap: %v", err)
	}
}
