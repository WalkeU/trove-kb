package server

import (
	"strings"
	"testing"

	trove "trove"
	"trove/internal/api"
)

func TestHistory(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	ok := ev.propose(agent1, "new gamma note", put("notes/gamma.md", md("gamma", "G.")), del("notes/beta.md"))
	if _, err := ev.e.Approve(owner, ok.ID, ok.Digest); err != nil {
		t.Fatal(err)
	}
	no := ev.propose(agent1, "bad idea", put("notes/alpha.md", md("alpha", "changed")))
	if _, err := ev.e.Reject(owner, no.ID, "not needed"); err != nil {
		t.Fatal(err)
	}

	_, err := ev.e.History(agent1, 0)
	wantKind(t, err, KindForbidden)

	h, err := ev.e.History(owner, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Commits carry the real time, the test clock is fixed: only compare
	// within one source.
	var rej, app *api.HistoryEntry
	kinds := []string{}
	for i, en := range h.Entries {
		kinds = append(kinds, en.Kind)
		switch {
		case en.Kind == "rejected" && rej == nil:
			rej = &h.Entries[i]
		case en.Kind == "applied" && app == nil:
			app = &h.Entries[i]
		case en.Kind == "import" && app == nil:
			t.Fatalf("import listed before the newer approval: %v", kinds)
		}
	}
	if rej == nil || app == nil {
		t.Fatalf("kinds = %v", kinds)
	}
	if rej.Proposal != no.ID || rej.Reason != "not needed" || rej.DecidedBy != owner.Name || len(rej.Files) != 1 || rej.Files[0].Op != "write" {
		t.Fatalf("rejected entry = %+v", rej)
	}
	if app.Proposal != ok.ID || app.Topic != "new gamma note" || app.Agent != agent1.Name || app.DecidedBy != owner.Name || app.Commit != ev.head() {
		t.Fatalf("applied entry = %+v", app)
	}
	ops := map[string]string{}
	for _, f := range app.Files {
		ops[f.Path] = f.Op
	}
	if ops["notes/gamma.md"] != "added" || ops["notes/beta.md"] != "deleted" || len(ops) != 2 {
		t.Fatalf("applied files = %+v", app.Files)
	}

	h, err = ev.e.History(owner, 1)
	if err != nil || len(h.Entries) != 1 || !h.Truncated {
		t.Fatalf("limit 1: %+v, %v", h, err)
	}
}

func TestAbout(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	a := ev.e.About()
	if a.Version == "" || a.Version != trove.Version || !strings.HasPrefix(a.Changelog, "# Changelog") {
		t.Fatalf("about = %q, changelog starts %q", a.Version, a.Changelog[:min(20, len(a.Changelog))])
	}
}
