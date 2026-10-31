package server

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trove/internal/api"
	"trove/internal/auth"
	"trove/internal/store"
)

// openDraft opens a draft for a with one written change.
func (ev *env) openDraft(a auth.Actor, topic, path string) api.Summary {
	ev.t.Helper()
	d, err := ev.e.Begin(a, api.BeginReq{Topic: topic})
	if err != nil {
		ev.t.Fatalf("begin: %v", err)
	}
	if _, err := ev.e.WriteChange(a, d.ID, api.ChangeReq{Path: path, Op: store.OpPut, Content: md(topic, "draft body")}); err != nil {
		ev.t.Fatalf("write: %v", err)
	}
	return d
}

func hasID(l []api.Summary, id string) bool {
	for _, s := range l {
		if s.ID == id {
			return true
		}
	}
	return false
}

func TestAgentGetsOtherAgentsNonDraftProposals(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	pend := ev.propose(agent1, "pending one", put("notes/alpha.md", md("alpha", "cross read body")))
	rej := ev.propose(agent1, "rejected one", put("notes/beta.md", md("beta", "z")))
	if _, err := ev.e.Reject(owner, rej.ID, "no"); err != nil {
		t.Fatal(err)
	}
	app := ev.propose(agent1, "applied one", put("notes/gamma.md", md("gamma", "g")))
	rv, err := ev.e.Review(owner, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ev.e.Approve(owner, app.ID, rv.Summary.Digest); err != nil {
		t.Fatal(err)
	}

	for _, s := range []api.Summary{pend, rej, app} {
		d, err := ev.e.Get(agent2, s.ID)
		if err != nil {
			t.Fatalf("agent2 get %s: %v", s.ID, err)
		}
		// Closed proposals may have their content dropped, as for the owner.
		if d.Agent != "agent1" || len(d.Changes) != 1 || (s.ID == pend.ID && d.Changes[0].Content == "") {
			t.Fatalf("detail incomplete: %+v", d)
		}
	}
	d, _ := ev.e.Get(agent2, pend.ID)
	if !strings.Contains(d.Changes[0].Content, "cross read body") {
		t.Fatalf("content missing: %+v", d.Changes)
	}
}

func TestCrossReadHidesOverlapIDsAndSuccessorDraft(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	a := ev.propose(agent1, "a", put("notes/alpha.md", md("alpha", "from agent1")))
	b := ev.propose(agent2, "b", put("notes/alpha.md", md("alpha", "from agent2")))
	d, err := ev.e.Get(agent2, a.ID)
	if err != nil || d.OverlapCount != 1 || len(d.Overlaps) != 0 {
		t.Fatalf("agent view of overlaps: %v %d %v", err, d.OverlapCount, d.Overlaps)
	}
	if o, _ := ev.e.Get(owner, a.ID); len(o.Overlaps) != 1 || o.Overlaps[0] != b.ID {
		t.Fatalf("owner view of overlaps: %v", o.Overlaps)
	}
	// b lands, a goes stale and is rebased into a fresh agent1 draft.
	if _, err := ev.e.Approve(owner, b.ID, b.Digest); err != nil {
		t.Fatal(err)
	}
	rb, err := ev.e.Rebase(agent1, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if g, _ := ev.e.Get(agent1, a.ID); g.SupersededBy != rb.New.ID {
		t.Fatalf("own view must keep superseded_by: %q", g.SupersededBy)
	}
	g, err := ev.e.Get(agent2, a.ID)
	if err != nil || g.SupersededBy != "" {
		t.Fatalf("foreign draft id leaked via superseded_by: %v %q", err, g.SupersededBy)
	}
	l, err := ev.e.List(agent2, "all", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range l {
		if s.ID == rb.New.ID || s.SupersededBy == rb.New.ID {
			t.Fatalf("foreign draft id leaked in list: %+v", s)
		}
	}
}

func TestAgentCannotSeeOtherAgentsDraft(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	d1 := ev.openDraft(agent1, "d1", "notes/alpha.md")
	d2 := ev.openDraft(agent2, "d2", "notes/beta.md")

	_, err := ev.e.Get(agent2, d1.ID)
	wantKind(t, err, KindNotFound)
	_, err = ev.e.Get(agent2, strings.Repeat("0", len(d1.ID)))
	wantKind(t, err, KindNotFound)
	if _, err := ev.e.Get(agent2, d2.ID); err != nil {
		t.Fatalf("own draft: %v", err)
	}
	for _, f := range []string{"all", "draft"} {
		l, err := ev.e.List(agent2, f, true)
		if err != nil {
			t.Fatal(err)
		}
		if hasID(l, d1.ID) {
			t.Fatalf("filter %q leaks agent1's draft", f)
		}
		if !hasID(l, d2.ID) {
			t.Fatalf("filter %q lacks agent2's own draft", f)
		}
	}
}

func TestListAllAgentsAndOwnOnly(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	d1 := ev.openDraft(agent1, "d1", "notes/alpha.md")
	p1 := ev.propose(agent1, "p1", put("notes/beta.md", md("beta", "b")))
	p2 := ev.propose(agent2, "p2", put("notes/gamma.md", md("gamma", "g")))

	l, err := ev.e.List(agent2, "all", false)
	if err != nil || len(l) != 1 || l[0].ID != p2.ID {
		t.Fatalf("own-only list: %v %+v", err, l)
	}
	l, err = ev.e.List(agent2, "all", true)
	if err != nil || len(l) != 2 || !hasID(l, p1.ID) || !hasID(l, p2.ID) || hasID(l, d1.ID) {
		t.Fatalf("all-agents list: %v %+v", err, l)
	}
	for _, s := range l {
		if s.Agent == "" {
			t.Fatalf("summary without agent: %+v", s)
		}
	}
	st, err := ev.e.Status(agent2)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Proposals) != 1 || st.Proposals[0].ID != p2.ID {
		t.Fatalf("status must show only own: %+v", st)
	}
	// Approvers see everything regardless of the flag.
	for _, flag := range []bool{false, true} {
		l, err = ev.e.List(owner, "all", flag)
		if err != nil || len(l) != 3 {
			t.Fatalf("owner list flag=%v: %v %d", flag, err, len(l))
		}
	}
}

func TestCrossReadDoesNotGrantWrites(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	d1 := ev.openDraft(agent1, "d1", "notes/alpha.md")
	p1 := ev.propose(agent1, "p1", put("notes/beta.md", md("beta", "b")))
	head := ev.head()

	for _, id := range []string{d1.ID, p1.ID} {
		before, err := ev.e.Get(owner, id)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ev.e.WriteChange(agent2, id, api.ChangeReq{Path: "notes/x.md", Op: store.OpPut, Content: md("x", "x")})
		wantKind(t, err, KindNotFound)
		_, err = ev.e.Submit(agent2, id, []store.Change{put("notes/x.md", md("x", "x"))})
		wantKind(t, err, KindNotFound)
		_, err = ev.e.Abort(agent2, id)
		wantKind(t, err, KindNotFound)
		_, err = ev.e.Rebase(agent2, id)
		wantKind(t, err, KindNotFound)
		_, err = ev.e.ReadFile(agent2, "notes/alpha.md", id)
		wantKind(t, err, KindNotFound)
		after, err := ev.e.Get(owner, id)
		if err != nil {
			t.Fatal(err)
		}
		if after.State != before.State || after.Digest != before.Digest || len(after.Changes) != len(before.Changes) {
			t.Fatalf("proposal %s changed: %+v -> %+v", id, before.Summary, after.Summary)
		}
	}
	if ev.head() != head {
		t.Fatal("head moved")
	}
	// The owner of the draft can still read through it.
	if _, err := ev.e.ReadFile(agent1, "notes/alpha.md", d1.ID); err != nil {
		t.Fatalf("own draft read: %v", err)
	}
}

func TestReaderCannotCrossRead(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	p1 := ev.propose(agent1, "p1", put("notes/beta.md", md("beta", "b")))
	for _, flag := range []bool{false, true} {
		_, err := ev.e.List(readerA, "all", flag)
		wantKind(t, err, KindForbidden)
	}
	_, err := ev.e.Get(readerA, p1.ID)
	wantKind(t, err, KindNotFound)
}

func TestHTTPCrossRead(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	roles := map[string]auth.Role{"agent1": auth.RoleAgent, "agent2": auth.RoleAgent, "reader1": auth.RoleReader}
	var entries []auth.TokenEntry
	toks := map[string]string{}
	for name, role := range roles {
		tok, err := auth.NewToken(role)
		if err != nil {
			t.Fatal(err)
		}
		toks[name] = tok
		entries = append(entries, auth.TokenEntry{Name: name, Role: role, SHA256: auth.Hash(tok)})
	}
	keys, err := auth.NewKeyring(entries)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewHandler(ev.e, keys, log.New(io.Discard, "", 0)))
	t.Cleanup(srv.Close)

	d1 := ev.openDraft(agent1, "d1", "notes/alpha.md")
	p1 := ev.propose(agent1, "p1", put("notes/beta.md", md("beta", "b")))
	p2 := ev.propose(agent2, "p2", put("notes/gamma.md", md("gamma", "g")))

	get := func(tok, path string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	code, body := get(toks["agent2"], "/v1/proposals?state=all&agents=all")
	if code != http.StatusOK || !strings.Contains(body, p1.ID) || !strings.Contains(body, p2.ID) || strings.Contains(body, d1.ID) {
		t.Fatalf("agents=all: %d %s", code, body)
	}
	code, body = get(toks["agent2"], "/v1/proposals?state=all")
	if code != http.StatusOK || strings.Contains(body, p1.ID) || !strings.Contains(body, p2.ID) {
		t.Fatalf("default list: %d %s", code, body)
	}
	if code, _ = get(toks["agent2"], "/v1/proposals?agents=bogus"); code != http.StatusBadRequest {
		t.Fatalf("agents=bogus: %d", code)
	}
	if code, _ = get(toks["reader1"], "/v1/proposals?agents=all"); code != http.StatusForbidden {
		t.Fatalf("reader list: %d", code)
	}
	if code, body = get(toks["agent2"], "/v1/proposals/"+p1.ID); code != http.StatusOK || !strings.Contains(body, "changes") {
		t.Fatalf("get pending: %d %s", code, body)
	}
	code, foreign := get(toks["agent2"], "/v1/proposals/"+d1.ID)
	_, missing := get(toks["agent2"], "/v1/proposals/"+strings.Repeat("0", len(d1.ID)))
	if code != http.StatusNotFound || foreign != missing {
		t.Fatalf("get foreign draft must look like a missing id: %d %q vs %q", code, foreign, missing)
	}
	if code, _ = get(toks["agent2"], "/v1/file?path=notes/alpha.md&draft="+d1.ID); code != http.StatusNotFound {
		t.Fatalf("read through foreign draft: %d", code)
	}
	if code, _ = get(toks["agent2"], "/v1/file?path=notes/alpha.md&draft="+p1.ID); code != http.StatusNotFound {
		t.Fatalf("read through foreign proposal: %d", code)
	}
	if code, _ = get(toks["agent1"], "/v1/file?path=notes/alpha.md&draft="+d1.ID); code != http.StatusOK {
		t.Fatalf("read through own draft: %d", code)
	}
	if code, _ = get(toks["agent2"], "/v1/proposals/"+p1.ID+"/review"); code != http.StatusForbidden {
		t.Fatalf("agent review: %d", code)
	}
	if code, _ = get(toks["reader1"], "/v1/proposals/"+p1.ID); code != http.StatusNotFound {
		t.Fatalf("reader get: %d", code)
	}
	for _, path := range []string{"/v1/proposals", "/v1/proposals?agents=all", "/v1/proposals/" + p1.ID} {
		if code, _ = get("", path); code == http.StatusOK {
			t.Fatalf("unauthenticated %s got 200", path)
		}
		if code, _ = get("wrong", path); code == http.StatusOK {
			t.Fatalf("bad token %s got 200", path)
		}
	}
}
