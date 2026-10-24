package server

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trove/internal/auth"
	"trove/internal/client"
)

type httpEnv struct {
	*env
	srv                  *httptest.Server
	agent, owner, reader *client.Client
}

func newHTTPEnv(t *testing.T) *httpEnv {
	t.Helper()
	ev := newEnv(t, nil, defaultFiles())
	toks := map[string]auth.Role{"agent1": auth.RoleAgent, "owner": auth.RoleApprover, "reader1": auth.RoleReader}
	var entries []auth.TokenEntry
	plain := map[string]string{}
	for name, role := range toks {
		tok, err := auth.NewToken(role)
		if err != nil {
			t.Fatal(err)
		}
		plain[name] = tok
		entries = append(entries, auth.TokenEntry{Name: name, Role: role, SHA256: auth.Hash(tok)})
	}
	keys, err := auth.NewKeyring(entries)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewHandler(ev.e, keys, log.New(io.Discard, "", 0)))
	t.Cleanup(srv.Close)
	return &httpEnv{env: ev, srv: srv,
		agent:  client.New(srv.URL, plain["agent1"]),
		owner:  client.New(srv.URL, plain["owner"]),
		reader: client.New(srv.URL, plain["reader1"]),
	}
}

func statusOf(err error) int {
	var ae *client.APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

func TestHTTPEndToEnd(t *testing.T) {
	h := newHTTPEnv(t)
	if _, err := client.New(h.srv.URL, "wrong").Head(); statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("unknown token must get 401, got %v", err)
	}
	if _, err := client.New(h.srv.URL, "").Head(); statusOf(err) != http.StatusUnauthorized {
		t.Fatalf("missing token must get 401, got %v", err)
	}
	dir := t.TempDir()
	ws, err := client.OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := client.Sync(h.reader, ws, "")
	if err != nil {
		t.Fatal(err)
	}
	if commit != h.head() {
		t.Fatalf("synced %s, head %s", commit, h.head())
	}
	alpha := filepath.Join(dir, "notes", "alpha.md")
	if _, err := os.Stat(alpha); err != nil {
		t.Fatalf("file not synced: %v", err)
	}
	// Local edit blocks sync until it is submitted.
	if err := os.WriteFile(alpha, []byte(md("alpha", "edited locally")), 0o644); err != nil {
		t.Fatal(err)
	}
	var unc *client.UncoveredError
	if _, err := client.Sync(h.agent, ws, ""); !errors.As(err, &unc) {
		t.Fatalf("sync must refuse uncovered changes, got %v", err)
	}
	if _, err := client.Begin(h.reader, ws, "x", nil); statusOf(err) != http.StatusForbidden {
		t.Fatalf("reader must not begin: %v", err)
	}
	if _, err := client.Begin(h.agent, ws, "edit alpha", nil); err != nil {
		t.Fatal(err)
	}
	s, err := client.Submit(h.agent, ws, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Agent token: approve must fail on the HTTP route.
	if _, err := h.agent.Approve(s.ID, s.Digest); statusOf(err) != http.StatusForbidden {
		t.Fatalf("agent approve must get 403, got %v", err)
	}
	if _, err := h.agent.Review(s.ID); statusOf(err) != http.StatusForbidden {
		t.Fatalf("agent review must get 403, got %v", err)
	}
	if _, err := h.agent.Import("tar", false, strings.NewReader("")); statusOf(err) != http.StatusForbidden {
		t.Fatalf("agent import must get 403, got %v", err)
	}
	if _, err := client.Sync(h.agent, ws, ""); err != nil {
		t.Fatalf("sync after submit should be allowed: %v", err)
	}
	if _, err := h.owner.Approve(s.ID, ""); statusOf(err) != http.StatusBadRequest {
		t.Fatalf("approve without digest must fail with 400, got %v", err)
	}
	rv, err := h.owner.Review(s.ID)
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.owner.Approve(s.ID, rv.Summary.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if res.Commit != h.head() {
		t.Fatal("approve did not move head")
	}
	if _, err := client.Sync(h.agent, ws, ""); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(alpha)
	if !strings.Contains(string(b), "edited locally") {
		t.Fatalf("approved change not in the mirror: %q", b)
	}
	text, err := h.reader.Instructions()
	if err != nil || !strings.Contains(text, "Trove") {
		t.Fatalf("instructions: %v", err)
	}
	if _, err := h.reader.List(""); statusOf(err) != http.StatusForbidden {
		t.Fatalf("reader list must get 403, got %v", err)
	}
	v, err := h.owner.VerifyAudit()
	if err != nil || !v.OK {
		t.Fatalf("audit verify: %+v %v", v, err)
	}
}

func TestHTTPRebaseFlow(t *testing.T) {
	h := newHTTPEnv(t)
	dir := t.TempDir()
	ws, _ := client.OpenWorkspace(dir)
	if _, err := client.Sync(h.agent, ws, ""); err != nil {
		t.Fatal(err)
	}
	alpha := filepath.Join(dir, "notes", "alpha.md")
	os.WriteFile(alpha, []byte(md("alpha", "mine")), 0o644)
	if _, err := client.Begin(h.agent, ws, "mine", nil); err != nil {
		t.Fatal(err)
	}
	mine, err := client.Submit(h.agent, ws, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Someone else's change to the same file lands first.
	other := h.propose(agent2, "other", put("notes/alpha.md", md("alpha", "theirs")))
	if _, err := h.e.Approve(owner, other.ID, other.Digest); err != nil {
		t.Fatal(err)
	}
	res, ref, err := client.Rebase(h.agent, ws, mine.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.New.Supersedes != mine.ID {
		t.Fatal("missing supersedes")
	}
	if b, err := os.ReadFile(filepath.Join(ref, "notes", "alpha.md")); err != nil || !strings.Contains(string(b), "mine") {
		t.Fatalf("reference copy missing: %v", err)
	}
	if b, _ := os.ReadFile(alpha); !strings.Contains(string(b), "theirs") {
		t.Fatal("mirror not synced to the new base")
	}
	os.WriteFile(alpha, []byte(md("alpha", "theirs and mine")), 0o644)
	ns, err := client.Submit(h.agent, ws, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ns.ID == mine.ID || ns.Status != "ready" {
		t.Fatalf("bad rebased proposal: %+v", ns)
	}
}
