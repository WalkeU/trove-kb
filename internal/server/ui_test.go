package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trove/internal/auth"
	"trove/internal/config"
	"trove/internal/webui"
)

func rawGet(t *testing.T, h http.Handler, method, path, token string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type uiEnv struct {
	*env
	h                    *Handler
	owner, agent, reader string
}

func newUIEnv(t *testing.T, mutate func(*config.Config)) *uiEnv {
	t.Helper()
	ev := newEnv(t, mutate, defaultFiles())
	u := &uiEnv{env: ev}
	var entries []auth.TokenEntry
	for name, role := range map[string]auth.Role{"owner": auth.RoleApprover, "agent1": auth.RoleAgent, "reader1": auth.RoleReader} {
		tok, err := auth.NewToken(role)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, auth.TokenEntry{Name: name, Role: role, SHA256: auth.Hash(tok)})
		switch role {
		case auth.RoleApprover:
			u.owner = tok
		case auth.RoleAgent:
			u.agent = tok
		default:
			u.reader = tok
		}
	}
	keys, err := auth.NewKeyring(entries)
	if err != nil {
		t.Fatal(err)
	}
	u.h = NewHandler(ev.e, keys, log.New(io.Discard, "", 0))
	return u
}

// The UI is static and needs no token; the API around it is unchanged.
func TestUIServedWithoutTokenAPIUnchanged(t *testing.T) {
	u := newUIEnv(t, nil)
	rec := rawGet(t, u.h, http.MethodGet, "/ui/", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<script type="module" src="app.js">`) {
		t.Fatalf("/ui/: %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != webui.CSP {
		t.Fatalf("UI CSP = %q", got)
	}
	// Root and API still require a token, exactly as before.
	for _, p := range []string{"/", "/v1/head", "/v1/tree", "/uix", "/v1/ui/"} {
		if rec := rawGet(t, u.h, http.MethodGet, p, "", nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without token: %d, want 401", p, rec.Code)
		}
	}
	if rec := rawGet(t, u.h, http.MethodGet, "/healthz", "", nil); rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Errorf("/healthz: %d %q", rec.Code, rec.Body.String())
	}
	// A token does not change what /ui/ is: still the same static page.
	if rec := rawGet(t, u.h, http.MethodGet, "/ui/app.js", u.owner, nil); rec.Code != http.StatusOK {
		t.Errorf("/ui/app.js with token: %d", rec.Code)
	}
	// The UI path is not a way around the API rules.
	if rec := rawGet(t, u.h, http.MethodPost, "/ui/../v1/proposals/x/approve", u.agent, strings.NewReader(`{"digest":"x"}`)); rec.Code == http.StatusOK {
		t.Errorf("approve through a /ui path must not succeed: %d", rec.Code)
	}
}

func TestUIDisabled(t *testing.T) {
	u := newUIEnv(t, func(c *config.Config) { c.DisableUI = true })
	if rec := rawGet(t, u.h, http.MethodGet, "/ui/", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled UI must not be served: %d", rec.Code)
	}
	if rec := rawGet(t, u.h, http.MethodGet, "/ui/", u.owner, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("disabled UI with token: %d, want 404", rec.Code)
	}
}

// API responses carry hardening headers, never CORS headers, and never
// render as a document even when the content is HTML.
func TestAPIHeadersAndNoCORS(t *testing.T) {
	u := newUIEnv(t, nil)
	for _, p := range []string{"/v1/head", "/v1/tree", "/v1/status", "/v1/file?path=notes/alpha.md", "/v1/search?q=alpha", "/v1/instructions", "/nope"} {
		rec := rawGet(t, u.h, http.MethodGet, p, u.reader, nil)
		h := rec.Header()
		for k, v := range map[string]string{
			"X-Content-Type-Options":  "nosniff",
			"Cache-Control":           "no-store",
			"Referrer-Policy":         "same-origin",
			"Content-Security-Policy": apiCSP,
			"X-Frame-Options":         "DENY",
		} {
			if got := h.Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", p, k, got, v)
			}
		}
		for k := range h {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("%s: unexpected CORS header %s", p, k)
			}
		}
	}
	// Preflight from another origin gets no CORS approval.
	rec := rawGet(t, u.h, http.MethodOptions, "/v1/proposals/x/approve", "", nil)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" || rec.Code == http.StatusOK || rec.Code == http.StatusNoContent {
		t.Errorf("preflight must not succeed: %d", rec.Code)
	}
}

// What the UI does with each token is decided by the API: a reader can
// browse but not see proposals; an agent cannot review, approve or reject.
func TestUIRolesEnforcedByAPI(t *testing.T) {
	u := newUIEnv(t, nil)
	s := u.propose(agent1, "ui test", put("notes/new.md", md("new", "<script>alert(1)</script>​")))
	id, digest := s.ID, s.Digest
	for _, p := range []string{"/v1/tree", "/v1/file?path=notes/alpha.md", "/v1/search?q=alpha", "/v1/status"} {
		if rec := rawGet(t, u.h, http.MethodGet, p, u.reader, nil); rec.Code != http.StatusOK {
			t.Errorf("reader %s: %d", p, rec.Code)
		}
	}
	if rec := rawGet(t, u.h, http.MethodGet, "/v1/proposals?state=pending", u.reader, nil); rec.Code != http.StatusForbidden {
		t.Errorf("reader list: %d", rec.Code)
	}
	for _, tok := range []string{u.reader, u.agent} {
		if rec := rawGet(t, u.h, http.MethodGet, "/v1/proposals/"+id+"/review", tok, nil); rec.Code != http.StatusForbidden {
			t.Errorf("review with non-approver: %d", rec.Code)
		}
		body := `{"digest":"` + digest + `"}`
		if rec := rawGet(t, u.h, http.MethodPost, "/v1/proposals/"+id+"/approve", tok, strings.NewReader(body)); rec.Code != http.StatusForbidden {
			t.Errorf("approve with non-approver: %d", rec.Code)
		}
		if rec := rawGet(t, u.h, http.MethodPost, "/v1/proposals/"+id+"/reject", tok, strings.NewReader(`{"reason":"x"}`)); rec.Code != http.StatusForbidden {
			t.Errorf("reject with non-approver: %d", rec.Code)
		}
	}
	// The owner's review shows the HTML as escaped data in JSON, with the
	// invisible character escaped by the server.
	rec := rawGet(t, u.h, http.MethodGet, "/v1/proposals/"+id+"/review", u.owner, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("owner review: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("review content type %q", ct)
	}
	var rv struct {
		Summary struct{ Digest string }
		Files   []struct{ Diff string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rv); err != nil {
		t.Fatal(err)
	}
	if rv.Summary.Digest != digest || len(rv.Files) != 1 {
		t.Fatalf("review: %+v", rv)
	}
	if !strings.Contains(rv.Files[0].Diff, `<script>alert(1)</script>\u{200b}`) {
		t.Errorf("diff must carry the raw text with the invisible character escaped: %q", rv.Files[0].Diff)
	}
	// A wrong digest (what a stale page would send) applies nothing.
	bad := `{"digest":"` + strings.Repeat("0", 64) + `"}`
	if rec := rawGet(t, u.h, http.MethodPost, "/v1/proposals/"+id+"/approve", u.owner, strings.NewReader(bad)); rec.Code == http.StatusOK {
		t.Fatal("approve with a different digest must fail")
	}
	ok := `{"digest":"` + digest + `"}`
	if rec := rawGet(t, u.h, http.MethodPost, "/v1/proposals/"+id+"/approve", u.owner, strings.NewReader(ok)); rec.Code != http.StatusOK {
		t.Fatalf("approve with the shown digest: %d %s", rec.Code, rec.Body.String())
	}
}
