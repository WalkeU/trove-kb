package server

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trove/internal/config"
)

const testPassword = "correct horse battery staple"

type browserReq struct {
	method, url, remote, origin, body string
	headers                           map[string]string
	cookies                           []*http.Cookie
	tls                               bool
}

func (u *uiEnv) browser(t *testing.T, br browserReq) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if br.body != "" {
		req = httptest.NewRequest(br.method, br.url, strings.NewReader(br.body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(br.method, br.url, nil)
	}
	if br.remote != "" {
		req.RemoteAddr = br.remote
	}
	if br.origin != "" {
		req.Header.Set("Origin", br.origin)
	}
	for k, v := range br.headers {
		req.Header.Set(k, v)
	}
	for _, c := range br.cookies {
		req.AddCookie(c)
	}
	if br.tls {
		req.TLS = &tls.ConnectionState{}
	}
	rec := httptest.NewRecorder()
	u.h.ServeHTTP(rec, req)
	return rec
}

func setupBody() string {
	return `{"password":"` + testPassword + `","password_confirm":"` + testPassword + `"}`
}

func cookieMap(rec *httptest.ResponseRecorder) map[string]*http.Cookie {
	m := map[string]*http.Cookie{}
	for _, c := range rec.Result().Cookies() {
		m[c.Name] = c
	}
	return m
}

func authState(t *testing.T, rec *httptest.ResponseRecorder) (httpAllowed, httpsRequired bool) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("/auth/state: %d", rec.Code)
	}
	var st struct {
		HTTPAllowed   bool `json:"http_allowed"`
		HTTPSRequired bool `json:"https_required"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st.HTTPAllowed, st.HTTPSRequired
}

func checkCookies(t *testing.T, rec *httptest.ResponseRecorder, prefix string, secure bool) []*http.Cookie {
	t.Helper()
	m := cookieMap(rec)
	var out []*http.Cookie
	for _, kind := range []string{"access", "refresh", "csrf"} {
		c := m[prefix+kind]
		if c == nil || c.Value == "" {
			t.Fatalf("missing cookie %s%s; got %v", prefix, kind, m)
		}
		if c.Secure != secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.HttpOnly != (kind != "csrf") {
			t.Fatalf("cookie %s: secure=%v samesite=%v path=%q httponly=%v", c.Name, c.Secure, c.SameSite, c.Path, c.HttpOnly)
		}
		out = append(out, c)
	}
	return out
}

// Default: plain HTTP sign-in works from any source address (not only
// 100.64.0.0/10), with non-Secure trove-http-* cookies; Origin and CSRF
// checks are still enforced.
func TestPlainHTTPBrowserAuthDefault(t *testing.T) {
	u := newUIEnv(t, nil)
	const base, peer, origin = "http://trove.lan:8470", "192.0.2.10:51000", "http://trove.lan:8470"

	allowed, required := authState(t, u.browser(t, browserReq{method: http.MethodGet, url: base + "/auth/state", remote: peer}))
	if !allowed || required {
		t.Fatalf("state: http_allowed=%v https_required=%v", allowed, required)
	}

	// Origin is still required and must match scheme and host exactly.
	for _, bad := range []string{"", "https://trove.lan:8470", "http://evil.example", "http://trove.lan:8471", "null"} {
		rec := u.browser(t, browserReq{method: http.MethodPost, url: base + "/auth/setup", remote: peer, origin: bad, body: setupBody(), headers: map[string]string{"Authorization": "Bearer " + u.owner}})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("setup with Origin %q: %d, want 403", bad, rec.Code)
		}
	}
	// Setup still needs the owner's approver token.
	if rec := u.browser(t, browserReq{method: http.MethodPost, url: base + "/auth/setup", remote: peer, origin: origin, body: setupBody(), headers: map[string]string{"Authorization": "Bearer " + u.agent}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("setup with agent token: %d", rec.Code)
	}

	rec := u.browser(t, browserReq{method: http.MethodPost, url: base + "/auth/setup", remote: peer, origin: origin, body: setupBody(), headers: map[string]string{"Authorization": "Bearer " + u.owner}})
	if rec.Code != http.StatusOK {
		t.Fatalf("plain HTTP setup: %d %s", rec.Code, rec.Body.String())
	}
	cookies := checkCookies(t, rec, "trove-http-", false)
	for name := range cookieMap(rec) {
		if strings.HasPrefix(name, "__Host-") {
			t.Fatalf("plain HTTP must not set %s", name)
		}
	}

	// Login from a different, non-tailnet address also works.
	rec = u.browser(t, browserReq{method: http.MethodPost, url: base + "/auth/login", remote: "203.0.113.7:4000", origin: origin, body: `{"password":"` + testPassword + `"}`})
	if rec.Code != http.StatusOK {
		t.Fatalf("plain HTTP login: %d %s", rec.Code, rec.Body.String())
	}
	checkCookies(t, rec, "trove-http-", false)

	// Reads with the session cookie work.
	if rec := u.browser(t, browserReq{method: http.MethodGet, url: base + "/v1/head", remote: peer, cookies: cookies}); rec.Code != http.StatusOK {
		t.Fatalf("session read: %d %s", rec.Code, rec.Body.String())
	}
	if rec := u.browser(t, browserReq{method: http.MethodGet, url: base + "/auth/session", remote: peer, cookies: cookies}); rec.Code != http.StatusOK {
		t.Fatalf("/auth/session: %d", rec.Code)
	}

	// Mutations need the exact Origin and the CSRF header.
	s := u.propose(agent1, "browser reject", put("notes/new.md", md("new", "x")))
	reject := base + "/v1/proposals/" + s.ID + "/reject"
	csrf := cookies[2].Value
	for _, tc := range []struct {
		origin, csrf string
	}{
		{origin, ""},
		{origin, strings.Repeat("A", 43)},
		{"http://evil.example", csrf},
		{"https://trove.lan:8470", csrf},
		{"", csrf},
	} {
		rec := u.browser(t, browserReq{method: http.MethodPost, url: reject, remote: peer, origin: tc.origin, body: `{"reason":"x"}`, cookies: cookies, headers: map[string]string{"X-Trove-CSRF": tc.csrf}})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("reject origin=%q csrf=%q: %d, want 403", tc.origin, tc.csrf, rec.Code)
		}
	}
	if rec := u.browser(t, browserReq{method: http.MethodPost, url: reject, remote: peer, origin: origin, body: `{"reason":"x"}`, cookies: cookies, headers: map[string]string{"X-Trove-CSRF": csrf}}); rec.Code != http.StatusOK {
		t.Fatalf("reject with origin+csrf: %d %s", rec.Code, rec.Body.String())
	}

	// Session cookies from plain HTTP do not authenticate an HTTPS request.
	if rec := u.browser(t, browserReq{method: http.MethodGet, url: "https://trove.lan:8470/v1/head", remote: peer, cookies: cookies, tls: true}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("plain cookies over TLS: %d, want 401", rec.Code)
	}

	// Logout without CSRF fails; with CSRF it clears the plain cookies.
	if rec := u.browser(t, browserReq{method: http.MethodPost, url: base + "/auth/logout", remote: peer, origin: origin, cookies: cookies}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("logout without CSRF: %d", rec.Code)
	}
}

// With an explicit web_origin, plain HTTP must match it, not the Host header.
func TestPlainHTTPUsesConfiguredOrigin(t *testing.T) {
	u := newUIEnv(t, func(c *config.Config) { c.WebOrigin = "http://192.168.0.167:8470" })
	body, hdr := setupBody(), map[string]string{"Authorization": "Bearer " + u.owner}
	if rec := u.browser(t, browserReq{method: http.MethodPost, url: "http://evil.example/auth/setup", remote: "192.0.2.10:1", origin: "http://evil.example", body: body, headers: hdr}); rec.Code != http.StatusForbidden {
		t.Fatalf("Host-derived origin accepted despite web_origin: %d", rec.Code)
	}
	if rec := u.browser(t, browserReq{method: http.MethodPost, url: "http://trove:8470/auth/setup", remote: "192.0.2.10:1", origin: "http://192.168.0.167:8470", body: body, headers: hdr}); rec.Code != http.StatusOK {
		t.Fatalf("configured origin: %d %s", rec.Code, rec.Body.String())
	}
}

// web_require_https: plain HTTP is refused everywhere, from any address.
func TestRequireHTTPSRefusesPlainHTTP(t *testing.T) {
	u := newUIEnv(t, func(c *config.Config) { c.WebRequireHTTPS = true })
	const base, peer = "http://trove.lan:8470", "192.0.2.10:51000"
	allowed, required := authState(t, u.browser(t, browserReq{method: http.MethodGet, url: base + "/auth/state", remote: peer}))
	if allowed || !required {
		t.Fatalf("state: http_allowed=%v https_required=%v", allowed, required)
	}
	for _, remote := range []string{peer, "100.64.0.5:1234", "127.0.0.1:1234"} {
		rec := u.browser(t, browserReq{method: http.MethodPost, url: base + "/auth/setup", remote: remote, origin: "http://trove.lan:8470", body: setupBody(), headers: map[string]string{"Authorization": "Bearer " + u.owner}})
		if rec.Code != http.StatusForbidden || len(rec.Result().Cookies()) != 0 {
			t.Fatalf("setup over HTTP from %s: %d, want 403 without cookies", remote, rec.Code)
		}
	}
	if rec := u.browser(t, browserReq{method: http.MethodGet, url: base + "/v1/head", remote: peer}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie-less /v1 over HTTP: %d", rec.Code)
	}
	if u.h.browserConfigured() {
		t.Fatal("setup must not have happened")
	}
	// Direct TLS still works with __Host- Secure cookies.
	rec := u.browser(t, browserReq{method: http.MethodPost, url: "https://trove.lan/auth/setup", remote: peer, origin: "https://trove.lan", body: setupBody(), headers: map[string]string{"Authorization": "Bearer " + u.owner}, tls: true})
	if rec.Code != http.StatusOK {
		t.Fatalf("TLS setup: %d %s", rec.Code, rec.Body.String())
	}
	checkCookies(t, rec, "__Host-trove-", true)
}

// X-Forwarded-Proto: https from a peer outside web_trusted_proxies is
// refused rather than treated as either HTTPS or plain HTTP.
func TestForwardedProtoFromUntrustedPeerRejected(t *testing.T) {
	u := newUIEnv(t, func(c *config.Config) { c.WebTrustedProxies = []string{"10.9.9.9/32"} })
	xfp := map[string]string{"X-Forwarded-Proto": "https", "Authorization": "Bearer " + u.owner}
	allowed, _ := authState(t, u.browser(t, browserReq{method: http.MethodGet, url: "http://trove.lan/auth/state", remote: "192.0.2.10:1", headers: xfp}))
	if allowed {
		t.Fatal("http_allowed with a forwarded https claim")
	}
	for _, origin := range []string{"https://trove.lan", "http://trove.lan"} {
		rec := u.browser(t, browserReq{method: http.MethodPost, url: "http://trove.lan/auth/setup", remote: "192.0.2.10:1", origin: origin, body: setupBody(), headers: xfp})
		if rec.Code != http.StatusForbidden || len(rec.Result().Cookies()) != 0 {
			t.Fatalf("untrusted XFP with Origin %s: %d, want 403", origin, rec.Code)
		}
	}
}

// HTTPS through a trusted proxy keeps Secure __Host- cookies, also when
// web_require_https is on.
func TestTrustedProxyHTTPSUsesHostCookies(t *testing.T) {
	for _, require := range []bool{false, true} {
		u := newUIEnv(t, func(c *config.Config) {
			c.WebTrustedProxies = []string{"172.18.0.1/32"}
			c.WebOrigin = "https://trove.example.com"
			c.WebRequireHTTPS = require
		})
		hdr := map[string]string{"X-Forwarded-Proto": "https", "Authorization": "Bearer " + u.owner}
		rec := u.browser(t, browserReq{method: http.MethodPost, url: "http://trove:8470/auth/setup", remote: "172.18.0.1:5555", origin: "https://trove.example.com", body: setupBody(), headers: hdr})
		if rec.Code != http.StatusOK {
			t.Fatalf("require=%v proxy setup: %d %s", require, rec.Code, rec.Body.String())
		}
		cookies := checkCookies(t, rec, "__Host-trove-", true)
		for name := range cookieMap(rec) {
			if strings.HasPrefix(name, "trove-http-") {
				t.Fatalf("HTTPS must not set %s", name)
			}
		}
		if rec := u.browser(t, browserReq{method: http.MethodGet, url: "http://trove:8470/v1/head", remote: "172.18.0.1:5555", cookies: cookies, headers: map[string]string{"X-Forwarded-Proto": "https"}}); rec.Code != http.StatusOK {
			t.Fatalf("require=%v proxy session read: %d", require, rec.Code)
		}
	}
}

func TestRootRedirectsBrowsersToUI(t *testing.T) {
	u := newUIEnv(t, nil)
	const peer = "192.0.2.10:51000"

	rec := u.browser(t, browserReq{method: http.MethodGet, url: "http://trove.lan:8470/", remote: peer, headers: map[string]string{"Accept": "text/html,application/xhtml+xml"}})
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/ui/" {
		t.Fatalf("browser GET /: %d Location=%q, want 302 /ui/", rec.Code, rec.Header().Get("Location"))
	}
	// API clients keep the normal answer.
	for _, accept := range []string{"", "application/json", "*/*"} {
		rec := u.browser(t, browserReq{method: http.MethodGet, url: "http://trove.lan:8470/", remote: peer, headers: map[string]string{"Accept": accept}})
		if rec.Code == http.StatusFound {
			t.Fatalf("GET / with Accept %q must not redirect", accept)
		}
	}
}
