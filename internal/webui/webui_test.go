package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func get(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestAssetsServedWithHeaders(t *testing.T) {
	want := map[string]string{
		"/ui/":            "text/html; charset=utf-8",
		"/ui/index.html":  "text/html; charset=utf-8",
		"/ui/app.js":      "text/javascript; charset=utf-8",
		"/ui/md.js":       "text/javascript; charset=utf-8",
		"/ui/render.js":   "text/javascript; charset=utf-8",
		"/ui/app.css":     "text/css; charset=utf-8",
		"/ui/favicon.svg": "image/svg+xml",
	}
	for path, ct := range want {
		rec := get(t, http.MethodGet, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		h := rec.Header()
		if got := h.Get("Content-Type"); got != ct {
			t.Errorf("%s: content type %q, want %q", path, got, ct)
		}
		checks := map[string]string{
			"Content-Security-Policy": CSP,
			"X-Content-Type-Options":  "nosniff",
			"Referrer-Policy":         "same-origin",
			"X-Frame-Options":         "DENY",
			"Cache-Control":           "no-store",
		}
		for k, v := range checks {
			if got := h.Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", path, k, got, v)
			}
		}
		if rec.Body.Len() == 0 {
			t.Errorf("%s: empty body", path)
		}
	}
}

// The CSP is the main XSS backstop: every directive of the agreed policy
// must be present verbatim.
func TestCSPDirectives(t *testing.T) {
	for _, d := range []string{
		"default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'",
		"img-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'",
	} {
		if !strings.Contains(CSP, d) {
			t.Errorf("CSP lacks %q", d)
		}
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "data:", "*", "http:", "https:"} {
		if strings.Contains(CSP, bad) {
			t.Errorf("CSP must not contain %q", bad)
		}
	}
}

func TestUnknownPathsAndMethods(t *testing.T) {
	for _, p := range []string{"/ui/nope.js", "/ui/static/app.js", "/ui/../go.mod", "/ui/app.js/", "/ui/.env", "/ui/index.html.bak"} {
		if rec := get(t, http.MethodGet, p); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, rec.Code)
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
		rec := get(t, m, "/ui/")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", m, rec.Code)
		}
		if rec.Header().Get("Content-Security-Policy") != CSP {
			t.Errorf("%s: missing CSP on error response", m)
		}
	}
	rec := get(t, http.MethodGet, "/ui")
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/ui/" {
		t.Errorf("/ui must redirect to /ui/, got %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get(t, http.MethodHead, "/ui/app.js"); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD: %d, %d bytes", rec.Code, rec.Body.Len())
	}
}

func TestMatch(t *testing.T) {
	for p, want := range map[string]bool{"/ui": true, "/ui/": true, "/ui/app.js": true, "/uix": false, "/": false, "/v1/ui": false, "/healthz": false} {
		if Match(p) != want {
			t.Errorf("Match(%q) = %v", p, !want)
		}
	}
}

// Every embedded file is reachable and every served name is embedded.
func TestAssetTable(t *testing.T) {
	embedded := map[string]bool{}
	fs.WalkDir(files, "static", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			embedded[p] = true
		}
		return nil
	})
	served := map[string]bool{}
	for _, a := range assets {
		if !embedded[a.file] {
			t.Errorf("served file %s is not embedded", a.file)
		}
		served[a.file] = true
	}
	for f := range embedded {
		if !served[f] {
			t.Errorf("embedded file %s is not served", f)
		}
	}
}

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := files.ReadFile("static/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Regression guard for the XSS rules: no inline script or style in the
// page, no event handler attributes, only same-origin script and style.
func TestIndexHasNoInlineCode(t *testing.T) {
	html := read(t, "index.html")
	lower := strings.ToLower(html)
	if strings.Contains(lower, "<style") {
		t.Error("index.html must not contain a <style> element")
	}
	if regexp.MustCompile(`\sstyle\s*=`).MatchString(lower) {
		t.Error("index.html must not contain style attributes")
	}
	if m := regexp.MustCompile(`\son[a-z]+\s*=`).FindString(lower); m != "" {
		t.Errorf("index.html must not contain event handler attributes: %q", m)
	}
	for _, m := range regexp.MustCompile(`<script[^>]*>`).FindAllString(lower, -1) {
		if !strings.Contains(m, `src="`) {
			t.Errorf("inline script: %s", m)
		}
	}
	if strings.Count(lower, "<script") != strings.Count(lower, `<script type="module" src="`) {
		t.Error("every script must be an external module")
	}
	for _, m := range regexp.MustCompile(`(?:src|href)="([^"#]+)"`).FindAllStringSubmatch(html, -1) {
		if _, ok := assets[m[1]]; !ok {
			t.Errorf("index.html references %q, which is not served", m[1])
		}
	}
	if strings.Contains(lower, "<form") {
		t.Error("no forms: form-action is 'none' and requests are sent through fetch")
	}
	if strings.Contains(lower, "<img") || strings.Contains(lower, "<iframe") {
		t.Error("no images or frames in the page")
	}
}

// Regression guard for the rendering and token rules in the scripts.
func TestScriptsAvoidDangerousSinks(t *testing.T) {
	banned := []string{
		"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
		"localStorage", "document.cookie =", "document.cookie=", "setAttribute(\"on", "setAttribute('on", "srcdoc",
		"createContextualFragment", "DOMParser", "javascript:", "window.open", ".src =", "setTimeout(\"", "setInterval(\"",
		"http://", "https://", "import(",
	}
	for _, name := range []string{"app.js", "md.js", "render.js"} {
		src := read(t, name)
		code := stripComments(src)
		for _, b := range banned {
			if strings.Contains(code, b) {
				t.Errorf("%s contains %q", name, b)
			}
		}
	}
}

// Every href assignment must use a value built by the link rules:
// readHref (internal), res.url (passed safeExternal), or a review route.
func TestHrefAssignmentsAreSanitized(t *testing.T) {
	re := regexp.MustCompile(`\.href\s*=\s*([^;]+);`)
	allowed := []string{"readHref(", "res.url", `"#/review/" + encodeURIComponent(`, `"#/review"`}
	n := 0
	for _, name := range []string{"app.js", "render.js", "md.js"} {
		for _, m := range re.FindAllStringSubmatch(stripComments(read(t, name)), -1) {
			n++
			ok := false
			for _, a := range allowed {
				if strings.HasPrefix(strings.TrimSpace(m[1]), a) {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s: unsanitized href assignment: %s", name, m[0])
			}
		}
	}
	if n == 0 {
		t.Fatal("no href assignments found; the check is broken")
	}
	r := stripComments(read(t, "render.js"))
	if !strings.Contains(r, `if (res.kind === "external")`) || !strings.Contains(r, `a.rel = "noopener noreferrer nofollow"`) {
		t.Error("external links must be gated on safeExternal and use rel=noopener noreferrer")
	}
}

// Browser authentication stays in HttpOnly cookies. The one-time owner
// token is submitted only to setup, and no credential enters Web Storage.
func TestTokenHandling(t *testing.T) {
	app := stripComments(read(t, "app.js"))
	for _, forbidden := range []string{"localStorage", "sessionStorage", "state.token"} {
		if strings.Contains(app, forbidden) {
			t.Errorf("browser session code contains %q", forbidden)
		}
	}
	if strings.Count(app, `Authorization: "Bearer " + ownerToken`) != 1 || !strings.Contains(app, `authRequest("POST", "setup"`) {
		t.Error("the owner token must only authorize first setup")
	}
	if strings.Count(app, "fetch(") != 1 || !strings.Contains(app, "fetch(base + path, init)") {
		t.Error("all requests must go through the shared same-origin request function")
	}
	for _, want := range []string{`credentials: "same-origin"`, `redirect: "error"`, `referrerPolicy: "same-origin"`, `mode: "same-origin"`} {
		if !strings.Contains(app, want) {
			t.Errorf("fetch options lack %s", want)
		}
	}
	if !strings.Contains(app, `const API = "../v1/";`) || !strings.Contains(app, `const AUTH = "../auth/";`) {
		t.Error("API and auth bases must be relative")
	}
	if !strings.Contains(app, `__Host-trove-csrf=`) || !strings.Contains(app, `trove-http-csrf=`) || regexp.MustCompile(`document\.cookie\s*=`).MatchString(app) {
		t.Error("JavaScript may read only the CSRF cookie; it must not write cookies")
	}
	if strings.Contains(app, "approve all") || strings.Contains(strings.ToLower(app), "approveall") {
		t.Error("there must be no approve-all action")
	}
	if !strings.Contains(app, "{ digest: shown.digest }") {
		t.Error("approve must send the digest of the review on screen")
	}
}

// stripComments removes // line comments and /* */ blocks (good enough for
// our own files: no URLs or "//" inside string literals in code).
func stripComments(s string) string {
	s = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(s, "")
	return regexp.MustCompile(`(?m)^\s*//.*$`).ReplaceAllString(s, "")
}

// The sign-in form starts hidden so a signed-in user never sees it flash
// while the stored session is checked.
func TestLoginStartsHidden(t *testing.T) {
	html := read(t, "index.html")
	if !regexp.MustCompile(`<main id="login"[^>]*\shidden`).MatchString(html) {
		t.Error(`<main id="login"> must start hidden`)
	}
	js := read(t, "app.js")
	if strings.Contains(js, "lock(\"\");\n  loadAuthState(true)") {
		t.Error("boot must not call lock(\"\") before the session check")
	}
}
