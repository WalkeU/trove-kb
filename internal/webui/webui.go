// Package webui serves the built-in browser UI: static HTML, CSS and
// JavaScript embedded into the binary. The UI has no server-side logic of
// its own; every action is a request to the existing /v1 API with the
// token the user pasted into the page.
package webui

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed static/index.html static/app.css static/app.js static/md.js static/render.js static/favicon.svg
var files embed.FS

// Prefix is the URL path the UI is served under.
const Prefix = "/ui/"

// CSP is the Content-Security-Policy of every UI response. No inline
// script or style, no external origin, no frames, no forms, no plugins.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// assets maps the served name to the embedded file and its content type.
// Only these names exist; there is no directory listing and no fallback.
var assets = map[string]struct{ file, ctype string }{
	"":            {"static/index.html", "text/html; charset=utf-8"},
	"index.html":  {"static/index.html", "text/html; charset=utf-8"},
	"app.css":     {"static/app.css", "text/css; charset=utf-8"},
	"app.js":      {"static/app.js", "text/javascript; charset=utf-8"},
	"md.js":       {"static/md.js", "text/javascript; charset=utf-8"},
	"render.js":   {"static/render.js", "text/javascript; charset=utf-8"},
	"favicon.svg": {"static/favicon.svg", "image/svg+xml"},
}

// SetSecurityHeaders writes the headers shared by the UI and the API.
func SetSecurityHeaders(h http.Header) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
}

// Handler serves the UI under Prefix ("/ui" redirects to "/ui/").
func Handler() http.Handler {
	return http.HandlerFunc(serve)
}

// Match reports whether a request path belongs to the UI.
func Match(path string) bool {
	return path == "/ui" || strings.HasPrefix(path, Prefix)
}

func serve(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	SetSecurityHeaders(h)
	h.Set("Content-Security-Policy", CSP)
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/ui" {
		http.Redirect(w, r, Prefix, http.StatusMovedPermanently)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, Prefix)
	a, ok := assets[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := files.ReadFile(a.file)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.Set("Content-Type", a.ctype)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	w.Write(b)
}
