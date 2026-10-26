package server

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"trove/internal/auth"
	"trove/internal/store"
)

const (
	browserAuthFile     = "browser-auth.json"
	accessCookie        = "__Host-trove-access"
	refreshCookie       = "__Host-trove-refresh"
	csrfCookie          = "__Host-trove-csrf"
	accessLifetime      = 10 * time.Minute
	refreshLifetime     = 7 * 24 * time.Hour
	refreshRetryWindow  = 5 * time.Second
	passwordMemory      = 19 * 1024
	passwordIterations  = 2
	passwordParallelism = 1
)

type passwordRecord struct {
	Salt string `json:"salt"`
	Hash string `json:"hash"`
}

type browserSession struct {
	ID             string    `json:"id"`
	AccessHash     string    `json:"access_hash"`
	RefreshHash    string    `json:"refresh_hash"`
	CSRFHash       string    `json:"csrf_hash"`
	UsedRefresh    []string  `json:"used_refresh,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	AccessExpires  time.Time `json:"access_expires"`
	RefreshExpires time.Time `json:"refresh_expires"`
}

type browserAuthState struct {
	Version  int                        `json:"version"`
	Owner    string                     `json:"owner,omitempty"`
	Password *passwordRecord            `json:"password,omitempty"`
	Sessions map[string]*browserSession `json:"sessions,omitempty"`
}

type browserTokens struct {
	Access         string
	Refresh        string
	CSRF           string
	AccessExpires  time.Time
	RefreshExpires time.Time
}

type refreshRetry struct {
	OldAccessHash string
	Tokens        browserTokens
	Until         time.Time
}

type loginWindow struct {
	Start time.Time
	Count int
}

// browserAuth holds one owner's credentials and opaque browser sessions.
// Persisted records contain password/token hashes, never raw credentials.
type browserAuth struct {
	mu           sync.Mutex
	path         string
	state        browserAuthState
	retries      map[string]refreshRetry
	attempts     map[string]loginWindow
	global       loginWindow
	passwordWork chan struct{}
}

func openBrowserAuth(dataDir string) (*browserAuth, error) {
	b := &browserAuth{
		path:         filepath.Join(dataDir, browserAuthFile),
		state:        browserAuthState{Version: 1, Sessions: map[string]*browserSession{}},
		retries:      map[string]refreshRetry{},
		attempts:     map[string]loginWindow{},
		passwordWork: make(chan struct{}, 2),
	}
	data, err := os.ReadFile(b.path)
	if errors.Is(err, os.ErrNotExist) {
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) > 16<<20 {
		return nil, errors.New("browser auth state is too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b.state); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("invalid browser auth state")
	}
	if b.state.Version != 1 || b.state.Password == nil || !auth.ValidName(b.state.Owner) {
		return nil, errors.New("invalid browser auth state")
	}
	if !validPasswordRecord(b.state.Password) {
		return nil, errors.New("invalid password hash")
	}
	if b.state.Sessions == nil {
		b.state.Sessions = map[string]*browserSession{}
	}
	if len(b.state.Sessions) > 16 {
		return nil, errors.New("too many browser sessions")
	}
	for id, s := range b.state.Sessions {
		if s == nil || s.ID != id || !store.ValidID(id) || !validHash(s.AccessHash) || !validHash(s.RefreshHash) || !validHash(s.CSRFHash) || len(s.UsedRefresh) > 2048 {
			return nil, errors.New("invalid browser session")
		}
		for _, hash := range s.UsedRefresh {
			if !validHash(hash) {
				return nil, errors.New("invalid refresh history")
			}
		}
	}
	return b, nil
}

func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validPasswordRecord(p *passwordRecord) bool {
	salt, e1 := base64.RawStdEncoding.DecodeString(p.Salt)
	hash, e2 := base64.RawStdEncoding.DecodeString(p.Hash)
	return e1 == nil && e2 == nil && len(salt) == 16 && len(hash) == 32
}

func passwordOK(password string) bool {
	n := utf8.RuneCountInString(password)
	return utf8.ValidString(password) && n >= 15 && n <= 128 && len(password) <= 1024
}

func makePassword(password string) (*passwordRecord, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	hash := argon2.IDKey([]byte(password), salt, passwordIterations, passwordMemory, passwordParallelism, 32)
	return &passwordRecord{Salt: base64.RawStdEncoding.EncodeToString(salt), Hash: base64.RawStdEncoding.EncodeToString(hash)}, nil
}

func verifyPassword(p *passwordRecord, password string) bool {
	if p == nil || len(password) > 1024 || !validPasswordRecord(p) {
		return false
	}
	salt, _ := base64.RawStdEncoding.DecodeString(p.Salt)
	want, _ := base64.RawStdEncoding.DecodeString(p.Hash)
	got := argon2.IDKey([]byte(password), salt, passwordIterations, passwordMemory, passwordParallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func tokenFamily(token string) string {
	id, secret, ok := strings.Cut(token, ".")
	if !ok || !store.ValidID(id) || len(secret) != 43 {
		return ""
	}
	return id
}

func equalHash(a, b string) bool {
	return len(a) == 64 && len(b) == 64 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (b *browserAuth) configured() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state.Password != nil
}

func (b *browserAuth) clone() browserAuthState {
	n := b.state
	n.Sessions = make(map[string]*browserSession, len(b.state.Sessions))
	for id, s := range b.state.Sessions {
		q := *s
		q.UsedRefresh = append([]string(nil), s.UsedRefresh...)
		n.Sessions[id] = &q
	}
	return n
}

func (b *browserAuth) save(n browserAuthState) error {
	data, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	if err := store.WriteFileAtomic(b.path, append(data, '\n')); err != nil {
		return err
	}
	b.state = n
	return nil
}

func (b *browserAuth) addSession(n *browserAuthState, now time.Time) (browserTokens, error) {
	for id, s := range n.Sessions {
		if !now.Before(s.RefreshExpires) {
			delete(n.Sessions, id)
		}
	}
	if len(n.Sessions) >= 16 {
		var oldest string
		var when time.Time
		for id, s := range n.Sessions {
			if oldest == "" || s.CreatedAt.Before(when) {
				oldest, when = id, s.CreatedAt
			}
		}
		delete(n.Sessions, oldest)
	}
	id, err := store.NewID()
	if err != nil {
		return browserTokens{}, err
	}
	a, err := randomSecret()
	if err != nil {
		return browserTokens{}, err
	}
	r, err := randomSecret()
	if err != nil {
		return browserTokens{}, err
	}
	c, err := randomSecret()
	if err != nil {
		return browserTokens{}, err
	}
	t := browserTokens{Access: id + "." + a, Refresh: id + "." + r, CSRF: c, AccessExpires: now.Add(accessLifetime), RefreshExpires: now.Add(refreshLifetime)}
	n.Sessions[id] = &browserSession{ID: id, AccessHash: auth.Hash(t.Access), RefreshHash: auth.Hash(t.Refresh), CSRFHash: auth.Hash(c), CreatedAt: now, AccessExpires: t.AccessExpires, RefreshExpires: t.RefreshExpires}
	return t, nil
}

func (b *browserAuth) setup(owner, password string) (browserTokens, error) {
	p, err := makePassword(password)
	if err != nil {
		return browserTokens{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state.Password != nil {
		return browserTokens{}, errors.New("owner account is already configured")
	}
	n := b.clone()
	n.Owner, n.Password = owner, p
	t, err := b.addSession(&n, time.Now())
	if err != nil {
		return browserTokens{}, err
	}
	if err := b.save(n); err != nil {
		return browserTokens{}, err
	}
	return t, nil
}

func (b *browserAuth) login(password string) (browserTokens, error) {
	b.mu.Lock()
	p := b.state.Password
	b.mu.Unlock()
	if p == nil || !verifyPassword(p, password) {
		return browserTokens{}, errors.New("invalid credentials")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// A concurrent password change invalidates this verification.
	if b.state.Password != p {
		return browserTokens{}, errors.New("invalid credentials")
	}
	n := b.clone()
	t, err := b.addSession(&n, time.Now())
	if err != nil {
		return browserTokens{}, err
	}
	if err := b.save(n); err != nil {
		return browserTokens{}, err
	}
	return t, nil
}

func requestCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func (b *browserAuth) access(r *http.Request) (auth.Actor, bool) {
	token := requestCookie(r, accessCookie)
	id := tokenFamily(token)
	if id == "" {
		return auth.Actor{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.state.Sessions[id]
	if s == nil || !time.Now().Before(s.AccessExpires) || !time.Now().Before(s.RefreshExpires) || !equalHash(s.AccessHash, auth.Hash(token)) {
		return auth.Actor{}, false
	}
	return auth.Actor{Name: b.state.Owner, Role: auth.RoleApprover}, true
}

func csrfMatches(r *http.Request, s *browserSession) bool {
	cookie := requestCookie(r, csrfCookie)
	header := r.Header.Get("X-Trove-CSRF")
	return len(cookie) == 43 && subtle.ConstantTimeCompare([]byte(cookie), []byte(header)) == 1 && equalHash(s.CSRFHash, auth.Hash(cookie))
}

func (b *browserAuth) csrf(r *http.Request) bool {
	token := requestCookie(r, accessCookie)
	id := tokenFamily(token)
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.state.Sessions[id]
	return s != nil && time.Now().Before(s.AccessExpires) && equalHash(s.AccessHash, auth.Hash(token)) && csrfMatches(r, s)
}

func (b *browserAuth) refresh(r *http.Request) (browserTokens, error) {
	token := requestCookie(r, refreshCookie)
	id := tokenFamily(token)
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.state.Sessions[id]
	if s == nil || !now.Before(s.RefreshExpires) || !csrfMatches(r, s) {
		return browserTokens{}, errors.New("invalid session")
	}
	hash := auth.Hash(token)
	if !equalHash(s.RefreshHash, hash) {
		// A browser can send an already in-flight refresh after another tab
		// rotated its cookies. Only the exact old access+refresh pair may
		// receive the same response during this short, in-memory retry window.
		if retry, ok := b.retries[hash]; ok && now.Before(retry.Until) && equalHash(retry.OldAccessHash, auth.Hash(requestCookie(r, accessCookie))) {
			return retry.Tokens, nil
		}
		for _, used := range s.UsedRefresh {
			if equalHash(used, hash) {
				n := b.clone()
				delete(n.Sessions, id)
				if err := b.save(n); err != nil {
					return browserTokens{}, err
				}
				break
			}
		}
		return browserTokens{}, errors.New("invalid session")
	}
	if len(s.UsedRefresh) >= 2048 {
		return browserTokens{}, errors.New("session has expired")
	}
	a, err := randomSecret()
	if err != nil {
		return browserTokens{}, err
	}
	next, err := randomSecret()
	if err != nil {
		return browserTokens{}, err
	}
	t := browserTokens{Access: id + "." + a, Refresh: id + "." + next, CSRF: requestCookie(r, csrfCookie), AccessExpires: now.Add(accessLifetime), RefreshExpires: s.RefreshExpires}
	n := b.clone()
	q := n.Sessions[id]
	q.UsedRefresh = append(q.UsedRefresh, hash)
	q.AccessHash, q.RefreshHash = auth.Hash(t.Access), auth.Hash(t.Refresh)
	q.AccessExpires = t.AccessExpires
	if err := b.save(n); err != nil {
		return browserTokens{}, err
	}
	for key, retry := range b.retries {
		if !now.Before(retry.Until) {
			delete(b.retries, key)
		}
	}
	b.retries[hash] = refreshRetry{OldAccessHash: s.AccessHash, Tokens: t, Until: now.Add(refreshRetryWindow)}
	return t, nil
}

func (b *browserAuth) logout(r *http.Request, all bool) error {
	token := requestCookie(r, refreshCookie)
	id := tokenFamily(token)
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.state.Sessions[id]
	if s == nil || !equalHash(s.RefreshHash, auth.Hash(token)) || !csrfMatches(r, s) {
		return errors.New("invalid session")
	}
	n := b.clone()
	if all {
		n.Sessions = map[string]*browserSession{}
	} else {
		delete(n.Sessions, id)
	}
	if err := b.save(n); err != nil {
		return err
	}
	b.retries = map[string]refreshRetry{}
	return nil
}

func (b *browserAuth) changePassword(r *http.Request, old, next string) error {
	b.mu.Lock()
	p := b.state.Password
	b.mu.Unlock()
	if !verifyPassword(p, old) {
		return errors.New("invalid credentials")
	}
	record, err := makePassword(next)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state.Password != p {
		return errors.New("invalid credentials")
	}
	token := requestCookie(r, accessCookie)
	s := b.state.Sessions[tokenFamily(token)]
	if s == nil || !equalHash(s.AccessHash, auth.Hash(token)) || !csrfMatches(r, s) {
		return errors.New("invalid session")
	}
	n := b.clone()
	n.Password = record
	n.Sessions = map[string]*browserSession{}
	if err := b.save(n); err != nil {
		return err
	}
	b.retries = map[string]refreshRetry{}
	return nil
}

func (b *browserAuth) allowAttempt(r *http.Request) bool {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Sub(b.global.Start) >= time.Minute {
		b.global = loginWindow{Start: now}
	}
	b.global.Count++
	if b.global.Count > 40 {
		return false
	}
	for key, window := range b.attempts {
		if now.Sub(window.Start) >= 15*time.Minute {
			delete(b.attempts, key)
		}
	}
	if len(b.attempts) >= 1024 {
		return false
	}
	window := b.attempts[ip]
	if window.Start.IsZero() {
		window.Start = now
	}
	window.Count++
	b.attempts[ip] = window
	return window.Count <= 8
}

func setBrowserCookies(w http.ResponseWriter, t browserTokens) {
	for _, c := range []*http.Cookie{
		{Name: accessCookie, Value: t.Access, Expires: t.AccessExpires, MaxAge: int(time.Until(t.AccessExpires).Seconds()), HttpOnly: true},
		{Name: refreshCookie, Value: t.Refresh, Expires: t.RefreshExpires, MaxAge: int(time.Until(t.RefreshExpires).Seconds()), HttpOnly: true},
		{Name: csrfCookie, Value: t.CSRF, Expires: t.RefreshExpires, MaxAge: int(time.Until(t.RefreshExpires).Seconds())},
	} {
		c.Path, c.Secure, c.SameSite = "/", true, http.SameSiteStrictMode
		http.SetCookie(w, c)
	}
}

func clearBrowserCookies(w http.ResponseWriter) {
	for _, name := range []string{accessCookie, refreshCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Secure: true, HttpOnly: name != csrfCookie, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	}
}

// authOrigin uses a configured external HTTPS origin, or HTTPS with the
// incoming Host. Forwarded headers are never trusted. A reverse proxy must
// preserve Host, or web_origin must be configured.
func (h *Handler) secureBrowserRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if r.Header.Get("X-Forwarded-Proto") != "https" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range h.cfg.WebTrustedProxies {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func (h *Handler) authOrigin(r *http.Request) bool {
	if !h.secureBrowserRequest(r) {
		return false
	}
	want := h.cfg.WebOrigin
	if want == "" {
		want = "https://" + r.Host
	}
	u, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.Scheme != "https" {
		return false
	}
	return u.String() == want
}

func authJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeErr(w, http.StatusUnsupportedMediaType, "JSON request required", nil)
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request", nil)
		return false
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		writeErr(w, http.StatusBadRequest, "invalid request", nil)
		return false
	}
	return true
}

func (h *Handler) handleBrowserAuth(w http.ResponseWriter, r *http.Request) {
	if h.browserErr != nil || h.browser == nil {
		writeErr(w, http.StatusServiceUnavailable, "browser authentication is unavailable", nil)
		return
	}
	b := h.browser
	if r.Method == http.MethodGet && r.URL.Path == "/auth/state" {
		writeJSON(w, http.StatusOK, map[string]any{"setup_required": !b.configured(), "https_required": true})
		return
	}
	if !h.secureBrowserRequest(r) {
		writeErr(w, http.StatusForbidden, "HTTPS is required for browser authentication", nil)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/auth/session" {
		actor, ok := b.access(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "login required", nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"actor": actor.Name, "role": actor.Role})
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusNotFound, "not found", nil)
		return
	}
	if !h.authOrigin(r) {
		writeErr(w, http.StatusForbidden, "HTTPS and a matching Origin are required", nil)
		return
	}
	switch r.URL.Path {
	case "/auth/setup", "/auth/login":
		if !b.allowAttempt(r) {
			w.Header().Set("Retry-After", "900")
			writeErr(w, http.StatusTooManyRequests, "too many login attempts; try again later", nil)
			return
		}
		select {
		case b.passwordWork <- struct{}{}:
			defer func() { <-b.passwordWork }()
		default:
			writeErr(w, http.StatusTooManyRequests, "authentication is busy; try again shortly", nil)
			return
		}
		var req struct {
			Password string `json:"password"`
			Confirm  string `json:"password_confirm"`
		}
		if !authJSON(w, r, &req) {
			return
		}
		var tokens browserTokens
		var err error
		if r.URL.Path == "/auth/setup" {
			if b.configured() {
				writeErr(w, http.StatusConflict, "owner account is already configured", nil)
				return
			}
			raw, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			actor, lookupErr := h.keys.Lookup(strings.TrimSpace(raw))
			if lookupErr != nil || actor.Role != auth.RoleApprover {
				writeErr(w, http.StatusUnauthorized, "invalid credentials", nil)
				return
			}
			if req.Password != req.Confirm || !passwordOK(req.Password) {
				writeErr(w, http.StatusBadRequest, "passwords must match and contain 15 to 128 characters", nil)
				return
			}
			tokens, err = b.setup(actor.Name, req.Password)
		} else {
			tokens, err = b.login(req.Password)
		}
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid credentials", nil)
			return
		}
		setBrowserCookies(w, tokens)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "/auth/refresh":
		tokens, err := b.refresh(r)
		if err != nil {
			clearBrowserCookies(w)
			writeErr(w, http.StatusUnauthorized, "session has expired; log in again", nil)
			return
		}
		setBrowserCookies(w, tokens)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "/auth/logout", "/auth/logout-all":
		if err := b.logout(r, r.URL.Path == "/auth/logout-all"); err != nil {
			clearBrowserCookies(w)
			writeErr(w, http.StatusUnauthorized, "login required", nil)
			return
		}
		clearBrowserCookies(w)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "/auth/password":
		if _, ok := b.access(r); !ok || !b.csrf(r) {
			writeErr(w, http.StatusUnauthorized, "login required", nil)
			return
		}
		if !b.allowAttempt(r) {
			writeErr(w, http.StatusTooManyRequests, "too many attempts; try again later", nil)
			return
		}
		select {
		case b.passwordWork <- struct{}{}:
			defer func() { <-b.passwordWork }()
		default:
			writeErr(w, http.StatusTooManyRequests, "authentication is busy; try again shortly", nil)
			return
		}
		var req struct {
			Current  string `json:"current_password"`
			Password string `json:"password"`
			Confirm  string `json:"password_confirm"`
		}
		if !authJSON(w, r, &req) {
			return
		}
		if req.Password != req.Confirm || !passwordOK(req.Password) {
			writeErr(w, http.StatusBadRequest, "passwords must match and contain 15 to 128 characters", nil)
			return
		}
		if err := b.changePassword(r, req.Current, req.Password); err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid credentials", nil)
			return
		}
		clearBrowserCookies(w)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeErr(w, http.StatusNotFound, "not found", nil)
	}
}

func (h *Handler) browserActor(w http.ResponseWriter, r *http.Request) (auth.Actor, bool) {
	if !h.secureBrowserRequest(r) {
		writeErr(w, http.StatusUnauthorized, "use HTTPS to sign in", nil)
		return auth.Actor{}, false
	}
	if h.browserErr != nil || h.browser == nil {
		writeErr(w, http.StatusServiceUnavailable, "browser authentication is unavailable", nil)
		return auth.Actor{}, false
	}
	actor, ok := h.browser.access(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "login required", nil)
		return auth.Actor{}, false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		if !h.authOrigin(r) || !h.browser.csrf(r) {
			writeErr(w, http.StatusForbidden, "invalid request origin or CSRF token", nil)
			return auth.Actor{}, false
		}
	}
	return actor, true
}

func (h *Handler) browserConfigured() bool {
	return h.browser != nil && h.browser.configured()
}

func (h *Handler) browserStartupError() error {
	if h.browserErr != nil {
		return fmt.Errorf("browser authentication: %w", h.browserErr)
	}
	return nil
}
