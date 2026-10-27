package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"trove/internal/api"
	"trove/internal/auth"
	"trove/internal/config"
	"trove/internal/store"
	"trove/internal/webui"
)

type ctxKey struct{}

// Handler is the HTTP API.
// rateLimiter allows a few log lines per interval and counts the rest.
type rateLimiter struct {
	mu         sync.Mutex
	window     time.Time
	n          int
	suppressed int
}

const logPerMinute = 10

// allow reports whether a line may be written now, and how many were
// suppressed since the last written one.
func (l *rateLimiter) allow(now time.Time) (int, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if m := now.Truncate(time.Minute); !m.Equal(l.window) {
		l.window, l.n = m, 0
	}
	if l.n >= logPerMinute {
		l.suppressed++
		return 0, false
	}
	l.n++
	s := l.suppressed
	l.suppressed = 0
	return s, true
}

type Handler struct {
	unknown    rateLimiter
	e          *Engine
	keys       *auth.Keyring
	cfg        config.Config
	log        *log.Logger
	mux        *http.ServeMux
	browser    *browserAuth
	browserErr error
}

// NewHandler builds the HTTP handler.
func NewHandler(e *Engine, keys *auth.Keyring, logger *log.Logger) *Handler {
	if logger == nil {
		logger = log.New(os.Stderr, "trove: ", log.LstdFlags)
	}
	h := &Handler{e: e, keys: keys, cfg: e.cfg, log: logger, mux: http.NewServeMux()}
	h.browser, h.browserErr = openBrowserAuth(e.cfg.DataDir)
	m := h.mux
	m.HandleFunc("GET /v1/head", h.head)
	m.HandleFunc("GET /v1/snapshot", h.snapshot)
	m.HandleFunc("GET /v1/tree", h.tree)
	m.HandleFunc("GET /v1/file", h.file)
	m.HandleFunc("GET /v1/search", h.search)
	m.HandleFunc("GET /v1/instructions", h.instructions)
	m.HandleFunc("GET /v1/status", h.status)
	m.HandleFunc("GET /v1/proposals", h.list)
	m.HandleFunc("POST /v1/proposals", h.begin)
	m.HandleFunc("GET /v1/proposals/{id}", h.get)
	m.HandleFunc("GET /v1/proposals/{id}/review", h.review)
	m.HandleFunc("POST /v1/proposals/{id}/changes", h.change)
	m.HandleFunc("POST /v1/proposals/{id}/submit", h.submit)
	m.HandleFunc("POST /v1/proposals/{id}/abort", h.abort)
	m.HandleFunc("POST /v1/proposals/{id}/rebase", h.rebase)
	m.HandleFunc("POST /v1/proposals/{id}/approve", h.approve)
	m.HandleFunc("POST /v1/proposals/{id}/reject", h.reject)
	m.HandleFunc("POST /v1/import", h.importKB)
	m.HandleFunc("GET /v1/audit/verify", h.verify)
	return h
}

// apiCSP forbids everything for API responses: a JSON or markdown body
// must never be rendered or executed as a document.
const apiCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox"

// ServeHTTP authenticates every request, then dispatches it.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Shared hardening headers (nosniff, no-referrer, no-store, no
	// framing); the UI sets its own, stricter CSP for its pages.
	webui.SetSecurityHeaders(w.Header())
	if !h.cfg.DisableUI && webui.Match(r.URL.Path) {
		// Static files only, no token needed: every action the UI takes
		// is a request to /v1 below, authenticated by the browser session.
		webui.Handler().ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Security-Policy", apiCSP)
	if r.URL.Path == "/healthz" {
		w.Write([]byte("ok\n"))
		return
	}
	if strings.HasPrefix(r.URL.Path, "/auth/") {
		h.handleBrowserAuth(w, r)
		return
	}
	var actor auth.Actor
	if authorization := r.Header.Get("Authorization"); authorization != "" {
		token, ok := strings.CutPrefix(authorization, "Bearer ")
		if !ok {
			writeErr(w, http.StatusUnauthorized, "invalid authorization header", nil)
			return
		}
		var err error
		actor, err = h.keys.Lookup(strings.TrimSpace(token))
		if err != nil {
			if n, ok := h.unknown.allow(time.Now()); ok {
				h.log.Printf("rejected request with unknown token from %q %q %q (%d similar suppressed)", r.RemoteAddr, r.Method, r.URL.Path, n)
			}
			writeErr(w, http.StatusUnauthorized, "invalid token", nil)
			return
		}
		// Once the owner has migrated to browser password authentication,
		// a raw approver token cannot bypass the UI decision path.
		if actor.Role == auth.RoleApprover && (h.browserErr != nil || h.browserConfigured()) &&
			strings.HasPrefix(r.URL.Path, "/v1/proposals/") &&
			(strings.HasSuffix(r.URL.Path, "/approve") || strings.HasSuffix(r.URL.Path, "/reject")) {
			writeErr(w, http.StatusForbidden, "use the owner browser session to approve or reject", nil)
			return
		}
	} else {
		var ok bool
		actor, ok = h.browserActor(w, r)
		if !ok {
			return
		}
	}
	h.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, actor)))
}

func actorOf(r *http.Request) auth.Actor {
	a, _ := r.Context().Value(ctxKey{}).(auth.Actor)
	return a
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string, details []string) {
	writeJSON(w, status, api.ErrorResp{Error: msg, Details: details})
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	var ee *Error
	if !errors.As(err, &ee) {
		h.log.Printf("internal error: %q", err.Error())
		writeErr(w, http.StatusInternalServerError, "internal error", nil)
		return
	}
	status := http.StatusInternalServerError
	switch ee.Kind {
	case KindInvalid:
		status = http.StatusBadRequest
	case KindForbidden:
		status = http.StatusForbidden
	case KindNotFound:
		status = http.StatusNotFound
	case KindConflict:
		status = http.StatusConflict
	case KindLimit:
		status = http.StatusTooManyRequests
	}
	if status == http.StatusInternalServerError {
		h.log.Printf("internal error: %q", ee.Error())
	}
	writeErr(w, status, ee.Msg, ee.Details)
}

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error(), nil)
		return false
	}
	return true
}

const smallBody = 64 << 10

func (h *Handler) head(w http.ResponseWriter, r *http.Request) {
	c, err := h.e.Head()
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, api.HeadResp{Commit: c})
}

// snapshot streams a tar of HEAD (or of ?commit=, which must be in HEAD history).
func (h *Handler) snapshot(w http.ResponseWriter, r *http.Request) {
	head, err := h.e.Head()
	if err != nil {
		h.fail(w, err)
		return
	}
	if head == "" {
		writeErr(w, http.StatusConflict, "the knowledge base is empty", nil)
		return
	}
	commit := head
	if q := r.URL.Query().Get("commit"); q != "" && q != head {
		if !ValidCommitID(q) {
			writeErr(w, http.StatusBadRequest, "commit must be a full commit id", nil)
			return
		}
		ctx, cancel := gitCtx()
		defer cancel()
		c, err := h.e.repo.ResolveCommit(ctx, q)
		if err != nil {
			writeErr(w, http.StatusNotFound, "unknown commit", nil)
			return
		}
		ok, err := h.e.repo.IsAncestor(ctx, c, head)
		if err != nil || !ok {
			writeErr(w, http.StatusNotFound, "commit is not in the knowledge base history", nil)
			return
		}
		commit = c
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("X-Trove-Commit", commit)
	if err := h.e.repo.Archive(r.Context(), commit, w); err != nil {
		h.log.Printf("snapshot: %q", err.Error())
	}
}

func (h *Handler) tree(w http.ResponseWriter, r *http.Request) {
	t, err := h.e.Tree(r.URL.Query().Get("prefix"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (h *Handler) file(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f, err := h.e.ReadFile(actorOf(r), q.Get("path"), q.Get("draft"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (h *Handler) search(w http.ResponseWriter, r *http.Request) {
	res, err := h.e.Search(r.URL.Query().Get("q"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) instructions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	io.WriteString(w, h.e.Instructions())
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	st, err := h.e.Status(actorOf(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	l, err := h.e.List(actorOf(r), r.URL.Query().Get("state"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (h *Handler) begin(w http.ResponseWriter, r *http.Request) {
	var req api.BeginReq
	if !h.decode(w, r, smallBody, &req) {
		return
	}
	s, err := h.e.Begin(actorOf(r), req)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	d, err := h.e.Get(actorOf(r), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (h *Handler) review(w http.ResponseWriter, r *http.Request) {
	rv, err := h.e.Review(actorOf(r), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rv)
}

// submitLimit allows for JSON escaping overhead on top of the content limit.
func (h *Handler) submitLimit() int64 {
	return int64(h.cfg.Limits.MaxTotalBytes)*6 + (1 << 20)
}

func (h *Handler) change(w http.ResponseWriter, r *http.Request) {
	var req api.ChangeReq
	if !h.decode(w, r, int64(h.cfg.Limits.MaxFileBytes)*6+smallBody, &req) {
		return
	}
	s, err := h.e.WriteChange(actorOf(r), r.PathValue("id"), req)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	var req api.SubmitReq
	if !h.decode(w, r, h.submitLimit(), &req) {
		return
	}
	var changes []store.Change
	if req.Changes != nil {
		changes = req.Changes
	}
	s, err := h.e.Submit(actorOf(r), r.PathValue("id"), changes)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *Handler) abort(w http.ResponseWriter, r *http.Request) {
	s, err := h.e.Abort(actorOf(r), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *Handler) rebase(w http.ResponseWriter, r *http.Request) {
	res, err := h.e.Rebase(actorOf(r), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (h *Handler) approve(w http.ResponseWriter, r *http.Request) {
	a := actorOf(r)
	if a.Role != auth.RoleApprover {
		// Checked again inside the engine; rejected here before reading the body.
		h.fail(w, h.e.deny(a, "approve", r.PathValue("id"), "only the approver token can approve"))
		return
	}
	var req api.ApproveReq
	if !h.decode(w, r, smallBody, &req) {
		return
	}
	res, err := h.e.Approve(a, r.PathValue("id"), req.Digest)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) reject(w http.ResponseWriter, r *http.Request) {
	var req api.RejectReq
	if !h.decode(w, r, smallBody, &req) {
		return
	}
	s, err := h.e.Reject(actorOf(r), r.PathValue("id"), req.Reason)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h *Handler) importKB(w http.ResponseWriter, r *http.Request) {
	a := actorOf(r)
	if a.Role != auth.RoleApprover {
		h.fail(w, h.e.deny(a, "import", "", "only the approver token can import"))
		return
	}
	body := http.MaxBytesReader(w, r.Body, h.cfg.Limits.MaxImportBytes)
	opt := ImportOptions{AllowSecretHistory: r.URL.Query().Get("allow_secret_history") == "1"}
	res, err := h.e.ImportWith(a, r.URL.Query().Get("mode"), body, opt)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	res, err := h.e.VerifyAudit(actorOf(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// Serve runs the HTTP server until ctx is cancelled.
func Serve(ctx context.Context, cfg config.Config, logger *log.Logger) error {
	if logger == nil {
		logger = log.New(os.Stderr, "trove: ", log.LstdFlags)
	}
	keys, err := auth.NewKeyring(cfg.Tokens)
	if err != nil {
		return err
	}
	if keys.Len() == 0 {
		return fmt.Errorf("no tokens configured")
	}
	e, err := Open(cfg, Options{})
	if err != nil {
		return err
	}
	defer e.Close()
	for _, w := range e.StartupWarnings {
		logger.Printf("WARNING: %q", w)
	}
	if cfg.TLSCert == "" && !isLoopback(cfg.Listen) {
		logger.Printf("WARNING: listening on %s without TLS; tokens travel in clear text unless the network (VPN, reverse proxy) protects them", cfg.Listen)
	}
	if cfg.WebRequireHTTPS {
		logger.Printf("browser sign-in: HTTPS only (web_require_https)")
	} else {
		logger.Printf("browser sign-in: plain HTTP allowed; passwords and session cookies are not encrypted on plain HTTP. Set web_require_https (TROVE_WEB_REQUIRE_HTTPS=1) for anything beyond a trusted network")
	}
	if cfg.WebAllowTailnetHTTP {
		logger.Printf("WARNING: web_allow_tailnet_http is deprecated and ignored; plain HTTP sign-in is allowed from any address unless web_require_https is set")
	}
	handler := NewHandler(e, keys, logger)
	if err := handler.browserStartupError(); err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    32 << 10,
	}
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				e.Expire()
			}
		}
	}()
	errc := make(chan error, 1)
	go func() {
		logger.Printf("listening on %s (data: %s)", cfg.Listen, cfg.DataDir)
		if cfg.TLSCert != "" {
			errc <- srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	}
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
