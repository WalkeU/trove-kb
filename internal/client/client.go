// Package client talks to a Trove server and manages the local mirror.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"trove/internal/api"
	"trove/internal/safe"
	"trove/internal/store"
)

// Client is an HTTP API client.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// CheckTransport refuses to send a token over plain http to anything but
// a loopback address, unless insecure is set (for example inside a VPN or
// tailnet, where http is an explicit, documented choice).
func CheckTransport(raw string, insecure bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid server URL %s", safe.Line(raw, 200))
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		if insecure {
			return nil
		}
		return fmt.Errorf("refusing to send the token over plain http to %s; use https, or pass --insecure-http (TROVE_INSECURE_HTTP=1) if the network is protected", safe.Line(host, 200))
	}
	return fmt.Errorf("unsupported URL scheme %q", safe.Line(u.Scheme, 20))
}

// New returns a client. The token is sent as a bearer token.
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTP: &http.Client{
			Timeout: 10 * time.Minute,
			// Never follow redirects: Go would forward the Authorization
			// header on a same-host https->http redirect (C-12). The API
			// never redirects, so a 3xx is reported as an error.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// APIError is a non-2xx response.
type APIError struct {
	Status  int
	Message string
	Details []string
}

func (e *APIError) Error() string {
	// Server text is untrusted for the terminal (compromised server, proxy).
	s := fmt.Sprintf("server: %s (HTTP %d)", safe.Line(e.Message, 500), e.Status)
	for _, d := range e.Details {
		s += "\n  - " + safe.Line(d, 500)
	}
	return s
}

func (c *Client) request(method, path string, q url.Values, body io.Reader, contentType string) (*http.Response, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("no server URL (set TROVE_URL or --url)")
	}
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		var er api.ErrorResp
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if json.Unmarshal(data, &er) != nil || er.Error == "" {
			er.Error = strings.TrimSpace(string(data))
		}
		return nil, &APIError{Status: resp.StatusCode, Message: er.Error, Details: er.Details}
	}
	return resp, nil
}

func (c *Client) call(method, path string, q url.Values, in, out any) error {
	var body io.Reader
	ct := ""
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
		ct = "application/json"
	}
	resp, err := c.request(method, path, q, body, ct)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		_, err = io.Copy(io.Discard, resp.Body)
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func pid(id string) string { return "/v1/proposals/" + url.PathEscape(id) }

// Head returns the current commit.
func (c *Client) Head() (string, error) {
	var h api.HeadResp
	err := c.call("GET", "/v1/head", nil, nil, &h)
	return h.Commit, err
}

// Snapshot opens a tar stream of HEAD (or of commit, if set). The caller
// closes the returned reader.
func (c *Client) Snapshot(commit string) (string, io.ReadCloser, error) {
	q := url.Values{}
	if commit != "" {
		q.Set("commit", commit)
	}
	resp, err := c.request("GET", "/v1/snapshot", q, nil, "")
	if err != nil {
		return "", nil, err
	}
	got := resp.Header.Get("X-Trove-Commit")
	if got == "" {
		resp.Body.Close()
		return "", nil, fmt.Errorf("server did not send X-Trove-Commit")
	}
	return got, resp.Body, nil
}

// Status returns the server status for this token.
func (c *Client) Status() (api.StatusResp, error) {
	var s api.StatusResp
	err := c.call("GET", "/v1/status", nil, nil, &s)
	return s, err
}

// Begin opens a draft.
func (c *Client) Begin(req api.BeginReq) (api.Summary, error) {
	var s api.Summary
	err := c.call("POST", "/v1/proposals", nil, req, &s)
	return s, err
}

// WriteChange writes or deletes one file in a server-side draft.
func (c *Client) WriteChange(id string, req api.ChangeReq) (api.Summary, error) {
	var s api.Summary
	err := c.call("POST", pid(id)+"/changes", nil, req, &s)
	return s, err
}

// Submit freezes a draft. nil changes means "use the server-side draft".
func (c *Client) Submit(id string, changes []store.Change) (api.Summary, error) {
	var s api.Summary
	err := c.call("POST", pid(id)+"/submit", nil, api.SubmitReq{Changes: changes}, &s)
	return s, err
}

// Abort withdraws a draft or proposal.
func (c *Client) Abort(id string) (api.Summary, error) {
	var s api.Summary
	err := c.call("POST", pid(id)+"/abort", nil, struct{}{}, &s)
	return s, err
}

// Rebase supersedes a stale proposal with a new draft.
func (c *Client) Rebase(id string) (api.RebaseResp, error) {
	var r api.RebaseResp
	err := c.call("POST", pid(id)+"/rebase", nil, struct{}{}, &r)
	return r, err
}

// List returns visible proposals ("" = open, "all", or a state).
func (c *Client) List(state string) ([]api.Summary, error) {
	q := url.Values{}
	if state != "" {
		q.Set("state", state)
	}
	var l []api.Summary
	err := c.call("GET", "/v1/proposals", q, nil, &l)
	return l, err
}

// Get returns a proposal with content.
func (c *Client) Get(id string) (api.Detail, error) {
	var d api.Detail
	err := c.call("GET", pid(id), nil, nil, &d)
	return d, err
}

// Review returns the review rendering (approver).
func (c *Client) Review(id string) (api.ReviewResp, error) {
	var r api.ReviewResp
	err := c.call("GET", pid(id)+"/review", nil, nil, &r)
	return r, err
}

// Approve applies a proposal (approver, digest required).
func (c *Client) Approve(id, digest string) (api.ApproveResp, error) {
	var r api.ApproveResp
	err := c.call("POST", pid(id)+"/approve", nil, api.ApproveReq{Digest: digest}, &r)
	return r, err
}

// Reject closes a proposal (approver).
func (c *Client) Reject(id, reason string) (api.Summary, error) {
	var s api.Summary
	err := c.call("POST", pid(id)+"/reject", nil, api.RejectReq{Reason: reason}, &s)
	return s, err
}

// Import uploads a tar or bundle (approver, empty server only).
func (c *Client) Import(mode string, allowSecretHistory bool, body io.Reader) (api.ImportResp, error) {
	q := url.Values{"mode": {mode}}
	if allowSecretHistory {
		q.Set("allow_secret_history", "1")
	}
	resp, err := c.request("POST", "/v1/import", q, body, "application/octet-stream")
	if err != nil {
		return api.ImportResp{}, err
	}
	defer resp.Body.Close()
	var r api.ImportResp
	err = json.NewDecoder(resp.Body).Decode(&r)
	return r, err
}

// Instructions returns the agent instructions text.
func (c *Client) Instructions() (string, error) {
	resp, err := c.request("GET", "/v1/instructions", nil, nil, "")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b), err
}

// Tree lists files at HEAD.
func (c *Client) Tree(prefix string) (api.TreeResp, error) {
	q := url.Values{}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	var t api.TreeResp
	err := c.call("GET", "/v1/tree", q, nil, &t)
	return t, err
}

// ReadFile reads a file at HEAD or through a draft.
func (c *Client) ReadFile(path, draft string) (api.FileResp, error) {
	q := url.Values{"path": {path}}
	if draft != "" {
		q.Set("draft", draft)
	}
	var f api.FileResp
	err := c.call("GET", "/v1/file", q, nil, &f)
	return f, err
}

// Search searches HEAD.
func (c *Client) Search(query string) (api.SearchResp, error) {
	var s api.SearchResp
	err := c.call("GET", "/v1/search", url.Values{"q": {query}}, nil, &s)
	return s, err
}

// VerifyAudit asks the server to verify its audit log (approver).
func (c *Client) VerifyAudit() (api.VerifyResp, error) {
	var v api.VerifyResp
	err := c.call("GET", "/v1/audit/verify", nil, nil, &v)
	return v, err
}
