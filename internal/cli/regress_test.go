package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trove/internal/audit"
)

func run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb)
	return code, out.String() + errb.String()
}

func clearTokenEnv(t *testing.T) {
	for _, k := range []string{"TROVE_TOKEN", "TROVE_TOKEN_FILE", "TROVE_APPROVER_TOKEN", "TROVE_APPROVER_TOKEN_FILE", "TROVE_URL", "TROVE_DIR", "TROVE_INSECURE_HTTP"} {
		t.Setenv(k, "")
	}
}

// A-6: approver commands never use TROVE_TOKEN (the agent's variable).
func TestRegressA6ApproverTokenSeparate(t *testing.T) {
	clearTokenEnv(t)
	t.Setenv("TROVE_TOKEN", "agent-token")
	t.Setenv("TROVE_URL", "http://127.0.0.1:1")
	for _, args := range [][]string{
		{"review"},
		{"approve", "0123456789abcdef0123456789abcdef", "--digest", strings.Repeat("a", 64)},
		{"reject", "0123456789abcdef0123456789abcdef", "no"},
		{"import", t.TempDir()},
		{"audit", "verify", "--remote"},
	} {
		code, out := run(t, args...)
		if code == 0 || !strings.Contains(out, "TROVE_APPROVER_TOKEN") {
			t.Errorf("%v must require the approver token variable, got %d %q", args, code, out)
		}
	}
}

// A-7: with the approver token, the URL never comes from the mirror state.
func TestRegressA7NoStateURLForApprover(t *testing.T) {
	clearTokenEnv(t)
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".trove"), 0o700)
	os.WriteFile(filepath.Join(dir, ".trove", "state.json"), []byte(`{"url":"https://attacker.example"}`), 0o600)
	t.Setenv("TROVE_DIR", dir)
	t.Setenv("TROVE_APPROVER_TOKEN", "owner-token")
	code, out := run(t, "review", "--dir", dir)
	if code == 0 || !strings.Contains(out, "explicit server URL") {
		t.Fatalf("approver command used the mirror URL: %d %q", code, out)
	}
	// Plain http to a non-loopback host is refused without --insecure-http.
	t.Setenv("TROVE_URL", "http://192.0.2.1:8470")
	code, out = run(t, "review")
	if code == 0 || !strings.Contains(out, "insecure-http") {
		t.Fatalf("token sent over plain http: %d %q", code, out)
	}
}

// B-11.1: trove mcp refuses an approver token.
func TestRegressMCPRefusesApprover(t *testing.T) {
	clearTokenEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"commit":"","actor":"owner","role":"approver"}`))
	}))
	defer srv.Close()
	t.Setenv("TROVE_URL", srv.URL)
	t.Setenv("TROVE_TOKEN", "owner-token-in-the-wrong-variable")
	code, out := run(t, "mcp")
	if code == 0 || !strings.Contains(out, "approver token") {
		t.Fatalf("mcp must refuse an approver token: %d %q", code, out)
	}
}

// B-10: error text is escaped before it reaches the terminal.
func TestRegressB10ErrorEscaped(t *testing.T) {
	clearTokenEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("{\"error\":\"evil \\u001b]0;owned\\u0007 text\"}"))
	}))
	defer srv.Close()
	t.Setenv("TROVE_URL", srv.URL)
	t.Setenv("TROVE_TOKEN", "x")
	_, out := run(t, "list")
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Fatalf("escape sequence reached the terminal: %q", out)
	}
}

// A-5: audit verify checks a saved last hash.
func TestRegressAuditExpectLast(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := audit.Open(p, time.Now)
	l.Append(audit.Entry{Actor: "a", Event: "e", Result: "ok"})
	res, _ := audit.VerifyFile(p)
	if code, out := run(t, "audit", "verify", "--file", p, "--expect-last", res.LastHash); code != 0 {
		t.Fatalf("valid anchor refused: %s", out)
	}
	if code, _ := run(t, "audit", "verify", "--file", p, "--expect-last", strings.Repeat("0", 64)); code == 0 {
		t.Fatal("unknown anchor accepted")
	}
}
