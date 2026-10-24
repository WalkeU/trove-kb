package server

// Regression tests for the re-verification reviews (C-n: approval path,
// D-n: input handling). Each test reproduces the proof of concept and
// fails on the code before the fix.

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trove/internal/api"
	"trove/internal/auth"
	"trove/internal/config"
	"trove/internal/store"
)

// C-1: a case-twin folder pair inside one proposal is refused.
func TestRegressC1FolderTwinInOneProposal(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	d, _ := ev.e.Begin(agent1, api.BeginReq{Topic: "two notes"})
	_, err := ev.e.Submit(agent1, d.ID, []store.Change{
		put("notes/Sub/a.md", md("a", "A")),
		put("notes/sub/b.md", md("b", "B")),
	})
	wantKind(t, err, KindInvalid)
	// File and folder in one proposal, in any letter case.
	_, err = ev.e.Submit(agent1, d.ID, []store.Change{
		put("notes/X.md", md("a", "A")),
		put("notes/x.md/y.md", md("b", "B")),
	})
	wantKind(t, err, KindInvalid)
}

// C-2: a proposal that no longer fits HEAD (sibling case-twin folder
// created since its base) is shown stale and can be rebased.
func TestRegressC2SiblingFolderTwinNotStuck(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	a := ev.propose(agent1, "a", put("notes/Sub/x.md", md("x", "X")))
	b := ev.propose(agent2, "b", put("notes/sub/y.md", md("y", "Y")))
	if _, err := ev.e.Approve(owner, a.ID, a.Digest); err != nil {
		t.Fatal(err)
	}
	g, _ := ev.e.Get(owner, b.ID)
	if g.Status != "stale" {
		t.Fatalf("B must be shown stale, got %q", g.Status)
	}
	_, err := ev.e.Approve(owner, b.ID, b.Digest)
	wantKind(t, err, KindConflict)
	if _, err := ev.e.Rebase(agent2, b.ID); err != nil {
		t.Fatalf("B must be rebasable: %v", err)
	}
}

// C-3: bytes written into a draft opened more than 24 hours ago count.
func TestRegressC3QuotaOldDraft(t *testing.T) {
	ev := newEnv(t, func(c *config.Config) { c.Limits.AgentBytesPerDay = 1 << 20 }, defaultFiles())
	d, err := ev.e.Begin(agent1, api.BeginReq{Topic: "old draft"})
	if err != nil {
		t.Fatal(err)
	}
	ev.clock.Advance(25 * time.Hour)
	body := md("x", strings.Repeat("z", 250<<10))
	ok := 0
	for i := 0; i < 40; i++ {
		if _, err := ev.e.WriteChange(agent1, d.ID, api.ChangeReq{Path: fmt.Sprintf("notes/f%d.md", i%3), Op: "put", Content: body}); err != nil {
			wantKind(t, err, KindLimit)
			break
		}
		ok++
	}
	if ok > 4 {
		t.Fatalf("%d writes of %d bytes accepted with a 1 MiB daily quota", ok, len(body))
	}
}

// C-4 / D-3: parallel submits cannot exceed the quota; the charge happens
// before the validation.
func TestRegressC4ParallelSubmitQuota(t *testing.T) {
	quota := 2 << 20
	ev := newEnv(t, func(c *config.Config) { c.Limits.AgentBytesPerDay = quota }, defaultFiles())
	d, err := ev.e.Begin(agent1, api.BeginReq{Topic: "race"})
	if err != nil {
		t.Fatal(err)
	}
	bad := []store.Change{put("notes/big.md", strings.Repeat("line of text\n", 70000))} // ~900 KB, no frontmatter
	var wg sync.WaitGroup
	var mu sync.Mutex
	validated := 0
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ev.e.Submit(agent1, d.ID, bad)
			if err != nil && strings.Contains(err.Error(), "validation failed") {
				mu.Lock()
				validated++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	ev.e.mu.Lock()
	_, used := ev.e.usage("agent1")
	ev.e.mu.Unlock()
	if used > quota {
		t.Fatalf("usage %d exceeds the quota %d", used, quota)
	}
	if validated*len(bad[0].Content) > quota {
		t.Fatalf("%d submits were fully validated (%d bytes) with a %d byte quota", validated, validated*len(bad[0].Content), quota)
	}
}

// C-5: refused requests (even from a reader token) do not grow the audit
// chain; the security log is rate limited.
func TestRegressC5AuditFloodReader(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	tok, _ := auth.NewToken(auth.RoleReader)
	keys, _ := auth.NewKeyring([]auth.TokenEntry{{Name: "reader1", Role: auth.RoleReader, SHA256: auth.Hash(tok)}})
	srv := httptest.NewServer(NewHandler(ev.e, keys, log.New(io.Discard, "", 0)))
	defer srv.Close()
	auditPath := filepath.Join(ev.cfg.DataDir, "audit.jsonl")
	before := countLines(t, auditPath)
	id := strings.Repeat("a", 32)
	for i := 0; i < 300; i++ {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/proposals/"+id+"/approve", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	if after := countLines(t, auditPath); after != before {
		t.Fatalf("refused requests grew the audit chain: %d -> %d lines", before, after)
	}
	ev.e.sec.Flush()
	if n := countLines(t, filepath.Join(ev.cfg.DataDir, "security.jsonl")); n > 10 {
		t.Fatalf("security log not rate limited: %d lines for 300 refused requests", n)
	}
}

func countLines(t *testing.T, p string) int {
	t.Helper()
	f, err := os.Open(p)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	n := 0
	for sc.Scan() {
		n++
	}
	return n
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func objectExists(ev *env, id string) bool {
	return exec.Command("git", "--git-dir", ev.e.repo.Dir, "cat-file", "-e", id).Run() == nil
}

// C-6 / D-4: a rejected bundle import leaves neither a branch nor the
// rejected objects in kb.git, also when the import is interrupted.
func TestRegressC6ImportAtomic(t *testing.T) {
	requireGit(t)
	src := t.TempDir()
	gitIn(t, src, "init", "-q")
	os.MkdirAll(filepath.Join(src, "notes"), 0o755)
	tok := "gh" + "p_" + strings.Repeat("A1b2", 9)
	os.WriteFile(filepath.Join(src, "notes", "a.md"), []byte(md("a", "token "+tok)), 0o644)
	os.WriteFile(filepath.Join(src, ".gitattributes"), []byte("secret.md export-ignore\n"), 0o644)
	gitIn(t, src, "add", "-A")
	gitIn(t, src, "commit", "-q", "-m", "init")
	blob := gitIn(t, src, "rev-parse", "HEAD:notes/a.md")
	bundle := filepath.Join(t.TempDir(), "kb.bundle")
	gitIn(t, src, "bundle", "create", bundle, "HEAD")

	// Plain rejection.
	ev := newEnv(t, nil, nil)
	f, _ := os.Open(bundle)
	_, err := ev.e.Import(owner, "bundle", f)
	f.Close()
	wantKind(t, err, KindInvalid)
	if ev.head() != "" || objectExists(ev, blob) {
		t.Fatal("rejected import left a branch or the secret blob in kb.git")
	}
	// Interrupted import: the context is cancelled while the bundle is
	// being validated (the PoC cancelled it when a branch appeared).
	for _, delay := range []time.Duration{0, 20 * time.Millisecond, 80 * time.Millisecond} {
		ev := newEnv(t, nil, nil)
		f, _ := os.Open(bundle)
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(delay); cancel() }()
		ev.e.mu.Lock()
		_, err := ev.e.importBundle(ctx, f, ImportOptions{})
		ev.e.mu.Unlock()
		cancel()
		f.Close()
		if err == nil {
			t.Fatal("import of a rejected bundle succeeded")
		}
		if ev.head() != "" || objectExists(ev, blob) {
			t.Fatalf("interrupted import (delay %v) left state in kb.git", delay)
		}
		if m, _ := filepath.Glob(filepath.Join(ev.e.repo.TmpDir, "import-*")); len(m) > 0 {
			t.Fatalf("temporary import repository not removed: %v", m)
		}
	}
}

// D-4: a version too large to scan blocks the import (it used to skip
// the secret scan silently).
func TestRegressD4LargeHistoryBlob(t *testing.T) {
	requireGit(t)
	src := t.TempDir()
	gitIn(t, src, "init", "-q")
	os.MkdirAll(filepath.Join(src, "notes"), 0o755)
	big := strings.Repeat("filler line of an exported log\n", (1100<<10)/31) + "github token gh" + "p_" + strings.Repeat("A", 36) + "\n"
	os.WriteFile(filepath.Join(src, "notes", "big.md"), []byte(big), 0o644)
	os.WriteFile(filepath.Join(src, "INDEX.md"), []byte("# Index\n"), 0o644)
	gitIn(t, src, "add", ".")
	gitIn(t, src, "commit", "-q", "-m", "one")
	blob := gitIn(t, src, "rev-parse", "HEAD:notes/big.md")
	os.Remove(filepath.Join(src, "notes", "big.md"))
	gitIn(t, src, "add", "-A")
	gitIn(t, src, "commit", "-q", "-m", "two")
	bundle := filepath.Join(t.TempDir(), "kb.bundle")
	gitIn(t, src, "bundle", "create", bundle, "HEAD")
	ev := newEnv(t, nil, nil)
	f, _ := os.Open(bundle)
	defer f.Close()
	_, err := ev.e.ImportWith(owner, "bundle", f, ImportOptions{AllowSecretHistory: true})
	wantKind(t, err, KindInvalid)
	if ev.head() != "" || objectExists(ev, blob) {
		t.Fatal("refused import left state in kb.git")
	}
}

// D-11 / B-11.9: the import checks content (control characters) and the
// size of every file.
func TestRegressD11ImportContent(t *testing.T) {
	ev := newEnv(t, nil, nil)
	_, err := ev.e.Import(owner, "tar", tarOf(t, map[string]string{"a.md": md("a", "bell \a here")}))
	wantKind(t, err, KindInvalid)
	if !strings.Contains(err.Error(), "control character") {
		t.Fatalf("unclear error: %v", err)
	}
	big := strings.Repeat("x", int(ev.e.maxImportFile())+1)
	_, err = ev.e.Import(owner, "tar", tarOf(t, map[string]string{"a.md": md("a", "x"), "b.txt": big}))
	wantKind(t, err, KindInvalid)
	_, err = ev.e.Import(owner, "tar", tarOf(t, map[string]string{"Notes/a.md": md("a", "x"), "notes/b.md": md("b", "y")}))
	wantKind(t, err, KindInvalid) // folder twin in an import (C-1)
	if ev.head() != "" {
		t.Fatal("a refused import left a branch")
	}
}

// C-10: a failed save leaves memory and disk in agreement.
func TestRegressC10SaveFailureKeepsState(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	r := ev.propose(agent1, "r", put("notes/beta.md", md("beta", "y")))
	archive := filepath.Join(ev.cfg.DataDir, "archive")
	if err := os.RemoveAll(archive); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, []byte("not a directory"), 0o600); err != nil { // archive writes now fail
		t.Fatal(err)
	}
	_, err := ev.e.Reject(owner, r.ID, "no")
	wantKind(t, err, KindInternal)
	if ev.state(r.ID) != store.StatePending {
		t.Fatal("memory says rejected although the state was not saved")
	}
	_, err = ev.e.Abort(agent1, r.ID)
	wantKind(t, err, KindInternal)
	if ev.state(r.ID) != store.StatePending {
		t.Fatal("memory says aborted although the state was not saved")
	}
	os.Remove(archive)
	os.Mkdir(archive, 0o700)
	if _, err := ev.e.Approve(owner, r.ID, r.Digest); err != nil {
		t.Fatalf("proposal must still be approvable: %v", err)
	}
}

// D-10: after a restart the content check runs again (outside the mutex)
// and approval still works.
func TestRegressD10ApproveAfterRestart(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	s := ev.propose(agent1, "t", put("notes/alpha.md", md("alpha", "x")))
	ev.reopen()
	if _, err := ev.e.Approve(owner, s.ID, s.Digest); err != nil {
		t.Fatal(err)
	}
}

// D-6: request data cannot inject escape sequences or lines into the log.
func TestRegressD6LogInjection(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	keys, _ := auth.NewKeyring(nil)
	var logbuf bytes.Buffer
	var lmu sync.Mutex
	lw := writerFunc(func(p []byte) (int, error) { lmu.Lock(); defer lmu.Unlock(); return logbuf.Write(p) })
	srv := httptest.NewServer(NewHandler(ev.e, keys, log.New(lw, "trove: ", 0)))
	defer srv.Close()
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "GET /v1/x%%1b]0;owned%%07%%0afake%%20approve%%20ok HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer nope\r\nConnection: close\r\n\r\n")
	io.ReadAll(bufio.NewReader(c))
	c.Close()
	lmu.Lock()
	out := logbuf.String()
	lmu.Unlock()
	if strings.ContainsAny(out, "\x1b\x07") || strings.Count(out, "\n") != 1 {
		t.Fatalf("log injection: %q", out)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
