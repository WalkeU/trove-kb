package server

import (
	"archive/tar"
	"bytes"
	"errors"
	"os/exec"
	"sort"
	"sync"
	"testing"
	"time"

	"trove/internal/api"
	"trove/internal/auth"
	"trove/internal/config"
	"trove/internal/store"
)

var (
	agent1   = auth.Actor{Name: "agent1", Role: auth.RoleAgent}
	agent2   = auth.Actor{Name: "agent2", Role: auth.RoleAgent}
	owner    = auth.Actor{Name: "owner", Role: auth.RoleApprover}
	readerA  = auth.Actor{Name: "reader1", Role: auth.RoleReader}
	baseTime = time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not found")
	}
}

func testConfig(dir string) config.Config {
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.Validation.AllowedDirs = append(cfg.Validation.AllowedDirs, "notes", "other", "sub")
	return cfg
}

type env struct {
	t     *testing.T
	e     *Engine
	cfg   config.Config
	clock *clock
	hook  func() error
}

// newEnv opens an engine on a fresh data dir and imports files.
func newEnv(t *testing.T, mutate func(*config.Config), files map[string]string) *env {
	t.Helper()
	requireGit(t)
	cfg := testConfig(t.TempDir())
	if mutate != nil {
		mutate(&cfg)
	}
	ev := &env{t: t, cfg: cfg, clock: &clock{t: baseTime}}
	ev.open()
	if files != nil {
		if _, err := ev.e.Import(owner, "tar", tarOf(t, files)); err != nil {
			t.Fatalf("import: %v", err)
		}
	}
	return ev
}

func (ev *env) open() {
	ev.t.Helper()
	e, err := Open(ev.cfg, Options{Now: ev.clock.Now, AfterCommit: func() error {
		if ev.hook != nil {
			return ev.hook()
		}
		return nil
	}})
	if err != nil {
		ev.t.Fatalf("open: %v", err)
	}
	ev.e = e
	ev.t.Cleanup(func() { e.Close() })
}

func (ev *env) reopen() {
	ev.t.Helper()
	ev.e.Close()
	ev.open()
}

func tarOf(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := files[n]
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg, ModTime: baseTime}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func md(title, body string) string {
	return "---\ntitle: " + title + "\nupdated: 2026-01-01\nstatus: current\n---\n\n" + body + "\n"
}

func defaultFiles() map[string]string {
	return map[string]string{
		"INDEX.md":           "# Index\n\n- notes\n",
		"notes/alpha.md":     md("alpha", "Alpha note."),
		"notes/beta.md":      md("beta", "Beta note."),
		"runbooks/deploy.md": md("deploy", "Step 1."),
		"artifacts/x.yml":    "key: value\n",
	}
}

func put(path, content string) store.Change {
	return store.Change{Path: path, Op: store.OpPut, Content: content}
}

func del(path string) store.Change { return store.Change{Path: path, Op: store.OpDelete} }

// propose opens a draft and submits changes in one go.
func (ev *env) propose(a auth.Actor, topic string, changes ...store.Change) api.Summary {
	ev.t.Helper()
	d, err := ev.e.Begin(a, api.BeginReq{Topic: topic})
	if err != nil {
		ev.t.Fatalf("begin: %v", err)
	}
	s, err := ev.e.Submit(a, d.ID, changes)
	if err != nil {
		ev.t.Fatalf("submit: %v", err)
	}
	return s
}

func (ev *env) head() string {
	ev.t.Helper()
	h, err := ev.e.Head()
	if err != nil {
		ev.t.Fatal(err)
	}
	return h
}

func (ev *env) commits() int {
	ev.t.Helper()
	ctx, cancel := gitCtx()
	defer cancel()
	n, err := ev.e.repo.CommitCount(ctx)
	if err != nil {
		ev.t.Fatal(err)
	}
	return n
}

func (ev *env) readHead(path string) (string, bool) {
	ev.t.Helper()
	ctx, cancel := gitCtx()
	defer cancel()
	s, ok, err := ev.e.readAt(ctx, ev.head(), path)
	if err != nil {
		ev.t.Fatal(err)
	}
	return s, ok
}

func kindOf(err error) Kind {
	var ee *Error
	if errors.As(err, &ee) {
		return ee.Kind
	}
	return 0
}

func wantKind(t *testing.T, err error, k Kind) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error of kind %d, got nil", k)
	}
	if got := kindOf(err); got != k {
		t.Fatalf("expected error kind %d, got %d (%v)", k, got, err)
	}
}

func (ev *env) state(id string) store.State {
	ev.e.mu.Lock()
	defer ev.e.mu.Unlock()
	return ev.e.props[id].State
}
