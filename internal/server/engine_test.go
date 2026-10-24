package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"trove/internal/api"
	"trove/internal/audit"
	"trove/internal/config"
	"trove/internal/gitrepo"
	"trove/internal/store"
)

func TestFullFlow(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	before := ev.head()
	s := ev.propose(agent1, "update alpha",
		put("notes/alpha.md", md("alpha", "Alpha note, updated.")),
		put("notes/gamma.md", md("gamma", "New note.")))
	if s.State != store.StatePending || s.Status != "ready" {
		t.Fatalf("want pending/ready, got %s/%s", s.State, s.Status)
	}
	if len(s.Digest) != 64 {
		t.Fatalf("missing digest")
	}
	rv, err := ev.e.Review(owner, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rv.Files) != 2 || !strings.Contains(rv.Files[0].Diff, "+Alpha note, updated.") {
		t.Fatalf("unexpected review: %+v", rv.Files)
	}
	if !rv.Files[1].New {
		t.Fatalf("gamma should be marked new")
	}
	res, err := ev.e.Approve(owner, s.ID, s.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if ev.head() != res.Commit || res.Commit == before {
		t.Fatalf("head did not move to the approval commit")
	}
	if c, _ := ev.readHead("notes/alpha.md"); !strings.Contains(c, "updated") {
		t.Fatalf("change not applied")
	}
	if _, ok := ev.readHead("artifacts/x.yml"); !ok {
		t.Fatalf("untouched file lost")
	}
	if ev.state(s.ID) != store.StateApplied {
		t.Fatalf("state not applied")
	}
	// The commit carries the trailers.
	ctx, cancel := gitCtx()
	defer cancel()
	entries, err := ev.e.repo.FindByTrailer(ctx, TrailerProposal, s.ID)
	if err != nil || len(entries) != 1 {
		t.Fatalf("trailer commit not found: %v %d", err, len(entries))
	}
	tr := parseTrailers(entries[0].Message)
	if tr[TrailerDigest][0] != s.Digest || tr[TrailerAgent][0] != "agent1" || tr[TrailerApprover][0] != "owner" {
		t.Fatalf("bad trailers: %v", tr)
	}
	// Archived, audit chain intact.
	if _, err := os.Stat(filepath.Join(ev.cfg.DataDir, "archive", s.ID+".json")); err != nil {
		t.Fatalf("applied proposal not archived: %v", err)
	}
	if _, err := audit.VerifyFile(filepath.Join(ev.cfg.DataDir, "audit.jsonl")); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
}

func TestAgentTokenCannotApprove(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	s := ev.propose(agent1, "t", put("notes/alpha.md", md("alpha", "x")))
	head := ev.head()
	_, err := ev.e.Approve(agent1, s.ID, s.Digest)
	wantKind(t, err, KindForbidden)
	_, err = ev.e.Approve(readerA, s.ID, s.Digest)
	wantKind(t, err, KindForbidden)
	_, err = ev.e.Reject(agent1, s.ID, "no")
	wantKind(t, err, KindForbidden)
	_, err = ev.e.Review(agent1, s.ID)
	wantKind(t, err, KindForbidden)
	_, err = ev.e.Import(agent1, "tar", tarOf(t, map[string]string{"a.md": "x"}))
	wantKind(t, err, KindForbidden)
	_, err = ev.e.Begin(readerA, api.BeginReq{Topic: "x"})
	wantKind(t, err, KindForbidden)
	_, err = ev.e.Begin(owner, api.BeginReq{Topic: "x"})
	wantKind(t, err, KindForbidden) // no admin bypass: the approver cannot propose either
	if ev.head() != head || ev.state(s.ID) != store.StatePending {
		t.Fatalf("a denied approval changed something")
	}
	// Refused attempts go to the rate-limited security log (C-5), not the audit chain.
	data, err := os.ReadFile(filepath.Join(ev.cfg.DataDir, "security.jsonl"))
	if err != nil || !strings.Contains(string(data), `"event":"approve:denied"`) {
		t.Fatalf("denied attempt not recorded: %v %s", err, data)
	}
}

func TestAgentSeesOnlyOwnProposals(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	s := ev.propose(agent1, "t", put("notes/alpha.md", md("alpha", "x")))
	if _, err := ev.e.Get(agent2, s.ID); kindOf(err) != KindNotFound {
		t.Fatalf("agent2 can see agent1's proposal: %v", err)
	}
	_, err := ev.e.Abort(agent2, s.ID)
	wantKind(t, err, KindNotFound)
	l, err := ev.e.List(agent2, "all")
	if err != nil || len(l) != 0 {
		t.Fatalf("agent2 list: %v %d", err, len(l))
	}
	_, err = ev.e.List(readerA, "")
	wantKind(t, err, KindForbidden)
}

func TestDigestMismatch(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	s := ev.propose(agent1, "t", put("notes/alpha.md", md("alpha", "x")))
	head := ev.head()
	wrong := strings.Repeat("0", 64)
	_, err := ev.e.Approve(owner, s.ID, wrong)
	wantKind(t, err, KindConflict)
	_, err = ev.e.Approve(owner, s.ID, "")
	wantKind(t, err, KindInvalid)
	_, err = ev.e.Approve(owner, s.ID, s.Digest[:20])
	wantKind(t, err, KindInvalid)
	if ev.head() != head || ev.state(s.ID) != store.StatePending {
		t.Fatalf("digest mismatch applied something")
	}
	// Tampering with the stored content is detected even with the right digest.
	ev.e.mu.Lock()
	ev.e.props[s.ID].Changes[0].Content = md("alpha", "tampered")
	ev.e.mu.Unlock()
	_, err = ev.e.Approve(owner, s.ID, s.Digest)
	wantKind(t, err, KindConflict)
	if ev.head() != head {
		t.Fatalf("tampered proposal applied")
	}
}

func TestDigestCoversMetadata(t *testing.T) {
	p := &store.Proposal{Base: "b", Agent: "a", Topic: "t", Changes: []store.Change{put("x.md", "1")}}
	d1 := store.ComputeDigest(p)
	p.Topic = "t2"
	if store.ComputeDigest(p) == d1 {
		t.Fatal("topic not covered")
	}
	p.Topic = "t"
	p.Changes = []store.Change{put("x.md", "2")}
	if store.ComputeDigest(p) == d1 {
		t.Fatal("content not covered")
	}
	p.Changes = []store.Change{put("x.md", "1")}
	if store.ComputeDigest(p) != d1 {
		t.Fatal("digest not deterministic")
	}
}

func TestStaleAndOverlap(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	a := ev.propose(agent1, "a", put("notes/alpha.md", md("alpha", "from agent1")))
	b := ev.propose(agent2, "b", put("notes/alpha.md", md("alpha", "from agent2")))
	c := ev.propose(agent2, "c", put("notes/beta.md", md("beta", "independent")))
	lb, err := ev.e.Get(owner, b.ID)
	if err != nil || lb.OverlapCount != 1 || len(lb.Overlaps) != 1 || lb.Overlaps[0] != a.ID {
		t.Fatalf("overlap not reported: %+v %v", lb.Summary, err)
	}
	la, _ := ev.e.Get(agent1, a.ID)
	if la.OverlapCount != 1 || len(la.Overlaps) != 0 {
		t.Fatalf("agent must see the overlap count but not foreign ids: %+v", la.Summary)
	}
	if _, err := ev.e.Approve(owner, a.ID, a.Digest); err != nil {
		t.Fatal(err)
	}
	gb, _ := ev.e.Get(owner, b.ID)
	if gb.Status != "stale" || len(gb.StaleFiles) != 1 {
		t.Fatalf("b should be stale: %+v", gb.Summary)
	}
	head := ev.head()
	_, err = ev.e.Approve(owner, b.ID, b.Digest)
	wantKind(t, err, KindConflict)
	if ev.head() != head {
		t.Fatalf("stale proposal applied")
	}
	// Independent proposals stay approvable in any order.
	gc, _ := ev.e.Get(owner, c.ID)
	if gc.Status != "ready" {
		t.Fatalf("c should still be ready")
	}
	if _, err := ev.e.Approve(owner, c.ID, c.Digest); err != nil {
		t.Fatal(err)
	}
}

func TestRebase(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	a := ev.propose(agent1, "a", put("notes/alpha.md", md("alpha", "one")))
	b := ev.propose(agent2, "b", put("notes/alpha.md", md("alpha", "two")))
	_, err := ev.e.Rebase(agent2, b.ID)
	wantKind(t, err, KindConflict) // not stale yet
	if _, err := ev.e.Approve(owner, a.ID, a.Digest); err != nil {
		t.Fatal(err)
	}
	_, err = ev.e.Rebase(agent1, b.ID)
	wantKind(t, err, KindNotFound) // not the owner of b
	res, err := ev.e.Rebase(agent2, b.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res.New.ID == b.ID || res.New.Supersedes != b.ID || res.New.State != store.StateDraft || res.New.Base != ev.head() {
		t.Fatalf("bad rebase result: %+v", res.New)
	}
	if ev.state(b.ID) != store.StateSuperseded || len(res.Old.Changes) != 1 {
		t.Fatalf("old proposal not superseded or content missing")
	}
	_, err = ev.e.Approve(owner, b.ID, b.Digest)
	wantKind(t, err, KindConflict)
	ns, err := ev.e.Submit(agent2, res.New.ID, []store.Change{put("notes/alpha.md", md("alpha", "one and two"))})
	if err != nil {
		t.Fatal(err)
	}
	if ns.Digest == b.Digest || ns.Status != "ready" {
		t.Fatalf("rebased proposal must have a new digest and be ready")
	}
	if _, err := ev.e.Approve(owner, ns.ID, b.Digest); err == nil {
		t.Fatal("old digest must not approve the new proposal")
	}
	if _, err := ev.e.Approve(owner, ns.ID, ns.Digest); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentApproveSameProposal(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	s := ev.propose(agent1, "t", put("notes/alpha.md", md("alpha", "x")))
	before := ev.commits()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ev.e.Approve(owner, s.ID, s.Digest); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("want exactly one successful approval, got %d", ok)
	}
	if got := ev.commits(); got != before+1 {
		t.Fatalf("want exactly one new commit, got %d", got-before)
	}
}

func TestConcurrentApproveConflicting(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	var props []api.Summary
	for i := 0; i < 4; i++ {
		a := agent1
		if i%2 == 1 {
			a = agent2
		}
		props = append(props, ev.propose(a, "t", put("notes/alpha.md", md("alpha", strings.Repeat("v", i+1)))))
	}
	before := ev.commits()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for _, p := range props {
		p := p
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ev.e.Approve(owner, p.ID, p.Digest); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 || ev.commits() != before+1 {
		t.Fatalf("want one success and one commit, got %d successes, %d commits", ok, ev.commits()-before)
	}
}

func TestCrashBetweenCommitAndStateRecovered(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	s := ev.propose(agent1, "t", put("notes/alpha.md", md("alpha", "x")))
	before := ev.commits()
	ev.hook = func() error { return os.ErrDeadlineExceeded }
	if _, err := ev.e.Approve(owner, s.ID, s.Digest); err == nil {
		t.Fatal("simulated crash should return an error")
	}
	ev.hook = nil
	if ev.commits() != before+1 {
		t.Fatal("the commit should exist")
	}
	// On disk the proposal is still pending.
	if _, err := os.Stat(filepath.Join(ev.cfg.DataDir, "proposals", s.ID+".json")); err != nil {
		t.Fatalf("pending file missing: %v", err)
	}
	head := ev.head()
	ev.reopen()
	if ev.state(s.ID) != store.StateApplied {
		t.Fatalf("recovery did not mark the proposal applied")
	}
	d, _ := ev.e.Get(owner, s.ID)
	if d.AppliedCommit != head || d.DecidedBy != "owner" {
		t.Fatalf("recovered metadata wrong: %+v", d.Summary)
	}
	_, err := ev.e.Approve(owner, s.ID, s.Digest)
	wantKind(t, err, KindConflict)
	if ev.commits() != before+1 {
		t.Fatal("proposal applied twice")
	}
}

func TestCrashThenApproveAgainIsIdempotent(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	s := ev.propose(agent1, "t", put("notes/alpha.md", md("alpha", "x")))
	before := ev.commits()
	ev.hook = func() error { return os.ErrDeadlineExceeded }
	ev.e.Approve(owner, s.ID, s.Digest)
	ev.hook = nil
	// Same process, in-memory state still pending: the retry must find the
	// existing commit instead of applying again.
	res, err := ev.e.Approve(owner, s.ID, s.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if res.Commit != ev.head() || ev.commits() != before+1 {
		t.Fatalf("retry created a duplicate commit")
	}
}

func TestTrailerCannotBeForgedFromTopic(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	victim := ev.propose(agent2, "victim", put("notes/beta.md", md("beta", "v")))
	evil := "x\nTrove-Proposal: " + victim.ID + "\nTrove-Digest: " + victim.Digest
	s := ev.propose(agent1, evil, put("notes/alpha.md", md("alpha", "a")))
	if strings.Contains(s.Topic, "\n") {
		t.Fatalf("topic not sanitized")
	}
	if _, err := ev.e.Approve(owner, s.ID, s.Digest); err != nil {
		t.Fatal(err)
	}
	ev.reopen()
	if ev.state(victim.ID) != store.StatePending {
		t.Fatalf("forged trailer marked another proposal applied")
	}
}

func TestExpiry(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	s := ev.propose(agent1, "t", put("notes/alpha.md", md("alpha", "x")))
	draft, err := ev.e.Begin(agent1, api.BeginReq{Topic: "draft"})
	if err != nil {
		t.Fatal(err)
	}
	ev.clock.Advance(7*24*time.Hour - time.Minute)
	ev.e.Expire()
	if ev.state(s.ID) != store.StatePending {
		t.Fatal("expired too early")
	}
	ev.clock.Advance(2 * time.Minute)
	ev.e.Expire()
	if ev.state(s.ID) != store.StateExpired || ev.state(draft.ID) != store.StateExpired {
		t.Fatal("not expired after the TTL")
	}
	if _, err := os.Stat(filepath.Join(ev.cfg.DataDir, "archive", s.ID+".json")); err != nil {
		t.Fatal("expired proposal not kept in the archive")
	}
	_, err = ev.e.Approve(owner, s.ID, s.Digest)
	wantKind(t, err, KindConflict)
}

func TestLimits(t *testing.T) {
	ev := newEnv(t, func(c *config.Config) { c.Limits.PerAgent = 2; c.Limits.Total = 3 }, defaultFiles())
	d1, err := ev.e.Begin(agent1, api.BeginReq{Topic: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ev.e.Begin(agent1, api.BeginReq{Topic: "2"}); err != nil {
		t.Fatal(err)
	}
	_, err = ev.e.Begin(agent1, api.BeginReq{Topic: "3"})
	wantKind(t, err, KindLimit)
	if _, err := ev.e.Begin(agent2, api.BeginReq{Topic: "4"}); err != nil {
		t.Fatal(err)
	}
	_, err = ev.e.Begin(agent2, api.BeginReq{Topic: "5"})
	wantKind(t, err, KindLimit) // total limit
	if _, err := ev.e.Abort(agent1, d1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.e.Begin(agent2, api.BeginReq{Topic: "6"}); err != nil {
		t.Fatalf("slot not freed after abort: %v", err)
	}
}

func TestSubmitValidationKeepsDraft(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	d, _ := ev.e.Begin(agent1, api.BeginReq{Topic: "t"})
	cases := [][]store.Change{
		{put("../evil.md", md("x", "y"))},
		{put("/abs.md", md("x", "y"))},
		{put(".git/config.md", md("x", "y"))},
		{put("notes/x.txt", "plain")},
		{put("notes/nofm.md", "no frontmatter")},
		{put("notes/key.md", md("k", "-----BEGIN OPENSSH PRIVATE KEY-----"))},
		{del("notes/missing.md")},
		{},
	}
	for i, c := range cases {
		_, err := ev.e.Submit(agent1, d.ID, c)
		wantKind(t, err, KindInvalid)
		if ev.state(d.ID) != store.StateDraft {
			t.Fatalf("case %d: draft state changed", i)
		}
	}
	// Identical content is a no-op and therefore "no changes".
	same, _ := ev.readHead("notes/alpha.md")
	_, err := ev.e.Submit(agent1, d.ID, []store.Change{put("notes/alpha.md", same)})
	wantKind(t, err, KindInvalid)
}

func TestSymlinkInTreeRejected(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	ctx, cancel := gitCtx()
	defer cancel()
	head := ev.head()
	c, err := ev.e.repo.BuildCommit(ctx, head, []gitrepo.Edit{{Path: "notes/link.md", Mode: "120000", Content: []byte("../../etc/passwd")}}, "symlink", gitrepo.Ident{Name: "t", Email: "t@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ev.e.repo.UpdateRef(ctx, c, head); err != nil {
		t.Fatal(err)
	}
	d, _ := ev.e.Begin(agent1, api.BeginReq{Topic: "t"})
	_, err = ev.e.Submit(agent1, d.ID, []store.Change{put("notes/link.md", md("x", "y"))})
	wantKind(t, err, KindInvalid)
	_, err = ev.e.Submit(agent1, d.ID, []store.Change{del("notes/link.md")})
	wantKind(t, err, KindInvalid)
}

func TestServerSideDraft(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	d, _ := ev.e.Begin(agent1, api.BeginReq{Topic: "mcp style"})
	if _, err := ev.e.WriteChange(agent1, d.ID, api.ChangeReq{Path: "notes/new.md", Op: "put", Content: md("n", "x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.e.WriteChange(agent1, d.ID, api.ChangeReq{Path: "notes/beta.md", Op: "delete"}); err != nil {
		t.Fatal(err)
	}
	_, err := ev.e.WriteChange(agent2, d.ID, api.ChangeReq{Path: "notes/x.md", Op: "put", Content: md("n", "x")})
	wantKind(t, err, KindNotFound)
	_, err = ev.e.WriteChange(agent1, d.ID, api.ChangeReq{Path: "../x.md", Op: "put", Content: "x"})
	wantKind(t, err, KindInvalid)
	f, err := ev.e.ReadFile(agent1, "notes/new.md", d.ID)
	if err != nil || !strings.Contains(f.Content, "x") {
		t.Fatalf("draft read: %v", err)
	}
	s, err := ev.e.Submit(agent1, d.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Files) != 2 {
		t.Fatalf("want 2 files, got %d", len(s.Files))
	}
	if _, err := ev.e.WriteChange(agent1, d.ID, api.ChangeReq{Path: "notes/y.md", Op: "put", Content: md("y", "y")}); kindOf(err) != KindConflict {
		t.Fatalf("submitted proposal must be immutable: %v", err)
	}
}

func TestReject(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	s := ev.propose(agent1, "t", put("notes/alpha.md", md("alpha", "x")))
	_, err := ev.e.Reject(owner, s.ID, "")
	wantKind(t, err, KindInvalid)
	if _, err := ev.e.Reject(owner, s.ID, "not needed"); err != nil {
		t.Fatal(err)
	}
	if ev.state(s.ID) != store.StateRejected {
		t.Fatal("not rejected")
	}
	_, err = ev.e.Approve(owner, s.ID, s.Digest)
	wantKind(t, err, KindConflict)
}

func TestImportOnlyOnceAndPaths(t *testing.T) {
	ev := newEnv(t, nil, nil)
	_, err := ev.e.Begin(agent1, api.BeginReq{Topic: "x"})
	wantKind(t, err, KindConflict) // empty knowledge base
	_, err = ev.e.Import(owner, "tar", tarOf(t, map[string]string{"../evil.md": "x"}))
	wantKind(t, err, KindInvalid)
	// Decision 10b: a possible secret blocks the import (nothing is imported).
	_, err = ev.e.Import(owner, "tar", tarOf(t, map[string]string{"a.md": md("a", "x"), "sub/b.md": md("b", "token="+"abcdef123456")}))
	wantKind(t, err, KindInvalid)
	if ev.head() != "" {
		t.Fatal("a rejected import left a branch")
	}
	res, err := ev.e.Import(owner, "tar", tarOf(t, map[string]string{"a.md": md("a", "x"), ".obsidian/x.json": "{}", "sub/b.md": md("b", "no secret")}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 2 || len(res.Skipped) != 1 {
		t.Fatalf("unexpected import result: %+v", res)
	}
	_, err = ev.e.Import(owner, "tar", tarOf(t, map[string]string{"c.md": "x"}))
	wantKind(t, err, KindConflict)
}

func TestImportBundleWithHistory(t *testing.T) {
	requireGit(t)
	src := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", src, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	git("init", "--quiet")
	os.WriteFile(filepath.Join(src, "a.md"), []byte(md("a", "1")), 0o644)
	git("add", "a.md")
	git("commit", "--quiet", "-m", "one")
	os.WriteFile(filepath.Join(src, "a.md"), []byte(md("a", "2")), 0o644)
	git("commit", "--quiet", "-am", "two")
	bundle := filepath.Join(t.TempDir(), "kb.bundle")
	git("bundle", "create", bundle, "HEAD")
	ev := newEnv(t, nil, nil)
	f, err := os.Open(bundle)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := ev.e.Import(owner, "bundle", f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Commits != 2 || res.Files != 1 {
		t.Fatalf("unexpected bundle import: %+v", res)
	}
	if c, _ := ev.readHead("a.md"); !strings.Contains(c, "2") {
		t.Fatal("wrong content after bundle import")
	}
}

func TestSecondInstanceLocked(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	if _, err := Open(ev.cfg, Options{}); err == nil {
		t.Fatal("second instance on the same data dir must fail")
	}
}

func TestReviewEscapesUntrustedContent(t *testing.T) {
	ev := newEnv(t, nil, defaultFiles())
	// Control, tag and bidi characters in content are refused outright.
	for _, bad := range []string{"evil \x1b[2J clear", "rtl \u202e x", "tag \U000E0049\U000E0067 x"} {
		d, _ := ev.e.Begin(agent1, api.BeginReq{Topic: "x"})
		_, err := ev.e.Submit(agent1, d.ID, []store.Change{put("notes/alpha.md", md("alpha", bad))})
		wantKind(t, err, KindInvalid)
		ev.e.Abort(agent1, d.ID)
	}
	// Other invisible characters pass with a warning and are escaped.
	s := ev.propose(agent1, "topic \x1b[31mred", put("notes/alpha.md", md("alpha", "zero\u200bwidth and\u00a0nbsp")))
	if !hasWarning(s.Warnings, "invisible character") {
		t.Fatalf("missing invisible character warning: %v", s.Warnings)
	}
	rv, err := ev.e.Review(owner, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	all := rv.Summary.Topic + rv.Files[0].Diff
	if strings.ContainsRune(all, 0x1b) || strings.ContainsRune(all, 0x202e) {
		t.Fatalf("control characters reached the review output: %q", all)
	}
	if rv.Notice == "" {
		t.Fatal("missing untrusted-content notice")
	}
	if strings.ContainsRune(all, 0x200b) || strings.ContainsRune(all, 0xa0) || !strings.Contains(all, `\u{200b}`) {
		t.Fatalf("invisible characters not escaped: %q", all)
	}
}

func hasWarning(list []string, sub string) bool {
	for _, w := range list {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
