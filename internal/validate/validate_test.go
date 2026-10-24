package validate

import (
	"strings"
	"testing"

	"trove/internal/config"
	"trove/internal/gitrepo"
	"trove/internal/store"
)

func rules(t *testing.T, mutate func(*config.Config)) *Rules {
	t.Helper()
	cfg := config.Default()
	cfg.Validation.AllowedDirs = append(cfg.Validation.AllowedDirs, "notes", "other", "a", "sub", "dir.md", "file.md", "projekt")
	if mutate != nil {
		mutate(&cfg)
	}
	r, err := New(cfg.Validation, cfg.Limits)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func fm(body string) string {
	return "---\ntitle: t\nupdated: 2026-01-01\nstatus: current\n---\n" + body + "\n"
}

var reg = gitrepo.Entry{Mode: "100644", Type: "blob", ID: "x"}

func TestCheckPathAttacks(t *testing.T) {
	r := rules(t, nil)
	bad := []string{
		"", "../x.md", "a/../../x.md", "a/../b.md", "/etc/x.md", "./x.md", "a//b.md",
		".git/config.md", "a/.git/x.md", ".trove/state.md", "notes/.hidden.md",
		`a\b.md`, "C:/x.md", "c:x.md", "x.md:stream", "a/x.txt", "x.MD", "x",
		"con.md", "notes/nul.md", "a /x.md", "a./x.md", "notes/x.md ", "a/\x1bx.md",
		strings.Repeat("a", 300) + ".md",
	}
	for _, p := range bad {
		if err := r.CheckPath(p); err == nil {
			t.Errorf("path %q should be rejected", p)
		}
	}
	good := []string{"x.md", "notes/x.md", "notes/sub/hdd mount.md", "projekt/árvíztűrő.md"}
	for _, p := range good {
		if err := r.CheckPath(p); err != nil {
			t.Errorf("path %q should be accepted: %v", p, err)
		}
	}
}

func TestAllowedDirs(t *testing.T) {
	r := rules(t, func(c *config.Config) {
		c.Validation.AllowedDirs = []string{"notes", "runbooks"}
		c.Validation.AllowRootFiles = false
	})
	if err := r.CheckPath("notes/a.md"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"secret/a.md", "a.md"} {
		if err := r.CheckPath(p); err == nil {
			t.Errorf("%q should be outside the allowed folders", p)
		}
	}
}

func check(r *Rules, base map[string]gitrepo.Entry, scope []string, changes ...store.Change) Result {
	if base == nil {
		base = map[string]gitrepo.Entry{}
	}
	return r.Check(changes, base, func(string) (string, error) { return "", nil }, scope)
}

func hasMsg(list []string, sub string) bool {
	for _, m := range list {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

func TestFrontmatter(t *testing.T) {
	r := rules(t, nil)
	res := check(r, nil, nil, store.Change{Path: "a.md", Op: "put", Content: "no frontmatter"})
	if res.OK() {
		t.Fatal("missing frontmatter must block")
	}
	res = check(r, nil, nil, store.Change{Path: "a.md", Op: "put", Content: "---\ntitle: t\nupdated:\nstatus: x\n---\n"})
	if !hasMsg(res.Errors, `"updated"`) {
		t.Fatalf("empty field must block: %v", res.Errors)
	}
	res = check(r, nil, nil, store.Change{Path: "a.md", Op: "put", Content: "\uFEFF---\r\ntitle: t\r\nupdated: 2026-01-01\r\nstatus: current\r\n---\r\nbody"})
	if !res.OK() {
		t.Fatalf("BOM/CRLF frontmatter should pass: %v", res.Errors)
	}
	res = check(r, nil, nil, store.Change{Path: "INDEX.md", Op: "put", Content: "# Index"})
	if !res.OK() {
		t.Fatalf("exempt file should pass: %v", res.Errors)
	}
}

func TestSecretsBlock(t *testing.T) {
	r := rules(t, nil)
	secrets := []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"password=" + "hunter22",
		"DB_PASSWORD = " + "s3cretvalue",
		"token=" + "abcd1234",
		"api_key=" + "\"zzzz9999\"",
		"gh" + "p_" + strings.Repeat("A", 36),
		"github_" + "pat_" + strings.Repeat("b", 30),
		"AK" + "IA" + strings.Repeat("Q", 16),
		"xo" + "xb-" + strings.Repeat("1", 12),
		"123456789:" + "AA" + strings.Repeat("c", 33),
		"sk" + "-" + strings.Repeat("d", 30),
		"AI" + "za" + strings.Repeat("e", 35),
		"ey" + "J" + strings.Repeat("f", 12) + ".ey" + "J" + strings.Repeat("g", 12) + "." + strings.Repeat("h", 12),
		"tskey-" + "auth-" + strings.Repeat("k", 16),
	}
	for _, s := range secrets {
		res := check(r, nil, nil, store.Change{Path: "a.md", Op: "put", Content: fm("x\n" + s)})
		if res.OK() {
			t.Errorf("secret %q was not blocked", s)
		}
	}
	harmless := []string{
		"token=<stored in the password manager>",
		"password=$DB_PASSWORD",
		"password=****",
		"The token is stored in the vault, entry X.",
		"token: see accounts note",
	}
	for _, s := range harmless {
		res := check(r, nil, nil, store.Change{Path: "a.md", Op: "put", Content: fm(s)})
		if !res.OK() {
			t.Errorf("harmless line %q blocked: %v", s, res.Errors)
		}
	}
}

func TestCustomSecretPattern(t *testing.T) {
	r := rules(t, func(c *config.Config) { c.Validation.ExtraSecretPatterns = []string{`ACME-[0-9]{6}`} })
	if res := check(r, nil, nil, store.Change{Path: "a.md", Op: "put", Content: fm("ACME-123456")}); res.OK() {
		t.Fatal("custom pattern not applied")
	}
	if _, err := New(config.Validation{ExtraSecretPatterns: []string{"("}}, config.Default().Limits); err == nil {
		t.Fatal("invalid pattern must fail")
	}
}

func TestSizeLimits(t *testing.T) {
	r := rules(t, func(c *config.Config) {
		c.Limits.MaxFileBytes = 100
		c.Limits.MaxTotalBytes = 150
		c.Limits.MaxFiles = 2
	})
	big := fm(strings.Repeat("x", 200))
	if res := check(r, nil, nil, store.Change{Path: "a.md", Op: "put", Content: big}); res.OK() {
		t.Fatal("file size limit not enforced")
	}
	small := fm(strings.Repeat("y", 30))
	if res := check(r, nil, nil,
		store.Change{Path: "a.md", Op: "put", Content: small},
		store.Change{Path: "b.md", Op: "put", Content: small}); res.OK() {
		t.Fatal("total size limit not enforced")
	}
	if res := check(r, nil, nil,
		store.Change{Path: "a.md", Op: "put", Content: "---\n"},
		store.Change{Path: "b.md", Op: "put", Content: "---\n"},
		store.Change{Path: "c.md", Op: "put", Content: "---\n"}); !hasMsg(res.Errors, "too many files") {
		t.Fatal("file count limit not enforced")
	}
}

func TestStructuralErrors(t *testing.T) {
	r := rules(t, nil)
	base := map[string]gitrepo.Entry{
		"notes/a.md":    reg,
		"notes/link.md": {Mode: "120000", Type: "blob", ID: "y"},
		"file.md":       reg,
		"dir.md/x.md":   reg,
		"sub/mod.md":    {Mode: "160000", Type: "commit", ID: "z"},
	}
	cases := []store.Change{
		{Path: "notes/link.md", Op: "put", Content: fm("x")},
		{Path: "notes/link.md", Op: "delete"},
		{Path: "sub/mod.md", Op: "put", Content: fm("x")},
		{Path: "file.md/child.md", Op: "put", Content: fm("x")},
		{Path: "dir.md", Op: "put", Content: fm("x")},
		{Path: "missing.md", Op: "delete"},
		{Path: "notes/a.md", Op: "rename"},
		{Path: "notes/b.md", Op: "put", Content: "---\x00"},
		{Path: "notes/b.md", Op: "put", Content: string([]byte{0xff, 0xfe})},
	}
	for _, c := range cases {
		if res := check(r, base, nil, c); res.OK() {
			t.Errorf("change %+v should be rejected", c.Path+" "+c.Op)
		}
	}
	if res := check(r, base, nil, store.Change{Path: "notes/a.md", Op: "put", Content: fm("1")}, store.Change{Path: "notes/a.md", Op: "delete"}); res.OK() {
		t.Error("duplicate path must be rejected")
	}
	if res := check(r, nil, nil); res.OK() {
		t.Error("empty change set must be rejected")
	}
}

func TestWarnings(t *testing.T) {
	r := rules(t, func(c *config.Config) { c.Limits.LargeDiffLines = 5 })
	base := map[string]gitrepo.Entry{"notes/a.md": reg, "notes/old.md": reg}
	content := fm("dash \u2014 here\nand \u2013 there\npublic 8.8.8.8\nprivate 10.1.2.3 192.168.1.1 100.64.1.1 192.0.2.10\n1\n2\n3\n4")
	res := r.Check([]store.Change{
		{Path: "notes/a.md", Op: "put", Content: content},
		{Path: "notes/old.md", Op: "delete"},
		{Path: "other/new.md", Op: "put", Content: fm("x")},
	}, base, func(string) (string, error) { return "", nil }, nil)
	if !res.OK() {
		t.Fatalf("warnings must not block: %v", res.Errors)
	}
	for _, want := range []string{"em dash", "en dash", "public IP address 8.8.8.8", "file deleted", "new file", "large change", "top-level folders"} {
		if !hasMsg(res.Warnings, want) {
			t.Errorf("missing warning %q in %v", want, res.Warnings)
		}
	}
	for _, ip := range []string{"10.1.2.3", "192.168.1.1", "100.64.1.1", "192.0.2.10"} {
		if hasMsg(res.Warnings, ip) {
			t.Errorf("non-public address %s flagged", ip)
		}
	}
	scoped := check(r, nil, []string{"notes"}, store.Change{Path: "other/x.md", Op: "put", Content: fm("x")})
	if !hasMsg(scoped.Warnings, "outside the proposal scope") {
		t.Errorf("scope warning missing: %v", scoped.Warnings)
	}
}

func TestIsPublicIPv4(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8": true, "1.2.3.4": true, "172.32.0.1": true, "100.128.0.1": true,
		"10.0.0.1": false, "172.16.5.5": false, "192.168.0.1": false, "100.64.0.1": false,
		"100.127.255.255": false, "127.0.0.1": false, "198.51.100.7": false, "999.1.1.1": false,
	}
	for ip, want := range cases {
		if got := IsPublicIPv4(ip); got != want {
			t.Errorf("IsPublicIPv4(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestTopic(t *testing.T) {
	got, err := Topic("  a\nTrove-Proposal: x\r\n\x1b[2Jb  ")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(got, "\n\r\x1b") {
		t.Fatalf("topic not single line: %q", got)
	}
	if _, err := Topic(" \n\t "); err == nil {
		t.Fatal("empty topic must fail")
	}
	if long, _ := Topic(strings.Repeat("x", 500)); len([]rune(long)) > 200 {
		t.Fatal("topic not truncated")
	}
}
