package validate

import (
	"strings"
	"testing"

	"trove/internal/config"
	"trove/internal/store"
)

// B-6: common secret notations are caught.
func TestRegressB6SecretForms(t *testing.T) {
	r := rules(t, nil)
	caught := []string{
		"password: Sup3rS3cret!",
		`"api_key": "a8f5f167f44f4964e6c998dee827110c"`,
		"db: postgres://admin:S3cretPass@10.0.0.5/kb",
		"token := gh" + "p_\u200b" + strings.Repeat("ABCDEFGHIJKL", 3),
		"-----BEGIN RSA\u00a0PRIVATE KEY-----",
		"-----BEGIN RSA\nPRIVATE KEY-----",
		"password = $ecretValue123",
		"Z2hwX0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpag==", // base64 of a GitHub-style token
		"gl" + "pat-" + strings.Repeat("x", 20),
		"secret: 'abcdef12'",
	}
	for _, c := range caught {
		if len(r.Secrets(c)) == 0 {
			t.Errorf("not caught: %q", c)
		}
	}
	harmless := []string{
		"token: see the accounts note",
		"Token: stored in the password manager",
		"password: <in the vault>",
		"url: https://example.com/path",
		"login: postgres://admin:<password>@db.example.com/kb",
		"pwd=$(pwd)",
		"commit 3f2a9c1e5b7d4a6c8e0f2b4d6a8c0e2f4b6d8a0c",
	}
	for _, c := range harmless {
		if f := r.Secrets(c); len(f) != 0 {
			t.Errorf("false positive on %q: %v", c, f)
		}
	}
	if w := r.SecretWarnings("key material: " + "q8Zr1Lx9Vt2Wm7Kp3Ns6Jd4Hf5Gb0Ca8Ye1Uo9Ii2"); len(w) == 0 {
		t.Error("high-entropy block not flagged")
	}
}

// B-9: confusable, invisible, decomposed and Windows-special paths are refused.
func TestRegressB9Paths(t *testing.T) {
	r := rules(t, nil)
	for _, p := range []string{
		"notes/CON .md", "notes/COM\u00b9.md", "notes/CONIN$.md", "GIT~1/config.md",
		"notes/cafe\u0301.md", "notes/\u0430lpha.md", "notes/al\u200bpha.md", "notes/\u202egpj.md",
		"notes/a\u3000.md", "notes/a\u00a0b.md", "notes/x\U000E0041.md",
	} {
		if err := r.CheckPath(p); err == nil {
			t.Errorf("path %q must be refused", p)
		}
	}
	if err := r.CheckPath("notes/caf\u00e9.md"); err != nil {
		t.Errorf("precomposed Latin letters must be accepted: %v", err)
	}
}

// B-4: tag and bidi characters in content block; zero width only warns.
func TestRegressB4ContentInvisible(t *testing.T) {
	r := rules(t, nil)
	for _, c := range []string{"x\U000E0049y", "x\u202ey", "x\u2066y", "x\x1b[2Jy"} {
		if res := check(r, nil, nil, store.Change{Path: "notes/a.md", Op: "put", Content: fm(c)}); res.OK() {
			t.Errorf("content %q must be refused", c)
		}
	}
	res := check(r, nil, nil, store.Change{Path: "notes/a.md", Op: "put", Content: fm("zero\u200bwidth")})
	if !res.OK() || !hasMsg(res.Warnings, "invisible character") {
		t.Errorf("zero width must warn, not block: %v %v", res.Errors, res.Warnings)
	}
}

// B-11.4: the agent-chosen scope does not hide the multi-folder warning.
func TestRegressScopeDoesNotHideWarning(t *testing.T) {
	r := rules(t, nil)
	res := check(r, nil, []string{"notes", "other"},
		store.Change{Path: "notes/a.md", Op: "put", Content: fm("x")},
		store.Change{Path: "other/b.md", Op: "put", Content: fm("x")})
	if !hasMsg(res.Warnings, "top-level folders") || !hasMsg(res.Warnings, "scope of 2 folders") {
		t.Fatalf("warnings: %v", res.Warnings)
	}
}

// Decision 10a: the allowed folder list cannot be empty.
func TestRegressAllowedDirsRequired(t *testing.T) {
	cfg := config.Default()
	cfg.Validation.AllowedDirs = nil
	if _, err := New(cfg.Validation, cfg.Limits); err == nil {
		t.Fatal("empty allowed_dirs must be an error")
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("config validation must refuse empty allowed_dirs")
	}
	d := config.Default().Validation.AllowedDirs
	if strings.Join(d, ",") != "infra,projects,apps,claude,snippets,runbooks,decisions" {
		t.Fatalf("unexpected defaults: %v", d)
	}
}
