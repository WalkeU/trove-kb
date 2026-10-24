package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"trove/internal/audit"
	"trove/internal/auth"
	"trove/internal/client"
	"trove/internal/config"
	"trove/internal/server"
)

var tokenRe = regexp.MustCompile(`^trove_(approver|agent|reader)_[0-9a-f]{64}$`)

// runInit runs trove init with the given stdin; tty selects the wizard.
func runInit(t *testing.T, stdin string, tty bool, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	e := &env{out: &out, errw: &errb, in: strings.NewReader(stdin), tty: tty}
	err := e.initSetup(args)
	code := 0
	if err != nil {
		errb.WriteString("error: " + err.Error() + "\n")
		code = 1
	}
	return code, out.String(), errb.String()
}

func initEnv(t *testing.T) {
	t.Helper()
	// The welcome commit (default) needs git, like the server.
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	clearTokenEnv(t)
	t.Setenv("TROVE_INIT_DIR", "")
	t.Setenv("TROVE_CONFIG", "")
}

// readTokens returns the token entries of tokens.json.
func readTokens(t *testing.T, root string) []auth.TokenEntry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "config", "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	var list []auth.TokenEntry
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatal(err)
	}
	return list
}

func readTokenFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// listFiles returns every path below root (slash separated, relative).
func listFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && p != root {
			rel, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out
}

func TestInitNonInteractive(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	code, out, errs := runInit(t, "", false, "--yes", "--dir", root, "--agent", "laptop", "--agent", "ci,docs-bot", "--reader", "viewer")
	if code != 0 {
		t.Fatalf("init failed: %s%s", out, errs)
	}
	entries := readTokens(t, root)
	want := map[string]auth.Role{"owner": auth.RoleApprover, "laptop": auth.RoleAgent, "ci": auth.RoleAgent, "docs-bot": auth.RoleAgent, "viewer": auth.RoleReader}
	if len(entries) != len(want) {
		t.Fatalf("tokens.json has %d entries, want %d", len(entries), len(want))
	}
	files := map[auth.Role]string{auth.RoleApprover: "owner", auth.RoleAgent: "agents", auth.RoleReader: "readers"}
	for _, en := range entries {
		if want[en.Name] != en.Role {
			t.Errorf("entry %s has role %s", en.Name, en.Role)
		}
		tok := readTokenFile(t, filepath.Join(root, files[en.Role], en.Name+".token"))
		if !tokenRe.MatchString(tok) || !strings.HasPrefix(tok, "trove_"+string(en.Role)+"_") {
			t.Errorf("token for %s has the wrong format", en.Name)
		}
		if auth.Hash(tok) != en.SHA256 {
			t.Errorf("hash of %s does not match tokens.json", en.Name)
		}
		// The raw token is never printed by default.
		if strings.Contains(out+errs, tok) {
			t.Errorf("token of %s printed without --show-tokens", en.Name)
		}
	}
	// tokens.json holds hashes only, never a raw token.
	raw, _ := os.ReadFile(filepath.Join(root, "config", "tokens.json"))
	if strings.Contains(string(raw), "trove_") {
		t.Error("tokens.json contains a raw token")
	}
	// The generated config loads with the serve code path, with safe defaults.
	cfg, err := serveConfig([]string{"--config", filepath.Join(root, "config", "trove.json")})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:8470" {
		t.Errorf("default listen %q", cfg.Listen)
	}
	if strings.Join(cfg.Validation.AllowedDirs, ",") != "infra,projects,apps,claude,snippets,runbooks,decisions" {
		t.Errorf("default allowed_dirs %v", cfg.Validation.AllowedDirs)
	}
	if filepath.Clean(cfg.DataDir) != filepath.Join(root, "data") {
		t.Errorf("data_dir resolves to %s", cfg.DataDir)
	}
	cj, _ := os.ReadFile(filepath.Join(root, "config", "trove.json"))
	if strings.Contains(string(cj), `"tokens"`) || strings.Contains(string(cj), "null") {
		t.Errorf("trove.json has an inline token list or null values:\n%s", cj)
	}
	// Next steps: serve, Docker hardening, separate env, MCP, import.
	for _, s := range []string{
		"trove serve --config", "--read-only", "--cap-drop ALL", "no-new-privileges", "-p 127.0.0.1:8470:8470",
		"TROVE_TOKEN_FILE", "TROVE_APPROVER_TOKEN_FILE", "claude mcp add trove", `"mcpServers"`, "welcome note", "--no-welcome",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("next steps miss %q", s)
		}
	}
	// The agent sections never mention the owner token file.
	agentPart := out[strings.Index(out, "3. Agent"):strings.Index(out, "4. MCP")]
	mcpPart := out[strings.Index(out, "4. MCP"):]
	for _, part := range []string{agentPart, mcpPart} {
		if strings.Contains(part, "owner.token") || strings.Contains(part, "APPROVER") {
			t.Errorf("agent instructions mention the approver token:\n%s", part)
		}
	}
}

func TestInitPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce unix modes; TestInitNonInteractive covers that init works there")
	}
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	if code, out, errs := runInit(t, "", false, "--yes", "--dir", root, "--reader", "r1"); code != 0 {
		t.Fatalf("init failed: %s%s", out, errs)
	}
	for _, rel := range listFiles(t, root) {
		if strings.HasPrefix(rel, "data/") {
			// The repository inside the 0700 data folder is written by git
			// (and later by the server) with git's own modes.
			continue
		}
		fi, err := os.Stat(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o600)
		if fi.IsDir() {
			want = 0o700
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s has mode %v, want %v", rel, fi.Mode().Perm(), want)
		}
	}
	fi, _ := os.Stat(root)
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("root folder mode %v", fi.Mode().Perm())
	}
	// An existing, too open folder is tightened.
	root2 := filepath.Join(t.TempDir(), "open")
	os.MkdirAll(filepath.Join(root2, "owner"), 0o755)
	os.Chmod(filepath.Join(root2, "owner"), 0o755)
	if code, out, errs := runInit(t, "", false, "--yes", "--dir", root2); code != 0 {
		t.Fatalf("init failed: %s%s", out, errs)
	}
	fi, _ = os.Stat(filepath.Join(root2, "owner"))
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("existing owner folder not tightened: %v", fi.Mode().Perm())
	}
}

func TestInitRefusesOverwrite(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	if code, out, errs := runInit(t, "", false, "--yes", "--dir", root); code != 0 {
		t.Fatalf("init failed: %s%s", out, errs)
	}
	before := readTokenFile(t, filepath.Join(root, "owner", "owner.token"))
	tj, _ := os.ReadFile(filepath.Join(root, "config", "tokens.json"))
	code, _, errs := runInit(t, "", false, "--yes", "--dir", root)
	if code == 0 || !strings.Contains(errs, "--force") {
		t.Fatalf("second init must refuse without --force: %d %s", code, errs)
	}
	if readTokenFile(t, filepath.Join(root, "owner", "owner.token")) != before {
		t.Fatal("owner token overwritten without --force")
	}
	tj2, _ := os.ReadFile(filepath.Join(root, "config", "tokens.json"))
	if !bytes.Equal(tj, tj2) {
		t.Fatal("tokens.json changed without --force")
	}
	// A single leftover file (for example only the config) also blocks.
	root2 := filepath.Join(t.TempDir(), "partial")
	os.MkdirAll(filepath.Join(root2, "config"), 0o700)
	os.WriteFile(filepath.Join(root2, "config", "trove.json"), []byte("{}"), 0o600)
	if code, _, errs := runInit(t, "", false, "--yes", "--dir", root2); code == 0 || !strings.Contains(errs, "trove.json") {
		t.Fatalf("existing trove.json must block: %s", errs)
	}
	// --force replaces every token.
	if code, out, errs := runInit(t, "", false, "--yes", "--force", "--dir", root); code != 0 {
		t.Fatalf("init --force failed: %s%s", out, errs)
	}
	after := readTokenFile(t, filepath.Join(root, "owner", "owner.token"))
	if after == before {
		t.Fatal("--force kept the old owner token")
	}
	for _, en := range readTokens(t, root) {
		if en.Name == "owner" && en.SHA256 != auth.Hash(after) {
			t.Fatal("tokens.json does not match the new owner token")
		}
	}
}

func TestInitNonLoopback(t *testing.T) {
	initEnv(t)
	base := t.TempDir()
	for _, addr := range []string{"0.0.0.0:8470", ":8470", "192.0.2.10:8470"} {
		root := filepath.Join(base, "x"+strings.NewReplacer(":", "_", ".", "_").Replace(addr))
		code, _, errs := runInit(t, "", false, "--yes", "--dir", root, "--listen", addr)
		if code == 0 || !strings.Contains(errs, "WARNING") || !strings.Contains(errs, "--allow-non-loopback") {
			t.Fatalf("%s accepted without confirmation: %s", addr, errs)
		}
		if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: refused init left files behind", addr)
		}
	}
	root := filepath.Join(base, "ok")
	code, out, errs := runInit(t, "", false, "--yes", "--dir", root, "--listen", "0.0.0.0:9000", "--allow-non-loopback")
	if code != 0 || !strings.Contains(errs, "TLS") {
		t.Fatalf("confirmed non-loopback init: %d %s%s", code, out, errs)
	}
	if !strings.Contains(out, "'http://127.0.0.1:9000'") || !strings.Contains(out, "-p 127.0.0.1:9000:9000") {
		t.Errorf("next steps do not use the configured port:\n%s", out)
	}
	// Loopback spellings need no confirmation.
	for i, addr := range []string{"localhost:8470", "[::1]:8470", "127.0.0.2:8470"} {
		root := filepath.Join(base, "lo"+string(rune('a'+i)))
		if code, out, errs := runInit(t, "", false, "--yes", "--dir", root, "--listen", addr); code != 0 {
			t.Errorf("%s refused: %s%s", addr, out, errs)
		}
	}
}

func TestInitRejectsBadInput(t *testing.T) {
	initEnv(t)
	base := t.TempDir()
	cases := [][]string{
		{"--allowed-dirs", ""},
		{"--allowed-dirs", " , "},
		{"--allowed-dirs", "infra/sub"},
		{"--allowed-dirs", ".git"},
		{"--allowed-dirs", "..,infra"},
		{"--agent", ""},
		{"--agent", "owner"},
		{"--agent", "a", "--reader", "A"},
		{"--agent", "../x"},
		{"--agent", ".hidden"},
		{"--agent", "CON"},
		{"--owner", "bad name"},
		{"--listen", "8470"},
		{"--listen", "127.0.0.1:99999"},
		{"positional"},
	}
	for i, c := range cases {
		root := filepath.Join(base, "c"+string(rune('a'+i)))
		args := append([]string{"--yes", "--dir", root}, c...)
		if code, _, _ := runInit(t, "", false, args...); code == 0 {
			t.Errorf("%v accepted", c)
		}
		if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%v: refused init left files behind", c)
		}
	}
}

// Without a terminal and without --yes, init never waits for an answer.
func TestInitNoTTYNeverPrompts(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	code, out, errs := runInit(t, "y\ny\ny\n", false, "--dir", root)
	if code == 0 || !strings.Contains(errs, "--yes") {
		t.Fatalf("init without a terminal must fail fast: %d %s%s", code, out, errs)
	}
	if strings.Contains(out, "[") {
		t.Errorf("a question was printed: %s", out)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("files written")
	}
}

// docker run without -i gives /dev/null as stdin: not a terminal.
func TestIsTerminalNullAndFile(t *testing.T) {
	dn, err := os.Open(os.DevNull)
	if err != nil {
		t.Skip(err)
	}
	defer dn.Close()
	if isTerminal(dn) {
		t.Error("the null device counts as a terminal")
	}
	f, _ := os.Create(filepath.Join(t.TempDir(), "in"))
	defer f.Close()
	if isTerminal(f) {
		t.Error("a regular file counts as a terminal")
	}
}

func TestInitWizard(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "kb setup")
	input := strings.Join([]string{
		root,           // folder
		"0.0.0.0:9100", // non-loopback
		"n",            // declined: asked again with the loopback default
		"",             // keep 127.0.0.1:8470
		"a/b",          // invalid folder, asked again
		"runbooks, notes",
		"",          // owner
		"bot1 bot2", // agents
		"",          // readers: none
		"",          // welcome note: yes
		"",          // create: yes
	}, "\n") + "\n"
	code, out, errs := runInit(t, input, true)
	if code != 0 {
		t.Fatalf("wizard failed: %s%s", out, errs)
	}
	if !strings.Contains(out, "WARNING") {
		t.Error("no warning for the non-loopback answer")
	}
	cfg, err := config.Load(filepath.Join(root, "config", "trove.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:8470" || strings.Join(cfg.Validation.AllowedDirs, ",") != "runbooks,notes" {
		t.Fatalf("wizard answers not used: %s %v", cfg.Listen, cfg.Validation.AllowedDirs)
	}
	names := map[string]auth.Role{}
	for _, en := range cfg.Tokens {
		names[en.Name] = en.Role
	}
	if names["owner"] != auth.RoleApprover || names["bot1"] != auth.RoleAgent || names["bot2"] != auth.RoleAgent || len(names) != 3 {
		t.Fatalf("tokens: %v", names)
	}
	if _, err := os.Stat(filepath.Join(root, "readers")); !errors.Is(err, os.ErrNotExist) {
		t.Error("readers folder created without readers")
	}
	if gitOut(t, root, "rev-list", "--count", "main") != "1" {
		t.Error("no welcome commit with the default answer")
	}
}

func TestInitWizardAccepted(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	input := strings.Join([]string{root, "0.0.0.0:9100", "yes", "", "", "", "", "n", ""}, "\n") + "\n"
	code, out, errs := runInit(t, input, true)
	if code != 0 {
		t.Fatalf("wizard failed: %s%s", out, errs)
	}
	cfg, err := config.Load(filepath.Join(root, "config", "trove.json"))
	if err != nil || cfg.Listen != "0.0.0.0:9100" {
		t.Fatalf("confirmed non-loopback address not stored: %v %q", err, cfg.Listen)
	}
	// The welcome note was declined: the knowledge base stays empty.
	if _, err := os.Stat(filepath.Join(root, "data", "kb.git")); !errors.Is(err, os.ErrNotExist) {
		t.Error("welcome note written although declined")
	}
}

// Declining, or input ending in the middle of the wizard, writes nothing.
func TestInitWizardAbort(t *testing.T) {
	initEnv(t)
	for name, input := range map[string]string{
		"eof":     "",
		"partial": "%s\n\n",
		"decline": "%s\n\n\n\n\n\n\nn\n",
	} {
		root := filepath.Join(t.TempDir(), "trove")
		in := strings.ReplaceAll(input, "%s", root)
		code, out, errs := runInit(t, in, true, "--dir", root)
		if code == 0 || !strings.Contains(errs, "aborted") {
			t.Errorf("%s: wizard did not abort: %s%s", name, out, errs)
		}
		if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: files written", name)
		}
	}
}

func TestInitShowTokens(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	code, out, errs := runInit(t, "", false, "--yes", "--dir", root, "--show-tokens")
	if code != 0 {
		t.Fatalf("init failed: %s%s", out, errs)
	}
	for _, p := range []string{"owner/owner.token", "agents/agent.token"} {
		tok := readTokenFile(t, filepath.Join(root, filepath.FromSlash(p)))
		if strings.Count(out+errs, tok) != 1 {
			t.Errorf("%s must be printed exactly once with --show-tokens", p)
		}
	}
}

// A failure or interrupt in the middle of writing leaves nothing behind:
// no token file, no tokens.json, no created folder, no temp file.
func TestInitRollback(t *testing.T) {
	initEnv(t)
	base := t.TempDir()
	o := initOptions{listen: "127.0.0.1:8470", allowedDirs: []string{"notes"}, owner: "owner", agents: []string{"a1", "a2"}}
	for step := 0; step < 4; step++ {
		o.dir = filepath.Join(base, "fail"+string(rune('0'+step)))
		p, err := buildInitPlan(o)
		if err != nil {
			t.Fatal(err)
		}
		boom := errors.New("simulated crash")
		err = applyInitPlan(p, initHooks{beforeWrite: func(i int) error {
			if i == step {
				return boom
			}
			return nil
		}})
		if !errors.Is(err, boom) {
			t.Fatalf("step %d: %v", step, err)
		}
		if _, err := os.Stat(o.dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("step %d: left %v", step, listFiles(t, o.dir))
		}
	}
	// An interrupt (SIGINT/SIGTERM) during the write phase rolls back too.
	o.dir = filepath.Join(base, "interrupted")
	p, _ := buildInitPlan(o)
	sig := make(chan os.Signal, 1)
	err := applyInitPlan(p, initHooks{interrupt: sig, beforeWrite: func(i int) error {
		if i == 2 {
			sig <- syscall.SIGTERM
		}
		return nil
	}})
	if !errors.Is(err, errInitAborted) {
		t.Fatalf("interrupt: %v", err)
	}
	if _, err := os.Stat(o.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupt left %v", listFiles(t, o.dir))
	}
	// With --force, a failed run restores the previous setup and keeps
	// folders that existed before.
	o.dir = filepath.Join(base, "forced")
	p, _ = buildInitPlan(o)
	if err := applyInitPlan(p, initHooks{}); err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, f := range p.files {
		before[f.path], _ = os.ReadFile(f.path)
	}
	o.force = true
	p2, _ := buildInitPlan(o)
	if err := applyInitPlan(p2, initHooks{beforeWrite: func(i int) error {
		if i == 3 {
			return errors.New("disk full")
		}
		return nil
	}}); err == nil {
		t.Fatal("expected failure")
	}
	for path, want := range before {
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, want) {
			t.Errorf("%s not restored after the failed --force run", path)
		}
	}
	for _, rel := range listFiles(t, o.dir) {
		if strings.Contains(rel, ".tmp-") {
			t.Errorf("temp file left: %s", rel)
		}
	}
}

// Temp files of an earlier crashed run (which may hold a token) are removed.
func TestInitRemovesStaleTemps(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	os.MkdirAll(filepath.Join(root, "owner"), 0o700)
	stale := filepath.Join(root, "owner", ".tmp-123")
	os.WriteFile(stale, []byte("trove_approver_old"), 0o600)
	if code, out, errs := runInit(t, "", false, "--yes", "--dir", root); code != 0 {
		t.Fatalf("init failed: %s%s", out, errs)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale temp file kept")
	}
}

func TestInitWarnsInsideGitTree(t *testing.T) {
	initEnv(t)
	repo := t.TempDir()
	os.Mkdir(filepath.Join(repo, ".git"), 0o700)
	code, out, errs := runInit(t, "", false, "--yes", "--dir", filepath.Join(repo, "trove"))
	if code != 0 || !strings.Contains(errs, "git working tree") {
		t.Fatalf("no git warning: %d %s%s", code, out, errs)
	}
}

// Inside the image TROVE_INIT_DIR=/data is the default folder, and the
// printed commands use the host path.
func TestInitContainerDefaults(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "data")
	t.Setenv("TROVE_INIT_DIR", root)
	code, out, errs := runInit(t, "", false, "--yes")
	if code != 0 {
		t.Fatalf("init failed: %s%s", out, errs)
	}
	if _, err := os.Stat(filepath.Join(root, "config", "trove.json")); err != nil {
		t.Fatal("TROVE_INIT_DIR not used")
	}
	if !strings.Contains(out, `'./trove/config:/config:ro'`) || !strings.Contains(out, "./trove/agents/agent.token") || strings.Contains(out, root) {
		t.Errorf("printed commands do not use the host folder:\n%s", out)
	}
	code, out, _ = runInit(t, "", false, "--yes", "--force", "--host-dir", "/srv/trove")
	if code != 0 || !strings.Contains(out, "/srv/trove/owner/owner.token") || !strings.Contains(out, "export TROVE_URL=") {
		t.Errorf("--host-dir not used:\n%s", out)
	}
	// A Windows host folder: Windows separators and PowerShell syntax.
	code, out, _ = runInit(t, "", false, "--yes", "--force", "--host-dir", `C:\Users\me\trove`)
	if code != 0 || !strings.Contains(out, `C:\Users\me\trove\agents\agent.token`) || !strings.Contains(out, "$env:TROVE_URL") {
		t.Errorf("Windows --host-dir not used:\n%s", out)
	}
}

func TestServeListenOverride(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	if code, out, errs := runInit(t, "", false, "--yes", "--dir", root); code != 0 {
		t.Fatalf("init failed: %s%s", out, errs)
	}
	cp := filepath.Join(root, "config", "trove.json")
	cfg, err := serveConfig([]string{"--config", cp, "--listen", "0.0.0.0:8470"})
	if err != nil || cfg.Listen != "0.0.0.0:8470" {
		t.Fatalf("--listen not applied: %v %q", err, cfg.Listen)
	}
	if _, err := serveConfig([]string{"--config", cp, "--listen", "nonsense"}); err == nil {
		t.Fatal("invalid --listen accepted")
	}
	cfg, _ = serveConfig([]string{"--config", cp})
	if cfg.Listen != "127.0.0.1:8470" {
		t.Fatalf("config listen changed: %q", cfg.Listen)
	}
}

// Printed paths are single quoted, so nothing in them expands in a shell.
func TestShellQuote(t *testing.T) {
	if got := shellQuote("/a b/$HOME/it's", true); got != `'/a b/$HOME/it'\''s'` {
		t.Errorf("posix: %s", got)
	}
	if got := shellQuote(`C:\a b\$x\it's`, false); got != `'C:\a b\$x\it''s'` {
		t.Errorf("powershell: %s", got)
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// startServer runs a real server with the generated config until the test
// ends and returns its URL.
func startServer(t *testing.T, root string) string {
	t.Helper()
	cfg, err := serveConfig([]string{"--config", filepath.Join(root, "config", "trove.json")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, cfg, nil) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	url := "http://" + cfg.Listen
	tok := readTokenFile(t, filepath.Join(root, "owner", "owner.token"))
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := client.New(url, tok).Status(); err == nil {
			return url
		} else if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// propose runs sync, begin, the edit and submit as the agent and returns
// the proposal id and digest.
func propose(t *testing.T, mirror, topic string, edit func()) (string, string) {
	t.Helper()
	for _, args := range [][]string{{"sync", "--dir", mirror}, {"begin", topic, "--dir", mirror}} {
		if code, out := run(t, args...); code != 0 {
			t.Fatalf("%v: %s", args, out)
		}
	}
	edit()
	code, out := run(t, "submit", "--dir", mirror)
	m := regexp.MustCompile(`submitted proposal (\S+)\ndigest: (\S+)`).FindStringSubmatch(out)
	if code != 0 || m == nil {
		t.Fatalf("submit: %s", out)
	}
	return m[1], m[2]
}

// gitOut runs git on the knowledge base repository of a setup.
func gitOut(t *testing.T, root string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"--git-dir", filepath.Join(root, "data", "kb.git")}, args...)...).Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// End to end: the generated config starts a real server, the generated
// tokens authenticate with their roles, the agent can sync right away
// (welcome commit), and changes to the welcome note and to a new file go
// through submit and approve.
func TestInitServerStarts(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	if code, out, errs := runInit(t, "", false, "--yes", "--dir", root, "--listen", freePort(t), "--reader", "viewer"); code != 0 {
		t.Fatalf("init failed: %s%s", out, errs)
	}
	url := startServer(t, root)
	for file, role := range map[string]string{"owner/owner.token": "approver", "agents/agent.token": "agent", "readers/viewer.token": "reader"} {
		st, err := client.New(url, readTokenFile(t, filepath.Join(root, filepath.FromSlash(file)))).Status()
		if err != nil || st.Role != role {
			t.Errorf("%s: role %q, err %v", file, st.Role, err)
		}
	}
	if _, err := client.New(url, "trove_agent_"+strings.Repeat("0", 64)).Status(); err == nil {
		t.Error("an unknown token was accepted")
	}
	t.Setenv("TROVE_URL", url)
	t.Setenv("TROVE_APPROVER_TOKEN_FILE", filepath.Join(root, "owner", "owner.token"))
	t.Setenv("TROVE_TOKEN_FILE", filepath.Join(root, "agents", "agent.token"))
	mirror := t.TempDir()
	// 1. A new file next to the welcome note.
	id, digest := propose(t, mirror, "first note", func() {
		if _, err := os.Stat(filepath.Join(mirror, "INDEX.md")); err != nil {
			t.Fatal("the welcome note was not synced")
		}
		os.Mkdir(filepath.Join(mirror, "runbooks"), 0o755)
		os.WriteFile(filepath.Join(mirror, "runbooks", "first.md"), []byte(md("first", "hello")), 0o644)
	})
	if code, out := run(t, "approve", id, "--digest", digest); code != 0 || !strings.Contains(out, "applied as commit") {
		t.Fatalf("approve: %s", out)
	}
	// 2. A change to the welcome note itself.
	id, digest = propose(t, mirror, "edit welcome", func() {
		os.WriteFile(filepath.Join(mirror, "INDEX.md"), []byte(md("Home", "our notes")), 0o644)
	})
	if code, out := run(t, "approve", id, "--digest", digest); code != 0 {
		t.Fatalf("approve: %s", out)
	}
	if code, out := run(t, "audit", "verify", "--remote"); code != 0 || !strings.Contains(out, "audit chain OK") {
		t.Fatalf("audit: %s", out)
	}
	if n := gitOut(t, root, "rev-list", "--count", "main"); n != "3" {
		t.Errorf("want 3 commits (welcome + 2 approvals), got %s", n)
	}
	// Import is refused now, with a pointer to --no-welcome.
	kb := filepath.Join(t.TempDir(), "kb")
	os.Mkdir(kb, 0o700)
	os.WriteFile(filepath.Join(kb, "INDEX.md"), []byte("# KB\n"), 0o600)
	if code, out := run(t, "import", kb); code == 0 {
		t.Fatalf("import into a non-empty knowledge base: %s", out)
	}
}

// The welcome commit: one root commit with the bootstrap trailer, the
// owner as approver, the note valid for the rules, and audited.
func TestInitWelcomeCommit(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	code, out, errs := runInit(t, "", false, "--yes", "--dir", root, "--owner", "alice", "--allowed-dirs", "runbooks,notes")
	if code != 0 {
		t.Fatalf("init failed: %s%s", out, errs)
	}
	if n := gitOut(t, root, "rev-list", "--count", "main"); n != "1" {
		t.Fatalf("commits: %s", n)
	}
	msg := gitOut(t, root, "log", "-1", "--format=%B", "main")
	if !strings.Contains(msg, "Trove-Bootstrap: welcome") || !strings.Contains(msg, "Trove-Approver: alice") {
		t.Errorf("commit message: %q", msg)
	}
	if files := gitOut(t, root, "ls-tree", "-r", "--name-only", "main"); files != "INDEX.md" {
		t.Errorf("files: %q", files)
	}
	note := gitOut(t, root, "show", "main:INDEX.md")
	for _, want := range []string{"title: Welcome", "status: current", "trove begin", "trove submit", "runbooks, notes"} {
		if !strings.Contains(note, want) {
			t.Errorf("welcome note misses %q", want)
		}
	}
	if strings.ContainsAny(note, "–—") {
		t.Error("welcome note uses an en or em dash")
	}
	res, err := audit.VerifyFile(filepath.Join(root, "data", "audit.jsonl"))
	if err != nil || res.Lines != 2 {
		t.Fatalf("audit: %d lines, %v", res.Lines, err)
	}
	al, _ := os.ReadFile(filepath.Join(root, "data", "audit.jsonl"))
	if !strings.Contains(string(al), `"event":"bootstrap-intent"`) || !strings.Contains(string(al), `"event":"bootstrap"`) || !strings.Contains(string(al), `"actor":"alice"`) {
		t.Errorf("audit lines: %s", al)
	}
	if !strings.Contains(out, "welcome note (INDEX.md") {
		t.Errorf("next steps do not mention the welcome note:\n%s", out)
	}
}

// --no-welcome leaves the knowledge base empty for an import: sync is
// refused until the owner imports, and the import works.
func TestInitNoWelcomeImport(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	code, out, errs := runInit(t, "", false, "--yes", "--dir", root, "--listen", freePort(t), "--no-welcome")
	if code != 0 || !strings.Contains(out, "trove import /path/to/kb --history") {
		t.Fatalf("init failed or no import hint: %s%s", out, errs)
	}
	if _, err := os.Stat(filepath.Join(root, "data", "kb.git")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("--no-welcome touched the data folder")
	}
	url := startServer(t, root)
	t.Setenv("TROVE_URL", url)
	t.Setenv("TROVE_TOKEN_FILE", filepath.Join(root, "agents", "agent.token"))
	t.Setenv("TROVE_APPROVER_TOKEN_FILE", filepath.Join(root, "owner", "owner.token"))
	mirror := t.TempDir()
	if code, out := run(t, "sync", "--dir", mirror); code == 0 || !strings.Contains(out, "empty") {
		t.Fatalf("sync of an empty knowledge base: %s", out)
	}
	kb := filepath.Join(t.TempDir(), "kb")
	os.MkdirAll(filepath.Join(kb, "runbooks"), 0o700)
	os.WriteFile(filepath.Join(kb, "runbooks", "a.md"), []byte(md("a", "x")), 0o600)
	if code, out := run(t, "import", kb); code != 0 {
		t.Fatalf("import: %s", out)
	}
	if code, out := run(t, "sync", "--dir", mirror); code != 0 {
		t.Fatalf("sync after import: %s", out)
	}
	if strings.Contains(gitOut(t, root, "log", "--format=%B", "main"), "Trove-Bootstrap") {
		t.Error("a welcome commit was written with --no-welcome")
	}
}

// An existing knowledge base is never changed: init --force replaces the
// config and the tokens but writes no second welcome commit.
func TestInitWelcomeNotOnExistingKB(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	if code, out, errs := runInit(t, "", false, "--yes", "--dir", root); code != 0 {
		t.Fatalf("init failed: %s%s", out, errs)
	}
	head := gitOut(t, root, "rev-parse", "main")
	code, out, errs := runInit(t, "", false, "--yes", "--force", "--dir", root)
	if code != 0 || !strings.Contains(out, "was not empty") {
		t.Fatalf("init --force: %s%s", out, errs)
	}
	if gitOut(t, root, "rev-parse", "main") != head {
		t.Fatal("init --force changed the knowledge base")
	}
	if _, err := audit.VerifyFile(filepath.Join(root, "data", "audit.jsonl")); err != nil {
		t.Fatal(err)
	}
}

// While a server holds the data folder, the welcome commit cannot be
// written: init fails and leaves the earlier setup and the data untouched.
func TestInitWelcomeRefusedWhileServerRuns(t *testing.T) {
	initEnv(t)
	root := filepath.Join(t.TempDir(), "trove")
	if code, out, errs := runInit(t, "", false, "--yes", "--dir", root, "--no-welcome"); code != 0 {
		t.Fatalf("init failed: %s%s", out, errs)
	}
	before := readTokenFile(t, filepath.Join(root, "owner", "owner.token"))
	cfg, err := serveConfig([]string{"--config", filepath.Join(root, "config", "trove.json")})
	if err != nil {
		t.Fatal(err)
	}
	eng, err := server.Open(cfg, server.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	code, _, errs := runInit(t, "", false, "--yes", "--force", "--dir", root)
	if code == 0 || !strings.Contains(errs, "welcome note") {
		t.Fatalf("init must fail while the data folder is locked: %s", errs)
	}
	if readTokenFile(t, filepath.Join(root, "owner", "owner.token")) != before {
		t.Fatal("the earlier owner token was not restored")
	}
	// A fresh setup whose data folder is locked: nothing with a token stays.
	root2 := filepath.Join(t.TempDir(), "fresh")
	cfg2 := config.Default()
	cfg2.DataDir = filepath.Join(root2, "data")
	eng2, err := server.Open(cfg2, server.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng2.Close()
	if code, _, _ := runInit(t, "", false, "--yes", "--dir", root2); code == 0 {
		t.Fatal("init succeeded on a locked data folder")
	}
	for _, rel := range listFiles(t, root2) {
		if strings.HasSuffix(rel, ".token") || strings.HasPrefix(rel, "config") {
			t.Errorf("left behind: %s", rel)
		}
	}
	if _, err := os.Stat(filepath.Join(root2, "data", "kb.git")); err != nil {
		t.Error("the existing data folder was removed")
	}
}
