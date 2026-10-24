package client

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func tarFiles(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for n, c := range files {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(c))
	}
	tw.Close()
	return &buf
}

// B-2: variants of .git/.trove that resolve to the same folder on
// Windows or macOS are refused, as are other special names.
func TestRegressB2MetaDirVariants(t *testing.T) {
	for _, n := range []string{
		".GIT/config", ".Git/hooks/post-checkout", ".git./description", ".git /info/exclude",
		"GIT~1/HEAD.bak", "TROVE~1/state.json", ".TROVE/state.json.bak", "CON", "notes/nul.txt",
		"a.md:stream", "notes/x.md.", "notes/x.md ", "notes/\u200bx.md",
	} {
		if _, _, err := ReadSnapshot(tarFiles(t, map[string]string{n: "x"}), 1<<20); err == nil {
			t.Errorf("snapshot entry %q must be refused", n)
		}
	}
}

// B-2 (Windows effect): nothing lands in the mirror's .git folder.
func TestRegressB2NothingWrittenIntoDotGit(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git"), 0o755)
	os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("[core]\n\tbare = false\n"), 0o644)
	ws, err := OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".GIT/config", ".git./hooks/post-checkout", ".TROVE/state.json"} {
		if files, _, err := ReadSnapshot(tarFiles(t, map[string]string{name: "[core]\n\tfsmonitor = calc.exe\n"}), 1<<20); err == nil {
			ws.ApplySnapshot("c1", files)
		}
	}
	cfg, _ := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if strings.Contains(string(cfg), "fsmonitor") {
		t.Fatal(".git/config was overwritten")
	}
	// The mirror's own .git (and any hidden entry) is not part of the KB.
	mods, _, _ := ws.Modifications()
	if len(mods) != 0 {
		t.Fatalf("hidden entries reported as modifications: %v", mods)
	}
}

// B-10: local file names in errors cannot reach the terminal raw.
func TestRegressB10EscapeInSyncError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ESC is not allowed in Windows file names")
	}
	dir := t.TempDir()
	name := "\x1b]0;owned\x07\x1b[2K\rnotes.md"
	os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644)
	ws, _ := OpenWorkspace(dir)
	ws.State.Commit = "abc"
	ws.State.Manifest = map[string]string{}
	_, err := Sync(&Client{}, ws, "")
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\x07\r") {
		t.Fatalf("escape sequence in error text: %q", err)
	}
	e := &APIError{Status: 500, Message: "bad \x1b[2J", Details: []string{"\x1b]0;x\x07"}}
	if strings.ContainsAny(e.Error(), "\x1b\x07") {
		t.Fatal("server message not escaped")
	}
}

// A-7 / B-11.2: no token over plain http to a non-loopback host unless
// explicitly allowed.
func TestRegressA7Transport(t *testing.T) {
	cases := []struct {
		url      string
		insecure bool
		ok       bool
	}{
		{"https://kb.example.com", false, true},
		{"http://127.0.0.1:8470", false, true},
		{"http://localhost:8470", false, true},
		{"http://[::1]:8470", false, true},
		{"http://192.0.2.10:8470", false, false},
		{"http://kb.example.com", false, false},
		{"http://192.0.2.10:8470", true, true},
		{"ftp://kb.example.com", true, false},
		{"not a url", true, false},
	}
	for _, c := range cases {
		if err := CheckTransport(c.url, c.insecure); (err == nil) != c.ok {
			t.Errorf("CheckTransport(%q, %v) = %v, want ok=%v", c.url, c.insecure, err, c.ok)
		}
	}
}
