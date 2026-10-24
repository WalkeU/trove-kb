package client

import (
	"archive/tar"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func orderedTar(t *testing.T, names []string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
		tw.Write([]byte("x"))
	}
	tw.Close()
	return &buf
}

// C-1 / D-7: the client checks the whole snapshot (file/folder conflicts,
// case twins of folders) before writing anything.
func TestRegressD7SnapshotCollisions(t *testing.T) {
	for _, names := range [][]string{
		{"infra/a.md", "infra/x.md", "infra/x.md/y.md"},
		{"Notes/a.md", "notes/b.md"},
		{"notes/Sub/a.md", "notes/sub/b.md"},
	} {
		if _, _, err := ReadSnapshot(orderedTar(t, names), 1<<20); err == nil {
			t.Errorf("snapshot %v must be refused", names)
		}
	}
	// ApplySnapshot itself refuses such a set and writes nothing.
	dir := t.TempDir()
	ws, _ := OpenWorkspace(dir)
	err := ws.ApplySnapshot("new", map[string][]byte{"infra/a.md": []byte("1"), "infra/x.md": []byte("2"), "infra/x.md/y.md": []byte("3")})
	if err == nil {
		t.Fatal("conflicting snapshot applied")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("files were written before the check: %v", entries)
	}
}

// C-12: the client never follows a redirect (the token would travel along).
func TestRegressC12NoRedirect(t *testing.T) {
	gotAuth := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth <- r.Header.Get("Authorization")
		w.Write([]byte(`{"commit":""}`))
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer redirector.Close()
	c := New(redirector.URL, "secret-token")
	if _, err := c.Head(); err == nil {
		t.Fatal("redirect must be an error")
	}
	select {
	case a := <-gotAuth:
		t.Fatalf("redirect followed, target got Authorization %q", a)
	default:
	}
}
