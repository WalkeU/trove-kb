package client

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"trove/internal/store"
)

func tarWith(t *testing.T, entries ...*tar.Header) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg && h.Size > 0 {
			tw.Write(bytes.Repeat([]byte("x"), int(h.Size)))
		}
	}
	tw.Close()
	return &buf
}

func reg(name string) *tar.Header {
	return &tar.Header{Name: name, Typeflag: tar.TypeReg, Size: 3, Mode: 0o644}
}

func TestReadSnapshotRejectsEscapes(t *testing.T) {
	for _, name := range []string{"../evil.md", "/abs.md", "a/../../x.md", ".trove/state.json", ".git/config", `a\..\b.md`, "C:/x.md"} {
		if _, _, err := ReadSnapshot(tarWith(t, reg(name)), 1<<20); err == nil {
			t.Errorf("entry %q must be rejected", name)
		}
	}
	files, skipped, err := ReadSnapshot(tarWith(t, reg("ok.md"), &tar.Header{Name: "link.md", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}), 1<<20)
	if err != nil || len(files) != 1 || len(skipped) != 1 {
		t.Fatalf("symlink must be skipped: %v %v %v", err, files, skipped)
	}
	if _, _, err := ReadSnapshot(tarWith(t, reg("A.md"), reg("a.md")), 1<<20); err == nil {
		t.Error("case collision must be rejected")
	}
	if _, _, err := ReadSnapshot(tarWith(t, reg("a.md"), reg("b.md")), 4); err == nil {
		t.Error("size limit not enforced")
	}
}

func TestModificationsAndCoverage(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWorkspace(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.ApplySnapshot("c1", map[string][]byte{"a.md": []byte("1"), "sub/b.md": []byte("2")}); err != nil {
		t.Fatal(err)
	}
	mods, _, err := w.Modifications()
	if err != nil || len(mods) != 0 {
		t.Fatalf("fresh mirror has modifications: %v %v", mods, err)
	}
	os.WriteFile(filepath.Join(dir, "a.md"), []byte("changed"), 0o644)
	os.Remove(filepath.Join(dir, "sub", "b.md"))
	os.WriteFile(filepath.Join(dir, "new.md"), []byte("n"), 0o644)
	mods, _, _ = w.Modifications()
	kinds := map[string]string{}
	for _, m := range mods {
		kinds[m.Path] = m.Kind
	}
	if kinds["a.md"] != "modified" || kinds["sub/b.md"] != "deleted" || kinds["new.md"] != "added" {
		t.Fatalf("unexpected modifications: %v", kinds)
	}
	changes, err := PendingChanges(w, []string{"a.md", "sub"})
	if err != nil || len(changes) != 2 {
		t.Fatalf("path filter: %v %v", changes, err)
	}
	w.State.Submitted = map[string]map[string]string{"p1": {"a.md": sum([]byte("changed"))}}
	mods, _, _ = w.Modifications()
	for _, m := range mods {
		if (m.Path == "a.md") != (m.Covered == "p1") {
			t.Fatalf("coverage wrong for %s: %q", m.Path, m.Covered)
		}
	}
	// ApplySnapshot restores the snapshot and removes files not in it.
	if err := w.ApplySnapshot("c2", map[string][]byte{"a.md": []byte("1")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "new.md")); !os.IsNotExist(err) {
		t.Fatal("file outside the snapshot not removed")
	}
	if _, err := os.Stat(filepath.Join(dir, "sub")); !os.IsNotExist(err) {
		t.Fatal("empty folder not removed")
	}
	reopened, err := OpenWorkspace(dir)
	if err != nil || reopened.State.Commit != "c2" {
		t.Fatalf("state not saved: %v", err)
	}
}

func TestScanReportsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "link.md")); err != nil {
		t.Skip("symlinks not available: ", err)
	}
	w, _ := OpenWorkspace(dir)
	_, problems, err := w.Scan()
	if err != nil || len(problems) != 1 {
		t.Fatalf("symlink not reported: %v %v", problems, err)
	}
	if _, err := PendingChanges(w, nil); err == nil {
		t.Fatal("submit must refuse a mirror with symlinks")
	}
}

func TestWriteReferenceRejectsEscapes(t *testing.T) {
	w, _ := OpenWorkspace(t.TempDir())
	_, err := w.WriteReference("0123456789abcdef0123456789abcdef", []store.Change{{Path: "../x.md", Op: "put", Content: "x"}})
	if err == nil {
		t.Fatal("escape not rejected")
	}
	if _, err := w.WriteReference("../../x", nil); err == nil {
		t.Fatal("bad id not rejected")
	}
}
