package validate

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trove/internal/config"
)

// TestKBNoBlockingFindings runs the import rules (path, content, secret
// scan) over a real knowledge base, read only, and requires zero blocking
// findings (D-5: no false positives on legitimate notes). It runs only
// when TROVE_KB_DIR points to a knowledge base, for example in Docker:
//
//	docker run --rm -v "<repo>:/src" -v "<kb>:/kb:ro" -e TROVE_KB_DIR=/kb -w /src golang:1.22 go test ./internal/validate -run KB -v
func TestKBNoBlockingFindings(t *testing.T) {
	root := os.Getenv("TROVE_KB_DIR")
	if root == "" {
		t.Skip("TROVE_KB_DIR not set")
	}
	cfg := config.Default()
	r, err := New(cfg.Validation, cfg.Limits)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	n := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".") && p != root {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		paths = append(paths, rel)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		n++
		if err := ContentError(string(b)); err != nil {
			t.Errorf("%s: content: %v", rel, err)
		}
		for _, f := range r.Secrets(string(b)) {
			// Only the rule name and line number: never print the value.
			t.Errorf("%s: blocking secret finding: %s", rel, f)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range PathSetProblems(paths) {
		t.Errorf("path: %s", p)
	}
	t.Logf("scanned %d files", n)
}
