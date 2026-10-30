package diff

import (
	"strings"
	"testing"
)

func TestUnified(t *testing.T) {
	old := "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n"
	neu := "a\nb\nc\nd\nE\nf\ng\nh\ni\nj\nk\n"
	got := Unified(old, neu, 1)
	for _, want := range []string{"-e\n", "+E\n", "+k\n", "unchanged"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, " a\n") {
		t.Errorf("context not collapsed:\n%s", got)
	}
}

func TestStats(t *testing.T) {
	r, a := Stats("x\ny\n", "x\nz\nw\n")
	if r != 1 || a != 2 {
		t.Fatalf("got -%d +%d", r, a)
	}
	r, a = Stats("", "1\n2\n")
	if r != 0 || a != 2 {
		t.Fatalf("got -%d +%d", r, a)
	}
}

func TestWhole(t *testing.T) {
	got := Whole("a\nb\nc\nd\ne\nf\ng\n", "a\nB\nc\nd\ne\nf\ng\nh\n")
	want := " a\n-b\n+B\n c\n d\n e\n f\n g\n+h\n"
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if got := Whole("", "x\n"); got != "+x\n" {
		t.Fatalf("new file: %q", got)
	}
}
