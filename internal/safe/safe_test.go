package safe

import (
	"strings"
	"testing"
)

func TestTextEscapes(t *testing.T) {
	got := Text("a\x1b[31mb\u202ec\tok\nnext\x00", 0, 0)
	if strings.ContainsAny(got, "\x1b\x00\u202e") {
		t.Fatalf("dangerous runes kept: %q", got)
	}
	if !strings.Contains(got, `\u{001b}`) || !strings.Contains(got, "\tok\nnext") {
		t.Fatalf("unexpected rendering: %q", got)
	}
}

func TestTextTruncates(t *testing.T) {
	got := Text(strings.Repeat("x", 50)+"\nshort", 10, 0)
	if !strings.Contains(got, "line truncated") || !strings.Contains(got, "\nshort") {
		t.Fatalf("line truncation: %q", got)
	}
	got = Text(strings.Repeat("y", 1000), 0, 100)
	if len(got) > 200 || !strings.Contains(got, "output truncated") {
		t.Fatalf("total truncation: %d", len(got))
	}
	if Text(string([]byte{0xff}), 0, 0) != "\uFFFD" {
		t.Fatal("invalid UTF-8 not replaced")
	}
}

func TestOneLine(t *testing.T) {
	got := OneLine("  a\r\n b\x1b\t c  ", 0)
	if got != "a b c" {
		t.Fatalf("got %q", got)
	}
	if got := OneLine("abcdef", 3); got != "abc" {
		t.Fatalf("got %q", got)
	}
}
