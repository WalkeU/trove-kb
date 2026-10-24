package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A-5: duplicate keys or data appended to a line must not verify.
func TestRegressA5NonCanonicalLines(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(p, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	l.Append(Entry{Actor: "owner", Role: "approver", Event: "approve", Proposal: "aa", Result: "ok"})
	l.Append(Entry{Actor: "owner", Role: "approver", Event: "reject", Proposal: "bb", Result: "ok"})
	raw, _ := os.ReadFile(p)
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))

	dup := bytes.Replace(lines[0], []byte(`{"seq":1,`), []byte(`{"seq":1,"actor":"mallory","event":"forged",`), 1)
	if _, err := Verify(bytes.NewReader(append(append(dup, '\n'), append(lines[1], '\n')...))); err == nil {
		t.Error("duplicate keys accepted")
	}
	trailing := append(append([]byte{}, lines[1]...), []byte(` {"seq":3,"actor":"mallory"}`)...)
	if _, err := Verify(bytes.NewReader(append(append(append([]byte{}, lines[0]...), '\n'), append(trailing, '\n')...))); err == nil {
		t.Error("trailing data accepted")
	}
	spaced := bytes.Replace(lines[0], []byte(`,"time"`), []byte(`, "time"`), 1)
	if _, err := Verify(bytes.NewReader(append(spaced, '\n'))); err == nil {
		t.Error("non-canonical whitespace accepted")
	}
}

// A-5: a saved last hash detects truncation of the log.
func TestRegressA5Anchor(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(p, time.Now)
	for i := 0; i < 4; i++ {
		l.Append(Entry{Actor: "a", Event: "e", Result: "ok"})
	}
	res, err := VerifyFile(p)
	if err != nil {
		t.Fatal(err)
	}
	anchor := res.LastHash
	l.Append(Entry{Actor: "a", Event: "e", Result: "ok"})
	res, _ = VerifyFileAnchor(p, anchor)
	if n, err := res.CheckAnchor(anchor); err != nil || n != 1 {
		t.Fatalf("anchor: %d %v", n, err)
	}
	raw, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	os.WriteFile(p, []byte(strings.Join(lines[:2], "\n")+"\n"), 0o600)
	res, err = VerifyFileAnchor(p, anchor)
	if err != nil {
		t.Fatalf("a truncated chain still verifies on its own: %v", err)
	}
	if _, err := res.CheckAnchor(anchor); err == nil {
		t.Fatal("truncation past the anchor not detected")
	}
}
