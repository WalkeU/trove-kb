package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeLog(t *testing.T, n int) (string, []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path, func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := l.Append(Entry{Actor: "a", Role: "agent", Event: "submit", Proposal: "p", Result: "ok", Detail: "line\nbreak"}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func verifyLines(lines []string) error {
	_, err := Verify(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	return err
}

func TestChainValid(t *testing.T) {
	path, lines := writeLog(t, 5)
	res, err := VerifyFile(path)
	if err != nil || res.Lines != 5 {
		t.Fatalf("valid log rejected: %v (%d lines)", err, res.Lines)
	}
	if strings.Contains(lines[0], `line\nbreak`) {
		t.Fatal("detail must be stored as one line")
	}
	// Reopening continues the chain.
	l, err := Open(path, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append(Entry{Actor: "b", Event: "approve", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	if res, err := VerifyFile(path); err != nil || res.Lines != 6 {
		t.Fatalf("chain broken after reopen: %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	_, lines := writeLog(t, 5)
	modified := append([]string(nil), lines...)
	modified[2] = strings.Replace(modified[2], `"result":"ok"`, `"result":"denied"`, 1)
	if verifyLines(modified) == nil {
		t.Error("modified line not detected")
	}
	deleted := append(append([]string(nil), lines[:2]...), lines[3:]...)
	if verifyLines(deleted) == nil {
		t.Error("deleted middle line not detected")
	}
	swapped := append([]string(nil), lines...)
	swapped[1], swapped[2] = swapped[2], swapped[1]
	if verifyLines(swapped) == nil {
		t.Error("reordered lines not detected")
	}
	if verifyLines(lines[1:]) == nil {
		t.Error("removed first line not detected")
	}
	extra := append(append([]string(nil), lines...), `{"seq":6}`)
	if verifyLines(extra) == nil {
		t.Error("forged line not detected")
	}
	if verifyLines(lines) != nil {
		t.Error("original must still verify")
	}
}

// C-11: a torn last line (interrupted write) is cut off at Open, reported,
// and the chain continues from the last complete line.
func TestOpenCutsTornLastLine(t *testing.T) {
	path, lines := writeLog(t, 3)
	torn := strings.Join(lines, "\n") + "\n" + lines[2][:20]
	if err := os.WriteFile(path, []byte(torn), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Open(path, time.Now)
	if err == nil || l == nil {
		t.Fatal("Open must report the torn line and return a usable log")
	}
	if err := l.Append(Entry{Actor: "b", Event: "e", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	if res, err := VerifyFile(path); err != nil || res.Lines != 4 {
		t.Fatalf("chain broken after recovering from a torn line: %v (%d lines)", err, res.Lines)
	}
}
