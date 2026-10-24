package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// C-8: Open reads only the end of the log (constant memory, no full scan
// at startup), and continues the chain from the last line.
func TestRegressC8OpenReadsOnlyTheTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	f, _ := os.Create(p)
	w := bufio.NewWriter(f)
	prev := Genesis
	n := 50000
	for i := 1; i <= n; i++ {
		e := Entry{Seq: int64(i), Time: "2026-10-24T00:00:00Z", Actor: "a", Role: "agent", Event: "e", Result: "ok", Prev: prev}
		if i == 10 {
			e.Prev = "broken" // a broken chain in the middle does not stop startup
		}
		h, _ := entryHash(e)
		e.Hash = h
		b, _ := json.Marshal(e)
		w.Write(b)
		w.WriteByte('\n')
		prev = h
	}
	w.Flush()
	f.Close()
	start := time.Now()
	l, err := Open(p, time.Now)
	if err != nil || l == nil {
		t.Fatalf("open: %v", err)
	}
	if l.seq != int64(n) || l.last != prev {
		t.Fatalf("chain position not taken from the last line: seq=%d", l.seq)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("open took %v: it scans the whole log", d)
	}
	// The full check (offline / background) still finds the break.
	if _, err := VerifyFile(p); err == nil {
		t.Fatal("broken chain not detected by Verify")
	}
}
