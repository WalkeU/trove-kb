package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"trove/internal/safe"
)

// SecurityLog records rejected attempts (role violations, limit hits,
// refused submissions). It is kept apart from the hash-chained audit log
// so that a client sending many refused requests cannot fill the audit
// log (and with it the disk that fail-closed approvals need):
//
//   - per minute, at most PerKey lines per (actor, event, reason) and at
//     most PerMinute lines in total are written; the rest is counted and
//     summarized when the minute ends;
//   - the file is rotated once it reaches MaxBytes (one old generation,
//     path + ".1"), so it never uses more than about 2*MaxBytes.
//
// It is best effort: write errors are reported on stderr, never returned.
type SecurityLog struct {
	mu        sync.Mutex
	path      string
	now       func() time.Time
	MaxBytes  int64
	PerKey    int
	PerMinute int

	window     time.Time
	perKey     map[string]int
	suppressed map[string]int
	total      int
}

// SecurityEntry is one line of the security log.
type SecurityEntry struct {
	Time       string `json:"time"`
	Actor      string `json:"actor"`
	Role       string `json:"role"`
	Event      string `json:"event"`
	Proposal   string `json:"proposal,omitempty"`
	Reason     string `json:"reason"`
	Suppressed int    `json:"suppressed,omitempty"`
}

// NewSecurityLog returns a security log writing to path.
func NewSecurityLog(path string, now func() time.Time) *SecurityLog {
	return &SecurityLog{path: path, now: now, MaxBytes: 8 << 20, PerKey: 5, PerMinute: 120,
		perKey: map[string]int{}, suppressed: map[string]int{}}
}

// Record logs a rejected attempt, subject to the rate limits.
func (s *SecurityLog) Record(actor, role, event, proposal, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	minute := now.Truncate(time.Minute)
	if !minute.Equal(s.window) {
		s.flushLocked()
		s.window, s.perKey, s.suppressed, s.total = minute, map[string]int{}, map[string]int{}, 0
	}
	reason = safe.OneLine(reason, 300)
	key := actor + "\x00" + event + "\x00" + reason
	if s.perKey[key] >= s.PerKey || s.total >= s.PerMinute {
		s.suppressed[key]++
		return
	}
	s.perKey[key]++
	s.total++
	s.writeLocked(SecurityEntry{Time: now.Format(time.RFC3339Nano), Actor: actor, Role: role, Event: event, Proposal: proposal, Reason: reason})
}

// Flush writes the summaries of the current minute (used at shutdown and in tests).
func (s *SecurityLog) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushLocked()
	s.suppressed = map[string]int{}
}

func (s *SecurityLog) flushLocked() {
	for key, n := range s.suppressed {
		var actor, event, reason string
		parts := splitKey(key)
		actor, event, reason = parts[0], parts[1], parts[2]
		s.writeLocked(SecurityEntry{Time: s.window.Add(time.Minute).Format(time.RFC3339Nano), Actor: actor, Event: event,
			Reason: reason, Suppressed: n})
	}
}

func splitKey(k string) [3]string {
	var out [3]string
	i := 0
	start := 0
	for j := 0; j < len(k) && i < 2; j++ {
		if k[j] == 0 {
			out[i] = k[start:j]
			i++
			start = j + 1
		}
	}
	out[i] = k[start:]
	return out
}

func (s *SecurityLog) writeLocked(e SecurityEntry) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	b = append(b, '\n')
	if st, err := os.Stat(s.path); err == nil && st.Size()+int64(len(b)) > s.MaxBytes {
		if err := os.Rename(s.path, s.path+".1"); err != nil {
			fmt.Fprintf(os.Stderr, "trove: rotating security log: %v\n", err)
		}
	}
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "trove: security log: %v\n", err)
		return
	}
	if _, err := f.Write(b); err != nil {
		fmt.Fprintf(os.Stderr, "trove: security log: %v\n", err)
	}
	f.Close()
}
