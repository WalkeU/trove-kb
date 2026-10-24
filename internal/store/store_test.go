package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTransitions(t *testing.T) {
	if !CanTransition(StateDraft, StatePending) || !CanTransition(StatePending, StateApplied) {
		t.Fatal("valid transition refused")
	}
	for _, from := range []State{StateApplied, StateRejected, StateAborted, StateExpired, StateSuperseded} {
		for _, to := range []State{StatePending, StateApplied, StateDraft} {
			if CanTransition(from, to) {
				t.Errorf("%s -> %s must be impossible", from, to)
			}
		}
	}
	if CanTransition(StateDraft, StateApplied) {
		t.Error("a draft cannot be applied")
	}
}

func TestSaveArchiveAndReload(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := NewID()
	p := &Proposal{ID: id, State: StatePending, Topic: "t", CreatedAt: time.Now().UTC(), Changes: []Change{{Path: "a.md", Op: OpPut, Content: "x"}}}
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	p.State = StateApplied
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "proposals", id+".json")); !os.IsNotExist(err) {
		t.Fatal("terminal proposal still in proposals/")
	}
	// Simulate a crash that left a stale active copy behind.
	p.State = StatePending
	data := []byte(`{"id":"` + id + `","state":"pending"}`)
	if err := os.WriteFile(filepath.Join(dir, "proposals", id+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	all, err := s.LoadAll(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if all[id].State != StateApplied {
		t.Fatalf("archived copy must win, got %s", all[id].State)
	}
	if _, err := os.Stat(filepath.Join(dir, "proposals", id+".json")); !os.IsNotExist(err) {
		t.Fatal("stale active copy not cleaned up")
	}
	if err := s.Save(&Proposal{ID: "../x"}); err == nil {
		t.Fatal("invalid id must not be saved")
	}
}

func TestLockExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trove.lock")
	l, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(path); err == nil {
		t.Fatal("second lock must fail")
	}
	l.Release()
	l2, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	l2.Release()
}
