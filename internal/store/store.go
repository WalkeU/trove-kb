// Package store persists proposals as one JSON file each, written with an
// atomic replace (temp file, fsync, rename). Active proposals (draft,
// pending) live in proposals/, terminal ones in archive/.
package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// State of a proposal.
type State string

const (
	StateDraft      State = "draft"
	StatePending    State = "pending"
	StateApplied    State = "applied"
	StateRejected   State = "rejected"
	StateAborted    State = "aborted"
	StateExpired    State = "expired"
	StateSuperseded State = "superseded"
)

// Terminal reports whether no further transition is possible.
func (s State) Terminal() bool {
	switch s {
	case StateApplied, StateRejected, StateAborted, StateExpired, StateSuperseded:
		return true
	}
	return false
}

// Open reports whether the proposal still occupies a queue slot.
func (s State) Open() bool { return s == StateDraft || s == StatePending }

var transitions = map[State][]State{
	StateDraft:   {StatePending, StateAborted, StateExpired},
	StatePending: {StateApplied, StateRejected, StateAborted, StateExpired, StateSuperseded},
}

// CanTransition reports whether from -> to is allowed.
func CanTransition(from, to State) bool {
	for _, s := range transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Change operations.
const (
	OpPut    = "put"
	OpDelete = "delete"
)

// Change is one file change of a proposal.
type Change struct {
	Path    string `json:"path"`
	Op      string `json:"op"`
	Content string `json:"content,omitempty"`
	// Size is the content length, kept after the content is dropped.
	Size int `json:"size,omitempty"`
}

// Proposal is the stored metadata and content of one proposal.
type Proposal struct {
	ID            string    `json:"id"`
	State         State     `json:"state"`
	Topic         string    `json:"topic"`
	Agent         string    `json:"agent"`
	Scope         []string  `json:"scope,omitempty"`
	Base          string    `json:"base"`
	Supersedes    string    `json:"supersedes,omitempty"`
	SupersededBy  string    `json:"superseded_by,omitempty"`
	Changes       []Change  `json:"changes"`
	Digest        string    `json:"digest,omitempty"`
	Warnings      []string  `json:"warnings,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	SubmittedAt   time.Time `json:"submitted_at,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
	AppliedCommit string    `json:"applied_commit,omitempty"`
	DecidedBy     string    `json:"decided_by,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	// BytesWritten counts every byte the agent wrote into this proposal
	// (overwrites included); it feeds the per-agent daily quota.
	BytesWritten int `json:"bytes_written,omitempty"`
	// ContentDropped is set once a closed proposal no longer stores content.
	ContentDropped bool `json:"content_dropped,omitempty"`
	// Writes records written bytes per hour (by write time, not by the
	// creation time of the proposal), for the rolling daily quota.
	Writes []WriteMark `json:"writes,omitempty"`
}

// WriteMark is the number of bytes written in one hour.
type WriteMark struct {
	Hour  time.Time `json:"hour"`
	Bytes int       `json:"bytes"`
}

// AddWrite charges n bytes at time now.
func (p *Proposal) AddWrite(now time.Time, n int) {
	if n <= 0 {
		return
	}
	p.BytesWritten += n
	h := now.UTC().Truncate(time.Hour)
	if k := len(p.Writes); k > 0 && p.Writes[k-1].Hour.Equal(h) {
		p.Writes[k-1].Bytes += n
		return
	}
	p.Writes = append(p.Writes, WriteMark{Hour: h, Bytes: n})
}

// WrittenSince returns the bytes written at or after since.
func (p *Proposal) WrittenSince(since time.Time) int {
	n := 0
	for _, w := range p.Writes {
		if !w.Hour.Before(since.Truncate(time.Hour)) {
			n += w.Bytes
		}
	}
	return n
}

// Clone returns a deep copy (slices are not shared).
func (p *Proposal) Clone() *Proposal {
	q := *p
	q.Scope = append([]string(nil), p.Scope...)
	q.Changes = append([]Change(nil), p.Changes...)
	q.Warnings = append([]string(nil), p.Warnings...)
	q.Writes = append([]WriteMark(nil), p.Writes...)
	return &q
}

// DropContent removes the file contents (keeping paths, ops and sizes).
// Closed proposals do not keep content: applied content lives in git, and
// discarded content must not accumulate on disk or in memory.
func (p *Proposal) DropContent() {
	for i := range p.Changes {
		if p.Changes[i].Content != "" {
			p.Changes[i].Size = len(p.Changes[i].Content)
			p.Changes[i].Content = ""
		}
	}
	p.ContentDropped = true
}

// Marshal encodes a proposal without HTML escaping (so "<" stays one
// byte instead of six).
func Marshal(p *Proposal) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SortChanges orders changes by path (the canonical order).
func SortChanges(c []Change) {
	sort.Slice(c, func(i, j int) bool { return c[i].Path < c[j].Path })
}

// ComputeDigest returns the SHA-256 fingerprint of everything an approver
// approves: base, agent, topic, supersedes and the sorted changes.
// Paths never contain newlines (validated), so the encoding is unambiguous;
// contents are length-prefixed.
func ComputeDigest(p *Proposal) string {
	changes := append([]Change(nil), p.Changes...)
	SortChanges(changes)
	h := sha256.New()
	field := func(name, value string) {
		h.Write([]byte(name + " " + strconv.Itoa(len(value)) + "\n" + value + "\n"))
	}
	h.Write([]byte("trove-proposal-v1\n"))
	field("base", p.Base)
	field("agent", p.Agent)
	field("topic", p.Topic)
	field("supersedes", p.Supersedes)
	for _, c := range changes {
		field("op", c.Op)
		field("path", c.Path)
		field("content", c.Content)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// NewID returns a random 128-bit hex id.
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var idRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidID reports whether s looks like a proposal id.
func ValidID(s string) bool { return idRe.MatchString(s) }

// Store manages the proposal files.
type Store struct {
	activeDir  string
	archiveDir string
}

// Open creates the directories if needed.
func Open(dataDir string) (*Store, error) {
	s := &Store{
		activeDir:  filepath.Join(dataDir, "proposals"),
		archiveDir: filepath.Join(dataDir, "archive"),
	}
	for _, d := range []string{s.activeDir, s.archiveDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// LoadAll reads the proposals. Archived proposals are loaded without
// content, and only if they changed after since (older ones stay on disk
// only). If a proposal exists in both directories (crash between archive
// write and active removal), the archived copy wins and the active file
// is removed.
func (s *Store) LoadAll(since time.Time) (map[string]*Proposal, error) {
	all := map[string]*Proposal{}
	archived, err := s.loadDir(s.archiveDir)
	if err != nil {
		return nil, err
	}
	for id, p := range archived {
		if !p.ContentDropped {
			p.DropContent()
		}
		if p.UpdatedAt.Before(since) {
			continue
		}
		all[id] = p
	}
	active, err := s.loadDir(s.activeDir)
	if err != nil {
		return nil, err
	}
	for id, p := range active {
		if _, dup := archived[id]; dup {
			os.Remove(filepath.Join(s.activeDir, id+".json"))
			continue
		}
		all[id] = p
	}
	return all, nil
}

func (s *Store) loadDir(dir string) (map[string]*Proposal, error) {
	res := map[string]*Proposal{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".json" {
			continue
		}
		id := name[:len(name)-len(".json")]
		if !ValidID(id) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		var p Proposal
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if p.ID != id {
			return nil, fmt.Errorf("%s: id mismatch", name)
		}
		res[id] = &p
	}
	return res, nil
}

// Save writes the proposal atomically. Terminal proposals are written to
// the archive first and then removed from the active directory.
func (s *Store) Save(p *Proposal) error {
	if !ValidID(p.ID) {
		return errors.New("invalid proposal id")
	}
	if p.State.Terminal() && !p.ContentDropped {
		p.DropContent()
	}
	data, err := Marshal(p)
	if err != nil {
		return err
	}
	name := p.ID + ".json"
	if p.State.Terminal() {
		if err := WriteFileAtomic(filepath.Join(s.archiveDir, name), data); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(s.activeDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		syncDir(s.activeDir)
		return nil
	}
	return WriteFileAtomic(filepath.Join(s.activeDir, name), data)
}

// WriteFileAtomic writes data to path via a temp file in the same
// directory, fsyncs it, renames it over path and fsyncs the directory.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	syncDir(dir)
	return nil
}

// syncDir fsyncs a directory where the OS supports it (best effort; it
// is not possible on Windows).
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	d.Close()
}
