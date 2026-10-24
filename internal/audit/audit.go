// Package audit writes a hash-chained JSON Lines log. Every line contains
// the hash of the previous line, so editing, reordering or deleting lines
// is detectable with Verify. This is tamper evidence, not immutability: a
// process with write access to the file can rewrite the whole chain.
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"trove/internal/safe"
)

// Genesis is the prev value of the first line.
var Genesis = strings.Repeat("0", 64)

// Entry is one audit line.
type Entry struct {
	Seq      int64  `json:"seq"`
	Time     string `json:"time"`
	Actor    string `json:"actor"`
	Role     string `json:"role"`
	Event    string `json:"event"`
	Proposal string `json:"proposal,omitempty"`
	Result   string `json:"result"`
	Detail   string `json:"detail,omitempty"`
	Prev     string `json:"prev"`
	Hash     string `json:"hash,omitempty"`
}

func entryHash(e Entry) (string, error) {
	e.Hash = ""
	body, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(e.Prev))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Log appends entries to a file.
type Log struct {
	mu   sync.Mutex
	path string
	seq  int64
	last string
	now  func() time.Time
}

// Open opens (or creates) the log and positions the chain after the last
// line. It reads only the end of the file (constant memory and time, so a
// large log cannot slow down or break startup); the full chain check is
// Verify. A torn last line (crash or full disk during a write) is cut off
// and reported as an error together with a usable Log.
func Open(path string, now func() time.Time) (*Log, error) {
	l := &Log{path: path, last: Genesis, now: now}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	last, cleanEnd, torn, err := lastLine(f)
	if err != nil {
		return nil, err
	}
	var warn error
	if torn {
		if err := f.Truncate(cleanEnd); err != nil {
			return nil, fmt.Errorf("cutting a torn last line: %w", err)
		}
		warn = fmt.Errorf("the last audit line was incomplete (interrupted write) and was removed")
	}
	if last == nil {
		return l, warn
	}
	var e Entry
	if err := json.Unmarshal(last, &e); err != nil || e.Hash == "" {
		return l, fmt.Errorf("the last audit line is not valid; new lines start a new chain segment")
	}
	l.seq, l.last = e.Seq, e.Hash
	return l, warn
}

// lastLine returns the last complete line of f, the offset after it, and
// whether a torn (unterminated) tail follows it.
func lastLine(f *os.File) (line []byte, cleanEnd int64, torn bool, err error) {
	st, err := f.Stat()
	if err != nil {
		return nil, 0, false, err
	}
	size := st.Size()
	if size == 0 {
		return nil, 0, false, nil
	}
	n := int64(256 << 10)
	if n > size {
		n = size
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, size-n); err != nil {
		return nil, 0, false, err
	}
	cleanEnd = size
	if buf[len(buf)-1] != '\n' {
		torn = true
		i := bytes.LastIndexByte(buf, '\n')
		if i < 0 {
			if n < size {
				return nil, 0, false, fmt.Errorf("audit log: last line longer than %d bytes", n)
			}
			return nil, 0, true, nil
		}
		cleanEnd = size - int64(len(buf)-i-1)
		buf = buf[:i+1]
	}
	buf = buf[:len(buf)-1]
	i := bytes.LastIndexByte(buf, '\n')
	if i < 0 && n < size {
		return nil, 0, false, fmt.Errorf("audit log: last line longer than %d bytes", n)
	}
	return append([]byte(nil), buf[i+1:]...), cleanEnd, torn, nil
}

// Append writes one entry (fsynced). If the write or the fsync fails, the
// file is cut back to its previous length, so a failed append never
// leaves a torn or unaccounted line that would break the chain.
func (l *Log) Append(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.Seq = l.seq + 1
	e.Time = l.now().UTC().Format(time.RFC3339Nano)
	e.Prev = l.last
	e.Detail = safe.OneLine(e.Detail, 500)
	h, err := entryHash(e)
	if err != nil {
		return err
	}
	e.Hash = h
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	before := st.Size()
	_, werr := f.Write(append(line, '\n'))
	if werr == nil {
		werr = f.Sync()
	}
	if werr != nil {
		_ = f.Truncate(before)
		f.Close()
		return werr
	}
	if err := f.Close(); err != nil {
		return err
	}
	l.seq = e.Seq
	l.last = h
	return nil
}

// Result summarizes a verification.
type Result struct {
	Lines    int
	LastSeq  int64
	LastHash string
	// AnchorFound and AfterAnchor are set when an anchor hash was given.
	AnchorFound bool
	AfterAnchor int
}

// CheckAnchor reports the anchor result of a verification made with
// VerifyAnchor / VerifyFileAnchor.
func (r Result) CheckAnchor(hash string) (after int, err error) {
	if !r.AnchorFound {
		return 0, fmt.Errorf("the saved hash %s is not in the chain (log truncated or rewritten)", hash)
	}
	return r.AfterAnchor, nil
}

// Verify checks the chain line by line and stops at the first problem.
// It streams: memory use does not grow with the log size.
func Verify(r io.Reader) (Result, error) { return VerifyAnchor(r, "") }

// VerifyAnchor is Verify that also looks for a previously saved hash.
func VerifyAnchor(r io.Reader, anchor string) (Result, error) {
	var res Result
	anchorIdx := -1
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	prev := Genesis
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Bytes()
		if len(raw) == 0 {
			return res, fmt.Errorf("line %d: empty line", lineNo)
		}
		var e Entry
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return res, fmt.Errorf("line %d: invalid JSON: %v", lineNo, err)
		}
		if e.Prev != prev {
			return res, fmt.Errorf("line %d: chain broken (prev hash does not match the previous line)", lineNo)
		}
		if e.Seq != res.LastSeq+1 {
			return res, fmt.Errorf("line %d: sequence %d, expected %d", lineNo, e.Seq, res.LastSeq+1)
		}
		h, err := entryHash(e)
		if err != nil {
			return res, err
		}
		if h != e.Hash {
			return res, fmt.Errorf("line %d: hash mismatch (line content was modified)", lineNo)
		}
		// Strict form: the raw line must be byte for byte the canonical
		// encoding. This rejects duplicate keys, reordered keys, extra
		// whitespace and data appended after the object, so the raw text
		// a human or grep reads is exactly what was hashed.
		canon, err := json.Marshal(e)
		if err != nil {
			return res, err
		}
		if !bytes.Equal(canon, raw) {
			return res, fmt.Errorf("line %d: not in canonical form (duplicate keys or extra data)", lineNo)
		}
		prev = e.Hash
		res.Lines++
		if anchor != "" && e.Hash == anchor {
			anchorIdx = res.Lines
		}
		res.LastSeq = e.Seq
		res.LastHash = e.Hash
	}
	if err := sc.Err(); err != nil {
		return res, fmt.Errorf("line %d: %v", lineNo+1, err)
	}
	if anchorIdx >= 0 {
		res.AnchorFound = true
		res.AfterAnchor = res.Lines - anchorIdx
	}
	return res, nil
}

// VerifyFileAnchor verifies a log file and looks for a saved hash.
func VerifyFileAnchor(path, anchor string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	return VerifyAnchor(f, anchor)
}

// VerifyFile verifies a log file.
func VerifyFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	return Verify(f)
}
