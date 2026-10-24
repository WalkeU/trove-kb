package client

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"trove/internal/safe"
	"trove/internal/store"
	"trove/internal/validate"
)

// MetaDir is the per-mirror metadata directory.
const MetaDir = ".trove"

// State is the local mirror state (.trove/state.json).
type State struct {
	URL       string                       `json:"url,omitempty"`
	Commit    string                       `json:"commit,omitempty"`
	Manifest  map[string]string            `json:"manifest,omitempty"`  // path -> sha256 at Commit
	Drafts    map[string]string            `json:"drafts,omitempty"`    // draft id -> base commit
	Submitted map[string]map[string]string `json:"submitted,omitempty"` // proposal id -> path -> sha256 ("" = deleted)
}

// Workspace is a local mirror directory.
type Workspace struct {
	Dir   string
	State State
}

// Mod is a local modification relative to the synced commit.
type Mod struct {
	Path    string
	Kind    string // added | modified | deleted
	Hash    string // sha256 of the current content, "" when deleted
	Covered string // id of a submitted proposal carrying exactly this change
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// OpenWorkspace loads the mirror state of dir (an empty state if none).
func OpenWorkspace(dir string) (*Workspace, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", abs)
	}
	w := &Workspace{Dir: abs}
	data, err := os.ReadFile(filepath.Join(abs, MetaDir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return w, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &w.State); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(MetaDir, "state.json"), err)
	}
	return w, nil
}

// Save writes the state atomically.
func (w *Workspace) Save() error {
	if err := os.MkdirAll(filepath.Join(w.Dir, MetaDir), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(w.State, "", "  ")
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(filepath.Join(w.Dir, MetaDir, "state.json"), data)
}

// Synced reports whether the mirror has been synced at least once.
func (w *Workspace) Synced() bool { return w.State.Commit != "" }

// Scan hashes every regular file of the mirror (except .trove and .git).
// Symlinks and other special files are reported as problems.
func (w *Workspace) Scan() (map[string]string, []string, error) {
	files := map[string]string{}
	var problems []string
	err := filepath.WalkDir(w.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(w.Dir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		// Hidden entries (.trove, .git, editor folders) are never part of
		// the knowledge base: the server refuses hidden paths.
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			problems = append(problems, rel+": symbolic links are not supported")
			return nil
		}
		if !d.Type().IsRegular() {
			problems = append(problems, rel+": not a regular file")
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[rel] = sum(b)
		return nil
	})
	return files, problems, err
}

// Modifications compares the mirror to the synced manifest.
func (w *Workspace) Modifications() ([]Mod, []string, error) {
	files, problems, err := w.Scan()
	if err != nil {
		return nil, nil, err
	}
	var mods []Mod
	for p, h := range files {
		old, ok := w.State.Manifest[p]
		switch {
		case !ok:
			mods = append(mods, Mod{Path: p, Kind: "added", Hash: h})
		case old != h:
			mods = append(mods, Mod{Path: p, Kind: "modified", Hash: h})
		}
	}
	for p := range w.State.Manifest {
		if _, ok := files[p]; !ok {
			mods = append(mods, Mod{Path: p, Kind: "deleted"})
		}
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	ids := make([]string, 0, len(w.State.Submitted))
	for id := range w.State.Submitted {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for i := range mods {
		for _, id := range ids {
			if h, ok := w.State.Submitted[id][mods[i].Path]; ok && h == mods[i].Hash {
				mods[i].Covered = id
				break
			}
		}
	}
	return mods, problems, nil
}

// localPath maps a slash path to a file below the mirror, refusing
// anything that could escape it.
func (w *Workspace) localPath(p string) (string, error) {
	if err := safeRel(p); err != nil {
		return "", err
	}
	return filepath.Join(w.Dir, filepath.FromSlash(p)), nil
}

// safeRel applies the server's path rules on the client too: the client
// must not trust the server (or the network). This refuses every hidden
// segment in any letter case (.git, .GIT, .git., .TROVE), 8.3 short names
// (GIT~1), NTFS streams and drive letters (":"), backslashes, device
// names, trailing dots and spaces, and non-Latin or invisible characters.
func safeRel(p string) error {
	if err := validate.CheckPathSyntax(p); err != nil {
		return fmt.Errorf("unsafe path %s: %v", safe.Line(fmt.Sprintf("%q", p), 300), err)
	}
	return nil
}

// ReadLocal reads a mirror file by slash path.
func (w *Workspace) ReadLocal(p string) ([]byte, error) {
	lp, err := w.localPath(p)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(lp)
}

// ReadSnapshot reads a tar stream into memory (regular files only).
func ReadSnapshot(r io.Reader, maxBytes int64) (map[string][]byte, []string, error) {
	files := map[string][]byte{}
	var skipped []string
	var total int64
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("reading snapshot: %w", err)
		}
		switch hdr.Typeflag {
		case tar.TypeDir, tar.TypeXGlobalHeader:
			continue
		case tar.TypeReg:
		default:
			skipped = append(skipped, hdr.Name)
			continue
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		if err := safeRel(name); err != nil {
			return nil, nil, fmt.Errorf("snapshot contains %v", err)
		}
		if _, dup := files[name]; dup {
			return nil, nil, fmt.Errorf("snapshot contains %s twice", safe.Line(fmt.Sprintf("%q", name), 300))
		}
		total += hdr.Size
		if total > maxBytes {
			return nil, nil, fmt.Errorf("snapshot larger than %d bytes", maxBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
		if err != nil {
			return nil, nil, err
		}
		files[name] = data
	}
	if err := checkSnapshot(files); err != nil {
		return nil, nil, err
	}
	return files, skipped, nil
}

// checkSnapshot applies the server's whole-tree rule (validate.PathSetProblems:
// path syntax, file/folder conflicts, case twins of files and folders) to
// a complete snapshot, before anything is written to the mirror.
func checkSnapshot(files map[string][]byte) error {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	if problems := validate.PathSetProblems(paths); len(problems) > 0 {
		return fmt.Errorf("snapshot refused, nothing was written: %s", safe.Line(strings.Join(problems, "; "), 2000))
	}
	return nil
}

// ApplySnapshot replaces the mirror content with files and records commit.
// The caller must have checked that no uncovered local modification exists.
func (w *Workspace) ApplySnapshot(commit string, files map[string][]byte) error {
	if err := checkSnapshot(files); err != nil {
		return err
	}
	current, _, err := w.Scan()
	if err != nil {
		return err
	}
	// Remove files that are not part of the new snapshot.
	for p := range current {
		if _, keep := files[p]; keep {
			continue
		}
		lp, err := w.localPath(p)
		if err != nil {
			continue
		}
		if err := os.Remove(lp); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		w.removeEmptyParents(p)
	}
	// Folders of files deleted locally (already gone) may be left empty.
	for p := range w.State.Manifest {
		if _, keep := files[p]; !keep {
			w.removeEmptyParents(p)
		}
	}
	manifest := map[string]string{}
	names := make([]string, 0, len(files))
	for p := range files {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		data := files[p]
		h := sum(data)
		manifest[p] = h
		if current[p] == h {
			continue
		}
		lp, err := w.localPath(p)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(lp), 0o755); err != nil {
			return err
		}
		if err := store.WriteFileAtomic(lp, data); err != nil {
			return err
		}
	}
	w.State.Commit = commit
	w.State.Manifest = manifest
	w.State.Submitted = nil
	return w.Save()
}

func (w *Workspace) removeEmptyParents(p string) {
	dir := path.Dir(p)
	for dir != "." && dir != "/" && dir != "" {
		lp, err := w.localPath(dir)
		if err != nil || os.Remove(lp) != nil {
			return
		}
		dir = path.Dir(dir)
	}
}

// WriteReference stores a copy of a proposal's changes under
// .trove/rebase/<id>/ so the agent can redo them after a rebase.
func (w *Workspace) WriteReference(id string, changes []store.Change) (string, error) {
	if !store.ValidID(id) {
		return "", fmt.Errorf("invalid id")
	}
	root := filepath.Join(w.Dir, MetaDir, "rebase", id)
	var deleted []string
	for _, c := range changes {
		if err := safeRel(c.Path); err != nil {
			return "", err
		}
		if c.Op == store.OpDelete {
			deleted = append(deleted, c.Path)
			continue
		}
		lp := filepath.Join(root, filepath.FromSlash(c.Path))
		if err := os.MkdirAll(filepath.Dir(lp), 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(lp, []byte(c.Content), 0o644); err != nil {
			return "", err
		}
	}
	if len(deleted) > 0 {
		if err := os.MkdirAll(root, 0o755); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(root, "DELETED.txt"), []byte(strings.Join(deleted, "\n")+"\n"), 0o644); err != nil {
			return "", err
		}
	}
	return root, nil
}
