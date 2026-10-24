// Package gitrepo is a thin wrapper over the git binary. It only uses a
// bare repository and plumbing commands, so there is no working copy that
// could be modified between a check and a commit.
package gitrepo

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Branch is the only branch Trove maintains.
const Branch = "refs/heads/main"

// Repo is a bare git repository driven through the git binary.
type Repo struct {
	Dir    string // path of the bare repository
	TmpDir string // scratch directory (temporary index files, TMPDIR for git)
	cfg    string // private git config file
}

// Ident is a commit author/committer.
type Ident struct {
	Name  string
	Email string
}

// Entry is one file in a tree listing.
type Entry struct {
	Mode string
	Type string
	ID   string
}

// IsRegular reports whether the entry is a regular (non-symlink, non-submodule) file.
func (e Entry) IsRegular() bool {
	return e.Type == "blob" && (e.Mode == "100644" || e.Mode == "100755")
}

// Edit is one change applied when building a commit.
type Edit struct {
	Path    string
	Mode    string // default 100644
	Content []byte
	Blob    string // precomputed blob id (HashObject); Content is ignored then
	Delete  bool
}

// HashObject stores content as a blob and returns its id.
func (r *Repo) HashObject(ctx context.Context, content []byte) (string, error) {
	return r.hashObject(ctx, content)
}

// FetchFrom fetches main of another (validated, local) repository into
// this repository's main, which must not exist yet.
func (r *Repo) FetchFrom(ctx context.Context, srcGitDir string) error {
	_, err := r.run(ctx, nil, nil, "-c", "fetch.fsckObjects=true", "fetch", "--no-tags", "--quiet", srcGitDir, Branch+":"+Branch)
	return err
}

// Error carries git's stderr.
type Error struct {
	Args   []string
	Code   int
	Stderr string
}

func (e *Error) Error() string {
	return fmt.Sprintf("git %s: exit %d: %s", strings.Join(e.Args, " "), e.Code, strings.TrimSpace(e.Stderr))
}

// New prepares a Repo handle. It writes a private git config so that the
// user's global/system git configuration never influences the server.
func New(dir, tmpDir string) (*Repo, error) {
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return nil, err
	}
	cfg := filepath.Join(tmpDir, "gitconfig")
	content := "[safe]\n\tdirectory = *\n[init]\n\tdefaultBranch = main\n[gc]\n\tauto = 0\n[core]\n\tquotePath = false\n"
	if err := os.WriteFile(cfg, []byte(content), 0o600); err != nil {
		return nil, err
	}
	return &Repo{Dir: dir, TmpDir: tmpDir, cfg: cfg}, nil
}

func (r *Repo) env(extra []string) []string {
	var env []string
	for _, kv := range os.Environ() {
		// Never inherit GIT_DIR, GIT_INDEX_FILE and friends from the caller.
		if strings.HasPrefix(strings.ToUpper(kv), "GIT_") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+r.cfg,
		"GIT_TERMINAL_PROMPT=0",
		"TMPDIR="+r.TmpDir,
	)
	return append(env, extra...)
}

func (r *Repo) command(ctx context.Context, extraEnv []string, args ...string) *exec.Cmd {
	full := append([]string{"--git-dir", r.Dir}, args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = r.env(extraEnv)
	return cmd
}

func (r *Repo) run(ctx context.Context, extraEnv []string, stdin io.Reader, args ...string) ([]byte, error) {
	cmd := r.command(ctx, extraEnv, args...)
	cmd.Stdin = stdin
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		code := -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		return out.Bytes(), &Error{Args: args, Code: code, Stderr: errb.String() + " " + err.Error()}
	}
	return out.Bytes(), nil
}

func exitCode(err error) int {
	var ge *Error
	if errors.As(err, &ge) {
		return ge.Code
	}
	return -1
}

func trim(b []byte) string { return strings.TrimSpace(string(b)) }

// Init creates the bare repository if it does not exist yet.
func (r *Repo) Init(ctx context.Context) error {
	if _, err := os.Stat(filepath.Join(r.Dir, "HEAD")); err == nil {
		return nil
	}
	if err := os.MkdirAll(r.Dir, 0o700); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "git", "init", "--bare", "--quiet", r.Dir)
	cmd.Env = r.env(nil)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git init: %v: %s", err, out)
	}
	_, err := r.run(ctx, nil, nil, "symbolic-ref", "HEAD", Branch)
	return err
}

// Head returns the commit id of the main branch, or "" for an empty repository.
func (r *Repo) Head(ctx context.Context) (string, error) {
	out, err := r.run(ctx, nil, nil, "for-each-ref", "--format=%(objectname)", Branch)
	if err != nil {
		return "", err
	}
	return trim(out), nil
}

// ResolveCommit returns the full id of a commit, or an error if it does not exist.
func (r *Repo) ResolveCommit(ctx context.Context, rev string) (string, error) {
	if rev == "" || strings.HasPrefix(rev, "-") {
		return "", fmt.Errorf("invalid revision")
	}
	out, err := r.run(ctx, nil, nil, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("unknown commit %q", rev)
	}
	return trim(out), nil
}

// IsAncestor reports whether a is an ancestor of (or equal to) b.
func (r *Repo) IsAncestor(ctx context.Context, a, b string) (bool, error) {
	_, err := r.run(ctx, nil, nil, "merge-base", "--is-ancestor", a, b)
	if err == nil {
		return true, nil
	}
	if exitCode(err) == 1 {
		return false, nil
	}
	return false, err
}

// Tree lists every file of a commit (recursively), keyed by path.
func (r *Repo) Tree(ctx context.Context, commit string) (map[string]Entry, error) {
	files := map[string]Entry{}
	if commit == "" {
		return files, nil
	}
	out, err := r.run(ctx, nil, nil, "ls-tree", "-r", "-z", "--full-tree", commit)
	if err != nil {
		return nil, err
	}
	for _, rec := range bytes.Split(out, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		tab := bytes.IndexByte(rec, '\t')
		if tab < 0 {
			return nil, fmt.Errorf("unexpected ls-tree output")
		}
		meta := strings.Fields(string(rec[:tab]))
		if len(meta) != 3 {
			return nil, fmt.Errorf("unexpected ls-tree output")
		}
		files[string(rec[tab+1:])] = Entry{Mode: meta[0], Type: meta[1], ID: meta[2]}
	}
	return files, nil
}

// ReadBlob returns the content of a blob.
func (r *Repo) ReadBlob(ctx context.Context, id string) ([]byte, error) {
	return r.run(ctx, nil, nil, "cat-file", "blob", id)
}

func (r *Repo) hashObject(ctx context.Context, content []byte) (string, error) {
	out, err := r.run(ctx, nil, bytes.NewReader(content), "hash-object", "-w", "--no-filters", "--stdin")
	if err != nil {
		return "", err
	}
	return trim(out), nil
}

// BuildCommit creates a commit object (parent may be "" for a root commit)
// with the edits applied, using a private temporary index. It does not move
// any ref; call UpdateRef for that.
func (r *Repo) BuildCommit(ctx context.Context, parent string, edits []Edit, message string, who Ident) (string, error) {
	f, err := os.CreateTemp(r.TmpDir, "index-*")
	if err != nil {
		return "", err
	}
	index := f.Name()
	f.Close()
	os.Remove(index) // git must create the index file itself
	defer os.Remove(index)
	defer os.Remove(index + ".lock")
	env := []string{"GIT_INDEX_FILE=" + index}

	if parent != "" {
		_, err = r.run(ctx, env, nil, "read-tree", parent)
	} else {
		_, err = r.run(ctx, env, nil, "read-tree", "--empty")
	}
	if err != nil {
		return "", err
	}
	var info bytes.Buffer
	for _, e := range edits {
		if strings.ContainsAny(e.Path, "\t\n\x00") || e.Path == "" {
			return "", fmt.Errorf("invalid path for index: %q", e.Path)
		}
		if e.Delete {
			fmt.Fprintf(&info, "0 %s\t%s\n", strings.Repeat("0", 40), e.Path)
			continue
		}
		blob := e.Blob
		if blob == "" {
			var err error
			if blob, err = r.hashObject(ctx, e.Content); err != nil {
				return "", err
			}
		}
		mode := e.Mode
		if mode == "" {
			mode = "100644"
		}
		fmt.Fprintf(&info, "%s %s\t%s\n", mode, blob, e.Path)
	}
	if info.Len() > 0 {
		if _, err := r.run(ctx, env, &info, "update-index", "--index-info"); err != nil {
			return "", err
		}
	}
	out, err := r.run(ctx, env, nil, "write-tree")
	if err != nil {
		return "", err
	}
	tree := trim(out)
	args := []string{"commit-tree", tree}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	identEnv := []string{
		"GIT_AUTHOR_NAME=" + who.Name, "GIT_AUTHOR_EMAIL=" + who.Email,
		"GIT_COMMITTER_NAME=" + who.Name, "GIT_COMMITTER_EMAIL=" + who.Email,
	}
	out, err = r.run(ctx, identEnv, strings.NewReader(message), args...)
	if err != nil {
		return "", err
	}
	return trim(out), nil
}

// UpdateRef moves the main branch to newCommit only if it currently points
// to oldCommit ("" means the branch must not exist yet). This is an atomic
// compare-and-swap inside git.
func (r *Repo) UpdateRef(ctx context.Context, newCommit, oldCommit string) error {
	old := oldCommit
	if old == "" {
		old = strings.Repeat("0", len(newCommit))
	}
	_, err := r.run(ctx, nil, nil, "update-ref", "-m", "trove", Branch, newCommit, old)
	return err
}

// LogEntry is a commit id with its full message.
type LogEntry struct {
	ID      string
	Message string
}

// FindByTrailer lists commits reachable from main whose message contains
// "key: value" (fixed string search; callers must still parse the trailers).
func (r *Repo) FindByTrailer(ctx context.Context, key, value string) ([]LogEntry, error) {
	head, err := r.Head(ctx)
	if err != nil || head == "" {
		return nil, err
	}
	out, err := r.run(ctx, nil, nil, "log", "-F", "--grep="+key+": "+value, "--format=%H%x00%B%x01", head)
	if err != nil {
		return nil, err
	}
	var res []LogEntry
	for _, rec := range strings.Split(string(out), "\x01") {
		rec = strings.TrimLeft(rec, "\r\n")
		if rec == "" {
			continue
		}
		parts := strings.SplitN(rec, "\x00", 2)
		if len(parts) != 2 {
			continue
		}
		res = append(res, LogEntry{ID: strings.TrimSpace(parts[0]), Message: parts[1]})
	}
	return res, nil
}

// CommitCount returns the number of commits reachable from main.
func (r *Repo) CommitCount(ctx context.Context) (int, error) {
	head, err := r.Head(ctx)
	if err != nil || head == "" {
		return 0, err
	}
	out, err := r.run(ctx, nil, nil, "rev-list", "--count", head)
	if err != nil {
		return 0, err
	}
	var n int
	_, err = fmt.Sscanf(trim(out), "%d", &n)
	return n, err
}

// Archive writes a tar archive of commit to w.
func (r *Repo) Archive(ctx context.Context, commit string, w io.Writer) error {
	cmd := r.command(ctx, nil, "archive", "--format=tar", commit)
	var errb bytes.Buffer
	cmd.Stdout = w
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git archive: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}

// Match is one search hit.
type Match struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// Grep searches commit for a fixed string (case-insensitive, text files only).
func (r *Repo) Grep(ctx context.Context, commit, query string, limit int) ([]Match, error) {
	out, err := r.run(ctx, nil, nil, "grep", "-I", "-n", "-i", "-F", "-z", "-e", query, commit)
	if err != nil {
		if exitCode(err) == 1 {
			return nil, nil
		}
		return nil, err
	}
	var res []Match
	prefix := commit + ":"
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" {
			continue
		}
		nul := strings.IndexByte(line, 0)
		if nul < 0 {
			continue
		}
		name := strings.TrimPrefix(line[:nul], prefix)
		rest := line[nul+1:]
		sep := strings.IndexAny(rest, ":\x00")
		if sep < 0 {
			continue
		}
		var n int
		fmt.Sscanf(rest[:sep], "%d", &n)
		res = append(res, Match{Path: name, Line: n, Text: rest[sep+1:]})
		if limit > 0 && len(res) >= limit {
			break
		}
	}
	return res, nil
}

// FetchBundle verifies a bundle file and fetches its HEAD into main, with
// object checking on. The branch must not exist yet (the caller checks
// that the repo is empty).
func (r *Repo) FetchBundle(ctx context.Context, file string) error {
	if _, err := r.run(ctx, nil, nil, "bundle", "verify", "--quiet", file); err != nil {
		return err
	}
	_, err := r.run(ctx, nil, nil, "-c", "fetch.fsckObjects=true", "-c", "transfer.fsckObjects=true",
		"fetch", "--no-tags", "--quiet", file, "HEAD:"+Branch)
	return err
}

// DeleteBranch removes main if it still points to commit (used to undo a
// rejected import).
func (r *Repo) DeleteBranch(ctx context.Context, commit string) error {
	_, err := r.run(ctx, nil, nil, "update-ref", "-d", Branch, commit)
	return err
}

// ChangedPaths lists the paths that differ between two commits.
func (r *Repo) ChangedPaths(ctx context.Context, a, b string) ([]string, error) {
	out, err := r.run(ctx, nil, nil, "diff-tree", "-r", "--no-renames", "--name-only", "-z", a, b)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// HistoryBlobs calls fn for every blob reachable from commit (all
// versions in history), reading them through one "cat-file --batch"
// process. Blobs larger than maxSize are reported with nil content, so
// the caller can refuse them instead of skipping them silently. A non-nil
// error from fn stops the walk.
func (r *Repo) HistoryBlobs(ctx context.Context, commit string, maxSize int64, fn func(path string, content []byte) error) error {
	out, err := r.run(ctx, nil, nil, "rev-list", "--objects", commit)
	if err != nil {
		return err
	}
	type obj struct{ id, path string }
	var objs []obj
	for _, line := range strings.Split(string(out), "\n") {
		id, p, ok := strings.Cut(line, " ")
		if ok && p != "" {
			objs = append(objs, obj{id, p})
		}
	}
	if len(objs) == 0 {
		return nil
	}
	var in bytes.Buffer
	for _, o := range objs {
		in.WriteString(o.id + "\n")
	}
	check, err := r.run(ctx, nil, &in, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)")
	if err != nil {
		return err
	}
	var want []obj
	for i, line := range strings.Split(strings.TrimSpace(string(check)), "\n") {
		if i >= len(objs) {
			break
		}
		f := strings.Fields(line)
		if len(f) != 3 || f[1] != "blob" {
			continue
		}
		var size int64
		fmt.Sscanf(f[2], "%d", &size)
		if size > maxSize {
			if err := fn(objs[i].path, nil); err != nil {
				return err
			}
			continue
		}
		want = append(want, objs[i])
	}
	if len(want) == 0 {
		return nil
	}
	var ids bytes.Buffer
	for _, o := range want {
		ids.WriteString(o.id + "\n")
	}
	cmd := r.command(ctx, nil, "cat-file", "--batch")
	cmd.Stdin = &ids
	var errb bytes.Buffer
	cmd.Stderr = &errb
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	rd := bufio.NewReader(stdout)
	var ferr error
	for _, o := range want {
		header, err := rd.ReadString('\n')
		if err != nil {
			ferr = fmt.Errorf("cat-file --batch: %v", err)
			break
		}
		f := strings.Fields(header)
		if len(f) != 3 {
			ferr = fmt.Errorf("cat-file --batch: unexpected header %q", header)
			break
		}
		var size int64
		fmt.Sscanf(f[2], "%d", &size)
		buf := make([]byte, size+1) // content plus the trailing newline
		if _, err := io.ReadFull(rd, buf); err != nil {
			ferr = fmt.Errorf("cat-file --batch: %v", err)
			break
		}
		if err := fn(o.path, buf[:size]); err != nil {
			ferr = err
			break
		}
	}
	if ferr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return ferr
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("cat-file --batch: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}
