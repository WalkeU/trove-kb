package server

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"trove/internal/api"
	"trove/internal/auth"
	"trove/internal/gitrepo"
	"trove/internal/store"
	"trove/internal/validate"
)

// importTimeout bounds a whole import (validation of a long history can
// take longer than one ordinary git operation).
const importTimeout = 15 * time.Minute

// ImportOptions modify an import.
type ImportOptions struct {
	// AllowSecretHistory turns secret findings in older history versions
	// (bundle mode) into warnings. Findings in HEAD always block.
	AllowSecretHistory bool
}

// Import loads the initial knowledge base into an empty repository. It is
// allowed exactly once (while the branch does not exist), approver only.
//
// mode "tar": a tar of plain files, committed as one root commit. Files
// are checked and stored one by one (memory holds one file at a time).
// mode "bundle": a git bundle whose HEAD becomes main (history preserved).
// The bundle is fetched into a separate temporary repository and fully
// validated there; only a valid history is fetched into the knowledge
// base. A rejected or interrupted import therefore leaves nothing behind
// in kb.git (no branch, no objects), and the temporary repository is
// removed on every path (also on panic); a leftover from a crash is
// removed at the next start.
//
// Every file must satisfy the client path rules (no hidden paths, no
// symlinks or submodules, no case or file/folder collisions), the content
// rules (UTF-8 text without control, tag or bidi characters) and the size
// limit, and possible secrets block the import.
func (e *Engine) Import(a auth.Actor, mode string, body io.Reader) (api.ImportResp, error) {
	return e.ImportWith(a, mode, body, ImportOptions{})
}

// ImportWith is Import with options.
func (e *Engine) ImportWith(a auth.Actor, mode string, body io.Reader, opt ImportOptions) (api.ImportResp, error) {
	if a.Role != auth.RoleApprover {
		return api.ImportResp{}, e.deny(a, "import", "", "only the approver token can import")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), importTimeout)
	defer cancel()
	head, err := e.repo.Head(ctx)
	if err != nil {
		return api.ImportResp{}, newErr(KindInternal, "%v", err)
	}
	if head != "" {
		e.logEvent(a, "import", "", "denied", "repository is not empty")
		return api.ImportResp{}, newErr(KindConflict, "import is only possible into an empty knowledge base")
	}
	if mode != "tar" && mode != "bundle" {
		return api.ImportResp{}, newErr(KindInvalid, "mode must be tar or bundle")
	}
	if err := e.mustLog(a, "import-intent", "", "pending", "mode="+mode); err != nil {
		return api.ImportResp{}, newErr(KindInternal, "audit log not writable, nothing was imported: %v", err)
	}
	var res api.ImportResp
	if mode == "tar" {
		res, err = e.importTar(ctx, a, body)
	} else {
		res, err = e.importBundle(ctx, body, opt)
	}
	if err != nil {
		e.logEvent(a, "import", "", "failed", err.Error())
		return api.ImportResp{}, err
	}
	if n, err := e.repo.CommitCount(ctx); err == nil {
		res.Commits = n
	}
	e.logEvent(a, "import", "", "ok", fmt.Sprintf("mode=%s commit=%s files=%d commits=%d warnings=%d", mode, res.Commit, res.Files, res.Commits, len(res.Warnings)))
	return res, nil
}

// maxImportFile is the largest single file an import accepts (and scans).
func (e *Engine) maxImportFile() int64 { return int64(e.cfg.Limits.MaxFileBytes) * 4 }

// checkImportTree applies the shared whole-tree rule plus the file mode rule.
func checkImportTree(t map[string]gitrepo.Entry) []string {
	paths := make([]string, 0, len(t))
	var problems []string
	for p, ent := range t {
		paths = append(paths, p)
		if !ent.IsRegular() {
			problems = append(problems, fmt.Sprintf("%q: not a regular file (mode %s)", p, ent.Mode))
		}
	}
	sort.Strings(problems)
	return append(problems, validate.PathSetProblems(paths)...)
}

// fileProblems checks one imported file: size, content rules, secrets.
func (e *Engine) fileProblems(where, name string, content []byte) []string {
	if int64(len(content)) > e.maxImportFile() {
		return []string{fmt.Sprintf("%s%s: file larger than %d bytes, refused (it cannot be fully checked)", where, name, e.maxImportFile())}
	}
	if !utf8.Valid(content) {
		return []string{fmt.Sprintf("%s%s: not UTF-8 text (binary files are not supported)", where, name)}
	}
	var out []string
	if err := validate.ContentError(string(content)); err != nil {
		out = append(out, fmt.Sprintf("%s%s: %v", where, name, err))
	}
	for _, f := range e.rules.Secrets(string(content)) {
		out = append(out, fmt.Sprintf("%s%s: possible secret, %s", where, name, f))
	}
	return out
}

func importErr(msg string, details []string) error {
	if len(details) > 20 {
		details = append(details[:20], fmt.Sprintf("... and %d more", len(details)-20))
	}
	return &Error{Kind: KindInvalid, Msg: msg, Details: details}
}

func (e *Engine) importTar(ctx context.Context, a auth.Actor, body io.Reader) (api.ImportResp, error) {
	var res api.ImportResp
	tr := tar.NewReader(body)
	var edits []gitrepo.Edit
	tree := map[string]gitrepo.Entry{}
	var problems []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return res, newErr(KindInvalid, "reading tar: %v", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		switch hdr.Typeflag {
		case tar.TypeDir, tar.TypeXGlobalHeader:
			continue
		case tar.TypeReg:
		default:
			res.Skipped = append(res.Skipped, name+" (not a regular file)")
			continue
		}
		if hidden(name) {
			res.Skipped = append(res.Skipped, name+" (hidden path)")
			continue
		}
		if _, dup := tree[name]; dup {
			return res, newErr(KindInvalid, "%q: duplicate path", name)
		}
		if hdr.Size > e.maxImportFile() {
			problems = append(problems, fmt.Sprintf("%s: file larger than %d bytes, refused", name, e.maxImportFile()))
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, e.maxImportFile()+1))
		if err != nil {
			return res, newErr(KindInvalid, "reading %q: %v", name, err)
		}
		tree[name] = gitrepo.Entry{Mode: "100644", Type: "blob"}
		if fp := e.fileProblems("", name, data); len(fp) > 0 {
			problems = append(problems, fp...)
			continue
		}
		// Store the checked blob now, so only one file is held in memory.
		blob, err := e.repo.HashObject(ctx, data)
		if err != nil {
			return res, newErr(KindInternal, "storing %q: %v", name, err)
		}
		edits = append(edits, gitrepo.Edit{Path: name, Blob: blob})
	}
	problems = append(problems, checkImportTree(tree)...)
	if len(problems) > 0 {
		return res, importErr("the import was refused, nothing was imported; fix these files and import again", problems)
	}
	if len(edits) == 0 {
		return res, newErr(KindInvalid, "the archive contains no files")
	}
	msg := fmt.Sprintf("trove: import (%d files)\n\nInitial import by %s.\n", len(edits), a.Name)
	commit, err := e.repo.BuildCommit(ctx, "", edits, msg, gitrepo.Ident{Name: e.cfg.BotName, Email: e.cfg.BotEmail})
	if err != nil {
		return res, newErr(KindInternal, "building commit: %v", err)
	}
	if err := e.repo.UpdateRef(ctx, commit, ""); err != nil {
		return res, newErr(KindConflict, "branch was created concurrently: %v", err)
	}
	res.Commit = commit
	res.Files = len(edits)
	return res, nil
}

// importBundle validates the bundle in a temporary repository and fetches
// it into the knowledge base only if everything passes.
func (e *Engine) importBundle(ctx context.Context, body io.Reader, opt ImportOptions) (res api.ImportResp, err error) {
	id, err := store.NewID()
	if err != nil {
		return res, newErr(KindInternal, "%v", err)
	}
	work := filepath.Join(e.repo.TmpDir, "import-"+id)
	// Cleanup on every path, including panics; kb.git is not touched
	// before the final fetch.
	defer os.RemoveAll(work)
	if err := os.MkdirAll(work, 0o700); err != nil {
		return res, newErr(KindInternal, "%v", err)
	}
	staging, err := gitrepo.New(filepath.Join(work, "staging.git"), filepath.Join(work, "tmp"))
	if err != nil {
		return res, newErr(KindInternal, "%v", err)
	}
	if err := staging.Init(ctx); err != nil {
		return res, newErr(KindInternal, "%v", err)
	}
	bundle := filepath.Join(work, "import.bundle")
	f, err := os.Create(bundle)
	if err != nil {
		return res, newErr(KindInternal, "%v", err)
	}
	if _, err := io.Copy(f, body); err != nil {
		f.Close()
		return res, newErr(KindInvalid, "receiving bundle: %v", err)
	}
	if err := f.Close(); err != nil {
		return res, newErr(KindInternal, "%v", err)
	}
	if err := staging.FetchBundle(ctx, bundle); err != nil {
		return res, newErr(KindInvalid, "bundle import failed: %v", err)
	}
	head, err := staging.Head(ctx)
	if err != nil || head == "" {
		return res, newErr(KindInvalid, "the bundle has no HEAD commit: %v", err)
	}
	t, err := staging.Tree(ctx, head)
	if err != nil {
		return res, newErr(KindInternal, "%v", err)
	}
	if problems := checkImportTree(t); len(problems) > 0 {
		return res, importErr("the bundle contains invalid paths, nothing was imported", problems)
	}
	var problems []string
	paths := make([]string, 0, len(t))
	for p := range t {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		b, err := staging.ReadBlob(ctx, t[p].ID)
		if err != nil {
			return res, newErr(KindInternal, "%v", err)
		}
		problems = append(problems, e.fileProblems("", p, b)...)
	}
	if len(problems) > 0 {
		return res, importErr("the HEAD of the bundle was refused, nothing was imported; fix these files and import again", problems)
	}
	// Every older version too: secrets block unless explicitly allowed;
	// blobs too large to scan always block (D-4).
	var hist, tooLarge []string
	err = staging.HistoryBlobs(ctx, head, e.maxImportFile(), func(p string, content []byte) error {
		if content == nil {
			tooLarge = append(tooLarge, fmt.Sprintf("history: %s: a version larger than %d bytes cannot be scanned, refused", p, e.maxImportFile()))
			return nil
		}
		for _, f := range e.rules.Secrets(string(content)) {
			hist = append(hist, fmt.Sprintf("history: %s: possible secret, %s", p, f))
		}
		return nil
	})
	if err != nil {
		return res, newErr(KindInternal, "scanning history: %v", err)
	}
	if len(tooLarge) > 0 {
		return res, importErr("the history contains files too large to scan, nothing was imported", tooLarge)
	}
	if len(hist) > 0 {
		sort.Strings(hist)
		if !opt.AllowSecretHistory {
			return res, importErr("possible secrets found in older history versions, nothing was imported; clean the history or import with --allow-secret-history", hist)
		}
		res.Warnings = append(res.Warnings, hist...)
	}
	if err := e.repo.FetchFrom(ctx, staging.Dir); err != nil {
		return res, newErr(KindInternal, "storing the validated history: %v", err)
	}
	final, err := e.repo.Head(ctx)
	if err != nil || final != head {
		return res, newErr(KindInternal, "the knowledge base head %q does not match the validated head %q", final, head)
	}
	res.Commit = head
	res.Files = len(t)
	return res, nil
}

func hidden(p string) bool {
	for _, seg := range strings.Split(path.Clean(p), "/") {
		if strings.HasPrefix(seg, ".") && seg != "." && seg != ".." {
			return true
		}
	}
	return false
}
