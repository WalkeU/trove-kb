package validate

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

var windowsReserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true, "conin$": true, "conout$": true, "clock$": true,
	"com0": true, "com1": true, "com2": true, "com3": true, "com4": true, "com5": true, "com6": true, "com7": true, "com8": true, "com9": true,
	"lpt0": true, "lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true, "lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// asciiPathPunct lists the ASCII punctuation allowed in path segments.
// Notably absent: backslash, colon (drive letters, NTFS streams), tilde
// (8.3 short names such as GIT~1), wildcard and shell characters.
const asciiPathPunct = " -_.()+,&'@!#="

// latinLookalikes are letters inside the allowed Latin-1 Supplement and
// Latin Extended-A blocks that imitate an ASCII letter or fold differently
// on some file systems: dotless i, kra, long s, n preceded by apostrophe.
var latinLookalikes = map[rune]bool{0x0131: true, 0x0138: true, 0x0149: true, 0x017F: true}

// allowedPathRune is a deliberate allowlist: ASCII letters, digits and a
// few punctuation marks, plus the precomposed letters of the Latin-1
// Supplement and Latin Extended-A blocks (U+00C0-U+017F: the accented
// letters of European languages, including Hungarian), minus a few
// lookalikes. Everything else is refused: combining marks (so decomposed
// NFD spellings cannot coexist with their NFC twins), other scripts
// (Cyrillic "a"), Latin Extended-B, IPA extensions, small capitals,
// modifier letters, fullwidth forms, variation selectors, invisible
// characters, non-ASCII spaces and bidi controls. This is a
// standard-library approximation of "NFC and no confusables".
func allowedPathRune(r rune) bool {
	if r < utf8.RuneSelf {
		return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(asciiPathPunct, r)
	}
	return r >= 0x00C0 && r <= 0x017F && unicode.IsLetter(r) && !latinLookalikes[r]
}

// CheckPathSyntax validates the structure of a slash separated relative
// path: canonical form, allowed characters, no empty, "." or ".."
// segments, no hidden segments (".git", ".GIT", ".trove", ".git." ...),
// no segment ending in a space or dot, no Windows device names. It is
// shared by the server (proposals, imports) and the client (snapshots),
// which must not trust the server.
func CheckPathSyntax(p string) error {
	if p == "" {
		return fmt.Errorf("empty path")
	}
	if len(p) > 255 {
		return fmt.Errorf("path too long")
	}
	if !utf8.ValidString(p) {
		return fmt.Errorf("path is not valid UTF-8")
	}
	for _, r := range p {
		if r != '/' && !allowedPathRune(r) {
			return fmt.Errorf("character %q (U+%04X) is not allowed in paths", r, r)
		}
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("absolute path")
	}
	if path.Clean(p) != p {
		return fmt.Errorf("path is not in canonical form")
	}
	for _, seg := range strings.Split(p, "/") {
		switch {
		case seg == "" || seg == "." || seg == "..":
			return fmt.Errorf("path contains %q segment", seg)
		case strings.HasPrefix(seg, "."):
			return fmt.Errorf("hidden path segment %q (for example .git) is not allowed", seg)
		case strings.HasSuffix(seg, " ") || strings.HasSuffix(seg, "."):
			return fmt.Errorf("path segment %q ends with a space or dot", seg)
		case strings.HasPrefix(seg, " "):
			return fmt.Errorf("path segment %q starts with a space", seg)
		}
		base := strings.ToLower(seg)
		if i := strings.IndexByte(base, '.'); i >= 0 {
			base = base[:i]
		}
		if windowsReserved[strings.TrimRight(base, " ")] {
			return fmt.Errorf("path segment %q is a reserved device name", seg)
		}
	}
	return nil
}

// CheckImportPath validates a path of the initial import: the same
// structural rules as proposals, any extension.
func CheckImportPath(p string) error { return CheckPathSyntax(p) }

// FoldKey is the key under which two paths collide on case-insensitive
// file systems (Windows, default macOS). Decomposed forms are already
// refused by CheckPathSyntax, so lower-casing is enough.
func FoldKey(p string) string { return strings.ToLower(p) }

// PathIndex detects paths that cannot coexist in one tree on a
// case-insensitive file system: a file and a folder with the same name
// (in any letter case), or two spellings of the same file or folder that
// differ only in letter case. It is the one shared rule for proposals,
// imports and client snapshots.
type PathIndex struct {
	files   map[string]string // fold key -> exact file path
	folders map[string]string // fold key -> exact folder path
}

// NewPathIndex returns an empty index.
func NewPathIndex() *PathIndex {
	return &PathIndex{files: map[string]string{}, folders: map[string]string{}}
}

// Conflict reports why p cannot be added ("" if it can). Adding an exact
// path that is already present is not a conflict.
func (x *PathIndex) Conflict(p string) string {
	segs := strings.Split(p, "/")
	for i := 1; i <= len(segs); i++ {
		prefix := strings.Join(segs[:i], "/")
		key := FoldKey(prefix)
		last := i == len(segs)
		if f, ok := x.files[key]; ok {
			if !last {
				return fmt.Sprintf("parent %q is a file", f)
			}
			if f != p {
				return fmt.Sprintf("collides with %q on case-insensitive file systems", f)
			}
		}
		if d, ok := x.folders[key]; ok {
			if last {
				return fmt.Sprintf("path is an existing folder %q", d)
			}
			if d != prefix {
				return fmt.Sprintf("folder %q collides with %q on case-insensitive file systems", prefix, d)
			}
		}
	}
	return ""
}

// Add records p (call Conflict first).
func (x *PathIndex) Add(p string) {
	x.files[FoldKey(p)] = p
	for i := 0; i < len(p); i++ {
		if p[i] == '/' {
			x.folders[FoldKey(p[:i])] = p[:i]
		}
	}
}

// Remove forgets a file (folders are kept; a folder that only becomes
// empty is still a conflict source, which is the safe side).
func (x *PathIndex) Remove(p string) {
	if x.files[FoldKey(p)] == p {
		delete(x.files, FoldKey(p))
	}
}

// PathSetProblems checks a whole set of paths (an import tree, a client
// snapshot) with CheckPathSyntax and the PathIndex rules, in sorted order.
func PathSetProblems(paths []string) []string {
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	idx := NewPathIndex()
	var problems []string
	for _, p := range sorted {
		if err := CheckPathSyntax(p); err != nil {
			problems = append(problems, fmt.Sprintf("%q: %v", p, err))
			continue
		}
		if c := idx.Conflict(p); c != "" {
			problems = append(problems, fmt.Sprintf("%q: %s", p, c))
			continue
		}
		idx.Add(p)
	}
	return problems
}
