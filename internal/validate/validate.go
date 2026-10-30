// Package validate implements the server-side submission rules: paths,
// sizes, frontmatter, content and secret scanning (blocking) plus review
// warnings (non-blocking).
package validate

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"trove/internal/config"
	"trove/internal/diff"
	"trove/internal/gitrepo"
	"trove/internal/safe"
	"trove/internal/store"
)

// Rules is a compiled rule set.
type Rules struct {
	v       config.Validation
	l       config.Limits
	secrets []secretRule
	allowed map[string]bool
	exempt  map[string]bool
}

// New compiles the rules.
func New(v config.Validation, l config.Limits) (*Rules, error) {
	r := &Rules{v: v, l: l, allowed: map[string]bool{}, exempt: map[string]bool{}}
	r.secrets = append(r.secrets, builtinSecrets...)
	for i, expr := range v.ExtraSecretPatterns {
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("extra_secret_patterns[%d]: %w", i, err)
		}
		r.secrets = append(r.secrets, secretRule{name: fmt.Sprintf("custom pattern %d", i+1), re: re})
	}
	if len(v.AllowedDirs) == 0 {
		return nil, fmt.Errorf("validation.allowed_dirs must list at least one folder (an empty list does not mean \"everything\")")
	}
	for _, d := range v.AllowedDirs {
		d = strings.Trim(d, "/")
		if err := CheckPathSyntax(d); err != nil {
			return nil, fmt.Errorf("allowed_dirs %q: %w", d, err)
		}
		r.allowed[d] = true
	}
	for _, p := range v.FrontmatterExempt {
		r.exempt[p] = true
	}
	return r, nil
}

// CheckPath validates a proposal path: CheckPathSyntax, .md extension,
// inside an allowed folder.
func (r *Rules) CheckPath(p string) error {
	if err := CheckPathSyntax(p); err != nil {
		return err
	}
	if !strings.HasSuffix(p, ".md") {
		return fmt.Errorf("only .md files are allowed")
	}
	segs := strings.Split(p, "/")
	if len(segs) == 1 {
		if !r.v.AllowRootFiles {
			return fmt.Errorf("files in the repository root are not allowed")
		}
		return nil
	}
	if !r.allowed[segs[0]] {
		return fmt.Errorf("folder %q is not an allowed folder", segs[0])
	}
	return nil
}

// CleanScope validates and normalizes a list of scope folders.
func CleanScope(scope []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, s := range scope {
		s = strings.Trim(strings.TrimSpace(s), "/")
		if s == "" {
			continue
		}
		if err := CheckPathSyntax(s); err != nil {
			return nil, fmt.Errorf("scope %q: %w", safe.Line(s, 80), err)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, nil
}

// Topic normalizes a topic string (single line, max 200 runes).
func Topic(t string) (string, error) {
	t = safe.OneLine(t, 200)
	if t == "" {
		return "", fmt.Errorf("topic must not be empty")
	}
	return t, nil
}

// CheckTopic normalizes a topic and refuses it if it looks like it carries
// a secret: the topic goes into the audit log and the commit message,
// where it can never be removed by a later proposal.
func (r *Rules) CheckTopic(t string) (string, error) {
	t, err := Topic(t)
	if err != nil {
		return "", err
	}
	if f := r.Secrets(t); len(f) > 0 {
		return "", fmt.Errorf("the topic looks like it contains a secret (%s)", strings.TrimPrefix(f[0], "line 1: "))
	}
	return t, nil
}

// Frontmatter parses a leading YAML-like block of "key: value" lines.
// It returns ok=false if the content does not start with a block.
func Frontmatter(content string) (map[string]string, bool) {
	s := strings.TrimPrefix(content, "\ufeff")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") {
		return nil, false
	}
	rest := s[4:]
	end := -1
	lines := strings.Split(rest, "\n")
	for i, line := range lines {
		if strings.TrimRight(line, " \t") == "---" {
			end = i
			break
		}
	}
	if end < 0 {
		return nil, false
	}
	fields := map[string]string{}
	for _, line := range lines[:end] {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' || line[0] == '-' {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		fields[strings.TrimSpace(k)] = v
	}
	return fields, true
}

// ContentError reports content that is never acceptable in a note:
// invalid UTF-8, control characters (other than tab, LF, CR), Unicode tag
// characters (invisible "ASCII smuggling") and bidi controls (visual
// reordering). These have no legitimate use in a markdown knowledge base
// and are the main tools for hiding instructions from a human reviewer,
// so they block instead of only warning.
func ContentError(content string) error {
	if !utf8.ValidString(content) {
		return fmt.Errorf("content must be valid UTF-8")
	}
	line := 1
	for _, r := range content {
		switch {
		case r == '\n':
			line++
		case r == '\t' || r == '\r':
		case unicode.IsControl(r):
			return fmt.Errorf("line %d: control character U+%04X is not allowed", line, r)
		case safe.IsTag(r):
			return fmt.Errorf("line %d: invisible Unicode tag character U+%04X is not allowed", line, r)
		case safe.IsBidiControl(r):
			return fmt.Errorf("line %d: bidirectional control character U+%04X is not allowed", line, r)
		case r >= 0xE0100 && r <= 0xE01EF:
			// Variation selectors supplement: can carry hidden bytes like tag
			// characters ("emoji smuggling"). U+FE00-FE0F only warns (emoji).
			return fmt.Errorf("line %d: variation selector U+%04X is not allowed", line, r)
		}
	}
	return nil
}

// Result of a check.
type Result struct {
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// OK reports whether there are no blocking errors.
func (r Result) OK() bool { return len(r.Errors) == 0 }

// BaseFile gives access to the base version of a file.
type BaseFile func(path string) (content string, err error)

// Check validates a change set against a tree (the proposal base, and at
// approval time also HEAD). readBase is used for diff size warnings of
// modified files; pass nil to skip that (expensive) part.
func (r *Rules) Check(changes []store.Change, base map[string]gitrepo.Entry, readBase BaseFile, scope []string) Result {
	return r.check(changes, base, readBase, scope, true)
}

// CheckStructure runs only the tree-dependent rules (paths, existence,
// file/folder and case collisions, sizes): no content scanning. Approve
// uses it on the base and HEAD trees; the content of a pending proposal
// is fixed by its digest and was fully checked at submit.
func (r *Rules) CheckStructure(changes []store.Change, tree map[string]gitrepo.Entry, scope []string) Result {
	return r.check(changes, tree, nil, scope, false)
}

func (r *Rules) check(changes []store.Change, base map[string]gitrepo.Entry, readBase BaseFile, scope []string, content bool) Result {
	var res Result
	errf := func(format string, a ...any) { res.Errors = append(res.Errors, fmt.Sprintf(format, a...)) }
	warnf := func(format string, a ...any) { res.Warnings = append(res.Warnings, fmt.Sprintf(format, a...)) }

	if len(changes) == 0 {
		errf("the proposal contains no changes")
		return res
	}
	if len(changes) > r.l.MaxFiles {
		errf("too many files: %d (limit %d)", len(changes), r.l.MaxFiles)
	}
	// The index holds the resulting tree: base minus deleted files, plus
	// every put added as it is checked, so twins inside one proposal (also
	// folder twins such as notes/Sub/a.md + notes/sub/b.md) are caught.
	deleted := map[string]bool{}
	for _, c := range changes {
		if c.Op == store.OpDelete {
			deleted[c.Path] = true
		}
	}
	idx := NewPathIndex()
	for p := range base {
		if !deleted[p] {
			idx.Add(p)
		}
	}
	seen := map[string]string{} // fold key -> path
	total := 0
	topDirs := map[string]bool{}
	for _, c := range changes {
		p := c.Path
		shown := safe.Line(p, 0)
		if prev, dup := seen[FoldKey(p)]; dup {
			if prev == p {
				errf("%s: listed more than once", shown)
			} else {
				errf("%s: collides with %s on case-insensitive file systems", shown, safe.Line(prev, 0))
			}
			continue
		}
		seen[FoldKey(p)] = p
		if err := r.CheckPath(p); err != nil {
			errf("%s: %v", shown, err)
			continue
		}
		if content {
			for _, s := range r.Secrets(p) {
				errf("%s: the path looks like it contains a secret (%s)", shown, strings.TrimPrefix(s, "line 1: "))
			}
		}
		if i := strings.IndexByte(p, '/'); i > 0 {
			topDirs[p[:i]] = true
		} else {
			topDirs[""] = true
		}
		if len(scope) > 0 && !inScope(p, scope) {
			warnf("%s: outside the proposal scope (%s)", shown, strings.Join(scope, ", "))
		}
		entry, exists := base[p]
		if exists && !entry.IsRegular() {
			errf("%s: existing entry is not a regular file (symlink or submodule)", shown)
			continue
		}
		switch c.Op {
		case store.OpDelete:
			if c.Content != "" {
				errf("%s: delete must not carry content", shown)
			}
			if !exists {
				errf("%s: cannot delete, file does not exist", shown)
				continue
			}
			warnf("%s: file deleted", shown)
		case store.OpPut:
			total += len(c.Content)
			if conflict := idx.Conflict(p); conflict != "" {
				errf("%s: %s", shown, conflict)
				continue
			}
			idx.Add(p)
			if len(c.Content) > r.l.MaxFileBytes {
				errf("%s: file too large: %d bytes (limit %d)", shown, len(c.Content), r.l.MaxFileBytes)
				continue
			}
			if !content {
				continue
			}
			if err := ContentError(c.Content); err != nil {
				errf("%s: %v", shown, err)
				continue
			}
			if !r.exempt[p] && len(r.v.FrontmatterFields) > 0 {
				fm, ok := Frontmatter(c.Content)
				if !ok {
					errf("%s: missing frontmatter (--- block with %s)", shown, strings.Join(r.v.FrontmatterFields, ", "))
				} else {
					for _, f := range r.v.FrontmatterFields {
						if strings.TrimSpace(fm[f]) == "" {
							errf("%s: frontmatter field %q is missing or empty", shown, f)
						}
					}
				}
			}
			for _, s := range r.Secrets(c.Content) {
				errf("%s: possible secret, %s", shown, s)
			}
			for _, s := range r.SecretWarnings(c.Content) {
				warnf("%s: %s", shown, s)
			}
			r.contentWarnings(shown, c.Content, warnf)
			if !exists {
				warnf("%s: new file", shown)
			} else if readBase != nil {
				old, err := readBase(p)
				if err == nil {
					removed, added := diff.Stats(old, c.Content)
					if removed+added > r.l.LargeDiffLines {
						warnf("%s: large change (%d lines removed, %d added)", shown, removed, added)
					}
				}
			}
		default:
			errf("%s: unknown operation %q", shown, safe.Line(c.Op, 20))
		}
	}
	if total > r.l.MaxTotalBytes {
		errf("proposal too large: %d bytes (limit %d)", total, r.l.MaxTotalBytes)
	}
	// The scope is chosen by the agent, so it never hides this warning.
	if len(topDirs) > 1 {
		warnf("the proposal touches %d different top-level folders", len(topDirs))
	}
	if len(scope) > 1 {
		warnf("the agent declared a scope of %d folders (%s)", len(scope), strings.Join(scope, ", "))
	}
	return res
}

func inScope(p string, scope []string) bool {
	for _, s := range scope {
		if strings.HasPrefix(p, s+"/") {
			return true
		}
	}
	return false
}

var ipv4Re = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

var okNets = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC 1918
		"100.64.0.0/10",                              // CGNAT / tailnets
		"127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8", // loopback, link-local, this network
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", // documentation
		"224.0.0.0/4", "255.255.255.255/32",
	} {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		nets = append(nets, n)
	}
	return nets
}()

// IsPublicIPv4 reports whether s is an IPv4 address outside the private,
// CGNAT, loopback, link-local, documentation and multicast ranges.
func IsPublicIPv4(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return false
	}
	for _, n := range okNets {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

const maxWarnPerKind = 3

func (r *Rules) contentWarnings(shown, content string, warnf func(string, ...any)) {
	em, en, ips, inv := 0, 0, 0, 0
	for i, line := range strings.Split(content, "\n") {
		if strings.ContainsRune(line, '\u2014') {
			if em < maxWarnPerKind {
				warnf("%s: line %d contains an em dash (U+2014)", shown, i+1)
			}
			em++
		}
		if strings.ContainsRune(line, '\u2013') {
			if en < maxWarnPerKind {
				warnf("%s: line %d contains an en dash (U+2013)", shown, i+1)
			}
			en++
		}
		if j := strings.IndexFunc(line, func(r rune) bool { return r != '\t' && r != '\r' && safe.IsInvisible(r) }); j >= 0 {
			r, _ := utf8.DecodeRuneInString(line[j:])
			if inv < maxWarnPerKind {
				warnf("%s: line %d contains an invisible character U+%04X (shown escaped in the review)", shown, i+1, r)
			}
			inv++
		}
		for _, m := range ipv4Re.FindAllString(line, -1) {
			if IsPublicIPv4(m) {
				if ips < maxWarnPerKind {
					warnf("%s: line %d contains a public IP address %s", shown, i+1, m)
				}
				ips++
			}
		}
	}
	if em > maxWarnPerKind {
		warnf("%s: %d more em dash line(s)", shown, em-maxWarnPerKind)
	}
	if en > maxWarnPerKind {
		warnf("%s: %d more en dash line(s)", shown, en-maxWarnPerKind)
	}
	if inv > maxWarnPerKind {
		warnf("%s: %d more line(s) with invisible characters", shown, inv-maxWarnPerKind)
	}
	if ips > maxWarnPerKind {
		warnf("%s: %d more public IP address(es)", shown, ips-maxWarnPerKind)
	}
}

// StripBOM removes every U+FEFF (byte order mark, also the deprecated
// zero width no-break space) from note content. Windows tools write it at
// the start of a file, and it ends up in the middle when frontmatter is
// prepended to such a file. It carries no meaning in markdown, only shows
// up as a stray invisible character, so it is dropped before a proposal
// is checked and stored.
func StripBOM(content string) string {
	if !strings.ContainsRune(content, '\uFEFF') {
		return content
	}
	return strings.ReplaceAll(content, "\uFEFF", "")
}
