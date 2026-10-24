package validate

import (
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"trove/internal/safe"
)

// secretRule is a line pattern; accept (optional) filters placeholders.
type secretRule struct {
	name   string
	re     *regexp.Regexp
	accept func(m []string) bool
}

var envRef = regexp.MustCompile(`^\$(\{|\(|[A-Z_][A-Z0-9_]*$)`)
var dottedIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)
var identLike = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)

// placeholderWords mark documentation values ("passwordhere", "changeme",
// "your-token", "<REMOVED>") that are not secrets.
var placeholderWords = []string{"here", "changeme", "change_me", "change-me", "example", "your", "placeholder",
	"redacted", "removed", "eltavolitva", "elt\u00e1vol\u00edtva", "dummy", "sample", "xxx", "todo", "fixme", "...", "\u2026"}

// isPlaceholder recognizes documentation placeholders that are not secrets.
func isPlaceholder(v string) bool {
	if v == "" || strings.HasPrefix(v, "<") || strings.HasPrefix(v, "{{") || envRef.MatchString(v) {
		return true
	}
	first, _ := utf8.DecodeRuneInString(v)
	if strings.Trim(v, "*xX.-_") == "" || strings.Trim(v, string(first)) == "" { // all the same character
		return true
	}
	l := strings.ToLower(v)
	for _, w := range placeholderWords {
		if strings.Contains(l, w) {
			return true
		}
	}
	switch l {
	case "password", "passwd", "secret", "token", "jelszo", "jelsz\u00f3", "true", "false", "null", "none", "nil", "yes", "no":
		return true
	}
	return false
}

// isCode recognizes values that are program text, not literal secrets:
// function calls, indexing, templates, dotted identifiers, paths.
func isCode(v string) bool {
	return strings.ContainsAny(v, "()[]{}") || strings.Contains(v, "->") || dottedIdent.MatchString(v) ||
		strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") || strings.HasPrefix(v, ".")
}

func hasDigit(s string) bool  { return strings.IndexFunc(s, unicode.IsDigit) >= 0 }
func hasLetter(s string) bool { return strings.IndexFunc(s, unicode.IsLetter) >= 0 }
func hasUpperOrSymbol(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return unicode.IsUpper(r) || unicode.IsPunct(r) || unicode.IsSymbol(r) }) >= 0
}

// credKeys are the key words of a credential assignment (longest first),
// including Hungarian (jelszó) and German (Passwort, Kennwort).
const credKeys = `jelsz[o\x{f3}]|passw(?:or)?d|passwort|kennwort|pass|pwd|pw|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?key|private[_-]?key`

// Built-in rules. A match blocks the submission.
var builtinSecrets = []secretRule{
	{name: "private key block", re: regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY`)},
	{
		// name=value, name := value, name: value, "name": "value". The key
		// must start a word (OLDPWD, bypass do not count; DB_PASSWORD does).
		name: "credential assignment",
		re:   regexp.MustCompile(`(?i)(?:^|[^\pL])(` + credKeys + `)["']?\s*(:=|=|:)\s*(["'` + "`" + `]?)([^\s"'<>` + "`" + `]+)`),
		accept: func(m []string) bool {
			sep, quoted, v := m[2], m[3] != "", strings.TrimRight(m[4], ",;.")
			if isPlaceholder(v) || isCode(v) {
				return false
			}
			switch sep {
			case "=":
				return len(v) >= 6
			case ":=":
				// Go-style assignment: only literal, password-shaped values.
				return len(v) >= 6 && hasDigit(v) && hasLetter(v)
			}
			// "key: value" is also ordinary prose ("token: see the vault",
			// "passwd: host-104 /path"), so only a quoted value or a
			// password-shaped one (letters, digits and an upper case letter
			// or symbol, not a lower case host or id) counts.
			if len(v) < 6 {
				return false
			}
			if quoted {
				return true
			}
			return hasDigit(v) && hasLetter(v) && hasUpperOrSymbol(v) && !identLike.MatchString(v)
		},
	}, {
		name: "credentials in URL",
		re:   regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@]+:([^\s/@]+)@`),
		accept: func(m []string) bool {
			return !isPlaceholder(m[1])
		},
	},
	{name: "GitHub token", re: regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`)},
	{name: "GitLab token", re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`)},
	{name: "AWS access key id", re: regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{name: "Slack token", re: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{name: "Telegram bot token", re: regexp.MustCompile(`\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b`)},
	{name: "OpenAI/Anthropic style key", re: regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`)},
	{name: "Google API key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{name: "JSON Web Token", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{name: "Tailscale/Headscale key", re: regexp.MustCompile(`\btskey-[a-z]+-[A-Za-z0-9-]{10,}`)},
	{name: "Stripe secret key", re: regexp.MustCompile(`\b(sk|rk)_live_[A-Za-z0-9]{16,}`)},
	{name: "npm token", re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{name: "Hugging Face token", re: regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}\b`)},
	{name: "age secret key", re: regexp.MustCompile(`AGE-SECRET-KEY-1[0-9A-Z]{50,}`)},
}

// pemAcrossLines catches a private key header split over lines or spaces.
var pemAcrossLines = regexp.MustCompile(`-----BEGIN[A-Z0-9 \t\r\n]{0,60}PRIVATE[ \t\r\n]+KEY`)

var base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)
var entropyRun = regexp.MustCompile(`[A-Za-z0-9+/=_-]{40,}`)

// normalizeForScan removes invisible characters and maps every kind of
// space to an ASCII space, so "ghp_<zero width space>..." or a PEM header
// with a no-break space is still recognized.
func normalizeForScan(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteByte(' ')
		case safe.IsInvisible(r):
			// dropped
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (r *Rules) scanLines(text, prefix string) []string {
	var out []string
	for i, line := range strings.Split(text, "\n") {
		for _, s := range r.secrets {
			for _, m := range s.re.FindAllStringSubmatch(line, -1) {
				if s.accept == nil || s.accept(m) {
					out = append(out, fmt.Sprintf("line %d: %s%s", i+1, prefix, s.name))
					break
				}
			}
		}
	}
	return out
}

func printable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' || c > 0x7e {
			return false
		}
	}
	return true
}

func decodeAny(s string) []byte {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b
		}
	}
	return nil
}

// Secrets returns the blocking secret findings of a text. The scan is a
// guard against accidental leaks; it cannot stop deliberate evasion.
func (r *Rules) Secrets(content string) []string {
	norm := normalizeForScan(content)
	out := r.scanLines(norm, "")
	if loc := pemAcrossLines.FindStringIndex(norm); loc != nil {
		line := strings.Count(norm[:loc[0]], "\n") + 1
		out = append(out, fmt.Sprintf("line %d: private key block", line))
	}
	// One level of base64 unwrapping.
	for _, m := range base64Run.FindAllString(norm, -1) {
		if dec := decodeAny(m); printable(dec) {
			for _, f := range r.scanLines(string(dec), "base64-encoded ") {
				out = append(out, f+" (in "+safe.Line(m[:16], 16)+"...)")
			}
		}
	}
	return out
}

func entropy(s string) float64 {
	counts := map[rune]int{}
	for _, c := range s {
		counts[c]++
	}
	var h float64
	n := float64(len(s))
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// SecretWarnings returns non-blocking hints: long high-entropy blocks
// that may be encoded keys.
func (r *Rules) SecretWarnings(content string) []string {
	var out []string
	for i, line := range strings.Split(normalizeForScan(content), "\n") {
		for _, m := range entropyRun.FindAllString(line, -1) {
			if hasDigit(m) && strings.ToLower(m) != m && strings.ToUpper(m) != m && entropy(m) >= 4.3 {
				out = append(out, fmt.Sprintf("line %d: long high-entropy block (encoded key?)", i+1))
				break
			}
		}
	}
	return out
}
