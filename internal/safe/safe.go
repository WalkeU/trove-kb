// Package safe renders untrusted text (proposal content, topics, reasons)
// so that it cannot control the terminal or hide characters from a reviewer.
package safe

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// IsInvisible reports runes that render as nothing (or as something else)
// on a terminal but are still read by an LLM: format characters (zero
// width, bidi marks, tag characters U+E0000-E007F), private use and
// unassigned code points, line/paragraph separators, non-ASCII spaces,
// variation selectors, combining grapheme joiner and Hangul fillers.
func IsInvisible(r rune) bool {
	if r == ' ' {
		return false
	}
	if !unicode.IsGraphic(r) {
		return true // Cc, Cf, Co, Cn, Zl, Zp (and therefore all tag characters)
	}
	switch {
	case unicode.Is(unicode.Zs, r): // NBSP, ideographic space, ...
		return true
	case unicode.Is(unicode.Variation_Selector, r):
		return true
	case r == 0x034F, r == 0x115F, r == 0x1160, r == 0x3164, r == 0xFFA0, r == 0x17B4, r == 0x17B5:
		return true
	}
	return false
}

// IsBidiControl reports bidirectional formatting characters.
func IsBidiControl(r rune) bool {
	return unicode.Is(unicode.Bidi_Control, r)
}

// IsTag reports Unicode tag characters (used for "ASCII smuggling").
func IsTag(r rune) bool { return r >= 0xE0000 && r <= 0xE007F }

// isDangerous reports runes that must never reach a terminal verbatim.
// Everything invisible is escaped; only newline and tab pass.
func isDangerous(r rune) bool {
	if r == '\n' || r == '\t' {
		return false
	}
	return IsInvisible(r)
}

// Text escapes dangerous runes, replaces invalid UTF-8, truncates lines
// longer than maxLine runes and the whole text after maxTotal bytes.
// A value <= 0 disables the corresponding limit.
func Text(s string, maxLine, maxTotal int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	var b strings.Builder
	lineRunes := 0
	truncatedLine := false
	for _, r := range s {
		if maxTotal > 0 && b.Len() >= maxTotal {
			b.WriteString("\n[... output truncated ...]")
			return b.String()
		}
		if r == '\n' {
			b.WriteRune(r)
			lineRunes = 0
			truncatedLine = false
			continue
		}
		if truncatedLine {
			continue
		}
		if maxLine > 0 && lineRunes >= maxLine {
			b.WriteString(" [... line truncated]")
			truncatedLine = true
			continue
		}
		if isDangerous(r) {
			fmt.Fprintf(&b, "\\u{%04x}", r)
		} else {
			b.WriteRune(r)
		}
		lineRunes++
	}
	return b.String()
}

// Line renders s as a single line: newlines become spaces, then Text applies.
func Line(s string, max int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return Text(s, max, 0)
}

// OneLine sanitizes a value that is stored and later embedded in a single
// line (commit trailers, topics): control and bidi runes are dropped,
// whitespace runs collapse to one space, and the result is cut to max runes.
func OneLine(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if isDangerous(r) {
			continue
		}
		if space && b.Len() > 0 {
			if max > 0 && n >= max {
				break
			}
			b.WriteByte(' ')
			n++
		}
		space = false
		if max > 0 && n >= max {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
