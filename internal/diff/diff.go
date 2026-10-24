// Package diff produces a small line-based diff for review output.
package diff

import (
	"fmt"
	"strings"
)

// maxCells bounds the LCS table; larger inputs fall back to a full replace.
const maxCells = 4_000_000

// Op is one diff line operation.
type Op struct {
	Kind byte // ' ', '-', '+'
	Text string
}

// Lines splits text into lines without the trailing newline.
func Lines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

// Compute returns the line operations turning a into b (LCS based).
func Compute(a, b []string) []Op {
	n, m := len(a), len(b)
	if n*m > maxCells {
		ops := make([]Op, 0, n+m)
		for _, l := range a {
			ops = append(ops, Op{'-', l})
		}
		for _, l := range b {
			ops = append(ops, Op{'+', l})
		}
		return ops
	}
	// lcs[i][j] = LCS length of a[i:] and b[j:], stored flat.
	w := m + 1
	lcs := make([]int32, (n+1)*w)
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i*w+j] = lcs[(i+1)*w+j+1] + 1
			} else if lcs[(i+1)*w+j] >= lcs[i*w+j+1] {
				lcs[i*w+j] = lcs[(i+1)*w+j]
			} else {
				lcs[i*w+j] = lcs[i*w+j+1]
			}
		}
	}
	ops := make([]Op, 0, n+m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, Op{' ', a[i]})
			i++
			j++
		case lcs[(i+1)*w+j] >= lcs[i*w+j+1]:
			ops = append(ops, Op{'-', a[i]})
			i++
		default:
			ops = append(ops, Op{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, Op{'-', a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, Op{'+', b[j]})
	}
	return ops
}

// Stats returns the number of removed and added lines.
func Stats(oldText, newText string) (removed, added int) {
	for _, op := range Compute(Lines(oldText), Lines(newText)) {
		switch op.Kind {
		case '-':
			removed++
		case '+':
			added++
		}
	}
	return
}

// Unified renders the diff with `context` unchanged lines around changes;
// longer unchanged runs are collapsed into a marker line.
func Unified(oldText, newText string, context int) string {
	ops := Compute(Lines(oldText), Lines(newText))
	keep := make([]bool, len(ops))
	for i, op := range ops {
		if op.Kind == ' ' {
			continue
		}
		lo, hi := i-context, i+context
		if lo < 0 {
			lo = 0
		}
		if hi >= len(ops) {
			hi = len(ops) - 1
		}
		for k := lo; k <= hi; k++ {
			keep[k] = true
		}
	}
	var b strings.Builder
	skipped := 0
	flush := func() {
		if skipped > 0 {
			fmt.Fprintf(&b, "@@ %d unchanged line(s) @@\n", skipped)
			skipped = 0
		}
	}
	for i, op := range ops {
		if !keep[i] {
			skipped++
			continue
		}
		flush()
		b.WriteByte(op.Kind)
		b.WriteString(op.Text)
		b.WriteByte('\n')
	}
	flush()
	return b.String()
}
