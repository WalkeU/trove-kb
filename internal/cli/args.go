package cli

import (
	"flag"
	"strings"
)

type boolFlag interface{ IsBoolFlag() bool }

// parse parses flags that may appear before or after positional
// arguments (the standard flag package stops at the first positional).
// "--" ends flag parsing.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			pos = append(pos, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		hasValue := strings.Contains(name, "=")
		if hasValue {
			name = name[:strings.IndexByte(name, '=')]
		}
		f := fs.Lookup(name)
		flags = append(flags, a)
		if f == nil || hasValue {
			continue
		}
		if bf, ok := f.Value.(boolFlag); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return pos, nil
}
