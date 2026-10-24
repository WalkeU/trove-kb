package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseFlagsAfterPositionals(t *testing.T) {
	fs := newFlags("approve")
	digest := fs.String("digest", "", "")
	dry := fs.Bool("dry-run", false, "")
	pos, err := parse(fs, []string{"abc", "--digest", "ff", "--dry-run", "x", "--", "--not-a-flag"})
	if err != nil {
		t.Fatal(err)
	}
	if *digest != "ff" || !*dry {
		t.Fatalf("flags not parsed: %q %v", *digest, *dry)
	}
	if strings.Join(pos, ",") != "abc,x,--not-a-flag" {
		t.Fatalf("positionals: %v", pos)
	}
	fs2 := newFlags("x")
	v := fs2.String("scope", "", "")
	if _, err := parse(fs2, []string{"--scope=a,b", "topic"}); err != nil || *v != "a,b" {
		t.Fatalf("--flag=value: %v %q", err, *v)
	}
}

func TestApproveRequiresDigest(t *testing.T) {
	var out, errb bytes.Buffer
	t.Setenv("TROVE_TOKEN", "x")
	t.Setenv("TROVE_URL", "http://192.0.2.1:1")
	code := Run([]string{"approve", "0123456789abcdef0123456789abcdef"}, &out, &errb)
	if code == 0 || !strings.Contains(errb.String(), "--digest is required") {
		t.Fatalf("approve without digest must fail locally: %d %s", code, errb.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if Run([]string{"nope"}, &out, &errb) != 2 {
		t.Fatal("unknown command must exit 2")
	}
}
