package auth

import (
	"strings"
	"testing"
)

func TestKeyring(t *testing.T) {
	tok, err := NewToken(RoleAgent)
	if err != nil {
		t.Fatal(err)
	}
	k, err := NewKeyring([]TokenEntry{{Name: "a1", Role: RoleAgent, SHA256: Hash(tok)}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := k.Lookup(tok)
	if err != nil || a.Name != "a1" || a.Role != RoleAgent {
		t.Fatalf("lookup: %+v %v", a, err)
	}
	for _, bad := range []string{"", tok + "x", strings.ToUpper(tok), Hash(tok)} {
		if _, err := k.Lookup(bad); err == nil {
			t.Errorf("token %q must not authenticate", bad)
		}
	}
}

func TestKeyringValidation(t *testing.T) {
	h := Hash("x")
	cases := [][]TokenEntry{
		{{Name: "bad name", Role: RoleAgent, SHA256: h}},
		{{Name: "a", Role: "admin", SHA256: h}},
		{{Name: "a", Role: RoleAgent, SHA256: "abc"}},
		{{Name: "a", Role: RoleAgent, SHA256: h}, {Name: "a", Role: RoleReader, SHA256: Hash("y")}},
		{{Name: "a", Role: RoleAgent, SHA256: h}, {Name: "b", Role: RoleApprover, SHA256: h}},
	}
	for i, c := range cases {
		if _, err := NewKeyring(c); err == nil {
			t.Errorf("case %d must be rejected", i)
		}
	}
}
