// Package auth maps bearer tokens to named actors with a role.
// Only SHA-256 hashes of tokens are kept; lookups are constant time
// with respect to the token content.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Role is one of the three access levels.
type Role string

const (
	RoleReader   Role = "reader"
	RoleAgent    Role = "agent"
	RoleApprover Role = "approver"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	return r == RoleReader || r == RoleAgent || r == RoleApprover
}

// Actor is an authenticated caller.
type Actor struct {
	Name string
	Role Role
}

// TokenEntry is one configured token (hash only).
type TokenEntry struct {
	Name   string `json:"name"`
	Role   Role   `json:"role"`
	SHA256 string `json:"sha256"`
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// ValidName reports whether a token name is acceptable. Names end up in
// commit trailers and audit lines, so they are restricted.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// Hash returns the hex SHA-256 of a token.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewToken returns a random token with a role prefix (for readability only).
func NewToken(role Role) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "trove_" + string(role) + "_" + hex.EncodeToString(buf), nil
}

// Keyring holds the configured token hashes.
type Keyring struct {
	entries []entry
}

type entry struct {
	actor Actor
	hash  [32]byte
}

// NewKeyring validates the entries and builds a keyring.
func NewKeyring(list []TokenEntry) (*Keyring, error) {
	k := &Keyring{}
	names := map[string]bool{}
	hashes := map[string]bool{}
	for i, t := range list {
		if !ValidName(t.Name) {
			return nil, fmt.Errorf("token %d: invalid name %q (allowed: A-Z a-z 0-9 . _ -, max 64)", i, t.Name)
		}
		if !t.Role.Valid() {
			return nil, fmt.Errorf("token %q: invalid role %q", t.Name, t.Role)
		}
		h := strings.ToLower(strings.TrimSpace(t.SHA256))
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("token %q: sha256 must be 64 hex characters", t.Name)
		}
		if names[t.Name] {
			return nil, fmt.Errorf("token name %q is used twice", t.Name)
		}
		if hashes[h] {
			return nil, fmt.Errorf("token %q: the same token hash is configured twice", t.Name)
		}
		names[t.Name] = true
		hashes[h] = true
		var e entry
		e.actor = Actor{Name: t.Name, Role: t.Role}
		copy(e.hash[:], raw)
		k.entries = append(k.entries, e)
	}
	return k, nil
}

// ErrUnknownToken is returned for tokens that are not configured.
var ErrUnknownToken = errors.New("unknown token")

// Lookup finds the actor for a presented token. Every entry is compared,
// so the time taken does not depend on which entry matches.
func (k *Keyring) Lookup(token string) (Actor, error) {
	if token == "" {
		return Actor{}, ErrUnknownToken
	}
	sum := sha256.Sum256([]byte(token))
	found := -1
	for i := range k.entries {
		if subtle.ConstantTimeCompare(sum[:], k.entries[i].hash[:]) == 1 {
			found = i
		}
	}
	if found < 0 {
		return Actor{}, ErrUnknownToken
	}
	return k.entries[found].actor, nil
}

// Len returns the number of configured tokens.
func (k *Keyring) Len() int { return len(k.entries) }
