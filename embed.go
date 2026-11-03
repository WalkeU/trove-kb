// Package trove holds files embedded into the binary.
package trove

import (
	_ "embed"
	"strings"
)

// AgentInstructions is the default content of AGENT-INSTRUCTIONS.md.
//
//go:embed AGENT-INSTRUCTIONS.md
var AgentInstructions string

// Changelog is the CHANGELOG.md the binary was built from.
//
//go:embed CHANGELOG.md
var Changelog string

//go:embed VERSION
var versionFile string

// Version is the release version, overridable with -ldflags "-X trove.Version=...".
// When it is left empty, the VERSION file the binary was built from is used.
var Version = ""

func init() {
	if strings.TrimSpace(Version) == "" {
		Version = strings.TrimSpace(versionFile)
	}
	if Version == "" {
		Version = "0.0.0-dev"
	}
}
