// Package trove holds files embedded into the binary.
package trove

import _ "embed"

// AgentInstructions is the default content of AGENT-INSTRUCTIONS.md.
//
//go:embed AGENT-INSTRUCTIONS.md
var AgentInstructions string

// Version is the release version, overridable with -ldflags "-X trove.Version=...".
var Version = "0.1.0-dev"
