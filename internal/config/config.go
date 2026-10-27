// Package config loads the server configuration (JSON).
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trove/internal/auth"
)

// Limits bound the proposal queue and the size of submissions.
type Limits struct {
	PerAgent       int   `json:"per_agent"`
	Total          int   `json:"total"`
	TTLHours       int   `json:"ttl_hours"`
	MaxFileBytes   int   `json:"max_file_bytes"`
	MaxTotalBytes  int   `json:"max_total_bytes"`
	MaxFiles       int   `json:"max_files"`
	LargeDiffLines int   `json:"large_diff_lines"`
	MaxImportBytes int64 `json:"max_import_bytes"`
	// AgentBytesPerDay bounds the content an agent may write (draft
	// writes and submissions, including overwrites) in a rolling 24 hours.
	AgentBytesPerDay int `json:"agent_bytes_per_day"`
	// AgentBeginsPerDay bounds how many drafts an agent may open in 24 hours.
	AgentBeginsPerDay int `json:"agent_begins_per_day"`
	// ArchiveMemoryDays: closed proposals older than this are not kept in
	// memory (their metadata file stays in archive/).
	ArchiveMemoryDays int `json:"archive_memory_days"`
}

// Validation configures the submission rules.
type Validation struct {
	// AllowedDirs lists top-level folders a proposal may touch. It must not
	// be empty (an empty list is a configuration error, not "everything").
	AllowedDirs []string `json:"allowed_dirs"`
	// AllowRootFiles allows files directly in the repository root.
	AllowRootFiles bool `json:"allow_root_files"`
	// FrontmatterFields must be present and non-empty in every put file.
	FrontmatterFields []string `json:"frontmatter_fields"`
	// FrontmatterExempt lists exact paths that need no frontmatter (e.g. INDEX.md).
	FrontmatterExempt []string `json:"frontmatter_exempt"`
	// ExtraSecretPatterns are additional regular expressions that block a submission.
	ExtraSecretPatterns []string `json:"extra_secret_patterns"`
}

// Config is the server configuration.
type Config struct {
	Listen           string            `json:"listen"`
	DataDir          string            `json:"data_dir"`
	TLSCert          string            `json:"tls_cert"`
	TLSKey           string            `json:"tls_key"`
	BotName          string            `json:"bot_name"`
	BotEmail         string            `json:"bot_email"`
	Tokens           []auth.TokenEntry `json:"tokens,omitempty"`
	TokensFile       string            `json:"tokens_file"`
	InstructionsFile string            `json:"instructions_file"`
	Limits           Limits            `json:"limits"`
	Validation       Validation        `json:"validation"`
	// DisableUI turns off the built-in web UI under /ui/ (static files;
	// the API stays the same either way).
	DisableUI bool `json:"disable_ui,omitempty"`
	// WebRequireHTTPS refuses browser sign-in over plain HTTP. Off by default:
	// plain HTTP works from any address, like a typical self-hosted app.
	WebRequireHTTPS bool `json:"web_require_https,omitempty"`
	// WebAllowTailnetHTTP is deprecated and ignored (plain HTTP is the default now).
	WebAllowTailnetHTTP bool `json:"web_allow_tailnet_http,omitempty"`
	// WebOrigin is the exact browser origin when the external Host differs.
	WebOrigin string `json:"web_origin,omitempty"`
	// WebTrustedProxies may assert X-Forwarded-Proto=https for browser auth.
	WebTrustedProxies []string `json:"web_trusted_proxies,omitempty"`
}

// Default returns a configuration with the defaults of the first release.
func Default() Config {
	return Config{
		Listen:   "127.0.0.1:8470",
		DataDir:  "./data",
		BotName:  "trove-bot",
		BotEmail: "trove-bot@example.invalid",
		Limits: Limits{
			PerAgent:       5,
			Total:          20,
			TTLHours:       7 * 24,
			MaxFileBytes:   256 << 10,
			MaxTotalBytes:  1 << 20,
			MaxFiles:       50,
			LargeDiffLines: 300,
			MaxImportBytes: 256 << 20,
			// Defaults sized for a personal KB; tune per deployment.
			AgentBytesPerDay:  20 << 20,
			AgentBeginsPerDay: 100,
			ArchiveMemoryDays: 30,
		},
		Validation: Validation{
			AllowedDirs:       []string{"infra", "projects", "apps", "claude", "snippets", "runbooks", "decisions"},
			AllowRootFiles:    true,
			FrontmatterFields: []string{"title", "updated", "status"},
			FrontmatterExempt: []string{"INDEX.md", "README.md"},
		},
	}
}

// TTL returns the proposal lifetime.
func (c Config) TTL() time.Duration { return time.Duration(c.Limits.TTLHours) * time.Hour }

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Load reads a config file, applies defaults for missing values, loads
// tokens_file (relative paths resolve against the config file directory)
// and validates the result.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := decodeStrict(data, &cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	base := filepath.Dir(path)
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	cfg.DataDir = resolve(cfg.DataDir)
	cfg.TokensFile = resolve(cfg.TokensFile)
	cfg.InstructionsFile = resolve(cfg.InstructionsFile)
	cfg.TLSCert = resolve(cfg.TLSCert)
	cfg.TLSKey = resolve(cfg.TLSKey)
	if err := applyEnv(&cfg); err != nil {
		return cfg, err
	}
	if cfg.TokensFile != "" {
		td, err := os.ReadFile(cfg.TokensFile)
		if err != nil {
			return cfg, fmt.Errorf("tokens_file: %w", err)
		}
		var extra []auth.TokenEntry
		if err := decodeStrict(td, &extra); err != nil {
			return cfg, fmt.Errorf("%s: %w", cfg.TokensFile, err)
		}
		cfg.Tokens = append(cfg.Tokens, extra...)
	}
	return cfg, cfg.Validate()
}

// applyEnv lets the browser-auth transport be switched from the environment
// (docker compose env_file, systemd EnvironmentFile) without editing the JSON.
// An unset or empty variable leaves the config file value alone.
//
//	TROVE_WEB_REQUIRE_HTTPS       1/true or 0/false
//	TROVE_WEB_ORIGIN              exact browser origin
//	TROVE_WEB_TRUSTED_PROXIES     comma-separated proxy CIDRs
func applyEnv(c *Config) error {
	if v := strings.TrimSpace(os.Getenv("TROVE_WEB_REQUIRE_HTTPS")); v != "" {
		switch strings.ToLower(v) {
		case "1", "true":
			c.WebRequireHTTPS = true
		case "0", "false":
			c.WebRequireHTTPS = false
		default:
			return fmt.Errorf("TROVE_WEB_REQUIRE_HTTPS must be 1, true, 0 or false")
		}
	}
	if v := strings.TrimSpace(os.Getenv("TROVE_WEB_ORIGIN")); v != "" {
		c.WebOrigin = v
	}
	if v := strings.TrimSpace(os.Getenv("TROVE_WEB_TRUSTED_PROXIES")); v != "" {
		c.WebTrustedProxies = nil
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.WebTrustedProxies = append(c.WebTrustedProxies, p)
			}
		}
	}
	return nil
}

// Validate checks the configuration for obvious mistakes.
func (c Config) Validate() error {
	if c.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("tls_cert and tls_key must be set together")
	}
	if c.WebOrigin != "" {
		u, err := url.Parse(c.WebOrigin)
		validScheme := u != nil && (u.Scheme == "https" || (!c.WebRequireHTTPS && u.Scheme == "http"))
		if err != nil || !validScheme || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("web_origin must be an origin without path, query or fragment, and https when web_require_https is on")
		}
	}
	for _, cidr := range c.WebTrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("web_trusted_proxies must contain IP CIDRs")
		}
	}
	if !auth.ValidName(c.BotName) {
		return fmt.Errorf("bot_name must match [A-Za-z0-9._-]{1,64}")
	}
	l := c.Limits
	if l.PerAgent < 1 || l.Total < 1 || l.TTLHours < 1 || l.MaxFileBytes < 1 || l.MaxTotalBytes < 1 || l.MaxFiles < 1 || l.LargeDiffLines < 1 || l.MaxImportBytes < 1 ||
		l.AgentBytesPerDay < 1 || l.AgentBeginsPerDay < 1 || l.ArchiveMemoryDays < 1 {
		return fmt.Errorf("all limits must be positive")
	}
	if len(c.Validation.AllowedDirs) == 0 {
		return fmt.Errorf("validation.allowed_dirs must list at least one folder")
	}
	if _, err := auth.NewKeyring(c.Tokens); err != nil {
		return err
	}
	return nil
}
