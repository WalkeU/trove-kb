package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "trove.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func clearWebEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"TROVE_WEB_ALLOW_TAILNET_HTTP", "TROVE_WEB_ORIGIN", "TROVE_WEB_TRUSTED_PROXIES"} {
		t.Setenv(k, "")
	}
}

func TestEnvEnablesTailnetHTTP(t *testing.T) {
	clearWebEnv(t)
	t.Setenv("TROVE_WEB_ALLOW_TAILNET_HTTP", "1")
	t.Setenv("TROVE_WEB_ORIGIN", "http://100.64.0.5:8470")
	cfg, err := Load(writeCfg(t, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.WebAllowTailnetHTTP || cfg.WebOrigin != "http://100.64.0.5:8470" {
		t.Fatalf("env not applied: %+v", cfg.WebAllowTailnetHTTP)
	}
}

func TestEnvDisablesTailnetHTTP(t *testing.T) {
	clearWebEnv(t)
	t.Setenv("TROVE_WEB_ALLOW_TAILNET_HTTP", "0")
	t.Setenv("TROVE_WEB_ORIGIN", "https://trove.example.com")
	cfg, err := Load(writeCfg(t, `{"web_allow_tailnet_http":true,"web_origin":"http://100.64.0.5:8470"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebAllowTailnetHTTP || cfg.WebOrigin != "https://trove.example.com" {
		t.Fatalf("env did not override file: %+v", cfg.WebOrigin)
	}
}

func TestEnvUnsetKeepsFile(t *testing.T) {
	clearWebEnv(t)
	cfg, err := Load(writeCfg(t, `{"web_allow_tailnet_http":true,"web_origin":"http://100.64.0.5:8470"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.WebAllowTailnetHTTP {
		t.Fatal("file value lost")
	}
}

func TestEnvRejectsBadValues(t *testing.T) {
	clearWebEnv(t)
	t.Setenv("TROVE_WEB_ALLOW_TAILNET_HTTP", "maybe")
	if _, err := Load(writeCfg(t, `{}`)); err == nil {
		t.Fatal("bad bool accepted")
	}
	clearWebEnv(t)
	t.Setenv("TROVE_WEB_TRUSTED_PROXIES", "not-a-cidr")
	if _, err := Load(writeCfg(t, `{}`)); err == nil {
		t.Fatal("bad CIDR accepted")
	}
}

func TestEnvTailnetHTTPStillNeedsTailnetOrigin(t *testing.T) {
	clearWebEnv(t)
	t.Setenv("TROVE_WEB_ALLOW_TAILNET_HTTP", "1")
	t.Setenv("TROVE_WEB_ORIGIN", "http://192.168.0.167:8470")
	if _, err := Load(writeCfg(t, `{}`)); err == nil {
		t.Fatal("non-tailnet http origin accepted")
	}
}

func TestEnvTrustedProxies(t *testing.T) {
	clearWebEnv(t)
	t.Setenv("TROVE_WEB_TRUSTED_PROXIES", " 192.168.0.168/32, 10.0.0.0/24 ,")
	cfg, err := Load(writeCfg(t, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.WebTrustedProxies) != 2 || cfg.WebTrustedProxies[0] != "192.168.0.168/32" {
		t.Fatalf("got %v", cfg.WebTrustedProxies)
	}
}
