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
	for _, k := range []string{"TROVE_WEB_REQUIRE_HTTPS", "TROVE_WEB_ORIGIN", "TROVE_WEB_TRUSTED_PROXIES"} {
		t.Setenv(k, "")
	}
}

func TestPlainHTTPIsDefault(t *testing.T) {
	clearWebEnv(t)
	cfg, err := Load(writeCfg(t, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebRequireHTTPS || cfg.WebOrigin != "" {
		t.Fatalf("unexpected defaults: require_https=%v origin=%q", cfg.WebRequireHTTPS, cfg.WebOrigin)
	}
}

func TestEnvEnablesRequireHTTPS(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", " true "} {
		clearWebEnv(t)
		t.Setenv("TROVE_WEB_REQUIRE_HTTPS", v)
		t.Setenv("TROVE_WEB_ORIGIN", "https://trove.example.com")
		cfg, err := Load(writeCfg(t, `{}`))
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if !cfg.WebRequireHTTPS || cfg.WebOrigin != "https://trove.example.com" {
			t.Fatalf("%q: env not applied: %v %q", v, cfg.WebRequireHTTPS, cfg.WebOrigin)
		}
	}
}

func TestEnvDisablesRequireHTTPS(t *testing.T) {
	for _, v := range []string{"0", "false"} {
		clearWebEnv(t)
		t.Setenv("TROVE_WEB_REQUIRE_HTTPS", v)
		cfg, err := Load(writeCfg(t, `{"web_require_https":true,"web_origin":"https://trove.example.com"}`))
		if err != nil {
			t.Fatalf("%q: %v", v, err)
		}
		if cfg.WebRequireHTTPS {
			t.Fatalf("%q: env did not override file", v)
		}
	}
}

func TestEnvUnsetKeepsFile(t *testing.T) {
	clearWebEnv(t)
	cfg, err := Load(writeCfg(t, `{"web_require_https":true,"web_origin":"https://trove.example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.WebRequireHTTPS || cfg.WebOrigin != "https://trove.example.com" {
		t.Fatal("file value lost")
	}
}

func TestEnvOriginOverridesFile(t *testing.T) {
	clearWebEnv(t)
	t.Setenv("TROVE_WEB_ORIGIN", "https://other.example.com")
	cfg, err := Load(writeCfg(t, `{"web_origin":"http://192.168.0.167:8470"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebOrigin != "https://other.example.com" {
		t.Fatalf("got %q", cfg.WebOrigin)
	}
}

func TestEnvRejectsBadValues(t *testing.T) {
	clearWebEnv(t)
	t.Setenv("TROVE_WEB_REQUIRE_HTTPS", "maybe")
	if _, err := Load(writeCfg(t, `{}`)); err == nil {
		t.Fatal("bad bool accepted")
	}
	clearWebEnv(t)
	t.Setenv("TROVE_WEB_TRUSTED_PROXIES", "not-a-cidr")
	if _, err := Load(writeCfg(t, `{}`)); err == nil {
		t.Fatal("bad CIDR accepted")
	}
}

func TestHTTPOriginAcceptedByDefault(t *testing.T) {
	clearWebEnv(t)
	for _, origin := range []string{"http://192.168.0.167:8470", "http://trove.lan", "http://100.64.0.5:8470"} {
		if _, err := Load(writeCfg(t, `{"web_origin":"`+origin+`"}`)); err != nil {
			t.Fatalf("%s rejected: %v", origin, err)
		}
	}
}

func TestHTTPOriginRejectedWhenHTTPSRequired(t *testing.T) {
	clearWebEnv(t)
	if _, err := Load(writeCfg(t, `{"web_require_https":true,"web_origin":"http://192.168.0.167:8470"}`)); err == nil {
		t.Fatal("http origin accepted with web_require_https in file")
	}
	clearWebEnv(t)
	t.Setenv("TROVE_WEB_REQUIRE_HTTPS", "1")
	if _, err := Load(writeCfg(t, `{"web_origin":"http://192.168.0.167:8470"}`)); err == nil {
		t.Fatal("http origin accepted with TROVE_WEB_REQUIRE_HTTPS=1")
	}
}

func TestBadOriginShapesRejected(t *testing.T) {
	clearWebEnv(t)
	for _, origin := range []string{"ftp://trove.example.com", "https://trove.example.com/ui", "https://u@trove.example.com", "https://trove.example.com?x=1", "https://"} {
		if _, err := Load(writeCfg(t, `{"web_origin":"`+origin+`"}`)); err == nil {
			t.Fatalf("%s accepted", origin)
		}
	}
}

func TestDeprecatedTailnetKeyStillLoads(t *testing.T) {
	clearWebEnv(t)
	cfg, err := Load(writeCfg(t, `{"web_allow_tailnet_http":true,"web_origin":"http://100.64.0.5:8470"}`))
	if err != nil {
		t.Fatalf("old config rejected: %v", err)
	}
	if cfg.WebRequireHTTPS {
		t.Fatal("deprecated key must not switch on HTTPS-only")
	}
}

func TestEnvTrustedProxies(t *testing.T) {
	clearWebEnv(t)
	t.Setenv("TROVE_WEB_TRUSTED_PROXIES", " 192.168.0.168/32, 10.0.0.0/24 ,")
	cfg, err := Load(writeCfg(t, `{}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.WebTrustedProxies) != 2 || cfg.WebTrustedProxies[0] != "192.168.0.168/32" || cfg.WebTrustedProxies[1] != "10.0.0.0/24" {
		t.Fatalf("got %v", cfg.WebTrustedProxies)
	}
}
