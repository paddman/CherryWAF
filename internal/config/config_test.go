package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := `{
  "version": 1,
  "http": {"enabled": true, "listen": "127.0.0.1:8080"},
  "https": {"enabled": false},
  "admin": {"enabled": true},
  "security": {},
  "rules": {"builtins": true},
  "logging": {},
  "virtual_hosts": [{
    "name": "test",
    "enabled": true,
    "domains": ["Example.COM"],
    "upstream": "http://127.0.0.1:9000"
  }]
}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.BlockThreshold != 10 {
		t.Fatalf("unexpected threshold: %d", cfg.Security.BlockThreshold)
	}
	if got := cfg.VirtualHosts[0].Domains[0]; got != "example.com" {
		t.Fatalf("domain was not normalized: %q", got)
	}
}

func TestRejectsPublicAdminByDefault(t *testing.T) {
	cfg := Config{
		Version:      CurrentVersion,
		HTTP:         HTTPConfig{Enabled: true, Listen: ":8080"},
		Admin:        AdminConfig{Enabled: true, Listen: "0.0.0.0:9090", TokenEnv: "TOKEN"},
		Security:     SecurityConfig{Mode: "blocking", BlockThreshold: 10, MaxBodyBytes: 1024, MaxHeaderBytes: 8192},
		VirtualHosts: []VirtualHost{{Name: "v", Enabled: true, Domains: []string{"example.com"}, Upstream: "http://127.0.0.1:9000"}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback validation error, got %v", err)
	}
}

func TestRejectsTrailingJSONValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := `{
  "version": 1,
  "http": {"enabled": true, "listen": "127.0.0.1:8080"},
  "https": {"enabled": false},
  "admin": {"enabled": false},
  "security": {},
  "rules": {"builtins": true},
  "logging": {},
  "virtual_hosts": [{"name":"v","enabled":true,"domains":["example.com"],"upstream":"http://127.0.0.1:9000"}]
} {"unexpected":true}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("expected trailing JSON rejection, got %v", err)
	}
}

func TestRejectsUnsafeResponseHeaders(t *testing.T) {
	cfg := Config{
		Version:  CurrentVersion,
		HTTP:     HTTPConfig{Enabled: true, Listen: ":8080"},
		Admin:    AdminConfig{Enabled: false},
		Security: SecurityConfig{Mode: "blocking", BlockThreshold: 10, MaxBodyBytes: 1024, MaxHeaderBytes: 8192, ForwardedForHeader: "X-Forwarded-For"},
		VirtualHosts: []VirtualHost{{
			Name: "v", Enabled: true, Domains: []string{"example.com"}, Upstream: "http://127.0.0.1:9000",
			ResponseHeaders: map[string]string{"Connection": "close", "X-Test": "safe\r\ninjected: true"},
		}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cannot be overridden") || !strings.Contains(err.Error(), "invalid value") {
		t.Fatalf("expected unsafe response header rejection, got %v", err)
	}
}

func TestValidateDomainPattern(t *testing.T) {
	for _, valid := range []string{"example.com", "*.example.com", "192.0.2.1", "localhost", "xn--bcher-kva.example"} {
		if err := ValidateDomainPattern(valid); err != nil {
			t.Fatalf("expected %q to be valid: %v", valid, err)
		}
	}
	for _, invalid := range []string{"..", "-bad.example", "bad-.example", "bad_name.example", "*.*.example.com"} {
		if err := ValidateDomainPattern(invalid); err == nil {
			t.Fatalf("expected %q to be invalid", invalid)
		}
	}
}
