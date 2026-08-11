package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyUpstreamDefaultsToGroup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data := `{
  "version":1,
  "http":{"enabled":true,"listen":"127.0.0.1:8080"},
  "https":{"enabled":false},
  "admin":{"enabled":false},
  "security":{},
  "rules":{"builtins":true},
  "logging":{},
  "virtual_hosts":[{"name":"legacy","enabled":true,"domains":["legacy.example"],"upstream":"http://127.0.0.1:9000"}]
}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.VirtualHosts[0].Action; got != "group" {
		t.Fatalf("expected legacy action group, got %q", got)
	}
	if got := cfg.VirtualHosts[0].Persistence.Mode; got != "none" {
		t.Fatalf("expected no persistence, got %q", got)
	}
}

func TestServerPoolAndPerApplicationPolicyValidate(t *testing.T) {
	cfg := Config{
		Version: CurrentVersion,
		HTTP:    HTTPConfig{Enabled: true, Listen: ":8080"},
		Admin:   AdminConfig{Enabled: false},
		Security: SecurityConfig{
			Mode: "detect", BlockThreshold: 10, MaxBodyBytes: 1 << 20, MaxHeaderBytes: 1 << 20,
			ForwardedForHeader: "X-Forwarded-For", Reputation: ReputationConfig{Mode: "monitor", Entries: []string{"203.0.113.0/24 scanner range"}},
		},
		ServerPools: []ServerPool{{
			Name: "api", Enabled: true, Algorithm: "least_connections", FailureMode: "reject",
			Members:     []PoolMember{{ID: "api-1", URL: "http://127.0.0.1:9001", Enabled: true, Weight: 1, Priority: 100}},
			HealthCheck: HealthCheckConfig{Enabled: true, Type: "http", IntervalSeconds: 10, TimeoutSeconds: 3, HealthyThreshold: 2, UnhealthyThreshold: 3, Method: "GET", Path: "/healthz", ExpectedStatusMin: 200, ExpectedStatusMax: 399},
		}},
		VirtualHosts: []VirtualHost{{
			Name: "app", Enabled: true, Domains: []string{"app.example"}, Action: "group", ServerPool: "api",
			Persistence:   PersistenceConfig{Mode: "source_ip", TTLSeconds: 3600},
			WAFPolicy:     WAFPolicyConfig{Mode: "blocking", BlockThreshold: 12, FailMode: "closed", AllowCIDRs: []string{"10.0.0.0/8"}},
			BotPolicy:     BotPolicyConfig{Enabled: true, Mode: "monitor", RequestsPerMinute: 600, Burst: 100, BadUserAgents: []string{"(?i)badbot"}},
			ContentRoutes: []ContentRoute{{Name: "api", Enabled: true, Pool: "api", PathPrefix: "/api/"}},
		}},
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsUnknownPoolAndUnsafeRedirect(t *testing.T) {
	cfg := Config{
		Version:  CurrentVersion,
		HTTP:     HTTPConfig{Enabled: true, Listen: ":8080"},
		Admin:    AdminConfig{Enabled: false},
		Security: SecurityConfig{Mode: "blocking", BlockThreshold: 10, MaxBodyBytes: 1 << 20, MaxHeaderBytes: 1 << 20, ForwardedForHeader: "X-Forwarded-For", Reputation: ReputationConfig{Mode: "monitor"}},
		VirtualHosts: []VirtualHost{
			{Name: "missing", Enabled: true, Domains: []string{"missing.example"}, Action: "group", ServerPool: "none", WAFPolicy: WAFPolicyConfig{Mode: "inherit", FailMode: "closed"}, Persistence: PersistenceConfig{Mode: "none"}},
			{Name: "redirect", Enabled: true, Domains: []string{"redirect.example"}, Action: "redirect", Redirect: RedirectConfig{URL: "https://example.com\r\nX-Test: bad", Status: 302}, WAFPolicy: WAFPolicyConfig{Mode: "inherit", FailMode: "closed"}, Persistence: PersistenceConfig{Mode: "none"}},
		},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "unknown server pool") || !strings.Contains(err.Error(), "line breaks") {
		t.Fatalf("expected pool and redirect errors, got %v", err)
	}
}
