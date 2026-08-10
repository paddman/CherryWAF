package core

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateDoesNotOpenConfiguredLogFiles(t *testing.T) {
	dir := t.TempDir()
	blockedParent := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(dir, "cherrywaf.json")
	configJSON := fmt.Sprintf(`{
  "version": 1,
  "http": {
    "enabled": true,
    "listen": "127.0.0.1:8080",
    "redirect_to_https": false
  },
  "https": {
    "enabled": false,
    "listen": "127.0.0.1:8443",
    "min_tls_version": "1.2"
  },
  "admin": {
    "enabled": false,
    "listen": "127.0.0.1:9090",
    "token_env": "CHERRYWAF_ADMIN_TOKEN",
    "allow_public": false
  },
  "security": {
    "mode": "blocking",
    "block_threshold": 10,
    "max_body_bytes": 1048576,
    "max_header_bytes": 1048576,
    "trusted_proxies": [],
    "forwarded_for_header": "X-Forwarded-For",
    "rate_limit": {
      "enabled": false,
      "requests_per_second": 50,
      "burst": 100,
      "entry_ttl_seconds": 600
    }
  },
  "rules": {
    "builtins": true,
    "files": []
  },
  "logging": {
    "access_file": %q,
    "security_file": %q
  },
  "virtual_hosts": [
    {
      "name": "test-app",
      "enabled": true,
      "domains": ["test.example.com"],
      "upstream": "http://127.0.0.1:8081",
      "preserve_host": true,
      "frontend_tls": {
        "certificate_file": "",
        "private_key_file": ""
      },
      "origin_tls": {
        "server_name": "",
        "ca_file": "",
        "insecure_skip_verify": false
      },
      "response_headers": {}
    }
  ]
}`,
		filepath.Join(blockedParent, "access.jsonl"),
		filepath.Join(blockedParent, "security.jsonl"),
	)
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := Validate(configPath)
	if err != nil {
		t.Fatalf("Validate opened configured log files or rejected a valid config: %v", err)
	}
	if result.RuleCount == 0 {
		t.Fatal("expected built-in rules to be compiled")
	}
}
