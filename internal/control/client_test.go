package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeClientRequiresLoopback(t *testing.T) {
	if _, err := NewHTTPRuntimeClient("http://127.0.0.1:9090", "/tmp/env"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"https://127.0.0.1:9090", "http://192.0.2.1:9090", "http://example.com:9090", "garbage"} {
		if _, err := NewHTTPRuntimeClient(value, "/tmp/env"); err == nil {
			t.Fatalf("unsafe admin URL %q was accepted", value)
		}
	}
}

func TestReadAdminToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cherrywaf.env")
	if err := os.WriteFile(path, []byte("# comment\nOTHER=x\nCHERRYWAF_ADMIN_TOKEN='secret-token'\nCHERRYWAF_SETUP_TOKEN=claim-code\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := readAdminToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if token != "secret-token" {
		t.Fatalf("unexpected token %q", token)
	}
	setup, err := ReadSetupToken(path)
	if err != nil || setup != "claim-code" {
		t.Fatalf("unexpected setup token %q: %v", setup, err)
	}
}
