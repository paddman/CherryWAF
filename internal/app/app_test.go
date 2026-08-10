package app

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicHandlerProxiesAndBlocks(t *testing.T) {
	originHeaders := make(chan http.Header, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHeaders <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("origin-ok"))
	}))
	defer origin.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "cherrywaf.json")
	configJSON := fmt.Sprintf(`{
  "version": 1,
  "http": {"enabled": true, "listen": "127.0.0.1:8080", "redirect_to_https": false},
  "https": {"enabled": false, "listen": "127.0.0.1:8443"},
  "admin": {"enabled": false},
  "security": {
    "mode": "blocking", "block_threshold": 10,
    "max_body_bytes": 1048576, "max_header_bytes": 1048576,
    "rate_limit": {"enabled": false}
  },
  "rules": {"builtins": true, "files": []},
  "logging": {"access_file": %q, "security_file": %q},
  "virtual_hosts": [{
    "name": "test", "enabled": true, "domains": ["app.example.test"],
    "upstream": %q, "preserve_host": true,
    "frontend_tls": {}, "origin_tls": {}, "response_headers": {}
  }]
}`, filepath.Join(dir, "access.jsonl"), filepath.Join(dir, "security.jsonl"), origin.URL)
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	application, err := New(configPath, BuildInfo{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer application.closeRuntimes()
	handler := application.publicHandler(false)

	good := httptest.NewRequest(http.MethodGet, "http://app.example.test/products?q=books", nil)
	good.Host = "app.example.test"
	good.RemoteAddr = "198.51.100.10:1234"
	good.Header.Set("X-Forwarded-For", "203.0.113.99")
	good.Header.Set("Forwarded", "for=203.0.113.99")
	good.Header.Set("X-Request-ID", `unsafe"request`)
	goodRecorder := httptest.NewRecorder()
	handler.ServeHTTP(goodRecorder, good)
	if goodRecorder.Code != http.StatusOK || goodRecorder.Body.String() != "origin-ok" {
		t.Fatalf("benign request failed: status=%d body=%q", goodRecorder.Code, goodRecorder.Body.String())
	}
	forwarded := <-originHeaders
	if got := forwarded.Get("X-Forwarded-For"); got != "198.51.100.10" {
		t.Fatalf("spoofed forwarding header reached origin: %q", got)
	}
	if got := forwarded.Get("Forwarded"); got != "" {
		t.Fatalf("Forwarded header was not stripped: %q", got)
	}
	if got := goodRecorder.Header().Get("X-Request-ID"); got == `unsafe"request` || got == "" {
		t.Fatalf("unsafe request ID was not replaced: %q", got)
	}

	mismatch := httptest.NewRequest(http.MethodGet, "https://app.example.test/", nil)
	mismatch.Host = "app.example.test"
	mismatch.RemoteAddr = "198.51.100.10:1234"
	mismatch.TLS = &tls.ConnectionState{ServerName: "other.example.test"}
	mismatchRecorder := httptest.NewRecorder()
	application.publicHandler(true).ServeHTTP(mismatchRecorder, mismatch)
	if mismatchRecorder.Code != http.StatusMisdirectedRequest {
		t.Fatalf("SNI/Host mismatch was not rejected: status=%d body=%q", mismatchRecorder.Code, mismatchRecorder.Body.String())
	}

	attack := httptest.NewRequest(http.MethodGet, "http://app.example.test/?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	attack.Host = "app.example.test"
	attack.RemoteAddr = "198.51.100.10:1234"
	attackRecorder := httptest.NewRecorder()
	handler.ServeHTTP(attackRecorder, attack)
	if attackRecorder.Code != http.StatusForbidden {
		t.Fatalf("attack was not blocked: status=%d body=%q", attackRecorder.Code, attackRecorder.Body.String())
	}

	encoded := httptest.NewRequest(http.MethodPost, "http://app.example.test/upload", strings.NewReader("opaque"))
	encoded.Host = "app.example.test"
	encoded.RemoteAddr = "198.51.100.10:1234"
	encoded.Header.Set("Content-Encoding", "br")
	encodedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(encodedRecorder, encoded)
	if encodedRecorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("unsupported encoding was not rejected: status=%d body=%q", encodedRecorder.Code, encodedRecorder.Body.String())
	}
}
