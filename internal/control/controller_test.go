package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRuntime struct {
	reloadErr error
	failOnce  bool
	calls     int
}

func (f *fakeRuntime) Status(context.Context) (any, error) {
	return map[string]any{"mode": "detect", "metrics": map[string]any{"requests": 3}}, nil
}
func (f *fakeRuntime) Reload(context.Context) error {
	f.calls++
	if f.failOnce && f.calls > 1 {
		return nil
	}
	return f.reloadErr
}

func TestControllerFirstBootLoginCSRFAndRBAC(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "cherrywaf.json")
	if err := os.WriteFile(configPath, []byte("{\"version\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	controller, err := New(Options{ConfigPath: configPath, StateDir: filepath.Join(dir, "control"), Runtime: &fakeRuntime{}, SetupToken: "setup-1234"})
	if err != nil {
		t.Fatal(err)
	}
	handler := controller.Handler()

	status := httptest.NewRecorder()
	handler.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil))
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"setup_required":true`) {
		t.Fatalf("unexpected setup status: %d %s", status.Code, status.Body.String())
	}

	invalidSetup := httptest.NewRecorder()
	invalidSetupRequest := httptest.NewRequest(http.MethodPost, "/api/v1/setup/complete", strings.NewReader(`{"setup_token":"wrong-code","username":"admin","display_name":"Administrator","password":"CherryWAF-Admin-2026!"}`))
	handler.ServeHTTP(invalidSetup, invalidSetupRequest)
	if invalidSetup.Code != http.StatusUnauthorized {
		t.Fatalf("invalid setup code returned %d: %s", invalidSetup.Code, invalidSetup.Body.String())
	}

	setupBody := `{"setup_token":"setup-1234","username":"admin","display_name":"Administrator","password":"CherryWAF-Admin-2026!"}`
	setupRequest := httptest.NewRequest(http.MethodPost, "/api/v1/setup/complete", strings.NewReader(setupBody))
	setupRequest.Header.Set("Content-Type", "application/json")
	setup := httptest.NewRecorder()
	handler.ServeHTTP(setup, setupRequest)
	if setup.Code != http.StatusCreated {
		t.Fatalf("setup failed: %d %s", setup.Code, setup.Body.String())
	}
	cookie := setup.Result().Cookies()[0]
	var setupResult struct {
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(setup.Body.Bytes(), &setupResult); err != nil || setupResult.CSRF == "" {
		t.Fatalf("missing CSRF token: %v %s", err, setup.Body.String())
	}

	requestWithoutCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"viewer","display_name":"Viewer","password":"CherryWAF-Viewer-2026!","role":"viewer"}`))
	requestWithoutCSRF.AddCookie(cookie)
	withoutCSRF := httptest.NewRecorder()
	handler.ServeHTTP(withoutCSRF, requestWithoutCSRF)
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("mutation without CSRF returned %d", withoutCSRF.Code)
	}

	requestWithCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(`{"username":"viewer","display_name":"Viewer","password":"CherryWAF-Viewer-2026!","role":"viewer"}`))
	requestWithCSRF.AddCookie(cookie)
	requestWithCSRF.Header.Set("X-CSRF-Token", setupResult.CSRF)
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, requestWithCSRF)
	if created.Code != http.StatusCreated {
		t.Fatalf("user creation failed: %d %s", created.Code, created.Body.String())
	}

	root := httptest.NewRecorder()
	handler.ServeHTTP(root, httptest.NewRequest(http.MethodGet, "/", nil))
	if root.Header().Get("Content-Security-Policy") == "" || !strings.Contains(root.Body.String(), "CherryWAF Control Center") {
		t.Fatalf("embedded web UI or security headers missing")
	}
}

func TestConfigApplyRollsBackOnRuntimeReloadFailure(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "cherrywaf.json")
	original := []byte(`{
  "version": 1,
  "http": {"enabled": true, "listen": "127.0.0.1:8080", "redirect_to_https": false},
  "https": {"enabled": false, "listen": "127.0.0.1:8443", "min_tls_version": "1.2"},
  "admin": {"enabled": false},
  "security": {"mode": "detect", "block_threshold": 10, "max_body_bytes": 1048576, "max_header_bytes": 1048576, "trusted_proxies": [], "forwarded_for_header": "X-Forwarded-For", "rate_limit": {"enabled": false}},
  "rules": {"builtins": true, "files": []},
  "logging": {"access_file": "-", "security_file": "-"},
  "virtual_hosts": []
}
`)
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	controller, err := New(Options{ConfigPath: configPath, StateDir: filepath.Join(dir, "control"), Runtime: &fakeRuntime{reloadErr: errors.New("reload exploded"), failOnce: true}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = controller.applyConfigBytes([]byte(`{
  "version": 1,
  "http": {"enabled": true, "listen": "127.0.0.1:8080", "redirect_to_https": false},
  "https": {"enabled": false, "listen": "127.0.0.1:8443", "min_tls_version": "1.2"},
  "admin": {"enabled": false},
  "security": {"mode": "blocking", "block_threshold": 12, "max_body_bytes": 1048576, "max_header_bytes": 1048576, "trusted_proxies": [], "forwarded_for_header": "X-Forwarded-For", "rate_limit": {"enabled": false}},
  "rules": {"builtins": true, "files": []},
  "logging": {"access_file": "-", "security_file": "-"},
  "virtual_hosts": []
}`), "admin", "test")
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected rollback error, got %v", err)
	}
	after, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("configuration was not restored:\n%s", after)
	}
}

func TestCertificateSlugSeparatesWildcardAndExact(t *testing.T) {
	if certificateSlug("example.com") == certificateSlug("*.example.com") {
		t.Fatal("wildcard and exact certificates collide")
	}
}
