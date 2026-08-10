package waf

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestBlocksEncodedTraversal(t *testing.T) {
	engine, err := New("blocking", 10, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://example.com/download?file=%252e%252e%252fetc%252fpasswd", nil)
	decision := engine.Inspect(RequestData{Request: req})
	if !decision.Blocked {
		t.Fatalf("expected block, got %+v", decision)
	}
}

func TestDetectModeDoesNotBlock(t *testing.T) {
	engine, err := New("detect", 10, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	decision := engine.Inspect(RequestData{Request: req})
	if decision.Blocked {
		t.Fatalf("detect mode blocked request: %+v", decision)
	}
	if decision.Score < 10 || len(decision.Matches) == 0 {
		t.Fatalf("expected a detection, got %+v", decision)
	}
}

func TestBenignRequestPasses(t *testing.T) {
	engine, err := New("blocking", 10, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://example.com/products?category=books", nil)
	decision := engine.Inspect(RequestData{Request: req})
	if decision.Blocked || decision.Score != 0 {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

func TestLogRuleDoesNotTriggerThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	data := `{"version":1,"rules":[{"id":"TEST-LOG","name":"Log only","enabled":true,"targets":["query"],"pattern":"marker","score":100,"action":"log","severity":"info"}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, err := New("blocking", 10, false, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://example.com/?q=marker", nil)
	decision := engine.Inspect(RequestData{Request: req})
	if decision.Blocked || decision.Score != 0 || len(decision.Matches) != 1 {
		t.Fatalf("unexpected log-only decision: %+v", decision)
	}
}

func TestRejectsTrailingRuleFileValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	data := `{"version":1,"rules":[]} {"version":1,"rules":[]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New("blocking", 10, false, []string{path}); err == nil {
		t.Fatal("expected trailing rule-file JSON value to be rejected")
	}
}
