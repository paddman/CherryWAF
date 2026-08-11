package reputation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/paddman/CherryWAF/internal/config"
)

func TestLookupUsesLongestPrefixAndReason(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "feed.txt")
	if err := os.WriteFile(file, []byte("203.0.113.0/24 feed-range\n203.0.113.8 host-entry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{BaseDir: dir, Security: config.SecurityConfig{Reputation: config.ReputationConfig{Enabled: true, Mode: "block", Entries: []string{"198.51.100.0/24 inline"}, Files: []string{"feed.txt"}}}}
	store, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	match, ok := store.Lookup("203.0.113.8")
	if !ok || match.Prefix != "203.0.113.8/32" || match.Reason != "host-entry" || match.Mode != "block" {
		t.Fatalf("unexpected match: %#v ok=%v", match, ok)
	}
	if store.Count() != 3 {
		t.Fatalf("unexpected count %d", store.Count())
	}
}
