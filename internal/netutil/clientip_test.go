package netutil

import "testing"

func TestForwardedHeaderOnlyFromTrustedPeer(t *testing.T) {
	trusted, err := NewTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if got := ClientIP("203.0.113.9:1234", "1.2.3.4", trusted); got != "203.0.113.9" {
		t.Fatalf("untrusted peer spoofed client IP: %s", got)
	}
	if got := ClientIP("10.0.0.2:1234", "198.51.100.8, 10.0.0.1", trusted); got != "198.51.100.8" {
		t.Fatalf("unexpected forwarded client IP: %s", got)
	}
}
