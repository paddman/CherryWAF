package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterRefills(t *testing.T) {
	l := New(1, 2, time.Minute)
	defer l.Close()
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	if !l.Allow("client") || !l.Allow("client") {
		t.Fatal("burst should allow two requests")
	}
	if l.Allow("client") {
		t.Fatal("third request should be limited")
	}
	now = now.Add(time.Second)
	if !l.Allow("client") {
		t.Fatal("token should refill")
	}
}
