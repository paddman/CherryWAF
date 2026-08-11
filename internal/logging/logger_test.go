package logging

import (
	"io"
	"testing"
	"time"

	"github.com/paddman/CherryWAF/internal/waf"
)

func TestRecentSecurityKeepsNewestEventsAndReturnsCopies(t *testing.T) {
	logger := &Logger{
		security: &jsonLineWriter{writer: io.Discard},
	}

	for i := 0; i < recentSecurityCapacity+3; i++ {
		latitude := float64(i)
		if err := logger.Security(SecurityEvent{
			Timestamp: time.Unix(int64(i), 0).UTC(),
			RequestID: string(rune('a' + i%26)),
			ClientIP:  "203.0.113.10",
			Action:    "block",
			Matches:   []waf.Match{{RuleID: "LOCAL-1"}},
			Geo:       &GeoLocation{CountryCode: "TH", Latitude: &latitude},
		}); err != nil {
			t.Fatalf("Security() error: %v", err)
		}
	}

	events := logger.RecentSecurity(2)
	if len(events) != 2 {
		t.Fatalf("len(RecentSecurity()) = %d, want 2", len(events))
	}
	if got := events[0].Timestamp.Unix(); got != int64(recentSecurityCapacity+1) {
		t.Fatalf("first timestamp = %d, want %d", got, recentSecurityCapacity+1)
	}
	if got := events[1].Timestamp.Unix(); got != int64(recentSecurityCapacity+2) {
		t.Fatalf("last timestamp = %d, want %d", got, recentSecurityCapacity+2)
	}

	events[0].Matches[0].RuleID = "mutated"
	*events[0].Geo.Latitude = -99
	again := logger.RecentSecurity(2)
	if again[0].Matches[0].RuleID != "LOCAL-1" {
		t.Fatalf("stored match was mutated through returned copy")
	}
	if *again[0].Geo.Latitude == -99 {
		t.Fatalf("stored geo coordinates were mutated through returned copy")
	}
}
