package bot

import (
	"testing"

	"github.com/paddman/CherryWAF/internal/config"
)

func TestUserAgentMonitorAndBlock(t *testing.T) {
	engine, err := New(config.BotPolicyConfig{Enabled: true, Mode: "block", RequestsPerMinute: 60, Burst: 2, BadUserAgents: []string{"(?i)evilbot"}, AllowUserAgents: []string{"TrustedBot"}})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if decision := engine.Inspect("192.0.2.10", "TrustedBot evilbot"); decision.Matched {
		t.Fatalf("allow expression should win: %#v", decision)
	}
	if decision := engine.Inspect("192.0.2.11", "evilbot/1"); !decision.Matched || !decision.Blocked || decision.Kind != "user_agent" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}
