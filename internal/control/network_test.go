package control

import (
	"strings"
	"testing"
)

func TestValidateAndRenderNetworkPlan(t *testing.T) {
	plan := NetworkPlan{Version: 1, Interface: "ens18", DHCP4: false, Addresses: []string{"192.0.2.10/24"}, Gateway4: "192.0.2.1", Nameservers: []string{"1.1.1.1", "8.8.8.8"}, MTU: 1500}
	if err := ValidateNetworkPlan(plan, map[string]bool{"ens18": true}); err != nil {
		t.Fatal(err)
	}
	yaml, err := RenderNetplan(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"ens18:", "192.0.2.10/24", "via: 192.0.2.1", "1.1.1.1"} {
		if !strings.Contains(yaml, expected) {
			t.Fatalf("rendered Netplan does not contain %q:\n%s", expected, yaml)
		}
	}
}

func TestNetworkPlanRejectsUnsafeOrConflictingValues(t *testing.T) {
	tests := []NetworkPlan{
		{Version: 1, Interface: "lo", DHCP4: true},
		{Version: 1, Interface: "ens18\nowned", DHCP4: true},
		{Version: 1, Interface: "ens18", DHCP4: true, Addresses: []string{"192.0.2.10/24"}},
		{Version: 1, Interface: "ens18", DHCP4: false, Addresses: []string{"not-a-cidr"}},
		{Version: 1, Interface: "ens18", DHCP4: false, Addresses: []string{"192.0.2.10/24"}, Nameservers: []string{"not-an-ip"}},
	}
	for i, plan := range tests {
		if err := ValidateNetworkPlan(plan, nil); err == nil {
			t.Fatalf("invalid network plan %d was accepted: %#v", i, plan)
		}
	}
}
