//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paddman/CherryWAF/internal/control"
)

func TestDryRunNetworkApplyAndRollback(t *testing.T) {
	dir := t.TempDir()
	netplan := filepath.Join(dir, "99-cherrywaf.yaml")
	original := []byte("network:\n  version: 2\n")
	if err := os.WriteFile(netplan, original, 0o600); err != nil {
		t.Fatal(err)
	}
	d := &daemon{dataDir: filepath.Join(dir, "state"), netplan: netplan, binaryPath: "/usr/local/sbin/cherrywaf-netd", dryRun: true}
	result, err := d.apply(control.NetworkPlan{Version: 1, Interface: "ens18", DHCP4: true, MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := os.ReadFile(netplan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(changed), "ens18:") {
		t.Fatalf("new Netplan was not written:\n%s", changed)
	}
	if err := d.rollback(result.Token); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(netplan)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(original) {
		t.Fatalf("Netplan was not restored:\n%s", restored)
	}
	if pending, err := d.pendingChanges(); err != nil || len(pending) != 0 {
		t.Fatalf("pending change was not cleaned up: %#v %v", pending, err)
	}
}

func TestDryRunNetworkConfirmKeepsCandidate(t *testing.T) {
	dir := t.TempDir()
	netplan := filepath.Join(dir, "99-cherrywaf.yaml")
	if err := os.WriteFile(netplan, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &daemon{dataDir: filepath.Join(dir, "state"), netplan: netplan, binaryPath: "/usr/local/sbin/cherrywaf-netd", dryRun: true}
	result, err := d.apply(control.NetworkPlan{Version: 1, Interface: "ens18", DHCP4: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.confirm(result.Token); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(netplan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "ens18:") {
		t.Fatalf("confirmed candidate was not retained:\n%s", data)
	}
}

func TestDryRunRejectsConcurrentPendingNetworkChange(t *testing.T) {
	dir := t.TempDir()
	netplan := filepath.Join(dir, "99-cherrywaf.yaml")
	if err := os.WriteFile(netplan, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &daemon{dataDir: filepath.Join(dir, "state"), netplan: netplan, binaryPath: "/usr/local/sbin/cherrywaf-netd", dryRun: true}
	first, err := d.apply(control.NetworkPlan{Version: 1, Interface: "ens18", DHCP4: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.apply(control.NetworkPlan{Version: 1, Interface: "ens18", DHCP4: true}); err == nil || !strings.Contains(err.Error(), "awaiting confirmation") {
		t.Fatalf("second pending change was accepted: %v", err)
	}
	if err := d.rollback(first.Token); err != nil {
		t.Fatal(err)
	}
}
