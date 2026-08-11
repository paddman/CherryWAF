package proxy

import (
	"testing"

	"github.com/paddman/CherryWAF/internal/config"
	"github.com/paddman/CherryWAF/internal/metrics"
)

func TestOriginTransportDoesNotInheritEnvironmentProxy(t *testing.T) {
	backend, err := New(config.VirtualHost{
		Name: "test", Upstream: "http://origin.internal:8080",
	}, &config.Config{}, &metrics.Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.CloseIdleConnections()

	checked := 0
	for _, pool := range backend.pools {
		for _, member := range pool.members {
			checked++
			if member.transport.Proxy != nil {
				t.Fatalf("origin member %q unexpectedly inherited environment proxy settings", member.config.ID)
			}
		}
	}
	if checked == 0 {
		t.Fatal("backend did not create an origin member transport")
	}
}
