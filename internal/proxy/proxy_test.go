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
	if backend.transport.Proxy != nil {
		t.Fatal("origin transport unexpectedly inherited environment proxy settings")
	}
}
