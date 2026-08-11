package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/paddman/CherryWAF/internal/config"
	"github.com/paddman/CherryWAF/internal/metrics"
)

func testOrigin(t *testing.T, name string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Origin", name)
		_, _ = io.WriteString(w, name)
	}))
}

func poolConfig(name string, servers ...*httptest.Server) config.ServerPool {
	members := make([]config.PoolMember, 0, len(servers))
	for index, server := range servers {
		members = append(members, config.PoolMember{ID: fmt.Sprintf("m%d", index+1), URL: server.URL, Enabled: true, Weight: 1, Priority: 100})
	}
	return config.ServerPool{Name: name, Enabled: true, Algorithm: "round_robin", FailureMode: "reject", Members: members, HealthCheck: config.HealthCheckConfig{Enabled: false}}
}

func serve(t *testing.T, backend *Backend, path, clientIP string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://app.example"+path, nil)
	req.Host = "app.example"
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	backend.ServeHTTP(recorder, req, clientIP)
	return recorder
}

func TestRoundRobinAndContentRouting(t *testing.T) {
	one := testOrigin(t, "one")
	defer one.Close()
	two := testOrigin(t, "two")
	defer two.Close()
	api := testOrigin(t, "api")
	defer api.Close()
	cfg := &config.Config{ServerPools: []config.ServerPool{poolConfig("web", one, two), poolConfig("api", api)}}
	vhost := config.VirtualHost{Name: "app", Action: "group", ServerPool: "web", PreserveHost: true, Persistence: config.PersistenceConfig{Mode: "none"}, ContentRoutes: []config.ContentRoute{{Name: "api", Enabled: true, Pool: "api", PathPrefix: "/api/"}}}
	backend, err := New(vhost, cfg, &metrics.Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.CloseIdleConnections()
	if got := strings.TrimSpace(serve(t, backend, "/", "192.0.2.1").Body.String()); got != "one" {
		t.Fatalf("first origin = %q", got)
	}
	if got := strings.TrimSpace(serve(t, backend, "/", "192.0.2.2").Body.String()); got != "two" {
		t.Fatalf("second origin = %q", got)
	}
	if got := strings.TrimSpace(serve(t, backend, "/api/users", "192.0.2.3").Body.String()); got != "api" {
		t.Fatalf("content route origin = %q", got)
	}
}

func TestCookiePersistence(t *testing.T) {
	one := testOrigin(t, "one")
	defer one.Close()
	two := testOrigin(t, "two")
	defer two.Close()
	cfg := &config.Config{ServerPools: []config.ServerPool{poolConfig("web", one, two)}}
	vhost := config.VirtualHost{Name: "app", Action: "group", ServerPool: "web", Persistence: config.PersistenceConfig{Mode: "cookie", CookieName: "CWAF_ROUTE", TTLSeconds: 3600}}
	backend, err := New(vhost, cfg, &metrics.Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.CloseIdleConnections()
	first := serve(t, backend, "/", "192.0.2.10")
	result := first.Result()
	cookies := result.Cookies()
	_ = result.Body.Close()
	if len(cookies) == 0 || cookies[0].Name != "CWAF_ROUTE" {
		t.Fatalf("persistence cookie missing: %#v", cookies)
	}
	firstOrigin := strings.TrimSpace(first.Body.String())
	second := serve(t, backend, "/", "192.0.2.99", cookies[0])
	if got := strings.TrimSpace(second.Body.String()); got != firstOrigin {
		t.Fatalf("cookie did not persist: first=%q second=%q", firstOrigin, got)
	}
}

func TestCookiePersistenceSurvivesBackendReload(t *testing.T) {
	one := testOrigin(t, "one")
	defer one.Close()
	two := testOrigin(t, "two")
	defer two.Close()
	cfg := &config.Config{ServerPools: []config.ServerPool{poolConfig("web", one, two)}}
	vhost := config.VirtualHost{Name: "app", Action: "group", ServerPool: "web", Persistence: config.PersistenceConfig{Mode: "cookie", CookieName: "CWAF_ROUTE", TTLSeconds: 3600}}
	firstBackend, err := New(vhost, cfg, &metrics.Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	first := serve(t, firstBackend, "/", "192.0.2.10")
	result := first.Result()
	cookies := result.Cookies()
	_ = result.Body.Close()
	firstOrigin := strings.TrimSpace(first.Body.String())
	firstBackend.CloseIdleConnections()
	if len(cookies) == 0 {
		t.Fatal("persistence cookie missing")
	}

	secondBackend, err := New(vhost, cfg, &metrics.Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	defer secondBackend.CloseIdleConnections()
	second := serve(t, secondBackend, "/", "192.0.2.99", cookies[0])
	if got := strings.TrimSpace(second.Body.String()); got != firstOrigin {
		t.Fatalf("cookie was invalidated by backend reload: first=%q second=%q", firstOrigin, got)
	}
}

func TestHealthCheckMarksUnhealthyMember(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer bad.Close()
	good := testOrigin(t, "good")
	defer good.Close()
	pool := poolConfig("web", bad, good)
	pool.HealthCheck = config.HealthCheckConfig{Enabled: true, Type: "http", IntervalSeconds: 2, TimeoutSeconds: 1, HealthyThreshold: 1, UnhealthyThreshold: 1, Method: "GET", Path: "/", ExpectedStatusMin: 200, ExpectedStatusMax: 399}
	cfg := &config.Config{ServerPools: []config.ServerPool{pool}}
	backend, err := New(config.VirtualHost{Name: "app", Action: "group", ServerPool: "web", Persistence: config.PersistenceConfig{Mode: "none"}}, cfg, &metrics.Metrics{})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.CloseIdleConnections()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		statuses := backend.Status()
		if len(statuses) == 1 && statuses[0].Healthy == 1 {
			if got := strings.TrimSpace(serve(t, backend, "/", "192.0.2.2").Body.String()); got != "good" {
				t.Fatalf("unhealthy member selected: %q", got)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("health state did not converge: %#v", backend.Status())
}
