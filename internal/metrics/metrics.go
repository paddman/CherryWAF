package metrics

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

type Metrics struct {
	requests       atomic.Uint64
	blocked        atomic.Uint64
	rateLimited    atomic.Uint64
	bodyTooLarge   atomic.Uint64
	upstreamErrors atomic.Uint64
	reloads        atomic.Uint64
	reloadFailures atomic.Uint64
	inFlight       atomic.Int64
	status2xx      atomic.Uint64
	status3xx      atomic.Uint64
	status4xx      atomic.Uint64
	status5xx      atomic.Uint64
	latencyNanos   atomic.Uint64
}

type Snapshot struct {
	Requests       uint64 `json:"requests"`
	Blocked        uint64 `json:"blocked"`
	RateLimited    uint64 `json:"rate_limited"`
	BodyTooLarge   uint64 `json:"body_too_large"`
	UpstreamErrors uint64 `json:"upstream_errors"`
	Reloads        uint64 `json:"reloads"`
	ReloadFailures uint64 `json:"reload_failures"`
	InFlight       int64  `json:"in_flight"`
	Status2xx      uint64 `json:"status_2xx"`
	Status3xx      uint64 `json:"status_3xx"`
	Status4xx      uint64 `json:"status_4xx"`
	Status5xx      uint64 `json:"status_5xx"`
	LatencyNanos   uint64 `json:"latency_nanos_total"`
}

func (m *Metrics) RequestStarted() { m.requests.Add(1); m.inFlight.Add(1) }
func (m *Metrics) RequestFinished(status int, duration time.Duration) {
	m.inFlight.Add(-1)
	m.latencyNanos.Add(uint64(max(duration.Nanoseconds(), 0)))
	switch {
	case status >= 200 && status < 300:
		m.status2xx.Add(1)
	case status >= 300 && status < 400:
		m.status3xx.Add(1)
	case status >= 400 && status < 500:
		m.status4xx.Add(1)
	case status >= 500:
		m.status5xx.Add(1)
	}
}
func (m *Metrics) Blocked()       { m.blocked.Add(1) }
func (m *Metrics) RateLimited()   { m.rateLimited.Add(1) }
func (m *Metrics) BodyTooLarge()  { m.bodyTooLarge.Add(1) }
func (m *Metrics) UpstreamError() { m.upstreamErrors.Add(1) }
func (m *Metrics) Reloaded()      { m.reloads.Add(1) }
func (m *Metrics) ReloadFailed()  { m.reloadFailures.Add(1) }

func (m *Metrics) Snapshot() Snapshot {
	return Snapshot{
		Requests: m.requests.Load(), Blocked: m.blocked.Load(), RateLimited: m.rateLimited.Load(),
		BodyTooLarge: m.bodyTooLarge.Load(), UpstreamErrors: m.upstreamErrors.Load(),
		Reloads: m.reloads.Load(), ReloadFailures: m.reloadFailures.Load(), InFlight: m.inFlight.Load(),
		Status2xx: m.status2xx.Load(), Status3xx: m.status3xx.Load(), Status4xx: m.status4xx.Load(), Status5xx: m.status5xx.Load(),
		LatencyNanos: m.latencyNanos.Load(),
	}
}

func (m *Metrics) Prometheus() string {
	s := m.Snapshot()
	var b strings.Builder
	write := func(name, help, typ string, value any) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", name, help, name, typ, name, value)
	}
	write("cherrywaf_requests_total", "HTTP requests processed.", "counter", s.Requests)
	write("cherrywaf_blocked_total", "Requests blocked by WAF policy.", "counter", s.Blocked)
	write("cherrywaf_rate_limited_total", "Requests rejected by rate limiting.", "counter", s.RateLimited)
	write("cherrywaf_body_too_large_total", "Requests rejected because the body exceeded inspection limits.", "counter", s.BodyTooLarge)
	write("cherrywaf_upstream_errors_total", "Reverse proxy upstream failures.", "counter", s.UpstreamErrors)
	write("cherrywaf_reloads_total", "Successful configuration reloads.", "counter", s.Reloads)
	write("cherrywaf_reload_failures_total", "Failed configuration reloads.", "counter", s.ReloadFailures)
	write("cherrywaf_in_flight", "Requests currently being processed.", "gauge", s.InFlight)
	write("cherrywaf_http_2xx_total", "HTTP 2xx responses.", "counter", s.Status2xx)
	write("cherrywaf_http_3xx_total", "HTTP 3xx responses.", "counter", s.Status3xx)
	write("cherrywaf_http_4xx_total", "HTTP 4xx responses.", "counter", s.Status4xx)
	write("cherrywaf_http_5xx_total", "HTTP 5xx responses.", "counter", s.Status5xx)
	write("cherrywaf_request_latency_seconds_total", "Cumulative request latency in seconds.", "counter", float64(s.LatencyNanos)/float64(time.Second))
	return b.String()
}
