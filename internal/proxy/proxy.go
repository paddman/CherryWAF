package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paddman/CherryWAF/internal/config"
	"github.com/paddman/CherryWAF/internal/metrics"
)

type Backend struct {
	proxy         *httputil.ReverseProxy
	vhost         config.VirtualHost
	pools         map[string]*poolRuntime
	defaultPool   string
	contentRoutes []compiledContentRoute
	metric        *metrics.Metrics
	cookieKey     [32]byte
	stop          chan struct{}
	closeOnce     sync.Once
}

var (
	persistenceKeyOnce sync.Once
	persistenceKey     [32]byte
	persistenceKeyErr  error
)

func processPersistenceKey() ([32]byte, error) {
	persistenceKeyOnce.Do(func() {
		_, persistenceKeyErr = rand.Read(persistenceKey[:])
	})
	return persistenceKey, persistenceKeyErr
}

type poolRuntime struct {
	config  config.ServerPool
	members []*memberRuntime
	rr      atomic.Uint64
	mu      sync.Mutex
}

type memberRuntime struct {
	config config.PoolMember
	target *url.URL

	transport *http.Transport
	health    config.HealthCheckConfig

	healthy             atomic.Bool
	active              atomic.Int64
	requests            atomic.Uint64
	failures            atomic.Uint64
	consecutiveSuccess  atomic.Int32
	consecutiveFailures atomic.Int32
	lastCheckUnixNano   atomic.Int64
	lastError           atomic.Value
	currentWeight       int
	checking            atomic.Bool
}

type selectionState struct {
	mu          sync.RWMutex
	pool        *poolRuntime
	member      *memberRuntime
	clientIP    string
	secure      bool
	originalURL *url.URL
	attempted   map[string]struct{}
}

type contextKey uint8

const selectionContextKey contextKey = 1

type PoolStatus struct {
	Name        string         `json:"name"`
	Algorithm   string         `json:"algorithm"`
	FailureMode string         `json:"failure_mode"`
	Healthy     int            `json:"healthy_members"`
	Total       int            `json:"total_members"`
	Members     []MemberStatus `json:"members"`
}

type MemberStatus struct {
	ID          string    `json:"id"`
	URL         string    `json:"url"`
	Enabled     bool      `json:"enabled"`
	Backup      bool      `json:"backup"`
	Weight      int       `json:"weight"`
	Priority    int       `json:"priority"`
	Healthy     bool      `json:"healthy"`
	Active      int64     `json:"active_connections"`
	Requests    uint64    `json:"requests"`
	Failures    uint64    `json:"failures"`
	LastChecked time.Time `json:"last_checked,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

func New(vhost config.VirtualHost, cfg *config.Config, metric *metrics.Metrics) (*Backend, error) {
	backend := &Backend{
		vhost: vhost, pools: make(map[string]*poolRuntime), metric: metric,
		stop: make(chan struct{}),
	}
	cookieKey, err := processPersistenceKey()
	if err != nil {
		return nil, fmt.Errorf("generate persistence key: %w", err)
	}
	backend.cookieKey = cookieKey

	poolNames := make(map[string]struct{})
	if vhost.ServerPool != "" {
		backend.defaultPool = vhost.ServerPool
		poolNames[vhost.ServerPool] = struct{}{}
	} else {
		backend.defaultPool = "__direct__" + vhost.Name
		poolNames[backend.defaultPool] = struct{}{}
	}
	for _, route := range vhost.ContentRoutes {
		if route.Enabled {
			poolNames[route.Pool] = struct{}{}
		}
	}

	for name := range poolNames {
		var pool config.ServerPool
		if strings.HasPrefix(name, "__direct__") {
			pool = config.ServerPool{
				Name: name, Enabled: true, Algorithm: "round_robin", FailureMode: "last_resort",
				Members: []config.PoolMember{{
					ID: "origin", URL: vhost.Upstream, Enabled: true, Weight: 1, Priority: 100,
					OriginTLS: vhost.OriginTLS,
				}},
				HealthCheck: config.HealthCheckConfig{Enabled: false},
			}
		} else {
			configured := cfg.ServerPoolByName(name)
			if configured == nil {
				return nil, fmt.Errorf("server pool %q does not exist", name)
			}
			pool = *configured
		}
		runtime, err := newPoolRuntime(pool, vhost, cfg)
		if err != nil {
			backend.CloseIdleConnections()
			return nil, fmt.Errorf("server pool %q: %w", name, err)
		}
		backend.pools[name] = runtime
	}

	compiledRoutes, err := compileContentRoutes(vhost.ContentRoutes)
	if err != nil {
		backend.CloseIdleConnections()
		return nil, err
	}
	backend.contentRoutes = compiledRoutes

	backend.proxy = &httputil.ReverseProxy{
		Rewrite:        backend.rewrite,
		Transport:      poolTransport{backend: backend},
		FlushInterval:  100 * time.Millisecond,
		ModifyResponse: backend.modifyResponse,
		ErrorHandler:   backend.errorHandler,
	}
	backend.startHealthChecks()
	return backend, nil
}

func newPoolRuntime(pool config.ServerPool, vhost config.VirtualHost, cfg *config.Config) (*poolRuntime, error) {
	runtime := &poolRuntime{config: pool}
	for _, item := range pool.Members {
		if !item.Enabled {
			continue
		}
		target, err := url.Parse(item.URL)
		if err != nil {
			return nil, fmt.Errorf("member %q URL: %w", item.ID, err)
		}
		originTLS := item.OriginTLS
		if !hasOriginTLS(originTLS) {
			originTLS = vhost.OriginTLS
		}
		transport, err := newTransport(target, originTLS, cfg)
		if err != nil {
			return nil, fmt.Errorf("member %q transport: %w", item.ID, err)
		}
		member := &memberRuntime{config: item, target: target, transport: transport, health: pool.HealthCheck}
		member.healthy.Store(true)
		member.lastError.Store("")
		runtime.members = append(runtime.members, member)
	}
	if len(runtime.members) == 0 {
		return nil, errors.New("pool contains no enabled members")
	}
	return runtime, nil
}

func newTransport(target *url.URL, originTLS config.OriginTLSConfig, cfg *config.Config) (*http.Transport, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Protected origins are always contacted directly. Process-wide proxy
	// variables must never silently become part of the security path.
	transport.Proxy = nil
	transport.MaxIdleConns = 1024
	transport.MaxIdleConnsPerHost = 256
	transport.MaxConnsPerHost = 0
	transport.IdleConnTimeout = 90 * time.Second
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.ExpectContinueTimeout = time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ForceAttemptHTTP2 = true
	if target.Scheme == "https" {
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         originTLS.ServerName,
			InsecureSkipVerify: originTLS.InsecureSkipVerify, // Explicit opt-in; validated and disabled by default.
		}
		if originTLS.CAFile != "" {
			pool, err := loadCAPool(cfg.ResolvePath(originTLS.CAFile))
			if err != nil {
				return nil, err
			}
			tlsConfig.RootCAs = pool
		}
		transport.TLSClientConfig = tlsConfig
	}
	return transport, nil
}

func (b *Backend) rewrite(request *httputil.ProxyRequest) {
	state, ok := request.In.Context().Value(selectionContextKey).(*selectionState)
	if !ok || state == nil {
		return
	}
	member := state.currentMember()
	if member == nil {
		return
	}
	request.SetURL(member.target)
	if b.vhost.PreserveHost {
		request.Out.Host = request.In.Host
	} else {
		request.Out.Host = member.target.Host
	}
	request.SetXForwarded()
	request.Out.Header.Set("X-CherryWAF", "1")
	request.Out.Header.Set("X-CherryWAF-Pool", state.pool.config.Name)
	request.Out.Header.Set("X-CherryWAF-Member", member.config.ID)
	if request.Out.Header.Get("X-Request-ID") == "" {
		request.Out.Header.Set("X-Request-ID", NewRequestID())
	}
	for key, value := range b.vhost.RequestHeaders {
		request.Out.Header.Set(key, value)
	}
}

func (b *Backend) modifyResponse(response *http.Response) error {
	state, _ := response.Request.Context().Value(selectionContextKey).(*selectionState)
	if state != nil {
		member := state.currentMember()
		if member != nil {
			member.recordSuccess()
			if b.vhost.Persistence.Mode == "cookie" {
				response.Header.Add("Set-Cookie", b.persistenceCookie(state.pool, member, state.secure).String())
			}
		}
	}
	for key, value := range b.vhost.ResponseHeaders {
		response.Header.Set(key, value)
	}
	response.Header.Set("Via", "CherryWAF")
	return nil
}

func (b *Backend) errorHandler(w http.ResponseWriter, r *http.Request, proxyErr error) {
	b.metric.UpstreamError()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadGateway)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "upstream unavailable", "request_id": r.Header.Get("X-Request-ID"),
	})
}

func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request, clientIP string) string {
	pool := b.selectPool(r)
	if pool == nil {
		writeUnavailable(w, r, "server pool unavailable")
		return ""
	}
	member := b.selectMember(pool, r, clientIP, nil)
	if member == nil {
		writeUnavailable(w, r, "no healthy upstream member")
		return "pool:" + pool.config.Name
	}
	state := &selectionState{
		pool: pool, member: member, clientIP: clientIP, secure: r.TLS != nil,
		originalURL: cloneURL(r.URL), attempted: map[string]struct{}{member.config.ID: {}},
	}
	request := r.Clone(context.WithValue(r.Context(), selectionContextKey, state))
	if ip := net.ParseIP(clientIP); ip != nil {
		request.RemoteAddr = net.JoinHostPort(ip.String(), "0")
	}
	b.proxy.ServeHTTP(w, request)
	selected := state.currentMember()
	if selected == nil {
		return "pool:" + pool.config.Name
	}
	return selected.target.Redacted()
}

func (b *Backend) selectPool(r *http.Request) *poolRuntime {
	for _, route := range b.contentRoutes {
		if route.matches(r) {
			if pool := b.pools[route.config.Pool]; pool != nil {
				return pool
			}
		}
	}
	return b.pools[b.defaultPool]
}

func (b *Backend) selectMember(pool *poolRuntime, r *http.Request, clientIP string, excluded map[string]struct{}) *memberRuntime {
	eligible := pool.eligible(excluded, false)
	if len(eligible) == 0 && pool.config.FailureMode == "last_resort" {
		eligible = pool.eligible(excluded, true)
	}
	if len(eligible) == 0 {
		return nil
	}
	if b.vhost.Persistence.Mode == "cookie" {
		if cookie, err := r.Cookie(b.vhost.Persistence.CookieName); err == nil {
			if member := b.memberForCookie(pool, cookie.Value, eligible); member != nil {
				return member
			}
		}
	}
	if b.vhost.Persistence.Mode == "source_ip" || pool.config.Algorithm == "source_ip_hash" {
		return hashMember(eligible, clientIP)
	}
	return pool.choose(eligible)
}

func (p *poolRuntime) eligible(excluded map[string]struct{}, includeUnhealthy bool) []*memberRuntime {
	primary := make([]*memberRuntime, 0, len(p.members))
	backup := make([]*memberRuntime, 0, len(p.members))
	for _, member := range p.members {
		if excluded != nil {
			if _, found := excluded[member.config.ID]; found {
				continue
			}
		}
		if !includeUnhealthy && !member.healthy.Load() {
			continue
		}
		if member.config.Backup {
			backup = append(backup, member)
		} else {
			primary = append(primary, member)
		}
	}
	if len(primary) > 0 {
		return primary
	}
	return backup
}

func (p *poolRuntime) choose(eligible []*memberRuntime) *memberRuntime {
	if len(eligible) == 0 {
		return nil
	}
	switch p.config.Algorithm {
	case "least_connections":
		return leastConnections(eligible)
	case "weighted_round_robin":
		return p.weightedRoundRobin(eligible)
	case "primary_backup":
		return primaryBackup(eligible)
	case "random":
		position := p.rr.Add(0x9e3779b97f4a7c15)
		return eligible[int(position%uint64(len(eligible)))]
	default:
		position := p.rr.Add(1) - 1
		return eligible[int(position%uint64(len(eligible)))]
	}
}

func leastConnections(members []*memberRuntime) *memberRuntime {
	selected := members[0]
	selectedRatio := float64(selected.active.Load()) / float64(max(selected.config.Weight, 1))
	for _, member := range members[1:] {
		ratio := float64(member.active.Load()) / float64(max(member.config.Weight, 1))
		if ratio < selectedRatio || (ratio == selectedRatio && member.requests.Load() < selected.requests.Load()) {
			selected = member
			selectedRatio = ratio
		}
	}
	return selected
}

func primaryBackup(members []*memberRuntime) *memberRuntime {
	selected := members[0]
	for _, member := range members[1:] {
		if member.config.Priority < selected.config.Priority ||
			(member.config.Priority == selected.config.Priority && member.active.Load() < selected.active.Load()) {
			selected = member
		}
	}
	return selected
}

func (p *poolRuntime) weightedRoundRobin(members []*memberRuntime) *memberRuntime {
	p.mu.Lock()
	defer p.mu.Unlock()
	var selected *memberRuntime
	total := 0
	for _, member := range members {
		weight := max(member.config.Weight, 1)
		member.currentWeight += weight
		total += weight
		if selected == nil || member.currentWeight > selected.currentWeight {
			selected = member
		}
	}
	if selected != nil {
		selected.currentWeight -= total
	}
	return selected
}

func hashMember(members []*memberRuntime, value string) *memberRuntime {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(value))
	return members[int(hash.Sum64()%uint64(len(members)))]
}

func (b *Backend) memberForCookie(pool *poolRuntime, value string, eligible []*memberRuntime) *memberRuntime {
	for _, member := range eligible {
		if hmac.Equal([]byte(value), []byte(b.memberToken(pool, member))) {
			return member
		}
	}
	return nil
}

func (b *Backend) memberToken(pool *poolRuntime, member *memberRuntime) string {
	mac := hmac.New(sha256.New, b.cookieKey[:])
	_, _ = mac.Write([]byte(pool.config.Name))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(member.config.ID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:18])
}

func (b *Backend) persistenceCookie(pool *poolRuntime, member *memberRuntime, secure bool) *http.Cookie {
	return &http.Cookie{
		Name: b.vhost.Persistence.CookieName, Value: b.memberToken(pool, member),
		Path: "/", MaxAge: b.vhost.Persistence.TTLSeconds, HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode,
	}
}

func (b *Backend) Upstream() string {
	pool := b.pools[b.defaultPool]
	if pool == nil {
		return ""
	}
	if strings.HasPrefix(pool.config.Name, "__direct__") && len(pool.members) == 1 {
		return pool.members[0].target.Redacted()
	}
	return "pool:" + pool.config.Name
}

func (b *Backend) Status() []PoolStatus {
	if b == nil {
		return nil
	}
	names := make([]string, 0, len(b.pools))
	for name := range b.pools {
		names = append(names, name)
	}
	sort.Strings(names)
	statuses := make([]PoolStatus, 0, len(names))
	for _, name := range names {
		pool := b.pools[name]
		status := PoolStatus{Name: name, Algorithm: pool.config.Algorithm, FailureMode: pool.config.FailureMode, Total: len(pool.members)}
		for _, member := range pool.members {
			healthy := member.healthy.Load()
			if healthy {
				status.Healthy++
			}
			item := MemberStatus{
				ID: member.config.ID, URL: member.target.Redacted(), Enabled: member.config.Enabled,
				Backup: member.config.Backup, Weight: member.config.Weight, Priority: member.config.Priority,
				Healthy: healthy, Active: member.active.Load(), Requests: member.requests.Load(), Failures: member.failures.Load(),
			}
			if checked := member.lastCheckUnixNano.Load(); checked > 0 {
				item.LastChecked = time.Unix(0, checked).UTC()
			}
			if value := member.lastError.Load(); value != nil {
				item.LastError, _ = value.(string)
			}
			status.Members = append(status.Members, item)
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func (b *Backend) CloseIdleConnections() {
	if b == nil {
		return
	}
	b.closeOnce.Do(func() {
		close(b.stop)
		for _, pool := range b.pools {
			for _, member := range pool.members {
				member.transport.CloseIdleConnections()
			}
		}
	})
}

type poolTransport struct{ backend *Backend }

func (transport poolTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	state, ok := request.Context().Value(selectionContextKey).(*selectionState)
	if !ok || state == nil {
		return nil, errors.New("upstream selection state is missing")
	}
	member := state.currentMember()
	if member == nil {
		return nil, errors.New("upstream member is missing")
	}
	response, err := roundTripMember(member, request)
	if err == nil {
		return response, nil
	}
	member.recordFailure(err)
	if !retryable(request) {
		return nil, err
	}
	alternate := transport.backend.selectMember(state.pool, request, state.clientIP, state.attemptedMembers())
	if alternate == nil {
		return nil, err
	}
	state.setMember(alternate)
	retry, cloneErr := cloneForRetry(request, state, alternate)
	if cloneErr != nil {
		return nil, errors.Join(err, cloneErr)
	}
	response, retryErr := roundTripMember(alternate, retry)
	if retryErr != nil {
		alternate.recordFailure(retryErr)
		return nil, errors.Join(err, retryErr)
	}
	return response, nil
}

func roundTripMember(member *memberRuntime, request *http.Request) (*http.Response, error) {
	member.active.Add(1)
	member.requests.Add(1)
	defer member.active.Add(-1)
	return member.transport.RoundTrip(request)
}

func retryable(request *http.Request) bool {
	switch request.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return request.GetBody != nil
	}
}

func cloneForRetry(request *http.Request, state *selectionState, member *memberRuntime) (*http.Request, error) {
	retry := request.Clone(request.Context())
	if request.Body != nil && request.Body != http.NoBody {
		if request.GetBody == nil {
			return nil, errors.New("request body cannot be replayed")
		}
		body, err := request.GetBody()
		if err != nil {
			return nil, err
		}
		retry.Body = body
	}
	rewriteURL(retry.URL, member.target, state.originalURL)
	if state.pool != nil {
		retry.Header.Set("X-CherryWAF-Pool", state.pool.config.Name)
	}
	retry.Header.Set("X-CherryWAF-Member", member.config.ID)
	return retry, nil
}

func rewriteURL(output, target, original *url.URL) {
	output.Scheme = target.Scheme
	output.Host = target.Host
	output.Path, output.RawPath = joinURLPath(target, original)
	if target.RawQuery == "" || original.RawQuery == "" {
		output.RawQuery = target.RawQuery + original.RawQuery
	} else {
		output.RawQuery = target.RawQuery + "&" + original.RawQuery
	}
}

func (state *selectionState) currentMember() *memberRuntime {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.member
}

func (state *selectionState) setMember(member *memberRuntime) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.member = member
	state.attempted[member.config.ID] = struct{}{}
}

func (state *selectionState) attemptedMembers() map[string]struct{} {
	state.mu.RLock()
	defer state.mu.RUnlock()
	result := make(map[string]struct{}, len(state.attempted))
	for key := range state.attempted {
		result[key] = struct{}{}
	}
	return result
}

func (member *memberRuntime) recordSuccess() {
	member.consecutiveFailures.Store(0)
	if !member.health.Enabled {
		member.healthy.Store(true)
		return
	}
	if member.consecutiveSuccess.Add(1) >= int32(member.health.HealthyThreshold) {
		member.healthy.Store(true)
	}
	member.lastError.Store("")
}

func (member *memberRuntime) recordFailure(err error) {
	member.failures.Add(1)
	member.consecutiveSuccess.Store(0)
	if err != nil {
		member.lastError.Store(limitError(err.Error()))
	}
	if member.health.Enabled && member.consecutiveFailures.Add(1) >= int32(member.health.UnhealthyThreshold) {
		member.healthy.Store(false)
	}
}

func limitError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 256 {
		return value[:256]
	}
	return value
}

func writeUnavailable(w http.ResponseWriter, r *http.Request, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": message, "request_id": r.Header.Get("X-Request-ID"),
	})
}

func cloneURL(value *url.URL) *url.URL {
	if value == nil {
		return &url.URL{Path: "/"}
	}
	copy := *value
	return &copy
}

func joinURLPath(a, b *url.URL) (path, rawPath string) {
	if a.RawPath == "" && b.RawPath == "" {
		aslash := strings.HasSuffix(a.Path, "/")
		bslash := strings.HasPrefix(b.Path, "/")
		switch {
		case aslash && bslash:
			return a.Path + b.Path[1:], ""
		case !aslash && !bslash:
			return a.Path + "/" + b.Path, ""
		}
		return a.Path + b.Path, ""
	}
	aPath := a.EscapedPath()
	bPath := b.EscapedPath()
	aslash := strings.HasSuffix(aPath, "/")
	bslash := strings.HasPrefix(bPath, "/")
	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], aPath + bPath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, aPath + "/" + bPath
	}
	return a.Path + b.Path, aPath + bPath
}

func hasOriginTLS(value config.OriginTLSConfig) bool {
	return value.CAFile != "" || value.ServerName != "" || value.InsecureSkipVerify
}

func NewRequestID() string {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		return fmt.Sprintf("cwaf-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(data[:])
}

func loadCAPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read origin CA file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("origin CA file contains no valid PEM certificates")
	}
	return pool, nil
}

func Hostname(hostport string) string {
	host := strings.TrimSpace(strings.ToLower(hostport))
	if parsed, err := url.Parse("//" + host); err == nil && parsed.Hostname() != "" {
		return strings.TrimSuffix(parsed.Hostname(), ".")
	}
	return strings.TrimSuffix(host, ".")
}
