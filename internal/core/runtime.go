package core

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/paddman/CherryWAF/internal/certstore"
	"github.com/paddman/CherryWAF/internal/config"
	"github.com/paddman/CherryWAF/internal/logging"
	"github.com/paddman/CherryWAF/internal/metrics"
	"github.com/paddman/CherryWAF/internal/netutil"
	"github.com/paddman/CherryWAF/internal/proxy"
	"github.com/paddman/CherryWAF/internal/ratelimit"
	"github.com/paddman/CherryWAF/internal/waf"
)

type Runtime struct {
	Config         *config.Config
	Engine         *waf.Engine
	Certificates   *certstore.Store
	TrustedProxies *netutil.TrustedProxies
	Limiter        *ratelimit.Limiter
	Logger         *logging.Logger
	LoadedAt       time.Time

	exactRoutes    map[string]*Route
	wildcardRoutes map[string]*Route
	closeOnce      sync.Once
	closeErr       error
}

type Route struct {
	VirtualHost config.VirtualHost
	Backend     *proxy.Backend
}

func Build(configPath string, metric *metrics.Metrics) (*Runtime, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	ruleFiles := make([]string, 0, len(cfg.Rules.Files))
	for _, path := range cfg.Rules.Files {
		ruleFiles = append(ruleFiles, cfg.ResolvePath(path))
	}
	engine, err := waf.New(cfg.Security.Mode, cfg.Security.BlockThreshold, cfg.Rules.Builtins, ruleFiles)
	if err != nil {
		return nil, fmt.Errorf("build WAF engine: %w", err)
	}

	trusted, err := netutil.NewTrustedProxies(cfg.Security.TrustedProxies)
	if err != nil {
		return nil, err
	}

	logger, err := logging.New(cfg.ResolvePath(cfg.Logging.AccessFile), cfg.ResolvePath(cfg.Logging.SecurityFile))
	if err != nil {
		return nil, err
	}
	cleanupLogger := true
	defer func() {
		if cleanupLogger {
			_ = logger.Close()
		}
	}()

	runtime := &Runtime{
		Config: cfg, Engine: engine, TrustedProxies: trusted, Logger: logger,
		LoadedAt: time.Now().UTC(), exactRoutes: make(map[string]*Route), wildcardRoutes: make(map[string]*Route),
	}
	cleanupLogger = false
	if cfg.Security.RateLimit.Enabled {
		runtime.Limiter = ratelimit.New(
			cfg.Security.RateLimit.RequestsPerSecond,
			cfg.Security.RateLimit.Burst,
			time.Duration(cfg.Security.RateLimit.EntryTTLSeconds)*time.Second,
		)
	}

	if cfg.HTTPS.Enabled {
		store, err := certstore.Load(cfg, time.Now())
		if err != nil {
			runtime.Close()
			return nil, fmt.Errorf("load TLS certificates: %w", err)
		}
		runtime.Certificates = store
	}

	for _, vhost := range cfg.EnabledVirtualHosts() {
		backend, err := proxy.New(vhost, cfg, metric)
		if err != nil {
			runtime.Close()
			return nil, fmt.Errorf("virtual host %q: %w", vhost.Name, err)
		}
		route := &Route{VirtualHost: vhost, Backend: backend}
		for _, domain := range vhost.Domains {
			if strings.HasPrefix(domain, "*.") {
				runtime.wildcardRoutes[strings.TrimPrefix(domain, "*.")] = route
			} else {
				runtime.exactRoutes[domain] = route
			}
		}
	}

	return runtime, nil
}

func (r *Runtime) Route(host string) (*Route, bool) {
	if r == nil {
		return nil, false
	}
	host = proxy.Hostname(host)
	if route := r.exactRoutes[host]; route != nil {
		return route, true
	}
	// Deterministic longest-suffix match. Configuration validation prevents
	// exact duplicates but overlapping wildcards are legal and useful.
	suffixes := make([]string, 0, len(r.wildcardRoutes))
	for suffix := range r.wildcardRoutes {
		suffixes = append(suffixes, suffix)
	}
	sort.Slice(suffixes, func(i, j int) bool { return len(suffixes[i]) > len(suffixes[j]) })
	for _, suffix := range suffixes {
		needle := "." + suffix
		if !strings.HasSuffix(host, needle) {
			continue
		}
		left := strings.TrimSuffix(host, needle)
		if left != "" && !strings.Contains(left, ".") {
			return r.wildcardRoutes[suffix], true
		}
	}
	return nil, false
}

func (r *Runtime) TLSVersion() uint16 {
	if r != nil && r.Config.HTTPS.MinTLSVersion == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.Limiter != nil {
			r.Limiter.Close()
		}
		seen := make(map[*Route]struct{})
		for _, route := range r.exactRoutes {
			seen[route] = struct{}{}
		}
		for _, route := range r.wildcardRoutes {
			seen[route] = struct{}{}
		}
		for route := range seen {
			route.Backend.CloseIdleConnections()
		}
		if r.Logger != nil {
			r.closeErr = r.Logger.Close()
		}
	})
	return r.closeErr
}

func Validate(configPath string) (*ValidationResult, error) {
	metric := &metrics.Metrics{}
	runtime, err := Build(configPath, metric)
	if err != nil {
		return nil, err
	}
	defer runtime.Close()
	result := &ValidationResult{
		Mode: runtime.Engine.Mode(), RuleCount: runtime.Engine.RuleCount(),
		Domains: runtime.Config.DomainNames(), Certificates: runtime.CertificatesInfo(),
	}
	return result, nil
}

type ValidationResult struct {
	Mode         string           `json:"mode"`
	RuleCount    int              `json:"rule_count"`
	Domains      []string         `json:"domains"`
	Certificates []certstore.Info `json:"certificates,omitempty"`
}

func (r *Runtime) CertificatesInfo() []certstore.Info {
	if r == nil || r.Certificates == nil {
		return nil
	}
	return r.Certificates.Info()
}

func (r *Runtime) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if r == nil || r.Certificates == nil {
		return nil, errors.New("TLS certificate store is unavailable")
	}
	return r.Certificates.GetCertificate(hello)
}
