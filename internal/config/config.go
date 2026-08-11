package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const CurrentVersion = 1

type Config struct {
	Version      int            `json:"version"`
	HTTP         HTTPConfig     `json:"http"`
	HTTPS        HTTPSConfig    `json:"https"`
	Admin        AdminConfig    `json:"admin"`
	Security     SecurityConfig `json:"security"`
	Rules        RulesConfig    `json:"rules"`
	Logging      LoggingConfig  `json:"logging"`
	ServerPools  []ServerPool   `json:"server_pools,omitempty"`
	VirtualHosts []VirtualHost  `json:"virtual_hosts"`

	BaseDir string `json:"-"`
}

type HTTPConfig struct {
	Enabled         bool   `json:"enabled"`
	Listen          string `json:"listen"`
	RedirectToHTTPS bool   `json:"redirect_to_https"`
}

type HTTPSConfig struct {
	Enabled       bool   `json:"enabled"`
	Listen        string `json:"listen"`
	MinTLSVersion string `json:"min_tls_version"`
}

type AdminConfig struct {
	Enabled     bool   `json:"enabled"`
	Listen      string `json:"listen"`
	TokenEnv    string `json:"token_env"`
	AllowPublic bool   `json:"allow_public"`
}

type SecurityConfig struct {
	Mode               string           `json:"mode"`
	BlockThreshold     int              `json:"block_threshold"`
	MaxBodyBytes       int64            `json:"max_body_bytes"`
	MaxHeaderBytes     int              `json:"max_header_bytes"`
	TrustedProxies     []string         `json:"trusted_proxies"`
	ForwardedForHeader string           `json:"forwarded_for_header"`
	RateLimit          RateLimitConfig  `json:"rate_limit"`
	Reputation         ReputationConfig `json:"reputation,omitempty"`
}

type RateLimitConfig struct {
	Enabled           bool    `json:"enabled"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	Burst             int     `json:"burst"`
	EntryTTLSeconds   int     `json:"entry_ttl_seconds"`
}

type ReputationConfig struct {
	Enabled bool     `json:"enabled"`
	Mode    string   `json:"mode"`
	Entries []string `json:"entries,omitempty"`
	Files   []string `json:"files,omitempty"`
}

type RulesConfig struct {
	Builtins bool     `json:"builtins"`
	Files    []string `json:"files"`
}

type LoggingConfig struct {
	AccessFile   string `json:"access_file"`
	SecurityFile string `json:"security_file"`
}

type ServerPool struct {
	Name        string            `json:"name"`
	Enabled     bool              `json:"enabled"`
	Algorithm   string            `json:"algorithm"`
	FailureMode string            `json:"failure_mode"`
	Members     []PoolMember      `json:"members"`
	HealthCheck HealthCheckConfig `json:"health_check"`
}

type PoolMember struct {
	ID        string          `json:"id"`
	URL       string          `json:"url"`
	Enabled   bool            `json:"enabled"`
	Weight    int             `json:"weight"`
	Priority  int             `json:"priority"`
	Backup    bool            `json:"backup"`
	OriginTLS OriginTLSConfig `json:"origin_tls,omitempty"`
}

type HealthCheckConfig struct {
	Enabled            bool   `json:"enabled"`
	Type               string `json:"type"`
	IntervalSeconds    int    `json:"interval_seconds"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
	HealthyThreshold   int    `json:"healthy_threshold"`
	UnhealthyThreshold int    `json:"unhealthy_threshold"`
	Method             string `json:"method"`
	Path               string `json:"path"`
	Host               string `json:"host,omitempty"`
	ExpectedStatusMin  int    `json:"expected_status_min"`
	ExpectedStatusMax  int    `json:"expected_status_max"`
}

type VirtualHost struct {
	Name            string            `json:"name"`
	Enabled         bool              `json:"enabled"`
	Domains         []string          `json:"domains"`
	Action          string            `json:"action,omitempty"`
	Upstream        string            `json:"upstream,omitempty"`
	ServerPool      string            `json:"server_pool,omitempty"`
	Redirect        RedirectConfig    `json:"redirect,omitempty"`
	DiscardStatus   int               `json:"discard_status,omitempty"`
	PreserveHost    bool              `json:"preserve_host"`
	FrontendTLS     FrontendTLSConfig `json:"frontend_tls"`
	OriginTLS       OriginTLSConfig   `json:"origin_tls"`
	Persistence     PersistenceConfig `json:"persistence,omitempty"`
	WAFPolicy       WAFPolicyConfig   `json:"waf_policy,omitempty"`
	BotPolicy       BotPolicyConfig   `json:"bot_policy,omitempty"`
	ContentRoutes   []ContentRoute    `json:"content_routes,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers"`
}

type RedirectConfig struct {
	URL    string `json:"url,omitempty"`
	Status int    `json:"status,omitempty"`
}

type PersistenceConfig struct {
	Mode       string `json:"mode,omitempty"`
	CookieName string `json:"cookie_name,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

type WAFPolicyConfig struct {
	Mode           string           `json:"mode,omitempty"`
	BlockThreshold int              `json:"block_threshold,omitempty"`
	MaxBodyBytes   int64            `json:"max_body_bytes,omitempty"`
	Builtins       *bool            `json:"builtins,omitempty"`
	RuleFiles      []string         `json:"rule_files,omitempty"`
	RateLimit      *RateLimitConfig `json:"rate_limit,omitempty"`
	FailMode       string           `json:"fail_mode,omitempty"`
	AllowCIDRs     []string         `json:"allow_cidrs,omitempty"`
	DenyCIDRs      []string         `json:"deny_cidrs,omitempty"`
}

type BotPolicyConfig struct {
	Enabled           bool     `json:"enabled"`
	Mode              string   `json:"mode,omitempty"`
	RequestsPerMinute float64  `json:"requests_per_minute,omitempty"`
	Burst             int      `json:"burst,omitempty"`
	BadUserAgents     []string `json:"bad_user_agents,omitempty"`
	AllowUserAgents   []string `json:"allow_user_agents,omitempty"`
}

type ContentRoute struct {
	Name          string   `json:"name"`
	Enabled       bool     `json:"enabled"`
	Pool          string   `json:"pool"`
	Methods       []string `json:"methods,omitempty"`
	PathPrefix    string   `json:"path_prefix,omitempty"`
	PathPattern   string   `json:"path_pattern,omitempty"`
	HeaderName    string   `json:"header_name,omitempty"`
	HeaderPattern string   `json:"header_pattern,omitempty"`
	QueryName     string   `json:"query_name,omitempty"`
	QueryPattern  string   `json:"query_pattern,omitempty"`
}

type FrontendTLSConfig struct {
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
}

type OriginTLSConfig struct {
	ServerName         string `json:"server_name"`
	CAFile             string `json:"ca_file"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var cfg Config
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}
	cfg.BaseDir = filepath.Dir(abs)
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Version == 0 {
		c.Version = CurrentVersion
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = ":80"
	}
	if c.HTTPS.Listen == "" {
		c.HTTPS.Listen = ":443"
	}
	if c.HTTPS.MinTLSVersion == "" {
		c.HTTPS.MinTLSVersion = "1.2"
	}
	if c.Admin.Listen == "" {
		c.Admin.Listen = "127.0.0.1:9090"
	}
	if c.Admin.TokenEnv == "" {
		c.Admin.TokenEnv = "CHERRYWAF_ADMIN_TOKEN"
	}
	if c.Security.Mode == "" {
		c.Security.Mode = "blocking"
	}
	if c.Security.BlockThreshold == 0 {
		c.Security.BlockThreshold = 10
	}
	if c.Security.MaxBodyBytes == 0 {
		c.Security.MaxBodyBytes = 1 << 20
	}
	if c.Security.MaxHeaderBytes == 0 {
		c.Security.MaxHeaderBytes = 1 << 20
	}
	if c.Security.ForwardedForHeader == "" {
		c.Security.ForwardedForHeader = "X-Forwarded-For"
	}
	if c.Security.RateLimit.RequestsPerSecond == 0 {
		c.Security.RateLimit.RequestsPerSecond = 50
	}
	if c.Security.RateLimit.Burst == 0 {
		c.Security.RateLimit.Burst = 100
	}
	if c.Security.RateLimit.EntryTTLSeconds == 0 {
		c.Security.RateLimit.EntryTTLSeconds = 600
	}
	if c.Security.Reputation.Mode == "" {
		c.Security.Reputation.Mode = "monitor"
	}
	if c.Logging.AccessFile == "" {
		c.Logging.AccessFile = "-"
	}
	if c.Logging.SecurityFile == "" {
		c.Logging.SecurityFile = "-"
	}

	for poolIndex := range c.ServerPools {
		pool := &c.ServerPools[poolIndex]
		pool.Name = strings.TrimSpace(pool.Name)
		if pool.Algorithm == "" {
			pool.Algorithm = "round_robin"
		}
		if pool.FailureMode == "" {
			pool.FailureMode = "reject"
		}
		if pool.HealthCheck.Type == "" {
			pool.HealthCheck.Type = "http"
		}
		if pool.HealthCheck.IntervalSeconds == 0 {
			pool.HealthCheck.IntervalSeconds = 10
		}
		if pool.HealthCheck.TimeoutSeconds == 0 {
			pool.HealthCheck.TimeoutSeconds = 3
		}
		if pool.HealthCheck.HealthyThreshold == 0 {
			pool.HealthCheck.HealthyThreshold = 2
		}
		if pool.HealthCheck.UnhealthyThreshold == 0 {
			pool.HealthCheck.UnhealthyThreshold = 3
		}
		if pool.HealthCheck.Method == "" {
			pool.HealthCheck.Method = "GET"
		}
		if pool.HealthCheck.Path == "" {
			pool.HealthCheck.Path = "/"
		}
		if pool.HealthCheck.ExpectedStatusMin == 0 {
			pool.HealthCheck.ExpectedStatusMin = 200
		}
		if pool.HealthCheck.ExpectedStatusMax == 0 {
			pool.HealthCheck.ExpectedStatusMax = 399
		}
		for memberIndex := range pool.Members {
			member := &pool.Members[memberIndex]
			member.ID = strings.TrimSpace(member.ID)
			if member.ID == "" {
				member.ID = "member-" + strconv.Itoa(memberIndex+1)
			}
			if member.Weight == 0 {
				member.Weight = 1
			}
			if member.Priority == 0 {
				member.Priority = 100
			}
		}
	}

	for i := range c.VirtualHosts {
		vhost := &c.VirtualHosts[i]
		vhost.Name = strings.TrimSpace(vhost.Name)
		if vhost.Action == "" {
			vhost.Action = "group"
		}
		if vhost.Redirect.Status == 0 {
			vhost.Redirect.Status = 302
		}
		if vhost.DiscardStatus == 0 {
			vhost.DiscardStatus = 403
		}
		if vhost.Persistence.Mode == "" {
			vhost.Persistence.Mode = "none"
		}
		if vhost.Persistence.CookieName == "" {
			vhost.Persistence.CookieName = "CWAF_ROUTE"
		}
		if vhost.Persistence.TTLSeconds == 0 {
			vhost.Persistence.TTLSeconds = 3600
		}
		if vhost.WAFPolicy.Mode == "" {
			vhost.WAFPolicy.Mode = "inherit"
		}
		if vhost.WAFPolicy.FailMode == "" {
			vhost.WAFPolicy.FailMode = "closed"
		}
		if vhost.BotPolicy.Mode == "" {
			vhost.BotPolicy.Mode = "monitor"
		}
		if vhost.BotPolicy.Enabled && vhost.BotPolicy.RequestsPerMinute == 0 {
			vhost.BotPolicy.RequestsPerMinute = 300
		}
		if vhost.BotPolicy.Enabled && vhost.BotPolicy.Burst == 0 {
			vhost.BotPolicy.Burst = 60
		}
	}
}

func (c *Config) Validate() error {
	var errs []error

	if c.Version != CurrentVersion {
		errs = append(errs, fmt.Errorf("unsupported config version %d; expected %d", c.Version, CurrentVersion))
	}
	if !c.HTTP.Enabled && !c.HTTPS.Enabled {
		errs = append(errs, errors.New("at least one of http.enabled or https.enabled must be true"))
	}
	if c.HTTP.Enabled {
		if err := validateListen(c.HTTP.Listen); err != nil {
			errs = append(errs, fmt.Errorf("http.listen: %w", err))
		}
	}
	if c.HTTPS.Enabled {
		if err := validateListen(c.HTTPS.Listen); err != nil {
			errs = append(errs, fmt.Errorf("https.listen: %w", err))
		}
		if c.HTTPS.MinTLSVersion != "1.2" && c.HTTPS.MinTLSVersion != "1.3" {
			errs = append(errs, errors.New("https.min_tls_version must be \"1.2\" or \"1.3\""))
		}
	}
	if c.HTTP.RedirectToHTTPS && !c.HTTPS.Enabled {
		errs = append(errs, errors.New("http.redirect_to_https requires https.enabled=true"))
	}
	if c.Admin.Enabled {
		if err := validateListen(c.Admin.Listen); err != nil {
			errs = append(errs, fmt.Errorf("admin.listen: %w", err))
		}
		if !c.Admin.AllowPublic && !isLoopbackListen(c.Admin.Listen) {
			errs = append(errs, errors.New("admin.listen must use a loopback address unless admin.allow_public=true"))
		}
		if c.Admin.TokenEnv == "" {
			errs = append(errs, errors.New("admin.token_env must not be empty"))
		}
	}
	if c.Security.Mode != "blocking" && c.Security.Mode != "detect" {
		errs = append(errs, errors.New("security.mode must be \"blocking\" or \"detect\""))
	}
	if c.Security.BlockThreshold < 1 || c.Security.BlockThreshold > 1000 {
		errs = append(errs, errors.New("security.block_threshold must be between 1 and 1000"))
	}
	if c.Security.MaxBodyBytes < 1024 || c.Security.MaxBodyBytes > 128<<20 {
		errs = append(errs, errors.New("security.max_body_bytes must be between 1024 and 134217728"))
	}
	if c.Security.MaxHeaderBytes < 8192 || c.Security.MaxHeaderBytes > 16<<20 {
		errs = append(errs, errors.New("security.max_header_bytes must be between 8192 and 16777216"))
	}
	if c.Security.RateLimit.Enabled {
		if err := validateRateLimit(c.Security.RateLimit, "security.rate_limit"); err != nil {
			errs = append(errs, err)
		}
	}
	if !validHeaderName(c.Security.ForwardedForHeader) {
		errs = append(errs, errors.New("security.forwarded_for_header must be a valid HTTP header name"))
	}
	for _, cidr := range c.Security.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			errs = append(errs, fmt.Errorf("security.trusted_proxies contains invalid CIDR %q", cidr))
		}
	}
	if c.Security.Reputation.Mode != "monitor" && c.Security.Reputation.Mode != "block" {
		errs = append(errs, errors.New("security.reputation.mode must be \"monitor\" or \"block\""))
	}
	for _, entry := range c.Security.Reputation.Entries {
		if err := validateReputationEntry(entry); err != nil {
			errs = append(errs, fmt.Errorf("security.reputation entry %q: %w", entry, err))
		}
	}
	for _, path := range c.Security.Reputation.Files {
		if strings.TrimSpace(path) == "" {
			errs = append(errs, errors.New("security.reputation.files must not contain empty paths"))
		}
	}

	poolNames := make(map[string]struct{})
	for i := range c.ServerPools {
		pool := &c.ServerPools[i]
		if pool.Name == "" {
			errs = append(errs, fmt.Errorf("server_pools[%d].name must not be empty", i))
		} else if _, exists := poolNames[pool.Name]; exists {
			errs = append(errs, fmt.Errorf("duplicate server pool name %q", pool.Name))
		} else {
			poolNames[pool.Name] = struct{}{}
		}
		switch pool.Algorithm {
		case "round_robin", "weighted_round_robin", "least_connections", "source_ip_hash", "primary_backup", "random":
		default:
			errs = append(errs, fmt.Errorf("server pool %q uses unsupported algorithm %q", pool.Name, pool.Algorithm))
		}
		if pool.FailureMode != "reject" && pool.FailureMode != "last_resort" {
			errs = append(errs, fmt.Errorf("server pool %q failure_mode must be reject or last_resort", pool.Name))
		}
		if pool.Enabled && len(pool.Members) == 0 {
			errs = append(errs, fmt.Errorf("server pool %q must contain at least one member", pool.Name))
		}
		seenMembers := make(map[string]struct{})
		enabledMembers := 0
		for memberIndex := range pool.Members {
			member := &pool.Members[memberIndex]
			if member.ID == "" {
				errs = append(errs, fmt.Errorf("server pool %q member %d ID must not be empty", pool.Name, memberIndex))
			} else if _, exists := seenMembers[member.ID]; exists {
				errs = append(errs, fmt.Errorf("server pool %q contains duplicate member ID %q", pool.Name, member.ID))
			} else {
				seenMembers[member.ID] = struct{}{}
			}
			u, err := validateUpstreamURL(member.URL)
			if err != nil {
				errs = append(errs, fmt.Errorf("server pool %q member %q: %w", pool.Name, member.ID, err))
			} else if u.Scheme == "http" && hasOriginTLS(member.OriginTLS) {
				errs = append(errs, fmt.Errorf("server pool %q member %q defines origin_tls for a plain HTTP URL", pool.Name, member.ID))
			}
			if member.Weight < 1 || member.Weight > 1000 {
				errs = append(errs, fmt.Errorf("server pool %q member %q weight must be between 1 and 1000", pool.Name, member.ID))
			}
			if member.Priority < 1 || member.Priority > 1000 {
				errs = append(errs, fmt.Errorf("server pool %q member %q priority must be between 1 and 1000", pool.Name, member.ID))
			}
			if member.Enabled {
				enabledMembers++
			}
		}
		if pool.Enabled && enabledMembers == 0 {
			errs = append(errs, fmt.Errorf("server pool %q must contain at least one enabled member", pool.Name))
		}
		if pool.HealthCheck.Enabled {
			if err := validateHealthCheck(pool.HealthCheck); err != nil {
				errs = append(errs, fmt.Errorf("server pool %q health_check: %w", pool.Name, err))
			}
		}
	}

	seenNames := make(map[string]struct{})
	seenDomains := make(map[string]string)
	for i := range c.VirtualHosts {
		v := &c.VirtualHosts[i]
		v.Name = strings.TrimSpace(v.Name)
		if v.Name == "" {
			errs = append(errs, fmt.Errorf("virtual_hosts[%d].name must not be empty", i))
		} else if _, ok := seenNames[v.Name]; ok {
			errs = append(errs, fmt.Errorf("duplicate virtual host name %q", v.Name))
		} else {
			seenNames[v.Name] = struct{}{}
		}
		if !v.Enabled {
			continue
		}
		if len(v.Domains) == 0 {
			errs = append(errs, fmt.Errorf("virtual host %q must contain at least one domain", v.Name))
		}
		for j, domain := range v.Domains {
			domain = NormalizeDomain(domain)
			v.Domains[j] = domain
			if err := ValidateDomainPattern(domain); err != nil {
				errs = append(errs, fmt.Errorf("virtual host %q domain %q: %w", v.Name, domain, err))
				continue
			}
			if owner, ok := seenDomains[domain]; ok {
				errs = append(errs, fmt.Errorf("domain %q is assigned to both %q and %q", domain, owner, v.Name))
			} else {
				seenDomains[domain] = v.Name
			}
		}

		switch v.Action {
		case "group":
			if strings.TrimSpace(v.ServerPool) != "" && strings.TrimSpace(v.Upstream) != "" {
				errs = append(errs, fmt.Errorf("virtual host %q must use either server_pool or upstream, not both", v.Name))
			} else if v.ServerPool != "" {
				if _, exists := poolNames[v.ServerPool]; !exists {
					errs = append(errs, fmt.Errorf("virtual host %q references unknown server pool %q", v.Name, v.ServerPool))
				} else if pool := c.ServerPoolByName(v.ServerPool); pool == nil || !pool.Enabled {
					errs = append(errs, fmt.Errorf("virtual host %q references disabled server pool %q", v.Name, v.ServerPool))
				}
			} else {
				u, err := validateUpstreamURL(v.Upstream)
				if err != nil {
					errs = append(errs, fmt.Errorf("virtual host %q upstream: %w", v.Name, err))
				} else if u.Scheme == "http" && hasOriginTLS(v.OriginTLS) {
					errs = append(errs, fmt.Errorf("virtual host %q defines origin_tls options for a plain HTTP upstream", v.Name))
				}
			}
		case "redirect":
			if err := validateRedirect(v.Redirect); err != nil {
				errs = append(errs, fmt.Errorf("virtual host %q redirect: %w", v.Name, err))
			}
		case "discard":
			if v.DiscardStatus < 400 || v.DiscardStatus > 599 {
				errs = append(errs, fmt.Errorf("virtual host %q discard_status must be between 400 and 599", v.Name))
			}
		default:
			errs = append(errs, fmt.Errorf("virtual host %q action must be group, redirect, or discard", v.Name))
		}

		if c.HTTPS.Enabled {
			if strings.TrimSpace(v.FrontendTLS.CertificateFile) == "" || strings.TrimSpace(v.FrontendTLS.PrivateKeyFile) == "" {
				errs = append(errs, fmt.Errorf("virtual host %q requires frontend_tls certificate and private key while HTTPS is enabled", v.Name))
			}
		}
		if err := validatePersistence(v.Persistence); err != nil {
			errs = append(errs, fmt.Errorf("virtual host %q persistence: %w", v.Name, err))
		}
		if err := validateWAFPolicy(v.WAFPolicy); err != nil {
			errs = append(errs, fmt.Errorf("virtual host %q waf_policy: %w", v.Name, err))
		}
		if err := validateBotPolicy(v.BotPolicy); err != nil {
			errs = append(errs, fmt.Errorf("virtual host %q bot_policy: %w", v.Name, err))
		}
		if err := validateContentRoutes(c, v, poolNames); err != nil {
			errs = append(errs, err)
		}
		for header, value := range v.RequestHeaders {
			if !validHeaderName(header) {
				errs = append(errs, fmt.Errorf("virtual host %q request header %q is not a valid HTTP header name", v.Name, header))
				continue
			}
			if forbiddenRequestHeader(header) {
				errs = append(errs, fmt.Errorf("virtual host %q request header %q is managed by the HTTP transport and cannot be overridden", v.Name, header))
			}
			if !validHeaderValue(value) {
				errs = append(errs, fmt.Errorf("virtual host %q request header %q contains an invalid value", v.Name, header))
			}
		}
		for header, value := range v.ResponseHeaders {
			if !validHeaderName(header) {
				errs = append(errs, fmt.Errorf("virtual host %q response header %q is not a valid HTTP header name", v.Name, header))
				continue
			}
			if forbiddenResponseHeader(header) {
				errs = append(errs, fmt.Errorf("virtual host %q response header %q is managed by the HTTP transport and cannot be overridden", v.Name, header))
			}
			if !validHeaderValue(value) {
				errs = append(errs, fmt.Errorf("virtual host %q response header %q contains an invalid value", v.Name, header))
			}
		}
	}

	if c.HTTPS.Enabled && len(seenDomains) == 0 {
		errs = append(errs, errors.New("https.enabled requires at least one enabled virtual host with a certificate"))
	}

	return errors.Join(errs...)
}

func validateRateLimit(value RateLimitConfig, prefix string) error {
	var errs []error
	if value.RequestsPerSecond <= 0 {
		errs = append(errs, fmt.Errorf("%s.requests_per_second must be greater than zero", prefix))
	}
	if value.Burst < 1 {
		errs = append(errs, fmt.Errorf("%s.burst must be at least one", prefix))
	}
	if value.EntryTTLSeconds < 30 {
		errs = append(errs, fmt.Errorf("%s.entry_ttl_seconds must be at least 30", prefix))
	}
	return errors.Join(errs...)
}

func validateHealthCheck(value HealthCheckConfig) error {
	var errs []error
	if value.Type != "http" && value.Type != "tcp" {
		errs = append(errs, errors.New("type must be http or tcp"))
	}
	if value.IntervalSeconds < 2 || value.IntervalSeconds > 3600 {
		errs = append(errs, errors.New("interval_seconds must be between 2 and 3600"))
	}
	if value.TimeoutSeconds < 1 || value.TimeoutSeconds > 60 {
		errs = append(errs, errors.New("timeout_seconds must be between 1 and 60"))
	}
	if value.HealthyThreshold < 1 || value.HealthyThreshold > 20 {
		errs = append(errs, errors.New("healthy_threshold must be between 1 and 20"))
	}
	if value.UnhealthyThreshold < 1 || value.UnhealthyThreshold > 20 {
		errs = append(errs, errors.New("unhealthy_threshold must be between 1 and 20"))
	}
	if value.Type == "http" {
		if value.Path == "" || !strings.HasPrefix(value.Path, "/") {
			errs = append(errs, errors.New("path must begin with / for HTTP health checks"))
		}
		method := strings.ToUpper(strings.TrimSpace(value.Method))
		if method != "GET" && method != "HEAD" {
			errs = append(errs, errors.New("method must be GET or HEAD"))
		}
		if value.ExpectedStatusMin < 100 || value.ExpectedStatusMin > 599 || value.ExpectedStatusMax < value.ExpectedStatusMin || value.ExpectedStatusMax > 599 {
			errs = append(errs, errors.New("expected status range must be within 100..599"))
		}
	}
	return errors.Join(errs...)
}

func validatePersistence(value PersistenceConfig) error {
	switch value.Mode {
	case "none", "source_ip", "cookie":
	default:
		return errors.New("mode must be none, source_ip, or cookie")
	}
	if value.Mode == "cookie" {
		if !validCookieName(value.CookieName) {
			return errors.New("cookie_name is not a valid cookie name")
		}
		if value.TTLSeconds < 60 || value.TTLSeconds > 30*24*60*60 {
			return errors.New("ttl_seconds must be between 60 and 2592000")
		}
	}
	return nil
}

func validateWAFPolicy(value WAFPolicyConfig) error {
	var errs []error
	switch value.Mode {
	case "inherit", "detect", "blocking", "disabled":
	default:
		errs = append(errs, errors.New("mode must be inherit, detect, blocking, or disabled"))
	}
	if value.BlockThreshold != 0 && (value.BlockThreshold < 1 || value.BlockThreshold > 1000) {
		errs = append(errs, errors.New("block_threshold must be zero or between 1 and 1000"))
	}
	if value.MaxBodyBytes != 0 && (value.MaxBodyBytes < 1024 || value.MaxBodyBytes > 128<<20) {
		errs = append(errs, errors.New("max_body_bytes must be zero or between 1024 and 134217728"))
	}
	if value.FailMode != "closed" && value.FailMode != "open" {
		errs = append(errs, errors.New("fail_mode must be closed or open"))
	}
	if value.RateLimit != nil && value.RateLimit.Enabled {
		if err := validateRateLimit(*value.RateLimit, "waf_policy.rate_limit"); err != nil {
			errs = append(errs, err)
		}
	}
	for _, cidr := range append(append([]string(nil), value.AllowCIDRs...), value.DenyCIDRs...) {
		if err := validateIPOrCIDR(cidr); err != nil {
			errs = append(errs, fmt.Errorf("invalid access CIDR %q: %w", cidr, err))
		}
	}
	for _, path := range value.RuleFiles {
		if strings.TrimSpace(path) == "" {
			errs = append(errs, errors.New("rule_files must not contain empty paths"))
		}
	}
	return errors.Join(errs...)
}

func validateBotPolicy(value BotPolicyConfig) error {
	if !value.Enabled {
		return nil
	}
	var errs []error
	if value.Mode != "monitor" && value.Mode != "block" {
		errs = append(errs, errors.New("mode must be monitor or block"))
	}
	if value.RequestsPerMinute <= 0 || value.RequestsPerMinute > 1_000_000 {
		errs = append(errs, errors.New("requests_per_minute must be greater than zero and at most 1000000"))
	}
	if value.Burst < 1 || value.Burst > 1_000_000 {
		errs = append(errs, errors.New("burst must be between 1 and 1000000"))
	}
	for _, pattern := range append(append([]string(nil), value.BadUserAgents...), value.AllowUserAgents...) {
		if len(pattern) == 0 || len(pattern) > 4096 {
			errs = append(errs, errors.New("user-agent patterns must be between 1 and 4096 bytes"))
			continue
		}
		if _, err := regexp.Compile(pattern); err != nil {
			errs = append(errs, fmt.Errorf("compile user-agent pattern %q: %w", pattern, err))
		}
	}
	return errors.Join(errs...)
}

func validateContentRoutes(cfg *Config, vhost *VirtualHost, poolNames map[string]struct{}) error {
	if len(vhost.ContentRoutes) == 0 {
		return nil
	}
	if vhost.Action != "group" {
		return fmt.Errorf("virtual host %q content_routes require action=group", vhost.Name)
	}
	var errs []error
	seen := make(map[string]struct{})
	for i, route := range vhost.ContentRoutes {
		if !route.Enabled {
			continue
		}
		if strings.TrimSpace(route.Name) == "" {
			errs = append(errs, fmt.Errorf("virtual host %q content route %d name must not be empty", vhost.Name, i))
		} else if _, exists := seen[route.Name]; exists {
			errs = append(errs, fmt.Errorf("virtual host %q contains duplicate content route name %q", vhost.Name, route.Name))
		} else {
			seen[route.Name] = struct{}{}
		}
		if _, exists := poolNames[route.Pool]; !exists {
			errs = append(errs, fmt.Errorf("virtual host %q content route %q references unknown pool %q", vhost.Name, route.Name, route.Pool))
		} else if pool := cfg.ServerPoolByName(route.Pool); pool == nil || !pool.Enabled {
			errs = append(errs, fmt.Errorf("virtual host %q content route %q references disabled pool %q", vhost.Name, route.Name, route.Pool))
		}
		conditionCount := 0
		for _, method := range route.Methods {
			if !validMethod(method) {
				errs = append(errs, fmt.Errorf("virtual host %q content route %q has invalid method %q", vhost.Name, route.Name, method))
			}
		}
		if len(route.Methods) > 0 {
			conditionCount++
		}
		if route.PathPrefix != "" {
			if !strings.HasPrefix(route.PathPrefix, "/") {
				errs = append(errs, fmt.Errorf("virtual host %q content route %q path_prefix must begin with /", vhost.Name, route.Name))
			}
			conditionCount++
		}
		if route.PathPattern != "" {
			if _, err := regexp.Compile(route.PathPattern); err != nil {
				errs = append(errs, fmt.Errorf("virtual host %q content route %q path_pattern: %w", vhost.Name, route.Name, err))
			}
			conditionCount++
		}
		if route.HeaderName != "" || route.HeaderPattern != "" {
			if !validHeaderName(route.HeaderName) || route.HeaderPattern == "" {
				errs = append(errs, fmt.Errorf("virtual host %q content route %q requires a valid header_name and header_pattern", vhost.Name, route.Name))
			} else if _, err := regexp.Compile(route.HeaderPattern); err != nil {
				errs = append(errs, fmt.Errorf("virtual host %q content route %q header_pattern: %w", vhost.Name, route.Name, err))
			}
			conditionCount++
		}
		if route.QueryName != "" || route.QueryPattern != "" {
			if strings.TrimSpace(route.QueryName) == "" || route.QueryPattern == "" {
				errs = append(errs, fmt.Errorf("virtual host %q content route %q requires query_name and query_pattern", vhost.Name, route.Name))
			} else if _, err := regexp.Compile(route.QueryPattern); err != nil {
				errs = append(errs, fmt.Errorf("virtual host %q content route %q query_pattern: %w", vhost.Name, route.Name, err))
			}
			conditionCount++
		}
		if conditionCount == 0 {
			errs = append(errs, fmt.Errorf("virtual host %q content route %q must define at least one match condition", vhost.Name, route.Name))
		}
	}
	return errors.Join(errs...)
}

func validateRedirect(value RedirectConfig) error {
	if strings.ContainsAny(value.URL, "\r\n") {
		return errors.New("url must not contain line breaks")
	}
	if strings.TrimSpace(value.URL) == "" {
		return errors.New("url must not be empty")
	}
	candidate := strings.NewReplacer(
		"{host}", "example.test",
		"{request_uri}", "/request/path?query=1",
		"{path}", "/request/path",
		"{query}", "query=1",
	).Replace(value.URL)
	if !strings.HasPrefix(candidate, "/") {
		u, err := url.Parse(candidate)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("url must be an absolute HTTP/HTTPS URL or begin with /")
		}
	}
	switch value.Status {
	case 301, 302, 303, 307, 308:
		return nil
	default:
		return errors.New("status must be 301, 302, 303, 307, or 308")
	}
}

func validateUpstreamURL(value string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("must be an absolute http or https URL")
	}
	if u.User != nil {
		return nil, errors.New("must not contain embedded credentials")
	}
	if u.Fragment != "" {
		return nil, errors.New("must not contain a URL fragment")
	}
	return u, nil
}

func hasOriginTLS(value OriginTLSConfig) bool {
	return value.CAFile != "" || value.ServerName != "" || value.InsecureSkipVerify
}

func validateReputationEntry(value string) error {
	value = strings.TrimSpace(value)
	if cut, _, ok := strings.Cut(value, "#"); ok {
		value = strings.TrimSpace(cut)
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return errors.New("entry must not be empty")
	}
	return validateIPOrCIDR(fields[0])
}

func validateIPOrCIDR(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value must not be empty")
	}
	if strings.Contains(value, "/") {
		if _, _, err := net.ParseCIDR(value); err != nil {
			return err
		}
		return nil
	}
	if net.ParseIP(value) == nil {
		return errors.New("must be an IP address or CIDR")
	}
	return nil
}

func (c *Config) ResolvePath(path string) string {
	if path == "" || path == "-" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(c.BaseDir, path)
}

func (c *Config) EnabledVirtualHosts() []VirtualHost {
	out := make([]VirtualHost, 0, len(c.VirtualHosts))
	for _, v := range c.VirtualHosts {
		if v.Enabled {
			out = append(out, v)
		}
	}
	return out
}

func (c *Config) DomainNames() []string {
	names := make([]string, 0)
	for _, v := range c.VirtualHosts {
		if v.Enabled {
			names = append(names, v.Domains...)
		}
	}
	sort.Strings(names)
	return names
}

func (c *Config) ServerPoolByName(name string) *ServerPool {
	for i := range c.ServerPools {
		if c.ServerPools[i].Name == name {
			return &c.ServerPools[i]
		}
	}
	return nil
}

func validateListen(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("listen address must not be empty")
	}
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("must be in host:port form: %w", err)
	}
	if port == "" {
		return errors.New("port must not be empty")
	}
	return nil
}

func isLoopbackListen(value string) bool {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NormalizeDomain canonicalizes a configured DNS name for routing and SNI.
func NormalizeDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

// ValidateDomainPattern accepts a concrete DNS/IP name or a one-label wildcard.
// Internationalized domains must be supplied in their ASCII/Punycode form.
func ValidateDomainPattern(value string) error {
	value = NormalizeDomain(value)
	if value == "" {
		return errors.New("domain must not be empty")
	}
	if len(value) > 253 {
		return errors.New("domain is longer than 253 bytes")
	}
	if value == "localhost" || net.ParseIP(value) != nil {
		return nil
	}
	if strings.HasPrefix(value, "*.") {
		value = strings.TrimPrefix(value, "*.")
		if strings.Contains(value, "*") {
			return errors.New("wildcard is only allowed as the complete left-most label")
		}
	} else if strings.Contains(value, "*") {
		return errors.New("wildcard is only allowed as the complete left-most label")
	}
	if !strings.Contains(value, ".") {
		return errors.New("domain must contain a dot or be localhost")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("domain contains an empty or overlong label")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("domain labels must not begin or end with a hyphen")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return errors.New("domain must use ASCII letters, digits, dots, and hyphens")
		}
	}
	return nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func validMethod(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return true
}

func validCookieName(value string) bool { return validMethod(value) }

func validHeaderName(value string) bool {
	return validMethod(value)
}

func validHeaderValue(value string) bool {
	if len(value) > 8192 || strings.ContainsAny(value, "\r\n") {
		return false
	}
	for _, r := range value {
		if r == '\t' || r >= 0x20 {
			continue
		}
		return false
	}
	return true
}

func forbiddenRequestHeader(value string) bool {
	switch strings.ToLower(value) {
	case "connection", "content-length", "cookie", "forwarded", "host", "keep-alive", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto":
		return true
	default:
		return false
	}
}

func forbiddenResponseHeader(value string) bool {
	switch strings.ToLower(value) {
	case "connection", "content-length", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}
