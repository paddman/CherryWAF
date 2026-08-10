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
	"sort"
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
	Mode               string          `json:"mode"`
	BlockThreshold     int             `json:"block_threshold"`
	MaxBodyBytes       int64           `json:"max_body_bytes"`
	MaxHeaderBytes     int             `json:"max_header_bytes"`
	TrustedProxies     []string        `json:"trusted_proxies"`
	ForwardedForHeader string          `json:"forwarded_for_header"`
	RateLimit          RateLimitConfig `json:"rate_limit"`
}

type RateLimitConfig struct {
	Enabled           bool    `json:"enabled"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	Burst             int     `json:"burst"`
	EntryTTLSeconds   int     `json:"entry_ttl_seconds"`
}

type RulesConfig struct {
	Builtins bool     `json:"builtins"`
	Files    []string `json:"files"`
}

type LoggingConfig struct {
	AccessFile   string `json:"access_file"`
	SecurityFile string `json:"security_file"`
}

type VirtualHost struct {
	Name            string            `json:"name"`
	Enabled         bool              `json:"enabled"`
	Domains         []string          `json:"domains"`
	Upstream        string            `json:"upstream"`
	PreserveHost    bool              `json:"preserve_host"`
	FrontendTLS     FrontendTLSConfig `json:"frontend_tls"`
	OriginTLS       OriginTLSConfig   `json:"origin_tls"`
	ResponseHeaders map[string]string `json:"response_headers"`
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
	if c.Logging.AccessFile == "" {
		c.Logging.AccessFile = "-"
	}
	if c.Logging.SecurityFile == "" {
		c.Logging.SecurityFile = "-"
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
		if c.Security.RateLimit.RequestsPerSecond <= 0 {
			errs = append(errs, errors.New("security.rate_limit.requests_per_second must be greater than zero"))
		}
		if c.Security.RateLimit.Burst < 1 {
			errs = append(errs, errors.New("security.rate_limit.burst must be at least one"))
		}
		if c.Security.RateLimit.EntryTTLSeconds < 30 {
			errs = append(errs, errors.New("security.rate_limit.entry_ttl_seconds must be at least 30"))
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
		u, err := url.Parse(v.Upstream)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			errs = append(errs, fmt.Errorf("virtual host %q upstream must be an absolute http or https URL", v.Name))
		}
		if c.HTTPS.Enabled {
			if strings.TrimSpace(v.FrontendTLS.CertificateFile) == "" || strings.TrimSpace(v.FrontendTLS.PrivateKeyFile) == "" {
				errs = append(errs, fmt.Errorf("virtual host %q requires frontend_tls certificate and private key while HTTPS is enabled", v.Name))
			}
		}
		if u != nil && u.Scheme == "http" && (v.OriginTLS.CAFile != "" || v.OriginTLS.ServerName != "" || v.OriginTLS.InsecureSkipVerify) {
			errs = append(errs, fmt.Errorf("virtual host %q defines origin_tls options for a plain HTTP upstream", v.Name))
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
	if value == "localhost" {
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

func validHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", r) {
			continue
		}
		return false
	}
	return true
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

func forbiddenResponseHeader(value string) bool {
	switch strings.ToLower(value) {
	case "connection", "content-length", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}
