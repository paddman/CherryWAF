package certstore

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/paddman/CherryWAF/internal/config"
)

type Store struct {
	exact    map[string]*tls.Certificate
	wildcard map[string]*tls.Certificate
	fallback *tls.Certificate
	info     []Info
}

type Info struct {
	VirtualHost string    `json:"virtual_host"`
	Domains     []string  `json:"domains"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysLeft    int       `json:"days_left"`
}

func Load(cfg *config.Config, now time.Time) (*Store, error) {
	store := &Store{exact: make(map[string]*tls.Certificate), wildcard: make(map[string]*tls.Certificate)}
	for _, vhost := range cfg.EnabledVirtualHosts() {
		certFile := cfg.ResolvePath(vhost.FrontendTLS.CertificateFile)
		keyFile := cfg.ResolvePath(vhost.FrontendTLS.PrivateKeyFile)
		pair, leaf, err := loadAndValidatePair(certFile, keyFile, now)
		if err != nil {
			return nil, fmt.Errorf("virtual host %q: %w", vhost.Name, err)
		}
		for _, domain := range vhost.Domains {
			if err := VerifyDomain(leaf, domain); err != nil {
				return nil, fmt.Errorf("virtual host %q certificate does not cover %q: %w", vhost.Name, domain, err)
			}
			if strings.HasPrefix(domain, "*.") {
				store.wildcard[strings.TrimPrefix(domain, "*.")] = pair
			} else {
				store.exact[domain] = pair
			}
		}
		if store.fallback == nil {
			store.fallback = pair
		}
		store.info = append(store.info, Info{
			VirtualHost: vhost.Name, Domains: append([]string(nil), vhost.Domains...),
			Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(), Serial: leaf.SerialNumber.String(),
			NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
			DaysLeft: int(leaf.NotAfter.Sub(now).Hours() / 24),
		})
	}
	if cfg.HTTPS.Enabled && store.fallback == nil {
		return nil, errors.New("HTTPS is enabled but no certificate was loaded")
	}
	sort.Slice(store.info, func(i, j int) bool { return store.info[i].VirtualHost < store.info[j].VirtualHost })
	return store, nil
}

func (s *Store) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s == nil {
		return nil, errors.New("certificate store is not initialized")
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hello.ServerName)), ".")
	if cert := s.exact[host]; cert != nil {
		return cert, nil
	}
	for suffix, cert := range s.wildcard {
		needle := "." + suffix
		if !strings.HasSuffix(host, needle) {
			continue
		}
		left := strings.TrimSuffix(host, needle)
		if left != "" && !strings.Contains(left, ".") {
			return cert, nil
		}
	}
	if host == "" && s.fallback != nil {
		return s.fallback, nil
	}
	return nil, fmt.Errorf("no TLS certificate configured for SNI name %q", host)
}

func (s *Store) Info() []Info {
	if s == nil {
		return nil
	}
	out := make([]Info, len(s.info))
	copy(out, s.info)
	return out
}

func ValidatePair(certFile, keyFile string, now time.Time) (Info, error) {
	_, leaf, err := loadAndValidatePair(certFile, keyFile, now)
	if err != nil {
		return Info{}, err
	}
	return Info{
		Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(), Serial: leaf.SerialNumber.String(),
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
		DaysLeft: int(leaf.NotAfter.Sub(now).Hours() / 24),
	}, nil
}

func loadAndValidatePair(certFile, keyFile string, now time.Time) (*tls.Certificate, *x509.Certificate, error) {
	if certFile == "" || keyFile == "" {
		return nil, nil, errors.New("certificate and private key paths are required")
	}
	if err := validatePrivateKeyPermissions(keyFile); err != nil {
		return nil, nil, err
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load certificate pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, nil, errors.New("certificate file contains no certificates")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf certificate: %w", err)
	}
	pair.Leaf = leaf
	if now.Before(leaf.NotBefore) {
		return nil, nil, fmt.Errorf("certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return nil, nil, fmt.Errorf("certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return &pair, leaf, nil
}

func validatePrivateKeyPermissions(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat private key: %w", err)
	}
	perm := info.Mode().Perm()
	if perm&0o007 != 0 || perm&0o030 != 0 {
		return fmt.Errorf("private key %s permissions are %04o; expected 0600, 0640, or stricter without group write/world access", path, perm)
	}
	return nil
}

// VerifyDomain checks an exact DNS name or a configured one-label wildcard.
// x509.VerifyHostname expects a concrete reference name, so wildcard policies
// are validated with a synthetic single-label host beneath the suffix.
func VerifyDomain(leaf *x509.Certificate, domain string) error {
	if leaf == nil {
		return errors.New("certificate is nil")
	}
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if strings.HasPrefix(domain, "*.") {
		suffix := strings.TrimPrefix(domain, "*.")
		if suffix == "" || strings.Contains(suffix, "*") {
			return fmt.Errorf("invalid wildcard domain %q", domain)
		}
		domain = "cherrywaf-validation." + suffix
	}
	return leaf.VerifyHostname(domain)
}

// ParseLeafCertificate is used by the control utility when it needs to inspect
// a PEM certificate before placing it in the appliance certificate store.
func ParseLeafCertificate(certPEM []byte) (*x509.Certificate, error) {
	for {
		block, rest := pem.Decode(certPEM)
		if block == nil {
			return nil, errors.New("certificate PEM block not found")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		certPEM = rest
	}
}
