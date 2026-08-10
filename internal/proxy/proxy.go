package proxy

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/paddman/CherryWAF/internal/config"
	"github.com/paddman/CherryWAF/internal/metrics"
)

type Backend struct {
	proxy     *httputil.ReverseProxy
	transport *http.Transport
	upstream  string
}

func New(vhost config.VirtualHost, cfg *config.Config, metric *metrics.Metrics) (*Backend, error) {
	target, err := url.Parse(vhost.Upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream: %w", err)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Never inherit HTTP_PROXY/HTTPS_PROXY for protected origins. An appliance
	// must connect to the configured upstream directly unless an explicit,
	// audited egress-proxy feature is introduced later.
	transport.Proxy = nil
	transport.MaxIdleConns = 512
	transport.MaxIdleConnsPerHost = 128
	transport.IdleConnTimeout = 90 * time.Second
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.ExpectContinueTimeout = time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	transport.ForceAttemptHTTP2 = true

	if target.Scheme == "https" {
		tlsConfig := &tls.Config{
			MinVersion:         tls.VersionTLS12,
			ServerName:         vhost.OriginTLS.ServerName,
			InsecureSkipVerify: vhost.OriginTLS.InsecureSkipVerify, // Explicit opt-in; never enabled by default.
		}
		if vhost.OriginTLS.CAFile != "" {
			pool, err := loadCAPool(cfg.ResolvePath(vhost.OriginTLS.CAFile))
			if err != nil {
				return nil, err
			}
			tlsConfig.RootCAs = pool
		}
		transport.TLSClientConfig = tlsConfig
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Director = nil
	rp.Rewrite = func(req *httputil.ProxyRequest) {
		req.SetURL(target)
		if vhost.PreserveHost {
			req.Out.Host = req.In.Host
		}
		// Rewrite mode strips all client-provided forwarding headers before
		// this callback. SetXForwarded then emits only the client identity that
		// CherryWAF already resolved through its trusted-proxy policy.
		req.SetXForwarded()
		req.Out.Header.Set("X-CherryWAF", "1")
		if req.Out.Header.Get("X-Request-ID") == "" {
			req.Out.Header.Set("X-Request-ID", NewRequestID())
		}
	}
	rp.Transport = transport
	rp.FlushInterval = 100 * time.Millisecond
	rp.ModifyResponse = func(resp *http.Response) error {
		for key, value := range vhost.ResponseHeaders {
			resp.Header.Set(key, value)
		}
		resp.Header.Set("Via", "CherryWAF")
		return nil
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, proxyErr error) {
		metric.UpstreamError()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "upstream unavailable", "request_id": r.Header.Get("X-Request-ID"),
		})
	}

	return &Backend{proxy: rp, transport: transport, upstream: target.Redacted()}, nil
}

func (b *Backend) ServeHTTP(w http.ResponseWriter, r *http.Request, clientIP string) {
	request := r.Clone(r.Context())
	if ip := net.ParseIP(clientIP); ip != nil {
		request.RemoteAddr = net.JoinHostPort(ip.String(), "0")
	}
	b.proxy.ServeHTTP(w, request)
}

func (b *Backend) Upstream() string { return b.upstream }

func (b *Backend) CloseIdleConnections() {
	if b != nil && b.transport != nil {
		b.transport.CloseIdleConnections()
	}
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
