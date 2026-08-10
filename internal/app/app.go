package app

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/paddman/CherryWAF/internal/core"
	"github.com/paddman/CherryWAF/internal/logging"
	"github.com/paddman/CherryWAF/internal/metrics"
	"github.com/paddman/CherryWAF/internal/netutil"
	"github.com/paddman/CherryWAF/internal/proxy"
	"github.com/paddman/CherryWAF/internal/waf"
)

type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

type App struct {
	configPath string
	build      BuildInfo
	startedAt  time.Time
	metrics    *metrics.Metrics
	current    atomic.Pointer[core.Runtime]

	reloadMu sync.Mutex
	oldMu    sync.Mutex
	retired  []*core.Runtime
}

func New(configPath string, build BuildInfo) (*App, error) {
	metric := &metrics.Metrics{}
	runtime, err := core.Build(configPath, metric)
	if err != nil {
		return nil, err
	}
	a := &App{configPath: configPath, build: build, startedAt: time.Now().UTC(), metrics: metric}
	a.current.Store(runtime)
	return a, nil
}

func (a *App) Reload() error {
	a.reloadMu.Lock()
	defer a.reloadMu.Unlock()

	next, err := core.Build(a.configPath, a.metrics)
	if err != nil {
		a.metrics.ReloadFailed()
		return err
	}
	current := a.current.Load()
	if err := compatibleForHotReload(current, next); err != nil {
		_ = next.Close()
		a.metrics.ReloadFailed()
		return err
	}

	old := a.current.Swap(next)
	if old != nil {
		a.oldMu.Lock()
		a.retired = append(a.retired, old)
		a.oldMu.Unlock()
	}
	a.metrics.Reloaded()
	return nil
}

func compatibleForHotReload(old, next *core.Runtime) error {
	if old == nil || next == nil {
		return nil
	}
	a, b := old.Config, next.Config
	if a.HTTP.Enabled != b.HTTP.Enabled || a.HTTP.Listen != b.HTTP.Listen ||
		a.HTTPS.Enabled != b.HTTPS.Enabled || a.HTTPS.Listen != b.HTTPS.Listen ||
		a.Admin.Enabled != b.Admin.Enabled || a.Admin.Listen != b.Admin.Listen ||
		a.Security.MaxHeaderBytes != b.Security.MaxHeaderBytes {
		return errors.New("listener enablement, listen addresses, and max_header_bytes require a service restart")
	}
	return nil
}

func (a *App) Run(ctx context.Context) error {
	runtime := a.current.Load()
	if runtime == nil {
		return errors.New("runtime is not initialized")
	}
	cfg := runtime.Config

	type serving struct {
		name     string
		server   *http.Server
		listener net.Listener
		tls      bool
	}
	var listeners []serving
	closeListeners := func() {
		for _, item := range listeners {
			_ = item.listener.Close()
		}
	}

	if cfg.HTTP.Enabled {
		ln, err := net.Listen("tcp", cfg.HTTP.Listen)
		if err != nil {
			return fmt.Errorf("listen HTTP on %s: %w", cfg.HTTP.Listen, err)
		}
		listeners = append(listeners, serving{
			name: "http", listener: ln,
			server: &http.Server{
				Addr: cfg.HTTP.Listen, Handler: a.publicHandler(false), MaxHeaderBytes: cfg.Security.MaxHeaderBytes,
				ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 90 * time.Second,
			},
		})
	}
	if cfg.HTTPS.Enabled {
		ln, err := net.Listen("tcp", cfg.HTTPS.Listen)
		if err != nil {
			closeListeners()
			return fmt.Errorf("listen HTTPS on %s: %w", cfg.HTTPS.Listen, err)
		}
		tlsConfig := &tls.Config{
			MinVersion: runtime.TLSVersion(),
			NextProtos: []string{"h2", "http/1.1"},
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return a.current.Load().GetCertificate(hello)
			},
		}
		tlsConfig.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
			current := a.current.Load()
			return &tls.Config{
				MinVersion: current.TLSVersion(), NextProtos: []string{"h2", "http/1.1"},
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return a.current.Load().GetCertificate(hello)
				},
			}, nil
		}
		listeners = append(listeners, serving{
			name: "https", listener: ln, tls: true,
			server: &http.Server{
				Addr: cfg.HTTPS.Listen, Handler: a.publicHandler(true), MaxHeaderBytes: cfg.Security.MaxHeaderBytes, TLSConfig: tlsConfig,
				ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 90 * time.Second,
			},
		})
	}
	if cfg.Admin.Enabled {
		ln, err := net.Listen("tcp", cfg.Admin.Listen)
		if err != nil {
			closeListeners()
			return fmt.Errorf("listen admin on %s: %w", cfg.Admin.Listen, err)
		}
		listeners = append(listeners, serving{
			name: "admin", listener: ln,
			server: &http.Server{
				Addr: cfg.Admin.Listen, Handler: a.adminHandler(), MaxHeaderBytes: 64 << 10,
				ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
			},
		})
	}

	errCh := make(chan error, len(listeners))
	for _, item := range listeners {
		item := item
		go func() {
			slog.Info("listener started", "name", item.name, "address", item.listener.Addr().String())
			var err error
			if item.tls {
				err = item.server.ServeTLS(item.listener, "", "")
			} else {
				err = item.server.Serve(item.listener)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				errCh <- fmt.Errorf("%s listener: %w", item.name, err)
			}
		}()
	}

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, item := range listeners {
		if err := item.server.Shutdown(shutdownCtx); err != nil && runErr == nil {
			runErr = fmt.Errorf("shutdown %s server: %w", item.name, err)
		}
	}
	a.closeRuntimes()
	return runErr
}

func (a *App) closeRuntimes() {
	var runtimes []*core.Runtime
	if current := a.current.Swap(nil); current != nil {
		runtimes = append(runtimes, current)
	}
	a.oldMu.Lock()
	runtimes = append(runtimes, a.retired...)
	a.retired = nil
	a.oldMu.Unlock()
	for _, runtime := range runtimes {
		_ = runtime.Close()
	}
}

func (a *App) publicHandler(isHTTPS bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		a.metrics.RequestStarted()
		capture := &responseCapture{ResponseWriter: w, status: http.StatusOK}
		requestID := r.Header.Get("X-Request-ID")
		if !validRequestID(requestID) {
			requestID = proxy.NewRequestID()
		}
		r.Header.Set("X-Request-ID", requestID)
		capture.Header().Set("X-Request-ID", requestID)
		capture.Header().Set("Server", "CherryWAF")

		runtime := a.current.Load()
		var route *core.Route
		var clientIP = "unknown"
		defer func() {
			duration := time.Since(started)
			a.metrics.RequestFinished(capture.status, duration)
			if runtime == nil || runtime.Logger == nil {
				return
			}
			virtualHost, upstream := "", ""
			if route != nil {
				virtualHost = route.VirtualHost.Name
				upstream = route.Backend.Upstream()
			}
			_ = runtime.Logger.Access(logging.AccessEvent{
				Timestamp: time.Now().UTC(), RequestID: requestID, ClientIP: clientIP,
				VirtualHost: virtualHost, Host: r.Host, Method: r.Method, Path: r.URL.EscapedPath(), Protocol: r.Proto,
				Status: capture.status, Bytes: capture.bytes, DurationMS: float64(duration.Microseconds()) / 1000, Upstream: upstream,
			})
		}()

		if runtime == nil {
			writeJSON(capture, http.StatusServiceUnavailable, map[string]any{"error": "WAF runtime unavailable", "request_id": requestID})
			return
		}
		var ok bool
		route, ok = runtime.Route(r.Host)
		if !ok {
			writeJSON(capture, http.StatusMisdirectedRequest, map[string]any{"error": "unknown virtual host", "request_id": requestID})
			return
		}
		if isHTTPS && r.TLS != nil {
			sni := proxy.Hostname(r.TLS.ServerName)
			host := proxy.Hostname(r.Host)
			if sni != "" && sni != host {
				writeJSON(capture, http.StatusMisdirectedRequest, map[string]any{"error": "TLS SNI and HTTP Host do not match", "request_id": requestID})
				return
			}
		}

		forwarded := r.Header.Get(runtime.Config.Security.ForwardedForHeader)
		clientIP = netutil.ClientIP(r.RemoteAddr, forwarded, runtime.TrustedProxies)

		if !isHTTPS && runtime.Config.HTTP.RedirectToHTTPS {
			http.Redirect(capture, r, redirectURL(runtime, r), http.StatusPermanentRedirect)
			return
		}

		if runtime.Limiter != nil && !runtime.Limiter.Allow(route.VirtualHost.Name+"|"+clientIP) {
			a.metrics.RateLimited()
			capture.Header().Set("Retry-After", "1")
			logSyntheticSecurity(runtime, requestID, clientIP, route, r, "rate_limit", 0, "request rate exceeded")
			writeJSON(capture, http.StatusTooManyRequests, map[string]any{"error": "rate limit exceeded", "request_id": requestID})
			return
		}

		body, err := inspectionBody(r, runtime.Config.Security.MaxBodyBytes)
		if err != nil {
			if errors.Is(err, errUnsupportedContentEncoding) {
				a.metrics.Blocked()
				logSyntheticSecurity(runtime, requestID, clientIP, route, r, "block", 10, err.Error())
				writeJSON(capture, http.StatusUnsupportedMediaType, map[string]any{"error": err.Error(), "request_id": requestID})
				return
			}
			if errors.Is(err, errBodyTooLarge) {
				a.metrics.BodyTooLarge()
				logSyntheticSecurity(runtime, requestID, clientIP, route, r, "block", 20, "request body exceeds inspection limit")
				writeJSON(capture, http.StatusRequestEntityTooLarge, map[string]any{"error": "request body too large", "request_id": requestID})
				return
			}
			writeJSON(capture, http.StatusBadRequest, map[string]any{"error": "unable to inspect request body", "request_id": requestID})
			return
		}

		decision := runtime.Engine.Inspect(waf.RequestData{Request: r, Body: body})
		if len(decision.Matches) > 0 {
			action := "detect"
			if decision.Blocked {
				action = "block"
			}
			_ = runtime.Logger.Security(logging.SecurityEvent{
				Timestamp: time.Now().UTC(), RequestID: requestID, ClientIP: clientIP,
				VirtualHost: route.VirtualHost.Name, Host: r.Host, Method: r.Method, Path: r.URL.EscapedPath(),
				Action: action, Score: decision.Score, Reason: decision.Reason, Matches: decision.Matches,
			})
		}
		if decision.Blocked {
			a.metrics.Blocked()
			capture.Header().Set("Cache-Control", "no-store")
			writeJSON(capture, http.StatusForbidden, map[string]any{
				"error": "request blocked by CherryWAF", "request_id": requestID, "incident_score": decision.Score,
			})
			return
		}

		route.Backend.ServeHTTP(capture, r, clientIP)
	})
}

func (a *App) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"name": "CherryWAF", "status": "running", "version": a.build.Version})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if a.current.Load() == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not ready"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = io.WriteString(w, a.metrics.Prometheus())
	})
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if !a.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		runtime := a.current.Load()
		writeJSON(w, http.StatusOK, map[string]any{
			"name": "CherryWAF", "build": a.build, "started_at": a.startedAt,
			"uptime_seconds": int64(time.Since(a.startedAt).Seconds()),
			"loaded_at":      runtime.LoadedAt, "mode": runtime.Engine.Mode(), "rule_count": runtime.Engine.RuleCount(),
			"domains": runtime.Config.DomainNames(), "certificates": runtime.CertificatesInfo(), "metrics": a.metrics.Snapshot(),
		})
	})
	mux.HandleFunc("POST /api/v1/reload", func(w http.ResponseWriter, r *http.Request) {
		if !a.authorized(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		if err := a.Reload(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "reloaded", "loaded_at": a.current.Load().LoadedAt})
	})
	return mux
}

func (a *App) authorized(r *http.Request) bool {
	runtime := a.current.Load()
	if runtime == nil {
		return false
	}
	expected := strings.TrimSpace(getenv(runtime.Config.Admin.TokenEnv))
	if expected == "" {
		return false
	}
	provided := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if provided == "" {
		provided = strings.TrimSpace(r.Header.Get("X-Admin-Token"))
	}
	if len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

var getenv = func(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func validRequestID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("-_.:", r) {
			continue
		}
		return false
	}
	return true
}

func redirectURL(runtime *core.Runtime, r *http.Request) string {
	host := proxy.Hostname(r.Host)
	_, httpsPort, err := net.SplitHostPort(runtime.Config.HTTPS.Listen)
	if err == nil && httpsPort != "443" {
		host = net.JoinHostPort(host, httpsPort)
	}
	return "https://" + host + r.URL.RequestURI()
}

func logSyntheticSecurity(runtime *core.Runtime, requestID, clientIP string, route *core.Route, r *http.Request, action string, score int, reason string) {
	if runtime == nil || runtime.Logger == nil || route == nil {
		return
	}
	_ = runtime.Logger.Security(logging.SecurityEvent{
		Timestamp: time.Now().UTC(), RequestID: requestID, ClientIP: clientIP,
		VirtualHost: route.VirtualHost.Name, Host: r.Host, Method: r.Method, Path: r.URL.EscapedPath(),
		Action: action, Score: score, Reason: reason,
	})
}

var (
	errBodyTooLarge               = errors.New("request body too large")
	errUnsupportedContentEncoding = errors.New("unsupported request content encoding")
)

func inspectionBody(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	_ = r.Body.Close()
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if len(r.TransferEncoding) == 0 {
		r.ContentLength = int64(len(raw))
	}

	encoding := strings.ToLower(strings.TrimSpace(strings.Join(r.Header.Values("Content-Encoding"), ",")))
	if encoding != "" && encoding != "identity" && encoding != "gzip" {
		return nil, fmt.Errorf("%w: %s", errUnsupportedContentEncoding, encoding)
	}
	if encoding == "gzip" {
		reader, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("open gzip request body: %w", err)
		}
		decompressed, readErr := io.ReadAll(io.LimitReader(reader, limit+1))
		closeErr := reader.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if int64(len(decompressed)) > limit {
			return nil, errBodyTooLarge
		}
		return decompressed, nil
	}
	return raw, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type responseCapture struct {
	http.ResponseWriter
	status int
	bytes  int64
	wrote  bool
}

func (w *responseCapture) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.status = status
	w.wrote = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseCapture) Write(data []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += int64(n)
	return n, err
}

func (w *responseCapture) Flush() {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

func (w *responseCapture) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *responseCapture) ReadFrom(src io.Reader) (int64, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := readerFrom.ReadFrom(src)
		w.bytes += n
		return n, err
	}
	n, err := io.Copy(struct{ io.Writer }{w.ResponseWriter}, src)
	w.bytes += n
	return n, err
}

func (w *responseCapture) Unwrap() http.ResponseWriter { return w.ResponseWriter }
