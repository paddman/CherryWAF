package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/paddman/CherryWAF/internal/config"
)

func (b *Backend) startHealthChecks() {
	for _, pool := range b.pools {
		if !pool.config.HealthCheck.Enabled {
			continue
		}
		go b.runHealthChecks(pool)
	}
}

func (b *Backend) runHealthChecks(pool *poolRuntime) {
	checkAll := func() {
		for _, member := range pool.members {
			member := member
			go b.checkMember(pool, member)
		}
	}
	checkAll()
	ticker := time.NewTicker(time.Duration(pool.config.HealthCheck.IntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			checkAll()
		}
	}
}

func (b *Backend) checkMember(pool *poolRuntime, member *memberRuntime) {
	if !member.checking.CompareAndSwap(false, true) {
		return
	}
	defer member.checking.Store(false)

	check := pool.config.HealthCheck
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(check.TimeoutSeconds)*time.Second)
	defer cancel()

	var err error
	if check.Type == "tcp" {
		err = tcpCheck(ctx, member.target)
	} else {
		err = httpCheck(ctx, member, check)
	}
	member.lastCheckUnixNano.Store(time.Now().UTC().UnixNano())
	if err != nil {
		member.recordFailure(fmt.Errorf("active health check: %w", err))
		return
	}
	member.recordSuccess()
}

func tcpCheck(ctx context.Context, target *url.URL) error {
	address := target.Host
	if _, _, err := net.SplitHostPort(address); err != nil {
		port := "80"
		if target.Scheme == "https" {
			port = "443"
		}
		address = net.JoinHostPort(target.Hostname(), port)
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	return connection.Close()
}

func httpCheck(ctx context.Context, member *memberRuntime, check config.HealthCheckConfig) error {
	target := *member.target
	target.RawQuery = ""
	target.Fragment = ""
	target.Path = joinHealthPath(member.target.Path, check.Path)
	target.RawPath = ""

	request, err := http.NewRequestWithContext(ctx, strings.ToUpper(check.Method), target.String(), nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "CherryWAF-Health/1")
	request.Header.Set("X-CherryWAF-Health", "1")
	if check.Host != "" {
		request.Host = check.Host
	}
	client := &http.Client{
		Transport: member.transport,
		Timeout:   time.Duration(check.TimeoutSeconds) * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	closeErr := response.Body.Close()
	if response.StatusCode < check.ExpectedStatusMin || response.StatusCode > check.ExpectedStatusMax {
		return fmt.Errorf("HTTP %d outside expected range %d-%d", response.StatusCode, check.ExpectedStatusMin, check.ExpectedStatusMax)
	}
	return closeErr
}

func joinHealthPath(base, health string) string {
	if base == "" || base == "/" {
		if health == "" {
			return "/"
		}
		return health
	}
	if health == "" || health == "/" {
		return base
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(health, "/")
}
