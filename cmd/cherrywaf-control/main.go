package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/paddman/CherryWAF/internal/control"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("CherryWAF Control Center stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, args = args[0], args[1:]
	}
	switch command {
	case "serve":
		return serve(args)
	case "version":
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"version": version, "commit": commit, "date": date})
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := flags.String("listen", ":9443", "management HTTPS listen address")
	certFile := flags.String("tls-cert", "/var/lib/cherrywaf/management/fullchain.pem", "management TLS certificate")
	keyFile := flags.String("tls-key", "/var/lib/cherrywaf/management/privkey.pem", "management TLS private key")
	configPath := flags.String("config", "/etc/cherrywaf/cherrywaf.json", "CherryWAF configuration path")
	stateDir := flags.String("state-dir", "/var/lib/cherrywaf/control", "Control Center state directory")
	adminURL := flags.String("waf-admin-url", "http://127.0.0.1:9090", "loopback CherryWAF admin API")
	adminEnv := flags.String("waf-admin-env", "/etc/cherrywaf/cherrywaf.env", "file containing CHERRYWAF_ADMIN_TOKEN")
	networkSocket := flags.String("network-socket", "/run/cherrywaf/netd.sock", "privileged network helper socket")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if _, _, err := net.SplitHostPort(*listen); err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	runtimeClient, err := control.NewHTTPRuntimeClient(*adminURL, *adminEnv)
	if err != nil {
		return err
	}
	setupToken, _ := control.ReadSetupToken(*adminEnv)
	controller, err := control.New(control.Options{ConfigPath: *configPath, StateDir: *stateDir, NetworkSocket: *networkSocket, Runtime: runtimeClient, SetupToken: setupToken, Build: map[string]string{"version": version, "commit": commit, "date": date}})
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: *listen, Handler: controller.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}},
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		slog.Info("CherryWAF Control Center listening", "address", *listen)
		if err := server.ServeTLS(listener, *certFile, *keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return server.Shutdown(shutdown)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `CherryWAF Control Center

Usage:
  cherrywaf-control serve [options]
  cherrywaf-control version`)
}
