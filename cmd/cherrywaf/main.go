package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/paddman/CherryWAF/internal/app"
	"github.com/paddman/CherryWAF/internal/certstore"
	"github.com/paddman/CherryWAF/internal/core"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("CherryWAF stopped", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "serve"
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		command = args[0]
		args = args[1:]
	}
	switch command {
	case "serve":
		return serve(args)
	case "validate-config":
		return validateConfig(args)
	case "validate-cert":
		return validateCertificate(args)
	case "version":
		return printVersion()
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
	configPath := flags.String("config", "/etc/cherrywaf/cherrywaf.json", "configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	build := app.BuildInfo{Version: version, Commit: commit, Date: date}
	application, err := app.New(*configPath, build)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if err := application.Reload(); err != nil {
					slog.Error("configuration reload failed", "error", err)
				} else {
					slog.Info("configuration and certificates reloaded")
				}
			}
		}
	}()

	slog.Info("CherryWAF starting", "version", version, "commit", commit, "config", *configPath)
	return application.Run(ctx)
}

func validateConfig(args []string) error {
	flags := flag.NewFlagSet("validate-config", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/cherrywaf/cherrywaf.json", "configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	result, err := core.Validate(*configPath)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"valid": true, "result": result})
}

func validateCertificate(args []string) error {
	flags := flag.NewFlagSet("validate-cert", flag.ContinueOnError)
	certPath := flags.String("cert", "", "PEM certificate or full chain")
	keyPath := flags.String("key", "", "PEM private key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *certPath == "" || *keyPath == "" {
		return fmt.Errorf("--cert and --key are required")
	}
	info, err := certstore.ValidatePair(*certPath, *keyPath, time.Now())
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"valid": true, "certificate": info})
}

func printVersion() error {
	return json.NewEncoder(os.Stdout).Encode(app.BuildInfo{Version: version, Commit: commit, Date: date})
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `CherryWAF - reverse proxy web application firewall

Usage:
  cherrywaf serve --config /etc/cherrywaf/cherrywaf.json
  cherrywaf validate-config --config ./configs/cherrywaf.example.json
  cherrywaf validate-cert --cert fullchain.pem --key privkey.pem
  cherrywaf version`)
}
