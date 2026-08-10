package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/paddman/CherryWAF/internal/certstore"
	"github.com/paddman/CherryWAF/internal/config"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("a command is required")
	}
	switch args[0] {
	case "cert":
		return certCommand(args[1:])
	case "vhost":
		return vhostCommand(args[1:])
	case "reload":
		return reloadCommand(args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func certCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("cert requires validate or install")
	}
	switch args[0] {
	case "validate":
		flags := flag.NewFlagSet("cert validate", flag.ContinueOnError)
		certPath := flags.String("cert", "", "PEM certificate/full chain")
		keyPath := flags.String("key", "", "PEM private key")
		domain := flags.String("domain", "", "optional DNS name to verify")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		return validatePair(*certPath, *keyPath, *domain)
	case "install":
		flags := flag.NewFlagSet("cert install", flag.ContinueOnError)
		certPath := flags.String("cert", "", "PEM certificate/full chain")
		keyPath := flags.String("key", "", "PEM private key")
		domain := flags.String("domain", "", "DNS name for the certificate store")
		store := flags.String("store", "/etc/cherrywaf/certs", "certificate store directory")
		owner := flags.String("owner", "", "optional file owner")
		group := flags.String("group", "", "optional file group")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		return installPair(*certPath, *keyPath, *domain, *store, *owner, *group)
	default:
		return fmt.Errorf("unknown cert command %q", args[0])
	}
}

func validatePair(certPath, keyPath, domain string) error {
	if certPath == "" || keyPath == "" {
		return errors.New("--cert and --key are required")
	}
	info, err := certstore.ValidatePair(certPath, keyPath, time.Now())
	if err != nil {
		return err
	}
	if domain != "" {
		data, err := os.ReadFile(certPath)
		if err != nil {
			return err
		}
		leaf, err := certstore.ParseLeafCertificate(data)
		if err != nil {
			return err
		}
		if err := certstore.VerifyDomain(leaf, domain); err != nil {
			return fmt.Errorf("certificate does not cover %q: %w", domain, err)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"valid": true, "certificate": info})
}

func installPair(certPath, keyPath, domain, store, ownerName, groupName string) error {
	domain = config.NormalizeDomain(domain)
	if err := config.ValidateDomainPattern(domain); err != nil {
		return fmt.Errorf("invalid --domain: %w", err)
	}
	if err := validatePairSilent(certPath, keyPath, domain); err != nil {
		return err
	}
	destination := filepath.Join(store, domain)
	if err := os.MkdirAll(destination, 0o750); err != nil {
		return err
	}
	certDest := filepath.Join(destination, "fullchain.pem")
	keyDest := filepath.Join(destination, "privkey.pem")
	if err := atomicCopy(certPath, certDest, 0o644); err != nil {
		return err
	}
	keyMode := os.FileMode(0o600)
	if groupName != "" {
		keyMode = 0o640
	}
	if err := atomicCopy(keyPath, keyDest, keyMode); err != nil {
		return err
	}
	if ownerName != "" || groupName != "" {
		uid, gid, err := resolveOwnership(ownerName, groupName)
		if err != nil {
			return err
		}
		for _, path := range []string{destination, certDest, keyDest} {
			if err := os.Chown(path, uid, gid); err != nil {
				return fmt.Errorf("chown %s: %w", path, err)
			}
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"installed": true, "domain": domain, "certificate_file": certDest, "private_key_file": keyDest,
	})
}

func validatePairSilent(certPath, keyPath, domain string) error {
	if certPath == "" || keyPath == "" {
		return errors.New("--cert and --key are required")
	}
	if _, err := certstore.ValidatePair(certPath, keyPath, time.Now()); err != nil {
		return err
	}
	data, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	leaf, err := certstore.ParseLeafCertificate(data)
	if err != nil {
		return err
	}
	return certstore.VerifyDomain(leaf, domain)
}

func vhostCommand(args []string) error {
	if len(args) == 0 || args[0] != "upsert" {
		return errors.New("vhost requires the upsert command")
	}
	flags := flag.NewFlagSet("vhost upsert", flag.ContinueOnError)
	configPath := flags.String("config", "/etc/cherrywaf/cherrywaf.json", "configuration file")
	name := flags.String("name", "", "virtual host name")
	domain := flags.String("domain", "", "public domain")
	upstream := flags.String("upstream", "", "origin URL")
	certPath := flags.String("cert", "", "installed certificate path")
	keyPath := flags.String("key", "", "installed private key path")
	originServerName := flags.String("origin-server-name", "", "TLS SNI/verification name for the origin")
	preserveHost := flags.Bool("preserve-host", true, "preserve the public Host header")
	redirectHTTPS := flags.Bool("redirect-http", true, "redirect HTTP to HTTPS")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *name == "" || *domain == "" || *upstream == "" || *certPath == "" || *keyPath == "" {
		return errors.New("--name, --domain, --upstream, --cert, and --key are required")
	}
	*domain = config.NormalizeDomain(*domain)
	if err := config.ValidateDomainPattern(*domain); err != nil {
		return fmt.Errorf("invalid --domain: %w", err)
	}
	if err := validatePairSilent(*certPath, *keyPath, *domain); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	httpsWasEnabled := cfg.HTTPS.Enabled
	vhost := config.VirtualHost{
		Name: *name, Enabled: true, Domains: []string{*domain}, Upstream: *upstream, PreserveHost: *preserveHost,
		FrontendTLS:     config.FrontendTLSConfig{CertificateFile: *certPath, PrivateKeyFile: *keyPath},
		OriginTLS:       config.OriginTLSConfig{ServerName: *originServerName},
		ResponseHeaders: map[string]string{"X-Content-Type-Options": "nosniff"},
	}
	updated := false
	for i := range cfg.VirtualHosts {
		if cfg.VirtualHosts[i].Name == *name {
			cfg.VirtualHosts[i] = vhost
			updated = true
			break
		}
	}
	if !updated {
		cfg.VirtualHosts = append(cfg.VirtualHosts, vhost)
	}
	cfg.HTTPS.Enabled = true
	cfg.HTTP.RedirectToHTTPS = *redirectHTTPS
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := atomicWriteJSON(*configPath, cfg, 0o640); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"updated": true, "name": *name, "domain": *domain, "restart_required": !httpsWasEnabled,
	})
}

func reloadCommand(args []string) error {
	flags := flag.NewFlagSet("reload", flag.ContinueOnError)
	endpoint := flags.String("url", "http://127.0.0.1:9090/api/v1/reload", "admin reload endpoint")
	tokenEnv := flags.String("token-env", "CHERRYWAF_ADMIN_TOKEN", "environment variable containing the admin token")
	if err := flags.Parse(args); err != nil {
		return err
	}
	token := strings.TrimSpace(os.Getenv(*tokenEnv))
	if token == "" {
		return fmt.Errorf("environment variable %s is empty", *tokenEnv)
	}
	req, err := http.NewRequest(http.MethodPost, *endpoint, bytes.NewReader(nil))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("reload failed with %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	_, err = os.Stdout.Write(body)
	return err
}

func atomicCopy(source, destination string, mode os.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	tmp := destination + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, destination); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func atomicWriteJSON(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func resolveOwnership(ownerName, groupName string) (int, int, error) {
	uid, gid := -1, -1
	if ownerName != "" {
		u, err := user.Lookup(ownerName)
		if err != nil {
			return -1, -1, err
		}
		uid, err = strconv.Atoi(u.Uid)
		if err != nil {
			return -1, -1, err
		}
		if groupName == "" {
			gid, err = strconv.Atoi(u.Gid)
			if err != nil {
				return -1, -1, err
			}
		}
	}
	if groupName != "" {
		g, err := user.LookupGroup(groupName)
		if err != nil {
			return -1, -1, err
		}
		gid, err = strconv.Atoi(g.Gid)
		if err != nil {
			return -1, -1, err
		}
	}
	return uid, gid, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `CherryWAF control utility

Commands:
  cherrywafctl cert validate --cert fullchain.pem --key privkey.pem --domain app.example.com
  cherrywafctl cert install --domain app.example.com --cert fullchain.pem --key privkey.pem
  cherrywafctl vhost upsert --name app --domain app.example.com --upstream https://10.0.0.20:443 --cert /etc/cherrywaf/certs/app.example.com/fullchain.pem --key /etc/cherrywaf/certs/app.example.com/privkey.pem
  cherrywafctl reload`)
}
