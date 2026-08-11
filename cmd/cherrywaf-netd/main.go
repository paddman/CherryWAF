//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/paddman/CherryWAF/internal/control"
)

const (
	defaultSocketPath  = "/run/cherrywaf/netd.sock"
	defaultNetplanPath = "/etc/netplan/99-cherrywaf.yaml"
	defaultDataDir     = "/var/lib/cherrywaf/network"
	rollbackSeconds    = 60
)

type peerKey struct{}
type peer struct {
	PID      int32
	UID, GID uint32
}

type daemon struct {
	mu                           sync.Mutex
	dataDir, netplan, binaryPath string
	dryRun                       bool
	allowedUID                   uint32
}

type pendingChange struct {
	Token     string              `json:"token"`
	CreatedAt time.Time           `json:"created_at"`
	ConfirmBy time.Time           `json:"confirm_by"`
	Plan      control.NetworkPlan `json:"plan"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("CherryWAF network helper stopped", "error", err)
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
	case "rollback":
		flags := flag.NewFlagSet("rollback", flag.ContinueOnError)
		token := flags.String("token", "", "network change token")
		if err := flags.Parse(args); err != nil {
			return err
		}
		d, err := newDaemon()
		if err != nil {
			return err
		}
		return d.rollback(*token)
	case "help", "-h", "--help":
		fmt.Fprintln(os.Stderr, "usage: cherrywaf-netd [serve|rollback --token TOKEN]")
		return nil
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func newDaemon() (*daemon, error) {
	allowedUID, err := lookupAllowedUID()
	if err != nil {
		return nil, err
	}
	binaryPath, err := os.Executable()
	if err != nil {
		binaryPath = "/usr/local/sbin/cherrywaf-netd"
	}
	return &daemon{dataDir: envOr("CHERRYWAF_NETWORK_DATA_DIR", defaultDataDir), netplan: envOr("CHERRYWAF_NETPLAN_PATH", defaultNetplanPath), binaryPath: binaryPath, dryRun: os.Getenv("CHERRYWAF_NETD_DRY_RUN") == "1", allowedUID: allowedUID}, nil
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	socketPath := flags.String("socket", defaultSocketPath, "Unix socket path when not socket-activated")
	if err := flags.Parse(args); err != nil {
		return err
	}
	d, err := newDaemon()
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 && !d.dryRun {
		return errors.New("cherrywaf-netd must run as root")
	}
	listener, activated, err := activatedListener()
	if err != nil {
		return err
	}
	if !activated {
		if err := os.MkdirAll(filepath.Dir(*socketPath), 0o755); err != nil {
			return err
		}
		_ = os.Remove(*socketPath)
		listener, err = net.Listen("unix", *socketPath)
		if err != nil {
			return err
		}
		if err := os.Chmod(*socketPath, 0o660); err != nil {
			_ = listener.Close()
			return err
		}
	}
	defer listener.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", d.authorize(d.handleStatus))
	mux.HandleFunc("POST /v1/apply", d.authorize(d.handleApply))
	mux.HandleFunc("POST /v1/confirm", d.authorize(d.handleConfirm))
	mux.HandleFunc("POST /v1/rollback", d.authorize(d.handleRollback))
	mux.HandleFunc("POST /v1/restart-waf", d.authorize(d.handleRestartWAF))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 30 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if info, ok := peerCredentials(conn); ok {
				return context.WithValue(ctx, peerKey{}, info)
			}
			return ctx
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(shutdown)
}

func (d *daemon) authorize(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, ok := r.Context().Value(peerKey{}).(peer)
		if !ok || (info.UID != 0 && info.UID != d.allowedUID) {
			writeError(w, http.StatusForbidden, "unauthorized Unix peer")
			return
		}
		next(w, r)
	}
}

func (d *daemon) handleStatus(w http.ResponseWriter, _ *http.Request) {
	pending, _ := d.pendingChanges()
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "netplan_path": d.netplan, "rollback_seconds": rollbackSeconds, "pending": pending, "dry_run": d.dryRun})
}

func (d *daemon) handleApply(w http.ResponseWriter, r *http.Request) {
	var plan control.NetworkPlan
	if err := decodeJSON(r, &plan, 256<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	known, err := interfaceSet()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := control.ValidateNetworkPlan(plan, known); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := d.apply(plan)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func (d *daemon) handleConfirm(w http.ResponseWriter, r *http.Request) {
	d.handleTokenAction(w, r, true)
}
func (d *daemon) handleRollback(w http.ResponseWriter, r *http.Request) {
	d.handleTokenAction(w, r, false)
}

func (d *daemon) handleRestartWAF(w http.ResponseWriter, _ *http.Request) {
	if d.dryRun {
		writeJSON(w, http.StatusOK, map[string]any{"status": "restarted", "service": "cherrywaf.service", "dry_run": true})
		return
	}
	if err := runCommand(45*time.Second, "systemctl", "restart", "cherrywaf.service"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "restarted", "service": "cherrywaf.service"})
}

func (d *daemon) handleTokenAction(w http.ResponseWriter, r *http.Request, confirm bool) {
	var input struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &input, 64<<10); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var err error
	if confirm {
		err = d.confirm(input.Token)
	} else {
		err = d.rollback(input.Token)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := "rolled_back"
	if confirm {
		status = "confirmed"
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "token": input.Token})
}

func (d *daemon) apply(plan control.NetworkPlan) (control.NetworkApplyResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	pendingItems, err := d.pendingChanges()
	if err != nil {
		return control.NetworkApplyResult{}, err
	}
	if len(pendingItems) > 0 {
		return control.NetworkApplyResult{}, errors.New("another network change is awaiting confirmation or rollback")
	}
	if err := os.MkdirAll(filepath.Join(d.dataDir, "backups"), 0o700); err != nil {
		return control.NetworkApplyResult{}, err
	}
	token, err := randomHex(16)
	if err != nil {
		return control.NetworkApplyResult{}, err
	}
	yaml, err := control.RenderNetplan(plan)
	if err != nil {
		return control.NetworkApplyResult{}, err
	}
	backupPath := filepath.Join(d.dataDir, "backups", token+".yaml")
	absentPath := filepath.Join(d.dataDir, "backups", token+".absent")
	if current, readErr := os.ReadFile(d.netplan); readErr == nil {
		if err := writeAtomic(backupPath, current, 0o600); err != nil {
			return control.NetworkApplyResult{}, err
		}
	} else if errors.Is(readErr, os.ErrNotExist) {
		if err := writeAtomic(absentPath, []byte("absent\n"), 0o600); err != nil {
			return control.NetworkApplyResult{}, err
		}
	} else {
		return control.NetworkApplyResult{}, readErr
	}
	if err := writeAtomic(d.netplan, []byte(yaml), 0o600); err != nil {
		_ = d.cleanupChange(token)
		return control.NetworkApplyResult{}, err
	}
	confirmBy := time.Now().UTC().Add(rollbackSeconds * time.Second)
	pending := pendingChange{Token: token, CreatedAt: time.Now().UTC(), ConfirmBy: confirmBy, Plan: plan}
	pendingData, _ := json.MarshalIndent(pending, "", "  ")
	if err := writeAtomic(filepath.Join(d.dataDir, token+".json"), append(pendingData, '\n'), 0o600); err != nil {
		_ = d.restoreFiles(token)
		return control.NetworkApplyResult{}, err
	}
	if !d.dryRun {
		if err := runCommand(20*time.Second, "netplan", "generate"); err != nil {
			recoveryErr := d.discardPreparedChange(token)
			if recoveryErr != nil {
				return control.NetworkApplyResult{}, fmt.Errorf("netplan validation failed: %v; cleanup failed: %w", err, recoveryErr)
			}
			return control.NetworkApplyResult{}, fmt.Errorf("netplan validation failed: %w", err)
		}
		unit := rollbackUnit(token)
		if err := runCommand(15*time.Second, "systemd-run", "--quiet", "--unit", unit, "--on-active", fmt.Sprintf("%ds", rollbackSeconds), d.binaryPath, "rollback", "--token", token); err != nil {
			recoveryErr := d.discardPreparedChange(token)
			if recoveryErr != nil {
				return control.NetworkApplyResult{}, fmt.Errorf("schedule network rollback: %v; cleanup failed: %w", err, recoveryErr)
			}
			return control.NetworkApplyResult{}, fmt.Errorf("schedule network rollback: %w", err)
		}
		if err := runCommand(30*time.Second, "netplan", "apply"); err != nil {
			_ = d.cancelRollbackTimer(token)
			recoveryErr := d.recoverAppliedChange(token)
			if recoveryErr != nil {
				return control.NetworkApplyResult{}, fmt.Errorf("apply netplan: %v; automatic recovery failed: %w", err, recoveryErr)
			}
			return control.NetworkApplyResult{}, fmt.Errorf("apply netplan failed and the previous configuration was restored: %w", err)
		}
	}
	return control.NetworkApplyResult{Token: token, ConfirmBy: confirmBy, RollbackSec: rollbackSeconds, Message: "Network settings applied. Confirm before the deadline or CherryWAF will automatically roll back."}, nil
}

func (d *daemon) discardPreparedChange(token string) error {
	restoreErr := d.restoreFiles(token)
	if restoreErr != nil {
		return restoreErr
	}
	return d.cleanupChange(token)
}

func (d *daemon) recoverAppliedChange(token string) error {
	if err := d.restoreFiles(token); err != nil {
		return err
	}
	if !d.dryRun {
		if err := runCommand(20*time.Second, "netplan", "generate"); err != nil {
			return fmt.Errorf("validate restored Netplan: %w", err)
		}
		if err := runCommand(30*time.Second, "netplan", "apply"); err != nil {
			return fmt.Errorf("apply restored Netplan: %w", err)
		}
	}
	return d.cleanupChange(token)
}

func (d *daemon) confirm(token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !validToken(token) {
		return errors.New("invalid network token")
	}
	if _, err := os.Stat(filepath.Join(d.dataDir, token+".json")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("pending network change not found")
		}
		return err
	}
	if !d.dryRun {
		_ = d.cancelRollbackTimer(token)
	}
	return d.cleanupChange(token)
}

func (d *daemon) rollback(token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !validToken(token) {
		return errors.New("invalid network token")
	}
	if err := d.restoreFiles(token); err != nil {
		return err
	}
	if !d.dryRun {
		if err := runCommand(20*time.Second, "netplan", "generate"); err != nil {
			return err
		}
		if err := runCommand(30*time.Second, "netplan", "apply"); err != nil {
			return err
		}
	}
	return d.cleanupChange(token)
}

func (d *daemon) restoreFiles(token string) error {
	backupPath := filepath.Join(d.dataDir, "backups", token+".yaml")
	absentPath := filepath.Join(d.dataDir, "backups", token+".absent")
	if data, err := os.ReadFile(backupPath); err == nil {
		return writeAtomic(d.netplan, data, 0o600)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(absentPath); err == nil {
		if removeErr := os.Remove(d.netplan); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
		return nil
	}
	return errors.New("network rollback backup not found")
}

func (d *daemon) cancelRollbackTimer(token string) error {
	unit := rollbackUnit(token)
	_ = runCommand(10*time.Second, "systemctl", "stop", unit+".timer")
	_ = runCommand(10*time.Second, "systemctl", "stop", unit+".service")
	_ = runCommand(10*time.Second, "systemctl", "reset-failed", unit+".service")
	return nil
}

func (d *daemon) cleanupChange(token string) error {
	for _, path := range []string{filepath.Join(d.dataDir, token+".json"), filepath.Join(d.dataDir, "backups", token+".yaml"), filepath.Join(d.dataDir, "backups", token+".absent")} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (d *daemon) pendingChanges() ([]pendingChange, error) {
	entries, err := os.ReadDir(d.dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return []pendingChange{}, nil
	}
	if err != nil {
		return nil, err
	}
	var result []pendingChange
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(d.dataDir, entry.Name()))
		if err != nil {
			continue
		}
		var item pendingChange
		if json.Unmarshal(data, &item) == nil && validToken(item.Token) {
			result = append(result, item)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result, nil
}

func activatedListener() (net.Listener, bool, error) {
	pid, _ := strconv.Atoi(os.Getenv("LISTEN_PID"))
	fds, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if pid != os.Getpid() || fds < 1 {
		return nil, false, nil
	}
	file := os.NewFile(uintptr(3), "systemd-listen-fd")
	if file == nil {
		return nil, false, errors.New("systemd listener file descriptor is unavailable")
	}
	listener, err := net.FileListener(file)
	_ = file.Close()
	if err != nil {
		return nil, false, err
	}
	return listener, true, nil
}

func peerCredentials(conn net.Conn) (peer, bool) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return peer{}, false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return peer{}, false
	}
	var credential *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || controlErr != nil || credential == nil {
		return peer{}, false
	}
	return peer{PID: credential.Pid, UID: credential.Uid, GID: credential.Gid}, true
}

func lookupAllowedUID() (uint32, error) {
	if value := strings.TrimSpace(os.Getenv("CHERRYWAF_NETD_ALLOWED_UID")); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		return uint32(parsed), err
	}
	account, err := user.Lookup("cherrywaf")
	if err != nil {
		if os.Getenv("CHERRYWAF_NETD_DRY_RUN") == "1" {
			return uint32(os.Getuid()), nil
		}
		return 0, fmt.Errorf("look up cherrywaf user: %w", err)
	}
	parsed, err := strconv.ParseUint(account.Uid, 10, 32)
	return uint32(parsed), err
}

func interfaceSet() (map[string]bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make(map[string]bool, len(interfaces))
	for _, item := range interfaces {
		result[item.Name] = true
	}
	return result, nil
}
func rollbackUnit(token string) string { return "cherrywaf-network-rollback-" + token }
func validToken(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'f') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}
func randomHex(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func runCommand(timeout time.Duration, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%s timed out", name)
	}
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".netd-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func decodeJSON(r *http.Request, target any, limit int64) error {
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return errors.New("request body is too large")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values are not allowed")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}
func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
