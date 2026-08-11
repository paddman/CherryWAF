package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/paddman/CherryWAF/internal/core"
)

const maxConfigBytes = 4 << 20

func (c *Controller) handleConfigGet(w http.ResponseWriter, _ *http.Request, _ Principal) {
	data, err := os.ReadFile(c.opts.ConfigPath)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "active configuration is invalid JSON")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": value, "path": c.opts.ConfigPath})
}

func (c *Controller) handleConfigValidate(w http.ResponseWriter, r *http.Request, principal Principal) {
	data, err := readBody(r, maxConfigBytes)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, _, err := c.validateConfigBytes(data)
	if err != nil {
		c.audit(r, principal, "config.validate", "configuration", "failure", map[string]any{"error": err.Error()})
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.audit(r, principal, "config.validate", "configuration", "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "result": result})
}

func (c *Controller) handleConfigApply(w http.ResponseWriter, r *http.Request, principal Principal) {
	data, err := readBody(r, maxConfigBytes)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	revision, restart, result, err := c.applyConfigBytes(data, principal.User.Username, "Control Center configuration update")
	if err != nil {
		c.audit(r, principal, "config.apply", "configuration", "failure", map[string]any{"error": err.Error()})
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.audit(r, principal, "config.apply", "configuration", "success", map[string]any{"revision": revision.ID, "restart_required": restart})
	status := http.StatusOK
	if restart {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]any{"status": "applied", "revision": revision, "restart_required": restart, "validation": result})
}

func normalizeJSON(data []byte, max int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("JSON document is empty")
	}
	if len(data) > max {
		return nil, fmt.Errorf("JSON document exceeds %d bytes", max)
	}
	var value any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	pretty, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(pretty, '\n'), nil
}

func (c *Controller) validateConfigBytes(data []byte) (*core.ValidationResult, []byte, error) {
	pretty, err := normalizeJSON(data, maxConfigBytes)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(c.opts.ConfigPath), 0o770); err != nil {
		return nil, nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.opts.ConfigPath), ".candidate-*.json")
	if err != nil {
		return nil, nil, err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o660); err != nil {
		_ = tmp.Close()
		return nil, nil, err
	}
	if _, err := tmp.Write(pretty); err != nil {
		_ = tmp.Close()
		return nil, nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, nil, err
	}
	result, err := core.Validate(name)
	if err != nil {
		return nil, nil, err
	}
	return result, pretty, nil
}

func (c *Controller) applyConfigBytes(data []byte, actor, reason string) (Revision, bool, *core.ValidationResult, error) {
	c.configMu.Lock()
	defer c.configMu.Unlock()
	result, pretty, err := c.validateConfigBytes(data)
	if err != nil {
		return Revision{}, false, nil, err
	}
	revision, restart, err := c.applyBundleLocked(pretty, nil, actor, reason)
	return revision, restart, result, err
}

// rules == nil keeps the current GUI rule file. A non-nil empty slice removes it.
func (c *Controller) applyBundleLocked(configData []byte, rules *[]byte, actor, reason string) (Revision, bool, error) {
	currentConfig, err := os.ReadFile(c.opts.ConfigPath)
	if err != nil {
		return Revision{}, false, fmt.Errorf("read active configuration: %w", err)
	}
	currentRules, rulesExisted, err := readOptional(c.guiRulesPath())
	if err != nil {
		return Revision{}, false, err
	}
	revision, err := c.createRevisionLocked(currentConfig, currentRules, rulesExisted, actor, reason)
	if err != nil {
		return Revision{}, false, err
	}

	restore := func() error {
		var joined error
		if err := writeAtomic(c.opts.ConfigPath, currentConfig, 0o660); err != nil {
			joined = errors.Join(joined, err)
		}
		if err := restoreOptional(c.guiRulesPath(), currentRules, rulesExisted); err != nil {
			joined = errors.Join(joined, err)
		}
		return joined
	}
	if rules != nil {
		if len(*rules) == 0 {
			if err := os.Remove(c.guiRulesPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
				return revision, false, err
			}
		} else {
			if err := validateRuleBytes(c.guiRulesPath(), *rules); err != nil {
				return revision, false, err
			}
			if err := writeAtomic(c.guiRulesPath(), *rules, 0o640); err != nil {
				return revision, false, err
			}
		}
	}
	if err := writeAtomic(c.opts.ConfigPath, configData, 0o660); err != nil {
		_ = restore()
		return revision, false, err
	}
	if _, err := core.Validate(c.opts.ConfigPath); err != nil {
		rollbackErr := restore()
		if rollbackErr != nil {
			return revision, false, fmt.Errorf("candidate invalid: %v; rollback failed: %w", err, rollbackErr)
		}
		return revision, false, fmt.Errorf("candidate invalid and was rolled back: %w", err)
	}
	if c.opts.Runtime == nil {
		return revision, true, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	reloadErr := c.opts.Runtime.Reload(ctx)
	cancel()
	if reloadErr != nil {
		if restartRequired(reloadErr) {
			revision.RestartRequired = true
			_ = c.updateRevisionMetadata(revision)
			return revision, true, nil
		}
		rollbackErr := restore()
		if rollbackErr == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			rollbackErr = c.opts.Runtime.Reload(ctx)
			cancel()
		}
		if rollbackErr != nil {
			return revision, false, fmt.Errorf("reload failed: %v; automatic rollback failed: %w", reloadErr, rollbackErr)
		}
		return revision, false, fmt.Errorf("reload failed and changes were rolled back: %w", reloadErr)
	}
	return revision, false, nil
}

func restartRequired(err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(err.Error())
	return strings.Contains(value, "require a service restart") || (strings.Contains(value, "listener") && strings.Contains(value, "restart"))
}

func readOptional(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return data, err == nil, err
}

func restoreOptional(path string, data []byte, existed bool) error {
	if existed {
		return writeAtomic(path, data, 0o640)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (c *Controller) revisionsDir() string { return filepath.Join(c.opts.StateDir, "revisions") }

func (c *Controller) createRevisionLocked(configData, rulesData []byte, rulesExisted bool, actor, reason string) (Revision, error) {
	id := time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + newID()[:8]
	dir := filepath.Join(c.revisionsDir(), id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Revision{}, err
	}
	if err := writeAtomic(filepath.Join(dir, "config.json"), configData, 0o600); err != nil {
		return Revision{}, err
	}
	if rulesExisted {
		if err := writeAtomic(filepath.Join(dir, "rules.json"), rulesData, 0o600); err != nil {
			return Revision{}, err
		}
	} else if err := writeAtomic(filepath.Join(dir, "rules.absent"), []byte("absent\n"), 0o600); err != nil {
		return Revision{}, err
	}
	revision := Revision{ID: id, CreatedAt: time.Now().UTC(), Actor: actor, Reason: reason, IncludesRules: rulesExisted}
	if err := c.updateRevisionMetadata(revision); err != nil {
		return Revision{}, err
	}
	_ = c.pruneRevisions(50)
	return revision, nil
}

func (c *Controller) updateRevisionMetadata(revision Revision) error {
	data, err := json.MarshalIndent(revision, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(c.revisionsDir(), revision.ID, "metadata.json"), append(data, '\n'), 0o600)
}

func (c *Controller) listRevisions() ([]Revision, error) {
	entries, err := os.ReadDir(c.revisionsDir())
	if errors.Is(err, os.ErrNotExist) {
		return []Revision{}, nil
	}
	if err != nil {
		return nil, err
	}
	var revisions []Revision
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(c.revisionsDir(), entry.Name(), "metadata.json"))
		if err != nil {
			continue
		}
		var revision Revision
		if json.Unmarshal(data, &revision) == nil && validArtifactID(revision.ID) {
			revisions = append(revisions, revision)
		}
	}
	sort.Slice(revisions, func(i, j int) bool { return revisions[i].CreatedAt.After(revisions[j].CreatedAt) })
	return revisions, nil
}

func (c *Controller) pruneRevisions(keep int) error {
	revisions, err := c.listRevisions()
	if err != nil {
		return err
	}
	if len(revisions) <= keep {
		return nil
	}
	for _, revision := range revisions[keep:] {
		_ = os.RemoveAll(filepath.Join(c.revisionsDir(), revision.ID))
	}
	return nil
}

func (c *Controller) handleRevisionList(w http.ResponseWriter, _ *http.Request, _ Principal) {
	revisions, err := c.listRevisions()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revisions": revisions})
}

func (c *Controller) handleRevisionRestore(w http.ResponseWriter, r *http.Request, principal Principal) {
	id := r.PathValue("id")
	if !validArtifactID(id) {
		writeAPIError(w, http.StatusBadRequest, "invalid revision ID")
		return
	}
	dir := filepath.Join(c.revisionsDir(), id)
	configData, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if errors.Is(err, os.ErrNotExist) {
		writeAPIError(w, http.StatusNotFound, "revision not found")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var rules []byte
	if data, readErr := os.ReadFile(filepath.Join(dir, "rules.json")); readErr == nil {
		rules = data
	} else if !errors.Is(readErr, os.ErrNotExist) {
		writeAPIError(w, http.StatusInternalServerError, readErr.Error())
		return
	}
	c.configMu.Lock()
	revision, restart, applyErr := c.applyBundleLocked(configData, &rules, principal.User.Username, "Restore revision "+id)
	c.configMu.Unlock()
	if applyErr != nil {
		c.audit(r, principal, "config.restore", "revision/"+id, "failure", map[string]any{"error": applyErr.Error()})
		writeAPIError(w, http.StatusBadRequest, applyErr.Error())
		return
	}
	c.audit(r, principal, "config.restore", "revision/"+id, "success", map[string]any{"safety_revision": revision.ID, "restart_required": restart})
	writeJSON(w, http.StatusOK, map[string]any{"status": "restored", "safety_revision": revision, "restart_required": restart})
}

func validArtifactID(value string) bool {
	if value == "" || len(value) > 128 || strings.Contains(value, "..") {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("-_.", r) {
			continue
		}
		return false
	}
	return true
}
