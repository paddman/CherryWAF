package control

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxBackupEntryBytes = 8 << 20

type backupManifest struct {
	Version      int       `json:"version"`
	ID           string    `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	Actor        string    `json:"actor"`
	RulesPresent bool      `json:"rules_present"`
	Includes     []string  `json:"includes"`
	Note         string    `json:"note"`
}

func (c *Controller) backupsDir() string { return filepath.Join(c.opts.StateDir, "backups") }

func (c *Controller) handleBackupList(w http.ResponseWriter, _ *http.Request, _ Principal) {
	backups, err := c.listBackups()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"backups": backups, "scope": "WAF configuration and GUI rules; private keys, passwords, and sessions are excluded"})
}

func (c *Controller) handleBackupCreate(w http.ResponseWriter, r *http.Request, principal Principal) {
	backup, err := c.createBackup(principal.User.Username)
	if err != nil {
		c.audit(r, principal, "backup.create", "backup", "failure", map[string]any{"error": err.Error()})
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	c.audit(r, principal, "backup.create", "backup/"+backup.ID, "success", map[string]any{"size": backup.Size})
	writeJSON(w, http.StatusCreated, backup)
}

func (c *Controller) handleBackupDownload(w http.ResponseWriter, r *http.Request, principal Principal) {
	id := r.PathValue("id")
	if !validArtifactID(id) {
		writeAPIError(w, http.StatusBadRequest, "invalid backup ID")
		return
	}
	path := filepath.Join(c.backupsDir(), id+".zip")
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		writeAPIError(w, http.StatusNotFound, "backup not found")
		return
	}
	if err != nil || !info.Mode().IsRegular() {
		writeAPIError(w, http.StatusInternalServerError, "backup is unavailable")
		return
	}
	c.audit(r, principal, "backup.download", "backup/"+id, "success", map[string]any{"size": info.Size()})
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="CherryWAF-%s.zip"`, id))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, path)
}

func (c *Controller) handleBackupRestore(w http.ResponseWriter, r *http.Request, principal Principal) {
	id := r.PathValue("id")
	if !validArtifactID(id) {
		writeAPIError(w, http.StatusBadRequest, "invalid backup ID")
		return
	}
	result, err := c.restoreBackup(id, principal.User.Username)
	if err != nil {
		c.audit(r, principal, "backup.restore", "backup/"+id, "failure", map[string]any{"error": err.Error()})
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.audit(r, principal, "backup.restore", "backup/"+id, "success", result)
	writeJSON(w, http.StatusOK, map[string]any{"status": "restored", "result": result})
}

func (c *Controller) handleBackupDelete(w http.ResponseWriter, r *http.Request, principal Principal) {
	id := r.PathValue("id")
	if !validArtifactID(id) {
		writeAPIError(w, http.StatusBadRequest, "invalid backup ID")
		return
	}
	zipPath := filepath.Join(c.backupsDir(), id+".zip")
	metaPath := filepath.Join(c.backupsDir(), id+".json")
	if _, err := os.Stat(zipPath); errors.Is(err, os.ErrNotExist) {
		writeAPIError(w, http.StatusNotFound, "backup not found")
		return
	}
	if err := os.Remove(zipPath); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = os.Remove(metaPath)
	c.audit(r, principal, "backup.delete", "backup/"+id, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func (c *Controller) createBackup(actor string) (BackupInfo, error) {
	// Capture configuration and GUI rules from one coherent control-plane
	// transaction instead of racing an apply operation halfway through a ZIP.
	c.configMu.Lock()
	defer c.configMu.Unlock()
	if err := os.MkdirAll(c.backupsDir(), 0o750); err != nil {
		return BackupInfo{}, err
	}
	id := time.Now().UTC().Format("20060102T150405Z") + "-" + newID()[:8]
	created := time.Now().UTC()
	configData, err := os.ReadFile(c.opts.ConfigPath)
	if err != nil {
		return BackupInfo{}, err
	}
	ruleData, rulesPresent, err := readOptional(c.guiRulesPath())
	if err != nil {
		return BackupInfo{}, err
	}
	manifest := backupManifest{Version: 1, ID: id, CreatedAt: created, Actor: actor, RulesPresent: rulesPresent, Includes: []string{"config/cherrywaf.json", "manifest.json"}, Note: "Certificate private keys, password hashes, audit logs, and session tokens are excluded by design."}
	if rulesPresent {
		manifest.Includes = append(manifest.Includes, "rules/gui-rules.json")
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	if err := addZipFile(writer, "config/cherrywaf.json", configData, 0o600); err != nil {
		return BackupInfo{}, err
	}
	if rulesPresent {
		if err := addZipFile(writer, "rules/gui-rules.json", ruleData, 0o600); err != nil {
			return BackupInfo{}, err
		}
	}
	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	if err := addZipFile(writer, "manifest.json", append(manifestData, '\n'), 0o600); err != nil {
		return BackupInfo{}, err
	}
	if err := writer.Close(); err != nil {
		return BackupInfo{}, err
	}
	zipPath := filepath.Join(c.backupsDir(), id+".zip")
	if err := writeAtomic(zipPath, buffer.Bytes(), 0o600); err != nil {
		return BackupInfo{}, err
	}
	info := BackupInfo{ID: id, CreatedAt: created, Actor: actor, Size: int64(buffer.Len())}
	metadata, _ := json.MarshalIndent(info, "", "  ")
	if err := writeAtomic(filepath.Join(c.backupsDir(), id+".json"), append(metadata, '\n'), 0o600); err != nil {
		_ = os.Remove(zipPath)
		return BackupInfo{}, err
	}
	return info, nil
}

func addZipFile(writer *zip.Writer, name string, data []byte, mode os.FileMode) error {
	header := &zip.FileHeader{Name: name, Method: zip.Deflate}
	header.SetMode(mode)
	header.Modified = time.Now().UTC()
	entry, err := writer.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = entry.Write(data)
	return err
}

func (c *Controller) listBackups() ([]BackupInfo, error) {
	entries, err := os.ReadDir(c.backupsDir())
	if errors.Is(err, os.ErrNotExist) {
		return []BackupInfo{}, nil
	}
	if err != nil {
		return nil, err
	}
	var backups []BackupInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(c.backupsDir(), entry.Name()))
		if err != nil {
			continue
		}
		var info BackupInfo
		if json.Unmarshal(data, &info) == nil && validArtifactID(info.ID) {
			backups = append(backups, info)
		}
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt.After(backups[j].CreatedAt) })
	return backups, nil
}

func (c *Controller) restoreBackup(id, actor string) (map[string]any, error) {
	reader, err := zip.OpenReader(filepath.Join(c.backupsDir(), id+".zip"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("backup not found")
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	entries := make(map[string][]byte)
	for _, file := range reader.File {
		if file.UncompressedSize64 > maxBackupEntryBytes {
			return nil, fmt.Errorf("backup entry %s is too large", file.Name)
		}
		if file.Name != "config/cherrywaf.json" && file.Name != "rules/gui-rules.json" && file.Name != "manifest.json" {
			return nil, fmt.Errorf("backup contains unsupported entry %q", file.Name)
		}
		stream, err := file.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(stream, maxBackupEntryBytes+1))
		_ = stream.Close()
		if readErr != nil {
			return nil, readErr
		}
		if len(data) > maxBackupEntryBytes {
			return nil, fmt.Errorf("backup entry %s is too large", file.Name)
		}
		entries[file.Name] = data
	}
	configData := entries["config/cherrywaf.json"]
	if len(configData) == 0 {
		return nil, errors.New("backup does not contain a configuration")
	}
	var manifest backupManifest
	if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil || manifest.Version != 1 {
		return nil, errors.New("backup manifest is missing or invalid")
	}
	prettyConfig, err := normalizeJSON(configData, maxConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("backup configuration is invalid: %w", err)
	}
	var rules []byte
	if manifest.RulesPresent {
		rules = entries["rules/gui-rules.json"]
		if len(rules) == 0 {
			return nil, errors.New("backup manifest expects GUI rules but the file is missing")
		}
		if err := validateRuleBytes(c.guiRulesPath(), rules); err != nil {
			return nil, fmt.Errorf("backup rules are invalid: %w", err)
		}
	}
	c.configMu.Lock()
	revision, restart, err := c.applyBundleLocked(prettyConfig, &rules, actor, "Restore backup "+id)
	c.configMu.Unlock()
	if err != nil {
		return nil, err
	}
	return map[string]any{"safety_revision": revision.ID, "restart_required": restart}, nil
}
