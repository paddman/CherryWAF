package control

import (
	"context"
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

	"github.com/paddman/CherryWAF/internal/certstore"
	"github.com/paddman/CherryWAF/internal/config"
)

const maxCertificatePartBytes = 2 << 20

type managedCertificate struct {
	Domain          string    `json:"domain"`
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	Serial          string    `json:"serial"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	DaysLeft        int       `json:"days_left"`
	CertificateFile string    `json:"certificate_file"`
	PrivateKeyFile  string    `json:"private_key_file"`
	InUse           bool      `json:"in_use"`
}

func (c *Controller) certificatesDir() string { return filepath.Join(c.opts.StateDir, "certificates") }

func (c *Controller) handleCertificateList(w http.ResponseWriter, _ *http.Request, _ Principal) {
	items, err := c.listCertificates()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": items, "private_keys_exportable": false})
}

func (c *Controller) handleCertificateUpload(w http.ResponseWriter, r *http.Request, principal Principal) {
	r.Body = http.MaxBytesReader(w, r.Body, 5<<20)
	if err := r.ParseMultipartForm(5 << 20); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid multipart upload: "+err.Error())
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	domain := config.NormalizeDomain(r.FormValue("domain"))
	if err := config.ValidateDomainPattern(domain); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid domain: "+err.Error())
		return
	}
	certData, err := readMultipartPart(r, "certificate", maxCertificatePartBytes)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	keyData, err := readMultipartPart(r, "private_key", maxCertificatePartBytes)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.configMu.Lock()
	item, err := c.installCertificate(domain, certData, keyData)
	c.configMu.Unlock()
	if err != nil {
		c.audit(r, principal, "certificate.install", "certificate/"+domain, "failure", map[string]any{"error": err.Error()})
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.audit(r, principal, "certificate.install", "certificate/"+domain, "success", map[string]any{"not_after": item.NotAfter})
	writeJSON(w, http.StatusCreated, item)
}

func (c *Controller) handleCertificateDelete(w http.ResponseWriter, r *http.Request, principal Principal) {
	domain := config.NormalizeDomain(r.PathValue("domain"))
	if err := config.ValidateDomainPattern(domain); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid domain")
		return
	}

	// Serialize the reference check with configuration writes so a certificate
	// cannot be deleted between an application's validation and atomic apply.
	c.configMu.Lock()
	defer c.configMu.Unlock()
	inUse, err := c.certificateInUse(domain)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if inUse {
		writeAPIError(w, http.StatusConflict, "certificate is referenced by a configured virtual host")
		return
	}
	dir := filepath.Join(c.certificatesDir(), certificateSlug(domain))
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		writeAPIError(w, http.StatusNotFound, "certificate not found")
		return
	}
	if err := os.RemoveAll(dir); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	c.audit(r, principal, "certificate.delete", "certificate/"+domain, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func readMultipartPart(r *http.Request, name string, limit int64) ([]byte, error) {
	file, _, err := r.FormFile(name)
	if err != nil {
		return nil, fmt.Errorf("%s file is required", name)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s file is too large", name)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%s file is empty", name)
	}
	return data, nil
}

func (c *Controller) installCertificate(domain string, certData, keyData []byte) (managedCertificate, error) {
	if err := os.MkdirAll(c.certificatesDir(), 0o750); err != nil {
		return managedCertificate{}, err
	}
	tmpDir, err := os.MkdirTemp(c.certificatesDir(), ".cert-candidate-")
	if err != nil {
		return managedCertificate{}, err
	}
	defer os.RemoveAll(tmpDir)
	certPath := filepath.Join(tmpDir, "fullchain.pem")
	keyPath := filepath.Join(tmpDir, "privkey.pem")
	if err := os.WriteFile(certPath, certData, 0o640); err != nil {
		return managedCertificate{}, err
	}
	if err := os.WriteFile(keyPath, keyData, 0o600); err != nil {
		return managedCertificate{}, err
	}
	info, err := certstore.ValidatePair(certPath, keyPath, time.Now())
	if err != nil {
		return managedCertificate{}, err
	}
	leaf, err := certstore.ParseLeafCertificate(certData)
	if err != nil {
		return managedCertificate{}, err
	}
	if err := certstore.VerifyDomain(leaf, domain); err != nil {
		return managedCertificate{}, fmt.Errorf("certificate does not cover %s: %w", domain, err)
	}

	destination := filepath.Join(c.certificatesDir(), certificateSlug(domain))
	finalCert := filepath.Join(destination, "fullchain.pem")
	finalKey := filepath.Join(destination, "privkey.pem")
	metaPath := filepath.Join(destination, "metadata.json")
	oldCert, certExisted, err := readOptional(finalCert)
	if err != nil {
		return managedCertificate{}, err
	}
	oldKey, keyExisted, err := readOptional(finalKey)
	if err != nil {
		return managedCertificate{}, err
	}
	oldMeta, metaExisted, err := readOptional(metaPath)
	if err != nil {
		return managedCertificate{}, err
	}
	if certExisted != keyExisted {
		return managedCertificate{}, errors.New("existing managed certificate is incomplete; repair or remove it before replacement")
	}

	restore := func() error {
		if !certExisted && !keyExisted && !metaExisted {
			return os.RemoveAll(destination)
		}
		var joined error
		joined = errors.Join(joined, restoreOptional(finalCert, oldCert, certExisted))
		joined = errors.Join(joined, restoreOptional(finalKey, oldKey, keyExisted))
		joined = errors.Join(joined, restoreOptional(metaPath, oldMeta, metaExisted))
		return joined
	}

	if err := os.MkdirAll(destination, 0o750); err != nil {
		return managedCertificate{}, err
	}
	if err := writeAtomic(finalCert, certData, 0o640); err != nil {
		return managedCertificate{}, err
	}
	if err := writeAtomic(finalKey, keyData, 0o600); err != nil {
		_ = restore()
		return managedCertificate{}, err
	}
	metadata := map[string]any{"domain": domain, "installed_at": time.Now().UTC()}
	metadataData, _ := json.MarshalIndent(metadata, "", "  ")
	if err := writeAtomic(metaPath, append(metadataData, '\n'), 0o600); err != nil {
		_ = restore()
		return managedCertificate{}, err
	}

	inUse, err := c.certificateInUse(domain)
	if err != nil {
		_ = restore()
		return managedCertificate{}, err
	}
	if inUse && c.opts.Runtime != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		reloadErr := c.opts.Runtime.Reload(ctx)
		cancel()
		if reloadErr != nil {
			rollbackErr := restore()
			if rollbackErr == nil && certExisted {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				rollbackErr = c.opts.Runtime.Reload(ctx)
				cancel()
			}
			if rollbackErr != nil {
				return managedCertificate{}, fmt.Errorf("certificate reload failed: %v; rollback failed: %w", reloadErr, rollbackErr)
			}
			return managedCertificate{}, fmt.Errorf("certificate reload failed and replacement was rolled back: %w", reloadErr)
		}
	}
	return certificateFromInfo(domain, finalCert, finalKey, info, inUse), nil
}

func certificateFromInfo(domain, certPath, keyPath string, info certstore.Info, inUse bool) managedCertificate {
	return managedCertificate{Domain: domain, Subject: info.Subject, Issuer: info.Issuer, Serial: info.Serial, NotBefore: info.NotBefore, NotAfter: info.NotAfter, DaysLeft: info.DaysLeft, CertificateFile: certPath, PrivateKeyFile: keyPath, InUse: inUse}
}

func (c *Controller) listCertificates() ([]managedCertificate, error) {
	entries, err := os.ReadDir(c.certificatesDir())
	if errors.Is(err, os.ErrNotExist) {
		return []managedCertificate{}, nil
	}
	if err != nil {
		return nil, err
	}
	var result []managedCertificate
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(c.certificatesDir(), entry.Name())
		metaData, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
		if err != nil {
			continue
		}
		var meta struct {
			Domain string `json:"domain"`
		}
		if json.Unmarshal(metaData, &meta) != nil || meta.Domain == "" {
			continue
		}
		certPath, keyPath := filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
		info, err := certstore.ValidatePair(certPath, keyPath, time.Now())
		if err != nil {
			continue
		}
		inUse, _ := c.certificateInUse(meta.Domain)
		result = append(result, certificateFromInfo(meta.Domain, certPath, keyPath, info, inUse))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Domain < result[j].Domain })
	return result, nil
}

func (c *Controller) certificateInUse(domain string) (bool, error) {
	cfg, err := config.Load(c.opts.ConfigPath)
	if err != nil {
		return false, err
	}
	dir := filepath.Join(c.certificatesDir(), certificateSlug(domain))
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	for _, vhost := range cfg.VirtualHosts {
		if sameFilePath(cfg.ResolvePath(vhost.FrontendTLS.CertificateFile), certPath) || sameFilePath(cfg.ResolvePath(vhost.FrontendTLS.PrivateKeyFile), keyPath) {
			return true, nil
		}
	}
	return false, nil
}

func certificateSlug(domain string) string {
	prefix := "exact-"
	if strings.HasPrefix(domain, "*.") {
		prefix = "wildcard-"
		domain = strings.TrimPrefix(domain, "*.")
	}
	var b strings.Builder
	b.WriteString(prefix)
	for _, r := range domain {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
