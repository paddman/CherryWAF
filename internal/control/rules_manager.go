package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/paddman/CherryWAF/internal/config"
	"github.com/paddman/CherryWAF/internal/waf"
)

const maxRuleFileBytes = 4 << 20

func (c *Controller) guiRulesPath() string {
	return filepath.Join(c.opts.StateDir, "rules", "gui-rules.json")
}

func (c *Controller) handleRulesGet(w http.ResponseWriter, _ *http.Request, _ Principal) {
	path := c.guiRulesPath()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusOK, map[string]any{"active": false, "path": path, "rule_file": waf.RuleFile{Version: waf.RuleFileVersion, Rules: []waf.Rule{}}})
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var file waf.RuleFile
	if err := json.Unmarshal(data, &file); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "GUI rule file is invalid")
		return
	}
	cfg, _ := config.Load(c.opts.ConfigPath)
	active := false
	if cfg != nil {
		for _, rulePath := range cfg.Rules.Files {
			if sameFilePath(cfg.ResolvePath(rulePath), path) {
				active = true
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": active, "path": path, "rule_file": file})
}

func (c *Controller) handleRulesApply(w http.ResponseWriter, r *http.Request, principal Principal) {
	data, err := readBody(r, maxRuleFileBytes)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	var file waf.RuleFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		writeAPIError(w, http.StatusBadRequest, fmt.Sprintf("decode rule file: %v", err))
		return
	}
	if err := ensureEOF(dec); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if file.Version == 0 {
		file.Version = waf.RuleFileVersion
	}
	pretty, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	pretty = append(pretty, '\n')
	if err := validateRuleBytes(c.guiRulesPath(), pretty); err != nil {
		c.audit(r, principal, "rules.validate", "rules/gui", "failure", map[string]any{"error": err.Error()})
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	revision, restart, err := c.applyRuleBytes(pretty, principal.User.Username)
	if err != nil {
		c.audit(r, principal, "rules.apply", "rules/gui", "failure", map[string]any{"error": err.Error()})
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.audit(r, principal, "rules.apply", "rules/gui", "success", map[string]any{"revision": revision.ID, "rule_count": len(file.Rules), "restart_required": restart})
	writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "revision": revision, "rule_count": len(file.Rules), "restart_required": restart})
}

func (c *Controller) handleRulesTest(w http.ResponseWriter, r *http.Request, principal Principal) {
	var input struct {
		Rule waf.Rule `json:"rule"`
		Test struct {
			Method  string            `json:"method"`
			Path    string            `json:"path"`
			Query   string            `json:"query"`
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
		} `json:"test"`
	}
	if err := decodeJSON(r, &input, 1<<20); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	input.Rule.Enabled = true
	file := waf.RuleFile{Version: waf.RuleFileVersion, Rules: []waf.Rule{input.Rule}}
	data, _ := json.Marshal(file)
	if err := os.MkdirAll(c.opts.StateDir, 0o750); err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmp, err := os.CreateTemp(c.opts.StateDir, ".rule-test-*.json")
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	path := tmp.Name()
	defer os.Remove(path)
	_, _ = tmp.Write(data)
	_ = tmp.Close()
	engine, err := waf.New("blocking", 10, false, []string{path})
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	method := strings.TrimSpace(input.Test.Method)
	if method == "" {
		method = http.MethodGet
	}
	u := &url.URL{Path: input.Test.Path, RawQuery: input.Test.Query}
	req := &http.Request{Method: method, URL: u, Header: make(http.Header), Host: "test.example.invalid"}
	for key, value := range input.Test.Headers {
		req.Header.Set(key, value)
	}
	decision := engine.Inspect(waf.RequestData{Request: req, Body: []byte(input.Test.Body)})
	c.audit(r, principal, "rules.test", "rules/preview", "success", map[string]any{"matched": len(decision.Matches), "score": decision.Score})
	writeJSON(w, http.StatusOK, decision)
}

func validateRuleBytes(destination string, data []byte) error {
	if len(data) > maxRuleFileBytes {
		return errors.New("rule file exceeds 4 MiB")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".rules-candidate-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_, err = waf.New("detect", 10, false, []string{name})
	return err
}

func (c *Controller) applyRuleBytes(data []byte, actor string) (Revision, bool, error) {
	c.configMu.Lock()
	defer c.configMu.Unlock()
	cfg, err := config.Load(c.opts.ConfigPath)
	if err != nil {
		return Revision{}, false, err
	}
	rulePath := c.guiRulesPath()
	included := false
	for _, existing := range cfg.Rules.Files {
		if sameFilePath(cfg.ResolvePath(existing), rulePath) {
			included = true
			break
		}
	}
	if !included {
		cfg.Rules.Files = append(cfg.Rules.Files, rulePath)
	}
	candidate, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return Revision{}, false, err
	}
	candidate = append(candidate, '\n')
	return c.applyBundleLocked(candidate, &data, actor, "GUI rule update")
}

func sameFilePath(a, b string) bool {
	aAbs, aErr := filepath.Abs(a)
	bAbs, bErr := filepath.Abs(b)
	if aErr == nil && bErr == nil {
		return filepath.Clean(aAbs) == filepath.Clean(bAbs)
	}
	return filepath.Clean(a) == filepath.Clean(b)
}
