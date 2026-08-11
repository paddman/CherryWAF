package control

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Options struct {
	ConfigPath    string
	StateDir      string
	NetworkSocket string
	Runtime       RuntimeClient
	Build         map[string]string
	SetupToken    string
}

type Controller struct {
	opts     Options
	store    *store
	configMu sync.Mutex
}

func New(opts Options) (*Controller, error) {
	if strings.TrimSpace(opts.ConfigPath) == "" {
		return nil, errors.New("control config path is required")
	}
	if strings.TrimSpace(opts.StateDir) == "" {
		opts.StateDir = filepath.Join(filepath.Dir(opts.ConfigPath), "control")
	}
	st, err := openStore(opts.StateDir)
	if err != nil {
		return nil, err
	}
	return &Controller{opts: opts, store: st}, nil
}

func (c *Controller) Handler() http.Handler {
	mux := http.NewServeMux()
	assets, err := fs.Sub(webAssets, "web")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(assets))))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, readErr := fs.ReadFile(assets, "index.html")
		if readErr != nil {
			writeAPIError(w, http.StatusInternalServerError, "web UI is unavailable")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})

	mux.HandleFunc("GET /api/v1/setup/status", c.handleSetupStatus)
	mux.HandleFunc("POST /api/v1/setup/complete", c.handleSetupComplete)
	mux.HandleFunc("POST /api/v1/auth/login", c.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", c.require(RoleViewer, true, c.handleLogout))
	mux.HandleFunc("GET /api/v1/auth/me", c.require(RoleViewer, false, c.handleMe))
	mux.HandleFunc("GET /api/v1/dashboard", c.require(RoleViewer, false, c.handleDashboard))

	mux.HandleFunc("GET /api/v1/config", c.require(RoleViewer, false, c.handleConfigGet))
	mux.HandleFunc("POST /api/v1/config/validate", c.require(RoleOperator, true, c.handleConfigValidate))
	mux.HandleFunc("PUT /api/v1/config", c.require(RoleAdmin, true, c.handleConfigApply))
	mux.HandleFunc("GET /api/v1/revisions", c.require(RoleViewer, false, c.handleRevisionList))
	mux.HandleFunc("POST /api/v1/revisions/{id}/restore", c.require(RoleAdmin, true, c.handleRevisionRestore))

	mux.HandleFunc("GET /api/v1/rules", c.require(RoleViewer, false, c.handleRulesGet))
	mux.HandleFunc("PUT /api/v1/rules", c.require(RoleOperator, true, c.handleRulesApply))
	mux.HandleFunc("POST /api/v1/rules/test", c.require(RoleOperator, true, c.handleRulesTest))

	mux.HandleFunc("GET /api/v1/certificates", c.require(RoleViewer, false, c.handleCertificateList))
	mux.HandleFunc("POST /api/v1/certificates", c.require(RoleAdmin, true, c.handleCertificateUpload))
	mux.HandleFunc("DELETE /api/v1/certificates/{domain}", c.require(RoleAdmin, true, c.handleCertificateDelete))

	mux.HandleFunc("GET /api/v1/network", c.require(RoleViewer, false, c.handleNetworkStatus))
	mux.HandleFunc("POST /api/v1/network/validate", c.require(RoleAdmin, true, c.handleNetworkValidate))
	mux.HandleFunc("POST /api/v1/network/apply", c.require(RoleAdmin, true, c.handleNetworkApply))
	mux.HandleFunc("POST /api/v1/network/confirm", c.require(RoleAdmin, true, c.handleNetworkConfirm))
	mux.HandleFunc("POST /api/v1/network/rollback", c.require(RoleAdmin, true, c.handleNetworkRollback))
	mux.HandleFunc("POST /api/v1/system/restart-waf", c.require(RoleAdmin, true, c.handleWAFRestart))

	mux.HandleFunc("GET /api/v1/users", c.require(RoleAdmin, false, c.handleUsersList))
	mux.HandleFunc("POST /api/v1/users", c.require(RoleAdmin, true, c.handleUsersCreate))
	mux.HandleFunc("PUT /api/v1/users/{id}", c.require(RoleAdmin, true, c.handleUsersUpdate))
	mux.HandleFunc("DELETE /api/v1/users/{id}", c.require(RoleAdmin, true, c.handleUsersDelete))

	mux.HandleFunc("GET /api/v1/backups", c.require(RoleAdmin, false, c.handleBackupList))
	mux.HandleFunc("POST /api/v1/backups", c.require(RoleAdmin, true, c.handleBackupCreate))
	mux.HandleFunc("GET /api/v1/backups/{id}/download", c.require(RoleAdmin, false, c.handleBackupDownload))
	mux.HandleFunc("POST /api/v1/backups/{id}/restore", c.require(RoleAdmin, true, c.handleBackupRestore))
	mux.HandleFunc("DELETE /api/v1/backups/{id}", c.require(RoleAdmin, true, c.handleBackupDelete))
	mux.HandleFunc("GET /api/v1/audit", c.require(RoleAdmin, false, c.handleAuditList))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

type authedHandler func(http.ResponseWriter, *http.Request, Principal)

func (c *Controller) require(minimum Role, csrf bool, next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, sess, ok := c.principal(r)
		if !ok {
			writeAPIError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if roleLevel(principal.User.Role) < roleLevel(minimum) {
			writeAPIError(w, http.StatusForbidden, "insufficient permissions")
			return
		}
		if csrf {
			provided := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
			if provided == "" || provided != sess.CSRFToken {
				writeAPIError(w, http.StatusForbidden, "invalid CSRF token")
				return
			}
		}
		next(w, r, principal)
	}
}

func (c *Controller) principal(r *http.Request) (Principal, session, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return Principal{}, session{}, false
	}
	return c.store.sessionPrincipal(cookie.Value)
}

func (c *Controller) audit(r *http.Request, principal Principal, action, resource, outcome string, details map[string]any) {
	actor := principal.User.Username
	if actor == "" {
		actor = "anonymous"
	}
	_ = c.store.appendAudit(AuditEvent{Actor: actor, Role: principal.User.Role, Action: action, Resource: resource, Outcome: outcome, RemoteIP: remoteIP(r), Details: details})
}

func (c *Controller) handleSetupStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"setup_required": !c.store.setupCompleted(), "setup_token_required": strings.TrimSpace(c.opts.SetupToken) != "", "product": "CherryWAF Control Center", "version": 2, "build": c.opts.Build})
}

func (c *Controller) handleSetupComplete(w http.ResponseWriter, r *http.Request) {
	if c.store.setupCompleted() {
		writeAPIError(w, http.StatusConflict, "first-boot setup is already complete")
		return
	}
	var input struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		SetupToken  string `json:"setup_token"`
	}
	if err := decodeJSON(r, &input, 64<<10); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if expected := strings.TrimSpace(c.opts.SetupToken); expected != "" {
		provided := strings.TrimSpace(input.SetupToken)
		if len(provided) != len(expected) || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			_ = c.store.appendAudit(AuditEvent{Actor: "anonymous", Action: "setup.complete", Resource: "system", Outcome: "failure", RemoteIP: remoteIP(r), Details: map[string]any{"reason": "invalid setup token"}})
			writeAPIError(w, http.StatusUnauthorized, "invalid first-boot setup code")
			return
		}
	}
	user, err := c.store.createInitialAdmin(input.Username, input.DisplayName, input.Password)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, err := c.store.createSession(user.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to create session")
		return
	}
	setSessionCookie(w, r, sess)
	principal := Principal{User: user}
	c.audit(r, principal, "setup.complete", "system", "success", nil)
	writeJSON(w, http.StatusCreated, map[string]any{"user": user, "csrf_token": sess.CSRFToken, "expires_at": sess.ExpiresAt})
}

func (c *Controller) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !c.store.setupCompleted() {
		writeAPIError(w, http.StatusPreconditionRequired, "first-boot setup is required")
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &input, 64<<10); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := c.store.authenticate(input.Username, input.Password, remoteIP(r))
	if err != nil {
		_ = c.store.appendAudit(AuditEvent{Actor: strings.ToLower(strings.TrimSpace(input.Username)), Action: "auth.login", Resource: "session", Outcome: "failure", RemoteIP: remoteIP(r)})
		writeAPIError(w, http.StatusUnauthorized, err.Error())
		return
	}
	sess, err := c.store.createSession(user.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "unable to create session")
		return
	}
	setSessionCookie(w, r, sess)
	principal := Principal{User: user}
	c.audit(r, principal, "auth.login", "session", "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "csrf_token": sess.CSRFToken, "expires_at": sess.ExpiresAt})
}

func (c *Controller) handleLogout(w http.ResponseWriter, r *http.Request, principal Principal) {
	cookie, _ := r.Cookie(sessionCookie)
	if cookie != nil {
		c.store.deleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	c.audit(r, principal, "auth.logout", "session", "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "logged_out"})
}

func (c *Controller) handleMe(w http.ResponseWriter, r *http.Request, principal Principal) {
	_, sess, ok := c.principal(r)
	csrf := ""
	if ok {
		csrf = sess.CSRFToken
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": principal.User, "csrf_token": csrf, "expires_at": sess.ExpiresAt})
}

func (c *Controller) handleDashboard(w http.ResponseWriter, r *http.Request, _ Principal) {
	response := map[string]any{"product": "CherryWAF", "control_build": c.opts.Build, "runtime_available": false}
	if c.opts.Runtime != nil {
		status, err := c.opts.Runtime.Status(r.Context())
		if err == nil {
			response["runtime_available"] = true
			response["runtime"] = status
		} else {
			response["runtime_error"] = err.Error()
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (c *Controller) handleWAFRestart(w http.ResponseWriter, r *http.Request, principal Principal) {
	var response any
	if err := c.networkRequest(http.MethodPost, "/v1/restart-waf", map[string]any{}, &response); err != nil {
		c.audit(r, principal, "service.restart", "service/cherrywaf", "failure", map[string]any{"error": err.Error()})
		writeAPIError(w, http.StatusServiceUnavailable, "privileged appliance helper failed: "+err.Error())
		return
	}
	c.audit(r, principal, "service.restart", "service/cherrywaf", "success", nil)
	writeJSON(w, http.StatusOK, response)
}

func (c *Controller) handleUsersList(w http.ResponseWriter, _ *http.Request, _ Principal) {
	writeJSON(w, http.StatusOK, map[string]any{"users": c.store.users()})
}

func (c *Controller) handleUsersCreate(w http.ResponseWriter, r *http.Request, principal Principal) {
	var input struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		Role        Role   `json:"role"`
	}
	if err := decodeJSON(r, &input, 64<<10); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := c.store.createUser(input.Username, input.DisplayName, input.Password, input.Role)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.audit(r, principal, "user.create", "user/"+user.ID, "success", map[string]any{"username": user.Username, "role": user.Role})
	writeJSON(w, http.StatusCreated, user)
}

func (c *Controller) handleUsersUpdate(w http.ResponseWriter, r *http.Request, principal Principal) {
	id := r.PathValue("id")
	var update userUpdate
	if err := decodeJSON(r, &update, 64<<10); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := c.store.updateUser(id, update, principal.User.ID)
	if errors.Is(err, os.ErrNotExist) {
		writeAPIError(w, http.StatusNotFound, "user not found")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.audit(r, principal, "user.update", "user/"+id, "success", map[string]any{"username": user.Username, "role": user.Role, "disabled": user.Disabled})
	writeJSON(w, http.StatusOK, user)
}

func (c *Controller) handleUsersDelete(w http.ResponseWriter, r *http.Request, principal Principal) {
	id := r.PathValue("id")
	if err := c.store.deleteUser(id, principal.User.ID); errors.Is(err, os.ErrNotExist) {
		writeAPIError(w, http.StatusNotFound, "user not found")
		return
	} else if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.audit(r, principal, "user.delete", "user/"+id, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func (c *Controller) handleAuditList(w http.ResponseWriter, r *http.Request, _ Principal) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := c.store.readAudit(limit)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, sess session) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sess.Token, Path: "/", Expires: sess.ExpiresAt, MaxAge: int(time.Until(sess.ExpiresAt).Seconds()), HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

func decodeJSON(r *http.Request, target any, limit int64) error {
	data, err := readBody(r, limit)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return errors.New("invalid JSON: " + err.Error())
	}
	if err := ensureEOF(dec); err != nil {
		return errors.New("invalid JSON: " + err.Error())
	}
	return nil
}

func readBody(r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, errors.New("request body is required")
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("request body is too large")
	}
	return data, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}
