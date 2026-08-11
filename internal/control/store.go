package control

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	stateFileName   = "state.json"
	auditFileName   = "audit.jsonl"
	sessionCookie   = "cherrywaf_session"
	sessionDuration = 8 * time.Hour
)

type loginFailure struct {
	Count        int
	WindowStart  time.Time
	BlockedUntil time.Time
}

type store struct {
	dir       string
	statePath string
	auditPath string

	mu       sync.RWMutex
	auditMu  sync.Mutex
	state    persistentState
	sessions map[string]session
	failures map[string]loginFailure
	now      func() time.Time
}

func openStore(dir string) (*store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("control state directory is empty")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create control state directory: %w", err)
	}
	s := &store{
		dir: dir, statePath: filepath.Join(dir, stateFileName), auditPath: filepath.Join(dir, auditFileName),
		sessions: make(map[string]session), failures: make(map[string]loginFailure), now: time.Now,
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *store) load() error {
	data, err := os.ReadFile(s.statePath)
	if errors.Is(err, os.ErrNotExist) {
		now := s.now().UTC()
		s.state = persistentState{Version: stateVersion, CreatedAt: now, UpdatedAt: now}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read control state: %w", err)
	}
	var state persistentState
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return fmt.Errorf("decode control state: %w", err)
	}
	if err := ensureEOF(dec); err != nil {
		return fmt.Errorf("decode control state: %w", err)
	}
	if state.Version != stateVersion {
		return fmt.Errorf("unsupported control state version %d", state.Version)
	}
	s.state = state
	return nil
}

func cloneState(state persistentState) persistentState {
	copyState := state
	copyState.Users = append([]persistedUser(nil), state.Users...)
	return copyState
}

func (s *store) saveLocked() error {
	s.state.Version = stateVersion
	s.state.UpdatedAt = s.now().UTC()
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode control state: %w", err)
	}
	return writeAtomic(s.statePath, append(data, '\n'), 0o600)
}

func (s *store) setupCompleted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.SetupCompleted && len(s.state.Users) > 0
}

func (s *store) createInitialAdmin(username, displayName, password string) (User, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return User{}, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.SetupCompleted || len(s.state.Users) > 0 {
		return User{}, errors.New("first-boot setup is already complete")
	}
	before := cloneState(s.state)
	now := s.now().UTC()
	user := User{ID: newID(), Username: username, DisplayName: strings.TrimSpace(displayName), Role: RoleAdmin, CreatedAt: now, UpdatedAt: now}
	if user.DisplayName == "" {
		user.DisplayName = "CherryWAF Administrator"
	}
	s.state.Users = []persistedUser{{User: user, PasswordHash: hash}}
	s.state.SetupCompleted = true
	if err := s.saveLocked(); err != nil {
		s.state = before
		return User{}, err
	}
	return user, nil
}

func (s *store) authenticate(username, password, remote string) (User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	key := remote + "|" + username
	now := s.now().UTC()

	// Snapshot the candidate hash while holding the lock, then perform the
	// intentionally expensive PBKDF2 calculation without blocking unrelated
	// sessions, audit reads, or administrator changes.
	s.mu.Lock()
	s.pruneFailuresLocked(now)
	failure := s.failures[key]
	if now.Before(failure.BlockedUntil) {
		s.mu.Unlock()
		return User{}, fmt.Errorf("login temporarily blocked until %s", failure.BlockedUntil.Format(time.RFC3339))
	}
	userID := ""
	encoded := dummyPasswordHash
	for i := range s.state.Users {
		if s.state.Users[i].Username == username {
			userID = s.state.Users[i].ID
			encoded = s.state.Users[i].PasswordHash
			break
		}
	}
	s.mu.Unlock()

	passwordOK := verifyPassword(encoded, password)

	s.mu.Lock()
	defer s.mu.Unlock()
	now = s.now().UTC()
	failure = s.failures[key]
	if now.Before(failure.BlockedUntil) {
		return User{}, fmt.Errorf("login temporarily blocked until %s", failure.BlockedUntil.Format(time.RFC3339))
	}
	index := -1
	for i := range s.state.Users {
		record := &s.state.Users[i]
		if record.ID == userID && record.Username == username && record.PasswordHash == encoded {
			index = i
			break
		}
	}
	valid := index >= 0 && !s.state.Users[index].Disabled && passwordOK
	if !valid {
		if failure.WindowStart.IsZero() || now.Sub(failure.WindowStart) > 15*time.Minute {
			failure = loginFailure{WindowStart: now}
		}
		failure.Count++
		if failure.Count >= 8 {
			failure.BlockedUntil = now.Add(15 * time.Minute)
		}
		s.failures[key] = failure
		return User{}, errors.New("invalid username or password")
	}
	delete(s.failures, key)
	before := cloneState(s.state)
	s.state.Users[index].LastLoginAt = now
	s.state.Users[index].UpdatedAt = now
	if err := s.saveLocked(); err != nil {
		s.state = before
		return User{}, err
	}
	return s.state.Users[index].User, nil
}

func (s *store) createSession(userID string) (session, error) {
	token, err := randomToken(32)
	if err != nil {
		return session{}, err
	}
	csrf, err := randomToken(24)
	if err != nil {
		return session{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	s.pruneSessionsLocked(now)
	sess := session{Token: token, CSRFToken: csrf, UserID: userID, ExpiresAt: now.Add(sessionDuration)}
	s.sessions[token] = sess
	return sess, nil
}

func (s *store) sessionPrincipal(token string) (Principal, session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	s.pruneSessionsLocked(now)
	sess, ok := s.sessions[token]
	if !ok || !now.Before(sess.ExpiresAt) {
		return Principal{}, session{}, false
	}
	for _, record := range s.state.Users {
		if record.ID == sess.UserID && !record.Disabled {
			return Principal{User: record.User}, sess, true
		}
	}
	delete(s.sessions, token)
	return Principal{}, session{}, false
}

func (s *store) deleteSession(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *store) pruneSessionsLocked(now time.Time) {
	for token, sess := range s.sessions {
		if !now.Before(sess.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}

func (s *store) pruneFailuresLocked(now time.Time) {
	if len(s.failures) < 1024 {
		return
	}
	for key, failure := range s.failures {
		windowExpired := !failure.WindowStart.IsZero() && now.Sub(failure.WindowStart) > 30*time.Minute
		blockExpired := failure.BlockedUntil.IsZero() || !now.Before(failure.BlockedUntil)
		if windowExpired && blockExpired {
			delete(s.failures, key)
		}
	}
	// Bound hostile high-cardinality username/IP attempts even when every entry
	// is still inside its lockout window. Exact eviction order is intentionally
	// unimportant; valid credentials still undergo full password verification.
	for len(s.failures) > 8192 {
		for key := range s.failures {
			delete(s.failures, key)
			break
		}
	}
}

func (s *store) users() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]User, 0, len(s.state.Users))
	for _, record := range s.state.Users {
		users = append(users, record.User)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return users
}

func (s *store) createUser(username, displayName, password string, role Role) (User, error) {
	username, err := normalizeUsername(username)
	if err != nil {
		return User{}, err
	}
	if !validRole(role) {
		return User{}, errors.New("role must be admin, operator, or viewer")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, user := range s.state.Users {
		if user.Username == username {
			return User{}, errors.New("username already exists")
		}
	}
	before := cloneState(s.state)
	now := s.now().UTC()
	user := User{ID: newID(), Username: username, DisplayName: strings.TrimSpace(displayName), Role: role, CreatedAt: now, UpdatedAt: now}
	if user.DisplayName == "" {
		user.DisplayName = username
	}
	s.state.Users = append(s.state.Users, persistedUser{User: user, PasswordHash: hash})
	if err := s.saveLocked(); err != nil {
		s.state = before
		return User{}, err
	}
	return user, nil
}

type userUpdate struct {
	DisplayName *string `json:"display_name"`
	Role        *Role   `json:"role"`
	Disabled    *bool   `json:"disabled"`
	Password    *string `json:"password"`
}

func (s *store) updateUser(id string, update userUpdate, actorID string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	for i := range s.state.Users {
		if s.state.Users[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return User{}, os.ErrNotExist
	}
	before := cloneState(s.state)
	record := &s.state.Users[index]
	if update.DisplayName != nil {
		name := strings.TrimSpace(*update.DisplayName)
		if name == "" {
			return User{}, errors.New("display name must not be empty")
		}
		record.DisplayName = name
	}
	if update.Role != nil {
		if !validRole(*update.Role) {
			return User{}, errors.New("invalid role")
		}
		if record.ID == actorID && *update.Role != RoleAdmin {
			return User{}, errors.New("an administrator cannot remove their own admin role")
		}
		record.Role = *update.Role
	}
	if update.Disabled != nil {
		if record.ID == actorID && *update.Disabled {
			return User{}, errors.New("an administrator cannot disable their own account")
		}
		record.Disabled = *update.Disabled
	}
	passwordChanged := false
	if update.Password != nil && *update.Password != "" {
		hash, err := hashPassword(*update.Password)
		if err != nil {
			s.state = before
			return User{}, err
		}
		record.PasswordHash = hash
		passwordChanged = true
	}
	record.UpdatedAt = s.now().UTC()
	if err := s.ensureAdminLocked(); err != nil {
		s.state = before
		return User{}, err
	}
	if err := s.saveLocked(); err != nil {
		s.state = before
		return User{}, err
	}
	if record.Disabled || passwordChanged {
		for token, sess := range s.sessions {
			if sess.UserID == record.ID && (record.ID != actorID || record.Disabled) {
				delete(s.sessions, token)
			}
		}
	}
	return record.User, nil
}

func (s *store) deleteUser(id, actorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == actorID {
		return errors.New("an administrator cannot delete their own account")
	}
	index := -1
	for i := range s.state.Users {
		if s.state.Users[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return os.ErrNotExist
	}
	before := cloneState(s.state)
	s.state.Users = append(s.state.Users[:index], s.state.Users[index+1:]...)
	if err := s.ensureAdminLocked(); err != nil {
		s.state = before
		return err
	}
	if err := s.saveLocked(); err != nil {
		s.state = before
		return err
	}
	for token, sess := range s.sessions {
		if sess.UserID == id {
			delete(s.sessions, token)
		}
	}
	return nil
}

func (s *store) ensureAdminLocked() error {
	for _, user := range s.state.Users {
		if user.Role == RoleAdmin && !user.Disabled {
			return nil
		}
	}
	return errors.New("at least one enabled administrator is required")
}

func (s *store) appendAudit(event AuditEvent) error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if event.ID == "" {
		event.ID = newID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = s.now().UTC()
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(s.auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func (s *store) readAudit(limit int) ([]AuditEvent, error) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	file, err := os.Open(s.auditPath)
	if errors.Is(err, os.ErrNotExist) {
		return []AuditEvent{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var events []AuditEvent
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		var event AuditEvent
		if json.Unmarshal(scanner.Bytes(), &event) == nil {
			events = append(events, event)
			if len(events) > limit {
				events = events[1:]
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	return events, nil
}

func normalizeUsername(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 3 || len(value) > 64 {
		return "", errors.New("username must contain 3 to 64 characters")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return "", errors.New("username may contain only lowercase letters, numbers, dot, dash, and underscore")
	}
	return value, nil
}

func validRole(role Role) bool {
	return role == RoleAdmin || role == RoleOperator || role == RoleViewer
}

func roleLevel(role Role) int {
	switch role {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

func newID() string {
	value, err := randomToken(16)
	if err != nil {
		panic(err)
	}
	return value
}

func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cherrywaf-*")
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

func ensureEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
