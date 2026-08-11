package control

import "time"

const stateVersion = 1

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Role        Role      `json:"role"`
	Disabled    bool      `json:"disabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
}

type persistedUser struct {
	User
	PasswordHash string `json:"password_hash"`
}

type persistentState struct {
	Version        int             `json:"version"`
	SetupCompleted bool            `json:"setup_completed"`
	Users          []persistedUser `json:"users"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

type session struct {
	Token     string
	CSRFToken string
	UserID    string
	ExpiresAt time.Time
}

type Principal struct {
	User User `json:"user"`
}

type AuditEvent struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	Actor     string         `json:"actor"`
	Role      Role           `json:"role,omitempty"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Outcome   string         `json:"outcome"`
	RemoteIP  string         `json:"remote_ip,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

type Revision struct {
	ID              string    `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	Actor           string    `json:"actor"`
	Reason          string    `json:"reason"`
	RestartRequired bool      `json:"restart_required,omitempty"`
	IncludesRules   bool      `json:"includes_rules"`
}

type BackupInfo struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Actor     string    `json:"actor"`
	Size      int64     `json:"size"`
}
