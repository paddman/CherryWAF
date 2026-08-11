# CherryWAF Control Center v0.2

CherryWAF Control Center is the embedded browser-based management plane for a CherryWAF appliance. It is intentionally isolated from the HTTP/HTTPS data plane: a Control Center failure must not interrupt protected application traffic.

## Services and ports

| Component | Service | Listener | Purpose |
|---|---|---:|---|
| WAF data plane | `cherrywaf.service` | `80`, `443` | Inspect and proxy application traffic |
| WAF local API | part of `cherrywaf.service` | `127.0.0.1:9090` | Status, metrics, and hot reload |
| Control Center | `cherrywaf-control.service` | `9443/tcp` | Web GUI, authentication, policy management |
| Network helper | `cherrywaf-netd.socket` | Unix socket | Privileged Netplan changes with rollback |
| First-boot initializer | `cherrywaf-firstboot.service` | none | Unique token and management TLS generation |

Open the management UI at:

```text
https://APPLIANCE-IP:9443
```

The first certificate is appliance-local and self-signed. Replace or trust it according to the organization's management-PKI policy.

## First-boot workflow

1. The appliance generates a unique WAF admin token and a unique management TLS key pair.
2. The appliance console displays a one-time first-boot setup code.
3. The browser opens the administrator wizard and requires that console code.
4. The administrator configures DHCP or a static management address.
5. The administrator installs a frontend certificate, adds an application, and selects detect or blocking mode.

No default Control Center password is embedded in the image.

## Roles

| Role | Access |
|---|---|
| `viewer` | Read dashboard, applications, policy, rules, certificates, and network status |
| `operator` | Viewer access plus custom-rule editing and rule testing |
| `admin` | Full configuration, certificate, network, backup, user, and audit management |

Control Center enforces the following safeguards:

- At least one enabled administrator must remain.
- An administrator cannot delete, disable, or demote their own account.
- Passwords use salted PBKDF2-HMAC-SHA256 hashes.
- Sessions use `HttpOnly`, `SameSite=Strict` cookies and CSRF tokens.
- Repeated login failures trigger temporary lockout.
- Audit records cover authentication and every privileged change.

## Configuration transactions

A GUI configuration change follows this sequence:

1. Parse and normalize the candidate JSON.
2. Validate the complete WAF configuration and referenced rule/certificate files.
3. Create a safety revision of the active configuration and GUI rule file.
4. Atomically write the candidate.
5. Request a WAF hot reload over the loopback API.
6. Automatically restore and reload the previous revision when the reload fails.

Listener changes that cannot be hot-reloaded are saved as valid configuration and returned with `restart_required=true`. An administrator can then restart only `cherrywaf.service` from the Control Center through the fixed-function privileged helper; the management UI remains online.

## Visual Rule Studio

The Rule Studio manages the native versioned rule file at:

```text
/var/lib/cherrywaf/control/rules/gui-rules.json
```

Supported targets are:

```text
method, path, query, headers, cookies, body
```

Supported actions are:

```text
score, block, log
```

Patterns use Go's RE2 regular-expression engine. The test dialog evaluates one rule against a synthetic request without sending traffic to an origin.

## Certificates

The certificate screen accepts PEM full chains and matching PEM private keys. Before installation, Control Center validates:

- certificate/private-key pairing;
- certificate lifetime;
- exact or one-label wildcard hostname coverage;
- private-key filesystem permissions.

Managed certificates are stored below:

```text
/var/lib/cherrywaf/control/certificates/
```

Private-key bytes are never returned by the API. A certificate referenced by a virtual host cannot be deleted.

## Safe network configuration

Control Center does not run as root. Network changes are delegated to `cherrywaf-netd` through a group-restricted Unix socket. The helper validates and renders a Netplan document, backs up the active file, schedules a transient systemd rollback unit, applies the change, and returns a confirmation deadline.

The administrator must reconnect and confirm the change within 60 seconds. Otherwise the previous Netplan file is restored and applied automatically.

The helper accepts only local Unix peers running as `root` or the `cherrywaf` service user.

## Backup and rollback

Manual ZIP backups contain:

```text
config/cherrywaf.json
rules/gui-rules.json   # when present
manifest.json
```

They intentionally exclude:

- certificate private keys;
- Control Center users and password hashes;
- session tokens;
- audit logs;
- appliance host keys and WAF admin tokens.

Safety revisions are captured automatically before configuration and rule changes. The appliance retains the most recent 50 revisions.

## Main API routes

```text
GET  /api/v1/setup/status
POST /api/v1/setup/complete
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me
GET  /api/v1/dashboard

GET  /api/v1/config
POST /api/v1/config/validate
PUT  /api/v1/config
GET  /api/v1/revisions
POST /api/v1/revisions/{id}/restore

GET  /api/v1/rules
PUT  /api/v1/rules
POST /api/v1/rules/test

GET    /api/v1/certificates
POST   /api/v1/certificates
DELETE /api/v1/certificates/{domain}

GET  /api/v1/network
POST /api/v1/network/validate
POST /api/v1/network/apply
POST /api/v1/network/confirm
POST /api/v1/network/rollback
POST /api/v1/system/restart-waf

GET    /api/v1/backups
POST   /api/v1/backups
GET    /api/v1/backups/{id}/download
POST   /api/v1/backups/{id}/restore
DELETE /api/v1/backups/{id}

GET    /api/v1/users
POST   /api/v1/users
PUT    /api/v1/users/{id}
DELETE /api/v1/users/{id}
GET    /api/v1/audit
```

## Build

The frontend is embedded in the Go binary with `go:embed`. No Node.js runtime is required on the appliance.

```bash
make fmt
make test
make vet
make webcheck
make build
```

Generated binaries:

```text
dist/cherrywaf
dist/cherrywafctl
dist/cherrywaf-control
dist/cherrywaf-netd
```

## Current limitations

- Management TLS replacement is currently an operating-system task.
- Accounts are local; external OIDC/SAML and directory integration are not yet included.
- TOTP/WebAuthn MFA is not yet included.
- Application health checks and multi-origin load balancing are not yet exposed in Control Center.
- Backups exclude private keys by design and therefore do not represent a complete disaster-recovery export.
