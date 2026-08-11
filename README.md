# CherryWAF

CherryWAF is a Go-based reverse-proxy web application firewall with an embedded browser management plane and a hardened Ubuntu Server virtual-appliance build.

It terminates HTTP/HTTPS, selects certificates by SNI, inspects normalized requests, applies anomaly-scored rules, rate-limits abusive clients, and proxies accepted traffic to HTTP or verified HTTPS origins. The standalone **CherryWAF Control Center** manages applications, certificates, policy, custom rules, users, appliance networking, backups, and transactional rollback.

> **Status:** v0.3 engineering baseline. CherryWAF is suitable for development, controlled testing, pilot deployments, and appliance prototyping. It is not yet a drop-in replacement for a mature OWASP CRS deployment or a completed enterprise WAF product.

## Highlights

### Data plane

- HTTP and HTTPS reverse proxy
- TLS 1.2/1.3 policy and SNI certificate selection
- exact and one-label wildcard domains
- frontend TLS termination and origin TLS re-encryption
- custom origin SNI and private CA bundles
- bounded request-body inspection and multi-round normalization
- native SQLi, XSS, traversal, command-injection, SSTI, scanner, and sensitive-file detections
- anomaly scoring with detect and blocking modes
- local per-client token-bucket rate limiting
- multi-origin server pools with round-robin, weighted, least-connections, source-IP, primary/backup, and random selection
- active HTTP/TCP health checks, passive failure tracking, retry, persistence, and content-based pool routing
- per-application WAF, rate-limit, access-list, bot, redirect, discard, and fail-open/fail-closed policies
- global IP/CIDR reputation monitoring or blocking from inline entries and local feed files
- trusted-proxy-aware client IP extraction
- SNI/HTTP Host mismatch protection
- JSON Lines access and security events
- Prometheus-format metrics
- authenticated loopback administration API and hot reload

### Control Center

- first-boot administrator claim using a console setup code
- local login with salted PBKDF2 password hashes
- `admin`, `operator`, and read-only `viewer` roles
- CSRF-protected sessions and hardened browser security headers
- dashboard and protected-application editor
- Server Pools, Virtual Services, and Threat Intelligence workspaces
- frontend listener and origin TLS configuration
- certificate upload, hostname validation, replacement, and usage protection
- visual RE2 rule editor and synthetic request testing
- WAF policy and rate-limit editor
- Netplan configuration through a root helper with automatic timed rollback
- automatic configuration revisions, manual ZIP backups, and restore
- user management and JSONL audit trail
- advanced raw JSON configuration editor

### Appliance

- Ubuntu Server 26.04 LTS amd64
- QCOW2 target for Proxmox/KVM
- VMware-compatible OVA export path
- systemd sandboxing and non-root data/control services
- nftables, auditd, qemu-guest-agent, and unattended security updates
- unique WAF token, setup code, management TLS key, machine ID, and SSH host keys per cloned VM

## Architecture

```text
Administrator browser
        │ HTTPS :9443
        ▼
┌──────────────────────────────────────┐
│ CherryWAF Control Center            │
│ Login / RBAC / CSRF / Audit         │
│ Apps / TLS / Policy / Rules         │
│ Revisions / Backup / Network UI     │
└──────────────┬───────────────────────┘
               │ loopback API + Unix socket
        ┌──────┴──────────┐
        ▼                 ▼
 WAF admin API       cherrywaf-netd
 127.0.0.1:9090      privileged fixed actions
        │
        ▼
Internet ──HTTP/HTTPS──> CherryWAF data plane ──HTTP/verified HTTPS──> Origin
                         :80 / :443
```

The synchronous request path has no GUI, database, network-helper, or LLM dependency. A Control Center failure does not stop the WAF data plane from serving its currently loaded configuration.

## Repository layout

```text
cmd/cherrywaf/                 WAF data plane
cmd/cherrywafctl/              Local certificate and virtual-host CLI
cmd/cherrywaf-control/         Browser management server
cmd/cherrywaf-netd/            Privileged fixed-function network helper
internal/app/                  WAF listeners, request lifecycle, reload, admin API
internal/certstore/            Certificate validation and SNI store
internal/config/               Strict JSON configuration
internal/control/              Authentication, RBAC, API, revisions, backup, embedded UI
internal/core/                 Immutable WAF runtime and virtual-host routing
internal/proxy/                Reverse proxy and origin TLS
internal/waf/                  Normalization, rules, and anomaly scoring
configs/                       Example, Docker, and appliance configurations
rules/                         Custom rule examples
deployments/systemd/           Hardened appliance services and socket units
appliance/                     Ubuntu 26.04 Packer build and image hardening
docs/                          Architecture, threat model, Control Center, appliance notes
```

## Build and test

Requirements:

- Go 1.26.5 for the pinned release toolchain
- Node.js only for JavaScript syntax checking during development/CI
- Docker with Compose for the container smoke test
- Packer and QEMU/KVM only for virtual-appliance builds

```bash
make fmt
make vet
make test
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

Validate a configuration:

```bash
CHERRYWAF_ADMIN_TOKEN=development-only \
  ./dist/cherrywaf validate-config \
  --config ./configs/cherrywaf.example.json
```

## Docker data-plane demonstration

The Compose project demonstrates the WAF data plane and a test origin. The appliance Control Center is intentionally not required for this smoke test.

```bash
docker compose up --build -d
./scripts/smoke-test.sh
docker compose logs -f cherrywaf
```

Direct HTTPS test:

```bash
curl --insecure --resolve app.example.test:8443:127.0.0.1 \
  https://app.example.test:8443/
```

## Control Center access

On an appliance, open:

```text
https://APPLIANCE-IP:9443
```

The console displays the one-time first-boot setup code. There is no embedded default GUI password.

Main screens:

```text
Overview
Applications
Server Pools
Virtual Services
WAF Policy
Threat Intelligence
Rule Studio
Certificates
Network
Backup & Rollback
Users & Roles
Audit Log
Raw Configuration
```

See [Control Center design and API](docs/CONTROL_CENTER.md).

## Configuration transactions

Configuration and GUI rule changes use a validate-before-apply workflow:

```text
Candidate input
   ↓
Strict parse and full validation
   ↓
Create safety revision
   ↓
Atomic write
   ↓
Hot reload WAF
   ↓
Success, restart-required, or automatic rollback
```

Listener-set changes may require an explicit `cherrywaf.service` restart. The Control Center remains available on port 9443 while only the data plane restarts.

## Certificates

The CLI remains available for local administration:

```bash
sudo cherrywafctl cert validate \
  --domain app.example.com \
  --cert ./fullchain.pem \
  --key ./privkey.pem

sudo cherrywafctl cert install \
  --domain app.example.com \
  --cert ./fullchain.pem \
  --key ./privkey.pem \
  --owner root \
  --group cherrywaf
```

The Control Center can also install managed PEM certificate/key pairs and assign their paths to virtual hosts. Private-key bytes are never returned by its API.

## Custom rules

Rule files use versioned JSON:

```json
{
  "version": 1,
  "rules": [
    {
      "id": "LOCAL-200001",
      "name": "Block exposed internal path",
      "description": "Example local policy",
      "enabled": true,
      "targets": ["path"],
      "pattern": "(?i)^/internal/debug(?:/|$)",
      "score": 20,
      "action": "block",
      "severity": "critical"
    }
  ]
}
```

Supported targets are `method`, `path`, `query`, `headers`, `cookies`, and `body`. Supported actions are `score`, `block`, and `log`. Patterns use Go's RE2 engine.

## Ubuntu 26.04 virtual appliance

```bash
cp appliance/packer/variables.pkrvars.hcl.example \
   appliance/packer/variables.pkrvars.hcl

make appliance
```

Expected artifacts:

```text
CherryWAF-VERSION-ubuntu-26.04-amd64.qcow2
CherryWAF-VERSION-ubuntu-26.04.ova
SHA256SUMS
```

The actual QCOW2/OVA build requires a Linux KVM/QEMU host. GitHub Actions includes a manually triggered workflow intended for a self-hosted runner labelled `self-hosted`, `linux`, `x64`, and `kvm`.

See [Ubuntu 26.04 appliance notes](docs/APPLIANCE_UBUNTU_26_04.md) and [appliance build instructions](appliance/README.md).

## Security boundaries

- The WAF admin API remains loopback-only.
- The Control Center runs as the unprivileged `cherrywaf` user.
- Network and service restart operations are fixed endpoints exposed through a group-restricted Unix socket.
- Network changes require explicit confirmation and automatically roll back when connectivity is lost.
- Backups exclude certificate private keys, password hashes, session tokens, audit logs, and WAF admin tokens.
- Deploy new policies in detect mode against representative traffic before enabling blocking.

Read [SECURITY.md](SECURITY.md) and [Threat Model](docs/THREAT_MODEL.md) before exposing a pilot appliance.

## Current limitations

- no OWASP CRS/SecLang compatibility yet
- no ACME/Let's Encrypt issuance or automatic renewal
- no response-body inspection
- no distributed rate-limit or reputation state
- no managed browser challenge or advanced bot engine
- no TOTP/WebAuthn, OIDC, SAML, or directory integration
- no generic L4 TCP/UDP virtual services, GSLB, DNS authority, LinkProof, or multi-node HA/config synchronization yet
- no complete private-key disaster-recovery export
- no independent security audit or production performance certification yet

## Roadmap

1. OWASP CRS-compatible engine integration and granular exclusions
2. structured JSON, XML, form, and multipart parameter inspection
3. ACME issuance and renewal with clustered certificate coordination
4. application health checks and multi-origin load balancing
5. Redis-backed distributed limits and reputation cache
6. ClickHouse/SIEM event pipeline and asynchronous AI triage
7. MFA, external identity providers, signed configuration bundles, and HA control-plane replication
8. benchmark suites for throughput, latency, bypasses, and false positives

## License

A project license has not yet been selected. Until a license is added, normal copyright rules apply.
