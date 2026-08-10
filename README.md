# CherryWAF

CherryWAF is a Go-based reverse-proxy web application firewall and virtual appliance project. It terminates HTTP/HTTPS, selects certificates by SNI, inspects normalized requests, applies anomaly-scored rules, rate-limits abusive clients, and proxies allowed traffic to HTTP or verified HTTPS origins.

> **Status:** v0.1 engineering baseline. The repository is suitable for development, controlled testing, and appliance prototyping. It is not yet a drop-in replacement for a mature OWASP CRS deployment.

## Current capabilities

- HTTP and HTTPS reverse proxy
- TLS 1.2/1.3 minimum policy
- multiple virtual hosts on one listener
- exact and one-label wildcard SNI certificates
- certificate/private-key matching, hostname, lifetime, and permission validation
- frontend TLS termination and origin TLS re-encryption
- custom origin SNI and private CA bundle
- native detection rules for common SQLi, XSS, traversal, command injection, SSTI, scanners, and sensitive-file probes
- multi-round URL/HTML normalization with bounded request-body inspection
- blocking and detect-only modes with anomaly scoring
- per-client token-bucket rate limiting
- trusted-proxy-aware client IP extraction
- SNI/HTTP Host mismatch rejection to prevent cross-vhost domain fronting
- direct origin connections that do not inherit process-wide proxy environment variables
- JSON Lines access and security logs
- Prometheus-format local metrics
- authenticated loopback admin status and hot-reload API
- `cherrywafctl` certificate and virtual-host management utility
- rootless Docker demonstration
- hardened systemd service
- Packer build for an Ubuntu Server 24.04.4 LTS QCOW2 appliance
- OVA export path for VMware-compatible imports

## Architecture

```text
Internet
   │ HTTP / HTTPS
   ▼
┌──────────────────────────────────────┐
│ CherryWAF                            │
│  Listener and TLS termination       │
│  Host/SNI virtual-host routing      │
│  Framing and size guards            │
│  Request normalization              │
│  Native rule engine and scoring     │
│  Per-client rate limiting           │
│  JSON security events and metrics   │
└──────────────────┬───────────────────┘
                   │ HTTP or verified HTTPS
                   ▼
                Origin
```

The synchronous request path has no database or LLM dependency. External analytics, SIEM, and AI triage should consume security events asynchronously rather than becoming a fragile requirement for every request.

See [Architecture](docs/ARCHITECTURE.md) and [Threat Model](docs/THREAT_MODEL.md).

## Repository layout

```text
cmd/cherrywaf/             WAF server
cmd/cherrywafctl/          Local control utility
internal/app/              Listeners, request lifecycle, reload and admin API
internal/certstore/        Certificate validation and SNI store
internal/config/           Strict JSON configuration
internal/core/             Immutable runtime and virtual-host routing
internal/proxy/            Reverse proxy and origin TLS
internal/waf/              Normalization, rules and anomaly scoring
configs/                   Example, Docker and appliance configurations
rules/                     Custom rule examples
deployments/docker/        Container image and demo origin
deployments/systemd/       Hardened Linux service files
appliance/                 Packer, autoinstall and appliance hardening
```

## Requirements

- Go 1.26.5 for the release build
- Docker with Compose for the container demonstration
- Packer and QEMU/KVM only when building the virtual appliance

The module has no third-party Go runtime dependencies.

## Build and test

```bash
make fmt
make vet
make test
make build
```

Validate the sample configuration:

```bash
CHERRYWAF_ADMIN_TOKEN=development-only \
  ./dist/cherrywaf validate-config --config ./configs/cherrywaf.example.json
```

Run a local origin on port 8081 and start CherryWAF:

```bash
python3 -m http.server 8081

# In another terminal
CHERRYWAF_ADMIN_TOKEN=development-only \
  ./dist/cherrywaf serve --config ./configs/cherrywaf.example.json

curl -H 'Host: app.example.com' http://127.0.0.1:8080/
curl -i -H 'Host: app.example.com' \
  'http://127.0.0.1:8080/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E'
```

The second request should return HTTP 403 in blocking mode.

## Docker demonstration

```bash
docker compose up --build -d
./scripts/smoke-test.sh
docker compose logs -f cherrywaf
```

The Compose project generates a short-lived development certificate for `app.example.test`, starts a demo origin, and exposes:

| Endpoint | Purpose |
|---|---|
| `http://127.0.0.1:8080` | Redirect to HTTPS |
| `https://127.0.0.1:8443` | CherryWAF demonstration listener |

Direct test:

```bash
curl --insecure --resolve app.example.test:8443:127.0.0.1 \
  https://app.example.test:8443/
```

## Configuration

CherryWAF uses strict JSON. Unknown fields fail validation rather than being silently ignored.

```json
{
  "version": 1,
  "http": {
    "enabled": true,
    "listen": ":80",
    "redirect_to_https": true
  },
  "https": {
    "enabled": true,
    "listen": ":443",
    "min_tls_version": "1.2"
  },
  "admin": {
    "enabled": true,
    "listen": "127.0.0.1:9090",
    "token_env": "CHERRYWAF_ADMIN_TOKEN",
    "allow_public": false
  },
  "security": {
    "mode": "blocking",
    "block_threshold": 10,
    "max_body_bytes": 2097152,
    "max_header_bytes": 1048576,
    "trusted_proxies": ["10.0.0.0/8"],
    "forwarded_for_header": "X-Forwarded-For",
    "rate_limit": {
      "enabled": true,
      "requests_per_second": 100,
      "burst": 250,
      "entry_ttl_seconds": 600
    }
  },
  "rules": {
    "builtins": true,
    "files": ["/etc/cherrywaf/rules/custom.json"]
  },
  "logging": {
    "access_file": "/var/log/cherrywaf/access.jsonl",
    "security_file": "/var/log/cherrywaf/security.jsonl"
  },
  "virtual_hosts": [
    {
      "name": "app",
      "enabled": true,
      "domains": ["app.example.com"],
      "upstream": "https://10.10.10.20:443",
      "preserve_host": true,
      "frontend_tls": {
        "certificate_file": "/etc/cherrywaf/certs/app.example.com/fullchain.pem",
        "private_key_file": "/etc/cherrywaf/certs/app.example.com/privkey.pem"
      },
      "origin_tls": {
        "server_name": "origin.internal.example.com",
        "ca_file": "/etc/cherrywaf/ca/internal-ca.pem",
        "insecure_skip_verify": false
      },
      "response_headers": {
        "X-Content-Type-Options": "nosniff"
      }
    }
  ]
}
```

## Install and validate a certificate

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

Add or replace a virtual host:

```bash
sudo cherrywafctl vhost upsert \
  --name app \
  --domain app.example.com \
  --upstream https://10.10.10.20:443 \
  --origin-server-name origin.internal.example.com \
  --cert /etc/cherrywaf/certs/app.example.com/fullchain.pem \
  --key /etc/cherrywaf/certs/app.example.com/privkey.pem
```

If HTTPS was already running, reload without dropping the listeners:

```bash
sudo systemctl reload cherrywaf
```

Enabling HTTPS for the first time changes the listener set and requires:

```bash
sudo systemctl restart cherrywaf
```

## Admin and metrics endpoints

The admin listener defaults to loopback only.

```bash
curl http://127.0.0.1:9090/healthz
curl http://127.0.0.1:9090/readyz
curl http://127.0.0.1:9090/metrics

curl -H "Authorization: Bearer $CHERRYWAF_ADMIN_TOKEN" \
  http://127.0.0.1:9090/api/v1/status

curl -X POST -H "Authorization: Bearer $CHERRYWAF_ADMIN_TOKEN" \
  http://127.0.0.1:9090/api/v1/reload
```

Do not expose this listener publicly merely because it has a token. Loopback, SSH forwarding, or a separately authenticated management network is the intended model.

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

Supported targets are `method`, `path`, `query`, `headers`, `cookies`, and `body`. Supported actions are `score`, `block`, and `log`. Go's RE2 regular-expression engine is used, so catastrophic backtracking constructs are not available.

## Appliance

The first appliance target is **Ubuntu Server 24.04.4 LTS Minimal with the GA kernel**. It creates a QCOW2 image for Proxmox/KVM, installs a hardened systemd service, enables nftables and unattended security updates, and includes an OVA conversion script.

```bash
cp appliance/packer/variables.pkrvars.hcl.example \
   appliance/packer/variables.pkrvars.hcl
# Fill the password hash and SSH key paths.
make appliance
```

See [Appliance build and deployment](appliance/README.md).

## Security limitations in v0.1

The current native engine is intentionally small and auditable. It does not yet include OWASP CRS/SecLang compatibility, automatic ACME, distributed state, response-body inspection, managed bot challenges, file malware scanning, or a browser control plane. Deploy first in detect mode against representative traffic, tune false positives, and then enable blocking.

See [SECURITY.md](SECURITY.md) before reporting exploitable behavior.

## Roadmap

1. OWASP CRS-compatible engine integration and rule exclusions
2. structured JSON, XML, form, and multipart parameter inspection
3. ACME issuance and automatic certificate renewal
4. signed configuration bundles and clustered control plane
5. Redis-backed distributed limits and reputation cache
6. ClickHouse/SIEM event pipeline and asynchronous AI triage
7. web management console, RBAC, audit trail, backup and restore
8. benchmark suite for throughput, latency, bypasses, and false positives

## License

A project license has not yet been selected. Until a license is added, normal copyright rules apply.
