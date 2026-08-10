# CherryWAF Architecture

## Request path

```text
Client
  │ HTTP/HTTPS
  ▼
Listener and TLS termination
  │
  ▼
Virtual-host routing by Host/SNI
  │
  ├─ Request framing checks
  ├─ Bounded body capture/decompression
  ├─ Multi-stage normalization
  ├─ Native rule evaluation and anomaly scoring
  ├─ Per-client rate limiting
  └─ Structured security event logging
  │
  ▼
Reverse proxy
  │ HTTP or verified HTTPS
  ▼
Origin application
```

CherryWAF is split into a data path and a local control surface. The request path does not call an LLM, external reputation service, or database synchronously. Those integrations can consume security events asynchronously without adding an uncontrolled dependency to every web request.

## Packages

| Package | Responsibility |
|---|---|
| `internal/app` | HTTP/TLS listeners, request lifecycle, admin API, reloads |
| `internal/core` | Immutable runtime construction and route table |
| `internal/config` | Strict JSON configuration parsing and validation |
| `internal/certstore` | PEM loading, key matching, hostname and lifetime validation, SNI selection |
| `internal/waf` | Normalization, native rules, anomaly scoring, decisions |
| `internal/proxy` | Reverse proxy and origin TLS policy |
| `internal/ratelimit` | In-memory token buckets with idle eviction |
| `internal/netutil` | Trusted-proxy-aware client IP extraction |
| `internal/logging` | JSON Lines access and security event output |
| `internal/metrics` | In-process counters and Prometheus exposition |

## Runtime and reload model

Configuration, rules, certificates, route tables, origin transports, and log writers are built into an immutable runtime. A reload validates the complete replacement runtime before atomically publishing it. Requests that already captured the old runtime continue to completion. Listener address or enablement changes require a service restart.

## TLS model

Frontend TLS terminates at CherryWAF so HTTP semantics can be inspected. Certificate selection uses SNI and supports exact domains and one-label wildcards. When SNI is present, it must match the routed HTTP Host, preventing cross-virtual-host domain fronting. Certificate/private-key matching, validity periods, private-key permissions, and configured DNS coverage are checked before startup or reload.

Origin connections may use HTTP or HTTPS. HTTPS verification is enabled by default and can use the system trust store plus an optional private CA bundle. Origin SNI can be configured independently from the public hostname. Origin transports connect directly and deliberately ignore ambient HTTP proxy environment variables.

## Storage model

The v0.1 core has no mandatory database dependency. Configuration and certificates are local files; access and security events are JSON Lines. This keeps a single appliance deterministic and recoverable. A later clustered control plane can distribute signed configuration snapshots and aggregate logs without changing the request-path interface.

## Deployment forms

- Static Linux binaries
- Rootless runtime container
- Docker Compose demonstration
- systemd service on Linux
- Ubuntu Server 24.04.4 LTS QCOW2 appliance
- VMware-compatible OVA conversion path
