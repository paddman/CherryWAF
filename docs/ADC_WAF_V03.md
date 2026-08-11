# CherryWAF ADC and per-application WAF foundation (v0.3)

CherryWAF v0.3 adds the first application-delivery-controller layer around the existing reverse-proxy WAF. The goal is not to imitate a legacy appliance menu one checkbox at a time. The goal is to provide auditable delivery and security objects that can be composed into virtual services without coupling the browser GUI to the synchronous request path.

## Object model

```text
Virtual Service
├── Domains
├── Action: group | redirect | discard
├── Default Server Pool or direct upstream
├── Content Routes
├── Persistence Profile
├── Frontend TLS
├── Per-application WAF Policy
├── Per-application Rate Limit
├── Bot Policy
├── IP Allow/Deny Policy
└── Request/Response Header Policy

Server Pool
├── Algorithm
├── Failure Mode
├── Members
├── Primary / Backup Role
├── Weight / Priority
├── Per-member Origin TLS
└── HTTP or TCP Health Check
```

## Server-pool algorithms

| Algorithm | Behaviour |
|---|---|
| `round_robin` | Cycles through healthy primary members |
| `weighted_round_robin` | Smooth weighted distribution |
| `least_connections` | Selects the lowest active-connection/weight ratio |
| `source_ip_hash` | Stable source-IP affinity while membership is unchanged |
| `primary_backup` | Selects the lowest-priority healthy primary, then backup |
| `random` | Low-cost pseudo-random selection |

Healthy primary members are preferred. Backup members are selected only when no healthy primary remains. With `failure_mode=reject`, CherryWAF returns HTTP 503 when no healthy member exists. With `last_resort`, an unhealthy member may be attempted after all healthy options are exhausted.

## Health and failover

- Active HTTP checks support GET/HEAD, path, Host override, timeout, thresholds, and expected status range.
- Active TCP checks verify that a connection can be established.
- Transport failures are counted passively and contribute to unhealthy state when health monitoring is enabled.
- Replay-safe requests receive one alternate-member retry.
- Runtime status exposes member health, active connections, requests, failures, last check time, and last error.

## Persistence

- `none`: normal pool algorithm.
- `source_ip`: deterministic source-IP affinity.
- `cookie`: an opaque HMAC-authenticated `HttpOnly` cookie maps the client to a pool member. The cookie contains no origin address or topology details.

Persistence is best-effort. If the selected member is unavailable, normal healthy-member selection resumes.

## Content-based routing

Routes are evaluated in configuration order before default-pool selection. A route can combine:

- HTTP method;
- path prefix;
- path RE2 pattern;
- header name and RE2 pattern;
- query parameter name and RE2 pattern.

Every enabled route targets a named, enabled server pool.

## Per-application WAF policy

A virtual service can:

- inherit global WAF mode and rules;
- override mode with `detect`, `blocking`, or `disabled`;
- override block threshold and inspected-body limit;
- override built-in rules and add rule files;
- define a local rate limit or explicitly disable the global limiter;
- choose WAF engine `fail_mode=open|closed`;
- define IPv4/IPv6 allow and deny entries.

The data plane compiles each dedicated application policy during configuration validation. Runtime request handling does not read configuration files or query a database.

## Bot-policy baseline

The v0.3 bot module is deliberately limited and explainable:

- allow-listed User-Agent RE2 expressions;
- blocked/monitored User-Agent RE2 expressions;
- per-client request-rate anomaly limit;
- monitor or block action.

It is not a substitute for device fingerprinting, JavaScript proof-of-work, behavioural modelling, credential-stuffing detection, or a managed bot-intelligence feed.

## Reputation baseline

Global reputation can load IPv4/IPv6 addresses and CIDRs from inline configuration and local files. Longest-prefix matching is used. The policy supports monitor and block modes. Local files allow an external updater to refresh a feed without placing a remote API call in each request.

## Control Center

The embedded UI adds:

- **Server Pools** for members, algorithms, backup role, origin TLS, and health monitors;
- **Virtual Services** for action, pool binding, persistence, content routes, per-app WAF, bot, access lists, TLS, and header policies;
- **Threat Intelligence** for inline and file-backed reputation entries.

All changes continue to use the existing validate, revision, atomic-write, reload, and automatic-rollback transaction.

## Intentionally not claimed in v0.3

CherryWAF v0.3 does not yet provide:

- generic L4 TCP/UDP virtual services;
- OWASP CRS/SecLang compatibility;
- advanced browser bot challenges or device fingerprinting;
- response-body inspection;
- GSLB or authoritative DNS;
- LinkProof/WAN-link balancing;
- VRRP/floating VIP and multi-node state/configuration synchronisation;
- distributed rate-limit, persistence, or reputation state;
- AppShape-style request/response scripting.

Those are separate engineering programmes, not decorative tabs. Pretending otherwise would produce an impressive menu and a disappointing appliance.
