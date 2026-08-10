# CherryWAF Threat Model

## Security goals

CherryWAF aims to:

1. Terminate and validate frontend TLS safely.
2. Reject clearly malicious or malformed HTTP requests before they reach an origin.
3. Prevent unbounded request bodies and decompression from exhausting memory.
4. Preserve origin TLS verification by default.
5. Prevent untrusted peers from spoofing client addresses through forwarding headers.
6. Keep administration local and authenticated.
7. Fail configuration and certificate reloads without replacing the last valid runtime.
8. Produce auditable security decisions without logging private keys or request bodies.

## Trust boundaries

- The public network and all request metadata are untrusted.
- Forwarding headers are trusted only when the immediate peer belongs to a configured trusted-proxy CIDR.
- Configuration, rule files, CA bundles, certificates, and private keys are trusted administrative inputs and must be protected by operating-system permissions.
- Origins are separate trust domains. HTTPS origins must present a certificate accepted by the configured trust policy.
- The loopback admin API is privileged even though it is not remotely exposed by default.

## Defenses implemented in v0.1

- Go standard-library HTTP parsing and bounded server timeouts
- rejection of ambiguous content-length/transfer-encoding semantics visible to the application
- bounded compressed and decompressed body inspection
- capped normalization rounds for URL and HTML encodings
- anomaly scoring with blocking and detect-only modes
- exact and wildcard host routing with SNI/HTTP Host mismatch rejection
- strict configuration decoding with unknown-field rejection
- SNI certificate selection and certificate/key/domain validation
- origin transports that ignore ambient `HTTP_PROXY`/`HTTPS_PROXY` settings
- private-key permission checks on Unix
- token-bucket rate limiting
- constant-time admin token comparison
- systemd sandboxing and minimum bind capability
- nftables default-deny inbound policy in the appliance

## Explicit non-goals and current limitations

CherryWAF v0.1 is an engineering baseline, not a claim of complete protection against every web attack. It does not yet provide:

- OWASP Core Rule Set or ModSecurity/SecLang compatibility
- HTTP/3 or QUIC termination
- automatic ACME certificate issuance
- distributed rate limiting or clustered configuration state
- CAPTCHA or managed JavaScript challenges
- malware scanning for uploaded files
- semantic JSON/XML/multipart parameter exclusions
- automatic learning or false-positive tuning
- response-body inspection or data-loss prevention
- a browser management console

Native regular expressions use Go's RE2 engine, avoiding catastrophic backtracking, but signatures can still create false positives. New rules should be deployed in detect mode, evaluated against representative traffic, and then promoted to blocking mode.

## Operator responsibilities

- Patch the appliance and rotate administrator credentials.
- Use valid certificates and protect private keys.
- Configure trusted proxies narrowly.
- Keep origin TLS verification enabled.
- Size request limits and rate policies for each application.
- Forward JSON security logs to durable external storage.
- Test fail-open/fail-closed behavior and origin health before production rollout.
- Maintain bypass and recovery procedures outside the appliance.
