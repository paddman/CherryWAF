# Security Policy

## Supported versions

The project is in an initial pre-1.0 development phase. Security fixes are applied to the current `main` branch and the latest tagged release.

## Reporting a vulnerability

Do not publish exploitable details in a public issue. Use GitHub private vulnerability reporting for this repository when available. Include:

- affected version or commit
- deployment mode
- reproduction steps or a minimal request
- expected and observed behavior
- security impact
- suggested mitigation, when known

Do not include real customer credentials, private keys, access tokens, or production request bodies.

## Scope

Reports about request parsing, rule bypass, certificate selection, origin TLS validation, authentication, privilege boundaries, memory exhaustion, and appliance hardening are in scope. Generic false positives without a minimal reproduction are treated as tuning reports rather than vulnerabilities.
