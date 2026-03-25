
# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | No        |

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

Email: hello@sentinelgate.co.uk

Include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

You will receive an acknowledgement within the timeframes below.

## Patch SLA

| Severity | Acknowledge | Fix | Disclosure |
|----------|:-----------:|:---:|:----------:|
| **Critical** (auth bypass, RCE, data leak) | 24 hours | 72 hours | Post-fix, with post-mortem |
| **High** (privilege escalation, DoS) | 48 hours | 7 days | Post-fix |
| **Medium** (info disclosure, config issue) | 7 days | 30 days | With next release |

## Security Architecture

SentinelGate is a security proxy in the critical path of every AI agent tool call. Key security properties:

- **TLS 1.2+** for all HTTP connections
- **CSRF protection** with double-submit cookie pattern
- **CSP headers** restricting resource loading
- **Rate limiting** (IP and per-user) to prevent brute-force
- **Input validation** on all JSON-RPC messages
- **Secret redaction** in audit logs and error responses
- **API key hashing** with Argon2id (no plaintext storage)

## Security CI

Every PR and release is automatically scanned by:

| Tool | What it finds |
|------|---------------|
| gosec | Security bugs in Go code (injection, crypto, race conditions) |
| govulncheck | Dependencies with known CVEs |
| gitleaks | Secrets committed to the repository |
| Go fuzz testing | Crashes from malformed input on critical parsers |
