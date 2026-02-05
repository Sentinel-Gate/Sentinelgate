# Changelog

All notable changes to Sentinel Gate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-02-04

### Added

#### Observability
- **Prometheus metrics endpoint** (`/metrics`) with `sentinelgate_*` metrics:
  - `sentinelgate_requests_total` (counter)
  - `sentinelgate_request_duration_seconds` (histogram)
  - `sentinelgate_active_sessions` (gauge)
  - `sentinelgate_policy_evaluations_total` (counter)
  - `sentinelgate_audit_drops_total` (counter)
  - `sentinelgate_rate_limit_keys` (gauge)
- **Real health check endpoint** (`/health`) with component verification
- **Configurable log level** via config file (`log_level: debug|info|warn|error`)

#### Configuration
- Session timeout configuration (`server.session_timeout`)
- HTTP client timeout configuration (`upstream.http_timeout`)
- Rate limiter cleanup interval (`rate_limit.cleanup_interval`)
- Rate limiter max TTL (`rate_limit.max_ttl`)
- Audit channel size, batch size, flush interval, send timeout, warning threshold

#### Security
- **Argon2id password hashing** for API keys (replaces SHA-256)
- Backward compatibility with existing SHA-256 hashed keys
- DevMode startup warning with environment variable blocking (`SENTINELGATE_ALLOW_DEVMODE=false`)
- TLS termination documentation (nginx, Caddy examples)

#### Performance
- Lock-free policy evaluation using `atomic.Value`
- CEL result caching with xxhash keys
- Rule indexing by tool name pattern (exact match and wildcard)
- Single JSON parse in proxy service
- Adaptive audit flush based on channel depth

### Changed

- Audit system now uses backpressure instead of silent drops
- Rate-limited channel depth warnings (max once per minute)
- Docker healthcheck now uses real `/health` endpoint
- Improved error message sanitization for all client-facing responses

### Fixed

- **Memory leaks** in rate limiter, session store, and auth interceptor
- Background cleanup goroutines now properly started at application startup
- HTTPClient lifecycle: can now be reused after Close() (required for HTTP mode)
- Scanner buffer handling for large messages (256KB-1MB)
- Goroutine coordination and cleanup in proxy service
- RateLimitError now properly handled in SafeErrorMessage()

### Security

- API keys now use Argon2id (memory-hard) instead of SHA-256
- Error messages sanitized to prevent information leakage
- DevMode warning prominently logged at startup

## [1.0.0] - 2026-02-02

### Added

- Initial release of Sentinel Gate OSS
- MCP proxy with HTTP and stdio transport support
- RBAC policies using CEL (Common Expression Language)
- API key authentication with SHA-256 hashing
- Rate limiting with GCRA algorithm
- Audit logging to stdout or file
- Admin UI for managing policies, identities, and API keys
- Docker support with multi-stage build
- Development mode for local testing

[1.2.0]: https://github.com/Sentinel-Gate/Sentinelgate/compare/v1.0.0...v1.2.0
[1.0.0]: https://github.com/Sentinel-Gate/Sentinelgate/releases/tag/v1.0.0
