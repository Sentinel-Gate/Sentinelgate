// Package config provides configuration types for Sentinel Gate OSS.
//
// This is the OSS (Open Source Software) configuration schema, designed for
// simplicity and file-based configuration. It intentionally excludes Pro and
// Enterprise features:
//
//   - NO Redis session storage (in-memory only)
//   - NO PostgreSQL for audit logs (stdout/file only)
//   - NO SIEM integration (Splunk, Datadog)
//   - NO Admin web interface
//   - NO Content scanning (PII, injection, secrets)
//   - NO Email/webhook notifications
//   - NO SSO/SAML/SCIM authentication
//   - NO Multi-tenant support
//   - NO Approval workflows (allow/deny only)
//   - NO Framework context variables
//   - NO TLS configuration (handle via reverse proxy)
//
// For Pro features, see the sentinel-gate-pro module.
package config

// OSSConfig is the top-level configuration for Sentinel Gate OSS.
// It contains only the essential fields for a minimalist MCP proxy.
type OSSConfig struct {
	// Server configures the HTTP server listener.
	Server ServerConfig `yaml:"server" mapstructure:"server"`

	// Upstream configures the MCP server to proxy to.
	// Either HTTP URL or subprocess command must be specified.
	Upstream UpstreamConfig `yaml:"upstream" mapstructure:"upstream" validate:"required"`

	// Auth configures file-based identities and API keys.
	Auth AuthConfig `yaml:"auth" mapstructure:"auth" validate:"required"`

	// Audit configures where audit logs are written.
	Audit AuditConfig `yaml:"audit" mapstructure:"audit" validate:"required"`

	// RateLimit configures optional rate limiting.
	RateLimit RateLimitConfig `yaml:"rate_limit" mapstructure:"rate_limit"`

	// Policies defines the access control rules.
	// At least one policy with at least one rule is required.
	Policies []PolicyConfig `yaml:"policies" mapstructure:"policies" validate:"required,min=1,dive"`

	// DevMode enables development features (verbose logging, etc).
	DevMode bool `yaml:"dev_mode" mapstructure:"dev_mode"`
}

// ServerConfig configures the HTTP server.
// OSS version only supports HTTP (use a reverse proxy for TLS).
type ServerConfig struct {
	// HTTPAddr is the address to listen on (e.g., ":8080", "127.0.0.1:8080").
	// Defaults to ":8080" if empty.
	HTTPAddr string `yaml:"http_addr" mapstructure:"http_addr" validate:"omitempty,hostname_port"`

	// LogLevel sets the minimum log level.
	// Valid values: "debug", "info", "warn", "error".
	// Defaults to "info" if empty. DevMode=true overrides to "debug".
	LogLevel string `yaml:"log_level" mapstructure:"log_level" validate:"omitempty,oneof=debug info warn warning error"`

	// SessionTimeout is the duration before sessions expire (e.g., "30m", "1h").
	// Defaults to "30m" if not specified.
	SessionTimeout string `yaml:"session_timeout" mapstructure:"session_timeout" validate:"omitempty"`
}

// UpstreamConfig configures the upstream MCP server.
// Exactly one of HTTP or Command must be specified (mutually exclusive).
type UpstreamConfig struct {
	// HTTP is the URL of a remote MCP server (e.g., "http://localhost:3000/mcp").
	HTTP string `yaml:"http" mapstructure:"http" validate:"omitempty,url"`

	// Command is the path to an MCP server executable to spawn as a subprocess.
	Command string `yaml:"command" mapstructure:"command"`

	// Args are the arguments to pass to the subprocess command.
	Args []string `yaml:"args" mapstructure:"args"`

	// HTTPTimeout is the timeout for HTTP requests to upstream (e.g., "30s", "1m").
	// Defaults to "30s" if not specified.
	HTTPTimeout string `yaml:"http_timeout" mapstructure:"http_timeout" validate:"omitempty"`
}

// AuthConfig configures file-based authentication.
// All identities and API keys are defined in the configuration file.
type AuthConfig struct {
	// Identities defines the known identities (users/services).
	Identities []IdentityConfig `yaml:"identities" mapstructure:"identities" validate:"required,min=1,dive"`

	// APIKeys defines the API keys that map to identities.
	APIKeys []APIKeyConfig `yaml:"api_keys" mapstructure:"api_keys" validate:"required,min=1,dive"`
}

// IdentityConfig defines a file-based identity.
type IdentityConfig struct {
	// ID is the unique identifier for this identity.
	ID string `yaml:"id" mapstructure:"id" validate:"required"`

	// Name is the human-readable name for this identity.
	Name string `yaml:"name" mapstructure:"name" validate:"required"`

	// Roles are the roles assigned to this identity (used in policy evaluation).
	Roles []string `yaml:"roles" mapstructure:"roles" validate:"required,min=1"`
}

// APIKeyConfig defines an API key that authenticates as an identity.
type APIKeyConfig struct {
	// KeyHash is the SHA-256 hash of the API key, prefixed with "sha256:".
	// Generate with: echo -n "your-api-key" | sha256sum | cut -d' ' -f1
	// Then prefix with "sha256:" (e.g., "sha256:abc123...")
	KeyHash string `yaml:"key_hash" mapstructure:"key_hash" validate:"required,startswith=sha256:"`

	// IdentityID references the identity this key authenticates as.
	// Must match an ID in Auth.Identities.
	IdentityID string `yaml:"identity_id" mapstructure:"identity_id" validate:"required"`
}

// AuditConfig configures audit log output.
// OSS supports stdout or file output only (no PostgreSQL, SIEM).
type AuditConfig struct {
	// Output specifies where audit logs are written.
	// Valid values: "stdout" or "file:///absolute/path/to/audit.log"
	// Defaults to "stdout" if empty.
	Output string `yaml:"output" mapstructure:"output" validate:"required,audit_output"`

	// ChannelSize is the buffer size for the audit channel.
	// Larger values handle burst traffic better but use more memory.
	// Defaults to 1000 if not specified or 0.
	ChannelSize int `yaml:"channel_size" mapstructure:"channel_size" validate:"omitempty,min=1"`

	// BatchSize is the number of records to batch before writing.
	// Larger batches are more efficient but increase latency.
	// Defaults to 100 if not specified or 0.
	BatchSize int `yaml:"batch_size" mapstructure:"batch_size" validate:"omitempty,min=1"`

	// FlushInterval is how often to flush pending records (e.g., "1s", "500ms").
	// Shorter intervals reduce data loss risk but increase I/O.
	// Defaults to "1s" if not specified.
	FlushInterval string `yaml:"flush_interval" mapstructure:"flush_interval" validate:"omitempty"`

	// SendTimeout is how long to block when channel is full (e.g., "100ms", "0").
	// "0" or empty = drop immediately (no blocking).
	// Non-zero = block up to this duration before dropping.
	// Defaults to "100ms" if not specified.
	SendTimeout string `yaml:"send_timeout" mapstructure:"send_timeout" validate:"omitempty"`

	// WarningThreshold is the percentage (0-100) at which to log warnings.
	// When channel depth exceeds this percentage, a warning is logged (rate-limited).
	// Set to 0 to disable warnings. Defaults to 80 if not specified.
	WarningThreshold int `yaml:"warning_threshold" mapstructure:"warning_threshold" validate:"omitempty,min=0,max=100"`
}

// RateLimitConfig configures rate limiting.
type RateLimitConfig struct {
	// Enabled turns rate limiting on or off.
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`

	// IPRate is the maximum requests per minute per IP address.
	// Defaults to 100 if rate limiting is enabled.
	IPRate int `yaml:"ip_rate" mapstructure:"ip_rate" validate:"omitempty,min=1"`

	// UserRate is the maximum requests per minute per authenticated user.
	// Defaults to 1000 if rate limiting is enabled.
	UserRate int `yaml:"user_rate" mapstructure:"user_rate" validate:"omitempty,min=1"`

	// CleanupInterval is how often to clean up expired rate limit entries (e.g., "5m").
	// Only applies when rate limiting is enabled.
	// Defaults to "5m" if not specified.
	CleanupInterval string `yaml:"cleanup_interval" mapstructure:"cleanup_interval" validate:"omitempty"`

	// MaxTTL is the maximum age of a rate limit entry before removal (e.g., "1h").
	// Only applies when rate limiting is enabled.
	// Defaults to "1h" if not specified.
	MaxTTL string `yaml:"max_ttl" mapstructure:"max_ttl" validate:"omitempty"`
}

// PolicyConfig defines a named set of access control rules.
type PolicyConfig struct {
	// Name is the unique identifier for this policy.
	Name string `yaml:"name" mapstructure:"name" validate:"required"`

	// Rules are the access control rules in this policy.
	// Rules are evaluated in order; first match wins.
	Rules []RuleConfig `yaml:"rules" mapstructure:"rules" validate:"required,min=1,dive"`
}

// RuleConfig defines a single access control rule.
// OSS supports only allow/deny actions (no approval_required).
type RuleConfig struct {
	// Name is a human-readable identifier for this rule.
	Name string `yaml:"name" mapstructure:"name" validate:"required"`

	// Condition is a CEL expression that determines if this rule matches.
	// Available variables depend on request context (tool.name, user.roles, etc).
	Condition string `yaml:"condition" mapstructure:"condition" validate:"required"`

	// Action is what to do when the condition matches.
	// OSS supports only "allow" or "deny" (no "approval_required").
	Action string `yaml:"action" mapstructure:"action" validate:"required,oneof=allow deny"`
}

// SetDefaults applies sensible default values to the configuration.
func (c *OSSConfig) SetDefaults() {
	// Server defaults
	if c.Server.HTTPAddr == "" {
		c.Server.HTTPAddr = ":8080"
	}
	if c.Server.LogLevel == "" {
		c.Server.LogLevel = "info"
	}
	if c.Server.SessionTimeout == "" {
		c.Server.SessionTimeout = "30m"
	}

	// Upstream defaults
	if c.Upstream.HTTPTimeout == "" {
		c.Upstream.HTTPTimeout = "30s"
	}

	// Audit defaults
	if c.Audit.Output == "" {
		c.Audit.Output = "stdout"
	}
	if c.Audit.ChannelSize == 0 {
		c.Audit.ChannelSize = 1000
	}
	if c.Audit.BatchSize == 0 {
		c.Audit.BatchSize = 100
	}
	if c.Audit.FlushInterval == "" {
		c.Audit.FlushInterval = "1s"
	}
	if c.Audit.SendTimeout == "" {
		c.Audit.SendTimeout = "100ms"
	}
	if c.Audit.WarningThreshold == 0 {
		c.Audit.WarningThreshold = 80
	}

	// Rate limit defaults (only if enabled)
	if c.RateLimit.Enabled {
		if c.RateLimit.IPRate == 0 {
			c.RateLimit.IPRate = 100
		}
		if c.RateLimit.UserRate == 0 {
			c.RateLimit.UserRate = 1000
		}
		if c.RateLimit.CleanupInterval == "" {
			c.RateLimit.CleanupInterval = "5m"
		}
		if c.RateLimit.MaxTTL == "" {
			c.RateLimit.MaxTTL = "1h"
		}
	}
}
