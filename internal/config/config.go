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

import (
	"os"

	"github.com/spf13/viper"
)

// OSSConfig is the top-level configuration for Sentinel Gate OSS.
// It contains only the essential fields for a minimalist MCP proxy.
type OSSConfig struct {
	// Server configures the HTTP server listener.
	Server ServerConfig `yaml:"server" mapstructure:"server"`

	// Upstream configures the MCP server to proxy to (optional in multi-upstream mode).
	// Either HTTP URL or subprocess command must be specified for single-upstream YAML mode.
	// In multi-upstream mode, upstreams are configured via state.json instead.
	Upstream UpstreamConfig `yaml:"upstream" mapstructure:"upstream"`

	// AuditFile configures the file-based audit persistence.
	// Only used when audit output is "file://" or for structured file audit.
	AuditFile AuditFileConfig `yaml:"audit_file" mapstructure:"audit_file"`

	// Auth configures file-based identities and API keys.
	// Optional: when empty, only localhost admin UI access works (no API key auth).
	// Identities and API keys can be created from the admin UI.
	Auth AuthConfig `yaml:"auth" mapstructure:"auth"`

	// Audit configures where audit logs are written.
	Audit AuditConfig `yaml:"audit" mapstructure:"audit"`

	// RateLimit configures optional rate limiting.
	RateLimit RateLimitConfig `yaml:"rate_limit" mapstructure:"rate_limit"`

	// Policies defines the access control rules.
	// Optional: when empty, the server uses default-deny (no tool calls allowed).
	// Policies can be managed from the admin UI.
	Policies []PolicyConfig `yaml:"policies" mapstructure:"policies" validate:"omitempty,dive"`

	// HTTPGateway configures the optional HTTP forward proxy gateway.
	HTTPGateway HTTPGatewayConfig `yaml:"http_gateway" mapstructure:"http_gateway"`

	// DevMode enables development features (verbose logging, etc).
	DevMode bool `yaml:"dev_mode" mapstructure:"dev_mode"`
}

// HTTPGatewayConfig configures the HTTP Gateway forward and reverse proxy.
// When enabled, SentinelGate acts as a proxy for HTTP traffic from AI agents,
// applying the same security chain as MCP requests.
// Targets enable reverse proxy mode: requests matching target path prefixes
// are forwarded to configured upstream servers after the security chain.
type HTTPGatewayConfig struct {
	// Enabled controls whether the HTTP gateway is active.
	// Default: false (opt-in).
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	// PathPrefix is the URL path prefix for the gateway (e.g., "/proxy/").
	// All requests under this prefix are intercepted by the gateway.
	// Default: "/proxy/".
	PathPrefix string `yaml:"path_prefix" mapstructure:"path_prefix"`
	// Timeout is the timeout for forwarding requests to upstream (e.g., "30s").
	// Default: "30s".
	Timeout string `yaml:"timeout" mapstructure:"timeout"`
	// Targets configures reverse proxy upstream targets.
	// When targets are configured, requests matching target path prefixes
	// are forwarded to the configured upstream after security checks.
	Targets []HTTPUpstreamTarget `yaml:"targets" mapstructure:"targets"`
	// TLSInspection configures TLS inspection for HTTPS CONNECT requests.
	// When enabled, the gateway performs MITM decryption using a local CA
	// to inspect HTTPS traffic through the security chain.
	// Default: disabled (CONNECT requests are tunneled without inspection).
	TLSInspection TLSInspectionConfig `yaml:"tls_inspection" mapstructure:"tls_inspection"`
}

// TLSInspectionConfig configures TLS inspection for the HTTP Gateway.
// When enabled, CONNECT requests are intercepted, decrypted using a
// locally-generated CA certificate, and the plaintext HTTP request
// is processed through the canonical security chain.
type TLSInspectionConfig struct {
	// Enabled controls whether TLS inspection is active.
	// Default: false (CONNECT requests are tunneled without inspection).
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	// CADir is the directory where CA certificate and key are stored.
	// Default: "~/.sentinelgate".
	CADir string `yaml:"ca_dir" mapstructure:"ca_dir"`
	// BypassList contains domain patterns that should never be inspected.
	// Supports exact match (e.g., "example.com") and glob patterns (e.g., "*.google.com").
	// Traffic to these domains is tunneled without decryption.
	BypassList []string `yaml:"bypass_list" mapstructure:"bypass_list"`
	// CertTTL is the TTL for cached per-domain certificates (e.g., "1h", "30m").
	// Default: "1h".
	CertTTL string `yaml:"cert_ttl" mapstructure:"cert_ttl"`
}

// HTTPUpstreamTarget configures a reverse proxy upstream target.
// Requests matching PathPrefix are forwarded to the Upstream URL
// after passing through the canonical security chain.
type HTTPUpstreamTarget struct {
	// Name is a human-readable name for this target.
	Name string `yaml:"name" mapstructure:"name"`
	// PathPrefix is the URL path prefix to match (e.g., "/api/openai/").
	PathPrefix string `yaml:"path_prefix" mapstructure:"path_prefix" validate:"required"`
	// Upstream is the target URL base (e.g., "https://api.openai.com").
	Upstream string `yaml:"upstream" mapstructure:"upstream" validate:"required,url"`
	// StripPrefix controls whether PathPrefix is stripped before forwarding.
	StripPrefix bool `yaml:"strip_prefix" mapstructure:"strip_prefix"`
	// Headers are additional headers to inject into proxied requests.
	Headers map[string]string `yaml:"headers" mapstructure:"headers"`
}

// ServerConfig configures the HTTP server.
// OSS version only supports HTTP (use a reverse proxy for TLS).
type ServerConfig struct {
	// HTTPAddr is the address to listen on (e.g., "127.0.0.1:8080", "0.0.0.0:8080").
	// Defaults to "127.0.0.1:8080" (localhost only) if empty.
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
	// Optional: can be managed from the admin UI instead.
	Identities []IdentityConfig `yaml:"identities" mapstructure:"identities" validate:"omitempty,dive"`

	// APIKeys defines the API keys that map to identities.
	// Optional: can be managed from the admin UI instead.
	APIKeys []APIKeyConfig `yaml:"api_keys" mapstructure:"api_keys" validate:"omitempty,dive"`
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

	// BufferSize is the number of recent audit records to keep in the in-memory ring buffer.
	// Used for the admin UI's recent audit display. Defaults to 1000 if not specified or 0.
	BufferSize int `yaml:"buffer_size" mapstructure:"buffer_size" validate:"omitempty,min=1"`
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

// AuditFileConfig configures the file-based audit persistence.
type AuditFileConfig struct {
	// Dir is the directory where audit files are stored.
	Dir string `yaml:"dir" mapstructure:"dir"`
	// RetentionDays is the number of days to keep audit files.
	// Defaults to 7.
	RetentionDays int `yaml:"retention_days" mapstructure:"retention_days"`
	// MaxFileSizeMB is the maximum size per audit file in megabytes before rotation.
	// Defaults to 100.
	MaxFileSizeMB int `yaml:"max_file_size_mb" mapstructure:"max_file_size_mb"`
	// CacheSize is the number of recent audit records to keep in memory.
	// Defaults to 1000.
	CacheSize int `yaml:"cache_size" mapstructure:"cache_size"`
}

// SetDevDefaults applies permissive defaults for development mode.
// This allows running sentinel-gate with minimal config (just upstream).
// These defaults are applied BEFORE validation so required fields are satisfied.
func (c *OSSConfig) SetDevDefaults() {
	if !c.DevMode {
		return
	}

	// Provide a default dev identity if none configured
	if len(c.Auth.Identities) == 0 {
		c.Auth.Identities = []IdentityConfig{
			{
				ID:    "dev-user",
				Name:  "Development User",
				Roles: []string{"admin"},
			},
		}
	}

	// Provide a default dev API key if none configured
	// SHA256 of "dev-api-key"
	if len(c.Auth.APIKeys) == 0 {
		c.Auth.APIKeys = []APIKeyConfig{
			{
				KeyHash:    "sha256:6e1e4e1b8f8b36d08901cdb51b97841dfe20f5efd2fd2fd00768971408c46274",
				IdentityID: "dev-user",
			},
		}
	}

	// Provide a default catch-all allow policy if none configured
	if len(c.Policies) == 0 {
		c.Policies = []PolicyConfig{
			{
				Name: "dev-allow-all",
				Rules: []RuleConfig{
					{
						Name:      "allow-all",
						Condition: "true",
						Action:    "allow",
					},
				},
			},
		}
	}

	// Default audit to stdout if not configured
	if c.Audit.Output == "" {
		c.Audit.Output = "stdout"
	}
}

// SetDefaults applies sensible default values to the configuration.
func (c *OSSConfig) SetDefaults() {
	// Server defaults — bind to localhost only for security.
	// Users who need network access must explicitly set http_addr: ":8080" or "0.0.0.0:8080".
	if c.Server.HTTPAddr == "" {
		c.Server.HTTPAddr = "127.0.0.1:8080"
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
	if c.Audit.BufferSize == 0 {
		c.Audit.BufferSize = 1000
	}

	// HTTP Gateway defaults — enabled by default so Layer 2 works without YAML.
	// Only apply the default when the user hasn't explicitly set it in YAML/env.
	// viper.IsSet distinguishes "not set" (zero value) from "explicitly false".
	if !viper.IsSet("http_gateway.enabled") {
		c.HTTPGateway.Enabled = true
	}
	if c.HTTPGateway.PathPrefix == "" {
		c.HTTPGateway.PathPrefix = "/proxy/"
	}
	if c.HTTPGateway.Timeout == "" {
		c.HTTPGateway.Timeout = "30s"
	}

	// TLS Inspection defaults
	if c.HTTPGateway.TLSInspection.CADir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			c.HTTPGateway.TLSInspection.CADir = home + "/.sentinelgate"
		}
	}
	if c.HTTPGateway.TLSInspection.CertTTL == "" {
		c.HTTPGateway.TLSInspection.CertTTL = "1h"
	}
	// Default bypass list for domains that commonly break when inspected
	// due to certificate pinning (only when TLS inspection is enabled
	// and no bypass list is configured).
	if c.HTTPGateway.TLSInspection.Enabled && len(c.HTTPGateway.TLSInspection.BypassList) == 0 {
		c.HTTPGateway.TLSInspection.BypassList = []string{
			"*.google.com",
			"*.googleapis.com",
			"*.gstatic.com",
		}
	}

	// Rate limit defaults — enabled by default for security.
	// Only apply the default when the user hasn't explicitly set it in YAML/env.
	if !viper.IsSet("rate_limit.enabled") {
		c.RateLimit.Enabled = true
	}
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
