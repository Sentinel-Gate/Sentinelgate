// Package state provides file-based persistence for SentinelGate runtime state.
//
// The state.json file stores all runtime configuration including upstreams,
// policies, identities, API keys, and admin credentials. This package provides
// atomic writes, file locking, and backup functionality.
package state

import "time"

// AppState is the top-level structure persisted in state.json.
// It holds all runtime configuration that survives restarts.
type AppState struct {
	// Version is the schema version for forward compatibility. Currently "1".
	Version string `json:"version"`

	// DefaultPolicy is the fallback action when no policy matches ("deny" or "allow").
	DefaultPolicy string `json:"default_policy"`

	// Upstreams are the configured MCP upstream servers.
	Upstreams []UpstreamEntry `json:"upstreams"`

	// Policies are the access control rules evaluated in priority order.
	Policies []PolicyEntry `json:"policies"`

	// Identities are the known users and services.
	Identities []IdentityEntry `json:"identities"`

	// APIKeys are the authentication keys mapped to identities.
	APIKeys []APIKeyEntry `json:"api_keys"`

	// PolicyEvaluations are recent policy evaluation records.
	// Bounded to a maximum of 1000 entries (FIFO eviction).
	PolicyEvaluations []PolicyEvaluationEntry `json:"policy_evaluations,omitempty"`

	// OutboundRules are the persisted outbound control rules.
	// Includes both default blocklist rules and user-created rules.
	OutboundRules []OutboundRuleEntry `json:"outbound_rules,omitempty"`

	// ContentScanningConfig holds the response scanning configuration.
	// Mode is "monitor" (default) or "enforce".
	ContentScanningConfig *ContentScanningConfig `json:"content_scanning_config,omitempty"`

	// TLSInspectionConfig holds the TLS inspection configuration for the HTTP Gateway.
	// When non-nil, overrides the YAML-configured TLS inspection settings.
	TLSInspectionConfig *TLSInspectionState `json:"tls_inspection_config,omitempty"`

	// HTTPGatewayTargets are upstream targets for the HTTP Gateway reverse proxy.
	// Targets created via the admin API (future plan 07-03) are persisted here.
	HTTPGatewayTargets []HTTPGatewayTargetEntry `json:"http_gateway_targets,omitempty"`

	// ToolBaseline stores the tool schema baseline for drift detection.
	ToolBaseline map[string]ToolBaselineEntry `json:"tool_baseline,omitempty"`

	// QuarantinedTools lists tool names that are currently quarantined.
	QuarantinedTools []string `json:"quarantined_tools,omitempty"`

	// AdminPasswordHash is the Argon2id hash of the admin password.
	// Empty string means no admin password has been set.
	AdminPasswordHash string `json:"admin_password_hash"`

	// CreatedAt is when this state file was first created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this state file was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// UpstreamEntry represents a configured MCP upstream server.
type UpstreamEntry struct {
	// ID is the unique identifier (UUID).
	ID string `json:"id"`

	// Name is the human-readable display name.
	Name string `json:"name"`

	// Type is the transport type: "stdio" or "http".
	Type string `json:"type"`

	// Enabled indicates whether this upstream is active.
	Enabled bool `json:"enabled"`

	// Command is the executable path for stdio upstreams.
	Command string `json:"command,omitempty"`

	// Args are the command-line arguments for stdio upstreams.
	Args []string `json:"args,omitempty"`

	// URL is the endpoint for HTTP upstreams.
	URL string `json:"url,omitempty"`

	// Env holds environment variables passed to stdio upstreams.
	Env map[string]string `json:"env,omitempty"`

	// CreatedAt is when this upstream was added.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this upstream was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// PolicyEntry represents a single access control rule.
type PolicyEntry struct {
	// ID is the unique identifier.
	ID string `json:"id"`

	// Name is the human-readable name.
	Name string `json:"name"`

	// Priority determines evaluation order (lower number = higher priority).
	Priority int `json:"priority"`

	// ToolPattern is a glob pattern matching tool names (e.g. "*", "file_*").
	ToolPattern string `json:"tool_pattern"`

	// Condition is a CEL expression that must evaluate to true for this rule to apply.
	Condition string `json:"condition,omitempty"`

	// Action is "allow" or "deny".
	Action string `json:"action"`

	// Enabled indicates whether this rule is active.
	Enabled bool `json:"enabled"`

	// ReadOnly is true for rules sourced from YAML config (not editable via API).
	ReadOnly bool `json:"read_only"`

	// CreatedAt is when this rule was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when this rule was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// IdentityEntry represents a known user or service.
type IdentityEntry struct {
	// ID is the unique identifier.
	ID string `json:"id"`

	// Name is the display name.
	Name string `json:"name"`

	// Roles are the assigned roles (e.g. "admin", "user", "read-only").
	Roles []string `json:"roles"`

	// ReadOnly is true for identities sourced from YAML config.
	ReadOnly bool `json:"read_only"`

	// CreatedAt is when this identity was created.
	CreatedAt time.Time `json:"created_at"`
}

// PolicyEvaluationEntry represents a stored policy evaluation record.
type PolicyEvaluationEntry struct {
	// RequestID is the unique identifier for this evaluation.
	RequestID string `json:"request_id"`

	// ActionType is the canonical action type evaluated.
	ActionType string `json:"action_type"`

	// ActionName is the action that was evaluated.
	ActionName string `json:"action_name"`

	// Protocol is the originating protocol.
	Protocol string `json:"protocol"`

	// Gateway is the gateway that received the request.
	Gateway string `json:"gateway"`

	// Framework is the AI framework in use (optional).
	Framework string `json:"framework,omitempty"`

	// Decision is the evaluation result: "allow", "deny", or "approval_required".
	Decision string `json:"decision"`

	// RuleID is the rule that produced the decision.
	RuleID string `json:"rule_id,omitempty"`

	// LatencyMs is the evaluation latency in milliseconds.
	LatencyMs int64 `json:"latency_ms"`

	// Status is the current status: "pending", "approved", "denied", "timeout".
	Status string `json:"status"`

	// CreatedAt is when the evaluation was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the evaluation was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// APIKeyEntry represents an authentication key mapped to an identity.
type APIKeyEntry struct {
	// ID is the unique identifier.
	ID string `json:"id"`

	// KeyHash is the Argon2id hash of the API key.
	KeyHash string `json:"key_hash"`

	// IdentityID references the identity this key authenticates as.
	IdentityID string `json:"identity_id"`

	// Name is a human-readable display name for this key.
	Name string `json:"name"`

	// CreatedAt is when this key was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when this key expires. Nil means it never expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Revoked indicates whether this key has been revoked.
	Revoked bool `json:"revoked"`

	// ReadOnly is true for keys sourced from YAML config.
	ReadOnly bool `json:"read_only"`
}

// ContentScanningConfig configures the response content scanning feature.
type ContentScanningConfig struct {
	// Mode is "monitor" (log only) or "enforce" (block on detection).
	// Default is "monitor" to avoid false positives disrupting workflows.
	Mode string `json:"mode"`
	// Enabled indicates whether content scanning is active.
	// Default is true (security by default).
	Enabled bool `json:"enabled"`
	// UpdatedAt is when the config was last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// TLSInspectionState holds the persisted TLS inspection configuration.
// This follows the same pattern as ContentScanningConfig: a pointer field
// in AppState that is omitted when nil.
type TLSInspectionState struct {
	// Enabled controls whether TLS inspection is active.
	Enabled bool `json:"enabled"`
	// BypassList contains domain patterns to never inspect.
	BypassList []string `json:"bypass_list,omitempty"`
	// UpdatedAt is when the config was last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// OutboundRuleEntry represents a persisted outbound control rule in state.json.
// It maps to the domain OutboundRule type for JSON serialization.
type OutboundRuleEntry struct {
	// ID uniquely identifies this rule.
	ID string `json:"id"`
	// Name is the human-readable rule name.
	Name string `json:"name"`
	// Mode is "blocklist" or "allowlist".
	Mode string `json:"mode"`
	// Targets are the target specifications for this rule.
	Targets []OutboundTargetEntry `json:"targets"`
	// Action is "block", "alert", or "log".
	Action string `json:"action"`
	// Scope is empty for global rules, otherwise a scope identifier.
	Scope string `json:"scope"`
	// Priority determines evaluation order (lower = higher priority).
	Priority int `json:"priority"`
	// Enabled controls whether this rule is active.
	Enabled bool `json:"enabled"`
	// Base64Scan enables base64 URL decoding in URL extraction.
	Base64Scan bool `json:"base64_scan"`
	// HelpText is shown in deny messages.
	HelpText string `json:"help_text,omitempty"`
	// HelpURL is a link shown in deny messages.
	HelpURL string `json:"help_url,omitempty"`
	// ReadOnly is true for default blocklist rules that cannot be modified.
	ReadOnly bool `json:"read_only"`
	// TenantID is reserved for Pro multi-tenant support (OUT-12).
	TenantID string `json:"tenant_id,omitempty"`
	// CreatedAt is when this rule was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when this rule was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// OutboundTargetEntry represents a single target specification in a persisted outbound rule.
type OutboundTargetEntry struct {
	// Type is the kind of target: "domain", "ip", "cidr", "domain_glob", "port_range".
	Type string `json:"type"`
	// Value is the target value (e.g., "evil.com", "10.0.0.0/8", "*.ngrok.io").
	Value string `json:"value"`
}

// ToolBaselineEntry stores a snapshot of a tool's schema at baseline capture time.
type ToolBaselineEntry struct {
	// Name is the tool's unique identifier.
	Name string `json:"name"`
	// Description is the human-readable tool description.
	Description string `json:"description"`
	// InputSchema is the JSON Schema for the tool's parameters.
	InputSchema interface{} `json:"input_schema"`
	// CapturedAt records when this baseline was captured.
	CapturedAt time.Time `json:"captured_at"`
}

// HTTPGatewayTargetEntry represents a persisted HTTP Gateway reverse proxy target.
// Targets created via the admin API (future plan 07-03) are stored in state.json.
type HTTPGatewayTargetEntry struct {
	// ID uniquely identifies this target.
	ID string `json:"id"`
	// Name is a human-readable display name.
	Name string `json:"name"`
	// PathPrefix is the URL path prefix to match (e.g., "/api/openai/").
	PathPrefix string `json:"path_prefix"`
	// Upstream is the target URL base (e.g., "https://api.openai.com").
	Upstream string `json:"upstream"`
	// StripPrefix controls whether PathPrefix is stripped before forwarding.
	StripPrefix bool `json:"strip_prefix"`
	// Headers are additional headers to inject into proxied requests.
	Headers map[string]string `json:"headers,omitempty"`
	// Enabled controls whether this target is active.
	Enabled bool `json:"enabled"`
	// CreatedAt is when this target was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when this target was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}
