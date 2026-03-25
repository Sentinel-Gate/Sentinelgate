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

	// ContentScanningConfig holds the response scanning configuration.
	// Mode is "monitor" (default) or "enforce".
	ContentScanningConfig *ContentScanningConfig `json:"content_scanning_config,omitempty"`

	// ToolBaseline stores the tool schema baseline for drift detection.
	ToolBaseline map[string]ToolBaselineEntry `json:"tool_baseline,omitempty"`

	// QuarantinedTools lists tool names that are currently quarantined.
	QuarantinedTools []string `json:"quarantined_tools,omitempty"`

	// Quotas are the per-identity quota configurations.
	// Uses omitempty so existing state.json files without quotas load cleanly.
	Quotas []QuotaConfigEntry `json:"quotas,omitempty"`

	// Transforms are the configured response transformation rules.
	Transforms []TransformRuleEntry `json:"transforms,omitempty"`

	// RecordingConfig holds the session recording configuration.
	// Nil when not configured (recording disabled by default, backward compatible).
	RecordingConfig *RecordingConfigEntry `json:"recording_config,omitempty"`

	// TelemetryConfig holds the OpenTelemetry stdout export configuration.
	// Nil when not configured (telemetry disabled by default, backward compatible).
	TelemetryConfig *TelemetryConfigEntry `json:"telemetry_config,omitempty"`

	// NamespaceConfig holds the namespace isolation configuration.
	// Nil when not configured (all tools visible to all roles by default).
	NamespaceConfig *NamespaceConfigEntry `json:"namespace_config,omitempty"`

	// FinOpsConfig holds cost estimation and budget guardrail configuration.
	// Nil when not configured (FinOps disabled by default, backward compatible).
	FinOpsConfig *FinOpsConfigEntry `json:"finops_config,omitempty"`

	// HealthConfig holds agent health alerting thresholds.
	// Nil when not configured (defaults apply).
	HealthConfig *HealthConfigEntry `json:"health_config,omitempty"`

	// PermissionHealthConfig holds shadow mode / permission health configuration.
	// Nil when not configured (defaults apply, backward compatible).
	PermissionHealthConfig *PermissionHealthConfigEntry `json:"permission_health_config,omitempty"`

	// DriftConfig holds behavioral drift detection thresholds.
	// Nil when not configured (defaults apply, backward compatible).
	DriftConfig *DriftConfigEntry `json:"drift_config,omitempty"`

	// EvidenceConfig holds the cryptographic evidence toggle.
	// Nil when not configured (evidence disabled by default, backward compatible).
	// Changes take effect after restart since the EvidenceService is not hot-reloadable.
	EvidenceConfig *EvidenceConfigEntry `json:"evidence_config,omitempty"`

	// RestoredFromBackup indicates that the state was loaded from the .bak
	// file because the primary state.json was corrupt or unreadable.
	// Callers should treat the data as potentially stale.
	RestoredFromBackup bool `json:"restored_from_backup,omitempty"`

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

	// PolicyID is the parent policy UUID, persisted to prevent ID regeneration on restart (L-14).
	PolicyID string `json:"policy_id,omitempty"`

	// Name is the human-readable name.
	Name string `json:"name"`

	// Description provides additional context about the policy.
	Description string `json:"description,omitempty"`

	// PolicyPriority is the policy-level priority (higher number = higher priority).
	PolicyPriority int `json:"policy_priority,omitempty"`

	// Priority determines evaluation order (higher number = higher priority).
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

	// ApprovalTimeout is how long to wait for approval (e.g. "5m", "30s").
	ApprovalTimeout string `json:"approval_timeout,omitempty"`

	// TimeoutAction specifies what to do when an approval request times out ("deny" or "allow").
	TimeoutAction string `json:"timeout_action,omitempty"`

	// HelpText is optional admin-provided guidance shown when this rule denies an action.
	HelpText string `json:"help_text,omitempty"`

	// Source identifies the origin of this rule (e.g., "template:read-only", "redteam").
	Source string `json:"source,omitempty"`

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

	// UpdatedAt is when this identity was last updated.
	UpdatedAt time.Time `json:"updated_at"`
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

	// KeyPrefix stores the first 8 chars of the cleartext key for fast-path Argon2id lookup.
	// When present, Validate() uses a prefix index instead of O(n) iteration.
	KeyPrefix string `json:"key_prefix,omitempty"`

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
	// InputScanEnabled controls input (arguments) scanning for PII/secrets.
	// When true, tool call arguments are scanned before forwarding.
	InputScanEnabled bool `json:"input_scan_enabled"`
	// Whitelist contains context-specific exceptions for content scanning.
	Whitelist []ContentWhitelistEntry `json:"whitelist,omitempty"`
	// PatternActions maps pattern type to action override (off/alert/mask/block).
	PatternActions map[string]string `json:"pattern_actions,omitempty"`
	// UpdatedAt is when the config was last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// ContentWhitelistEntry is a persisted whitelist rule for content scanning.
type ContentWhitelistEntry struct {
	// ID uniquely identifies this entry.
	ID string `json:"id"`
	// PatternType is the type of pattern to skip (e.g. "email", "us_ssn").
	PatternType string `json:"pattern_type"`
	// Scope is the whitelist scope: "path", "agent", or "tool".
	Scope string `json:"scope"`
	// Value is the scope value (path glob, agent ID, or tool name).
	Value string `json:"value"`
	// CreatedAt is when this entry was created.
	CreatedAt time.Time `json:"created_at"`
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

// QuotaConfigEntry represents a per-identity quota configuration in state.json.
type QuotaConfigEntry struct {
	// IdentityID is the identity this quota applies to.
	IdentityID string `json:"identity_id"`
	// MaxCallsPerSession is the maximum number of total tool calls per session.
	MaxCallsPerSession int64 `json:"max_calls_per_session,omitempty"`
	// MaxWritesPerSession is the maximum number of write calls per session.
	MaxWritesPerSession int64 `json:"max_writes_per_session,omitempty"`
	// MaxDeletesPerSession is the maximum number of delete calls per session.
	MaxDeletesPerSession int64 `json:"max_deletes_per_session,omitempty"`
	// MaxCallsPerMinute is the maximum rate of calls per sliding window minute.
	MaxCallsPerMinute int64 `json:"max_calls_per_minute,omitempty"`
	// MaxCallsPerDay is the maximum number of calls per day.
	MaxCallsPerDay int64 `json:"max_calls_per_day,omitempty"`
	// ToolLimits are per-tool call limits.
	ToolLimits map[string]int64 `json:"tool_limits,omitempty"`
	// Action is "deny" or "warn".
	Action string `json:"action"`
	// Enabled controls whether this quota is active.
	Enabled bool `json:"enabled"`
}

// RecordingConfigEntry persists the session recording configuration in state.json.
// Using a pointer with omitempty in AppState ensures existing state.json files
// without this field load cleanly (backward compatible).
type RecordingConfigEntry struct {
	// Enabled enables or disables session recording globally.
	Enabled bool `json:"enabled"`
	// RecordPayloads controls whether tool arguments and responses are stored.
	RecordPayloads bool `json:"record_payloads"`
	// MaxFileSize is the maximum size in bytes for a single JSONL file (0 = unlimited).
	MaxFileSize int64 `json:"max_file_size,omitempty"`
	// RetentionDays is how many days to keep recording files (0 = keep forever).
	RetentionDays int `json:"retention_days,omitempty"`
	// RedactPatterns are regex patterns applied to string payloads before writing.
	RedactPatterns []string `json:"redact_patterns,omitempty"`
	// StorageDir is the directory where JSONL files are stored.
	StorageDir string `json:"storage_dir,omitempty"`
	// AutoRedactPII enables automatic redaction of built-in PII patterns.
	AutoRedactPII bool `json:"auto_redact_pii"`
}

// EvidenceConfigEntry persists the cryptographic evidence toggle in state.json.
// Changes require a restart to take effect (EvidenceService is not hot-reloadable).
type EvidenceConfigEntry struct {
	// Enabled controls whether cryptographic evidence signing is active.
	Enabled bool `json:"enabled"`
	// UpdatedAt is when the config was last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// TelemetryConfigEntry persists the OpenTelemetry stdout export configuration.
type TelemetryConfigEntry struct {
	// Enabled controls whether OTel stdout export is active.
	Enabled bool `json:"enabled"`
	// ServiceName is the OTel service name shown in traces/metrics.
	ServiceName string `json:"service_name"`
	// UpdatedAt is when the config was last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// NamespaceConfigEntry persists the namespace isolation configuration.
type NamespaceConfigEntry struct {
	// Enabled controls whether namespace filtering is active.
	Enabled bool `json:"enabled"`
	// Rules maps role names to their tool visibility rules.
	Rules map[string]NamespaceRuleEntry `json:"rules,omitempty"`
	// UpdatedAt is when the config was last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// NamespaceRuleEntry defines tool visibility for a role in state.json.
type NamespaceRuleEntry struct {
	// VisibleTools is a whitelist (only these tools visible). Empty = no whitelist.
	VisibleTools []string `json:"visible_tools,omitempty"`
	// HiddenTools is a blacklist (these tools hidden). Empty = no blacklist.
	HiddenTools []string `json:"hidden_tools,omitempty"`
}

// FinOpsConfigEntry persists the FinOps cost estimation and budget configuration.
type FinOpsConfigEntry struct {
	// Enabled controls whether cost tracking is active.
	Enabled bool `json:"enabled"`
	// DefaultCostPerCall is the default estimated cost per tool call (USD).
	DefaultCostPerCall float64 `json:"default_cost_per_call"`
	// ToolCosts maps tool names to their per-call cost estimate (USD).
	ToolCosts map[string]float64 `json:"tool_costs,omitempty"`
	// Budgets maps identity IDs to their monthly budget limit (USD).
	Budgets map[string]float64 `json:"budgets,omitempty"`
	// BudgetActions maps identity IDs to their over-budget action ("notify" or "block").
	BudgetActions map[string]string `json:"budget_actions,omitempty"`
	// AlertThresholds are budget percentage thresholds that trigger alerts (e.g. 0.7, 0.85, 1.0).
	AlertThresholds []float64 `json:"alert_thresholds,omitempty"`
	// UpdatedAt is when the config was last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// HealthConfigEntry holds agent health alerting thresholds (Upgrade 11).
type HealthConfigEntry struct {
	DenyRateWarning    float64 `json:"deny_rate_warning"`
	DenyRateCritical   float64 `json:"deny_rate_critical"`
	DriftScoreWarning  float64 `json:"drift_score_warning"`
	DriftScoreCritical float64 `json:"drift_score_critical"`
	ErrorRateWarning   float64 `json:"error_rate_warning"`
	ErrorRateCritical  float64 `json:"error_rate_critical"`
}

// TransformRuleEntry represents a persisted transform rule in state.json.
type TransformRuleEntry struct {
	// ID uniquely identifies this transform rule.
	ID string `json:"id"`
	// Name is the human-readable rule name.
	Name string `json:"name"`
	// Type is the transform type: "redact", "truncate", "inject", "dry_run", "mask".
	Type string `json:"type"`
	// ToolMatch is a glob pattern matching tool names (e.g., "*", "read_file").
	ToolMatch string `json:"tool_match"`
	// Priority determines execution order (lower = runs first).
	Priority int `json:"priority"`
	// Enabled controls whether this rule is active.
	Enabled bool `json:"enabled"`
	// Config holds the type-specific configuration as a generic map.
	// Using map[string]interface{} avoids importing the transform package
	// into the state package (keeps dependency direction clean: adapter -> domain).
	Config map[string]interface{} `json:"config"`
	// CreatedAt is when this rule was created.
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt is when this rule was last modified.
	UpdatedAt time.Time `json:"updated_at"`
}

// PermissionHealthConfigEntry persists permission health / shadow mode configuration.
type PermissionHealthConfigEntry struct {
	// Mode is the shadow mode: "disabled", "shadow", "suggest", or "auto".
	Mode string `json:"mode"`
	// LearningDays is the observation window in days (default 14).
	LearningDays int `json:"learning_days"`
	// GracePeriodDays is days before auto-apply (default 7).
	GracePeriodDays int `json:"grace_period_days"`
	// WhitelistTools are tools never suggested for removal.
	WhitelistTools []string `json:"whitelist_tools,omitempty"`
	// UpdatedAt is when the config was last changed.
	UpdatedAt time.Time `json:"updated_at"`
}

// DriftConfigEntry persists behavioral drift detection thresholds.
type DriftConfigEntry struct {
	// BaselineWindowDays is how many days of history for the baseline (default 14).
	BaselineWindowDays int `json:"baseline_window_days"`
	// CurrentWindowDays is how many days for current behavior (default 1).
	CurrentWindowDays int `json:"current_window_days"`
	// ToolShiftThreshold is % change in tool distribution to flag (default 0.20).
	ToolShiftThreshold float64 `json:"tool_shift_threshold"`
	// DenyRateThreshold is absolute change in deny rate (default 0.10).
	DenyRateThreshold float64 `json:"deny_rate_threshold"`
	// ErrorRateThreshold is absolute change in error rate (default 0.10).
	ErrorRateThreshold float64 `json:"error_rate_threshold"`
	// LatencyThreshold is % change in avg latency (default 0.50).
	LatencyThreshold float64 `json:"latency_threshold"`
	// TemporalThreshold is KL divergence for hourly pattern (default 0.30).
	TemporalThreshold float64 `json:"temporal_threshold"`
	// ArgShiftThreshold is % of new/missing arg keys to flag (default 0.30).
	ArgShiftThreshold float64 `json:"arg_shift_threshold"`
	// MinCallsBaseline is minimum calls in baseline to enable detection (default 10).
	MinCallsBaseline int `json:"min_calls_baseline"`
	// UpdatedAt is when the config was last changed.
	UpdatedAt time.Time `json:"updated_at"`
}
