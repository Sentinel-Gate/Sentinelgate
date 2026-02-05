// Package audit contains domain types for audit logging.
package audit

import "time"

// Decision constants for audit records.
const (
	// DecisionAllow indicates the tool call was permitted.
	DecisionAllow = "allow"
	// DecisionDeny indicates the tool call was blocked.
	DecisionDeny = "deny"
)

// EventType constants for compliance audit records.
// Categorized by SOC 2 Trust Services Criteria requirements.
const (
	// EventTypeToolCall is the default event type for tool invocations.
	EventTypeToolCall = "tool_call"

	// SOC2-01: Access control events (CC6)
	EventTypeLogin            = "access.login"
	EventTypeLogout           = "access.logout"
	EventTypeLoginFailed      = "access.login_failed"
	EventTypePermissionGrant  = "access.permission_grant"
	EventTypePermissionRevoke = "access.permission_revoke"
	EventTypeAPIKeyCreate     = "access.api_key_create"
	EventTypeAPIKeyRevoke     = "access.api_key_revoke"

	// SOC2-02: Configuration changes (CC7, CC8)
	EventTypePolicyCreate     = "config.policy_create"
	EventTypePolicyUpdate     = "config.policy_update"
	EventTypePolicyDelete     = "config.policy_delete"
	EventTypeScanConfigUpdate = "config.scan_update"
	EventTypeSSOConfigUpdate  = "config.sso_update"
	EventTypeTenantUpdate     = "config.tenant_update"

	// SOC2-03: User lifecycle events (CC6)
	EventTypeUserCreate  = "user.create"
	EventTypeUserModify  = "user.modify"
	EventTypeUserDisable = "user.disable"
	EventTypeUserDelete  = "user.delete"
	EventTypeUserEnable  = "user.enable"
)

// ActorType constants identify who performed an action.
const (
	ActorTypeAdmin  = "admin"
	ActorTypeUser   = "user"
	ActorTypeSystem = "system"
	ActorTypeAPIKey = "api_key"
)

// ComplianceAuditRecord extends AuditRecord for SOC 2 compliance events.
// Used for access control, configuration changes, and user lifecycle events.
type ComplianceAuditRecord struct {
	// Timestamp when the event occurred.
	Timestamp time.Time `json:"timestamp"`
	// TenantID for multi-tenant isolation.
	TenantID string `json:"tenant_id"`
	// EventType categorizes the event (access.*, config.*, user.*).
	EventType string `json:"event_type"`
	// RequestID for correlation across systems.
	RequestID string `json:"request_id"`

	// Actor information (who performed the action)
	ActorID       string `json:"actor_id"`
	ActorType     string `json:"actor_type"` // admin, user, system, api_key
	ActorUsername string `json:"actor_username,omitempty"`

	// Target information (what was affected)
	TargetID   string `json:"target_id,omitempty"`
	TargetType string `json:"target_type,omitempty"` // user, policy, config, etc.
	TargetName string `json:"target_name,omitempty"`

	// Change details
	OldValue string `json:"old_value,omitempty"` // JSON-encoded previous state
	NewValue string `json:"new_value,omitempty"` // JSON-encoded new state

	// Additional context
	SourceIP  string `json:"source_ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Reason    string `json:"reason,omitempty"`
	SessionID string `json:"session_id,omitempty"`
}

// AuditRecord represents a single auditable event from a tool call.
type AuditRecord struct {
	// Timestamp is when the tool call was received.
	Timestamp time.Time
	// SessionID from the authenticated session.
	SessionID string
	// IdentityID of the user making the call.
	IdentityID string
	// ToolName is the name of the tool being invoked.
	ToolName string
	// ToolArguments are the arguments passed to the tool (may be redacted).
	ToolArguments map[string]interface{}
	// Decision is "allow" or "deny".
	Decision string
	// Reason explains why the decision was made.
	Reason string
	// RuleID is the ID of the rule that matched (if any).
	RuleID string
	// RequestID is for correlation across systems.
	RequestID string
	// LatencyMicros is the policy evaluation latency in microseconds.
	LatencyMicros int64

	// Scan detection info (added for Phase 14)
	// ScanDetections is the number of sensitive content detections found.
	ScanDetections int
	// ScanAction is the action taken: "blocked", "redacted", "flagged", or empty (none).
	ScanAction string
	// ScanTypes is a comma-separated list of detection types (e.g., "secret,pii").
	ScanTypes string
}
