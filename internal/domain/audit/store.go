package audit

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors for audit store operations.
var (
	// ErrDateRangeExceeded is returned when the query date range exceeds the maximum allowed.
	ErrDateRangeExceeded = errors.New("date range exceeds maximum of 7 days")
)

// AuditStore persists audit records.
// Interface owned by domain per hexagonal architecture.
// Implementation handles batching and async writes.
type AuditStore interface {
	// Append stores audit records. Must be non-blocking from caller perspective.
	Append(ctx context.Context, records ...AuditRecord) error

	// Flush forces pending records to storage. Called during shutdown.
	Flush(ctx context.Context) error

	// Close releases resources.
	Close() error
}

// AuditFilter specifies query parameters for audit log queries.
type AuditFilter struct {
	// StartTime is the beginning of the time range (required).
	StartTime time.Time
	// EndTime is the end of the time range (required).
	EndTime time.Time
	// UserID filters by identity ID (optional).
	UserID string
	// SessionID filters by session ID (optional).
	SessionID string
	// ToolName filters by tool name (optional).
	ToolName string
	// Decision filters by decision (optional: "allow" or "deny").
	Decision string
	// Protocol filters by originating protocol (optional: "mcp", "http", "websocket", "runtime").
	Protocol string
	// Limit is the maximum number of records to return (default 100, max 100).
	Limit int
	// Cursor is the pagination cursor for fetching next page (optional).
	Cursor string
}

// ToolCallStats contains per-tool audit statistics.
type ToolCallStats struct {
	// Calls is the total number of calls to this tool.
	Calls int64
	// Allowed is the number of calls that were allowed.
	Allowed int64
	// Denied is the number of calls that were denied.
	Denied int64
}

// DetectionStats contains content scanning detection counts.
type DetectionStats struct {
	// SecretsFound is the count of secret detections.
	SecretsFound int64
	// PIIFound is the count of PII detections.
	PIIFound int64
	// InjectionsFound is the count of injection attempt detections.
	InjectionsFound int64
}

// AuditStats contains aggregated audit statistics for a time period.
// Used for transparency reporting per EU AI Act requirements.
type AuditStats struct {
	// TotalCalls is the total number of tool call audit records.
	TotalCalls int64
	// UniqueIdentities is the count of distinct identity IDs.
	UniqueIdentities int64
	// UniqueSessions is the count of distinct session IDs.
	UniqueSessions int64
	// ByTool maps tool names to per-tool statistics.
	ByTool map[string]ToolCallStats
	// ByDecision maps decision values to counts.
	ByDecision map[string]int64
	// Detections contains content scanning detection counts.
	Detections DetectionStats
}

// AuditQueryStore provides read access to audit logs for admin queries.
// This interface is separate from AuditStore which handles writes.
type AuditQueryStore interface {
	// Query retrieves audit records matching the filter.
	// Returns records, next cursor (empty if no more pages), and error.
	// Returns ErrDateRangeExceeded if EndTime - StartTime > 7 days.
	Query(ctx context.Context, filter AuditFilter) ([]AuditRecord, string, error)

	// QueryStats returns aggregated statistics for the given time range.
	// This supports EU AI Act transparency reporting requirements.
	QueryStats(ctx context.Context, start, end time.Time) (*AuditStats, error)
}

// ComplianceAuditFilter specifies query parameters for compliance audit queries.
type ComplianceAuditFilter struct {
	// StartTime is the beginning of the time range (required).
	StartTime time.Time
	// EndTime is the end of the time range (required).
	EndTime time.Time
	// EventTypes filters by specific event types (optional).
	EventTypes []string
	// ActorID filters by the actor who performed the action (optional).
	ActorID string
	// TargetID filters by the target of the action (optional).
	TargetID string
	// Limit is the maximum number of records to return (default 100, max 1000).
	Limit int
	// Cursor is the pagination cursor for fetching next page (optional).
	Cursor string
}

// ComplianceStats contains aggregated compliance statistics.
type ComplianceStats struct {
	// TotalEvents is the total count of compliance events.
	TotalEvents int64
	// AccessEvents is the count of access.* events.
	AccessEvents int64
	// ConfigChanges is the count of config.* events.
	ConfigChanges int64
	// UserLifecycleEvents is the count of user.* events.
	UserLifecycleEvents int64
	// FailedLogins is the count of access.login_failed events.
	FailedLogins int64
	// PolicyDenials is the count of tool_call events with denial reason.
	PolicyDenials int64
	// EventsByType maps event types to counts.
	EventsByType map[string]int64
}

// ComplianceAuditStore handles SOC 2 compliance audit records.
// These are separate from tool call audit records as they track
// access control, configuration changes, and user lifecycle events.
type ComplianceAuditStore interface {
	// Append stores compliance audit records.
	Append(ctx context.Context, records ...ComplianceAuditRecord) error

	// Query retrieves compliance audit records matching the filter.
	// Returns records, next cursor for pagination, and error.
	Query(ctx context.Context, filter ComplianceAuditFilter) ([]ComplianceAuditRecord, string, error)

	// QueryStats returns aggregated compliance statistics for the given time range.
	QueryStats(ctx context.Context, start, end time.Time) (*ComplianceStats, error)

	// PurgeOlderThan deletes compliance audit records older than the specified date.
	// This is used for retention management and should only be called after
	// verifying no active legal holds cover the affected time range.
	// Returns the number of records deleted.
	PurgeOlderThan(ctx context.Context, before time.Time) (int64, error)
}
