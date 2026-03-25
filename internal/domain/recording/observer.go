package recording

import (
	"log/slog"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// SessionInfoProvider is a minimal interface to retrieve session usage without
// importing the session package (avoids import cycle: recording -> session -> ...).
// The concrete implementation lives in start.go as recordingSessionAdapter.
type SessionInfoProvider interface {
	// GetUsage returns a usage snapshot for the given session ID.
	// Returns (snapshot, true) if found, or (zero, false) if not tracked.
	GetUsage(sessionID string) (SessionUsageSnapshot, bool)
}

// SessionUsageSnapshot captures the call counters for a session at a point in time.
// This is a local mirror of session.SessionUsage, duplicated to avoid import cycles
// (same pattern as SessionActionRecord in the action and policy packages).
type SessionUsageSnapshot struct {
	TotalCalls  int64
	ReadCalls   int64
	WriteCalls  int64
	DeleteCalls int64
}

// QuotaLimitProvider is a minimal interface to retrieve configured quota limits
// for an identity without importing the quota package (avoids import cycles).
// The concrete implementation lives in boot_interceptors.go as quotaLimitAdapter.
type QuotaLimitProvider interface {
	// GetLimits returns configured quota limits for the given identity.
	// Returns (snapshot, true) if found and enabled, or (zero, false) if not configured.
	GetLimits(identityID string) (QuotaLimitsSnapshot, bool)
}

// QuotaLimitsSnapshot captures the configured limits for an identity.
type QuotaLimitsSnapshot struct {
	MaxCallsPerSession   int64
	MaxWritesPerSession  int64
	MaxDeletesPerSession int64
	MaxCallsPerMinute    int64
}

// RecordingObserver bridges the proxy audit chain to the recording subsystem.
// It converts audit.AuditRecord values into RecordingEvent values and writes
// them to the FileRecorder. All operations are non-blocking (errors are logged,
// never returned) so the observer never impacts the MCP request path.
type RecordingObserver struct {
	recorder    *FileRecorder
	sessionInfo SessionInfoProvider  // may be nil
	quotaLimits QuotaLimitProvider   // may be nil
	logger      *slog.Logger
}

// SetQuotaLimitProvider sets the provider used to resolve configured quota limits
// for the identity. This is called during boot after the quota store is created.
func (o *RecordingObserver) SetQuotaLimitProvider(p QuotaLimitProvider) {
	o.quotaLimits = p
}

// NewRecordingObserver creates a RecordingObserver.
// recorder may be nil to disable recording (OnAuditRecord becomes a no-op).
// sessionInfo may be nil; quota snapshots are simply omitted when nil.
func NewRecordingObserver(recorder *FileRecorder, sessionInfo SessionInfoProvider, logger *slog.Logger) *RecordingObserver {
	return &RecordingObserver{
		recorder:    recorder,
		sessionInfo: sessionInfo,
		logger:      logger,
	}
}

// OnAuditRecord converts an audit.AuditRecord to a RecordingEvent and appends it
// to the session's JSONL file. If recording is disabled or the recorder is nil
// this is a no-op with zero allocation cost.
//
// This method is called from a goroutine spawned by AuditInterceptor after each
// tool call. It is safe for concurrent invocations.
func (o *RecordingObserver) OnAuditRecord(record audit.AuditRecord) {
	if o.recorder == nil {
		return
	}

	// Fast-path: read config via accessor, avoid work when disabled (L-3).
	cfg := o.recorder.GetConfig()

	if !cfg.Enabled {
		return
	}

	// Auto-start session on first event (atomic check-and-start, race-free).
	if err := o.recorder.startSessionIfNeeded(record.SessionID, record.IdentityID, record.IdentityName); err != nil {
		o.logger.Warn("recording: failed to start session",
			"session_id", record.SessionID,
			"error", err,
		)
		return
	}

	// Build event from audit record.
	event := RecordingEvent{
		Timestamp:    record.Timestamp,
		EventType:    EventToolCall,
		ToolName:     record.ToolName,
		Decision:     record.Decision,
		Reason:       record.Reason,
		RuleID:       record.RuleID,
		LatencyMicros: record.LatencyMicros,
		SessionID:    record.SessionID,
		IdentityID:   record.IdentityID,
		IdentityName: record.IdentityName,
	}

	// Attach request/response payloads only when payload recording is enabled.
	if cfg.RecordPayloads {
		event.RequestArgs = record.ToolArguments
		event.ResponseBody = record.ResponseBody
	}

	// Extract applied transform names.
	if len(record.TransformResults) > 0 {
		names := make([]string, 0, len(record.TransformResults))
		for _, tr := range record.TransformResults {
			if tr.RuleName != "" {
				names = append(names, tr.RuleName)
			}
		}
		if len(names) > 0 {
			event.TransformsApplied = names
		}
	}

	// Attach quota snapshot if session info is available.
	if o.sessionInfo != nil {
		if snapshot, ok := o.sessionInfo.GetUsage(record.SessionID); ok {
			qs := &QuotaSnapshot{
				TotalCalls:  snapshot.TotalCalls,
				ReadCalls:   snapshot.ReadCalls,
				WriteCalls:  snapshot.WriteCalls,
				DeleteCalls: snapshot.DeleteCalls,
			}
			// Resolve configured limits for this identity so the frontend
			// can display them without a separate API call (Bug 6 fix).
			if o.quotaLimits != nil && record.IdentityID != "" {
				if limits, found := o.quotaLimits.GetLimits(record.IdentityID); found {
					qs.TotalLimit = limits.MaxCallsPerSession
					qs.WriteLimit = limits.MaxWritesPerSession
					qs.DeleteLimit = limits.MaxDeletesPerSession
					qs.MinuteLimit = limits.MaxCallsPerMinute
				}
			}
			event.QuotaState = qs
		}
	}

	if err := o.recorder.RecordEvent(record.SessionID, event); err != nil {
		o.logger.Warn("recording: failed to record event",
			"session_id", record.SessionID,
			"tool", record.ToolName,
			"error", err,
		)
	}
}

// OnSessionEnd closes the recording file for the given session.
// Errors are logged at Warn level and never returned.
func (o *RecordingObserver) OnSessionEnd(sessionID string) {
	if o.recorder == nil {
		return
	}
	if err := o.recorder.EndSession(sessionID); err != nil {
		o.logger.Warn("recording: failed to end session",
			"session_id", sessionID,
			"error", err,
		)
	}
}
