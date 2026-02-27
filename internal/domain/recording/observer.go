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

// RecordingObserver bridges the proxy audit chain to the recording subsystem.
// It converts audit.AuditRecord values into RecordingEvent values and writes
// them to the FileRecorder. All operations are non-blocking (errors are logged,
// never returned) so the observer never impacts the MCP request path.
type RecordingObserver struct {
	recorder    *FileRecorder
	sessionInfo SessionInfoProvider // may be nil
	logger      *slog.Logger
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

	// Fast-path: read config under lock, avoid work when disabled.
	o.recorder.mu.Lock()
	enabled := o.recorder.config.Enabled
	recordPayloads := o.recorder.config.RecordPayloads
	o.recorder.mu.Unlock()

	if !enabled {
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

	// Attach request args only when payload recording is enabled.
	if recordPayloads {
		event.RequestArgs = record.ToolArguments
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
			event.QuotaState = &QuotaSnapshot{
				TotalCalls:  snapshot.TotalCalls,
				ReadCalls:   snapshot.ReadCalls,
				WriteCalls:  snapshot.WriteCalls,
				DeleteCalls: snapshot.DeleteCalls,
			}
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
