// Package recording provides session recording and replay functionality.
// It writes one JSONL file per session with one JSON object per line.
package recording

import "time"

// RecordingEventType identifies the kind of event in a recording.
type RecordingEventType string

const (
	// EventToolCall represents a single tool call event within a session.
	EventToolCall RecordingEventType = "tool_call"
	// EventSessionStart marks the beginning of a recorded session.
	EventSessionStart RecordingEventType = "session_start"
	// EventSessionEnd marks the end of a recorded session.
	EventSessionEnd RecordingEventType = "session_end"
)

// QuotaSnapshot captures quota counters at the moment of a tool call.
type QuotaSnapshot struct {
	TotalCalls  int64 `json:"total_calls"`
	ReadCalls   int64 `json:"read_calls"`
	WriteCalls  int64 `json:"write_calls"`
	DeleteCalls int64 `json:"delete_calls"`
}

// RecordingEvent is a single line in a JSONL recording file.
type RecordingEvent struct {
	// Sequence is monotonically increasing per session, starting at 1.
	Sequence int `json:"sequence"`
	// Timestamp is when this event occurred.
	Timestamp time.Time `json:"timestamp"`
	// EventType classifies the event.
	EventType RecordingEventType `json:"event_type"`
	// SessionID is the owning session identifier.
	SessionID string `json:"session_id"`
	// IdentityID of the user making the call.
	IdentityID string `json:"identity_id,omitempty"`
	// IdentityName is the human-readable identity name.
	IdentityName string `json:"identity_name,omitempty"`
	// ToolName is the name of the tool invoked (empty for session start/end).
	ToolName string `json:"tool_name,omitempty"`
	// Decision is "allow" or "deny" (empty for session start/end).
	Decision string `json:"decision,omitempty"`
	// Reason explains the policy decision.
	Reason string `json:"reason,omitempty"`
	// RuleID is the ID of the rule that matched (if any).
	RuleID string `json:"rule_id,omitempty"`
	// RequestArgs holds the tool call arguments. Nil when RecordPayloads=false.
	RequestArgs map[string]interface{} `json:"request_args,omitempty"`
	// ResponseBody holds the tool response text. Empty when RecordPayloads=false.
	ResponseBody string `json:"response_body,omitempty"`
	// TransformsApplied lists the transform rule names applied to this call.
	TransformsApplied []string `json:"transforms_applied,omitempty"`
	// QuotaState captures quota counters at the time of the call.
	QuotaState *QuotaSnapshot `json:"quota_state,omitempty"`
	// LatencyMicros is the policy evaluation latency in microseconds.
	LatencyMicros int64 `json:"latency_micros,omitempty"`
}

// SessionRecording is metadata about a recording file on disk.
type SessionRecording struct {
	// SessionID identifies the session this recording belongs to.
	SessionID string `json:"session_id"`
	// IdentityID of the recorded user.
	IdentityID string `json:"identity_id"`
	// IdentityName is the human-readable name of the recorded user.
	IdentityName string `json:"identity_name"`
	// StartedAt is when the session recording began.
	StartedAt time.Time `json:"started_at"`
	// EndedAt is when the session ended, nil if still active.
	EndedAt *time.Time `json:"ended_at,omitempty"`
	// EventCount is the total number of events in the recording.
	EventCount int `json:"event_count"`
	// DenyCount is the number of denied tool calls in the recording.
	DenyCount int `json:"deny_count"`
	// FilePath is the absolute path to the JSONL file.
	FilePath string `json:"file_path"`
	// FileSize is the size of the JSONL file in bytes.
	FileSize int64 `json:"file_size"`
}
