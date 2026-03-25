package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestAuditRecordCreation(t *testing.T) {
	now := time.Now().UTC()
	rec := AuditRecord{
		Timestamp:    now,
		SessionID:    "sess-001",
		IdentityID:   "id-42",
		IdentityName: "alice",
		ToolName:     "read_file",
		ToolArguments: map[string]interface{}{
			"path": "/data/report.csv",
		},
		Decision:      DecisionAllow,
		Reason:        "matched rule allow-readers",
		RuleID:        "rule-10",
		RequestID:     "req-abc",
		LatencyMicros: 450,
		Protocol:      "mcp",
		Framework:     "langchain",
	}

	if rec.Timestamp != now {
		t.Errorf("Timestamp = %v, want %v", rec.Timestamp, now)
	}
	if rec.SessionID != "sess-001" {
		t.Errorf("SessionID = %q, want %q", rec.SessionID, "sess-001")
	}
	if rec.IdentityID != "id-42" {
		t.Errorf("IdentityID = %q, want %q", rec.IdentityID, "id-42")
	}
	if rec.IdentityName != "alice" {
		t.Errorf("IdentityName = %q, want %q", rec.IdentityName, "alice")
	}
	if rec.ToolName != "read_file" {
		t.Errorf("ToolName = %q, want %q", rec.ToolName, "read_file")
	}
	if rec.Decision != DecisionAllow {
		t.Errorf("Decision = %q, want %q", rec.Decision, DecisionAllow)
	}
	if rec.Reason != "matched rule allow-readers" {
		t.Errorf("Reason = %q, want %q", rec.Reason, "matched rule allow-readers")
	}
	if rec.RuleID != "rule-10" {
		t.Errorf("RuleID = %q, want %q", rec.RuleID, "rule-10")
	}
	if rec.Protocol != "mcp" {
		t.Errorf("Protocol = %q, want %q", rec.Protocol, "mcp")
	}
	if rec.Framework != "langchain" {
		t.Errorf("Framework = %q, want %q", rec.Framework, "langchain")
	}
	if rec.LatencyMicros != 450 {
		t.Errorf("LatencyMicros = %d, want %d", rec.LatencyMicros, 450)
	}
}

func TestAuditRecordJSON(t *testing.T) {
	now := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	original := AuditRecord{
		Timestamp:    now,
		SessionID:    "sess-json",
		IdentityID:   "id-99",
		IdentityName: "bob",
		ToolName:     "execute_command",
		ToolArguments: map[string]interface{}{
			"cmd": "ls -la",
		},
		Decision:       DecisionDeny,
		Reason:         "blocked by policy",
		RuleID:         "rule-5",
		RequestID:      "req-xyz",
		LatencyMicros:  120,
		ScanDetections: 1,
		ScanAction:     "blocked",
		ScanTypes:      "secret",
		Protocol:       "http",
		Framework:      "crewai",
		Source:         "admin_evaluate",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded AuditRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("Timestamp mismatch: got %v, want %v", decoded.Timestamp, original.Timestamp)
	}
	if decoded.SessionID != original.SessionID {
		t.Errorf("SessionID = %q, want %q", decoded.SessionID, original.SessionID)
	}
	if decoded.IdentityID != original.IdentityID {
		t.Errorf("IdentityID = %q, want %q", decoded.IdentityID, original.IdentityID)
	}
	if decoded.ToolName != original.ToolName {
		t.Errorf("ToolName = %q, want %q", decoded.ToolName, original.ToolName)
	}
	if decoded.Decision != original.Decision {
		t.Errorf("Decision = %q, want %q", decoded.Decision, original.Decision)
	}
	if decoded.ScanDetections != original.ScanDetections {
		t.Errorf("ScanDetections = %d, want %d", decoded.ScanDetections, original.ScanDetections)
	}
	if decoded.ScanAction != original.ScanAction {
		t.Errorf("ScanAction = %q, want %q", decoded.ScanAction, original.ScanAction)
	}
	if decoded.ScanTypes != original.ScanTypes {
		t.Errorf("ScanTypes = %q, want %q", decoded.ScanTypes, original.ScanTypes)
	}
	if decoded.Protocol != original.Protocol {
		t.Errorf("Protocol = %q, want %q", decoded.Protocol, original.Protocol)
	}
	if decoded.Framework != original.Framework {
		t.Errorf("Framework = %q, want %q", decoded.Framework, original.Framework)
	}
	if decoded.Source != original.Source {
		t.Errorf("Source = %q, want %q", decoded.Source, original.Source)
	}
}

func TestAuditFilterDefaults(t *testing.T) {
	var f AuditFilter

	// A zero-value filter should be a valid Go struct (no panics).
	if f.StartTime != (time.Time{}) {
		t.Error("default StartTime should be zero")
	}
	if f.EndTime != (time.Time{}) {
		t.Error("default EndTime should be zero")
	}
	if f.UserID != "" {
		t.Error("default UserID should be empty")
	}
	if f.SessionID != "" {
		t.Error("default SessionID should be empty")
	}
	if f.ToolName != "" {
		t.Error("default ToolName should be empty")
	}
	if f.Decision != "" {
		t.Error("default Decision should be empty")
	}
	if f.Protocol != "" {
		t.Error("default Protocol should be empty")
	}
	if f.Limit != 0 {
		t.Errorf("default Limit = %d, want 0", f.Limit)
	}
	if f.LimitExplicit {
		t.Error("default LimitExplicit should be false")
	}
	if f.Cursor != "" {
		t.Error("default Cursor should be empty")
	}
}

func TestAuditScanContext(t *testing.T) {
	ctx := context.Background()
	ctxWithScan, holder := NewScanResultContext(ctx)

	if holder == nil {
		t.Fatal("NewScanResultContext returned nil holder")
	}

	// The holder should be retrievable from the context.
	retrieved := ScanResultFromContext(ctxWithScan)
	if retrieved == nil {
		t.Fatal("ScanResultFromContext returned nil")
	}
	if retrieved != holder {
		t.Error("retrieved holder is not the same pointer as the original")
	}

	// Verify initial zero values.
	if holder.Detections != 0 {
		t.Errorf("initial Detections = %d, want 0", holder.Detections)
	}
	if holder.Action != "" {
		t.Errorf("initial Action = %q, want empty", holder.Action)
	}
	if holder.Types != "" {
		t.Errorf("initial Types = %q, want empty", holder.Types)
	}

	// Mutating the holder should be visible via the context.
	holder.Detections = 3
	holder.Action = "blocked"
	holder.Types = "secret,pii"

	retrieved2 := ScanResultFromContext(ctxWithScan)
	if retrieved2.Detections != 3 {
		t.Errorf("Detections = %d, want 3", retrieved2.Detections)
	}
	if retrieved2.Action != "blocked" {
		t.Errorf("Action = %q, want %q", retrieved2.Action, "blocked")
	}
}

func TestAuditScanContext_MissingReturnsNil(t *testing.T) {
	ctx := context.Background()
	holder := ScanResultFromContext(ctx)
	if holder != nil {
		t.Error("ScanResultFromContext on plain context should return nil")
	}
}

func TestAuditTransformContext(t *testing.T) {
	ctx := context.Background()
	ctxWithTx, holder := NewTransformResultContext(ctx)

	if holder == nil {
		t.Fatal("NewTransformResultContext returned nil holder")
	}

	// The holder should be retrievable from the context.
	retrieved := TransformResultFromContext(ctxWithTx)
	if retrieved == nil {
		t.Fatal("TransformResultFromContext returned nil")
	}
	if retrieved != holder {
		t.Error("retrieved holder is not the same pointer as the original")
	}

	// Verify initial empty Results.
	if len(holder.Results) != 0 {
		t.Errorf("initial Results length = %d, want 0", len(holder.Results))
	}

	// Append a transform result and verify visibility.
	holder.Results = append(holder.Results, TransformApplied{
		RuleID:   "tx-1",
		RuleName: "redact-pii",
		Type:     "redact",
		Detail:   "replaced SSN",
	})

	retrieved2 := TransformResultFromContext(ctxWithTx)
	if len(retrieved2.Results) != 1 {
		t.Fatalf("Results length = %d, want 1", len(retrieved2.Results))
	}
	if retrieved2.Results[0].RuleID != "tx-1" {
		t.Errorf("RuleID = %q, want %q", retrieved2.Results[0].RuleID, "tx-1")
	}
	if retrieved2.Results[0].Type != "redact" {
		t.Errorf("Type = %q, want %q", retrieved2.Results[0].Type, "redact")
	}
}

func TestAuditTransformContext_MissingReturnsNil(t *testing.T) {
	ctx := context.Background()
	holder := TransformResultFromContext(ctx)
	if holder != nil {
		t.Error("TransformResultFromContext on plain context should return nil")
	}
}
