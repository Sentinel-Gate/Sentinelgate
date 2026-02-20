// Package memory provides in-memory implementations of outbound ports.
package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

func TestAuditStore_Append(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	buf := &bytes.Buffer{}
	store := NewAuditStoreWithWriter(buf)

	record := audit.AuditRecord{
		RequestID:  "req-1",
		ToolName:   "test_tool",
		Decision:   audit.DecisionAllow,
		Timestamp:  time.Now().UTC(),
		SessionID:  "sess-123",
		IdentityID: "user-1",
	}

	if err := store.Append(ctx, record); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	// Verify JSON was written
	output := buf.String()
	if output == "" {
		t.Fatal("Append() did not write to buffer")
	}

	// Verify it's valid JSON
	var decoded audit.AuditRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &decoded); err != nil {
		t.Fatalf("Written output is not valid JSON: %v", err)
	}

	if decoded.RequestID != "req-1" {
		t.Errorf("RequestID = %q, want %q", decoded.RequestID, "req-1")
	}
	if decoded.ToolName != "test_tool" {
		t.Errorf("ToolName = %q, want %q", decoded.ToolName, "test_tool")
	}
}

func TestAuditStore_AppendMultiple(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	buf := &bytes.Buffer{}
	store := NewAuditStoreWithWriter(buf)

	records := []audit.AuditRecord{
		{
			RequestID: "req-1",
			ToolName:  "tool_1",
			Decision:  audit.DecisionAllow,
			Timestamp: time.Now().UTC(),
		},
		{
			RequestID: "req-2",
			ToolName:  "tool_2",
			Decision:  audit.DecisionDeny,
			Timestamp: time.Now().UTC(),
		},
		{
			RequestID: "req-3",
			ToolName:  "tool_3",
			Decision:  audit.DecisionAllow,
			Timestamp: time.Now().UTC(),
		},
	}

	if err := store.Append(ctx, records...); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	// Verify multiple JSON lines were written
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 3 {
		t.Errorf("Expected 3 JSON lines, got %d", len(lines))
	}

	// Verify each line is valid JSON
	for i, line := range lines {
		var decoded audit.AuditRecord
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Errorf("Line %d is not valid JSON: %v", i, err)
		}
		expectedReqID := "req-" + string(rune('1'+i))
		if decoded.RequestID != expectedReqID {
			t.Errorf("Line %d RequestID = %q, want %q", i, decoded.RequestID, expectedReqID)
		}
	}
}

func TestAuditStore_CustomWriter(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	buf := &bytes.Buffer{}
	store := NewAuditStoreWithWriter(buf)

	record := audit.AuditRecord{
		RequestID:     "req-custom",
		ToolName:      "custom_tool",
		Decision:      audit.DecisionAllow,
		Timestamp:     time.Now().UTC(),
		ToolArguments: map[string]interface{}{"key": "value"},
	}

	if err := store.Append(ctx, record); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "custom_tool") {
		t.Error("Expected output to contain 'custom_tool'")
	}
	if !strings.Contains(output, "req-custom") {
		t.Error("Expected output to contain 'req-custom'")
	}
}

func TestAuditStore_Flush(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	buf := &bytes.Buffer{}
	store := NewAuditStoreWithWriter(buf)

	// Append a record
	record := audit.AuditRecord{
		RequestID: "req-flush",
		ToolName:  "flush_tool",
		Timestamp: time.Now().UTC(),
	}
	if err := store.Append(ctx, record); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	// Flush is a no-op but should not error
	if err := store.Flush(ctx); err != nil {
		t.Errorf("Flush() error: %v (expected nil, flush is no-op)", err)
	}

	// Verify the record is still there
	if buf.Len() == 0 {
		t.Error("Buffer should still contain data after Flush()")
	}
}

func TestAuditStore_Close(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	store := NewAuditStoreWithWriter(buf)

	// Close should work for non-file writers (no-op)
	if err := store.Close(); err != nil {
		t.Errorf("Close() error: %v (expected nil for non-file writer)", err)
	}
}

func TestAuditStore_AppendEmpty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	buf := &bytes.Buffer{}
	store := NewAuditStoreWithWriter(buf)

	// Append with no records should not error
	if err := store.Append(ctx); err != nil {
		t.Errorf("Append() with no records error: %v", err)
	}

	if buf.Len() != 0 {
		t.Errorf("Buffer should be empty after appending no records, got %d bytes", buf.Len())
	}
}

func TestAuditStore_ConcurrentAppend(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	buf := &bytes.Buffer{}
	store := NewAuditStoreWithWriter(buf)

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// 100 concurrent appends
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			record := audit.AuditRecord{
				RequestID: "req-" + string(rune('a'+(idx%26))),
				ToolName:  "concurrent_tool",
				Decision:  audit.DecisionAllow,
				Timestamp: time.Now().UTC(),
			}
			if err := store.Append(ctx, record); err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent Append() error: %v", err)
	}

	// Verify we have 100 lines
	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 100 {
		t.Errorf("Expected 100 JSON lines, got %d", len(lines))
	}
}

func TestAuditStore_RecordFields(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	buf := &bytes.Buffer{}
	store := NewAuditStoreWithWriter(buf)

	now := time.Now().UTC()
	record := audit.AuditRecord{
		RequestID:      "req-fields",
		ToolName:       "fields_tool",
		Decision:       audit.DecisionDeny,
		Timestamp:      now,
		SessionID:      "sess-456",
		IdentityID:     "user-admin",
		Reason:         "Policy violation",
		RuleID:         "rule-123",
		LatencyMicros:  1500,
		ScanDetections: 2,
		ScanAction:     "blocked",
		ScanTypes:      "secret,pii",
		ToolArguments:  map[string]interface{}{"path": "/etc/passwd"},
	}

	if err := store.Append(ctx, record); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	// Decode and verify all fields
	var decoded audit.AuditRecord
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}

	if decoded.RequestID != "req-fields" {
		t.Errorf("RequestID = %q, want %q", decoded.RequestID, "req-fields")
	}
	if decoded.Decision != audit.DecisionDeny {
		t.Errorf("Decision = %q, want %q", decoded.Decision, audit.DecisionDeny)
	}
	if decoded.SessionID != "sess-456" {
		t.Errorf("SessionID = %q, want %q", decoded.SessionID, "sess-456")
	}
	if decoded.IdentityID != "user-admin" {
		t.Errorf("IdentityID = %q, want %q", decoded.IdentityID, "user-admin")
	}
	if decoded.Reason != "Policy violation" {
		t.Errorf("Reason = %q, want %q", decoded.Reason, "Policy violation")
	}
	if decoded.RuleID != "rule-123" {
		t.Errorf("RuleID = %q, want %q", decoded.RuleID, "rule-123")
	}
	if decoded.LatencyMicros != 1500 {
		t.Errorf("LatencyMicros = %d, want %d", decoded.LatencyMicros, 1500)
	}
	if decoded.ScanDetections != 2 {
		t.Errorf("ScanDetections = %d, want %d", decoded.ScanDetections, 2)
	}
	if decoded.ScanAction != "blocked" {
		t.Errorf("ScanAction = %q, want %q", decoded.ScanAction, "blocked")
	}
	if decoded.ScanTypes != "secret,pii" {
		t.Errorf("ScanTypes = %q, want %q", decoded.ScanTypes, "secret,pii")
	}
}

func TestAuditStore_DefaultStdout(t *testing.T) {
	// Note: This test just verifies NewAuditStore doesn't panic
	// We don't actually write to stdout in tests

	store := NewAuditStore()
	if store == nil {
		t.Fatal("NewAuditStore() returned nil")
	}

	// Close should work (stdout is not closed)
	if err := store.Close(); err != nil {
		t.Errorf("Close() on default store error: %v", err)
	}
}
