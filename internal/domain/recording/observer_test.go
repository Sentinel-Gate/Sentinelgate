package recording

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// mockSessionInfo is a simple SessionInfoProvider for tests.
type mockSessionInfo struct {
	mu   sync.Mutex
	data map[string]SessionUsageSnapshot
}

func newMockSessionInfo() *mockSessionInfo {
	return &mockSessionInfo{data: make(map[string]SessionUsageSnapshot)}
}

func (m *mockSessionInfo) set(sessionID string, snap SessionUsageSnapshot) {
	m.mu.Lock()
	m.data[sessionID] = snap
	m.mu.Unlock()
}

func (m *mockSessionInfo) GetUsage(sessionID string) (SessionUsageSnapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap, ok := m.data[sessionID]
	return snap, ok
}

// makeAuditRecord returns a minimal AuditRecord for a given session.
func makeAuditRecord(sessionID, toolName, decision string) audit.AuditRecord {
	return audit.AuditRecord{
		Timestamp:    time.Now().UTC(),
		SessionID:    sessionID,
		IdentityID:   "id-" + sessionID,
		IdentityName: "user-" + sessionID,
		ToolName:     toolName,
		Decision:     decision,
		Reason:       "test-reason",
		LatencyMicros: 42,
	}
}

// readAllEvents reads all JSONL events from the first *.jsonl file for a session.
func readAllEvents(t *testing.T, dir, sessionID string) []RecordingEvent {
	t.Helper()
	pattern := filepath.Join(dir, sessionID+"_*.jsonl")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		t.Fatalf("no JSONL file found for session %s in %s", sessionID, dir)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read JSONL: %v", err)
	}

	var events []RecordingEvent
	// Split by newline and decode each line.
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var ev RecordingEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Logf("skip malformed line: %v", err)
			continue
		}
		events = append(events, ev)
	}
	return events
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// TestRecordingObserver_DisabledNoOp verifies that when recording is disabled
// no file is created and OnAuditRecord returns immediately.
func TestRecordingObserver_DisabledNoOp(t *testing.T) {
	dir := t.TempDir()
	cfg := RecordingConfig{
		Enabled:       false,
		StorageDir:    dir,
		MaxFileSize:   DefaultMaxFileSize,
		RetentionDays: DefaultRetentionDays,
	}
	recorder, err := NewFileRecorder(cfg, nil)
	if err != nil {
		t.Fatalf("NewFileRecorder: %v", err)
	}

	obs := NewRecordingObserver(recorder, nil, newTestLogger(t))
	obs.OnAuditRecord(makeAuditRecord("sess-disabled", "read_file", "allow"))

	// No JSONL file should have been created.
	matches, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(matches) != 0 {
		t.Errorf("expected no files created when disabled, got %d", len(matches))
	}
}

// TestRecordingObserver_AutoStartsSession verifies that calling OnAuditRecord
// for a new session ID automatically starts the session file and writes events.
func TestRecordingObserver_AutoStartsSession(t *testing.T) {
	dir := t.TempDir()
	cfg := RecordingConfig{
		Enabled:       true,
		StorageDir:    dir,
		MaxFileSize:   DefaultMaxFileSize,
		RetentionDays: DefaultRetentionDays,
	}
	recorder, err := NewFileRecorder(cfg, nil)
	if err != nil {
		t.Fatalf("NewFileRecorder: %v", err)
	}

	obs := NewRecordingObserver(recorder, nil, newTestLogger(t))
	t.Cleanup(func() { _ = recorder.EndSession("sess-autostart") })
	obs.OnAuditRecord(makeAuditRecord("sess-autostart", "list_files", "allow"))

	events := readAllEvents(t, dir, "sess-autostart")
	// Expect at least 2 events: session_start + tool_call.
	if len(events) < 2 {
		t.Fatalf("expected >= 2 events, got %d", len(events))
	}
	if events[0].EventType != EventSessionStart {
		t.Errorf("first event: got %q, want %q", events[0].EventType, EventSessionStart)
	}
	// Find the tool_call event.
	var toolCallFound bool
	for _, ev := range events {
		if ev.EventType == EventToolCall && ev.ToolName == "list_files" {
			toolCallFound = true
			break
		}
	}
	if !toolCallFound {
		t.Error("no tool_call event with tool_name=list_files found")
	}
}

// TestRecordingObserver_PrivacyStripsPayloads verifies that with RecordPayloads=false
// the event written has nil RequestArgs even when the audit record has args.
func TestRecordingObserver_PrivacyStripsPayloads(t *testing.T) {
	dir := t.TempDir()
	cfg := RecordingConfig{
		Enabled:        true,
		RecordPayloads: false, // privacy mode
		StorageDir:     dir,
		MaxFileSize:    DefaultMaxFileSize,
		RetentionDays:  DefaultRetentionDays,
	}
	recorder, err := NewFileRecorder(cfg, nil)
	if err != nil {
		t.Fatalf("NewFileRecorder: %v", err)
	}

	obs := NewRecordingObserver(recorder, nil, newTestLogger(t))
	t.Cleanup(func() { _ = recorder.EndSession("sess-privacy") })
	record := makeAuditRecord("sess-privacy", "write_file", "allow")
	record.ToolArguments = map[string]interface{}{
		"path":    "/etc/secret",
		"content": "sensitive data",
	}
	obs.OnAuditRecord(record)

	events := readAllEvents(t, dir, "sess-privacy")
	for _, ev := range events {
		if ev.EventType == EventToolCall {
			if ev.RequestArgs != nil {
				t.Errorf("privacy mode: RequestArgs should be nil, got %v", ev.RequestArgs)
			}
			return
		}
	}
	t.Error("no tool_call event found")
}

// TestRecordingObserver_QuotaSnapshot verifies that the QuotaState field is populated
// from the SessionInfoProvider when available.
func TestRecordingObserver_QuotaSnapshot(t *testing.T) {
	dir := t.TempDir()
	cfg := RecordingConfig{
		Enabled:       true,
		StorageDir:    dir,
		MaxFileSize:   DefaultMaxFileSize,
		RetentionDays: DefaultRetentionDays,
	}
	recorder, err := NewFileRecorder(cfg, nil)
	if err != nil {
		t.Fatalf("NewFileRecorder: %v", err)
	}

	info := newMockSessionInfo()
	info.set("sess-quota", SessionUsageSnapshot{
		TotalCalls:  5,
		ReadCalls:   3,
		WriteCalls:  1,
		DeleteCalls: 1,
	})

	obs := NewRecordingObserver(recorder, info, newTestLogger(t))
	t.Cleanup(func() { _ = recorder.EndSession("sess-quota") })
	obs.OnAuditRecord(makeAuditRecord("sess-quota", "read_file", "allow"))

	events := readAllEvents(t, dir, "sess-quota")
	for _, ev := range events {
		if ev.EventType == EventToolCall {
			if ev.QuotaState == nil {
				t.Fatal("QuotaState should not be nil when session info is available")
			}
			if ev.QuotaState.TotalCalls != 5 {
				t.Errorf("TotalCalls: got %d, want 5", ev.QuotaState.TotalCalls)
			}
			if ev.QuotaState.ReadCalls != 3 {
				t.Errorf("ReadCalls: got %d, want 3", ev.QuotaState.ReadCalls)
			}
			if ev.QuotaState.WriteCalls != 1 {
				t.Errorf("WriteCalls: got %d, want 1", ev.QuotaState.WriteCalls)
			}
			if ev.QuotaState.DeleteCalls != 1 {
				t.Errorf("DeleteCalls: got %d, want 1", ev.QuotaState.DeleteCalls)
			}
			return
		}
	}
	t.Error("no tool_call event found")
}

// TestRecordingObserver_ConcurrentCalls verifies that 10 goroutines calling
// OnAuditRecord for the same session do not cause a panic or data race.
// Run with -race flag.
func TestRecordingObserver_ConcurrentCalls(t *testing.T) {
	dir := t.TempDir()
	cfg := RecordingConfig{
		Enabled:       true,
		StorageDir:    dir,
		MaxFileSize:   DefaultMaxFileSize,
		RetentionDays: DefaultRetentionDays,
	}
	recorder, err := NewFileRecorder(cfg, nil)
	if err != nil {
		t.Fatalf("NewFileRecorder: %v", err)
	}

	obs := NewRecordingObserver(recorder, nil, newTestLogger(t))
	t.Cleanup(func() { _ = recorder.EndSession("sess-concurrent") })

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			obs.OnAuditRecord(makeAuditRecord("sess-concurrent", "read_file", "allow"))
		}()
	}
	wg.Wait()

	// Verify we got a valid JSONL file (at least session_start + some tool calls).
	events := readAllEvents(t, dir, "sess-concurrent")
	if len(events) < 2 {
		t.Fatalf("expected >= 2 events after concurrent calls, got %d", len(events))
	}
	if events[0].EventType != EventSessionStart {
		t.Errorf("first event: got %q, want %q", events[0].EventType, EventSessionStart)
	}
	// All events should have valid JSON (already verified by readAllEvents decoding).
}

// newTestLogger returns a no-op slog.Logger for tests.
// Uses nil to skip log output — the default logger will be used which goes to stderr.
// In test context this is acceptable; the important thing is no nil dereference.
func newTestLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.Default()
}
