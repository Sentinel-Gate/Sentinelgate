package recording_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/recording"
)

func newTestRecorder(t *testing.T, cfg recording.RecordingConfig) *recording.FileRecorder {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	rec, err := recording.NewFileRecorder(cfg, logger)
	if err != nil {
		t.Fatalf("NewFileRecorder: %v", err)
	}
	return rec
}

func defaultCfg(dir string) recording.RecordingConfig {
	return recording.RecordingConfig{
		Enabled:        true,
		RecordPayloads: true,
		MaxFileSize:    0,
		RetentionDays:  30,
		StorageDir:     dir,
	}
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %q: %v", path, err)
	}
	defer f.Close()
	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			count++
		}
	}
	return count
}

func findSessionFile(t *testing.T, dir, sessionID string) string {
	t.Helper()
	pattern := filepath.Join(dir, sessionID+"_*.jsonl")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		t.Fatalf("no JSONL file found for session %q", sessionID)
	}
	return matches[0]
}

// TestFileRecorder_StartAndEndSession verifies a JSONL file is created on
// StartSession and that EndSession writes the SessionEnd event.
func TestFileRecorder_StartAndEndSession(t *testing.T) {
	dir := t.TempDir()
	rec := newTestRecorder(t, defaultCfg(dir))

	sessionID := "sess-start-end"
	if err := rec.StartSession(sessionID, "id1", "Alice"); err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	path := findSessionFile(t, dir, sessionID)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("JSONL file not created: %v", err)
	}

	if err := rec.EndSession(sessionID); err != nil {
		t.Fatalf("EndSession: %v", err)
	}

	// File should now contain SessionStart + SessionEnd = 2 lines.
	lines := countLines(t, path)
	if lines != 2 {
		t.Fatalf("expected 2 lines (start+end), got %d", lines)
	}

	// Verify the last line is SessionEnd.
	f, _ := os.Open(path)
	defer f.Close()
	sc := bufio.NewScanner(f)
	var last recording.RecordingEvent
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			_ = json.Unmarshal(sc.Bytes(), &last)
		}
	}
	if last.EventType != recording.EventSessionEnd {
		t.Errorf("last event should be session_end, got %q", last.EventType)
	}
}

// TestFileRecorder_RecordEvent verifies events are written with correct sequence numbers
// and that the file contains start + events + end lines.
func TestFileRecorder_RecordEvent(t *testing.T) {
	dir := t.TempDir()
	rec := newTestRecorder(t, defaultCfg(dir))

	sessionID := "sess-record"
	_ = rec.StartSession(sessionID, "id1", "Bob")

	events := []recording.RecordingEvent{
		{ToolName: "read_file", Decision: "allow", EventType: recording.EventToolCall},
		{ToolName: "write_file", Decision: "deny", EventType: recording.EventToolCall},
		{ToolName: "list_dir", Decision: "allow", EventType: recording.EventToolCall},
	}
	for _, e := range events {
		if err := rec.RecordEvent(sessionID, e); err != nil {
			t.Fatalf("RecordEvent: %v", err)
		}
	}
	_ = rec.EndSession(sessionID)

	path := findSessionFile(t, dir, sessionID)
	lines := countLines(t, path)
	// start(1) + 3 events + end(1) = 5
	if lines != 5 {
		t.Errorf("expected 5 lines, got %d", lines)
	}

	// Verify sequence numbers are monotonically increasing.
	f, _ := os.Open(path)
	defer f.Close()
	sc := bufio.NewScanner(f)
	seq := 0
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var ev recording.RecordingEvent
		_ = json.Unmarshal(sc.Bytes(), &ev)
		seq++
		if ev.Sequence != seq {
			t.Errorf("line %d: expected sequence %d, got %d", seq, seq, ev.Sequence)
		}
	}
}

// TestFileRecorder_PrivacyMode verifies that with RecordPayloads=false,
// RequestArgs and ResponseBody are omitted from written events.
func TestFileRecorder_PrivacyMode(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultCfg(dir)
	cfg.RecordPayloads = false
	rec := newTestRecorder(t, cfg)

	sessionID := "sess-privacy"
	_ = rec.StartSession(sessionID, "id1", "Carol")

	err := rec.RecordEvent(sessionID, recording.RecordingEvent{
		EventType:    recording.EventToolCall,
		ToolName:     "read_file",
		Decision:     "allow",
		RequestArgs:  map[string]interface{}{"path": "/secret/file"},
		ResponseBody: "secret content",
	})
	if err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
	_ = rec.EndSession(sessionID)

	// Read the tool_call event from the file.
	path := findSessionFile(t, dir, sessionID)
	f, _ := os.Open(path)
	defer f.Close()
	sc := bufio.NewScanner(f)
	var toolEvent recording.RecordingEvent
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var ev recording.RecordingEvent
		_ = json.Unmarshal(sc.Bytes(), &ev)
		if ev.EventType == recording.EventToolCall {
			toolEvent = ev
		}
	}

	if toolEvent.RequestArgs != nil {
		t.Errorf("expected nil RequestArgs in privacy mode, got %v", toolEvent.RequestArgs)
	}
	if toolEvent.ResponseBody != "" {
		t.Errorf("expected empty ResponseBody in privacy mode, got %q", toolEvent.ResponseBody)
	}
}

// TestFileRecorder_RedactPatterns verifies that credit card patterns are replaced
// with [REDACTED] in written events when RecordPayloads=true.
func TestFileRecorder_RedactPatterns(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultCfg(dir)
	cfg.RecordPayloads = true
	cfg.RedactPatterns = []string{`\d{4}-\d{4}-\d{4}-\d{4}`}
	rec := newTestRecorder(t, cfg)

	sessionID := "sess-redact"
	_ = rec.StartSession(sessionID, "id1", "Dave")

	err := rec.RecordEvent(sessionID, recording.RecordingEvent{
		EventType:    recording.EventToolCall,
		ToolName:     "submit_form",
		Decision:     "allow",
		RequestArgs:  map[string]interface{}{"card": "1234-5678-9012-3456"},
		ResponseBody: "card: 4321-8765-2109-6543",
	})
	if err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
	_ = rec.EndSession(sessionID)

	path := findSessionFile(t, dir, sessionID)
	f, _ := os.Open(path)
	defer f.Close()
	sc := bufio.NewScanner(f)
	var toolEvent recording.RecordingEvent
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var ev recording.RecordingEvent
		_ = json.Unmarshal(sc.Bytes(), &ev)
		if ev.EventType == recording.EventToolCall {
			toolEvent = ev
		}
	}

	if toolEvent.RequestArgs["card"] != "[REDACTED]" {
		t.Errorf("expected [REDACTED] in RequestArgs.card, got %v", toolEvent.RequestArgs["card"])
	}
	if toolEvent.ResponseBody != "card: [REDACTED]" {
		t.Errorf("expected redacted ResponseBody, got %q", toolEvent.ResponseBody)
	}
}

// TestFileRecorder_RedactNestedObjects verifies that redaction patterns are applied
// recursively to nested maps and arrays, not just top-level strings (NOTE-06-03).
func TestFileRecorder_RedactNestedObjects(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultCfg(dir)
	cfg.RecordPayloads = true
	cfg.RedactPatterns = []string{`secret\d+`}
	rec := newTestRecorder(t, cfg)

	sessionID := "sess-redact-nested"
	_ = rec.StartSession(sessionID, "id1", "Nested")

	err := rec.RecordEvent(sessionID, recording.RecordingEvent{
		EventType: recording.EventToolCall,
		ToolName:  "nested_tool",
		Decision:  "allow",
		RequestArgs: map[string]interface{}{
			// Top-level string (regression test).
			"api_key": "secret123",
			// Nested object.
			"user": map[string]interface{}{
				"name":     "Alice",
				"password": "secret456",
			},
			// Array with mixed types.
			"tokens": []interface{}{"secret789", "public_token", float64(42)},
			// Deep nesting (3+ levels).
			"deep": map[string]interface{}{
				"level1": map[string]interface{}{
					"level2": map[string]interface{}{
						"secret_val": "secret999",
						"number":     float64(100),
					},
				},
			},
			// Non-string value at top level.
			"count": float64(5),
			// Boolean.
			"enabled": true,
			// Nil value.
			"nothing": nil,
		},
	})
	if err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
	_ = rec.EndSession(sessionID)

	// Read the tool_call event from the JSONL file.
	path := findSessionFile(t, dir, sessionID)
	f, _ := os.Open(path)
	defer f.Close()
	sc := bufio.NewScanner(f)
	var toolEvent recording.RecordingEvent
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var ev recording.RecordingEvent
		_ = json.Unmarshal(sc.Bytes(), &ev)
		if ev.EventType == recording.EventToolCall {
			toolEvent = ev
		}
	}

	args := toolEvent.RequestArgs

	// 1. Top-level string redaction still works.
	if args["api_key"] != "[REDACTED]" {
		t.Errorf("top-level string: expected [REDACTED], got %v", args["api_key"])
	}

	// 2. Nested object redaction.
	user, ok := args["user"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected user to be map, got %T", args["user"])
	}
	if user["name"] != "Alice" {
		t.Errorf("nested non-matching string: expected Alice, got %v", user["name"])
	}
	if user["password"] != "[REDACTED]" {
		t.Errorf("nested matching string: expected [REDACTED], got %v", user["password"])
	}

	// 3. Array redaction.
	tokens, ok := args["tokens"].([]interface{})
	if !ok {
		t.Fatalf("expected tokens to be slice, got %T", args["tokens"])
	}
	if len(tokens) != 3 {
		t.Fatalf("expected 3 tokens, got %d", len(tokens))
	}
	if tokens[0] != "[REDACTED]" {
		t.Errorf("array matching string: expected [REDACTED], got %v", tokens[0])
	}
	if tokens[1] != "public_token" {
		t.Errorf("array non-matching string: expected public_token, got %v", tokens[1])
	}
	if tokens[2] != float64(42) {
		t.Errorf("array number should pass through unchanged: got %v", tokens[2])
	}

	// 4. Deep nesting (3+ levels).
	deep, _ := args["deep"].(map[string]interface{})
	l1, _ := deep["level1"].(map[string]interface{})
	l2, _ := l1["level2"].(map[string]interface{})
	if l2["secret_val"] != "[REDACTED]" {
		t.Errorf("3-level nested string: expected [REDACTED], got %v", l2["secret_val"])
	}
	if l2["number"] != float64(100) {
		t.Errorf("3-level nested number should pass through: got %v", l2["number"])
	}

	// 5. Non-string values pass through unchanged.
	if args["count"] != float64(5) {
		t.Errorf("top-level number should pass through: got %v", args["count"])
	}
	if args["enabled"] != true {
		t.Errorf("top-level bool should pass through: got %v", args["enabled"])
	}
	if args["nothing"] != nil {
		t.Errorf("top-level nil should pass through: got %v", args["nothing"])
	}
}

// TestFileRecorder_MaxFileSize verifies that recording stops gracefully when
// the file size limit is reached (no error returned to caller).
func TestFileRecorder_MaxFileSize(t *testing.T) {
	dir := t.TempDir()
	cfg := defaultCfg(dir)
	cfg.MaxFileSize = 500 // very small limit
	rec := newTestRecorder(t, cfg)

	sessionID := "sess-maxsize"
	_ = rec.StartSession(sessionID, "id1", "Eve")

	// Record many events until we would exceed the limit.
	for i := range 50 {
		err := rec.RecordEvent(sessionID, recording.RecordingEvent{
			EventType:    recording.EventToolCall,
			ToolName:     "tool",
			Decision:     "allow",
			ResponseBody: "some response body content " + itoa(i),
		})
		// Must not return an error — graceful stop.
		if err != nil {
			t.Fatalf("RecordEvent(%d) returned error: %v", i, err)
		}
	}
}

// TestFileRecorder_ListRecordings creates 3 sessions and verifies that
// ListRecordings returns all 3, sorted by StartedAt descending.
func TestFileRecorder_ListRecordings(t *testing.T) {
	dir := t.TempDir()
	rec := newTestRecorder(t, defaultCfg(dir))

	sessions := []struct{ id, identity string }{
		{"sess-list-a", "Alice"},
		{"sess-list-b", "Bob"},
		{"sess-list-c", "Carol"},
	}
	for _, s := range sessions {
		_ = rec.StartSession(s.id, "id-"+s.id, s.identity)
		time.Sleep(2 * time.Millisecond) // ensure distinct timestamps
		_ = rec.EndSession(s.id)
	}

	recordings, err := rec.ListRecordings()
	if err != nil {
		t.Fatalf("ListRecordings: %v", err)
	}
	if len(recordings) != 3 {
		t.Fatalf("expected 3 recordings, got %d", len(recordings))
	}

	// Verify descending order.
	for i := 1; i < len(recordings); i++ {
		if recordings[i].StartedAt.After(recordings[i-1].StartedAt) {
			t.Errorf("recordings not sorted descending: index %d (%v) > index %d (%v)",
				i, recordings[i].StartedAt, i-1, recordings[i-1].StartedAt)
		}
	}
}

// TestFileRecorder_GetEvents_Pagination verifies that GetEvents correctly applies
// offset and limit, returning events starting from the correct position.
func TestFileRecorder_GetEvents_Pagination(t *testing.T) {
	dir := t.TempDir()
	rec := newTestRecorder(t, defaultCfg(dir))

	sessionID := "sess-pagination"
	_ = rec.StartSession(sessionID, "id1", "Frank")

	for i := range 10 {
		_ = rec.RecordEvent(sessionID, recording.RecordingEvent{
			EventType: recording.EventToolCall,
			ToolName:  "tool_" + itoa(i),
			Decision:  "allow",
		})
	}
	_ = rec.EndSession(sessionID)

	// Total lines in file: start(1) + 10 events + end(1) = 12.
	// GetEvents with offset=2 limit=3 should return lines at index 2,3,4.
	events, total, err := rec.GetEvents(sessionID, 2, 3)
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if total != 12 {
		t.Errorf("expected total=12, got %d", total)
	}
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}
	// Index 0 = start (seq 1), index 1 = tool_0 (seq 2), index 2 = tool_1 (seq 3).
	// offset=2 → third line = tool_1, which has sequence 3.
	if events[0].Sequence != 3 {
		t.Errorf("expected first returned event sequence=3, got %d", events[0].Sequence)
	}
}

// TestFileRecorder_DeleteRecording verifies that the JSONL file is removed after deletion.
func TestFileRecorder_DeleteRecording(t *testing.T) {
	dir := t.TempDir()
	rec := newTestRecorder(t, defaultCfg(dir))

	sessionID := "sess-delete"
	_ = rec.StartSession(sessionID, "id1", "Grace")
	_ = rec.EndSession(sessionID)

	path := findSessionFile(t, dir, sessionID)

	if err := rec.DeleteRecording(sessionID); err != nil {
		t.Fatalf("DeleteRecording: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("expected file to be deleted, but it still exists")
	}
}

// TestRecordingConfig_Validate verifies all validation rules.
func TestRecordingConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     recording.RecordingConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			cfg:     recording.RecordingConfig{StorageDir: "recordings", RetentionDays: 30, MaxFileSize: 1024},
			wantErr: false,
		},
		{
			name:    "empty StorageDir",
			cfg:     recording.RecordingConfig{StorageDir: "", RetentionDays: 30},
			wantErr: true,
		},
		{
			name:    "negative RetentionDays",
			cfg:     recording.RecordingConfig{StorageDir: "dir", RetentionDays: -1},
			wantErr: true,
		},
		{
			name:    "negative MaxFileSize",
			cfg:     recording.RecordingConfig{StorageDir: "dir", MaxFileSize: -1},
			wantErr: true,
		},
		{
			name:    "invalid regex pattern",
			cfg:     recording.RecordingConfig{StorageDir: "dir", RedactPatterns: []string{"[invalid"}},
			wantErr: true,
		},
		{
			name: "valid regex pattern",
			cfg: recording.RecordingConfig{
				StorageDir:     "dir",
				RedactPatterns: []string{`\d{4}-\d{4}-\d{4}-\d{4}`},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestFileRecorder_ConcurrentRecording verifies no data races when 5 goroutines
// record events to the same session concurrently.
func TestFileRecorder_ConcurrentRecording(t *testing.T) {
	dir := t.TempDir()
	rec := newTestRecorder(t, defaultCfg(dir))

	sessionID := "sess-concurrent"
	_ = rec.StartSession(sessionID, "id1", "Harry")

	var wg sync.WaitGroup
	for i := range 5 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := range 10 {
				_ = rec.RecordEvent(sessionID, recording.RecordingEvent{
					EventType: recording.EventToolCall,
					ToolName:  "tool_" + itoa(n) + "_" + itoa(j),
					Decision:  "allow",
				})
			}
		}(i)
	}
	wg.Wait()
	_ = rec.EndSession(sessionID)
}

// TestValidateSessionID tests the validateSessionID function with various inputs.
func TestValidateSessionID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"valid alphanumeric", "valid-session_123", false},
		{"path traversal", "../../etc/passwd", true},
		{"forward slash", "foo/bar", true},
		{"backslash", "foo\\bar", true},
		{"empty string", "", true},
		{"spaces", "a b c", true},
		{"simple valid", "normal", false},
		{"dots only", "..", true},
		{"dot prefix", "../hack", true},
		{"backslash traversal", "..\\windows", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := recording.ValidateSessionID(tt.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSessionID(%q) error = %v, wantErr = %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

// TestFileRecorder_PathTraversal verifies that session IDs with path traversal
// characters are rejected before any file is created.
func TestFileRecorder_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	rec := newTestRecorder(t, defaultCfg(dir))

	badIDs := []string{
		"../../etc/cron.d/pwn",
		"normal/slash",
		"..\\windows",
		"",
		"foo bar",
	}

	for _, id := range badIDs {
		err := rec.StartSession(id, "id1", "Attacker")
		if !errors.Is(err, recording.ErrInvalidSessionID) {
			t.Errorf("StartSession(%q) = %v, want ErrInvalidSessionID", id, err)
		}
	}

	// Verify no files were created outside the storage dir.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no files in storage dir, found %d", len(entries))
	}

	// Also verify GetRecording and DeleteRecording reject bad IDs.
	_, err = rec.GetRecording("../../etc/passwd")
	if !errors.Is(err, recording.ErrInvalidSessionID) {
		t.Errorf("GetRecording with traversal ID: %v, want ErrInvalidSessionID", err)
	}

	err = rec.DeleteRecording("../../etc/passwd")
	if !errors.Is(err, recording.ErrInvalidSessionID) {
		t.Errorf("DeleteRecording with traversal ID: %v, want ErrInvalidSessionID", err)
	}

	_, _, err = rec.GetEvents("../../etc/passwd", 0, 10)
	if !errors.Is(err, recording.ErrInvalidSessionID) {
		t.Errorf("GetEvents with traversal ID: %v, want ErrInvalidSessionID", err)
	}
}

// TestFileRecorder_FilePermissions verifies that JSONL files are created with
// 0600 permissions (owner-only read/write), not the default 0644.
func TestFileRecorder_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions not supported on Windows")
	}
	dir := t.TempDir()
	rec := newTestRecorder(t, defaultCfg(dir))

	sessionID := "sess-perms-test"
	if err := rec.StartSession(sessionID, "id1", "PermCheck"); err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	path := findSessionFile(t, dir, sessionID)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("file permissions = %04o, want 0600", perm)
	}

	_ = rec.EndSession(sessionID)
}

// TestFileRecorder_GetEvents_StreamingLargeFile verifies that GetEvents can handle
// a session with 1000+ events and returns correct pagination without loading all
// events into memory (streaming via json.Decoder).
func TestFileRecorder_GetEvents_StreamingLargeFile(t *testing.T) {
	dir := t.TempDir()
	rec := newTestRecorder(t, defaultCfg(dir))

	sessionID := "sess-large"
	_ = rec.StartSession(sessionID, "id1", "LargeTest")

	const numEvents = 1000
	for i := range numEvents {
		_ = rec.RecordEvent(sessionID, recording.RecordingEvent{
			EventType: recording.EventToolCall,
			ToolName:  "tool_" + itoa(i),
			Decision:  "allow",
		})
	}
	_ = rec.EndSession(sessionID)

	// Total lines: start(1) + 1000 events + end(1) = 1002.
	// Get a page from the middle: offset=500, limit=10.
	events, total, err := rec.GetEvents(sessionID, 500, 10)
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if total != 1002 {
		t.Errorf("expected total=1002, got %d", total)
	}
	if len(events) != 10 {
		t.Errorf("expected 10 events, got %d", len(events))
	}
	// offset=500 → event at position 500 = tool_499 with sequence 501.
	if len(events) > 0 && events[0].Sequence != 501 {
		t.Errorf("expected first event sequence=501, got %d", events[0].Sequence)
	}

	// Edge case: offset beyond total returns empty slice.
	events, total, err = rec.GetEvents(sessionID, 2000, 10)
	if err != nil {
		t.Fatalf("GetEvents beyond total: %v", err)
	}
	if total != 1002 {
		t.Errorf("expected total=1002 even when offset beyond, got %d", total)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events when offset beyond total, got %d", len(events))
	}
}

// TestFileRecorder_GetEvents_OversizedLine verifies that GetEvents can handle
// JSONL lines larger than 1MB (json.Decoder has no fixed line buffer limit).
func TestFileRecorder_GetEvents_OversizedLine(t *testing.T) {
	dir := t.TempDir()

	// Manually write a JSONL file with one very large event (>1MB response body).
	sessionID := "sess-oversized"
	filePath := filepath.Join(dir, sessionID+"_20260219T120000Z.jsonl")

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}

	enc := json.NewEncoder(f)
	// Write start event.
	_ = enc.Encode(recording.RecordingEvent{
		Sequence:  1,
		EventType: recording.EventSessionStart,
		SessionID: sessionID,
	})
	// Write a tool_call with a >1MB response body.
	largeBody := strings.Repeat("x", 2*1024*1024) // 2MB
	_ = enc.Encode(recording.RecordingEvent{
		Sequence:     2,
		EventType:    recording.EventToolCall,
		SessionID:    sessionID,
		ToolName:     "big_tool",
		Decision:     "allow",
		ResponseBody: largeBody,
	})
	// Write end event.
	_ = enc.Encode(recording.RecordingEvent{
		Sequence:  3,
		EventType: recording.EventSessionEnd,
		SessionID: sessionID,
	})
	_ = f.Close()

	// Create a FileRecorder and read events.
	cfg := defaultCfg(dir)
	rec := newTestRecorder(t, cfg)

	events, total, err := rec.GetEvents(sessionID, 0, 10)
	if err != nil {
		t.Fatalf("GetEvents with oversized line: %v", err)
	}
	if total != 3 {
		t.Errorf("expected total=3, got %d", total)
	}
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}
	// Verify the large event was read correctly.
	if len(events) >= 2 && len(events[1].ResponseBody) != 2*1024*1024 {
		t.Errorf("expected 2MB response body, got %d bytes", len(events[1].ResponseBody))
	}
}

// TestFileRecorder_ReadFileMetadata_OversizedLine verifies that readFileMetadata
// (used by ListRecordings/GetRecording) handles JSONL files with >1MB lines.
func TestFileRecorder_ReadFileMetadata_OversizedLine(t *testing.T) {
	dir := t.TempDir()

	sessionID := "sess-meta-large"
	filePath := filepath.Join(dir, sessionID+"_20260219T130000Z.jsonl")

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}

	enc := json.NewEncoder(f)
	_ = enc.Encode(recording.RecordingEvent{
		Sequence:     1,
		EventType:    recording.EventSessionStart,
		SessionID:    sessionID,
		IdentityID:   "id1",
		IdentityName: "BigUser",
		Timestamp:    time.Date(2026, 2, 19, 13, 0, 0, 0, time.UTC),
	})
	// Write a >1MB event.
	_ = enc.Encode(recording.RecordingEvent{
		Sequence:     2,
		EventType:    recording.EventToolCall,
		SessionID:    sessionID,
		Decision:     "deny",
		ResponseBody: strings.Repeat("y", 1500000),
	})
	_ = enc.Encode(recording.RecordingEvent{
		Sequence:  3,
		EventType: recording.EventSessionEnd,
		SessionID: sessionID,
		Timestamp: time.Date(2026, 2, 19, 13, 5, 0, 0, time.UTC),
	})
	_ = f.Close()

	cfg := defaultCfg(dir)
	rec := newTestRecorder(t, cfg)

	meta, err := rec.GetRecording(sessionID)
	if err != nil {
		t.Fatalf("GetRecording with oversized line: %v", err)
	}
	if meta.SessionID != sessionID {
		t.Errorf("expected sessionID=%q, got %q", sessionID, meta.SessionID)
	}
	if meta.EventCount != 3 {
		t.Errorf("expected EventCount=3, got %d", meta.EventCount)
	}
	if meta.DenyCount != 1 {
		t.Errorf("expected DenyCount=1, got %d", meta.DenyCount)
	}
	if meta.EndedAt == nil {
		t.Error("expected EndedAt to be set")
	}
}

// TestFileRecorder_DeleteActiveRecording_BUG04 verifies that deleting the recording
// of an active session cleans up the in-memory mapping, so new events for the same
// identity create a fresh recording file instead of being silently lost (BUG-04).
func TestFileRecorder_DeleteActiveRecording_BUG04(t *testing.T) {
	dir := t.TempDir()
	rec := newTestRecorder(t, defaultCfg(dir))

	sessionID := "sess-bug04"

	// Start session and record some events.
	if err := rec.StartSession(sessionID, "id1", "BugUser"); err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	_ = rec.RecordEvent(sessionID, recording.RecordingEvent{
		EventType: recording.EventToolCall,
		ToolName:  "read_file",
		Decision:  "allow",
	})

	// Delete the recording while the session is still active.
	if err := rec.DeleteRecording(sessionID); err != nil {
		t.Fatalf("DeleteRecording: %v", err)
	}

	// Verify the old file is gone.
	pattern := filepath.Join(dir, sessionID+"_*.jsonl")
	matches, _ := filepath.Glob(pattern)
	if len(matches) != 0 {
		t.Fatalf("expected no files after delete, found %d", len(matches))
	}

	// Now start the session again (simulating new events for the same identity).
	if err := rec.StartSession(sessionID, "id1", "BugUser"); err != nil {
		t.Fatalf("StartSession after delete: %v", err)
	}

	// Record a new event — this must NOT be lost.
	err := rec.RecordEvent(sessionID, recording.RecordingEvent{
		EventType: recording.EventToolCall,
		ToolName:  "write_file",
		Decision:  "allow",
	})
	if err != nil {
		t.Fatalf("RecordEvent after delete: %v", err)
	}

	_ = rec.EndSession(sessionID)

	// Verify a new file was created with the fresh events.
	matches, _ = filepath.Glob(pattern)
	if len(matches) != 1 {
		t.Fatalf("expected 1 new file after re-start, found %d", len(matches))
	}

	// The new file should have start(1) + event(1) + end(1) = 3 lines.
	lines := countLines(t, matches[0])
	if lines != 3 {
		t.Errorf("expected 3 lines in new recording, got %d", lines)
	}
}

// itoa is a simple int-to-string helper for tests.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
