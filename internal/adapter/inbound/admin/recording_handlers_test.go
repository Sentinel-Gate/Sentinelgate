package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/recording"
)

// setupRecordingTestHandler creates a test environment for recording handler tests.
// Returns the handler, a FileRecorder with recording enabled, and the temp dir path.
func setupRecordingTestHandler(t *testing.T) (*AdminAPIHandler, *recording.FileRecorder, string) {
	t.Helper()
	tmpDir := t.TempDir()
	storageDir := filepath.Join(tmpDir, "recordings")
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	cfg := recording.RecordingConfig{
		Enabled:        true,
		RecordPayloads: true,
		MaxFileSize:    recording.DefaultMaxFileSize,
		RetentionDays:  recording.DefaultRetentionDays,
		RedactPatterns: nil,
		StorageDir:     storageDir,
	}

	fr, err := recording.NewFileRecorder(cfg, logger)
	if err != nil {
		t.Fatalf("create FileRecorder: %v", err)
	}

	h := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	h.SetRecordingService(fr)

	return h, fr, tmpDir
}

// createTestSession creates a session with N tool-call events using the recorder directly.
// Returns the session ID.
func createTestSession(t *testing.T, fr *recording.FileRecorder, sessionID, identityID, identityName string, eventCount int) string {
	t.Helper()
	if err := fr.StartSession(sessionID, identityID, identityName); err != nil {
		t.Fatalf("start session %q: %v", sessionID, err)
	}
	for i := 0; i < eventCount; i++ {
		event := recording.RecordingEvent{
			Timestamp:  time.Now().UTC(),
			EventType:  recording.EventToolCall,
			ToolName:   "read_file",
			Decision:   "allow",
			Reason:     "policy match",
			SessionID:  sessionID,
			IdentityID: identityID,
		}
		if err := fr.RecordEvent(sessionID, event); err != nil {
			t.Fatalf("record event %d: %v", i, err)
		}
	}
	if err := fr.EndSession(sessionID); err != nil {
		t.Fatalf("end session %q: %v", sessionID, err)
	}
	return sessionID
}

// TestHandleListRecordings_Empty verifies GET /recordings returns [] when no recordings exist.
func TestHandleListRecordings_Empty(t *testing.T) {
	h, _, _ := setupRecordingTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/recordings", nil)
	w := httptest.NewRecorder()
	h.handleListRecordings(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var items []recordingListItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if items == nil {
		t.Fatal("expected non-nil empty array, got null")
	}
	if len(items) != 0 {
		t.Fatalf("recording count = %d, want 0", len(items))
	}
}

// TestHandleListRecordings_WithData verifies GET /recordings returns 2 items after creating 2 sessions.
func TestHandleListRecordings_WithData(t *testing.T) {
	h, fr, _ := setupRecordingTestHandler(t)

	createTestSession(t, fr, "sess-001", "id-a", "Alice", 3)
	createTestSession(t, fr, "sess-002", "id-b", "Bob", 5)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/recordings", nil)
	w := httptest.NewRecorder()
	h.handleListRecordings(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var items []recordingListItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("recording count = %d, want 2", len(items))
	}

	// Both sessions should have identity names set.
	ids := map[string]bool{items[0].SessionID: true, items[1].SessionID: true}
	if !ids["sess-001"] || !ids["sess-002"] {
		t.Errorf("unexpected session IDs: %v", items)
	}
}

// TestHandleListRecordings_FilterByIdentity verifies the identity filter returns only matching sessions.
func TestHandleListRecordings_FilterByIdentity(t *testing.T) {
	h, fr, _ := setupRecordingTestHandler(t)

	createTestSession(t, fr, "sess-alice", "id-alice", "Alice", 2)
	createTestSession(t, fr, "sess-bob", "id-bob", "Bob", 2)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/recordings?identity=id-alice", nil)
	w := httptest.NewRecorder()
	h.handleListRecordings(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var items []recordingListItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("recording count = %d, want 1 (only Alice)", len(items))
	}
	if items[0].IdentityID != "id-alice" {
		t.Errorf("IdentityID = %q, want %q", items[0].IdentityID, "id-alice")
	}
}

// TestHandleGetRecording_Found verifies GET /recordings/{id} returns correct metadata.
func TestHandleGetRecording_Found(t *testing.T) {
	h, fr, _ := setupRecordingTestHandler(t)
	createTestSession(t, fr, "sess-found", "id-x", "TestUser", 4)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/recordings/sess-found", nil)
	req.SetPathValue("id", "sess-found")
	w := httptest.NewRecorder()
	h.handleGetRecording(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var detail recordingDetailResponse
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if detail.SessionID != "sess-found" {
		t.Errorf("SessionID = %q, want %q", detail.SessionID, "sess-found")
	}
	if detail.IdentityName != "TestUser" {
		t.Errorf("IdentityName = %q, want %q", detail.IdentityName, "TestUser")
	}
	if detail.EventCount == 0 {
		t.Error("EventCount should be > 0")
	}
}

// TestHandleGetRecording_NotFound verifies GET /recordings/{id} returns 404 for nonexistent ID.
func TestHandleGetRecording_NotFound(t *testing.T) {
	h, _, _ := setupRecordingTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/recordings/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()
	h.handleGetRecording(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestHandleGetRecordingEvents_Paginated verifies pagination: 10 tool-call events + start + end = 12 total.
func TestHandleGetRecordingEvents_Paginated(t *testing.T) {
	h, fr, _ := setupRecordingTestHandler(t)
	createTestSession(t, fr, "sess-paged", "id-p", "Pager", 10)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/recordings/sess-paged/events?offset=2&limit=3", nil)
	req.SetPathValue("id", "sess-paged")
	w := httptest.NewRecorder()
	h.handleGetRecordingEvents(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result paginatedEventsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	// session_start + 10 tool_calls + session_end = 12 total
	if result.Total != 12 {
		t.Errorf("Total = %d, want 12 (start + 10 calls + end)", result.Total)
	}
	if len(result.Events) != 3 {
		t.Errorf("Events count = %d, want 3 (limit=3)", len(result.Events))
	}
	if result.Offset != 2 {
		t.Errorf("Offset = %d, want 2", result.Offset)
	}
	if result.Limit != 3 {
		t.Errorf("Limit = %d, want 3", result.Limit)
	}
}

// TestHandleExportRecording_JSON verifies JSON export with correct Content-Type and Content-Disposition.
func TestHandleExportRecording_JSON(t *testing.T) {
	h, fr, _ := setupRecordingTestHandler(t)
	createTestSession(t, fr, "sess-export", "id-e", "Exporter", 3)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/recordings/sess-export/export?format=json", nil)
	req.SetPathValue("id", "sess-export")
	w := httptest.NewRecorder()
	h.handleExportRecording(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	cd := resp.Header.Get("Content-Disposition")
	if !strings.Contains(cd, "sess-export.json") {
		t.Errorf("Content-Disposition = %q, want to contain sess-export.json", cd)
	}

	// Verify it's a valid JSON array.
	var events []recordingEventResponse
	if err := json.NewDecoder(resp.Body).Decode(&events); err != nil {
		t.Fatalf("decode JSON export: %v", err)
	}
	if len(events) == 0 {
		t.Error("expected at least 1 event in export")
	}
}

// TestHandleExportRecording_CSV verifies CSV export with correct Content-Type and header row.
func TestHandleExportRecording_CSV(t *testing.T) {
	h, fr, _ := setupRecordingTestHandler(t)
	createTestSession(t, fr, "sess-csv", "id-c", "CSVUser", 2)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/recordings/sess-csv/export?format=csv", nil)
	req.SetPathValue("id", "sess-csv")
	w := httptest.NewRecorder()
	h.handleExportRecording(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	cd := resp.Header.Get("Content-Disposition")
	if !strings.Contains(cd, "sess-csv.csv") {
		t.Errorf("Content-Disposition = %q, want to contain sess-csv.csv", cd)
	}

	// Verify CSV has header row.
	body := w.Body.String()
	if !strings.HasPrefix(body, "sequence,") {
		t.Errorf("CSV body does not start with header row; first 80 chars: %q", body[:min(len(body), 80)])
	}
}

// TestHandleDeleteRecording verifies DELETE /recordings/{id} returns 204 and recording is gone.
func TestHandleDeleteRecording(t *testing.T) {
	h, fr, _ := setupRecordingTestHandler(t)
	createTestSession(t, fr, "sess-delete", "id-d", "DelUser", 1)

	// DELETE the recording.
	req := httptest.NewRequest(http.MethodDelete, "/admin/api/v1/recordings/sess-delete", nil)
	req.SetPathValue("id", "sess-delete")
	w := httptest.NewRecorder()
	h.handleDeleteRecording(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// Subsequent GET should return 404.
	req2 := httptest.NewRequest(http.MethodGet, "/admin/api/v1/recordings/sess-delete", nil)
	req2.SetPathValue("id", "sess-delete")
	w2 := httptest.NewRecorder()
	h.handleGetRecording(w2, req2)
	if w2.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("after delete, status = %d, want %d", w2.Result().StatusCode, http.StatusNotFound)
	}
}

// TestHandleGetRecordingConfig verifies GET /recordings/config returns default values.
func TestHandleGetRecordingConfig(t *testing.T) {
	h, _, _ := setupRecordingTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/recordings/config", nil)
	w := httptest.NewRecorder()
	h.handleGetRecordingConfig(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var cfg recordingConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	// The test handler sets Enabled=true.
	if !cfg.Enabled {
		t.Error("Enabled should be true (set in setupRecordingTestHandler)")
	}
	if cfg.StorageDir == "" {
		t.Error("StorageDir should not be empty")
	}
}

// TestHandlePutRecordingConfig_Valid verifies PUT /recordings/config updates config and persists.
func TestHandlePutRecordingConfig_Valid(t *testing.T) {
	h, fr, _ := setupRecordingTestHandler(t)
	storageDir := fr.GetConfig().StorageDir // reuse same dir to avoid mkdir errors

	body := recordingConfigRequest{
		Enabled:        true,
		RecordPayloads: false,
		MaxFileSize:    recording.DefaultMaxFileSize,
		RetentionDays:  7,
		RedactPatterns: nil,
		StorageDir:     storageDir,
	}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/recordings/config", strings.NewReader(string(data)))
	w := httptest.NewRecorder()
	h.handlePutRecordingConfig(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		body2 := make([]byte, 512)
		n, _ := resp.Body.Read(body2)
		t.Fatalf("status = %d, want %d; body: %s", resp.StatusCode, http.StatusOK, body2[:n])
	}

	var cfg recordingConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if cfg.RetentionDays != 7 {
		t.Errorf("RetentionDays = %d, want 7", cfg.RetentionDays)
	}

	// GET should now reflect the updated config.
	req2 := httptest.NewRequest(http.MethodGet, "/admin/api/v1/recordings/config", nil)
	w2 := httptest.NewRecorder()
	h.handleGetRecordingConfig(w2, req2)

	var cfg2 recordingConfigResponse
	if err := json.NewDecoder(w2.Body).Decode(&cfg2); err != nil {
		t.Fatalf("decode GET config: %v", err)
	}
	if cfg2.RetentionDays != 7 {
		t.Errorf("after GET, RetentionDays = %d, want 7", cfg2.RetentionDays)
	}
}

// TestHandlePutRecordingConfig_InvalidRegex verifies PUT returns 400 for invalid regex pattern.
func TestHandlePutRecordingConfig_InvalidRegex(t *testing.T) {
	h, fr, _ := setupRecordingTestHandler(t)
	storageDir := fr.GetConfig().StorageDir

	body := recordingConfigRequest{
		Enabled:        true,
		RecordPayloads: true,
		MaxFileSize:    recording.DefaultMaxFileSize,
		RetentionDays:  30,
		RedactPatterns: []string{"[invalid-regex"},
		StorageDir:     storageDir,
	}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/recordings/config", strings.NewReader(string(data)))
	w := httptest.NewRecorder()
	h.handlePutRecordingConfig(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// min returns the smaller of a and b (used for safe slice truncation in test output).
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
