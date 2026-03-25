package admin

import (
	"bytes"
	"encoding/json"
	"io"
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

type recordingTestEnv struct {
	handler        *AdminAPIHandler
	recorder       *recording.FileRecorder
	stateStore     *state.FileStateStore
	mux            http.Handler
	storageDir     string
}

func setupRecordingTestEnv(t *testing.T) *recordingTestEnv {
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
	t.Cleanup(func() { fr.StopReaper() })

	handler := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	handler.SetRecordingService(fr)

	return &recordingTestEnv{
		handler:    handler,
		recorder:   fr,
		stateStore: stateStore,
		mux:        handler.Routes(),
		storageDir: storageDir,
	}
}

// recordingCSRFToken is a fixed CSRF token used across recording handler tests.
const recordingCSRFToken = "test-csrf-token-for-recording-tests"

func (e *recordingTestEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.RemoteAddr = "127.0.0.1:1234"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Include CSRF token on state-changing requests.
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete {
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: recordingCSRFToken})
		req.Header.Set("X-CSRF-Token", recordingCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeRecordingJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

// createRecordingSession creates a test session with N tool-call events.
func (e *recordingTestEnv) createRecordingSession(t *testing.T, sessionID, identityID, identityName string, eventCount int) {
	t.Helper()
	if err := e.recorder.StartSession(sessionID, identityID, identityName); err != nil {
		t.Fatalf("start session %q: %v", sessionID, err)
	}
	for i := 0; i < eventCount; i++ {
		evt := recording.RecordingEvent{
			Timestamp:  time.Now().UTC(),
			EventType:  recording.EventToolCall,
			ToolName:   "read_file",
			Decision:   "allow",
			Reason:     "policy match",
			SessionID:  sessionID,
			IdentityID: identityID,
		}
		if err := e.recorder.RecordEvent(sessionID, evt); err != nil {
			t.Fatalf("record event %d: %v", i, err)
		}
	}
	if err := e.recorder.EndSession(sessionID); err != nil {
		t.Fatalf("end session %q: %v", sessionID, err)
	}
}

// --- List Recordings ---

func TestHandleListRecordings_Empty(t *testing.T) {
	env := setupRecordingTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/recordings", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/recordings status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result []recordingListItem
	decodeRecordingJSON(t, rec, &result)
	if len(result) != 0 {
		t.Errorf("response count = %d, want 0", len(result))
	}
}

func TestHandleListRecordings_WithData(t *testing.T) {
	env := setupRecordingTestEnv(t)

	env.createRecordingSession(t, "sess-001", "id-a", "Alice", 3)
	env.createRecordingSession(t, "sess-002", "id-b", "Bob", 5)

	rec := env.doRequest(t, "GET", "/admin/api/v1/recordings", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result []recordingListItem
	decodeRecordingJSON(t, rec, &result)
	if len(result) != 2 {
		t.Fatalf("recording count = %d, want 2", len(result))
	}

	ids := map[string]bool{result[0].SessionID: true, result[1].SessionID: true}
	if !ids["sess-001"] || !ids["sess-002"] {
		t.Errorf("unexpected session IDs: %v", result)
	}
}

func TestHandleListRecordings_NilService(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	// Create handler WITHOUT recording service.
	handler := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	mux := handler.Routes()

	req := httptest.NewRequest("GET", "/admin/api/v1/recordings", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GET nil service status = %d, want %d (body=%s)", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

// --- Get Recording ---

func TestHandleGetRecording_NotFound(t *testing.T) {
	env := setupRecordingTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/recordings/nonexistent", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET nonexistent status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleGetRecording_Found(t *testing.T) {
	env := setupRecordingTestEnv(t)
	env.createRecordingSession(t, "sess-found", "id-x", "TestUser", 4)

	rec := env.doRequest(t, "GET", "/admin/api/v1/recordings/sess-found", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var detail recordingDetailResponse
	decodeRecordingJSON(t, rec, &detail)
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

// --- Delete Recording ---

func TestHandleDeleteRecording_NotFound(t *testing.T) {
	env := setupRecordingTestEnv(t)

	rec := env.doRequest(t, "DELETE", "/admin/api/v1/recordings/nonexistent", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE nonexistent status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleDeleteRecording_Existing(t *testing.T) {
	env := setupRecordingTestEnv(t)
	env.createRecordingSession(t, "sess-delete", "id-d", "DelUser", 1)

	rec := env.doRequest(t, "DELETE", "/admin/api/v1/recordings/sess-delete", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want %d (body=%s)", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Subsequent GET should return 404.
	getRec := env.doRequest(t, "GET", "/admin/api/v1/recordings/sess-delete", nil)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("after delete, GET status = %d, want %d", getRec.Code, http.StatusNotFound)
	}
}

// --- Recording Config ---

func TestHandleGetRecordingConfig(t *testing.T) {
	env := setupRecordingTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/recordings/config", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET config status = %d, want %d", rec.Code, http.StatusOK)
	}

	var cfg recordingConfigResponse
	decodeRecordingJSON(t, rec, &cfg)
	if !cfg.Enabled {
		t.Error("Enabled should be true")
	}
	if cfg.StorageDir == "" {
		t.Error("StorageDir should not be empty")
	}
	if cfg.RetentionDays != recording.DefaultRetentionDays {
		t.Errorf("RetentionDays = %d, want %d", cfg.RetentionDays, recording.DefaultRetentionDays)
	}
}

func TestHandlePutRecordingConfig_Valid(t *testing.T) {
	env := setupRecordingTestEnv(t)

	rec := env.doRequest(t, "PUT", "/admin/api/v1/recordings/config", recordingConfigRequest{
		Enabled:        true,
		RecordPayloads: false,
		MaxFileSize:    recording.DefaultMaxFileSize,
		RetentionDays:  7,
		RedactPatterns: nil,
		StorageDir:     "recordings",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT config status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var cfg recordingConfigResponse
	decodeRecordingJSON(t, rec, &cfg)
	if cfg.RetentionDays != 7 {
		t.Errorf("RetentionDays = %d, want 7", cfg.RetentionDays)
	}

	// GET should reflect updated config.
	getRec := env.doRequest(t, "GET", "/admin/api/v1/recordings/config", nil)
	var cfg2 recordingConfigResponse
	decodeRecordingJSON(t, getRec, &cfg2)
	if cfg2.RetentionDays != 7 {
		t.Errorf("after GET, RetentionDays = %d, want 7", cfg2.RetentionDays)
	}
}

func TestHandlePutRecordingConfig_NilService(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	// Create handler WITHOUT recording service.
	handler := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	mux := handler.Routes()

	body := recordingConfigRequest{
		Enabled:     true,
		StorageDir:  "recordings",
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/admin/api/v1/recordings/config", bytes.NewReader(data))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: recordingCSRFToken})
	req.Header.Set("X-CSRF-Token", recordingCSRFToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT nil service status = %d, want %d (body=%s)", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
}

func TestHandlePutRecordingConfig_InvalidRegex(t *testing.T) {
	env := setupRecordingTestEnv(t)
	storageDir := env.recorder.GetConfig().StorageDir

	rec := env.doRequest(t, "PUT", "/admin/api/v1/recordings/config", recordingConfigRequest{
		Enabled:        true,
		RecordPayloads: true,
		MaxFileSize:    recording.DefaultMaxFileSize,
		RetentionDays:  30,
		RedactPatterns: []string{"[invalid-regex"},
		StorageDir:     storageDir,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT invalid regex status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// --- Recording Events ---

func TestHandleGetRecordingEvents_NotFound(t *testing.T) {
	env := setupRecordingTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/recordings/nonexistent/events", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET events nonexistent status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleGetRecordingEvents_NegativeOffset(t *testing.T) {
	env := setupRecordingTestEnv(t)
	env.createRecordingSession(t, "sess-neg", "id-n", "NegUser", 2)

	rec := env.doRequest(t, "GET", "/admin/api/v1/recordings/sess-neg/events?offset=-1", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("GET events negative offset status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleGetRecordingEvents_Paginated(t *testing.T) {
	env := setupRecordingTestEnv(t)
	env.createRecordingSession(t, "sess-paged", "id-p", "Pager", 10)

	rec := env.doRequest(t, "GET", "/admin/api/v1/recordings/sess-paged/events?offset=2&limit=3", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET events status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result paginatedEventsResponse
	decodeRecordingJSON(t, rec, &result)
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

// --- Export ---

func TestHandleExportRecording_JSON(t *testing.T) {
	env := setupRecordingTestEnv(t)
	env.createRecordingSession(t, "sess-export", "id-e", "Exporter", 3)

	rec := env.doRequest(t, "GET", "/admin/api/v1/recordings/sess-export/export?format=json", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET export status = %d, want %d", rec.Code, http.StatusOK)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "sess-export.json") {
		t.Errorf("Content-Disposition = %q, want to contain sess-export.json", cd)
	}
}

func TestHandleExportRecording_CSV(t *testing.T) {
	env := setupRecordingTestEnv(t)
	env.createRecordingSession(t, "sess-csv", "id-c", "CSVUser", 2)

	rec := env.doRequest(t, "GET", "/admin/api/v1/recordings/sess-csv/export?format=csv", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET csv export status = %d, want %d", rec.Code, http.StatusOK)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}

	body := rec.Body.String()
	if !strings.HasPrefix(body, "sequence,") {
		t.Errorf("CSV body does not start with header row; first 80 chars: %q", body[:minInt(len(body), 80)])
	}
}

// --- Filter ---

func TestHandleListRecordings_FilterByIdentity(t *testing.T) {
	env := setupRecordingTestEnv(t)
	env.createRecordingSession(t, "sess-alice", "id-alice", "Alice", 2)
	env.createRecordingSession(t, "sess-bob", "id-bob", "Bob", 2)

	rec := env.doRequest(t, "GET", "/admin/api/v1/recordings?identity=id-alice", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET filter status = %d, want %d", rec.Code, http.StatusOK)
	}

	var items []recordingListItem
	decodeRecordingJSON(t, rec, &items)
	if len(items) != 1 {
		t.Fatalf("recording count = %d, want 1 (only Alice)", len(items))
	}
	if items[0].IdentityID != "id-alice" {
		t.Errorf("IdentityID = %q, want %q", items[0].IdentityID, "id-alice")
	}
}

// minInt returns the smaller of a and b.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
