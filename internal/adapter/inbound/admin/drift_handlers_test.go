package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/storage"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// --- stub implementations ---

// stubDriftReader implements service.DriftAuditReader with empty results.
type stubDriftReader struct{}

func (s *stubDriftReader) Query(_ context.Context, _ audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	return nil, "", nil
}

// --- test environment ---

type driftTestEnv struct {
	handler      *AdminAPIHandler
	driftService *service.DriftService
	stateStore   *state.FileStateStore
	mux          http.Handler
}

const driftCSRFToken = "test-csrf-token-for-drift-tests"

func setupDriftTestEnv(t *testing.T) *driftTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	tsStore, err := storage.NewSQLiteTimeSeriesStore(filepath.Join(tmpDir, "ts.db"))
	if err != nil {
		t.Fatalf("create ts store: %v", err)
	}
	t.Cleanup(func() { tsStore.Close() })

	driftSvc := service.NewDriftService(&stubDriftReader{}, tsStore, logger)
	t.Cleanup(func() { driftSvc.Stop() })

	handler := NewAdminAPIHandler(
		WithDriftService(driftSvc),
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	return &driftTestEnv{
		handler:      handler,
		driftService: driftSvc,
		stateStore:   stateStore,
		mux:          handler.Routes(),
	}
}

func setupDriftTestEnvNilService(t *testing.T) *driftTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	handler := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	return &driftTestEnv{
		handler:    handler,
		stateStore: stateStore,
		mux:        handler.Routes(),
	}
}

func (e *driftTestEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
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
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete {
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: driftCSRFToken})
		req.Header.Set("X-CSRF-Token", driftCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeDriftJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

// --- Tests ---

func TestHandleGetDriftConfig_Default(t *testing.T) {
	env := setupDriftTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/drift/config", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/drift/config status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp driftConfigResponse
	decodeDriftJSON(t, rec, &resp)

	if !resp.Configured {
		t.Errorf("Configured = false, want true (service is running)")
	}
	cfg := resp.Config
	defaults := service.DefaultDriftConfig()
	if cfg.BaselineWindowDays != defaults.BaselineWindowDays {
		t.Errorf("BaselineWindowDays = %d, want %d", cfg.BaselineWindowDays, defaults.BaselineWindowDays)
	}
	if cfg.CurrentWindowDays != defaults.CurrentWindowDays {
		t.Errorf("CurrentWindowDays = %d, want %d", cfg.CurrentWindowDays, defaults.CurrentWindowDays)
	}
	if cfg.ToolShiftThreshold != defaults.ToolShiftThreshold {
		t.Errorf("ToolShiftThreshold = %f, want %f", cfg.ToolShiftThreshold, defaults.ToolShiftThreshold)
	}
	if cfg.MinCallsBaseline != defaults.MinCallsBaseline {
		t.Errorf("MinCallsBaseline = %d, want %d", cfg.MinCallsBaseline, defaults.MinCallsBaseline)
	}
}

func TestHandleGetDriftConfig_NilService(t *testing.T) {
	env := setupDriftTestEnvNilService(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/drift/config", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/drift/config nil service status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Handler returns default config with configured=false when service is nil.
	var resp driftConfigResponse
	decodeDriftJSON(t, rec, &resp)

	if resp.Configured {
		t.Errorf("Configured = true, want false (service is nil)")
	}
	defaults := service.DefaultDriftConfig()
	if resp.Config.BaselineWindowDays != defaults.BaselineWindowDays {
		t.Errorf("BaselineWindowDays = %d, want %d", resp.Config.BaselineWindowDays, defaults.BaselineWindowDays)
	}
}

func TestHandlePutDriftConfig_Valid(t *testing.T) {
	env := setupDriftTestEnv(t)

	update := map[string]interface{}{
		"baseline_window_days": 30,
		"current_window_days":  7,
		"tool_shift_threshold": 0.35,
		"min_calls_baseline":   5,
	}

	rec := env.doRequest(t, "PUT", "/admin/api/v1/drift/config", update)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/api/v1/drift/config status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp driftConfigResponse
	decodeDriftJSON(t, rec, &resp)
	if !resp.Configured {
		t.Errorf("Configured = false, want true after PUT")
	}
	cfg := resp.Config
	if cfg.BaselineWindowDays != 30 {
		t.Errorf("BaselineWindowDays = %d, want 30", cfg.BaselineWindowDays)
	}
	if cfg.CurrentWindowDays != 7 {
		t.Errorf("CurrentWindowDays = %d, want 7", cfg.CurrentWindowDays)
	}
	if cfg.ToolShiftThreshold != 0.35 {
		t.Errorf("ToolShiftThreshold = %f, want 0.35", cfg.ToolShiftThreshold)
	}
	if cfg.MinCallsBaseline != 5 {
		t.Errorf("MinCallsBaseline = %d, want 5", cfg.MinCallsBaseline)
	}

	// Verify the update persisted by fetching the config again.
	getRec := env.doRequest(t, "GET", "/admin/api/v1/drift/config", nil)
	var fetchedResp driftConfigResponse
	decodeDriftJSON(t, getRec, &fetchedResp)
	if fetchedResp.Config.BaselineWindowDays != 30 {
		t.Errorf("fetched BaselineWindowDays = %d, want 30", fetchedResp.Config.BaselineWindowDays)
	}
}

func TestHandlePutDriftConfig_NegativeWindowDays(t *testing.T) {
	env := setupDriftTestEnv(t)

	update := map[string]interface{}{
		"baseline_window_days": 0,
	}

	rec := env.doRequest(t, "PUT", "/admin/api/v1/drift/config", update)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT negative window_days status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandlePutDriftConfig_NegativeThreshold(t *testing.T) {
	env := setupDriftTestEnv(t)

	update := map[string]interface{}{
		"tool_shift_threshold": -0.5,
	}

	rec := env.doRequest(t, "PUT", "/admin/api/v1/drift/config", update)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT negative threshold status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandlePutDriftConfig_NilService(t *testing.T) {
	env := setupDriftTestEnvNilService(t)

	update := map[string]interface{}{
		"baseline_window_days": 30,
	}

	rec := env.doRequest(t, "PUT", "/admin/api/v1/drift/config", update)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("PUT nil service status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleListDriftReports_NilService(t *testing.T) {
	env := setupDriftTestEnvNilService(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/drift/reports", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET drift reports nil service status = %d, want %d", rec.Code, http.StatusOK)
	}

	var reports []service.BehavioralDriftReport
	decodeDriftJSON(t, rec, &reports)
	if len(reports) != 0 {
		t.Errorf("expected empty reports, got %d", len(reports))
	}
}

func TestHandleResetDriftBaseline_NilService(t *testing.T) {
	env := setupDriftTestEnvNilService(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/drift/profiles/test-id/reset", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST reset nil service status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleGetDriftProfile_MissingID(t *testing.T) {
	env := setupDriftTestEnv(t)

	// Using the mux route, the {identity_id} segment will be empty string when
	// we hit the route directly with an empty segment. Since the mux requires a
	// path value, we call the handler directly with an empty path param.
	req := httptest.NewRequest("GET", "/admin/api/v1/drift/profiles/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	// SetPathValue to empty to simulate missing identity_id.
	req.SetPathValue("identity_id", "")
	rec := httptest.NewRecorder()
	env.handler.handleGetDriftProfile(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("GET drift profile missing ID status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}
