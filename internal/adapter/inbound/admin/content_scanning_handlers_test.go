package admin

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
)

// mockScanController implements ResponseScanController for testing.
type mockScanController struct {
	mode    action.ScanMode
	enabled bool
}

func (m *mockScanController) Mode() action.ScanMode        { return m.mode }
func (m *mockScanController) Enabled() bool                { return m.enabled }
func (m *mockScanController) SetMode(mode action.ScanMode) { m.mode = mode }
func (m *mockScanController) SetEnabled(enabled bool)      { m.enabled = enabled }

// testContentScanEnv creates a test environment for content scanning handler tests.
func testContentScanEnv(t *testing.T, ctrl ResponseScanController) *AdminAPIHandler {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	defaultState := stateStore.DefaultState()
	if err := stateStore.Save(defaultState); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	opts := []AdminAPIOption{
		WithStateStore(stateStore),
		WithAPILogger(logger),
	}
	if ctrl != nil {
		opts = append(opts, WithResponseScanController(ctrl))
	}

	return NewAdminAPIHandler(opts...)
}

func TestContentScanning_GetReturnsCurrentConfig(t *testing.T) {
	ctrl := &mockScanController{mode: action.ScanModeMonitor, enabled: true}
	h := testContentScanEnv(t, ctrl)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/security/content-scanning", nil)
	w := httptest.NewRecorder()

	h.handleGetContentScanning(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body contentScanningResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body.Mode != "monitor" {
		t.Errorf("mode = %q, want %q", body.Mode, "monitor")
	}
	if !body.Enabled {
		t.Errorf("enabled = false, want true")
	}
}

func TestContentScanning_GetNoController_Returns503(t *testing.T) {
	h := testContentScanEnv(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/security/content-scanning", nil)
	w := httptest.NewRecorder()

	h.handleGetContentScanning(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestContentScanning_UpdateValidRequest(t *testing.T) {
	ctrl := &mockScanController{mode: action.ScanModeMonitor, enabled: true}
	h := testContentScanEnv(t, ctrl)

	body := `{"mode":"enforce","enabled":false}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/security/content-scanning", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleUpdateContentScanning(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result contentScanningResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if result.Mode != "enforce" {
		t.Errorf("mode = %q, want %q", result.Mode, "enforce")
	}
	if result.Enabled {
		t.Errorf("enabled = true, want false")
	}
	if result.Message == "" {
		t.Error("message should not be empty")
	}

	// Verify the controller was updated.
	if ctrl.mode != action.ScanModeEnforce {
		t.Errorf("controller mode = %q, want %q", ctrl.mode, action.ScanModeEnforce)
	}
	if ctrl.enabled {
		t.Errorf("controller enabled = true, want false")
	}

	// Verify persistence to state.json.
	appState, err := h.stateStore.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if appState.ContentScanningConfig == nil {
		t.Fatal("ContentScanningConfig should not be nil after update")
	}
	if appState.ContentScanningConfig.Mode != "enforce" {
		t.Errorf("persisted mode = %q, want %q", appState.ContentScanningConfig.Mode, "enforce")
	}
	if appState.ContentScanningConfig.Enabled {
		t.Errorf("persisted enabled = true, want false")
	}
}

func TestContentScanning_UpdateInvalidMode_Returns400(t *testing.T) {
	ctrl := &mockScanController{mode: action.ScanModeMonitor, enabled: true}
	h := testContentScanEnv(t, ctrl)

	body := `{"mode":"invalid","enabled":true}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/security/content-scanning", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleUpdateContentScanning(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	// Verify the controller was not modified.
	if ctrl.mode != action.ScanModeMonitor {
		t.Errorf("controller mode changed to %q, should remain %q", ctrl.mode, action.ScanModeMonitor)
	}
}

func TestContentScanning_UpdateInvalidJSON_Returns400(t *testing.T) {
	ctrl := &mockScanController{mode: action.ScanModeMonitor, enabled: true}
	h := testContentScanEnv(t, ctrl)

	body := `{not-valid-json}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/security/content-scanning", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleUpdateContentScanning(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestContentScanning_UpdateNoController_Returns503(t *testing.T) {
	h := testContentScanEnv(t, nil)

	body := `{"mode":"enforce","enabled":true}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/security/content-scanning", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleUpdateContentScanning(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestContentScanning_ImmediateEffect(t *testing.T) {
	ctrl := &mockScanController{mode: action.ScanModeMonitor, enabled: true}
	h := testContentScanEnv(t, ctrl)

	// Update to enforce mode.
	body := `{"mode":"enforce","enabled":true}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/security/content-scanning", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleUpdateContentScanning(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("PUT status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}

	// GET should return the updated config immediately.
	req2 := httptest.NewRequest(http.MethodGet, "/admin/api/v1/security/content-scanning", nil)
	w2 := httptest.NewRecorder()
	h.handleGetContentScanning(w2, req2)

	var result contentScanningResponse
	if err := json.NewDecoder(w2.Result().Body).Decode(&result); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}

	if result.Mode != "enforce" {
		t.Errorf("GET after PUT: mode = %q, want %q", result.Mode, "enforce")
	}
	if !result.Enabled {
		t.Errorf("GET after PUT: enabled = false, want true")
	}
}
