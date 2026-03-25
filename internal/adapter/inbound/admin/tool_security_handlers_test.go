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
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

type toolSecurityTestEnv struct {
	handler             *AdminAPIHandler
	toolSecurityService *service.ToolSecurityService
	toolCache           *upstream.ToolCache
	stateStore          *state.FileStateStore
	mux                 http.Handler
}

func setupToolSecurityTestEnv(t *testing.T) *toolSecurityTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}
	toolCache := upstream.NewToolCache()
	toolSecSvc := service.NewToolSecurityService(toolCache, stateStore, logger)
	handler := NewAdminAPIHandler(
		WithToolSecurityService(toolSecSvc),
		WithToolCache(toolCache),
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	return &toolSecurityTestEnv{
		handler:             handler,
		toolSecurityService: toolSecSvc,
		toolCache:           toolCache,
		stateStore:          stateStore,
		mux:                 handler.Routes(),
	}
}

// toolSecCSRFToken is a fixed CSRF token used across tool security handler tests.
const toolSecCSRFToken = "test-csrf-token-for-tool-security-tests"

func (e *toolSecurityTestEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
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
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: toolSecCSRFToken})
		req.Header.Set("X-CSRF-Token", toolSecCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeToolSecJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

// seedToolCache populates the tool cache with sample tools for baseline tests.
func (e *toolSecurityTestEnv) seedToolCache(t *testing.T) {
	t.Helper()
	e.toolCache.SetToolsForUpstream("upstream-1", []*upstream.DiscoveredTool{
		{Name: "read_file", Description: "Reads a file", UpstreamID: "upstream-1", UpstreamName: "server-a", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "write_file", Description: "Writes a file", UpstreamID: "upstream-1", UpstreamName: "server-a", InputSchema: json.RawMessage(`{"type":"object"}`)},
	})
}

// --- Capture Baseline ---

func TestHandleCaptureBaseline(t *testing.T) {
	env := setupToolSecurityTestEnv(t)
	env.seedToolCache(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/tools/baseline", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/v1/tools/baseline status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result map[string]interface{}
	decodeToolSecJSON(t, rec, &result)
	count, ok := result["tools_captured"]
	if !ok {
		t.Fatal("response missing tools_captured")
	}
	if count.(float64) != 2 {
		t.Errorf("tools_captured = %v, want 2", count)
	}
}

func TestHandleCaptureBaseline_NilService(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	// Create handler WITHOUT tool security service.
	handler := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	mux := handler.Routes()

	req := httptest.NewRequest("POST", "/admin/api/v1/tools/baseline", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: toolSecCSRFToken})
	req.Header.Set("X-CSRF-Token", toolSecCSRFToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST nil service status = %d, want %d (body=%s)", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

// --- Get Baseline ---

func TestHandleGetBaseline_Empty(t *testing.T) {
	env := setupToolSecurityTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/tools/baseline", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/tools/baseline status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result map[string]interface{}
	decodeToolSecJSON(t, rec, &result)
	tools, ok := result["tools"]
	if !ok {
		t.Fatal("response missing tools")
	}
	toolsArr, ok := tools.([]interface{})
	if !ok {
		t.Fatalf("tools is not an array, got %T", tools)
	}
	if len(toolsArr) != 0 {
		t.Errorf("tools count = %d, want 0 (no baseline captured)", len(toolsArr))
	}
}

func TestHandleGetBaseline_AfterCapture(t *testing.T) {
	env := setupToolSecurityTestEnv(t)
	env.seedToolCache(t)

	// Capture baseline first.
	captureRec := env.doRequest(t, "POST", "/admin/api/v1/tools/baseline", nil)
	if captureRec.Code != http.StatusOK {
		t.Fatalf("capture baseline status = %d, want %d", captureRec.Code, http.StatusOK)
	}

	// Get baseline.
	rec := env.doRequest(t, "GET", "/admin/api/v1/tools/baseline", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET baseline status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result map[string]interface{}
	decodeToolSecJSON(t, rec, &result)
	tools := result["tools"].([]interface{})
	if len(tools) != 2 {
		t.Errorf("tools count = %d, want 2", len(tools))
	}
}

// --- Detect Drift ---

func TestHandleDetectDrift_NoBaseline(t *testing.T) {
	env := setupToolSecurityTestEnv(t)
	env.seedToolCache(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/tools/drift", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("GET /admin/api/v1/tools/drift (no baseline) status = %d, want %d (body=%s)", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

func TestHandleDetectDrift_NoChanges(t *testing.T) {
	env := setupToolSecurityTestEnv(t)
	env.seedToolCache(t)

	// Capture baseline.
	env.doRequest(t, "POST", "/admin/api/v1/tools/baseline", nil)

	// Detect drift (no changes).
	rec := env.doRequest(t, "GET", "/admin/api/v1/tools/drift", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET drift status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result map[string]interface{}
	decodeToolSecJSON(t, rec, &result)
	drifts, ok := result["drifts"]
	if !ok {
		t.Fatal("response missing drifts")
	}
	// No changes expected: drifts should be null or empty.
	if drifts != nil {
		if arr, ok := drifts.([]interface{}); ok && len(arr) > 0 {
			t.Errorf("drifts count = %d, want 0", len(arr))
		}
	}
}

// --- Quarantine ---

func TestHandleQuarantineTool(t *testing.T) {
	env := setupToolSecurityTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/tools/quarantine", map[string]string{
		"tool_name": "dangerous_tool",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST quarantine status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result map[string]interface{}
	decodeToolSecJSON(t, rec, &result)
	if result["quarantined"] != "dangerous_tool" {
		t.Errorf("quarantined = %v, want %q", result["quarantined"], "dangerous_tool")
	}

	// Verify via list.
	listRec := env.doRequest(t, "GET", "/admin/api/v1/tools/quarantine", nil)
	var listResult map[string]interface{}
	decodeToolSecJSON(t, listRec, &listResult)
	tools := listResult["quarantined_tools"].([]interface{})
	if len(tools) != 1 {
		t.Errorf("quarantined_tools count = %d, want 1", len(tools))
	}
}

func TestHandleQuarantineTool_MissingName(t *testing.T) {
	env := setupToolSecurityTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/tools/quarantine", map[string]string{
		"tool_name": "",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST quarantine missing name status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// --- Unquarantine ---

func TestHandleUnquarantineTool_NotQuarantined(t *testing.T) {
	env := setupToolSecurityTestEnv(t)

	rec := env.doRequest(t, "DELETE", "/admin/api/v1/tools/quarantine/not-quarantined-tool", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("DELETE unquarantine (not quarantined) status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleUnquarantineTool_Success(t *testing.T) {
	env := setupToolSecurityTestEnv(t)

	// Quarantine first.
	env.doRequest(t, "POST", "/admin/api/v1/tools/quarantine", map[string]string{
		"tool_name": "test-tool",
	})

	// Unquarantine.
	rec := env.doRequest(t, "DELETE", "/admin/api/v1/tools/quarantine/test-tool", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE unquarantine status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result map[string]interface{}
	decodeToolSecJSON(t, rec, &result)
	if result["unquarantined"] != "test-tool" {
		t.Errorf("unquarantined = %v, want %q", result["unquarantined"], "test-tool")
	}
}

// --- List Quarantined ---

func TestHandleListQuarantined_Empty(t *testing.T) {
	env := setupToolSecurityTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/tools/quarantine", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET quarantine list status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result map[string]interface{}
	decodeToolSecJSON(t, rec, &result)
	tools := result["quarantined_tools"].([]interface{})
	if len(tools) != 0 {
		t.Errorf("quarantined_tools count = %d, want 0", len(tools))
	}
}

// --- Accept Tool Change ---

func TestHandleAcceptToolChange_MissingName(t *testing.T) {
	env := setupToolSecurityTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/tools/accept-change", map[string]string{
		"tool_name": "",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST accept-change missing name status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}
