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

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

type telemetryTestEnv struct {
	handler          *AdminAPIHandler
	telemetryService *service.TelemetryService
	stateStore       *state.FileStateStore
	mux              http.Handler
}

func setupTelemetryTestEnv(t *testing.T) *telemetryTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}
	telemetrySvc, err := service.NewTelemetryService(service.TelemetryConfig{}, logger)
	if err != nil {
		t.Fatalf("create telemetry service: %v", err)
	}
	handler := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	handler.SetTelemetryService(telemetrySvc)
	return &telemetryTestEnv{
		handler:          handler,
		telemetryService: telemetrySvc,
		stateStore:       stateStore,
		mux:              handler.Routes(),
	}
}

// telemetryCSRFToken is a fixed CSRF token used across telemetry handler tests.
const telemetryCSRFToken = "test-csrf-token-for-telemetry-tests"

func (e *telemetryTestEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
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
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: telemetryCSRFToken})
		req.Header.Set("X-CSRF-Token", telemetryCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeTelemetryJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

// --- GET /admin/api/v1/telemetry/config ---

func TestHandleGetTelemetryConfig(t *testing.T) {
	env := setupTelemetryTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/telemetry/config", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/telemetry/config status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var cfg service.TelemetryConfig
	decodeTelemetryJSON(t, rec, &cfg)
	if cfg.ServiceName != "sentinelgate" {
		t.Errorf("ServiceName = %q, want %q", cfg.ServiceName, "sentinelgate")
	}
}

// --- PUT /admin/api/v1/telemetry/config ---

func TestHandlePutTelemetryConfig(t *testing.T) {
	env := setupTelemetryTestEnv(t)

	rec := env.doRequest(t, "PUT", "/admin/api/v1/telemetry/config", service.TelemetryConfig{
		Enabled:     false,
		ServiceName: "my-service",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/api/v1/telemetry/config status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var cfg service.TelemetryConfig
	decodeTelemetryJSON(t, rec, &cfg)
	if cfg.ServiceName != "my-service" {
		t.Errorf("ServiceName = %q, want %q", cfg.ServiceName, "my-service")
	}

	// Verify persisted by re-reading.
	getRec := env.doRequest(t, "GET", "/admin/api/v1/telemetry/config", nil)
	var persisted service.TelemetryConfig
	decodeTelemetryJSON(t, getRec, &persisted)
	if persisted.ServiceName != "my-service" {
		t.Errorf("persisted ServiceName = %q, want %q", persisted.ServiceName, "my-service")
	}
}

func TestHandlePutTelemetryConfig_InvalidServiceName(t *testing.T) {
	env := setupTelemetryTestEnv(t)

	rec := env.doRequest(t, "PUT", "/admin/api/v1/telemetry/config", service.TelemetryConfig{
		ServiceName: "invalid service name!",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT invalid service name status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	var errResp map[string]string
	decodeTelemetryJSON(t, rec, &errResp)
	if !strings.Contains(errResp["error"], "service_name") {
		t.Errorf("error message = %q, want mention of service_name", errResp["error"])
	}
}

func TestHandlePutTelemetryConfig_ServiceNameTooLong(t *testing.T) {
	env := setupTelemetryTestEnv(t)

	longName := strings.Repeat("a", 129)
	rec := env.doRequest(t, "PUT", "/admin/api/v1/telemetry/config", service.TelemetryConfig{
		ServiceName: longName,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT long service name status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	var errResp map[string]string
	decodeTelemetryJSON(t, rec, &errResp)
	if !strings.Contains(errResp["error"], "128") {
		t.Errorf("error message = %q, want mention of 128 char limit", errResp["error"])
	}
}

// --- Nil service ---

func TestHandleGetTelemetryConfig_NilService(t *testing.T) {
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
	// Do NOT call SetTelemetryService — leave nil.
	mux := handler.Routes()

	req := httptest.NewRequest("GET", "/admin/api/v1/telemetry/config", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET nil service status = %d, want %d (body=%s)", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

func TestHandlePutTelemetryConfig_NilService(t *testing.T) {
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
	mux := handler.Routes()

	body, _ := json.Marshal(service.TelemetryConfig{ServiceName: "test"})
	req := httptest.NewRequest("PUT", "/admin/api/v1/telemetry/config", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: telemetryCSRFToken})
	req.Header.Set("X-CSRF-Token", telemetryCSRFToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("PUT nil service status = %d, want %d (body=%s)", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}
