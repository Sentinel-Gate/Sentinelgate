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

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

type simulationTestEnv struct {
	handler           *AdminAPIHandler
	simulationService *service.SimulationService
	stateStore        *state.FileStateStore
	mux               http.Handler
}

func setupSimulationTestEnv(t *testing.T) *simulationTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	// Build a minimal PolicyService with an in-memory store.
	policyStore := memory.NewPolicyStore()
	policySvc, err := service.NewPolicyService(context.Background(), policyStore, logger)
	if err != nil {
		t.Fatalf("create policy service: %v", err)
	}

	// Audit reader that returns no records (empty history).
	auditReaderFn := func(n int) []audit.AuditRecord {
		return nil
	}

	simSvc := service.NewSimulationService(policySvc, auditReaderFn, logger)
	handler := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	handler.SetSimulationService(simSvc)
	return &simulationTestEnv{
		handler:           handler,
		simulationService: simSvc,
		stateStore:        stateStore,
		mux:               handler.Routes(),
	}
}

// simulationCSRFToken is a fixed CSRF token used across simulation handler tests.
const simulationCSRFToken = "test-csrf-token-for-simulation-tests"

func (e *simulationTestEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
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
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: simulationCSRFToken})
		req.Header.Set("X-CSRF-Token", simulationCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeSimulationJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

// --- Nil service ---

func TestHandleRunSimulation_NilService(t *testing.T) {
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
	// Do NOT call SetSimulationService — leave nil.
	mux := handler.Routes()

	body, _ := json.Marshal(simulationRequest{MaxRecords: 100})
	req := httptest.NewRequest("POST", "/admin/api/v1/simulation/run", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: simulationCSRFToken})
	req.Header.Set("X-CSRF-Token", simulationCSRFToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST nil service status = %d, want %d (body=%s)", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

// --- POST /admin/api/v1/simulation/run with empty body ---

func TestHandleRunSimulation_EmptyBody(t *testing.T) {
	env := setupSimulationTestEnv(t)

	// POST with no body — handler should accept it and run with defaults.
	req := httptest.NewRequest("POST", "/admin/api/v1/simulation/run", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: simulationCSRFToken})
	req.Header.Set("X-CSRF-Token", simulationCSRFToken)
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST empty body status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result service.SimulationResult
	decodeSimulationJSON(t, rec, &result)
	if result.TotalProcessed != 0 {
		t.Errorf("TotalProcessed = %d, want 0 (no audit records)", result.TotalProcessed)
	}
}

// --- POST /admin/api/v1/simulation/run with MaxRecords ---

func TestHandleRunSimulation_WithMaxRecords(t *testing.T) {
	env := setupSimulationTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/simulation/run", simulationRequest{
		MaxRecords: 500,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST with max_records status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result service.SimulationResult
	decodeSimulationJSON(t, rec, &result)
	// With an empty audit reader, we expect zero records processed.
	if result.TotalProcessed != 0 {
		t.Errorf("TotalProcessed = %d, want 0", result.TotalProcessed)
	}
	if result.DurationMs < 0 {
		t.Errorf("DurationMs = %d, want >= 0", result.DurationMs)
	}
}
