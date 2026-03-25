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
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/redteam"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// --- stub implementation ---

// stubRedTeamEval implements service.RedTeamPolicyEvaluator and always returns "allow".
type stubRedTeamEval struct{}

func (s *stubRedTeamEval) Evaluate(_ context.Context, _ policy.EvaluationContext) (policy.Decision, error) {
	return policy.Decision{Allowed: true}, nil
}

// --- test environment ---

type redteamTestEnv struct {
	handler        *AdminAPIHandler
	redteamService *service.RedTeamService
	stateStore     *state.FileStateStore
	mux            http.Handler
}

const redteamCSRFToken = "test-csrf-token-for-redteam-tests"

func setupRedTeamTestEnv(t *testing.T) *redteamTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	rtSvc := service.NewRedTeamService(&stubRedTeamEval{}, logger)

	handler := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	handler.SetRedTeamService(rtSvc)

	return &redteamTestEnv{
		handler:        handler,
		redteamService: rtSvc,
		stateStore:     stateStore,
		mux:            handler.Routes(),
	}
}

func setupRedTeamTestEnvNilService(t *testing.T) *redteamTestEnv {
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
	return &redteamTestEnv{
		handler:    handler,
		stateStore: stateStore,
		mux:        handler.Routes(),
	}
}

func (e *redteamTestEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
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
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: redteamCSRFToken})
		req.Header.Set("X-CSRF-Token", redteamCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeRedTeamJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

// --- Tests ---

func TestHandleGetRedTeamCorpus(t *testing.T) {
	env := setupRedTeamTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/redteam/corpus", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/redteam/corpus status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp struct {
		Patterns []redteam.AttackPattern `json:"patterns"`
		Total    int                     `json:"total"`
	}
	decodeRedTeamJSON(t, rec, &resp)
	if resp.Total == 0 {
		t.Error("expected non-empty corpus")
	}
	if len(resp.Patterns) != resp.Total {
		t.Errorf("patterns count = %d, total field = %d, want equal", len(resp.Patterns), resp.Total)
	}
}

func TestHandleGetRedTeamReports_Empty(t *testing.T) {
	env := setupRedTeamTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/redteam/reports", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/redteam/reports status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp struct {
		Reports []interface{} `json:"reports"`
	}
	decodeRedTeamJSON(t, rec, &resp)
	if len(resp.Reports) != 0 {
		t.Errorf("expected 0 reports, got %d", len(resp.Reports))
	}
}

func TestHandleRunRedTeam_MissingIdentity(t *testing.T) {
	env := setupRedTeamTestEnv(t)

	// No target_identity field.
	rec := env.doRequest(t, "POST", "/admin/api/v1/redteam/run", map[string]interface{}{
		"roles": []string{"user"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST run missing identity status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleRunRedTeam_InvalidCategory(t *testing.T) {
	env := setupRedTeamTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/redteam/run", map[string]interface{}{
		"target_identity": "test-agent",
		"category":        "nonexistent_category",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST run invalid category status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleRunRedTeam_Valid(t *testing.T) {
	env := setupRedTeamTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/redteam/run", map[string]interface{}{
		"target_identity": "test-agent",
		"roles":           []string{"user"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST run suite status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var report redteam.Report
	decodeRedTeamJSON(t, rec, &report)
	if report.CorpusSize == 0 {
		t.Error("expected non-zero corpus size in report")
	}
	if report.TargetID != "test-agent" {
		t.Errorf("TargetID = %q, want %q", report.TargetID, "test-agent")
	}
	if report.ID == "" {
		t.Error("report ID is empty")
	}
}

func TestHandleRunSingleRedTeam_MissingFields(t *testing.T) {
	env := setupRedTeamTestEnv(t)

	// Missing pattern_id.
	rec := env.doRequest(t, "POST", "/admin/api/v1/redteam/run/single", map[string]interface{}{
		"target_identity": "test-agent",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST single missing pattern_id status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleGetRedTeamReport_NotFound(t *testing.T) {
	env := setupRedTeamTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/redteam/reports/nonexistent-id", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET nonexistent report status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleGetRedTeamCorpus_NilService(t *testing.T) {
	env := setupRedTeamTestEnvNilService(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/redteam/corpus", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET corpus nil service status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleGetRedTeamReports_NilService(t *testing.T) {
	env := setupRedTeamTestEnvNilService(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/redteam/reports", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET reports nil service status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Handler returns empty list when service is nil.
	var resp struct {
		Reports []interface{} `json:"reports"`
	}
	decodeRedTeamJSON(t, rec, &resp)
	if len(resp.Reports) != 0 {
		t.Errorf("expected 0 reports, got %d", len(resp.Reports))
	}
}
