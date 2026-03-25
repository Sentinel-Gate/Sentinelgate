package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

type testFinOpsAuditReader struct {
	records []audit.AuditRecord
}

func (r *testFinOpsAuditReader) Query(_ context.Context, _ audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	return r.records, "", nil
}

func newTestFinOpsHandler(enabled bool) *AdminAPIHandler {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	records := []audit.AuditRecord{
		{Timestamp: time.Now(), IdentityID: "agent-a", ToolName: "read_file", Decision: "allow"},
		{Timestamp: time.Now(), IdentityID: "agent-a", ToolName: "write_file", Decision: "allow"},
		{Timestamp: time.Now(), IdentityID: "agent-b", ToolName: "read_file", Decision: "allow"},
		{Timestamp: time.Now(), IdentityID: "agent-b", ToolName: "read_file", Decision: "deny"},
	}
	reader := &testFinOpsAuditReader{records: records}
	svc := service.NewFinOpsService(reader, logger)
	if enabled {
		svc.SetConfig(service.FinOpsConfig{
			Enabled:            true,
			DefaultCostPerCall: 0.01,
			ToolCosts:          map[string]float64{},
			Budgets:            map[string]float64{"agent-a": 10.0},
			AlertThresholds:    []float64{0.7, 0.85, 1.0},
		})
	}
	h := &AdminAPIHandler{logger: logger}
	h.finopsService = svc
	return h
}

func TestHandleGetFinOpsCosts(t *testing.T) {
	h := newTestFinOpsHandler(true)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/finops/costs", nil)
	w := httptest.NewRecorder()

	h.handleGetFinOpsCosts(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var report service.CostReport
	json.NewDecoder(w.Body).Decode(&report)
	if report.TotalCalls != 3 { // 3 allowed
		t.Errorf("expected 3 calls, got %d", report.TotalCalls)
	}
	if report.TotalCost <= 0 {
		t.Error("expected positive cost")
	}
}

func TestHandleGetFinOpsCosts_Disabled(t *testing.T) {
	h := newTestFinOpsHandler(false)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/finops/costs", nil)
	w := httptest.NewRecorder()

	h.handleGetFinOpsCosts(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var report service.CostReport
	json.NewDecoder(w.Body).Decode(&report)
	if report.TotalCost != 0 {
		t.Errorf("disabled should return 0 cost, got %f", report.TotalCost)
	}
}

func TestHandleGetFinOpsIdentityCost(t *testing.T) {
	h := newTestFinOpsHandler(true)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/finops/costs/agent-a", nil)
	req.SetPathValue("identity_id", "agent-a")
	w := httptest.NewRecorder()

	h.handleGetFinOpsIdentityCost(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var detail service.IdentityCostDetail
	json.NewDecoder(w.Body).Decode(&detail)
	if detail.IdentityID != "agent-a" {
		t.Errorf("expected agent-a, got %s", detail.IdentityID)
	}
}

func TestHandleGetFinOpsIdentityCost_MissingID(t *testing.T) {
	h := newTestFinOpsHandler(true)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/finops/costs/", nil)
	w := httptest.NewRecorder()

	h.handleGetFinOpsIdentityCost(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleGetFinOpsBudgets(t *testing.T) {
	h := newTestFinOpsHandler(true)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/finops/budgets", nil)
	w := httptest.NewRecorder()

	h.handleGetFinOpsBudgets(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Budgets []service.BudgetStatus `json:"budgets"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Budgets) != 1 {
		t.Errorf("expected 1 budget, got %d", len(resp.Budgets))
	}
}

func TestHandleGetFinOpsConfig(t *testing.T) {
	h := newTestFinOpsHandler(true)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/finops/config", nil)
	w := httptest.NewRecorder()

	h.handleGetFinOpsConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var cfg service.FinOpsConfig
	json.NewDecoder(w.Body).Decode(&cfg)
	if !cfg.Enabled {
		t.Error("expected enabled")
	}
	if cfg.DefaultCostPerCall != 0.01 {
		t.Errorf("expected 0.01, got %f", cfg.DefaultCostPerCall)
	}
}

func TestHandleUpdateFinOpsConfig(t *testing.T) {
	h := newTestFinOpsHandler(true)

	body := `{"enabled":true,"default_cost_per_call":0.05,"tool_costs":{"query_db":1.0},"budgets":{"agent-a":100}}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/finops/config", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleUpdateFinOpsConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify config was updated
	cfg := h.finopsService.Config()
	if cfg.DefaultCostPerCall != 0.05 {
		t.Errorf("expected 0.05, got %f", cfg.DefaultCostPerCall)
	}
	if cfg.ToolCosts["query_db"] != 1.0 {
		t.Error("expected query_db cost of 1.0")
	}
}

func TestHandleFinOps_NoService(t *testing.T) {
	h := &AdminAPIHandler{logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))}

	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		code    int
	}{
		{"costs", h.handleGetFinOpsCosts, http.StatusServiceUnavailable},
		{"identity", h.handleGetFinOpsIdentityCost, http.StatusServiceUnavailable},
		{"config_put", h.handleUpdateFinOpsConfig, http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			tt.handler(w, req)
			if w.Code != tt.code {
				t.Errorf("expected %d, got %d", tt.code, w.Code)
			}
		})
	}
}
