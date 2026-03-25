package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// testHealthReader implements service.HealthAuditReader.
type testHealthReader struct {
	records []audit.AuditRecord
}

func (r *testHealthReader) Query(_ context.Context, filter audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	var result []audit.AuditRecord
	for _, rec := range r.records {
		if filter.UserID != "" && rec.IdentityID != filter.UserID {
			continue
		}
		if !filter.StartTime.IsZero() && rec.Timestamp.Before(filter.StartTime) {
			continue
		}
		if !filter.EndTime.IsZero() && rec.Timestamp.After(filter.EndTime) {
			continue
		}
		result = append(result, rec)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result, "", nil
}

func newTestHealthHandler() *AdminAPIHandler {
	now := time.Now()
	reader := &testHealthReader{
		records: []audit.AuditRecord{
			{IdentityID: "agent-1", Decision: "allow", Timestamp: now.Add(-1 * time.Hour), ToolName: "read_file"},
			{IdentityID: "agent-1", Decision: "deny", Timestamp: now.Add(-2 * time.Hour), ToolName: "write_file"},
			{IdentityID: "agent-1", Decision: "allow", Timestamp: now.Add(-3 * time.Hour), ToolName: "read_file"},
			{IdentityID: "agent-2", Decision: "allow", Timestamp: now.Add(-1 * time.Hour), ToolName: "list_files"},
		},
	}

	healthSvc := service.NewHealthService(reader, slog.Default())
	h := &AdminAPIHandler{
		healthService: healthSvc,
		logger:        slog.Default(),
	}
	return h
}

func TestHandleGetAgentHealth(t *testing.T) {
	h := newTestHealthHandler()

	req := httptest.NewRequest("GET", "/admin/api/v1/agents/agent-1/health", nil)
	req.SetPathValue("identity_id", "agent-1")
	w := httptest.NewRecorder()

	h.handleGetAgentHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var report service.AgentHealthReport
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if report.Status == "" {
		t.Error("Status should not be empty")
	}
	if report.Identity.TotalCalls == 0 {
		t.Error("TotalCalls should not be 0")
	}
}

func TestHandleGetAgentHealth_MissingID(t *testing.T) {
	h := newTestHealthHandler()

	req := httptest.NewRequest("GET", "/admin/api/v1/agents//health", nil)
	req.SetPathValue("identity_id", "")
	w := httptest.NewRecorder()

	h.handleGetAgentHealth(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleGetHealthOverview(t *testing.T) {
	h := newTestHealthHandler()

	req := httptest.NewRequest("GET", "/admin/api/v1/health/overview", nil)
	w := httptest.NewRecorder()

	h.handleGetHealthOverview(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var entries []service.HealthOverviewEntry
	if err := json.NewDecoder(w.Body).Decode(&entries); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if len(entries) < 1 {
		t.Error("expected at least 1 entry")
	}
}

func TestHandleGetHealthConfig(t *testing.T) {
	h := newTestHealthHandler()

	req := httptest.NewRequest("GET", "/admin/api/v1/health/config", nil)
	w := httptest.NewRecorder()

	h.handleGetHealthConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var cfg service.HealthConfig
	if err := json.NewDecoder(w.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if cfg.DenyRateWarning != 0.10 {
		t.Errorf("DenyRateWarning = %f, want 0.10", cfg.DenyRateWarning)
	}
}

func TestHandlePutHealthConfig(t *testing.T) {
	h := newTestHealthHandler()

	body := `{"deny_rate_warning": 0.20, "deny_rate_critical": 0.40}`
	req := httptest.NewRequest("PUT", "/admin/api/v1/health/config", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.handlePutHealthConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var cfg service.HealthConfig
	if err := json.NewDecoder(w.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if cfg.DenyRateWarning != 0.20 {
		t.Errorf("DenyRateWarning = %f, want 0.20", cfg.DenyRateWarning)
	}
	if cfg.DenyRateCritical != 0.40 {
		t.Errorf("DenyRateCritical = %f, want 0.40", cfg.DenyRateCritical)
	}
	// Others should remain at defaults
	if cfg.DriftScoreWarning != 0.30 {
		t.Errorf("DriftScoreWarning = %f, want 0.30 (default)", cfg.DriftScoreWarning)
	}
}

func TestHandleGetHealthNoService(t *testing.T) {
	h := &AdminAPIHandler{logger: slog.Default()}

	req := httptest.NewRequest("GET", "/admin/api/v1/health/overview", nil)
	w := httptest.NewRecorder()
	h.handleGetHealthOverview(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}
