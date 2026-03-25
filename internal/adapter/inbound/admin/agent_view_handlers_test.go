package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
)

// agentMockAuditReader implements AuditReader for agent view testing.
type agentMockAuditReader struct {
	records []audit.AuditRecord
}

func (m *agentMockAuditReader) GetRecent(n int) []audit.AuditRecord {
	if n > len(m.records) {
		return m.records
	}
	return m.records[:n]
}

func (m *agentMockAuditReader) Query(_ context.Context, filter audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	var result []audit.AuditRecord
	for _, r := range m.records {
		if filter.UserID != "" && r.IdentityID != filter.UserID {
			continue
		}
		result = append(result, r)
	}
	return result, "", nil
}

func TestHandleGetAgentSummary(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Create session tracker with a session.
	tracker := session.NewSessionTracker(1*time.Minute, session.DefaultClassifier())
	tracker.RecordCall("sess-1", "read_file", "test-agent", "Test Agent", nil)
	tracker.RecordCall("sess-1", "read_file", "test-agent", "Test Agent", nil)
	tracker.RecordCall("sess-1", "write_file", "test-agent", "Test Agent", nil)

	// Create mock audit reader.
	now := time.Now()
	reader := &agentMockAuditReader{
		records: []audit.AuditRecord{
			{Timestamp: now.Add(-1 * time.Hour), IdentityID: "test-agent", ToolName: "read_file", Decision: "allow", ScanDetections: 2, ScanAction: "redacted"},
			{Timestamp: now.Add(-30 * time.Minute), IdentityID: "test-agent", ToolName: "read_file", Decision: "allow"},
			{Timestamp: now.Add(-10 * time.Minute), IdentityID: "test-agent", ToolName: "write_file", Decision: "deny", RuleID: "deny-write", Reason: "blocked by policy", ScanDetections: 1, ScanAction: "blocked"},
			{Timestamp: now.Add(-5 * time.Minute), IdentityID: "other-agent", ToolName: "bash", Decision: "allow"},
		},
	}

	h := NewAdminAPIHandler(WithAPILogger(logger))
	h.sessionTracker = tracker
	h.auditReader = reader

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/agents/test-agent/summary", nil)
	req.SetPathValue("identity_id", "test-agent")
	w := httptest.NewRecorder()

	h.handleGetAgentSummary(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp agentSummaryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	// Identity should be populated (fallback to ID since no identity service).
	if resp.Identity.ID != "test-agent" {
		t.Errorf("expected identity ID test-agent, got %s", resp.Identity.ID)
	}

	// Session should be found.
	if resp.Session == nil {
		t.Fatal("expected session info")
	}
	if resp.Session.SessionID != "sess-1" {
		t.Errorf("expected session ID sess-1, got %s", resp.Session.SessionID)
	}

	// Stats: 3 records for test-agent (filtered from 4).
	if resp.Stats.TotalCalls != 3 {
		t.Errorf("expected 3 total calls, got %d", resp.Stats.TotalCalls)
	}
	if resp.Stats.AllowedCalls != 2 {
		t.Errorf("expected 2 allowed calls, got %d", resp.Stats.AllowedCalls)
	}
	if resp.Stats.DeniedCalls != 1 {
		t.Errorf("expected 1 denied call, got %d", resp.Stats.DeniedCalls)
	}

	// Scan stats: 2 records with detections (2+1=3 total), 1 blocked.
	if resp.Stats.ScanDetections != 3 {
		t.Errorf("expected 3 scan detections, got %d", resp.Stats.ScanDetections)
	}
	if resp.Stats.ScanBlocked != 1 {
		t.Errorf("expected 1 scan blocked, got %d", resp.Stats.ScanBlocked)
	}

	// Tool usage: read_file (2), write_file (1).
	if len(resp.ToolUsage) != 2 {
		t.Fatalf("expected 2 tool usage entries, got %d", len(resp.ToolUsage))
	}
	if resp.ToolUsage[0].ToolName != "read_file" {
		t.Errorf("expected first tool read_file, got %s", resp.ToolUsage[0].ToolName)
	}
	if resp.ToolUsage[0].Count != 2 {
		t.Errorf("expected read_file count 2, got %d", resp.ToolUsage[0].Count)
	}

	// Timeline: 3 items for test-agent.
	if len(resp.Timeline) != 3 {
		t.Errorf("expected 3 timeline items, got %d", len(resp.Timeline))
	}
}

func TestHandleGetAgentSummary_NotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	h := NewAdminAPIHandler(WithAPILogger(logger))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/agents/unknown/summary", nil)
	req.SetPathValue("identity_id", "unknown")
	w := httptest.NewRecorder()

	h.handleGetAgentSummary(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (with empty data), got %d", w.Code)
	}

	var resp agentSummaryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if resp.Identity.ID != "unknown" {
		t.Errorf("expected identity ID unknown, got %s", resp.Identity.ID)
	}
	if resp.Session != nil {
		t.Error("expected nil session for unknown agent")
	}
	if resp.Stats.TotalCalls != 0 {
		t.Errorf("expected 0 total calls, got %d", resp.Stats.TotalCalls)
	}
}

func TestHandleGetAgentSummary_MissingID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	h := NewAdminAPIHandler(WithAPILogger(logger))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/agents//summary", nil)
	req.SetPathValue("identity_id", "")
	w := httptest.NewRecorder()

	h.handleGetAgentSummary(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
