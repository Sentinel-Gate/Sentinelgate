package admin

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// mockAuditReader implements AuditReader for testing.
type mockAuditReader struct {
	records []audit.AuditRecord
}

func (m *mockAuditReader) GetRecent(n int) []audit.AuditRecord {
	if n > len(m.records) {
		n = len(m.records)
	}
	return m.records[:n]
}

func (m *mockAuditReader) Query(filter audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	var result []audit.AuditRecord
	for _, rec := range m.records {
		if filter.Decision != "" && rec.Decision != filter.Decision {
			continue
		}
		if filter.ToolName != "" && rec.ToolName != filter.ToolName {
			continue
		}
		if filter.UserID != "" && rec.IdentityID != filter.UserID {
			continue
		}
		if filter.Protocol != "" && rec.Protocol != filter.Protocol {
			continue
		}
		result = append(result, rec)
	}
	if filter.Limit > 0 && len(result) > filter.Limit {
		result = result[:filter.Limit]
	}
	return result, "", nil
}

func testAuditRecords() []audit.AuditRecord {
	now := time.Now().UTC()
	return []audit.AuditRecord{
		{
			Timestamp:  now.Add(-2 * time.Second),
			SessionID:  "sess-1",
			IdentityID: "user-1",
			ToolName:   "read_file",
			Decision:   "allow",
			Reason:     "matched rule admin-bypass",
			RuleID:     "rule-1",
			RequestID:  "req-1",
			Protocol:   "mcp",
			Framework:  "langchain",
		},
		{
			Timestamp:  now.Add(-1 * time.Second),
			SessionID:  "sess-2",
			IdentityID: "user-2",
			ToolName:   "delete_file",
			Decision:   "deny",
			Reason:     "matched rule block-delete",
			RuleID:     "rule-2",
			RequestID:  "req-2",
			Protocol:   "http",
			Framework:  "crewai",
		},
		{
			Timestamp:  now,
			SessionID:  "sess-1",
			IdentityID: "user-1",
			ToolName:   "write_file",
			Decision:   "allow",
			Reason:     "matched rule user-write",
			RuleID:     "rule-3",
			RequestID:  "req-3",
			Protocol:   "mcp",
			Framework:  "",
		},
	}
}

func TestHandleQueryAudit_Empty(t *testing.T) {
	reader := &mockAuditReader{records: nil}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit", nil)
	rec := httptest.NewRecorder()
	h.handleQueryAudit(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp AuditQueryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Count != 0 {
		t.Errorf("Count = %d, want 0", resp.Count)
	}
}

func TestHandleQueryAudit_WithRecords(t *testing.T) {
	reader := &mockAuditReader{records: testAuditRecords()}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit", nil)
	rec := httptest.NewRecorder()
	h.handleQueryAudit(rec, req)

	var resp AuditQueryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Count != 3 {
		t.Errorf("Count = %d, want 3", resp.Count)
	}
}

func TestHandleQueryAudit_DecisionFilter(t *testing.T) {
	reader := &mockAuditReader{records: testAuditRecords()}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit?decision=deny", nil)
	rec := httptest.NewRecorder()
	h.handleQueryAudit(rec, req)

	var resp AuditQueryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Count != 1 {
		t.Errorf("Count = %d, want 1 (deny only)", resp.Count)
	}
	if resp.Count > 0 && resp.Records[0].Decision != "deny" {
		t.Errorf("Decision = %q, want 'deny'", resp.Records[0].Decision)
	}
}

func TestHandleQueryAudit_InvalidDecision(t *testing.T) {
	reader := &mockAuditReader{records: testAuditRecords()}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit?decision=invalid", nil)
	rec := httptest.NewRecorder()
	h.handleQueryAudit(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleQueryAudit_NoReader(t *testing.T) {
	h := NewAdminAPIHandler()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit", nil)
	rec := httptest.NewRecorder()
	h.handleQueryAudit(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleAuditExport_CSV(t *testing.T) {
	reader := &mockAuditReader{records: testAuditRecords()}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit/export", nil)
	rec := httptest.NewRecorder()
	h.handleAuditExport(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "text/csv" {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}

	disp := rec.Header().Get("Content-Disposition")
	if !strings.Contains(disp, "attachment") {
		t.Errorf("Content-Disposition = %q, want attachment", disp)
	}

	csvReader := csv.NewReader(rec.Body)
	rows, err := csvReader.ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	// Header + 3 data rows.
	if len(rows) != 4 {
		t.Errorf("CSV rows = %d, want 4 (1 header + 3 data)", len(rows))
	}

	// Verify header.
	if rows[0][0] != "timestamp" {
		t.Errorf("first header = %q, want 'timestamp'", rows[0][0])
	}
}

func TestHandleAuditExport_NoReader(t *testing.T) {
	h := NewAdminAPIHandler()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit/export", nil)
	rec := httptest.NewRecorder()
	h.handleAuditExport(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestHandleAuditStream_Headers(t *testing.T) {
	reader := &mockAuditReader{records: testAuditRecords()}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit/stream", nil)

	// Create a cancelled context so SSE loop exits after initial batch.
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.handleAuditStream(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}

	cc := rec.Header().Get("Cache-Control")
	if cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}

	conn := rec.Header().Get("Connection")
	if conn != "keep-alive" {
		t.Errorf("Connection = %q, want keep-alive", conn)
	}
}

func TestHandleAuditStream_InitialRecords(t *testing.T) {
	reader := &mockAuditReader{records: testAuditRecords()}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit/stream", nil)
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.handleAuditStream(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "data: ") {
		t.Error("SSE body should contain initial records with 'data: ' prefix")
	}
}

func TestHandleAuditStream_NoReader(t *testing.T) {
	h := NewAdminAPIHandler()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit/stream", nil)
	rec := httptest.NewRecorder()
	h.handleAuditStream(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestParseAuditFilter_Defaults(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit", nil)
	filter, err := parseAuditFilter(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filter.Limit != 100 {
		t.Errorf("Limit = %d, want 100", filter.Limit)
	}
	if filter.StartTime.IsZero() {
		t.Error("StartTime should default to 24h ago")
	}
	if filter.EndTime.IsZero() {
		t.Error("EndTime should default to now")
	}
}

func TestParseAuditFilter_LimitClamp(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit?limit=5000", nil)
	filter, err := parseAuditFilter(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if filter.Limit != 1000 {
		t.Errorf("Limit = %d, want 1000 (clamped)", filter.Limit)
	}
}

func TestHandleQueryAudit_ProtocolFilter(t *testing.T) {
	reader := &mockAuditReader{records: testAuditRecords()}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit?protocol=mcp", nil)
	rec := httptest.NewRecorder()
	h.handleQueryAudit(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp AuditQueryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Count != 2 {
		t.Errorf("Count = %d, want 2 (mcp only)", resp.Count)
	}
	for _, r := range resp.Records {
		if r.Protocol != "mcp" {
			t.Errorf("Protocol = %q, want 'mcp'", r.Protocol)
		}
	}
}

func TestHandleQueryAudit_NoProtocolFilter(t *testing.T) {
	reader := &mockAuditReader{records: testAuditRecords()}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit", nil)
	rec := httptest.NewRecorder()
	h.handleQueryAudit(rec, req)

	var resp AuditQueryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Count != 3 {
		t.Errorf("Count = %d, want 3 (all entries)", resp.Count)
	}
}

func TestHandleQueryAudit_InvalidProtocol(t *testing.T) {
	reader := &mockAuditReader{records: testAuditRecords()}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit?protocol=invalid", nil)
	rec := httptest.NewRecorder()
	h.handleQueryAudit(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleAuditExport_ProtocolAndFrameworkColumns(t *testing.T) {
	reader := &mockAuditReader{records: testAuditRecords()}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit/export", nil)
	rec := httptest.NewRecorder()
	h.handleAuditExport(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	csvReader := csv.NewReader(rec.Body)
	rows, err := csvReader.ReadAll()
	if err != nil {
		t.Fatalf("read CSV: %v", err)
	}

	// Verify header includes protocol and framework columns.
	header := rows[0]
	if len(header) < 11 {
		t.Fatalf("header columns = %d, want at least 11", len(header))
	}
	if header[9] != "protocol" {
		t.Errorf("header[9] = %q, want 'protocol'", header[9])
	}
	if header[10] != "framework" {
		t.Errorf("header[10] = %q, want 'framework'", header[10])
	}

	// Verify data rows have protocol and framework values.
	if len(rows) < 2 {
		t.Fatal("expected at least 1 data row")
	}
	if rows[1][9] != "mcp" {
		t.Errorf("row 1 protocol = %q, want 'mcp'", rows[1][9])
	}
	if rows[1][10] != "langchain" {
		t.Errorf("row 1 framework = %q, want 'langchain'", rows[1][10])
	}
}

func TestHandleQueryAudit_ProtocolInDTO(t *testing.T) {
	reader := &mockAuditReader{records: testAuditRecords()}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit", nil)
	rec := httptest.NewRecorder()
	h.handleQueryAudit(rec, req)

	var resp AuditQueryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// First record should have protocol and framework fields populated.
	found := false
	for _, r := range resp.Records {
		if r.Protocol == "mcp" && r.Framework == "langchain" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one record with protocol=mcp, framework=langchain")
	}
}
