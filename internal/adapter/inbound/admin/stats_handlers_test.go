package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

func TestHandleGetStats_Empty(t *testing.T) {
	h := NewAdminAPIHandler()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil)
	rec := httptest.NewRecorder()

	h.handleGetStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp StatsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Upstreams != 0 || resp.Tools != 0 || resp.Policies != 0 {
		t.Errorf("counts should be 0 when services not configured: %+v", resp)
	}
	if resp.Allowed != 0 || resp.Denied != 0 || resp.RateLimited != 0 || resp.Errors != 0 {
		t.Errorf("counters should be 0: %+v", resp)
	}
}

func TestHandleGetStats_WithStatsService(t *testing.T) {
	stats := service.NewStatsService()
	stats.RecordAllow()
	stats.RecordAllow()
	stats.RecordAllow()
	stats.RecordDeny()
	stats.RecordRateLimited()
	stats.RecordRateLimited()
	stats.RecordError()

	h := NewAdminAPIHandler(
		WithStatsService(stats),
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil)
	rec := httptest.NewRecorder()

	h.handleGetStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp StatsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Allowed != 3 {
		t.Errorf("Allowed = %d, want 3", resp.Allowed)
	}
	if resp.Denied != 1 {
		t.Errorf("Denied = %d, want 1", resp.Denied)
	}
	if resp.RateLimited != 2 {
		t.Errorf("RateLimited = %d, want 2", resp.RateLimited)
	}
	if resp.Errors != 1 {
		t.Errorf("Errors = %d, want 1", resp.Errors)
	}
}

func TestHandleGetStats_ProtocolFrameworkCounts(t *testing.T) {
	stats := service.NewStatsService()
	stats.RecordProtocol("mcp")
	stats.RecordProtocol("mcp")
	stats.RecordProtocol("http")
	stats.RecordFramework("langchain")

	h := NewAdminAPIHandler(
		WithStatsService(stats),
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil)
	rec := httptest.NewRecorder()

	h.handleGetStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp StatsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.ProtocolCounts["mcp"] != 2 {
		t.Errorf("protocol_counts.mcp = %d, want 2", resp.ProtocolCounts["mcp"])
	}
	if resp.ProtocolCounts["http"] != 1 {
		t.Errorf("protocol_counts.http = %d, want 1", resp.ProtocolCounts["http"])
	}
	if resp.FrameworkCounts["langchain"] != 1 {
		t.Errorf("framework_counts.langchain = %d, want 1", resp.FrameworkCounts["langchain"])
	}
}

func TestHandleGetStats_EmptyMapsNotNull(t *testing.T) {
	h := NewAdminAPIHandler()

	req := httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil)
	rec := httptest.NewRecorder()

	h.handleGetStats(rec, req)

	// Parse as raw JSON to check protocol_counts and framework_counts are {} not null.
	var raw map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	pc, ok := raw["protocol_counts"]
	if !ok {
		t.Fatal("missing protocol_counts in response")
	}
	if pc == nil {
		t.Error("protocol_counts should be {} not null")
	}

	fc, ok := raw["framework_counts"]
	if !ok {
		t.Fatal("missing framework_counts in response")
	}
	if fc == nil {
		t.Error("framework_counts should be {} not null")
	}
}

func TestHandleGetStats_ContentType(t *testing.T) {
	h := NewAdminAPIHandler()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil)
	rec := httptest.NewRecorder()
	h.handleGetStats(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}
