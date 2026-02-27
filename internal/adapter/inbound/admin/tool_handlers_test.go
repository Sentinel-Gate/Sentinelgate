package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// --- Test helpers ---

func newTestToolHandler(t *testing.T, cache *upstream.ToolCache) *AdminAPIHandler {
	t.Helper()
	opts := []AdminAPIOption{WithAPILogger(slog.Default())}
	if cache != nil {
		opts = append(opts, WithToolCache(cache))
	}
	return NewAdminAPIHandler(opts...)
}

func serveToolRequest(t *testing.T, handler http.HandlerFunc, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// --- Tests for handleListTools ---

func TestHandleListTools_EmptyCache(t *testing.T) {
	cache := upstream.NewToolCache()
	h := newTestToolHandler(t, cache)
	rec := serveToolRequest(t, h.handleListTools, http.MethodGet, "/admin/api/tools")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}

	var resp toolListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Tools == nil {
		t.Fatal("expected empty tools array [], got null")
	}
	if len(resp.Tools) != 0 {
		t.Fatalf("expected 0 tools, got %d", len(resp.Tools))
	}
	if resp.Conflicts == nil {
		t.Fatal("expected empty conflicts array [], got null")
	}
	if len(resp.Conflicts) != 0 {
		t.Fatalf("expected 0 conflicts, got %d", len(resp.Conflicts))
	}
}

func TestHandleListTools_NilCache(t *testing.T) {
	h := newTestToolHandler(t, nil)
	rec := serveToolRequest(t, h.handleListTools, http.MethodGet, "/admin/api/tools")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp toolListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Tools == nil {
		t.Fatal("expected empty tools array [], got null")
	}
	if len(resp.Tools) != 0 {
		t.Fatalf("expected 0 tools, got %d", len(resp.Tools))
	}
}

func TestHandleListTools_WithTools(t *testing.T) {
	cache := upstream.NewToolCache()
	now := time.Date(2026, 2, 5, 12, 0, 0, 0, time.UTC)

	objSchema := json.RawMessage(`{"type":"object"}`)
	pathSchema := json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`)
	emptySchema := json.RawMessage(`{}`)

	cache.SetToolsForUpstream("upstream-b", []*upstream.DiscoveredTool{
		{
			Name:         "write_file",
			Description:  "Write a file",
			InputSchema:  objSchema,
			UpstreamID:   "upstream-b",
			UpstreamName: "alpha-server",
			DiscoveredAt: now,
		},
	})
	cache.SetToolsForUpstream("upstream-a", []*upstream.DiscoveredTool{
		{
			Name:         "read_file",
			Description:  "Read a file",
			InputSchema:  pathSchema,
			UpstreamID:   "upstream-a",
			UpstreamName: "beta-server",
			DiscoveredAt: now.Add(-time.Hour),
		},
		{
			Name:         "list_files",
			Description:  "List files",
			InputSchema:  emptySchema,
			UpstreamID:   "upstream-a",
			UpstreamName: "beta-server",
			DiscoveredAt: now.Add(-time.Hour),
		},
	})

	h := newTestToolHandler(t, cache)
	rec := serveToolRequest(t, h.handleListTools, http.MethodGet, "/admin/api/tools")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp toolListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tools := resp.Tools
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(tools))
	}

	// Expected sort order: alpha-server/write_file, beta-server/list_files, beta-server/read_file
	if tools[0].UpstreamName != "alpha-server" || tools[0].Name != "write_file" {
		t.Errorf("tools[0] expected alpha-server/write_file, got %s/%s", tools[0].UpstreamName, tools[0].Name)
	}
	if tools[1].UpstreamName != "beta-server" || tools[1].Name != "list_files" {
		t.Errorf("tools[1] expected beta-server/list_files, got %s/%s", tools[1].UpstreamName, tools[1].Name)
	}
	if tools[2].UpstreamName != "beta-server" || tools[2].Name != "read_file" {
		t.Errorf("tools[2] expected beta-server/read_file, got %s/%s", tools[2].UpstreamName, tools[2].Name)
	}

	for i, tool := range tools {
		if tool.Name == "" {
			t.Errorf("tools[%d]: name is empty", i)
		}
		if tool.UpstreamID == "" {
			t.Errorf("tools[%d]: upstream_id is empty", i)
		}
		if tool.UpstreamName == "" {
			t.Errorf("tools[%d]: upstream_name is empty", i)
		}
		if tool.DiscoveredAt.IsZero() {
			t.Errorf("tools[%d]: discovered_at is zero", i)
		}
		if tool.PolicyStatus != "unknown" {
			t.Errorf("tools[%d]: expected policy_status unknown, got %q", i, tool.PolicyStatus)
		}
	}

	// No conflicts expected since no duplicate tool names
	if len(resp.Conflicts) != 0 {
		t.Errorf("expected 0 conflicts, got %d", len(resp.Conflicts))
	}
}

func TestHandleListTools_FieldsPresent(t *testing.T) {
	cache := upstream.NewToolCache()
	now := time.Now().UTC()

	cache.SetToolsForUpstream("up1", []*upstream.DiscoveredTool{
		{
			Name:         "test_tool",
			Description:  "A test tool",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
			UpstreamID:   "up1",
			UpstreamName: "test-server",
			DiscoveredAt: now,
		},
	})

	h := newTestToolHandler(t, cache)
	rec := serveToolRequest(t, h.handleListTools, http.MethodGet, "/admin/api/tools")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Top-level must have "tools" and "conflicts" fields
	topLevelFields := []string{"tools", "conflicts"}
	for _, field := range topLevelFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("missing top-level field %q in response", field)
		}
	}

	// Parse tools array and check field presence
	var toolsArr []map[string]json.RawMessage
	if err := json.Unmarshal(raw["tools"], &toolsArr); err != nil {
		t.Fatalf("failed to decode tools array: %v", err)
	}

	if len(toolsArr) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(toolsArr))
	}

	requiredFields := []string{
		"name", "description", "input_schema",
		"upstream_id", "upstream_name", "discovered_at", "policy_status",
	}
	for _, field := range requiredFields {
		if _, ok := toolsArr[0][field]; !ok {
			t.Errorf("missing required field %q in tool response", field)
		}
	}
}

func TestHandleListTools_SortOrder(t *testing.T) {
	cache := upstream.NewToolCache()
	now := time.Now().UTC()

	cache.SetToolsForUpstream("u3", []*upstream.DiscoveredTool{
		{Name: "z_tool", UpstreamID: "u3", UpstreamName: "charlie", DiscoveredAt: now},
	})
	cache.SetToolsForUpstream("u1", []*upstream.DiscoveredTool{
		{Name: "b_tool", UpstreamID: "u1", UpstreamName: "alpha", DiscoveredAt: now},
		{Name: "a_tool", UpstreamID: "u1", UpstreamName: "alpha", DiscoveredAt: now},
	})
	cache.SetToolsForUpstream("u2", []*upstream.DiscoveredTool{
		{Name: "x_tool", UpstreamID: "u2", UpstreamName: "bravo", DiscoveredAt: now},
	})

	h := newTestToolHandler(t, cache)
	rec := serveToolRequest(t, h.handleListTools, http.MethodGet, "/admin/api/tools")

	var resp toolListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	tools := resp.Tools
	if len(tools) != 4 {
		t.Fatalf("expected 4 tools, got %d", len(tools))
	}

	expected := []struct {
		upstreamName string
		name         string
	}{
		{"alpha", "a_tool"},
		{"alpha", "b_tool"},
		{"bravo", "x_tool"},
		{"charlie", "z_tool"},
	}

	for i, exp := range expected {
		if tools[i].UpstreamName != exp.upstreamName || tools[i].Name != exp.name {
			t.Errorf("tools[%d]: expected %s/%s, got %s/%s",
				i, exp.upstreamName, exp.name, tools[i].UpstreamName, tools[i].Name)
		}
	}
}

// --- Tests for conflict detection in tool list ---

func TestHandleListTools_WithConflicts(t *testing.T) {
	cache := upstream.NewToolCache()
	now := time.Now().UTC()

	// Set up tools from upstream-a (winner)
	cache.SetToolsForUpstream("upstream-a", []*upstream.DiscoveredTool{
		{Name: "read_file", UpstreamID: "upstream-a", UpstreamName: "server-alpha", DiscoveredAt: now},
	})

	// Record a conflict: upstream-b had read_file too but was skipped
	cache.RecordConflict(upstream.ToolConflict{
		ToolName:            "read_file",
		SkippedUpstreamID:   "upstream-b",
		SkippedUpstreamName: "server-beta",
		WinnerUpstreamID:    "upstream-a",
		WinnerUpstreamName:  "server-alpha",
	})

	h := newTestToolHandler(t, cache)
	rec := serveToolRequest(t, h.handleListTools, http.MethodGet, "/admin/api/tools")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp toolListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(resp.Tools))
	}

	if len(resp.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(resp.Conflicts))
	}

	c := resp.Conflicts[0]
	if c.ToolName != "read_file" {
		t.Errorf("expected conflict tool_name 'read_file', got %q", c.ToolName)
	}
	if len(c.Upstreams) != 2 {
		t.Errorf("expected 2 upstreams in conflict, got %d", len(c.Upstreams))
	}
	if len(c.UpstreamIDs) != 2 {
		t.Errorf("expected 2 upstream_ids in conflict, got %d", len(c.UpstreamIDs))
	}
}

func TestHandleListTools_NoConflicts(t *testing.T) {
	cache := upstream.NewToolCache()
	now := time.Now().UTC()

	cache.SetToolsForUpstream("upstream-a", []*upstream.DiscoveredTool{
		{Name: "read_file", UpstreamID: "upstream-a", UpstreamName: "server-alpha", DiscoveredAt: now},
	})
	cache.SetToolsForUpstream("upstream-b", []*upstream.DiscoveredTool{
		{Name: "write_file", UpstreamID: "upstream-b", UpstreamName: "server-beta", DiscoveredAt: now},
	})

	h := newTestToolHandler(t, cache)
	rec := serveToolRequest(t, h.handleListTools, http.MethodGet, "/admin/api/tools")

	var resp toolListResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.Conflicts) != 0 {
		t.Errorf("expected 0 conflicts, got %d", len(resp.Conflicts))
	}
}

// --- Tests for handleRefreshTools ---

func TestHandleRefreshTools_NilDiscoveryService(t *testing.T) {
	cache := upstream.NewToolCache()
	h := newTestToolHandler(t, cache)

	rec := serveToolRequest(t, h.handleRefreshTools, http.MethodPost, "/admin/api/tools/refresh")

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d", rec.Code)
	}

	var errResp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp["error"] == "" {
		t.Fatal("expected error message in response")
	}
}

// --- Tests for evaluateToolPolicy ---

func TestHandleListTools_PolicyStatusEvaluation(t *testing.T) {
	h := NewAdminAPIHandler(WithAPILogger(slog.Default()))
	status := h.evaluateToolPolicy(context.Background(), "any_tool")
	if status != "unknown" {
		t.Errorf("expected unknown for nil policyService, got %q", status)
	}
}
