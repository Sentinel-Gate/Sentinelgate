package proxy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNewToolCacheAdapter(t *testing.T) {
	cache := upstream.NewToolCache()
	adapter := NewToolCacheAdapter(cache)

	if adapter == nil {
		t.Fatal("expected non-nil adapter")
	}
	if adapter.cache != cache {
		t.Error("adapter should wrap the provided cache")
	}
}

// ---------------------------------------------------------------------------
// GetTool
// ---------------------------------------------------------------------------

func TestToolCacheAdapter_GetTool_Found(t *testing.T) {
	cache := upstream.NewToolCache()
	cache.SetToolsForUpstream("up-1", []*upstream.DiscoveredTool{
		{
			Name:         "read_file",
			UpstreamID:   "up-1",
			UpstreamName: "filesystem",
			Description:  "Reads a file",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
			DiscoveredAt: time.Now(),
		},
	})

	adapter := NewToolCacheAdapter(cache)

	tool, ok := adapter.GetTool("read_file")
	if !ok {
		t.Fatal("expected tool to be found")
	}
	if tool.Name != "read_file" {
		t.Errorf("expected Name=read_file, got %q", tool.Name)
	}
	if tool.UpstreamID != "up-1" {
		t.Errorf("expected UpstreamID=up-1, got %q", tool.UpstreamID)
	}
	if tool.Description != "Reads a file" {
		t.Errorf("expected Description='Reads a file', got %q", tool.Description)
	}
	if string(tool.InputSchema) != `{"type":"object"}` {
		t.Errorf("unexpected InputSchema: %s", string(tool.InputSchema))
	}
}

func TestToolCacheAdapter_GetTool_NotFound(t *testing.T) {
	cache := upstream.NewToolCache()
	adapter := NewToolCacheAdapter(cache)

	tool, ok := adapter.GetTool("nonexistent_tool")
	if ok {
		t.Error("expected ok=false for missing tool")
	}
	if tool != nil {
		t.Error("expected nil tool for missing tool")
	}
}

func TestToolCacheAdapter_GetTool_ReturnsRoutableTool(t *testing.T) {
	cache := upstream.NewToolCache()
	cache.SetToolsForUpstream("up-2", []*upstream.DiscoveredTool{
		{
			Name:         "write_file",
			UpstreamID:   "up-2",
			UpstreamName: "editor",
			Description:  "Writes a file",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"path":{}}}`),
			DiscoveredAt: time.Now(),
		},
	})

	adapter := NewToolCacheAdapter(cache)
	tool, ok := adapter.GetTool("write_file")
	if !ok {
		t.Fatal("expected tool to be found")
	}

	// Verify correct fields.
	if tool.Name != "write_file" {
		t.Errorf("Name mismatch: %q", tool.Name)
	}
	if tool.UpstreamID != "up-2" {
		t.Errorf("UpstreamID mismatch: %q", tool.UpstreamID)
	}
}

// ---------------------------------------------------------------------------
// GetAllTools
// ---------------------------------------------------------------------------

func TestToolCacheAdapter_GetAllTools_Empty(t *testing.T) {
	cache := upstream.NewToolCache()
	adapter := NewToolCacheAdapter(cache)

	tools := adapter.GetAllTools()
	if len(tools) != 0 {
		t.Errorf("expected 0 tools from empty cache, got %d", len(tools))
	}
}

func TestToolCacheAdapter_GetAllTools_SingleUpstream(t *testing.T) {
	cache := upstream.NewToolCache()
	cache.SetToolsForUpstream("up-1", []*upstream.DiscoveredTool{
		{Name: "tool_a", UpstreamID: "up-1", Description: "A"},
		{Name: "tool_b", UpstreamID: "up-1", Description: "B"},
	})

	adapter := NewToolCacheAdapter(cache)
	tools := adapter.GetAllTools()

	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.Name] = true
		if tool.UpstreamID != "up-1" {
			t.Errorf("expected UpstreamID=up-1 for tool %s, got %q", tool.Name, tool.UpstreamID)
		}
	}
	if !names["tool_a"] {
		t.Error("missing tool_a")
	}
	if !names["tool_b"] {
		t.Error("missing tool_b")
	}
}

func TestToolCacheAdapter_GetAllTools_MultipleUpstreams(t *testing.T) {
	cache := upstream.NewToolCache()
	cache.SetToolsForUpstream("up-1", []*upstream.DiscoveredTool{
		{Name: "tool_a", UpstreamID: "up-1", Description: "A"},
	})
	cache.SetToolsForUpstream("up-2", []*upstream.DiscoveredTool{
		{Name: "tool_b", UpstreamID: "up-2", Description: "B"},
		{Name: "tool_c", UpstreamID: "up-2", Description: "C"},
	})

	adapter := NewToolCacheAdapter(cache)
	tools := adapter.GetAllTools()

	if len(tools) != 3 {
		t.Fatalf("expected 3 tools from 2 upstreams, got %d", len(tools))
	}

	names := map[string]bool{}
	for _, tool := range tools {
		names[tool.Name] = true
	}
	for _, expected := range []string{"tool_a", "tool_b", "tool_c"} {
		if !names[expected] {
			t.Errorf("missing tool %s", expected)
		}
	}
}

func TestToolCacheAdapter_GetAllTools_ReturnsRoutableTools(t *testing.T) {
	cache := upstream.NewToolCache()
	cache.SetToolsForUpstream("up-1", []*upstream.DiscoveredTool{
		{
			Name:        "tool_x",
			UpstreamID:  "up-1",
			Description: "X",
			InputSchema: json.RawMessage(`{"type":"object"}`),
		},
	})

	adapter := NewToolCacheAdapter(cache)
	tools := adapter.GetAllTools()

	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}

	if tools[0].Name != "tool_x" {
		t.Errorf("Name: got %q", tools[0].Name)
	}
	if tools[0].UpstreamID != "up-1" {
		t.Errorf("UpstreamID: got %q", tools[0].UpstreamID)
	}
	if tools[0].Description != "X" {
		t.Errorf("Description: got %q", tools[0].Description)
	}
	if string(tools[0].InputSchema) != `{"type":"object"}` {
		t.Errorf("InputSchema: got %s", string(tools[0].InputSchema))
	}
}

// ---------------------------------------------------------------------------
// Interface satisfaction
// ---------------------------------------------------------------------------

func TestToolCacheAdapter_ImplementsToolCacheReader(t *testing.T) {
	cache := upstream.NewToolCache()
	adapter := NewToolCacheAdapter(cache)

	// Compile-time check is already in tool_cache_adapter.go via
	// var _ ToolCacheReader = (*ToolCacheAdapter)(nil)
	// This test verifies it at runtime too.
	_ = ToolCacheReader(adapter) // would fail to compile if interface not satisfied
}

// ---------------------------------------------------------------------------
// toRoutableTool conversion
// ---------------------------------------------------------------------------

func TestToRoutableTool(t *testing.T) {
	dt := &upstream.DiscoveredTool{
		Name:         "convert_test",
		UpstreamID:   "up-99",
		Description:  "Test conversion",
		InputSchema:  json.RawMessage(`{"properties":{"a":{"type":"string"}}}`),
		UpstreamName: "test-server",
		DiscoveredAt: time.Now(),
	}

	rt := toRoutableTool(dt, dt.Name)

	if rt.Name != dt.Name {
		t.Errorf("Name: got %q, want %q", rt.Name, dt.Name)
	}
	if rt.UpstreamID != dt.UpstreamID {
		t.Errorf("UpstreamID: got %q, want %q", rt.UpstreamID, dt.UpstreamID)
	}
	if rt.Description != dt.Description {
		t.Errorf("Description: got %q, want %q", rt.Description, dt.Description)
	}
	if string(rt.InputSchema) != string(dt.InputSchema) {
		t.Errorf("InputSchema: got %s, want %s", string(rt.InputSchema), string(dt.InputSchema))
	}
}

// ---------------------------------------------------------------------------
// Cache updates reflected through adapter
// ---------------------------------------------------------------------------

func TestToolCacheAdapter_ReflectsUpdates(t *testing.T) {
	cache := upstream.NewToolCache()
	adapter := NewToolCacheAdapter(cache)

	// Initially empty.
	if tools := adapter.GetAllTools(); len(tools) != 0 {
		t.Fatalf("expected 0 tools initially, got %d", len(tools))
	}

	// Add tools.
	cache.SetToolsForUpstream("up-1", []*upstream.DiscoveredTool{
		{Name: "new_tool", UpstreamID: "up-1"},
	})

	tool, ok := adapter.GetTool("new_tool")
	if !ok {
		t.Fatal("expected to find newly added tool")
	}
	if tool.Name != "new_tool" {
		t.Errorf("Name: got %q", tool.Name)
	}

	// Remove upstream.
	cache.RemoveUpstream("up-1")

	_, ok = adapter.GetTool("new_tool")
	if ok {
		t.Error("tool should be gone after RemoveUpstream")
	}
	if tools := adapter.GetAllTools(); len(tools) != 0 {
		t.Errorf("expected 0 tools after removal, got %d", len(tools))
	}
}
