package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// =============================================================================
// Namespace E2E Tests — Full Pipeline with Real ToolCache + ToolCacheAdapter
// =============================================================================
//
// These tests exercise the complete namespace pipeline using REAL components:
//   - upstream.ToolCache (auto-namespacing logic)
//   - proxy.ToolCacheAdapter (DiscoveredTool → RoutableTool bridge)
//   - proxy.UpstreamRouter (tools/list, tools/call routing)
//
// Mock upstreams provide canned JSON-RPC responses via channel-based connections.

// =============================================================================
// Test 1: Two servers with conflicting tool names
// =============================================================================

// TestNamespace_FullPipeline_TwoServersConflict verifies the end-to-end namespace
// pipeline when two upstreams register tools with the same bare names.
//
// Expected behavior:
//   - tools/list returns 4 tools with namespace prefixes (desktop/read_file, etc.)
//   - tools/call with a namespaced name routes to the correct upstream
//   - tools/call with the bare name returns an "ambiguous" error with suggestions
func TestNamespace_FullPipeline_TwoServersConflict(t *testing.T) {
	// --- Setup: real ToolCache with 2 upstreams sharing tool names ---
	toolCache := upstream.NewToolCacheWithLogger(discardLogger())

	toolCache.SetToolsForUpstream("up-desktop", []*upstream.DiscoveredTool{
		{
			Name:         "read_file",
			UpstreamID:   "up-desktop",
			UpstreamName: "desktop",
			Description:  "Read file from desktop",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`),
			DiscoveredAt: time.Now(),
		},
		{
			Name:         "write_file",
			UpstreamID:   "up-desktop",
			UpstreamName: "desktop",
			Description:  "Write file to desktop",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}}}`),
			DiscoveredAt: time.Now(),
		},
	})

	toolCache.SetToolsForUpstream("up-train", []*upstream.DiscoveredTool{
		{
			Name:         "read_file",
			UpstreamID:   "up-train",
			UpstreamName: "train",
			Description:  "Read file from train",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`),
			DiscoveredAt: time.Now(),
		},
		{
			Name:         "write_file",
			UpstreamID:   "up-train",
			UpstreamName: "train",
			Description:  "Write file to train",
			InputSchema:  json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}}}`),
			DiscoveredAt: time.Now(),
		},
	})

	// Bridge the real ToolCache to the proxy's ToolCacheReader interface.
	adapter := proxy.NewToolCacheAdapter(toolCache)

	// Mock connections: each upstream returns a distinct response so we can
	// verify routing correctness.
	connProvider := &nsTestConnProvider{
		connections: map[string]*nsTestConn{
			"up-desktop": newNSTestConn(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"desktop-result"}]}}`),
			"up-train":   newNSTestConn(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"train-result"}]}}`),
		},
	}

	router := proxy.NewUpstreamRouter(adapter, connProvider, discardLogger())

	// --- Subtest: tools/list returns 4 namespaced tools ---
	t.Run("ToolsListReturns4NamespacedTools", func(t *testing.T) {
		msg := buildRegressionMessage(t, "tools/list", 1, nil, nil)
		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("tools/list error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected response, got nil")
		}

		tools := parseToolNames(t, resp.Raw)
		if len(tools) != 4 {
			t.Fatalf("expected 4 namespaced tools, got %d: %v", len(tools), tools)
		}

		// Verify all expected namespaced names are present.
		expected := []string{
			"desktop/read_file",
			"desktop/write_file",
			"train/read_file",
			"train/write_file",
		}
		sort.Strings(tools)
		sort.Strings(expected)
		for i, want := range expected {
			if tools[i] != want {
				t.Errorf("tool[%d]: got %q, want %q", i, tools[i], want)
			}
		}
	})

	// --- Subtest: tools/call "desktop/read_file" routes to desktop upstream ---
	t.Run("ToolsCallRoutesToDesktop", func(t *testing.T) {
		// Reset connections so we can verify which upstream received the request.
		connProvider.connections["up-desktop"] = newNSTestConn(
			`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"desktop-data"}]}}`)
		connProvider.connections["up-train"] = newNSTestConn(
			`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"train-data"}]}}`)

		msg := buildRegressionMessage(t, "tools/call", 2, map[string]interface{}{
			"name":      "desktop/read_file",
			"arguments": map[string]interface{}{"path": "/tmp/test.txt"},
		}, nil)

		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("tools/call error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected response, got nil")
		}

		// Verify the response came from desktop upstream.
		text := extractResponseText(t, resp.Raw)
		if text != "desktop-data" {
			t.Errorf("expected response from desktop upstream, got %q", text)
		}

		// Verify that the upstream received the bare name, not the namespaced name.
		written := string(connProvider.connections["up-desktop"].writer.buf)
		if strings.Contains(written, "desktop/read_file") {
			t.Error("forwarded message should NOT contain namespaced name \"desktop/read_file\"")
		}
		if !strings.Contains(written, `"read_file"`) {
			t.Error("forwarded message should contain bare name \"read_file\"")
		}

		// Verify train upstream was NOT written to.
		if len(connProvider.connections["up-train"].writer.buf) != 0 {
			t.Error("train upstream should NOT have received any data")
		}
	})

	// --- Subtest: tools/call "train/write_file" routes to train upstream ---
	t.Run("ToolsCallRoutesToTrain", func(t *testing.T) {
		connProvider.connections["up-desktop"] = newNSTestConn(
			`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"desktop-data"}]}}`)
		connProvider.connections["up-train"] = newNSTestConn(
			`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"train-write-ok"}]}}`)

		msg := buildRegressionMessage(t, "tools/call", 3, map[string]interface{}{
			"name":      "train/write_file",
			"arguments": map[string]interface{}{"path": "/tmp/out.txt", "content": "hello"},
		}, nil)

		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("tools/call error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected response, got nil")
		}

		text := extractResponseText(t, resp.Raw)
		if text != "train-write-ok" {
			t.Errorf("expected response from train upstream, got %q", text)
		}

		// Verify desktop upstream was NOT written to.
		if len(connProvider.connections["up-desktop"].writer.buf) != 0 {
			t.Error("desktop upstream should NOT have received any data")
		}
	})

	// --- Subtest: tools/call bare "read_file" → ambiguous error ---
	t.Run("BareNameAmbiguousError", func(t *testing.T) {
		msg := buildRegressionMessage(t, "tools/call", 4, map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{},
		}, nil)

		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("tools/call error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected error response, got nil")
		}

		errResp := parseErrorResponse(t, resp.Raw)
		if errResp.Code != proxy.ErrCodeMethodNotFound {
			t.Errorf("expected error code %d, got %d", proxy.ErrCodeMethodNotFound, errResp.Code)
		}
		if !strings.Contains(errResp.Message, "ambiguous") {
			t.Errorf("expected 'ambiguous' in error message, got %q", errResp.Message)
		}
		// Verify suggestions include both namespaced alternatives.
		if !strings.Contains(errResp.Message, "desktop/read_file") {
			t.Errorf("expected suggestion 'desktop/read_file' in error, got %q", errResp.Message)
		}
		if !strings.Contains(errResp.Message, "train/read_file") {
			t.Errorf("expected suggestion 'train/read_file' in error, got %q", errResp.Message)
		}
	})
}

// =============================================================================
// Test 2: Single server — no namespace needed (backward compat)
// =============================================================================

// TestNamespace_FullPipeline_SingleServer verifies that with only one upstream,
// tools are exposed with their bare names (no namespace prefix). This confirms
// zero regression from pre-namespace behavior.
func TestNamespace_FullPipeline_SingleServer(t *testing.T) {
	toolCache := upstream.NewToolCacheWithLogger(discardLogger())

	toolCache.SetToolsForUpstream("up-desktop", []*upstream.DiscoveredTool{
		{
			Name:         "read_file",
			UpstreamID:   "up-desktop",
			UpstreamName: "desktop",
			Description:  "Read a file",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
			DiscoveredAt: time.Now(),
		},
		{
			Name:         "write_file",
			UpstreamID:   "up-desktop",
			UpstreamName: "desktop",
			Description:  "Write a file",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
			DiscoveredAt: time.Now(),
		},
	})

	adapter := proxy.NewToolCacheAdapter(toolCache)

	connProvider := &nsTestConnProvider{
		connections: map[string]*nsTestConn{
			"up-desktop": newNSTestConn(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"file-data"}]}}`),
		},
	}

	router := proxy.NewUpstreamRouter(adapter, connProvider, discardLogger())

	// --- Subtest: tools/list returns bare names (no namespace) ---
	t.Run("ToolsListReturnsBareNames", func(t *testing.T) {
		msg := buildRegressionMessage(t, "tools/list", 1, nil, nil)
		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("tools/list error: %v", err)
		}

		tools := parseToolNames(t, resp.Raw)
		if len(tools) != 2 {
			t.Fatalf("expected 2 tools, got %d: %v", len(tools), tools)
		}

		// Verify no namespace prefixes.
		sort.Strings(tools)
		expected := []string{"read_file", "write_file"}
		for i, want := range expected {
			if tools[i] != want {
				t.Errorf("tool[%d]: got %q, want %q (should NOT have namespace)", i, tools[i], want)
			}
		}

		// Extra check: no "/" in any tool name.
		for _, name := range tools {
			if strings.Contains(name, "/") {
				t.Errorf("tool %q should NOT have a namespace prefix with single upstream", name)
			}
		}
	})

	// --- Subtest: tools/call bare name works (backward compat) ---
	t.Run("BareNameCallWorks", func(t *testing.T) {
		connProvider.connections["up-desktop"] = newNSTestConn(
			`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"read-ok"}]}}`)

		msg := buildRegressionMessage(t, "tools/call", 2, map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/tmp/a.txt"},
		}, nil)

		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("tools/call error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected response, got nil")
		}

		text := extractResponseText(t, resp.Raw)
		if text != "read-ok" {
			t.Errorf("expected 'read-ok', got %q", text)
		}

		// Verify no error in response.
		errResp := parseErrorResponseOptional(resp.Raw)
		if errResp != nil {
			t.Errorf("expected success, got error: code=%d message=%q", errResp.Code, errResp.Message)
		}
	})
}

// =============================================================================
// Test 3: Dynamic conflict resolution (add/remove upstream)
// =============================================================================

// TestNamespace_FullPipeline_DynamicConflictResolution verifies that namespace
// prefixes are dynamically activated when a conflicting upstream is added, and
// deactivated when the conflicting upstream is removed.
//
// Lifecycle:
//  1. Single upstream "desktop" → bare names (no namespace)
//  2. Add upstream "train" with same tool names → namespace activated
//  3. Remove upstream "train" → namespace deactivated, bare names restored
func TestNamespace_FullPipeline_DynamicConflictResolution(t *testing.T) {
	toolCache := upstream.NewToolCacheWithLogger(discardLogger())
	adapter := proxy.NewToolCacheAdapter(toolCache)

	connProvider := &nsTestConnProvider{
		connections: map[string]*nsTestConn{
			"up-desktop": newNSTestConn(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"desktop-ok"}]}}`),
		},
	}

	router := proxy.NewUpstreamRouter(adapter, connProvider, discardLogger())

	// --- Phase 1: Single upstream → bare names ---
	t.Run("Phase1_SingleUpstream_BareNames", func(t *testing.T) {
		toolCache.SetToolsForUpstream("up-desktop", []*upstream.DiscoveredTool{
			{
				Name:         "read_file",
				UpstreamID:   "up-desktop",
				UpstreamName: "desktop",
				Description:  "Read file",
				InputSchema:  json.RawMessage(`{"type":"object"}`),
				DiscoveredAt: time.Now(),
			},
			{
				Name:         "list_dir",
				UpstreamID:   "up-desktop",
				UpstreamName: "desktop",
				Description:  "List directory",
				InputSchema:  json.RawMessage(`{"type":"object"}`),
				DiscoveredAt: time.Now(),
			},
		})

		msg := buildRegressionMessage(t, "tools/list", 1, nil, nil)
		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("Phase1 tools/list error: %v", err)
		}

		tools := parseToolNames(t, resp.Raw)
		if len(tools) != 2 {
			t.Fatalf("Phase1: expected 2 tools, got %d: %v", len(tools), tools)
		}

		// No namespace prefix for single upstream.
		for _, name := range tools {
			if strings.Contains(name, "/") {
				t.Errorf("Phase1: tool %q should NOT have namespace prefix", name)
			}
		}
	})

	// --- Phase 2: Add conflicting upstream → namespace activated ---
	t.Run("Phase2_ConflictAdded_NamespaceActivated", func(t *testing.T) {
		// Add second upstream with a conflicting tool name ("read_file").
		// "list_dir" is unique to desktop, but "read_file" conflicts.
		toolCache.SetToolsForUpstream("up-train", []*upstream.DiscoveredTool{
			{
				Name:         "read_file",
				UpstreamID:   "up-train",
				UpstreamName: "train",
				Description:  "Read file from train",
				InputSchema:  json.RawMessage(`{"type":"object"}`),
				DiscoveredAt: time.Now(),
			},
		})

		connProvider.connections["up-train"] = newNSTestConn(
			`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"train-ok"}]}}`)

		msg := buildRegressionMessage(t, "tools/list", 2, nil, nil)
		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("Phase2 tools/list error: %v", err)
		}

		tools := parseToolNames(t, resp.Raw)
		// Expected: "desktop/read_file", "train/read_file", "list_dir" (unique, no prefix)
		if len(tools) != 3 {
			t.Fatalf("Phase2: expected 3 tools, got %d: %v", len(tools), tools)
		}

		toolSet := make(map[string]bool)
		for _, name := range tools {
			toolSet[name] = true
		}

		// "read_file" is ambiguous → both get namespace prefixes.
		if !toolSet["desktop/read_file"] {
			t.Error("Phase2: expected 'desktop/read_file' (namespaced)")
		}
		if !toolSet["train/read_file"] {
			t.Error("Phase2: expected 'train/read_file' (namespaced)")
		}
		// "list_dir" is unique → bare name.
		if !toolSet["list_dir"] {
			t.Error("Phase2: expected 'list_dir' (unique, bare)")
		}
		// Bare "read_file" should NOT be present.
		if toolSet["read_file"] {
			t.Error("Phase2: bare 'read_file' should NOT appear when ambiguous")
		}
	})

	// --- Phase 3: Remove conflicting upstream → namespace deactivated ---
	t.Run("Phase3_ConflictRemoved_BareNamesRestored", func(t *testing.T) {
		toolCache.RemoveUpstream("up-train")

		msg := buildRegressionMessage(t, "tools/list", 3, nil, nil)
		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("Phase3 tools/list error: %v", err)
		}

		tools := parseToolNames(t, resp.Raw)
		if len(tools) != 2 {
			t.Fatalf("Phase3: expected 2 tools, got %d: %v", len(tools), tools)
		}

		// After removing train, no conflicts remain → bare names restored.
		for _, name := range tools {
			if strings.Contains(name, "/") {
				t.Errorf("Phase3: tool %q should NOT have namespace prefix after conflict removal", name)
			}
		}

		toolSet := make(map[string]bool)
		for _, name := range tools {
			toolSet[name] = true
		}
		if !toolSet["read_file"] {
			t.Error("Phase3: expected bare 'read_file' restored")
		}
		if !toolSet["list_dir"] {
			t.Error("Phase3: expected bare 'list_dir' restored")
		}
	})
}

// =============================================================================
// Helpers — mock connection provider for namespace tests
// =============================================================================

// nsTestConnProvider implements proxy.UpstreamConnectionProvider for namespace tests.
type nsTestConnProvider struct {
	connections map[string]*nsTestConn
}

// nsTestConn holds a mock upstream connection with a writer and line channel.
type nsTestConn struct {
	writer *nsTestWriter
	lineCh chan []byte
}

// nsTestWriter captures bytes written to the upstream's stdin.
type nsTestWriter struct {
	buf []byte
}

func (w *nsTestWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *nsTestWriter) Close() error {
	return nil
}

// newNSTestConn creates a mock connection pre-loaded with a single JSON-RPC response.
func newNSTestConn(responseJSON string) *nsTestConn {
	ch := make(chan []byte, 1)
	ch <- []byte(responseJSON)
	return &nsTestConn{
		writer: &nsTestWriter{},
		lineCh: ch,
	}
}

func (p *nsTestConnProvider) GetConnection(upstreamID string) (io.WriteCloser, <-chan []byte, error) {
	conn, ok := p.connections[upstreamID]
	if !ok {
		return nil, nil, fmt.Errorf("upstream %s not connected", upstreamID)
	}
	return conn.writer, conn.lineCh, nil
}

func (p *nsTestConnProvider) AllConnected() bool {
	return len(p.connections) > 0
}

// =============================================================================
// Helpers — response parsing
// =============================================================================

// discardLogger returns a logger that discards all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// parseToolNames extracts tool names from a tools/list JSON-RPC response.
func parseToolNames(t *testing.T, raw []byte) []string {
	t.Helper()
	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("failed to parse tools/list response: %v\nraw: %s", err, string(raw))
	}
	names := make([]string, len(resp.Result.Tools))
	for i, tool := range resp.Result.Tools {
		names[i] = tool.Name
	}
	return names
}

// extractResponseText extracts the first text content from a tools/call JSON-RPC response.
func extractResponseText(t *testing.T, raw []byte) string {
	t.Helper()
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("failed to parse tools/call response: %v\nraw: %s", err, string(raw))
	}
	if len(resp.Result.Content) == 0 {
		t.Fatal("no content in tools/call response")
	}
	return resp.Result.Content[0].Text
}

// nsErrorResponse holds parsed JSON-RPC error fields.
type nsErrorResponse struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

// parseErrorResponse extracts the error from a JSON-RPC error response.
// Fails the test if the response is not an error.
func parseErrorResponse(t *testing.T, raw []byte) nsErrorResponse {
	t.Helper()
	var resp struct {
		Error *nsErrorResponse `json:"error"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("failed to parse error response: %v\nraw: %s", err, string(raw))
	}
	if resp.Error == nil {
		t.Fatalf("expected error response, got success\nraw: %s", string(raw))
	}
	return *resp.Error
}

// parseErrorResponseOptional extracts the error from a JSON-RPC response,
// returning nil if the response is a success.
func parseErrorResponseOptional(raw []byte) *nsErrorResponse {
	var resp struct {
		Error *nsErrorResponse `json:"error"`
	}
	if json.Unmarshal(raw, &resp) != nil {
		return nil
	}
	return resp.Error
}
