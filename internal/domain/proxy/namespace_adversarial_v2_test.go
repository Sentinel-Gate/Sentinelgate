package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// ---------------------------------------------------------------------------
// Test 1: Slash injection in tool name
// ---------------------------------------------------------------------------

// TestNamespace_Adversarial_SlashInjection verifies that the namespace parser
// correctly handles a tool whose original name contains "/" (e.g. "path/traversal").
// The resolved name is "server/path/traversal" where only the first "/" is the
// namespace separator and "path/traversal" is the bare name.
func TestNamespace_Adversarial_SlashInjection(t *testing.T) {
	t.Parallel()

	// A tool named "server/path/traversal" with OriginalName="path/traversal".
	// The upstream registered a tool called "path/traversal"; the namespace prefix is "server".
	cache := newMockToolCacheReader(
		&RoutableTool{
			Name:         "server/path/traversal",
			OriginalName: "path/traversal",
			UpstreamID:   "upstream-1",
			UpstreamName: "server",
			Description:  "Slash injection tool",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
		},
	)

	upstreamResponse := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`
	manager := newMockUpstreamConnectionProvider()
	manager.addConnection("upstream-1", upstreamResponse)

	router := newTestRouter(cache, manager)

	// Call the tool with its full namespaced name.
	msg := makeToolsCallRequest(t, 1, "server/path/traversal", nil)
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Verify it was routed to upstream-1.
	conn := manager.connections["upstream-1"]
	if len(conn.writer.buf) == 0 {
		t.Fatal("expected request to be forwarded to upstream-1")
	}

	// Verify the forwarded message has the bare name "path/traversal" (not "server/path/traversal").
	written := string(conn.writer.buf)
	var parsedReq struct {
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(written)), &parsedReq); err != nil {
		t.Fatalf("written data is not valid JSON: %v", err)
	}
	if parsedReq.Params.Name != "path/traversal" {
		t.Errorf("expected forwarded tool name %q, got %q", "path/traversal", parsedReq.Params.Name)
	}

	// Verify the response is a success (not an error).
	var result struct {
		Error  *json.RawMessage `json:"error"`
		Result json.RawMessage  `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Error != nil {
		t.Errorf("expected success, got error: %s", string(*result.Error))
	}
}

// ---------------------------------------------------------------------------
// Test 2: Empty server name
// ---------------------------------------------------------------------------

// TestNamespace_Adversarial_EmptyServerName verifies behavior when UpstreamName is
// empty. If two upstreams both have UpstreamName="" and share a tool, the resolved
// name would have an unusual prefix. This test verifies GetTool handles this properly.
func TestNamespace_Adversarial_EmptyServerName(t *testing.T) {
	t.Parallel()

	// Simulate a tool where the upstream name is empty. With only one upstream owning
	// "read_file", the resolved name should remain the bare name (no namespace needed).
	cache := newMockToolCacheReader(
		&RoutableTool{
			Name:         "read_file",
			OriginalName: "read_file",
			UpstreamID:   "upstream-1",
			UpstreamName: "",
			Description:  "Read file with empty server name",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
		},
	)

	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	// tools/list should return the tool.
	msg := makeToolsListRequest(t, 1)
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	names := parseToolsListResponse(t, resp)
	if len(names) != 1 {
		t.Fatalf("expected 1 tool, got %d: %v", len(names), names)
	}
	if names[0] != "read_file" {
		t.Errorf("expected tool name %q, got %q", "read_file", names[0])
	}

	// Now test with the real ToolCache to verify empty UpstreamName namespace behavior.
	realCache := upstream.NewToolCache()
	realCache.SetToolsForUpstream("u1", []*upstream.DiscoveredTool{
		{
			Name:         "read_file",
			UpstreamID:   "u1",
			UpstreamName: "",
			Description:  "Read from empty-name upstream",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
		},
	})

	// With a single upstream, GetTool should find it by bare name.
	tool, ok := realCache.GetTool("read_file")
	if !ok {
		t.Fatal("expected read_file to be found in real cache with empty UpstreamName")
	}
	if tool.UpstreamID != "u1" {
		t.Errorf("expected UpstreamID=u1, got %q", tool.UpstreamID)
	}

	// Add a second upstream with the same empty name and same tool.
	realCache.SetToolsForUpstream("u2", []*upstream.DiscoveredTool{
		{
			Name:         "read_file",
			UpstreamID:   "u2",
			UpstreamName: "",
			Description:  "Read from second empty-name upstream",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
		},
	})

	// Now bare name should be ambiguous.
	_, okBare := realCache.GetTool("read_file")
	if okBare {
		t.Error("expected bare read_file to be ambiguous with two empty-name upstreams")
	}

	// Since both UpstreamNames are "" (collide), resolved names should include _ID suffix.
	_, ok1 := realCache.GetTool("_u1/read_file")
	if !ok1 {
		t.Error("expected _u1/read_file to exist (empty name + ID suffix)")
	}
	_, ok2 := realCache.GetTool("_u2/read_file")
	if !ok2 {
		t.Error("expected _u2/read_file to exist (empty name + ID suffix)")
	}
}

// ---------------------------------------------------------------------------
// Test 3: Duplicate server names with different IDs
// ---------------------------------------------------------------------------

// TestNamespace_Adversarial_DuplicateServerNames verifies that two tools with the
// same UpstreamName="prod" but different UpstreamIDs are both accessible.
// The ToolCache should disambiguate by adding _ID suffix.
func TestNamespace_Adversarial_DuplicateServerNames(t *testing.T) {
	t.Parallel()

	// Use the real ToolCache to test the ID-suffix disambiguation.
	realCache := upstream.NewToolCache()

	realCache.SetToolsForUpstream("id1", []*upstream.DiscoveredTool{
		{
			Name:         "read_file",
			UpstreamID:   "id1",
			UpstreamName: "prod",
			Description:  "Read from prod-id1",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
		},
	})
	realCache.SetToolsForUpstream("id2", []*upstream.DiscoveredTool{
		{
			Name:         "read_file",
			UpstreamID:   "id2",
			UpstreamName: "prod",
			Description:  "Read from prod-id2",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
		},
	})

	adapter := NewToolCacheAdapter(realCache)

	// Both tools should be accessible via the adapter (tools/list).
	allTools := adapter.GetAllTools()
	if len(allTools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(allTools))
	}

	names := make(map[string]bool)
	for _, tool := range allTools {
		names[tool.Name] = true
	}

	// With duplicate UpstreamName="prod", resolved names should be "prod_id1/read_file" and "prod_id2/read_file".
	if !names["prod_id1/read_file"] {
		t.Errorf("expected prod_id1/read_file in tools list, got %v", names)
	}
	if !names["prod_id2/read_file"] {
		t.Errorf("expected prod_id2/read_file in tools list, got %v", names)
	}

	// Verify each resolves to the correct upstream.
	tool1, ok1 := adapter.GetTool("prod_id1/read_file")
	if !ok1 {
		t.Fatal("expected prod_id1/read_file to be found")
	}
	if tool1.UpstreamID != "id1" {
		t.Errorf("prod_id1/read_file: expected UpstreamID=id1, got %q", tool1.UpstreamID)
	}

	tool2, ok2 := adapter.GetTool("prod_id2/read_file")
	if !ok2 {
		t.Fatal("expected prod_id2/read_file to be found")
	}
	if tool2.UpstreamID != "id2" {
		t.Errorf("prod_id2/read_file: expected UpstreamID=id2, got %q", tool2.UpstreamID)
	}

	// Verify routing through the router (tools/list response).
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(adapter, manager)

	msg := makeToolsListRequest(t, 1)
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	respNames := parseToolsListResponse(t, resp)
	if len(respNames) != 2 {
		t.Fatalf("expected 2 tools in response, got %d: %v", len(respNames), respNames)
	}
}

// ---------------------------------------------------------------------------
// Test 4: Rapid reconnection via ToolCache
// ---------------------------------------------------------------------------

// TestNamespace_Adversarial_RapidReconnection exercises the ToolCache through the
// ToolCacheAdapter under rapid concurrent SetToolsForUpstream and RemoveUpstream calls.
// Verifies no panic and consistent state after all goroutines complete.
// Run with -race to detect data races.
func TestNamespace_Adversarial_RapidReconnection(t *testing.T) {
	t.Parallel()

	realCache := upstream.NewToolCache()
	adapter := NewToolCacheAdapter(realCache)
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(adapter, manager)

	const goroutines = 20
	const iterations = 50

	var wg sync.WaitGroup

	// Writers: rapidly set and remove tools for the same upstream.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			uid := fmt.Sprintf("u%d", id)
			for j := 0; j < iterations; j++ {
				realCache.SetToolsForUpstream(uid, []*upstream.DiscoveredTool{
					{
						Name:         fmt.Sprintf("tool_%d", id),
						UpstreamID:   uid,
						UpstreamName: fmt.Sprintf("srv%d", id),
						Description:  "test tool",
						InputSchema:  json.RawMessage(`{"type":"object"}`),
					},
				})
				if j%3 == 0 {
					realCache.RemoveUpstream(uid)
				}
			}
		}(i)
	}

	// Readers: concurrently read tools through the router.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				msg := makeToolsListRequest(t, int64(j+1))
				_, _ = router.Intercept(context.Background(), msg)
			}
		}()
	}

	wg.Wait()

	// After all goroutines complete, the cache should be in a consistent state.
	// Each upstream either has its tool or was removed on the last iteration.
	allTools := adapter.GetAllTools()
	count := realCache.Count()
	if count != len(allTools) {
		t.Errorf("Count() = %d but GetAllTools() returned %d items", count, len(allTools))
	}

	// Verify no negative counts or panics occurred.
	if count < 0 {
		t.Errorf("Count() returned negative value: %d", count)
	}
}

// ---------------------------------------------------------------------------
// Test 5: Tool name with slash (multi-slash namespace)
// ---------------------------------------------------------------------------

// TestNamespace_Adversarial_ToolNameWithSlash verifies that when an MCP tool's
// original name contains "/" (e.g. "fs/read"), and it's namespaced to become
// "desktop/fs/read", the router correctly rewrites it back to "fs/read" when
// forwarding to the upstream.
func TestNamespace_Adversarial_ToolNameWithSlash(t *testing.T) {
	t.Parallel()

	cache := newMockToolCacheReader(
		&RoutableTool{
			Name:         "desktop/fs/read",
			OriginalName: "fs/read",
			UpstreamID:   "upstream-1",
			UpstreamName: "desktop",
			Description:  "File system read",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
		},
	)

	upstreamResponse := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"data"}]}}`
	manager := newMockUpstreamConnectionProvider()
	manager.addConnection("upstream-1", upstreamResponse)

	router := newTestRouter(cache, manager)

	// Call the tool with the full namespaced name.
	msg := makeToolsCallRequest(t, 1, "desktop/fs/read", map[string]interface{}{"path": "/tmp/x"})
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Verify the forwarded message has the bare name "fs/read".
	conn := manager.connections["upstream-1"]
	if len(conn.writer.buf) == 0 {
		t.Fatal("expected request to be forwarded to upstream-1")
	}

	written := strings.TrimSpace(string(conn.writer.buf))
	var parsedReq struct {
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(written), &parsedReq); err != nil {
		t.Fatalf("written data is not valid JSON: %v", err)
	}
	if parsedReq.Params.Name != "fs/read" {
		t.Errorf("expected forwarded tool name %q, got %q", "fs/read", parsedReq.Params.Name)
	}

	// Verify the written JSON does NOT contain the full namespaced name.
	if strings.Contains(written, `"desktop/fs/read"`) {
		t.Error("forwarded JSON should not contain the namespaced name \"desktop/fs/read\"")
	}

	// Also verify through OriginalName function behavior: only the first "/" is the separator.
	origName := upstream.OriginalName("desktop/fs/read")
	if origName != "fs/read" {
		t.Errorf("upstream.OriginalName(\"desktop/fs/read\") = %q, want %q", origName, "fs/read")
	}

	// Verify the response is a success.
	var result struct {
		Error  *json.RawMessage `json:"error"`
		Result json.RawMessage  `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Error != nil {
		t.Errorf("expected success, got error: %s", string(*result.Error))
	}
}

// ---------------------------------------------------------------------------
// Test 6: 1000 tools performance
// ---------------------------------------------------------------------------

// TestNamespace_Adversarial_1000Tools verifies that the router handles a large number
// of tools (1000) from multiple upstreams efficiently. All tools should appear in
// the tools/list response and the operation should complete in under 1 second.
func TestNamespace_Adversarial_1000Tools(t *testing.T) {
	t.Parallel()

	const toolsPerUpstream = 500
	const numUpstreams = 2

	tools := make([]*RoutableTool, 0, toolsPerUpstream*numUpstreams)
	for u := 0; u < numUpstreams; u++ {
		upstreamID := fmt.Sprintf("upstream-%d", u)
		upstreamName := fmt.Sprintf("server-%d", u)
		for i := 0; i < toolsPerUpstream; i++ {
			// Each tool has a unique name per upstream to avoid ambiguity in the mock.
			toolName := fmt.Sprintf("%s/tool_%d", upstreamName, i)
			tools = append(tools, &RoutableTool{
				Name:         toolName,
				OriginalName: fmt.Sprintf("tool_%d", i),
				UpstreamID:   upstreamID,
				UpstreamName: upstreamName,
				Description:  fmt.Sprintf("Tool %d from %s", i, upstreamName),
				InputSchema:  json.RawMessage(`{"type":"object"}`),
			})
		}
	}

	cache := newMockToolCacheReader(tools...)
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	start := time.Now()

	msg := makeToolsListRequest(t, 1)
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	elapsed := time.Since(start)

	// Parse response and verify tool count.
	var result struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	expectedCount := toolsPerUpstream * numUpstreams
	if len(result.Result.Tools) != expectedCount {
		t.Errorf("expected %d tools, got %d", expectedCount, len(result.Result.Tools))
	}

	// Verify response time is reasonable (< 1 second).
	if elapsed > 1*time.Second {
		t.Errorf("tools/list with %d tools took %v, expected < 1s", expectedCount, elapsed)
	}

	// Verify a sample of tool names from each upstream are present.
	nameSet := make(map[string]bool, len(result.Result.Tools))
	for _, tool := range result.Result.Tools {
		nameSet[tool.Name] = true
	}
	for u := 0; u < numUpstreams; u++ {
		upstreamName := fmt.Sprintf("server-%d", u)
		for _, idx := range []int{0, 249, 499} {
			name := fmt.Sprintf("%s/tool_%d", upstreamName, idx)
			if !nameSet[name] {
				t.Errorf("missing tool %q in response", name)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test 7: Concurrent discovery (tools/list)
// ---------------------------------------------------------------------------

// TestNamespace_Adversarial_ConcurrentDiscovery fires 5 goroutines that simultaneously
// call tools/list through the router. Verifies no panic, no deadlock, and each
// response contains the same tool count.
func TestNamespace_Adversarial_ConcurrentDiscovery(t *testing.T) {
	t.Parallel()

	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool_a", UpstreamID: "up-1", Description: "A", InputSchema: json.RawMessage(`{"type":"object"}`)},
		&RoutableTool{Name: "tool_b", UpstreamID: "up-1", Description: "B", InputSchema: json.RawMessage(`{"type":"object"}`)},
		&RoutableTool{Name: "tool_c", UpstreamID: "up-2", Description: "C", InputSchema: json.RawMessage(`{"type":"object"}`)},
		&RoutableTool{Name: "ns/tool_d", OriginalName: "tool_d", UpstreamID: "up-2", Description: "D", InputSchema: json.RawMessage(`{"type":"object"}`)},
		&RoutableTool{Name: "ns/tool_e", OriginalName: "tool_e", UpstreamID: "up-3", Description: "E", InputSchema: json.RawMessage(`{"type":"object"}`)},
	)
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	const goroutines = 5
	const expectedTools = 5

	type result struct {
		count int
		err   error
	}
	results := make([]result, goroutines)

	var wg sync.WaitGroup
	// Use a barrier to ensure all goroutines start as close to simultaneously as possible.
	barrier := make(chan struct{})

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-barrier // wait for all goroutines to be ready

			msg := makeToolsListRequest(t, int64(idx+1))
			resp, err := router.Intercept(context.Background(), msg)
			if err != nil {
				results[idx] = result{err: err}
				return
			}
			if resp == nil {
				results[idx] = result{err: fmt.Errorf("nil response")}
				return
			}

			names := parseToolsListResponse(t, resp)
			results[idx] = result{count: len(names)}
		}(i)
	}

	// Release all goroutines at once.
	close(barrier)

	// Wait with a timeout to detect deadlocks.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines completed.
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock detected: concurrent tools/list did not complete within 10 seconds")
	}

	// Verify all goroutines got the same tool count and no errors.
	for i, r := range results {
		if r.err != nil {
			t.Errorf("goroutine %d returned error: %v", i, r.err)
			continue
		}
		if r.count != expectedTools {
			t.Errorf("goroutine %d got %d tools, expected %d", i, r.count, expectedTools)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers (local to this file)
// ---------------------------------------------------------------------------

