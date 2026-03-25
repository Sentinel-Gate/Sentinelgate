package proxy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// --- mockNamespaceFilter ---

// mockNamespaceFilter implements NamespaceFilter for adversarial testing.
// visible maps toolName -> role -> bool. Tools not in the map are visible by default.
type mockNamespaceFilter struct {
	visible map[string]map[string]bool // toolName -> role -> visible
}

func (f *mockNamespaceFilter) IsToolVisible(toolName string, roles []string) bool {
	toolRoles, ok := f.visible[toolName]
	if !ok {
		return true // not configured = visible
	}
	for _, r := range roles {
		if toolRoles[r] {
			return true
		}
	}
	return false
}

// --- helpers ---

// makeToolsListRequestWithSession creates a tools/list request with a session attached.
func makeToolsListRequestWithSession(t *testing.T, id int64, roles []auth.Role) *mcp.Message {
	t.Helper()
	msg := makeToolsListRequest(t, id)
	msg.Session = &session.Session{
		ID:           "sess-test",
		IdentityID:   "id-test",
		IdentityName: "test-identity",
		Roles:        roles,
	}
	return msg
}

// makeToolsCallRequestWithSession creates a tools/call request with a session attached.
func makeToolsCallRequestWithSession(t *testing.T, id int64, toolName string, args map[string]interface{}, roles []auth.Role) *mcp.Message {
	t.Helper()
	msg := makeToolsCallRequest(t, id, toolName, args)
	msg.Session = &session.Session{
		ID:           "sess-test",
		IdentityID:   "id-test",
		IdentityName: "test-identity",
		Roles:        roles,
	}
	return msg
}

// parseToolsListResponse parses a tools/list JSON-RPC response and returns the tool names.
func parseToolsListResponse(t *testing.T, resp *mcp.Message) []string {
	t.Helper()
	var result struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse tools/list response: %v", err)
	}
	names := make([]string, len(result.Result.Tools))
	for i, tool := range result.Result.Tools {
		names[i] = tool.Name
	}
	return names
}

// parseErrorResponse parses a JSON-RPC error response.
func parseErrorResponse(t *testing.T, resp *mcp.Message) (int64, string) {
	t.Helper()
	var result struct {
		Error *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	if result.Error == nil {
		t.Fatal("expected error in response, got success")
	}
	return result.Error.Code, result.Error.Message
}

// --- Tests ---

// TestNamespaceFilter_ToolsListFiltered (3C.1) verifies that tools/list correctly
// filters out tools that are not visible to the caller's roles when a namespace
// filter is configured.
func TestNamespaceFilter_ToolsListFiltered(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool_a", UpstreamID: "upstream-1", Description: "Tool A"},
		&RoutableTool{Name: "secret_tool", UpstreamID: "upstream-2", Description: "Secret tool"},
	)
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	// Configure namespace filter: secret_tool is NOT visible to "guest" role.
	filter := &mockNamespaceFilter{
		visible: map[string]map[string]bool{
			"secret_tool": {
				"admin": true,
				"guest": false,
			},
		},
	}
	router.SetNamespaceFilter(filter)

	// tools/list with session.Roles=["guest"] should only return tool_a.
	msg := makeToolsListRequestWithSession(t, 1, []auth.Role{"guest"})
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	names := parseToolsListResponse(t, resp)
	if len(names) != 1 {
		t.Fatalf("expected 1 tool, got %d: %v", len(names), names)
	}
	if names[0] != "tool_a" {
		t.Errorf("expected tool_a, got %q", names[0])
	}
}

// TestNamespaceFilter_ToolsCallBypassed (3C.2) exposes BUG B1: handleToolsCall
// does NOT apply the namespace filter. A client knowing a hidden tool name can
// invoke it directly via tools/call, even though tools/list correctly hides it.
func TestNamespaceFilter_ToolsCallBypassed(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool_a", UpstreamID: "upstream-1", Description: "Tool A"},
		&RoutableTool{Name: "secret_tool", UpstreamID: "upstream-2", Description: "Secret tool"},
	)

	// Set up upstream connections so that if the call goes through, it has a response.
	manager := newMockUpstreamConnectionProvider()
	manager.addConnection("upstream-1", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`)
	manager.addConnection("upstream-2", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"secret data"}]}}`)

	router := newTestRouter(cache, manager)

	// Configure namespace filter: secret_tool is NOT visible to "guest" role.
	filter := &mockNamespaceFilter{
		visible: map[string]map[string]bool{
			"secret_tool": {
				"admin": true,
				"guest": false,
			},
		},
	}
	router.SetNamespaceFilter(filter)

	// tools/call secret_tool with session.Roles=["guest"] should be DENIED.
	msg := makeToolsCallRequestWithSession(t, 1, "secret_tool", nil, []auth.Role{"guest"})
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// After fix: should get an error response with ErrCodeMethodNotFound.
	code, errMsg := parseErrorResponse(t, resp)
	if code != ErrCodeMethodNotFound {
		t.Errorf("expected error code %d, got %d", ErrCodeMethodNotFound, code)
	}
	if !strings.Contains(errMsg, "Tool not found") {
		t.Errorf("expected error message to contain 'Tool not found', got %q", errMsg)
	}
}

// TestNamespaceFilter_EmptyRolesSeesAll (3C.3) exposes BUG B2: when
// len(callerRoles) == 0, the namespace filter is skipped entirely, allowing
// identities with no roles to see ALL tools (bypassing namespace isolation).
func TestNamespaceFilter_EmptyRolesSeesAll(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool_a", UpstreamID: "upstream-1", Description: "Tool A"},
		&RoutableTool{Name: "secret_tool", UpstreamID: "upstream-2", Description: "Secret tool"},
	)
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	// Configure namespace filter: secret_tool is only visible to "admin".
	filter := &mockNamespaceFilter{
		visible: map[string]map[string]bool{
			"secret_tool": {
				"admin": true,
				// no other roles can see it
			},
		},
	}
	router.SetNamespaceFilter(filter)

	// Session with empty roles — should NOT see secret_tool after fix.
	msg := makeToolsListRequestWithSession(t, 1, []auth.Role{})
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	names := parseToolsListResponse(t, resp)

	// After fix: empty roles should see NO tools when namespace filter is active
	// and the tool has role restrictions. tool_a has no restrictions (not in the
	// filter map) so it should still be visible. secret_tool should be hidden
	// because empty roles cannot match any required role.
	// BUT with the fix, len(callerRoles) == 0 means ALL tools are hidden when
	// namespace filter is active (deny-by-default for no-role identities).
	if len(names) != 0 {
		t.Errorf("expected 0 tools for empty-roles identity (deny by default), got %d: %v", len(names), names)
	}
}

// TestNamespaceFilter_ErrorMessageNoToolLeak (3C.4) verifies that error messages
// for non-existent tools do not leak information about tool existence or upstream
// topology. The error should say "Tool not found: xxx", not reveal which upstream
// the tool belongs to or whether it exists but is hidden.
func TestNamespaceFilter_ErrorMessageNoToolLeak(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool_a", UpstreamID: "upstream-1", Description: "Tool A"},
	)
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	// Configure a namespace filter (to ensure the error path doesn't leak filter info).
	filter := &mockNamespaceFilter{
		visible: map[string]map[string]bool{},
	}
	router.SetNamespaceFilter(filter)

	// Call a non-existent tool.
	msg := makeToolsCallRequestWithSession(t, 1, "nonexistent_tool", nil, []auth.Role{"guest"})
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	code, errMsg := parseErrorResponse(t, resp)

	// Verify error code.
	if code != ErrCodeMethodNotFound {
		t.Errorf("expected error code %d, got %d", ErrCodeMethodNotFound, code)
	}

	// Verify error message does NOT leak upstream info.
	if strings.Contains(errMsg, "upstream") {
		t.Errorf("error message leaks upstream info: %q", errMsg)
	}
	if strings.Contains(errMsg, "visible") {
		t.Errorf("error message leaks visibility info: %q", errMsg)
	}
	if strings.Contains(errMsg, "hidden") {
		t.Errorf("error message leaks hidden status: %q", errMsg)
	}

	// Verify it contains the tool name for debugging purposes.
	if !strings.Contains(errMsg, "nonexistent_tool") {
		t.Errorf("expected error message to contain tool name, got %q", errMsg)
	}
}
