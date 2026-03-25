package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// --- helpers ---

// makeNotificationMessage creates a JSON-RPC notification (no "id" field) with
// the given method. Notifications have Direction = ClientToServer.
func makeNotificationMessage(t *testing.T, method string) *mcp.Message {
	t.Helper()
	raw := fmt.Sprintf(`{"jsonrpc":"2.0","method":%q}`, method)
	// Decode via the SDK so that msg.Method() works.
	req := &jsonrpc.Request{
		Method: method,
		// ID is zero-value (nil) — this is a notification.
	}
	return &mcp.Message{
		Raw:       []byte(raw),
		Direction: mcp.ClientToServer,
		Decoded:   req,
	}
}

// addConnectionMultiLine sets up a mock upstream connection that will return
// multiple lines (notifications + final response) on the read channel.
func addConnectionMultiLine(m *mockUpstreamConnectionProvider, upstreamID string, lines []string) {
	ch := make(chan []byte, len(lines))
	for _, line := range lines {
		ch <- []byte(line)
	}
	m.connections[upstreamID] = &mockConnection{
		writer: &mockWriteCloser{},
		lineCh: ch,
	}
}

// --- 1C.1: TestNotificationFlood_DoSGuard ---

// TestNotificationFlood_DoSGuard verifies that the router's Intercept method
// blocks client-sent notifications (messages with no "id" and method != "initialize")
// from reaching upstreams. This prevents a DoS attack where a flood of
// notifications could block per-upstream mutexes for 30 seconds each.
// Per JSON-RPC 2.0 Section 4.1, notifications must not receive responses,
// so the guard returns (nil, nil) to silently drop them.
func TestNotificationFlood_DoSGuard(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool-a", UpstreamID: "upstream-1", Description: "Tool A"},
	)
	manager := newMockUpstreamConnectionProvider()
	manager.addConnection("upstream-1", `{"jsonrpc":"2.0","id":1,"result":{}}`)

	router := newTestRouter(cache, manager)

	// Send 100 notifications — none should reach upstream, none should get responses.
	for i := 0; i < 100; i++ {
		method := fmt.Sprintf("notifications/progress_%d", i)
		msg := makeNotificationMessage(t, method)

		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("notification %d: unexpected error: %v", i, err)
		}
		if resp != nil {
			t.Fatalf("notification %d: expected nil response (JSON-RPC 2.0: server must not reply to notifications), got response", i)
		}
	}

	// Verify nothing was written to upstream.
	conn := manager.connections["upstream-1"]
	if len(conn.writer.buf) != 0 {
		t.Errorf("expected no bytes written to upstream, got %d bytes", len(conn.writer.buf))
	}
}

// --- 1C.2: TestNotificationInterleaving_Ordering (exposes BUG B6) ---

// TestNotificationInterleaving_Ordering_BoundaryOK verifies that forwardToUpstream
// can skip up to 9 notifications (maxAttempts=10, 9 notifications + 1 response = 10
// iterations) and still return the real response.
func TestNotificationInterleaving_Ordering_BoundaryOK(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool-ok", UpstreamID: "upstream-1", Description: "OK tool"},
	)
	manager := newMockUpstreamConnectionProvider()

	// 9 notifications + 1 real response = 10 reads. Should succeed.
	lines := make([]string, 0, 10)
	for i := 0; i < 9; i++ {
		lines = append(lines, fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"token":"t","progress":%d}}`, i))
	}
	lines = append(lines, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}`)

	addConnectionMultiLine(manager, "upstream-1", lines)
	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "tool-ok", nil)
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Verify we got the real response.
	var parsed struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(parsed.Result.Content) == 0 || parsed.Result.Content[0].Text != "hello" {
		t.Errorf("expected response text 'hello', got %+v", parsed.Result)
	}
}

// TestNotificationInterleaving_Ordering_BugB6 verifies that forwardToUpstream
// can handle any number of notifications before the real response. Previously
// (BUG B6), the loop had maxAttempts=10 which caused it to fail when exactly
// 10 notifications preceded the response. The fix removed the attempt limit
// and uses only the 30s timeout as a guard.
func TestNotificationInterleaving_Ordering_BugB6(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool-b6", UpstreamID: "upstream-1", Description: "B6 tool"},
	)
	manager := newMockUpstreamConnectionProvider()

	// 10 notifications + 1 real response. After the B6 fix, this should succeed.
	lines := make([]string, 0, 11)
	for i := 0; i < 10; i++ {
		lines = append(lines, fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"token":"t","progress":%d}}`, i))
	}
	lines = append(lines, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"not lost anymore"}]}}`)

	addConnectionMultiLine(manager, "upstream-1", lines)
	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "tool-b6", nil)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("expected no error after B6 fix, got: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	var parsed struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(parsed.Result.Content) == 0 || parsed.Result.Content[0].Text != "not lost anymore" {
		t.Errorf("expected response text 'not lost anymore', got %+v", parsed.Result)
	}
}

// TestNotificationInterleaving_Ordering_ManyNotifications verifies that even a large
// number of notifications (50) before the response is handled correctly after the B6 fix.
func TestNotificationInterleaving_Ordering_ManyNotifications(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool-many", UpstreamID: "upstream-1", Description: "Many notifications tool"},
	)
	manager := newMockUpstreamConnectionProvider()

	// 50 notifications + 1 real response.
	lines := make([]string, 0, 51)
	for i := 0; i < 50; i++ {
		lines = append(lines, fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"token":"t","progress":%d}}`, i))
	}
	lines = append(lines, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"survived 50 notifications"}]}}`)

	addConnectionMultiLine(manager, "upstream-1", lines)
	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "tool-many", nil)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("expected no error with 50 notifications, got: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	var parsed struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(parsed.Result.Content) == 0 || parsed.Result.Content[0].Text != "survived 50 notifications" {
		t.Errorf("expected response text 'survived 50 notifications', got %+v", parsed.Result)
	}
}

// --- 1C.3: TestNotification_MethodWithID ---

// TestNotification_MethodWithID verifies that a message with both "method" and "id"
// is NOT treated as a notification by forwardToUpstream's skip logic. In JSON-RPC 2.0,
// a message with an "id" is a request (or response), not a notification — even if it
// has a "method" field. The notification skip only applies when id is absent.
func TestNotification_MethodWithID(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool-mid", UpstreamID: "upstream-1", Description: "Method with ID tool"},
	)
	manager := newMockUpstreamConnectionProvider()

	// The upstream returns a message that has both "method" and "id".
	// This looks like a server-to-client request (e.g., sampling), not a notification.
	// forwardToUpstream should treat it as the response (not skip it).
	methodWithID := `{"jsonrpc":"2.0","id":99,"method":"sampling/createMessage","params":{}}`

	addConnectionMultiLine(manager, "upstream-1", []string{methodWithID})
	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "tool-mid", nil)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// The message should have been accepted (not skipped) and the ID remapped
	// to the client's request ID (1).
	var parsed struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	if err := json.Unmarshal(resp.Raw, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// ID should be remapped to client's original ID (1).
	var respID float64
	if err := json.Unmarshal(parsed.ID, &respID); err != nil {
		t.Fatalf("failed to parse response ID: %v", err)
	}
	if respID != 1 {
		t.Errorf("expected ID to be remapped to 1, got %v", respID)
	}
}

// --- 1C.4: TestNotification_ExplicitNullIDvsAbsent ---

// TestNotification_ExplicitNullIDvsAbsent documents the difference between
// {"id":null} and an absent "id" field in how forwardToUpstream's notification
// skip logic handles them.
//
// - Absent "id":  json.Unmarshal sets peek.ID = nil → notification is skipped
// - Explicit null: json.Unmarshal sets peek.ID = json.RawMessage("null") → NOT nil → not skipped
//
// This is correct JSON-RPC 2.0 behavior: explicit null means "I'm a request/response
// with an unset ID" (invalid but not a notification), while absent means notification.
func TestNotification_ExplicitNullIDvsAbsent(t *testing.T) {
	t.Run("absent_id_is_notification", func(t *testing.T) {
		// When "id" is absent, peek.ID == nil → notification → skipped.
		absentID := `{"jsonrpc":"2.0","method":"notifications/progress"}`

		var peek struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal([]byte(absentID), &peek); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if peek.ID != nil {
			t.Errorf("expected nil for absent id, got %s", string(peek.ID))
		}
		if peek.Method != "notifications/progress" {
			t.Errorf("expected method 'notifications/progress', got %q", peek.Method)
		}

		// This combination (ID nil + Method non-empty) triggers the skip.
		isNotification := peek.ID == nil && peek.Method != ""
		if !isNotification {
			t.Error("absent id with method should be classified as notification")
		}
	})

	t.Run("explicit_null_id_is_not_notification", func(t *testing.T) {
		// When "id" is explicitly null, peek.ID = json.RawMessage("null") → NOT nil.
		explicitNull := `{"jsonrpc":"2.0","method":"notifications/progress","id":null}`

		var peek struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal([]byte(explicitNull), &peek); err != nil {
			t.Fatalf("unmarshal failed: %v", err)
		}

		if peek.ID == nil {
			t.Error("expected non-nil for explicit null id")
		}
		if string(peek.ID) != "null" {
			t.Errorf("expected raw value 'null', got %s", string(peek.ID))
		}

		// This combination (ID not nil) means NOT a notification → not skipped.
		isNotification := peek.ID == nil && peek.Method != ""
		if isNotification {
			t.Error("explicit null id should NOT be classified as notification")
		}
	})

	t.Run("explicit_null_id_accepted_by_forwardToUpstream", func(t *testing.T) {
		// Verify the end-to-end behavior: a message with explicit null id and a method
		// is treated as a response (not skipped) by forwardToUpstream.
		cache := newMockToolCacheReader(
			&RoutableTool{Name: "tool-null", UpstreamID: "upstream-1", Description: "Null ID tool"},
		)
		manager := newMockUpstreamConnectionProvider()

		// Upstream sends a message with explicit null id — should be accepted, not skipped.
		explicitNullResponse := `{"jsonrpc":"2.0","id":null,"method":"notifications/progress","result":{}}`
		addConnectionMultiLine(manager, "upstream-1", []string{explicitNullResponse})

		router := newTestRouter(cache, manager)
		msg := makeToolsCallRequest(t, 1, "tool-null", nil)
		resp, err := router.Intercept(context.Background(), msg)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected response, got nil")
		}

		// The message should have been accepted (not skipped as notification)
		// because id is explicitly null (not absent).
		t.Log("explicit null id message was correctly NOT treated as a notification")
	})
}

// --- 1C.5: TestClientNotificationBlocked ---

// TestClientNotificationBlocked verifies that client-sent notifications (no id,
// ClientToServer direction, method != "initialize") are silently dropped by Intercept
// (nil, nil) without touching upstreams.
// Per JSON-RPC 2.0 Section 4.1: "The Server MUST NOT reply to a Notification."
// Exception: notifications/cancelled is forwarded to upstreams (M-12) but still
// returns nil to the caller (no JSON-RPC response).
func TestClientNotificationBlocked(t *testing.T) {
	methods := []string{
		"notifications/progress",
		"notifications/initialized",
		"tools/call",
		"tools/list",
		"resources/list",
		"some/custom/method",
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			cache := newMockToolCacheReader(
				&RoutableTool{Name: "tool-a", UpstreamID: "upstream-1"},
			)
			manager := newMockUpstreamConnectionProvider()
			manager.addConnection("upstream-1", `{"jsonrpc":"2.0","id":1,"result":{}}`)
			router := newTestRouter(cache, manager)

			msg := makeNotificationMessage(t, method)
			resp, err := router.Intercept(context.Background(), msg)

			if err != nil {
				t.Fatalf("unexpected error for notification %q: %v", method, err)
			}
			if resp != nil {
				t.Fatalf("expected nil response for notification %q (JSON-RPC 2.0: must not reply), got response", method)
			}

			// Verify nothing was forwarded to upstream.
			conn := manager.connections["upstream-1"]
			if len(conn.writer.buf) != 0 {
				t.Errorf("expected no bytes written to upstream for notification %q, got %d bytes", method, len(conn.writer.buf))
			}
		})
	}
}

// TestClientNotificationCancelledForwarded verifies that notifications/cancelled
// is forwarded to upstreams (M-12) so they can abort in-progress work, while still
// returning nil (no JSON-RPC response) to the caller.
func TestClientNotificationCancelledForwarded(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool-a", UpstreamID: "upstream-1"},
	)
	manager := newMockUpstreamConnectionProvider()
	manager.addConnection("upstream-1", `{"jsonrpc":"2.0","id":1,"result":{}}`)
	router := newTestRouter(cache, manager)

	msg := makeNotificationMessage(t, "notifications/cancelled")
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatal("expected nil response for notifications/cancelled (it is a notification), got response")
	}

	// Verify the notification WAS forwarded to the upstream.
	conn := manager.connections["upstream-1"]
	if len(conn.writer.buf) == 0 {
		t.Error("expected notifications/cancelled to be forwarded to upstream, but nothing was written")
	}
}

// TestClientNotificationBlocked_InitializeDropped verifies that "initialize"
// without an id is treated as a notification and silently dropped per JSON-RPC 2.0 Section 4.1.
func TestClientNotificationBlocked_InitializeDropped(t *testing.T) {
	cache := newMockToolCacheReader()
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	raw := `{"jsonrpc":"2.0","method":"initialize"}`
	req := &jsonrpc.Request{
		Method: "initialize",
	}
	msg := &mcp.Message{
		Raw:       []byte(raw),
		Direction: mcp.ClientToServer,
		Decoded:   req,
	}

	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatal("expected nil response for initialize notification (no id), got response")
	}
}

// TestNotificationFlood_NoUpstreamMutexContention verifies that the notification
// guard fires BEFORE the AllConnected check and before any upstream mutex is acquired.
// Even with allConnected=false, notifications should be silently dropped (nil, nil),
// not produce the "No upstreams available" error.
func TestNotificationFlood_NoUpstreamMutexContention(t *testing.T) {
	cache := newMockToolCacheReader()
	manager := newMockUpstreamConnectionProvider()
	manager.allConnected = false // all upstreams disconnected

	router := newTestRouter(cache, manager)

	msg := makeNotificationMessage(t, "notifications/progress")
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Fatal("expected nil response (notification guard should drop silently), got response")
	}
}

// --- 1C.6: TestNotificationDuringToolDiscovery ---

// TestNotificationDuringToolDiscovery verifies that forwardToUpstream correctly
// skips notifications even when 10 are interleaved before the tool call response.
// This mirrors the maxSkip=10 pattern in tool_discovery_service.go's readResponse.
// After the B6 fix (timeout-only approach), any number of notifications should work.
func TestNotificationDuringToolDiscovery(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "discover-tool", UpstreamID: "upstream-1", Description: "Discovery tool"},
	)
	manager := newMockUpstreamConnectionProvider()

	// 10 notifications (matching tool_discovery_service's maxSkip=10) + 1 response
	lines := make([]string, 0, 11)
	for i := 0; i < 10; i++ {
		lines = append(lines, fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed","params":{"index":%d}}`, i))
	}
	lines = append(lines, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"discovery complete"}]}}`)

	addConnectionMultiLine(manager, "upstream-1", lines)
	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "discover-tool", nil)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error with 10 notifications during tool call: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	var parsed struct {
		Result struct {
			Content []struct{ Text string `json:"text"` } `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(parsed.Result.Content) == 0 || parsed.Result.Content[0].Text != "discovery complete" {
		t.Errorf("expected 'discovery complete', got %+v", parsed.Result)
	}

	t.Log("forwardToUpstream correctly skipped 10 notifications during tool call (mirrors tool_discovery_service maxSkip=10)")
}
