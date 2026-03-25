package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// --- Mock implementations ---

// mockToolCacheReader implements ToolCacheReader for testing.
type mockToolCacheReader struct {
	tools map[string]*RoutableTool
}

func newMockToolCacheReader(tools ...*RoutableTool) *mockToolCacheReader {
	m := &mockToolCacheReader{tools: make(map[string]*RoutableTool)}
	for _, t := range tools {
		m.tools[t.Name] = t
	}
	return m
}

func (m *mockToolCacheReader) GetTool(name string) (*RoutableTool, bool) {
	t, ok := m.tools[name]
	return t, ok
}

func (m *mockToolCacheReader) GetAllTools() []*RoutableTool {
	result := make([]*RoutableTool, 0, len(m.tools))
	for _, t := range m.tools {
		result = append(result, t)
	}
	return result
}

func (m *mockToolCacheReader) IsAmbiguous(name string) (bool, []string) {
	return false, nil
}

// mockUpstreamConnectionProvider implements UpstreamConnectionProvider for testing.
type mockUpstreamConnectionProvider struct {
	connections  map[string]*mockConnection
	allConnected bool
}

type mockConnection struct {
	writer *mockWriteCloser
	lineCh <-chan []byte
}

type mockWriteCloser struct {
	buf    []byte
	closed bool
	err    error
}

func (w *mockWriteCloser) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *mockWriteCloser) Close() error {
	w.closed = true
	return nil
}

func newMockUpstreamConnectionProvider() *mockUpstreamConnectionProvider {
	return &mockUpstreamConnectionProvider{
		connections:  make(map[string]*mockConnection),
		allConnected: true,
	}
}

func (m *mockUpstreamConnectionProvider) GetConnection(upstreamID string) (io.WriteCloser, <-chan []byte, error) {
	conn, ok := m.connections[upstreamID]
	if !ok {
		return nil, nil, fmt.Errorf("upstream %s not connected", upstreamID)
	}
	return conn.writer, conn.lineCh, nil
}

func (m *mockUpstreamConnectionProvider) AllConnected() bool {
	return m.allConnected
}

func (m *mockUpstreamConnectionProvider) addConnection(upstreamID string, responseJSON string) {
	ch := make(chan []byte, 1)
	ch <- []byte(responseJSON)
	m.connections[upstreamID] = &mockConnection{
		writer: &mockWriteCloser{},
		lineCh: ch,
	}
}

// --- Helper functions ---

func makeToolsListRequest(t *testing.T, id int64) *mcp.Message {
	t.Helper()
	reqID, _ := jsonrpc.MakeID(float64(id))
	req := &jsonrpc.Request{
		ID:     reqID,
		Method: "tools/list",
	}
	raw, err := jsonrpc.EncodeMessage(req)
	if err != nil {
		t.Fatalf("failed to encode tools/list request: %v", err)
	}
	return &mcp.Message{
		Raw:       raw,
		Direction: mcp.ClientToServer,
		Decoded:   req,
	}
}

func makeToolsCallRequest(t *testing.T, id int64, toolName string, args map[string]interface{}) *mcp.Message {
	t.Helper()
	params := map[string]interface{}{
		"name": toolName,
	}
	if args != nil {
		params["arguments"] = args
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("failed to marshal params: %v", err)
	}

	reqID, _ := jsonrpc.MakeID(float64(id))
	req := &jsonrpc.Request{
		ID:     reqID,
		Method: "tools/call",
		Params: json.RawMessage(paramsJSON),
	}
	raw, err := jsonrpc.EncodeMessage(req)
	if err != nil {
		t.Fatalf("failed to encode tools/call request: %v", err)
	}
	return &mcp.Message{
		Raw:       raw,
		Direction: mcp.ClientToServer,
		Decoded:   req,
	}
}

func makeInitializeRequest(t *testing.T, id int64) *mcp.Message {
	t.Helper()
	reqID, _ := jsonrpc.MakeID(float64(id))
	params := json.RawMessage(`{"protocolVersion":"2025-11-25","clientInfo":{"name":"test-client","version":"1.0.0"}}`)
	req := &jsonrpc.Request{
		ID:     reqID,
		Method: "initialize",
		Params: params,
	}
	raw, err := jsonrpc.EncodeMessage(req)
	if err != nil {
		t.Fatalf("failed to encode initialize request: %v", err)
	}
	return &mcp.Message{
		Raw:       raw,
		Direction: mcp.ClientToServer,
		Decoded:   req,
	}
}

func newTestRouter(cache ToolCacheReader, manager UpstreamConnectionProvider) *UpstreamRouter {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewUpstreamRouter(cache, manager, logger)
}

// --- Tests ---

// TestRouterCompileTimeCheck verifies UpstreamRouter implements MessageInterceptor.
func TestRouterCompileTimeCheck(t *testing.T) {
	// This is verified at compile time via the var _ declaration in the source.
	// If that declaration is missing, this test won't compile.
	var _ MessageInterceptor = (*UpstreamRouter)(nil)
}

// TestRouterToolsListAggregation tests that tools/list returns tools from all upstreams.
func TestRouterToolsListAggregation(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool-a", UpstreamID: "upstream-1", Description: "Tool A desc", InputSchema: json.RawMessage(`{"type":"object"}`)},
		&RoutableTool{Name: "tool-b", UpstreamID: "upstream-1", Description: "Tool B desc", InputSchema: json.RawMessage(`{"type":"object"}`)},
		&RoutableTool{Name: "tool-c", UpstreamID: "upstream-2", Description: "Tool C desc", InputSchema: json.RawMessage(`{"type":"object"}`)},
	)
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	msg := makeToolsListRequest(t, 1)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
		return
	}

	// Parse the response to verify tools
	var result struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int64  `json:"id"`
		Result  struct {
			Tools []struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				InputSchema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(result.Result.Tools) != 3 {
		t.Errorf("expected 3 tools, got %d", len(result.Result.Tools))
	}

	// Verify all tool names are present
	toolNames := make(map[string]bool)
	for _, tool := range result.Result.Tools {
		toolNames[tool.Name] = true
	}
	for _, name := range []string{"tool-a", "tool-b", "tool-c"} {
		if !toolNames[name] {
			t.Errorf("expected tool %q in response", name)
		}
	}
}

// TestRouterToolsListEmpty tests that tools/list returns empty array when no tools.
func TestRouterToolsListEmpty(t *testing.T) {
	cache := newMockToolCacheReader() // no tools
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	msg := makeToolsListRequest(t, 1)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result struct {
		Result struct {
			Tools []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Result.Tools == nil {
		t.Error("expected empty tools array, got nil")
	}
	if len(result.Result.Tools) != 0 {
		t.Errorf("expected 0 tools, got %d", len(result.Result.Tools))
	}
}

// TestRouterToolsCallRouting tests that tools/call routes to the correct upstream.
func TestRouterToolsCallRouting(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "read-file", UpstreamID: "upstream-1", Description: "Read a file"},
		&RoutableTool{Name: "search-web", UpstreamID: "upstream-2", Description: "Search the web"},
	)

	// Build a valid JSON-RPC response for the upstream to return
	upstreamResponse := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"file contents"}]}}`

	manager := newMockUpstreamConnectionProvider()
	manager.addConnection("upstream-1", upstreamResponse)
	manager.addConnection("upstream-2", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"search results"}]}}`)

	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "read-file", map[string]interface{}{"path": "/tmp/test"})
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Verify it was sent to upstream-1 (check writer got data)
	conn1 := manager.connections["upstream-1"]
	if len(conn1.writer.buf) == 0 {
		t.Error("expected request to be forwarded to upstream-1")
	}

	// Verify upstream-2 was NOT written to
	conn2 := manager.connections["upstream-2"]
	if len(conn2.writer.buf) != 0 {
		t.Error("did not expect request to be forwarded to upstream-2")
	}

	// Verify the response direction
	if resp.Direction != mcp.ServerToClient {
		t.Errorf("expected ServerToClient direction, got %v", resp.Direction)
	}
}

// TestRouterToolsCallNotFound tests that calling an unknown tool returns error -32601.
func TestRouterToolsCallNotFound(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool-a", UpstreamID: "upstream-1"},
	)
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "nonexistent-tool", nil)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected error response, got nil")
	}

	// Parse response and check for error code -32601
	var result struct {
		Error *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Error == nil {
		t.Fatal("expected error in response")
	}
	if result.Error.Code != -32601 {
		t.Errorf("expected error code -32601, got %d", result.Error.Code)
	}
	if !strings.Contains(result.Error.Message, "nonexistent-tool") {
		t.Errorf("expected error message to contain tool name, got %q", result.Error.Message)
	}
}

// TestRouterToolsCallUpstreamUnavailable tests error when upstream is disconnected.
func TestRouterToolsCallUpstreamUnavailable(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool-a", UpstreamID: "upstream-1"},
	)
	// Manager has no connections - upstream-1 is not connected
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "tool-a", nil)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected error response, got nil")
	}

	var result struct {
		Error *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Error == nil {
		t.Fatal("expected error in response")
	}
	if result.Error.Code != -32603 {
		t.Errorf("expected error code -32603, got %d", result.Error.Code)
	}
}

// TestRouterAllUpstreamsDisconnected tests 503-equivalent error when no upstreams available.
func TestRouterAllUpstreamsDisconnected(t *testing.T) {
	cache := newMockToolCacheReader()
	manager := newMockUpstreamConnectionProvider()
	manager.allConnected = false // simulate all disconnected

	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "some_tool", nil)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected error response, got nil")
	}

	var result struct {
		Error *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Error == nil {
		t.Fatal("expected error in response")
	}
	if result.Error.Code != -32000 {
		t.Errorf("expected error code -32000 (no upstreams), got %d", result.Error.Code)
	}
}

// TestRouterHandlesInitializeLocally tests that initialize is handled by the proxy directly.
func TestRouterHandlesInitializeLocally(t *testing.T) {
	cache := newMockToolCacheReader()
	manager := newMockUpstreamConnectionProvider()

	router := newTestRouter(cache, manager)

	msg := makeInitializeRequest(t, 1)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Direction != mcp.ServerToClient {
		t.Error("expected ServerToClient direction")
	}

	// Verify the response contains protocolVersion and capabilities.
	var result struct {
		Result struct {
			ProtocolVersion string         `json:"protocolVersion"`
			Capabilities    map[string]any `json:"capabilities"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Result.ProtocolVersion == "" {
		t.Error("expected protocolVersion in response")
	}
	if result.Result.Capabilities == nil {
		t.Error("expected capabilities in response")
	}
	if result.Result.ServerInfo.Name != "sentinel-gate" {
		t.Errorf("expected serverInfo.name=sentinel-gate, got %q", result.Result.ServerInfo.Name)
	}
}

// TestHandleInitializeListChanged verifies that the initialize response includes
// tools.listChanged: true in its capabilities.
func TestHandleInitializeListChanged(t *testing.T) {
	cache := newMockToolCacheReader()
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	msg := makeInitializeRequest(t, 1)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Parse the response and check for tools.listChanged capability.
	var result struct {
		Result struct {
			Capabilities struct {
				Tools struct {
					ListChanged bool `json:"listChanged"`
				} `json:"tools"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if !result.Result.Capabilities.Tools.ListChanged {
		t.Error("expected capabilities.tools.listChanged to be true")
	}
}

// TestRouterToolsCallResponseContent verifies the response content from a tool call.
func TestRouterToolsCallResponseContent(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "echo", UpstreamID: "upstream-1", Description: "Echo tool"},
	)

	expectedResult := `{"content":[{"type":"text","text":"hello world"}]}`
	upstreamResponse := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":%s}`, expectedResult)

	manager := newMockUpstreamConnectionProvider()
	manager.addConnection("upstream-1", upstreamResponse)

	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "echo", map[string]interface{}{"text": "hello world"})
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse and verify the response has the expected result
	var parsed struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &parsed); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if parsed.Result == nil {
		t.Fatal("expected result in response")
	}
}

// TestRouterToolsCallWritesRawMessage verifies the raw request is forwarded to upstream.
func TestRouterToolsCallWritesRawMessage(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "test-tool", UpstreamID: "upstream-1"},
	)

	upstreamResponse := `{"jsonrpc":"2.0","id":1,"result":{}}`
	manager := newMockUpstreamConnectionProvider()
	manager.addConnection("upstream-1", upstreamResponse)

	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "test-tool", map[string]interface{}{"key": "value"})
	_, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the raw bytes were written to upstream stdin
	conn := manager.connections["upstream-1"]
	if len(conn.writer.buf) == 0 {
		t.Fatal("expected raw message to be written to upstream")
	}

	// The written data should be valid JSON-RPC followed by newline
	written := strings.TrimSpace(string(conn.writer.buf))
	var parsedReq struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal([]byte(written), &parsedReq); err != nil {
		t.Fatalf("written data is not valid JSON: %v", err)
	}
	if parsedReq.Method != "tools/call" {
		t.Errorf("expected method tools/call, got %q", parsedReq.Method)
	}
}

// TestRouterToolsListPreservesRequestID verifies the response ID matches the request.
func TestRouterToolsListPreservesRequestID(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "tool-a", UpstreamID: "upstream-1"},
	)
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	msg := makeToolsListRequest(t, 42)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result struct {
		ID float64 `json:"id"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.ID != 42 {
		t.Errorf("expected ID 42, got %v", result.ID)
	}
}

// TestInitializeSucceedsWithNoUpstreams verifies that initialize is handled
// locally even when no upstreams are connected (H-16). Initialize doesn't
// need upstreams — it advertises the proxy's own capabilities.
func TestInitializeSucceedsWithNoUpstreams(t *testing.T) {
	cache := newMockToolCacheReader()
	manager := newMockUpstreamConnectionProvider()
	manager.allConnected = false // no upstreams connected

	router := newTestRouter(cache, manager)

	msg := makeInitializeRequest(t, 1)
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected initialize response even with no upstreams, got nil")
	}

	var result struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Result.ProtocolVersion == "" {
		t.Error("expected protocolVersion — initialize should succeed without upstreams")
	}
}

// --- Mock for ambiguous tool resolution ---

// mockAmbiguousToolCacheReader extends the mock to support IsAmbiguous behavior
// for testing namespace collision scenarios.
type mockAmbiguousToolCacheReader struct {
	tools     map[string]*RoutableTool
	ambiguous map[string][]string // bare name → list of namespaced alternatives
}

func newMockAmbiguousToolCacheReader(tools ...*RoutableTool) *mockAmbiguousToolCacheReader {
	m := &mockAmbiguousToolCacheReader{
		tools:     make(map[string]*RoutableTool),
		ambiguous: make(map[string][]string),
	}
	for _, t := range tools {
		m.tools[t.Name] = t
	}
	return m
}

func (m *mockAmbiguousToolCacheReader) GetTool(name string) (*RoutableTool, bool) {
	t, ok := m.tools[name]
	return t, ok
}

func (m *mockAmbiguousToolCacheReader) GetAllTools() []*RoutableTool {
	result := make([]*RoutableTool, 0, len(m.tools))
	for _, t := range m.tools {
		result = append(result, t)
	}
	return result
}

func (m *mockAmbiguousToolCacheReader) IsAmbiguous(name string) (bool, []string) {
	suggestions, ok := m.ambiguous[name]
	return ok && len(suggestions) > 0, suggestions
}

// --- Namespace-aware tests ---

// TestRouter_ToolsListWithNamespace verifies that tools/list returns all namespaced
// and non-namespaced tools in sorted order.
func TestRouter_ToolsListWithNamespace(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "custom_tool", OriginalName: "custom_tool", UpstreamID: "upstream-1", Description: "Custom tool", InputSchema: json.RawMessage(`{"type":"object"}`)},
		&RoutableTool{Name: "desktop/read_file", OriginalName: "read_file", UpstreamID: "upstream-1", Description: "Desktop read", InputSchema: json.RawMessage(`{"type":"object"}`)},
		&RoutableTool{Name: "train/read_file", OriginalName: "read_file", UpstreamID: "upstream-2", Description: "Train read", InputSchema: json.RawMessage(`{"type":"object"}`)},
	)
	manager := newMockUpstreamConnectionProvider()
	router := newTestRouter(cache, manager)

	msg := makeToolsListRequest(t, 1)
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	var result struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(result.Result.Tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(result.Result.Tools))
	}

	// Verify sorted order: custom_tool < desktop/read_file < train/read_file
	expectedOrder := []string{"custom_tool", "desktop/read_file", "train/read_file"}
	for i, want := range expectedOrder {
		if result.Result.Tools[i].Name != want {
			t.Errorf("tool[%d]: expected %q, got %q", i, want, result.Result.Tools[i].Name)
		}
	}
}

// TestRouter_ToolCallWithNamespace verifies that a namespaced tools/call is routed
// to the correct upstream and the tool name is rewritten to the bare name.
func TestRouter_ToolCallWithNamespace(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "desktop/read_file", OriginalName: "read_file", UpstreamID: "upstream-1", Description: "Desktop read"},
	)

	upstreamResponse := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`
	manager := newMockUpstreamConnectionProvider()
	manager.addConnection("upstream-1", upstreamResponse)

	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "desktop/read_file", map[string]interface{}{"path": "/tmp/x"})
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Verify it was forwarded to upstream-1
	conn := manager.connections["upstream-1"]
	if len(conn.writer.buf) == 0 {
		t.Fatal("expected request to be forwarded to upstream-1")
	}

	// Verify the forwarded message has the bare name "read_file", not "desktop/read_file"
	written := string(conn.writer.buf)
	if strings.Contains(written, "desktop/read_file") {
		t.Error("forwarded message should NOT contain the namespaced name \"desktop/read_file\"")
	}
	if !strings.Contains(written, `"read_file"`) {
		t.Error("forwarded message should contain the bare name \"read_file\"")
	}
}

// TestRouter_ToolCallBareNameAmbiguous verifies that calling a bare name that maps
// to multiple namespaced tools returns an ambiguous error with suggestions.
func TestRouter_ToolCallBareNameAmbiguous(t *testing.T) {
	cache := newMockAmbiguousToolCacheReader(
		// Only namespaced entries in the tools map — bare "read_file" is NOT present.
		&RoutableTool{Name: "desktop/read_file", OriginalName: "read_file", UpstreamID: "upstream-1"},
		&RoutableTool{Name: "train/read_file", OriginalName: "read_file", UpstreamID: "upstream-2"},
	)
	cache.ambiguous["read_file"] = []string{"desktop/read_file", "train/read_file"}

	manager := newMockUpstreamConnectionProvider()
	manager.addConnection("upstream-1", `{"jsonrpc":"2.0","id":1,"result":{}}`)
	manager.addConnection("upstream-2", `{"jsonrpc":"2.0","id":1,"result":{}}`)

	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "read_file", nil)
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected error response, got nil")
	}

	var result struct {
		Error *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Error == nil {
		t.Fatal("expected error in response")
	}
	if result.Error.Code != -32601 {
		t.Errorf("expected error code -32601, got %d", result.Error.Code)
	}
	if !strings.Contains(result.Error.Message, "ambiguous") {
		t.Errorf("expected error message to contain \"ambiguous\", got %q", result.Error.Message)
	}
	if !strings.Contains(result.Error.Message, "desktop/read_file") {
		t.Errorf("expected error message to contain suggestion \"desktop/read_file\", got %q", result.Error.Message)
	}
	if !strings.Contains(result.Error.Message, "train/read_file") {
		t.Errorf("expected error message to contain suggestion \"train/read_file\", got %q", result.Error.Message)
	}
}

// TestRouter_ToolCallBareNameUnique verifies that a bare (non-namespaced) tool name
// that is unique (no collision) routes successfully — backward compatible behavior.
func TestRouter_ToolCallBareNameUnique(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "read_file", OriginalName: "read_file", UpstreamID: "upstream-1", Description: "Read a file"},
	)

	upstreamResponse := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"data"}]}}`
	manager := newMockUpstreamConnectionProvider()
	manager.addConnection("upstream-1", upstreamResponse)

	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "read_file", map[string]interface{}{"path": "/etc/hosts"})
	resp, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected response, got nil")
	}

	// Should be a success response, not an error
	var result struct {
		Error  *json.RawMessage `json:"error"`
		Result json.RawMessage  `json:"result"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("expected success, got error: %s", string(*result.Error))
	}
	if result.Result == nil {
		t.Error("expected result in response")
	}
}

// TestRouter_ForwardStripsNamespace verifies that when a namespaced tool name is
// forwarded to an upstream, the JSON params.name field is rewritten to the bare name.
func TestRouter_ForwardStripsNamespace(t *testing.T) {
	cache := newMockToolCacheReader(
		&RoutableTool{Name: "desktop/read_file", OriginalName: "read_file", UpstreamID: "upstream-1", Description: "Desktop read"},
	)

	upstreamResponse := `{"jsonrpc":"2.0","id":1,"result":{}}`
	manager := newMockUpstreamConnectionProvider()
	manager.addConnection("upstream-1", upstreamResponse)

	router := newTestRouter(cache, manager)

	msg := makeToolsCallRequest(t, 1, "desktop/read_file", map[string]interface{}{"path": "/tmp/x"})
	_, err := router.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse the written bytes to verify the tool name was rewritten
	conn := manager.connections["upstream-1"]
	if len(conn.writer.buf) == 0 {
		t.Fatal("expected raw message to be written to upstream")
	}

	written := strings.TrimSpace(string(conn.writer.buf))
	var parsedReq struct {
		Method string `json:"method"`
		Params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(written), &parsedReq); err != nil {
		t.Fatalf("written data is not valid JSON: %v", err)
	}
	if parsedReq.Method != "tools/call" {
		t.Errorf("expected method tools/call, got %q", parsedReq.Method)
	}
	if parsedReq.Params.Name != "read_file" {
		t.Errorf("expected forwarded tool name \"read_file\", got %q", parsedReq.Params.Name)
	}
	// Extra safety: verify the raw bytes don't contain the namespaced form
	if strings.Contains(written, "desktop/read_file") {
		t.Error("written JSON should not contain the namespaced name \"desktop/read_file\"")
	}
}
