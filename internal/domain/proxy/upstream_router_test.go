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

// mockUpstreamConnectionProvider implements UpstreamConnectionProvider for testing.
type mockUpstreamConnectionProvider struct {
	connections  map[string]*mockConnection
	allConnected bool
}

type mockConnection struct {
	writer *mockWriteCloser
	reader *mockReadCloser
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

type mockReadCloser struct {
	reader io.Reader
	closed bool
}

func (r *mockReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *mockReadCloser) Close() error {
	r.closed = true
	return nil
}

func newMockUpstreamConnectionProvider() *mockUpstreamConnectionProvider {
	return &mockUpstreamConnectionProvider{
		connections:  make(map[string]*mockConnection),
		allConnected: true,
	}
}

func (m *mockUpstreamConnectionProvider) GetConnection(upstreamID string) (io.WriteCloser, io.ReadCloser, error) {
	conn, ok := m.connections[upstreamID]
	if !ok {
		return nil, nil, fmt.Errorf("upstream %s not connected", upstreamID)
	}
	return conn.writer, conn.reader, nil
}

func (m *mockUpstreamConnectionProvider) AllConnected() bool {
	return m.allConnected
}

func (m *mockUpstreamConnectionProvider) addConnection(upstreamID string, responseJSON string) {
	m.connections[upstreamID] = &mockConnection{
		writer: &mockWriteCloser{},
		reader: &mockReadCloser{reader: strings.NewReader(responseJSON + "\n")},
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
	req := &jsonrpc.Request{
		ID:     reqID,
		Method: "initialize",
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

	// Even tools/list should fail
	msg := makeToolsListRequest(t, 1)
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
