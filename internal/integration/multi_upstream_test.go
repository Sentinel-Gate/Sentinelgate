package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// --- Mock implementations for integration tests ---

// intMockMCPClient implements outbound.MCPClient for integration tests.
type intMockMCPClient struct {
	mu         sync.Mutex
	startErr   error
	waitCh     chan struct{}
	started    bool
	closed     bool
	startCount int
}

func newIntMockMCPClient() *intMockMCPClient {
	return &intMockMCPClient{
		waitCh: make(chan struct{}),
	}
}

func (m *intMockMCPClient) Start(_ context.Context) (io.WriteCloser, io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCount++
	if m.startErr != nil {
		return nil, nil, m.startErr
	}
	m.started = true
	m.closed = false
	m.waitCh = make(chan struct{})
	return &intNopWriteCloser{}, &intNopReadCloser{}, nil
}

func (m *intMockMCPClient) Wait() error {
	<-m.waitCh
	return nil
}

func (m *intMockMCPClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.started = false
	select {
	case <-m.waitCh:
	default:
		close(m.waitCh)
	}
	return nil
}

var _ outbound.MCPClient = (*intMockMCPClient)(nil)

type intNopWriteCloser struct{}

func (n *intNopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (n *intNopWriteCloser) Close() error                { return nil }

type intNopReadCloser struct{}

func (n *intNopReadCloser) Read(_ []byte) (int, error) { return 0, io.EOF }
func (n *intNopReadCloser) Close() error               { return nil }

// intMockUpstreamStore implements upstream.UpstreamStore for integration tests.
type intMockUpstreamStore struct {
	mu        sync.RWMutex
	upstreams map[string]*upstream.Upstream
}

func newIntMockUpstreamStore() *intMockUpstreamStore {
	return &intMockUpstreamStore{
		upstreams: make(map[string]*upstream.Upstream),
	}
}

func (s *intMockUpstreamStore) List(_ context.Context) ([]upstream.Upstream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]upstream.Upstream, 0, len(s.upstreams))
	for _, u := range s.upstreams {
		result = append(result, *u)
	}
	return result, nil
}

func (s *intMockUpstreamStore) Get(_ context.Context, id string) (*upstream.Upstream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.upstreams[id]
	if !ok {
		return nil, upstream.ErrUpstreamNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *intMockUpstreamStore) Add(_ context.Context, u *upstream.Upstream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstreams[u.ID] = u
	return nil
}

func (s *intMockUpstreamStore) Update(_ context.Context, u *upstream.Upstream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.upstreams[u.ID]; !ok {
		return upstream.ErrUpstreamNotFound
	}
	s.upstreams[u.ID] = u
	return nil
}

func (s *intMockUpstreamStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.upstreams[id]; !ok {
		return upstream.ErrUpstreamNotFound
	}
	delete(s.upstreams, id)
	return nil
}

// intMockConnectionProvider implements proxy.UpstreamConnectionProvider for testing
// the router with pipe-based communication to verify request/response flow.
type intMockConnectionProvider struct {
	connections  map[string]*intMockConnection
	allConnected bool
}

type intMockConnection struct {
	writer *intMockWriteCloser
	reader *intMockReadCloser
}

type intMockWriteCloser struct {
	buf []byte
}

func (w *intMockWriteCloser) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *intMockWriteCloser) Close() error { return nil }

type intMockReadCloser struct {
	reader io.Reader
}

func (r *intMockReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *intMockReadCloser) Close() error { return nil }

func newIntMockConnectionProvider() *intMockConnectionProvider {
	return &intMockConnectionProvider{
		connections:  make(map[string]*intMockConnection),
		allConnected: true,
	}
}

func (m *intMockConnectionProvider) GetConnection(upstreamID string) (io.WriteCloser, io.ReadCloser, error) {
	conn, ok := m.connections[upstreamID]
	if !ok {
		return nil, nil, fmt.Errorf("upstream %s not connected", upstreamID)
	}
	return conn.writer, conn.reader, nil
}

func (m *intMockConnectionProvider) AllConnected() bool {
	return m.allConnected
}

func (m *intMockConnectionProvider) addConnection(upstreamID string, responseJSON string) {
	m.connections[upstreamID] = &intMockConnection{
		writer: &intMockWriteCloser{},
		reader: &intMockReadCloser{reader: strings.NewReader(responseJSON + "\n")},
	}
}

// --- Helper functions ---

func makeTestToolsListRequest(t *testing.T, id int64) *mcp.Message {
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

func makeTestToolsCallRequest(t *testing.T, id int64, toolName string) *mcp.Message {
	t.Helper()
	params := map[string]interface{}{
		"name": toolName,
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

// --- Integration Tests ---

// TestMultiUpstreamRouting verifies the full multi-upstream routing pipeline:
// ToolCache populated from 2 upstreams -> UpstreamRouter aggregates tools/list ->
// tools/call routed to correct upstream -> unknown tool returns -32601.
// (Success Criteria 3, 4)
func TestMultiUpstreamRouting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Step 1: Create ToolCache and populate with tools from 2 upstreams.
	toolCache := upstream.NewToolCache()
	now := time.Now()

	// Upstream A: tools ["read_file", "list_files"]
	toolCache.SetToolsForUpstream("upstream-a", []*upstream.DiscoveredTool{
		{Name: "read_file", Description: "Read a file", UpstreamID: "upstream-a", UpstreamName: "FS Server", DiscoveredAt: now, InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "list_files", Description: "List files", UpstreamID: "upstream-a", UpstreamName: "FS Server", DiscoveredAt: now, InputSchema: json.RawMessage(`{"type":"object"}`)},
	})

	// Upstream B: tools ["send_email", "search_web"]
	toolCache.SetToolsForUpstream("upstream-b", []*upstream.DiscoveredTool{
		{Name: "send_email", Description: "Send an email", UpstreamID: "upstream-b", UpstreamName: "Web Server", DiscoveredAt: now, InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "search_web", Description: "Search the web", UpstreamID: "upstream-b", UpstreamName: "Web Server", DiscoveredAt: now, InputSchema: json.RawMessage(`{"type":"object"}`)},
	})

	// Step 2: Create mock connection provider with responses for each upstream.
	provider := newIntMockConnectionProvider()
	provider.addConnection("upstream-a", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"file contents"}]}}`)
	provider.addConnection("upstream-b", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"email sent"}]}}`)

	// Step 3: Create UpstreamRouter with adapter and provider.
	cacheAdapter := proxy.NewToolCacheAdapter(toolCache)
	router := proxy.NewUpstreamRouter(cacheAdapter, provider, logger)

	// --- Test tools/list: should return all 4 tools ---
	t.Run("tools/list aggregates all tools", func(t *testing.T) {
		msg := makeTestToolsListRequest(t, 1)
		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("Intercept tools/list: unexpected error: %v", err)
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
			t.Fatalf("parse response: %v", err)
		}

		if len(result.Result.Tools) != 4 {
			t.Fatalf("expected 4 tools, got %d", len(result.Result.Tools))
		}

		// Verify all tool names are present.
		toolNames := make(map[string]bool)
		for _, tool := range result.Result.Tools {
			toolNames[tool.Name] = true
		}
		for _, expected := range []string{"read_file", "list_files", "send_email", "search_web"} {
			if !toolNames[expected] {
				t.Errorf("expected tool %q in tools/list response", expected)
			}
		}

		// Verify tools are sorted by name (deterministic ordering).
		names := make([]string, len(result.Result.Tools))
		for i, tool := range result.Result.Tools {
			names[i] = tool.Name
		}
		for i := 1; i < len(names); i++ {
			if names[i] < names[i-1] {
				t.Errorf("tools not sorted: %v", names)
				break
			}
		}
	})

	// --- Test tools/call routing: read_file -> upstream-a ---
	t.Run("tools/call routes to upstream-a", func(t *testing.T) {
		// Reset connections (new readers for fresh responses).
		provider.addConnection("upstream-a", `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"file contents"}]}}`)
		provider.addConnection("upstream-b", `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"email sent"}]}}`)

		msg := makeTestToolsCallRequest(t, 2, "read_file")
		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("Intercept tools/call read_file: unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected response, got nil")
		}

		// Verify upstream-a received the request.
		connA := provider.connections["upstream-a"]
		if len(connA.writer.buf) == 0 {
			t.Error("expected request forwarded to upstream-a")
		}

		// Verify upstream-b did NOT receive the request.
		connB := provider.connections["upstream-b"]
		if len(connB.writer.buf) != 0 {
			t.Error("did NOT expect request forwarded to upstream-b")
		}
	})

	// --- Test tools/call routing: send_email -> upstream-b ---
	t.Run("tools/call routes to upstream-b", func(t *testing.T) {
		// Reset connections.
		provider.addConnection("upstream-a", `{"jsonrpc":"2.0","id":3,"result":{}}`)
		provider.addConnection("upstream-b", `{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"email sent"}]}}`)

		msg := makeTestToolsCallRequest(t, 3, "send_email")
		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("Intercept tools/call send_email: unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected response, got nil")
		}

		// Verify upstream-b received the request.
		connB := provider.connections["upstream-b"]
		if len(connB.writer.buf) == 0 {
			t.Error("expected request forwarded to upstream-b")
		}

		// Verify upstream-a did NOT receive the request.
		connA := provider.connections["upstream-a"]
		if len(connA.writer.buf) != 0 {
			t.Error("did NOT expect request forwarded to upstream-a")
		}
	})

	// --- Test unknown tool: returns -32601 ---
	t.Run("unknown tool returns -32601", func(t *testing.T) {
		msg := makeTestToolsCallRequest(t, 4, "nonexistent_tool")
		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("Intercept nonexistent_tool: unexpected error: %v", err)
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
			t.Fatalf("parse error response: %v", err)
		}
		if result.Error == nil {
			t.Fatal("expected error in response")
		}
		if result.Error.Code != -32601 {
			t.Errorf("error code = %d, want -32601", result.Error.Code)
		}
		if !strings.Contains(result.Error.Message, "nonexistent_tool") {
			t.Errorf("error message should contain tool name, got %q", result.Error.Message)
		}
	})
}

// TestUpstreamFailureAndRecovery verifies that upstream connection failure triggers
// retry with exponential backoff, and recovery resets the retry count (Success Criteria 5).
func TestUpstreamFailureAndRecovery(t *testing.T) {
	store := newIntMockUpstreamStore()
	u := &upstream.Upstream{
		ID:      "up-fail",
		Name:    "flaky-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}
	_ = store.Add(context.Background(), u)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.NewUpstreamService(store, nil, logger) // nil stateStore: no persistence in test

	failCount := atomic.Int32{}
	failUntil := int32(2) // fail first 2 attempts, succeed on 3rd

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		mc := newIntMockMCPClient()
		if failCount.Add(1) <= failUntil {
			mc.startErr = errors.New("connection refused")
		}
		return mc, nil
	}

	mgr := service.NewUpstreamManager(svc, factory, logger)
	// Use short backoff for fast testing.
	mgr.SetBackoffBase(10 * time.Millisecond)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	// Start the upstream (first attempt will fail).
	if err := mgr.Start(ctx, "up-fail"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Assert status is Error or Connecting after first failure.
	status, _ := mgr.Status("up-fail")
	if status != upstream.StatusConnecting && status != upstream.StatusError {
		t.Errorf("Status after failure = %q, want Connecting or Error", status)
	}

	// Wait for retries to complete (10ms base, delays: 10ms, 20ms -> ~30ms total).
	time.Sleep(200 * time.Millisecond)

	// Assert status = Connected after retry succeeds.
	status, _ = mgr.Status("up-fail")
	if status != upstream.StatusConnected {
		t.Errorf("Status after recovery = %q, want %q", status, upstream.StatusConnected)
	}

	// Assert multiple attempts were made.
	attempts := failCount.Load()
	if attempts < 3 {
		t.Errorf("expected at least 3 attempts (2 failures + 1 success), got %d", attempts)
	}
}

// TestAllUpstreamsDisconnected verifies that the router returns a -32000 error
// (503-equivalent) when no upstreams are available.
func TestAllUpstreamsDisconnected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create router with mock provider where AllConnected() returns false.
	toolCache := upstream.NewToolCache()
	cacheAdapter := proxy.NewToolCacheAdapter(toolCache)

	provider := newIntMockConnectionProvider()
	provider.allConnected = false

	router := proxy.NewUpstreamRouter(cacheAdapter, provider, logger)

	// Send a tools/call message.
	msg := makeTestToolsCallRequest(t, 1, "any_tool")
	resp, err := router.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected error response, got nil")
	}

	// Verify -32000 error code (no upstreams available).
	var result struct {
		Error *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(resp.Raw, &result); err != nil {
		t.Fatalf("parse error response: %v", err)
	}
	if result.Error == nil {
		t.Fatal("expected error in response")
	}
	if result.Error.Code != -32000 {
		t.Errorf("error code = %d, want -32000", result.Error.Code)
	}
	if !strings.Contains(result.Error.Message, "No upstreams available") {
		t.Errorf("error message = %q, want to contain 'No upstreams available'", result.Error.Message)
	}
}
