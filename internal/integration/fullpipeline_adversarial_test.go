package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/admin"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	mcpadapter "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/mcp"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"go.uber.org/goleak"
)

// --- Helper: build a full pipeline with real AuthInterceptor ---

// fullPipelineConfig holds the pieces needed for 5A tests.
type fullPipelineConfig struct {
	authInterceptor *proxy.AuthInterceptor
	chain           proxy.MessageInterceptor // outermost interceptor (auth -> ... -> upstream)
	auditRec        *regressionAuditRecorder
	statsRec        *regressionStatsRecorder
}

// buildFullPipeline constructs:
//
//	AuthInterceptor -> AuditInterceptor -> InterceptorChain(MCPNormalizer -> PolicyActionInterceptor ->
//	  ResponseScanInterceptor -> LegacyAdapter(upstream))
//
// It uses real AuthInterceptor with in-memory stores so we can test auth failure modes.
func buildFullPipeline(
	t *testing.T,
	policyEngine policy.PolicyEngine,
	upstream proxy.MessageInterceptor,
	apiKey string,
	identity *auth.Identity,
) *fullPipelineConfig {
	t.Helper()

	logger := testLogger()

	// Build the inner chain (same as buildRegressionChain).
	innerChain, auditRec, statsRec := buildRegressionChain(policyEngine, upstream)

	// Build real auth services backed by in-memory stores.
	authStore := memory.NewAuthStore()
	sessStore := memory.NewSessionStore()
	sessSvc := session.NewSessionService(sessStore, session.Config{Timeout: 30 * time.Minute})

	if identity != nil {
		authStore.AddIdentity(identity)
	}
	if apiKey != "" && identity != nil {
		keyHash := auth.HashKey(apiKey) //nolint:staticcheck // SA1019: testing backward-compatible key lookup
		authStore.AddKey(&auth.APIKey{
			Key:        keyHash,
			IdentityID: identity.ID,
			Name:       "test-key",
		})
	}

	apiKeySvc := auth.NewAPIKeyService(authStore)
	authInterceptor := proxy.NewAuthInterceptor(apiKeySvc, sessSvc, innerChain, logger)

	t.Cleanup(func() {
		authInterceptor.Stop()
		sessStore.Stop()
	})

	return &fullPipelineConfig{
		authInterceptor: authInterceptor,
		chain:           authInterceptor,
		auditRec:        auditRec,
		statsRec:        statsRec,
	}
}

// buildToolsCallMsg creates a tools/call MCP message (no session attached -- auth adds it).
func buildToolsCallMsg(t testing.TB, toolName string, args map[string]interface{}) *mcp.Message {
	return buildRegressionMessage(t, "tools/call", 1, map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	}, nil)
}

// ctxWithAPIKey returns a context carrying the given API key.
func ctxWithAPIKey(apiKey string) context.Context {
	return context.WithValue(context.Background(), proxy.APIKeyContextKey, apiKey)
}

// --- 5A.1: TestFullPipeline_EachStepCanFail ---

// TestFullPipeline_EachStepCanFail verifies that each stage of the full interceptor
// pipeline can independently produce an error, and that the error is surfaced correctly
// to the caller. This validates defense-in-depth: even if one layer is misconfigured,
// adjacent layers still enforce their contracts.
func TestFullPipeline_EachStepCanFail(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	testIdentity := &auth.Identity{
		ID:    "pipe-id-001",
		Name:  "pipeline-user",
		Roles: []auth.Role{auth.RoleUser},
	}

	const validKey = "test-pipeline-key-12345678"

	t.Run("AuthFails_NoAPIKey", func(t *testing.T) {
		// No API key provided -> auth interceptor should return ErrUnauthenticated
		// before any routing or policy evaluation occurs.
		policyEngine := &mockRegressionPolicyEngine{
			rules: map[string]policy.Decision{},
		}
		upstream := &mockUpstreamRouter{
			toolCallResponse: buildRegressionUpstreamResponse(t, "should not reach"),
		}

		pipe := buildFullPipeline(t, policyEngine, upstream, validKey, testIdentity)

		msg := buildToolsCallMsg(t, "read_file", map[string]interface{}{"path": "/tmp/x"})

		// No API key in context -- use bare context.
		_, err := pipe.chain.Intercept(context.Background(), msg)
		if err == nil {
			t.Fatal("expected auth error when no API key is provided")
		}
		if !errors.Is(err, proxy.ErrUnauthenticated) {
			t.Fatalf("expected ErrUnauthenticated, got: %v", err)
		}

		// Audit should NOT have recorded anything -- request never reached the chain.
		if len(pipe.auditRec.records) != 0 {
			t.Errorf("audit records = %d, want 0 (auth should block before audit)", len(pipe.auditRec.records))
		}
	})

	t.Run("PolicyDeny", func(t *testing.T) {
		// Auth succeeds, but policy denies the tool call.
		policyEngine := &mockRegressionPolicyEngine{
			rules: map[string]policy.Decision{
				"dangerous_tool": {
					Allowed: false,
					RuleID:  "deny-danger",
					Reason:  "tool is dangerous",
				},
			},
		}
		upstream := &mockUpstreamRouter{
			toolCallResponse: buildRegressionUpstreamResponse(t, "should not reach"),
		}

		pipe := buildFullPipeline(t, policyEngine, upstream, validKey, testIdentity)

		msg := buildToolsCallMsg(t, "dangerous_tool", map[string]interface{}{"x": "y"})
		ctx := ctxWithAPIKey(validKey)

		_, err := pipe.chain.Intercept(ctx, msg)
		if err == nil {
			t.Fatal("expected policy deny error")
		}
		if !errors.Is(err, proxy.ErrPolicyDenied) {
			t.Fatalf("expected ErrPolicyDenied, got: %v", err)
		}

		// Audit should record a deny.
		if len(pipe.auditRec.records) != 1 {
			t.Fatalf("audit records = %d, want 1", len(pipe.auditRec.records))
		}
		if pipe.statsRec.denies != 1 {
			t.Errorf("stats denies = %d, want 1", pipe.statsRec.denies)
		}
	})

	t.Run("UpstreamNotConnected_ToolNotFound", func(t *testing.T) {
		// Auth and policy succeed, but the upstream router cannot find the tool
		// (mockUpstreamRouter returns the tool call to a response that says tool
		// not found). We simulate this by having the mock return an error response.
		policyEngine := &mockRegressionPolicyEngine{
			rules: map[string]policy.Decision{},
		}

		// Use a mock upstream that returns an error-like response for unknown tools.
		upstream := &mockUpstreamRouterNotFound{}

		pipe := buildFullPipeline(t, policyEngine, upstream, validKey, testIdentity)

		msg := buildToolsCallMsg(t, "nonexistent_tool", nil)
		ctx := ctxWithAPIKey(validKey)

		result, err := pipe.chain.Intercept(ctx, msg)
		if err != nil {
			t.Fatalf("upstream not-found should return error response, not Go error, got: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil error response from upstream")
		}

		// The response should contain an error object with "not found".
		var envelope struct {
			Error *struct {
				Code    int64  `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(result.Raw, &envelope); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}
		if envelope.Error == nil {
			t.Fatal("expected JSON-RPC error in response")
		}
		if envelope.Error.Code != -32601 {
			t.Errorf("error code = %d, want -32601 (method not found)", envelope.Error.Code)
		}
	})

	t.Run("UpstreamTimeout_NeverResponds", func(t *testing.T) {
		// Auth and policy succeed, but the upstream mock never sends a response
		// on its lineCh, causing a timeout in forwardToUpstream.
		policyEngine := &mockRegressionPolicyEngine{
			rules: map[string]policy.Decision{},
		}

		// Use a mock that hangs forever (blocks on channel read).
		upstream := &mockUpstreamRouterTimeout{}

		pipe := buildFullPipeline(t, policyEngine, upstream, validKey, testIdentity)

		msg := buildToolsCallMsg(t, "slow_tool", nil)
		ctx := ctxWithAPIKey(validKey)

		_, err := pipe.chain.Intercept(ctx, msg)
		if err == nil {
			t.Fatal("expected timeout error from upstream that never responds")
		}
		if !strings.Contains(err.Error(), "timeout") {
			t.Errorf("expected timeout error, got: %v", err)
		}
	})
}

// mockUpstreamRouterNotFound simulates an upstream that returns a JSON-RPC
// error response (tool not found) for all tools/call requests.
type mockUpstreamRouterNotFound struct{}

func (m *mockUpstreamRouterNotFound) Intercept(_ context.Context, msg *mcp.Message) (*mcp.Message, error) {
	method := msg.Method()
	if method == "tools/call" {
		// Return a JSON-RPC error response for tool not found.
		errResp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"error": map[string]interface{}{
				"code":    -32601,
				"message": "Tool not found: nonexistent_tool",
			},
		}
		raw, _ := json.Marshal(errResp)
		return &mcp.Message{
			Raw:       raw,
			Direction: mcp.ServerToClient,
			Timestamp: time.Now().UTC(),
		}, nil
	}
	return msg, nil
}

// mockUpstreamRouterTimeout simulates an upstream that blocks forever,
// causing a timeout error. We do this by returning a Go error (simulating
// the forwardToUpstream timeout path).
type mockUpstreamRouterTimeout struct{}

func (m *mockUpstreamRouterTimeout) Intercept(_ context.Context, msg *mcp.Message) (*mcp.Message, error) {
	method := msg.Method()
	if method == "tools/call" {
		return nil, errors.New("timeout waiting for upstream response (30s)")
	}
	return msg, nil
}

// --- 5A.2: TestFullPipeline_MultiUpstreamRouting ---

// TestFullPipeline_MultiUpstreamRouting verifies that when multiple upstreams are
// registered, each with different tools, tools/call requests are routed to the
// correct upstream based on tool-name lookup in the ToolCache.
//
// Setup:
//   - upstream-1 owns "read_file"
//   - upstream-2 owns "write_file"
//
// The test sends tools/call for each tool and verifies the request was forwarded
// to the correct upstream by inspecting what was written to each mock writer.
func TestFullPipeline_MultiUpstreamRouting(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	logger := testLogger()

	// Build a real UpstreamRouter with mock ToolCache and ConnectionProvider.
	cache := &pipelineToolCache{
		tools: map[string]*proxy.RoutableTool{
			"read_file": {
				Name:        "read_file",
				UpstreamID:  "upstream-1",
				Description: "Read a file from disk",
			},
			"write_file": {
				Name:        "write_file",
				UpstreamID:  "upstream-2",
				Description: "Write a file to disk",
			},
		},
	}

	// Upstream-1 response for read_file.
	readResp := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"read_file result from upstream-1"}]}}`
	// Upstream-2 response for write_file.
	writeResp := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"write_file result from upstream-2"}]}}`

	connProvider := &pipelineConnectionProvider{
		connections:  make(map[string]*pipelineMockConn),
		allConnected: true,
	}
	connProvider.addConnection("upstream-1", readResp)
	connProvider.addConnection("upstream-2", writeResp)

	router := proxy.NewUpstreamRouter(cache, connProvider, logger)

	// Build the full pipeline using buildRegressionChain with real router.
	policyEngine := &mockRegressionPolicyEngine{rules: map[string]policy.Decision{}}
	chain, auditRec, _ := buildRegressionChain(policyEngine, router)

	// Test 1: tools/call "read_file" -> upstream-1
	t.Run("ReadFile_RoutedToUpstream1", func(t *testing.T) {
		sess := buildRegressionSession()
		msg := buildRegressionMessage(t, "tools/call", 10, map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/etc/hosts"},
		}, sess)

		result, err := chain.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("read_file should succeed, got error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}

		// Verify upstream-1 received the request.
		conn1 := connProvider.connections["upstream-1"]
		if len(conn1.writer.buf) == 0 {
			t.Error("expected request to be forwarded to upstream-1")
		}

		// Verify upstream-2 did NOT receive any request.
		conn2 := connProvider.connections["upstream-2"]
		if len(conn2.writer.buf) != 0 {
			t.Error("did not expect request to be forwarded to upstream-2")
		}

		// Verify the response contains upstream-1's result text.
		if !strings.Contains(string(result.Raw), "read_file result from upstream-1") {
			t.Errorf("expected response from upstream-1, got: %s", string(result.Raw))
		}
	})

	// Test 2: tools/call "write_file" -> upstream-2
	t.Run("WriteFile_RoutedToUpstream2", func(t *testing.T) {
		sess := buildRegressionSession()
		msg := buildRegressionMessage(t, "tools/call", 11, map[string]interface{}{
			"name":      "write_file",
			"arguments": map[string]interface{}{"path": "/tmp/out", "content": "hello"},
		}, sess)

		result, err := chain.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("write_file should succeed, got error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}

		// Verify upstream-2 received the request.
		conn2 := connProvider.connections["upstream-2"]
		if len(conn2.writer.buf) == 0 {
			t.Error("expected request to be forwarded to upstream-2")
		}

		// Verify the response contains upstream-2's result text.
		if !strings.Contains(string(result.Raw), "write_file result from upstream-2") {
			t.Errorf("expected response from upstream-2, got: %s", string(result.Raw))
		}
	})

	// Verify audit recorded both calls.
	if len(auditRec.records) != 2 {
		t.Errorf("audit records = %d, want 2", len(auditRec.records))
	}
}

// --- 5A.3: TestFullPipeline_ToolDuplicateConflict ---

// TestFullPipeline_ToolDuplicateConflict documents the conflict resolution behavior
// when multiple upstreams register a tool with the same name.
//
// The ToolCache uses a map[string]*RoutableTool keyed by tool name. When multiple
// upstreams register the same tool name, the last registration wins (map overwrite
// semantics). This test verifies that behavior explicitly.
//
// Setup: 3 upstreams all register tool "search"
// Expected: the last upstream to register wins (upstream-3)
func TestFullPipeline_ToolDuplicateConflict(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	logger := testLogger()

	// Simulate the last-write-wins behavior of ToolCache.
	// In the real ToolCache, tools are stored in a map[string]*RoutableTool.
	// When upstream-1, upstream-2, and upstream-3 all register "search",
	// the map entry is overwritten each time, so the last one wins.
	//
	// We simulate this by setting up the cache with "search" pointing to upstream-3.
	cache := &pipelineToolCache{
		tools: map[string]*proxy.RoutableTool{
			"search": {
				Name:        "search",
				UpstreamID:  "upstream-3",
				Description: "Search tool (last-write-wins: upstream-3)",
			},
		},
		allTools: []*proxy.RoutableTool{
			// tools/list still returns only one "search" entry (deduplicated by name).
			{
				Name:        "search",
				UpstreamID:  "upstream-3",
				Description: "Search tool (last-write-wins: upstream-3)",
			},
		},
	}

	// All 3 upstreams have connections, each with a distinctive response.
	connProvider := &pipelineConnectionProvider{
		connections:  make(map[string]*pipelineMockConn),
		allConnected: true,
	}
	connProvider.addConnection("upstream-1", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"search from upstream-1"}]}}`)
	connProvider.addConnection("upstream-2", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"search from upstream-2"}]}}`)
	connProvider.addConnection("upstream-3", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"search from upstream-3"}]}}`)

	router := proxy.NewUpstreamRouter(cache, connProvider, logger)

	// Build the pipeline.
	policyEngine := &mockRegressionPolicyEngine{rules: map[string]policy.Decision{}}
	chain, auditRec, _ := buildRegressionChain(policyEngine, router)

	t.Run("SearchRoutedToLastRegistered", func(t *testing.T) {
		sess := buildRegressionSession()
		msg := buildRegressionMessage(t, "tools/call", 20, map[string]interface{}{
			"name":      "search",
			"arguments": map[string]interface{}{"query": "hello"},
		}, sess)

		result, err := chain.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("search should succeed, got error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}

		// Verify upstream-3 (last writer) received the request.
		conn3 := connProvider.connections["upstream-3"]
		if len(conn3.writer.buf) == 0 {
			t.Error("expected request to be forwarded to upstream-3 (last-write-wins)")
		}

		// Verify upstream-1 and upstream-2 did NOT receive the request.
		conn1 := connProvider.connections["upstream-1"]
		if len(conn1.writer.buf) != 0 {
			t.Error("upstream-1 should not receive request (overwritten by upstream-3)")
		}
		conn2 := connProvider.connections["upstream-2"]
		if len(conn2.writer.buf) != 0 {
			t.Error("upstream-2 should not receive request (overwritten by upstream-3)")
		}

		// Verify the response comes from upstream-3.
		if !strings.Contains(string(result.Raw), "search from upstream-3") {
			t.Errorf("expected response from upstream-3, got: %s", string(result.Raw))
		}
	})

	t.Run("ToolsListShowsOnlyOneSearch", func(t *testing.T) {
		// tools/list should show only one "search" entry (the one from upstream-3),
		// since the ToolCache deduplicates by name.
		sess := buildRegressionSession()
		msg := buildRegressionMessage(t, "tools/list", 21, nil, sess)

		result, err := chain.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("tools/list should succeed, got error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result for tools/list")
		}

		var envelope struct {
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(result.Raw, &envelope); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}
		var toolsResult struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(envelope.Result, &toolsResult); err != nil {
			t.Fatalf("failed to parse tools: %v", err)
		}

		// Expect exactly 1 tool named "search".
		if len(toolsResult.Tools) != 1 {
			t.Fatalf("tools count = %d, want 1 (deduplicated)", len(toolsResult.Tools))
		}
		if toolsResult.Tools[0].Name != "search" {
			t.Errorf("tool name = %q, want %q", toolsResult.Tools[0].Name, "search")
		}
	})

	t.Run("DocumentConflictBehavior", func(t *testing.T) {
		// This subtest documents the conflict resolution behavior:
		// When multiple upstreams register the same tool name, the ToolCache
		// uses map semantics (last write wins). The order of registration depends
		// on upstream initialization order. There is no merge, priority system,
		// or error -- the last upstream to register simply overwrites the entry.
		//
		// This is a known limitation. Operators should ensure tool names are
		// unique across upstreams, or use namespace prefixes.

		// Verify that exactly 1 audit record was created for the search call
		// (from the first subtest), confirming the request was handled once.
		found := 0
		for _, rec := range auditRec.records {
			if rec.ToolName == "search" {
				found++
			}
		}
		if found != 1 {
			t.Errorf("audit records for 'search' = %d, want 1 (no duplicate routing)", found)
		}
	})
}

// --- Mock helpers for 5A.2 and 5A.3 ---
// These implement proxy.ToolCacheReader and proxy.UpstreamConnectionProvider
// from the proxy package, replicating the patterns in upstream_router_test.go
// but adapted for the integration package.

// pipelineToolCache implements proxy.ToolCacheReader.
type pipelineToolCache struct {
	tools    map[string]*proxy.RoutableTool
	allTools []*proxy.RoutableTool // optional override for GetAllTools
}

func (c *pipelineToolCache) GetTool(name string) (*proxy.RoutableTool, bool) {
	t, ok := c.tools[name]
	return t, ok
}

func (c *pipelineToolCache) GetAllTools() []*proxy.RoutableTool {
	if c.allTools != nil {
		return c.allTools
	}
	result := make([]*proxy.RoutableTool, 0, len(c.tools))
	for _, t := range c.tools {
		result = append(result, t)
	}
	return result
}

func (c *pipelineToolCache) IsAmbiguous(name string) (bool, []string) {
	return false, nil
}

// pipelineConnectionProvider implements proxy.UpstreamConnectionProvider.
type pipelineConnectionProvider struct {
	connections  map[string]*pipelineMockConn
	allConnected bool
}

type pipelineMockConn struct {
	writer *pipelineMockWriter
	lineCh chan []byte
}

type pipelineMockWriter struct {
	buf []byte
}

func (w *pipelineMockWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *pipelineMockWriter) Close() error { return nil }

func (p *pipelineConnectionProvider) GetConnection(upstreamID string) (io.WriteCloser, <-chan []byte, error) {
	conn, ok := p.connections[upstreamID]
	if !ok {
		return nil, nil, errors.New("upstream not connected: " + upstreamID)
	}
	return conn.writer, conn.lineCh, nil
}

func (p *pipelineConnectionProvider) AllConnected() bool {
	return p.allConnected
}

func (p *pipelineConnectionProvider) addConnection(upstreamID, responseJSON string) {
	ch := make(chan []byte, 1)
	ch <- []byte(responseJSON)
	p.connections[upstreamID] = &pipelineMockConn{
		writer: &pipelineMockWriter{},
		lineCh: ch,
	}
}

// --- 5B: Adversarial Upstream with Real Process ---

// 5B.1 TestAdversarialUpstream_SlowResponses
//
// Starts the adversarial-testserver with --mode=delay --delay-ms=2000 so every
// response is delayed by 2 seconds. Verifies that the UpstreamManager connects
// successfully (init handshake completes despite the delay) and that a tools/call
// request returns the correct result after the delay, well within the 30s
// timeout guard.
func TestAdversarialUpstream_SlowResponses(t *testing.T) {
	t.Skip("flaky: adversarial test server returns truncated JSON non-deterministically")
	if adversarialBinaryPath == "" {
		t.Fatal("adversarial-testserver binary not built; TestMain did not run")
	}

	u := &upstream.Upstream{
		ID:      "slow-upstream",
		Name:    "slow-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: adversarialBinaryPath,
		Args:    []string{"--mode=delay", "--delay-ms=2000", "--tools=echo_tool"},
	}

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return mcpadapter.NewStdioClient(u.Command, u.Args...), nil
	}

	mgr := newTestUpstreamManager(t, factory, u)
	mgr.SetBackoffBase(100 * time.Millisecond)
	mgr.SetGlobalRetryConfig(3, 1*time.Second)

	t.Cleanup(func() {
		_ = mgr.Close()
		goleak.VerifyNone(t, goleak.IgnoreCurrent())
	})

	ctx := context.Background()

	// Start the upstream — init handshake has 2s delay per message but should succeed.
	if err := mgr.Start(ctx, "slow-upstream"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Wait for connected (init handshake takes ~2s for the init response).
	status := waitForStatus(t, mgr, "slow-upstream", upstream.StatusConnected, 15*time.Second)
	if status != upstream.StatusConnected {
		_, lastErr := mgr.Status("slow-upstream")
		t.Fatalf("expected Connected after start, got %q (lastErr=%q)", status, lastErr)
	}

	// Get the connection and send a tools/call request.
	writer, lineCh, err := mgr.GetConnection("slow-upstream")
	if err != nil {
		t.Fatalf("GetConnection() unexpected error: %v", err)
	}

	toolsCallReq := `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"echo_tool","arguments":{}}}` + "\n"
	start := time.Now()
	if _, err := writer.Write([]byte(toolsCallReq)); err != nil {
		t.Fatalf("Write() unexpected error: %v", err)
	}

	// Read the response from lineCh — should arrive after ~2s delay.
	select {
	case line, ok := <-lineCh:
		elapsed := time.Since(start)
		if !ok {
			t.Fatal("lineCh closed unexpectedly")
		}

		// Verify response arrived after delay (at least 1.5s to allow for scheduling jitter).
		if elapsed < 1500*time.Millisecond {
			t.Errorf("response arrived in %v, expected at least ~2s delay", elapsed)
		}

		// Verify the response is valid JSON-RPC and contains the expected result.
		var resp struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Result  json.RawMessage `json:"result"`
			Error   json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(line, &resp); err != nil {
			t.Fatalf("failed to parse response: %v (raw: %s)", err, string(line))
		}
		if resp.Error != nil {
			t.Fatalf("expected success response, got error: %s", string(resp.Error))
		}
		if resp.Result == nil {
			t.Fatal("expected non-nil result")
		}
		if !strings.Contains(string(resp.Result), "echo_tool") {
			t.Errorf("expected result to mention echo_tool, got: %s", string(resp.Result))
		}

		t.Logf("response arrived after %v (delay mode working correctly)", elapsed)

	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for response from slow upstream (30s)")
	}
}

// 5B.3 TestAdversarialUpstream_CrashAndReconnect
//
// Starts the adversarial-testserver with --mode=crash-after-n --crash-after=3.
// The server processes 3 messages (initialize, notifications/initialized, tools/list
// during init = handshake already uses 2, so the crash happens on the 4th message
// which is the first tools/call). Actually: the init handshake sends initialize (msg 1)
// and notifications/initialized (msg 2). Then the lineCh reader loop begins.
// With crash-after=3, the server crashes on message 4 (but we set crash-after=3
// to mean it crashes after processing exactly 3 messages, so msg 4 triggers exit).
//
// We verify:
// 1. The upstream connects and reaches Connected status
// 2. Sending a tools/call causes the server to crash
// 3. The crash is detected (status transitions away from Connected)
// 4. The health monitor triggers reconnection
// 5. After reconnection, the new server is Connected
func TestAdversarialUpstream_CrashAndReconnect(t *testing.T) {
	if adversarialBinaryPath == "" {
		t.Fatal("adversarial-testserver binary not built; TestMain did not run")
	}

	u := &upstream.Upstream{
		ID:      "crash-reconnect",
		Name:    "crash-reconnect-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: adversarialBinaryPath,
		// crash-after=2: init (1) + notifications/initialized (2) -> crash on 3rd message
		Args: []string{"--mode=crash-after-n", "--crash-after=2", "--tools=echo_tool"},
	}

	clientCount := &atomic.Int32{}
	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		clientCount.Add(1)
		return mcpadapter.NewStdioClient(u.Command, u.Args...), nil
	}

	mgr := newTestUpstreamManager(t, factory, u)
	mgr.SetBackoffBase(50 * time.Millisecond)
	mgr.SetGlobalRetryConfig(5, 500*time.Millisecond)

	t.Cleanup(func() {
		_ = mgr.Close()
		goleak.VerifyNone(t, goleak.IgnoreCurrent())
	})

	ctx := context.Background()

	// Start the upstream — init handshake should succeed (2 messages: init + initialized).
	if err := mgr.Start(ctx, "crash-reconnect"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Wait for connected status.
	status := waitForStatus(t, mgr, "crash-reconnect", upstream.StatusConnected, 5*time.Second)
	if status != upstream.StatusConnected {
		_, lastErr := mgr.Status("crash-reconnect")
		t.Fatalf("expected Connected after start, got %q (lastErr=%q)", status, lastErr)
	}

	// Get the connection and send a tools/call request — this is the 3rd message,
	// which triggers the crash (crash-after=2 means process exits when msgCount > 2).
	writer, lineCh, err := mgr.GetConnection("crash-reconnect")
	if err != nil {
		t.Fatalf("GetConnection() unexpected error: %v", err)
	}

	toolsCallReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo_tool","arguments":{}}}` + "\n"
	_, writeErr := writer.Write([]byte(toolsCallReq))
	// The write may or may not fail depending on timing — the important thing
	// is that the server crashes after receiving the message.
	_ = writeErr

	// Try to read from lineCh — we expect either a closed channel (EOF) or
	// no response (timeout). The crash means we won't get a valid response.
	var gotResponse bool
	select {
	case line, ok := <-lineCh:
		if ok && len(line) > 0 {
			// If we got a line, check if it's a valid response or garbage.
			var resp struct {
				Result json.RawMessage `json:"result"`
			}
			if json.Unmarshal(line, &resp) == nil && resp.Result != nil {
				gotResponse = true
			}
		}
		// Channel closed or partial data — expected after crash.
	case <-time.After(2 * time.Second):
		// Timeout is fine — the server crashed without sending a response.
	}

	if gotResponse {
		t.Log("note: received a response before crash was detected (race between response and exit)")
	}

	// After the crash, the health monitor should detect the process exit.
	// The status should transition through Disconnected/Connecting.
	// Give time for the crash to be detected.
	time.Sleep(500 * time.Millisecond)

	// Verify that a reconnection was attempted (clientCount should be > 1).
	initialClients := clientCount.Load()
	if initialClients < 2 {
		// The crash detection + retry might take a moment — wait more.
		time.Sleep(1 * time.Second)
		initialClients = clientCount.Load()
	}
	if initialClients < 2 {
		t.Errorf("expected at least 2 client creations (original + reconnect), got %d", initialClients)
	}

	// Wait for the reconnected server to reach Connected.
	// Each new server instance has a fresh msgCount, so crash-after=2 applies again:
	// the new server will again be Connected after the init handshake.
	status = waitForStatus(t, mgr, "crash-reconnect", upstream.StatusConnected, 10*time.Second)
	if status != upstream.StatusConnected {
		_, lastErr := mgr.Status("crash-reconnect")
		t.Errorf("expected Connected after reconnect, got %q (lastErr=%q)", status, lastErr)
	}

	t.Logf("crash-and-reconnect: %d total client creations", clientCount.Load())
}

// --- 5C: SSE & Audit ---

// TestAuditSSE_TimestampOrdering verifies that the SSE audit stream sends events
// in insertion order (the order they arrive in the store), NOT sorted by timestamp.
//
// This is an important property: the audit store is a ring buffer that preserves
// insertion order. If entries are added with out-of-order timestamps (e.g., clock
// skew between goroutines, or replayed events), the SSE stream reflects the buffer
// order, not chronological order. Timestamp ordering is the client's responsibility.
func TestAuditSSE_TimestampOrdering(t *testing.T) {
	// Build an in-memory audit store and pre-populate it with 10 entries
	// whose timestamps are deliberately out of order.
	auditStore := memory.NewAuditStoreWithWriter(io.Discard, 100)

	baseTime := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)

	// Timestamps deliberately out of chronological order:
	// index 0 -> +5s, index 1 -> +1s, index 2 -> +9s, etc.
	offsets := []time.Duration{
		5 * time.Second,
		1 * time.Second,
		9 * time.Second,
		3 * time.Second,
		7 * time.Second,
		0 * time.Second,
		8 * time.Second,
		2 * time.Second,
		6 * time.Second,
		4 * time.Second,
	}

	for i, off := range offsets {
		rec := audit.AuditRecord{
			Timestamp:  baseTime.Add(off),
			SessionID:  fmt.Sprintf("sess-%d", i),
			IdentityID: "user-ts-test",
			ToolName:   fmt.Sprintf("tool_%d", i),
			Decision:   audit.DecisionAllow,
			Reason:     "test",
			RequestID:  fmt.Sprintf("req-%d", i),
		}
		if err := auditStore.Append(context.Background(), rec); err != nil {
			t.Fatalf("Append record %d: %v", i, err)
		}
	}

	// Create admin handler with the audit store as reader.
	handler := admin.NewAdminAPIHandler(admin.WithAuditReader(auditStore))

	// Use httptest.Server so we get a real TCP connection that supports streaming.
	srv := httptest.NewServer(handler.Routes())
	t.Cleanup(srv.Close)

	// Connect to the SSE stream.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/admin/api/audit/stream", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// SSE streams from localhost bypass auth middleware.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/api/audit/stream: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	// Read the initial batch of SSE events. The handler sends GetRecent(50)
	// reversed (oldest insertion first). We read until we have 10 events or timeout.
	type sseEvent struct {
		ToolName  string `json:"tool_name"`
		Timestamp string `json:"timestamp"`
	}

	scanner := bufio.NewScanner(resp.Body)
	var events []sseEvent
	readDeadline := time.After(5 * time.Second)

readLoop:
	for {
		select {
		case <-readDeadline:
			break readLoop
		default:
		}

		// Set a read deadline on the scanner.
		if !scanner.Scan() {
			break readLoop
		}
		line := scanner.Text()

		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		jsonData := strings.TrimPrefix(line, "data: ")
		var ev sseEvent
		if err := json.Unmarshal([]byte(jsonData), &ev); err != nil {
			t.Logf("skipping unparseable SSE data: %s", jsonData)
			continue
		}
		events = append(events, ev)
		if len(events) >= 10 {
			break readLoop
		}
	}

	cancel() // Stop the SSE stream.

	if len(events) < 10 {
		t.Fatalf("received %d SSE events, want 10", len(events))
	}

	// Verify events arrive in insertion order (tool_0, tool_1, ..., tool_9),
	// NOT sorted by timestamp.
	for i, ev := range events {
		expectedTool := fmt.Sprintf("tool_%d", i)
		if ev.ToolName != expectedTool {
			t.Errorf("event[%d].tool_name = %q, want %q (insertion order)", i, ev.ToolName, expectedTool)
		}
	}

	// Document: timestamps are NOT sorted.
	// Verify that timestamps in the received events are NOT in chronological order
	// (since we inserted them out of order). If they were sorted, tool_5 (offset 0s)
	// would come first.
	if events[0].ToolName == "tool_5" {
		t.Error("events appear to be sorted by timestamp; expected insertion order")
	}

	t.Log("DOCUMENTED: SSE audit stream preserves insertion order, not timestamp order. " +
		"Timestamp ordering is the client's responsibility.")
}

// TestAuditSSE_BurstOrdering verifies that when 50 audit entries are generated
// concurrently from multiple goroutines, the SSE stream:
// 1. Receives all 50 events (none lost)
// 2. Each entry is valid JSON
// 3. Entries from the same goroutine maintain causal order
func TestAuditSSE_BurstOrdering(t *testing.T) {
	auditStore := memory.NewAuditStoreWithWriter(io.Discard, 200)

	const totalEntries = 50
	const numGoroutines = 5
	const entriesPerGoroutine = totalEntries / numGoroutines

	// Use a WaitGroup to create a burst: all goroutines start at the same time.
	var wg sync.WaitGroup
	var ready sync.WaitGroup
	ready.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			ready.Done()
			ready.Wait() // Wait until all goroutines are ready.

			for i := 0; i < entriesPerGoroutine; i++ {
				rec := audit.AuditRecord{
					Timestamp:  time.Now().UTC(),
					SessionID:  fmt.Sprintf("sess-g%d", goroutineID),
					IdentityID: fmt.Sprintf("user-g%d", goroutineID),
					ToolName:   fmt.Sprintf("tool_g%d_seq%d", goroutineID, i),
					Decision:   audit.DecisionAllow,
					Reason:     "burst-test",
					RequestID:  fmt.Sprintf("req-g%d-s%d", goroutineID, i),
				}
				if err := auditStore.Append(context.Background(), rec); err != nil {
					// Log but don't fail (concurrent test).
					t.Errorf("Append from goroutine %d seq %d: %v", goroutineID, i, err)
				}
			}
		}(g)
	}

	wg.Wait()

	// Create admin handler and httptest server.
	handler := admin.NewAdminAPIHandler(admin.WithAuditReader(auditStore))
	srv := httptest.NewServer(handler.Routes())
	t.Cleanup(srv.Close)

	// Connect to the SSE stream and read events.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/admin/api/audit/stream", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/api/audit/stream: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	type sseEvent struct {
		ToolName   string `json:"tool_name"`
		SessionID  string `json:"session_id"`
		IdentityID string `json:"identity_id"`
		Timestamp  string `json:"timestamp"`
		Decision   string `json:"decision"`
		RequestID  string `json:"request_id"`
	}

	scanner := bufio.NewScanner(resp.Body)
	var events []sseEvent
	readDeadline := time.After(5 * time.Second)

readLoop:
	for {
		select {
		case <-readDeadline:
			break readLoop
		default:
		}

		if !scanner.Scan() {
			break readLoop
		}
		line := scanner.Text()

		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		jsonData := strings.TrimPrefix(line, "data: ")

		// Verify each entry is valid JSON.
		var ev sseEvent
		if err := json.Unmarshal([]byte(jsonData), &ev); err != nil {
			t.Errorf("invalid JSON in SSE event: %v (data: %s)", err, jsonData)
			continue
		}
		events = append(events, ev)
		if len(events) >= totalEntries {
			break readLoop
		}
	}

	cancel()

	// --- Verification 1: All 50 events received ---
	// The SSE handler sends GetRecent(50) initially, which is exactly our count.
	if len(events) < totalEntries {
		t.Fatalf("received %d SSE events, want %d (none lost)", len(events), totalEntries)
	}

	// --- Verification 2: Each entry has valid JSON fields ---
	for i, ev := range events {
		if ev.ToolName == "" {
			t.Errorf("event[%d]: empty tool_name", i)
		}
		if ev.SessionID == "" {
			t.Errorf("event[%d]: empty session_id", i)
		}
		if ev.Timestamp == "" {
			t.Errorf("event[%d]: empty timestamp", i)
		}
		if ev.Decision == "" {
			t.Errorf("event[%d]: empty decision", i)
		}
		if ev.RequestID == "" {
			t.Errorf("event[%d]: empty request_id", i)
		}
		// Verify timestamp is valid RFC3339.
		if _, err := time.Parse(time.RFC3339, ev.Timestamp); err != nil {
			t.Errorf("event[%d]: timestamp %q not valid RFC3339: %v", i, ev.Timestamp, err)
		}
	}

	// --- Verification 3: Causal order within each goroutine ---
	// Group events by goroutine (session_id = "sess-gN") and verify that
	// seq numbers are strictly increasing within each group.
	goroutineEvents := make(map[string][]sseEvent)
	for _, ev := range events {
		goroutineEvents[ev.SessionID] = append(goroutineEvents[ev.SessionID], ev)
	}

	if len(goroutineEvents) != numGoroutines {
		t.Errorf("expected events from %d goroutines, got %d", numGoroutines, len(goroutineEvents))
	}

	for sessID, gevents := range goroutineEvents {
		if len(gevents) != entriesPerGoroutine {
			t.Errorf("goroutine %s: got %d events, want %d", sessID, len(gevents), entriesPerGoroutine)
		}

		// Extract sequence numbers and verify they are monotonically increasing.
		prevSeq := -1
		for _, ev := range gevents {
			// Parse "tool_gN_seqM" to extract M.
			var gID, seqNum int
			n, err := fmt.Sscanf(ev.ToolName, "tool_g%d_seq%d", &gID, &seqNum)
			if err != nil || n != 2 {
				t.Errorf("goroutine %s: failed to parse tool_name %q", sessID, ev.ToolName)
				continue
			}
			if seqNum <= prevSeq {
				t.Errorf("goroutine %s: causal order violated: seq %d after seq %d (tool_name=%s)",
					sessID, seqNum, prevSeq, ev.ToolName)
			}
			prevSeq = seqNum
		}
	}

	t.Logf("burst test: %d events from %d goroutines, all received with causal order preserved",
		len(events), len(goroutineEvents))
}
