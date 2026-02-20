package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// --- Mock types for MCP regression tests ---

// mockUpstreamRouter simulates an upstream MCP server that returns
// canned responses for tools/call and tools/list.
type mockUpstreamRouter struct {
	toolCallResponse *mcp.Message
	toolListResponse *mcp.Message
}

func (m *mockUpstreamRouter) Intercept(_ context.Context, msg *mcp.Message) (*mcp.Message, error) {
	method := msg.Method()
	switch method {
	case "tools/list":
		if m.toolListResponse != nil {
			return m.toolListResponse, nil
		}
	case "tools/call":
		if m.toolCallResponse != nil {
			return m.toolCallResponse, nil
		}
	}
	// Pass through notifications and other messages
	return msg, nil
}

// mockRegressionPolicyEngine is a configurable policy engine for regression tests.
type mockRegressionPolicyEngine struct {
	rules map[string]policy.Decision // tool name -> decision
}

func (m *mockRegressionPolicyEngine) Evaluate(_ context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
	if decision, ok := m.rules[evalCtx.ToolName]; ok {
		return decision, nil
	}
	// Default: allow if not in rules map
	return policy.Decision{
		Allowed: true,
		RuleID:  "default-allow",
		Reason:  "no matching deny rule",
	}, nil
}

// --- Helper constructors ---

// buildRegressionUpstreamResponse creates a standard upstream tools/call response.
func buildRegressionUpstreamResponse(content string) *mcp.Message {
	result := map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": content},
		},
	}
	resultJSON, _ := json.Marshal(result)

	rawMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  json.RawMessage(resultJSON),
	}
	rawBytes, _ := json.Marshal(rawMsg)

	id, _ := jsonrpc.MakeID(float64(1))
	resp := &jsonrpc.Response{
		ID:     id,
		Result: resultJSON,
	}

	return &mcp.Message{
		Raw:       rawBytes,
		Direction: mcp.ServerToClient,
		Decoded:   resp,
		Timestamp: time.Now().UTC(),
	}
}

// buildRegressionToolListResponse creates a tools/list response listing available tools.
func buildRegressionToolListResponse(tools []string) *mcp.Message {
	toolList := make([]map[string]interface{}, len(tools))
	for i, t := range tools {
		toolList[i] = map[string]interface{}{
			"name":        t,
			"description": "Test tool " + t,
			"inputSchema": map[string]interface{}{"type": "object"},
		}
	}
	result := map[string]interface{}{
		"tools": toolList,
	}
	resultJSON, _ := json.Marshal(result)

	rawMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"result":  json.RawMessage(resultJSON),
	}
	rawBytes, _ := json.Marshal(rawMsg)

	id, _ := jsonrpc.MakeID(float64(2))
	resp := &jsonrpc.Response{
		ID:     id,
		Result: resultJSON,
	}

	return &mcp.Message{
		Raw:       rawBytes,
		Direction: mcp.ServerToClient,
		Decoded:   resp,
		Timestamp: time.Now().UTC(),
	}
}

// buildRegressionMessage creates an MCP message for regression testing.
func buildRegressionMessage(method string, id float64, params map[string]interface{}, sess *session.Session) *mcp.Message {
	var paramsJSON json.RawMessage
	if params != nil {
		paramsJSON, _ = json.Marshal(params)
	}

	rawMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if paramsJSON != nil {
		rawMsg["params"] = json.RawMessage(paramsJSON)
	}
	rawBytes, _ := json.Marshal(rawMsg)

	jid, _ := jsonrpc.MakeID(id)
	req := &jsonrpc.Request{
		ID:     jid,
		Method: method,
		Params: paramsJSON,
	}

	return &mcp.Message{
		Raw:       rawBytes,
		Direction: mcp.ClientToServer,
		Decoded:   req,
		Timestamp: time.Now().UTC(),
		Session:   sess,
	}
}

// buildRegressionSession creates a test session for regression tests.
func buildRegressionSession() *session.Session {
	return &session.Session{
		ID:           "regression-sess-001",
		IdentityID:   "regression-id-001",
		IdentityName: "regression-test-user",
		Roles:        []auth.Role{auth.RoleUser},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		LastAccess:   time.Now().UTC(),
	}
}

// buildRegressionChain creates a complete MCP interceptor chain matching the
// real boot sequence:
// AuditInterceptor -> InterceptorChain(MCPNormalizer -> PolicyActionInterceptor ->
//
//	OutboundInterceptor -> ResponseScanInterceptor -> LegacyAdapter(mockUpstreamRouter))
func buildRegressionChain(
	policyEngine policy.PolicyEngine,
	upstream proxy.MessageInterceptor,
) (proxy.MessageInterceptor, *regressionAuditRecorder, *regressionStatsRecorder) {
	logger := testLogger()

	// Terminal: LegacyAdapter wrapping mock upstream router
	terminal := action.NewLegacyAdapter(upstream, "upstream-router")

	// ResponseScanInterceptor -> terminal
	scanner := action.NewResponseScanner()
	responseScan := action.NewResponseScanInterceptor(scanner, terminal, action.ScanModeMonitor, true, logger)

	// OutboundInterceptor (empty rules for regression -- no blocking) -> ResponseScanInterceptor
	resolver := action.NewDNSResolver(logger)
	outbound := action.NewOutboundInterceptor(nil, resolver, responseScan, logger)

	// PolicyActionInterceptor -> OutboundInterceptor
	policyInterceptor := action.NewPolicyActionInterceptor(policyEngine, outbound, logger)

	// InterceptorChain: MCPNormalizer -> PolicyActionInterceptor chain
	normalizer := action.NewMCPNormalizer()
	chain := action.NewInterceptorChain(normalizer, policyInterceptor, logger)

	// AuditInterceptor wrapping InterceptorChain
	auditRec := &regressionAuditRecorder{}
	statsRec := &regressionStatsRecorder{}
	auditInterceptor := proxy.NewAuditInterceptor(auditRec, statsRec, chain, logger)

	return auditInterceptor, auditRec, statsRec
}

// regressionAuditRecorder captures audit records for assertion.
type regressionAuditRecorder struct {
	records []audit.AuditRecord
}

func (r *regressionAuditRecorder) Record(record audit.AuditRecord) {
	r.records = append(r.records, record)
}

// regressionStatsRecorder tracks stats for assertion.
type regressionStatsRecorder struct {
	allows int
	denies int
}

func (r *regressionStatsRecorder) RecordAllow()             { r.allows++ }
func (r *regressionStatsRecorder) RecordDeny()              { r.denies++ }
func (r *regressionStatsRecorder) RecordRateLimited()       {}
func (r *regressionStatsRecorder) RecordProtocol(_ string)  {}
func (r *regressionStatsRecorder) RecordFramework(_ string) {}

// --- Regression Tests ---

// TestMCPRegression_ExistingTestsUnmodified exercises the complete MCP interceptor
// chain end-to-end, confirming backward compatibility with the normalized
// CanonicalAction flow. Each subtest matches an existing MCP test scenario (TEST-09).
func TestMCPRegression_ExistingTestsUnmodified(t *testing.T) {
	// Configure policy engine: read_file allowed, exec_command denied
	policyEngine := &mockRegressionPolicyEngine{
		rules: map[string]policy.Decision{
			"read_file": {
				Allowed: true,
				RuleID:  "reg-allow-read",
				Reason:  "read tools allowed",
			},
			"exec_command": {
				Allowed: false,
				RuleID:  "reg-deny-exec",
				Reason:  "exec tools blocked",
			},
		},
	}

	// Mock upstream returns canned responses
	upstream := &mockUpstreamRouter{
		toolCallResponse: buildRegressionUpstreamResponse("File contents: hello regression test"),
		toolListResponse: buildRegressionToolListResponse([]string{"read_file", "write_file", "list_files"}),
	}

	t.Run("NonToolCallPassthrough", func(t *testing.T) {
		// Build fresh chain per subtest to isolate state
		chain, _, _ := buildRegressionChain(policyEngine, upstream)

		// In the real flow, the auth interceptor attaches a session to all
		// messages (including notifications) before they reach the chain.
		// We simulate this by attaching a session to the notification.
		sess := buildRegressionSession()

		// Send a notifications/initialized message -> should pass through without error
		// The normalizer maps unknown methods to ActionToolCall, but the
		// PolicyActionInterceptor checks session and passes through.
		notification := buildRegressionMessage("notifications/initialized", 100, nil, sess)
		result, err := chain.Intercept(context.Background(), notification)

		if err != nil {
			t.Fatalf("notifications/initialized should pass through, got error: %v", err)
		}
		// Notifications don't produce tool-call audit records for non-tools/call methods
		if result == nil {
			t.Fatal("notifications/initialized should return non-nil result")
		}
	})

	t.Run("ToolCallAllowed", func(t *testing.T) {
		chain, auditRec, statsRec := buildRegressionChain(policyEngine, upstream)
		sess := buildRegressionSession()

		// Send tools/call with allowed tool -> should return upstream response
		msg := buildRegressionMessage("tools/call", 1, map[string]interface{}{
			"name":      "read_file",
			"arguments": map[string]interface{}{"path": "/tmp/test.txt"},
		}, sess)

		result, err := chain.Intercept(context.Background(), msg)

		if err != nil {
			t.Fatalf("allowed tool call should succeed, got error: %v", err)
		}
		if result == nil {
			t.Fatal("allowed tool call should return non-nil result")
		}
		if result.Direction != mcp.ServerToClient {
			t.Errorf("result.Direction = %v, want ServerToClient", result.Direction)
		}

		// Verify audit recorded
		if len(auditRec.records) != 1 {
			t.Fatalf("audit records = %d, want 1", len(auditRec.records))
		}
		if auditRec.records[0].Decision != audit.DecisionAllow {
			t.Errorf("audit decision = %q, want %q", auditRec.records[0].Decision, audit.DecisionAllow)
		}
		if statsRec.allows != 1 {
			t.Errorf("stats allows = %d, want 1", statsRec.allows)
		}
	})

	t.Run("ToolCallDeniedByPolicy", func(t *testing.T) {
		chain, auditRec, statsRec := buildRegressionChain(policyEngine, upstream)
		sess := buildRegressionSession()

		// Send tools/call with denied tool -> should return error
		msg := buildRegressionMessage("tools/call", 3, map[string]interface{}{
			"name":      "exec_command",
			"arguments": map[string]interface{}{"cmd": "ls -la"},
		}, sess)

		_, err := chain.Intercept(context.Background(), msg)

		if err == nil {
			t.Fatal("denied tool call should return error")
		}
		if !errors.Is(err, proxy.ErrPolicyDenied) {
			t.Errorf("error should wrap ErrPolicyDenied, got: %v", err)
		}

		// Verify audit recorded deny
		if len(auditRec.records) != 1 {
			t.Fatalf("audit records = %d, want 1", len(auditRec.records))
		}
		if auditRec.records[0].Decision != audit.DecisionDeny {
			t.Errorf("audit decision = %q, want %q", auditRec.records[0].Decision, audit.DecisionDeny)
		}
		if statsRec.denies != 1 {
			t.Errorf("stats denies = %d, want 1", statsRec.denies)
		}
	})

	t.Run("ToolsListAggregation", func(t *testing.T) {
		chain, _, _ := buildRegressionChain(policyEngine, upstream)
		sess := buildRegressionSession()

		// Send tools/list -> should return aggregated tool list from mock upstream
		msg := buildRegressionMessage("tools/list", 4, nil, sess)

		result, err := chain.Intercept(context.Background(), msg)

		if err != nil {
			t.Fatalf("tools/list should succeed, got error: %v", err)
		}
		if result == nil {
			t.Fatal("tools/list should return non-nil result")
		}
		if result.Direction != mcp.ServerToClient {
			t.Errorf("result.Direction = %v, want ServerToClient", result.Direction)
		}

		// Parse and verify the response contains tools
		var envelope struct {
			Result json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(result.Raw, &envelope); err != nil {
			t.Fatalf("failed to parse tools/list response: %v", err)
		}
		var toolsResult struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(envelope.Result, &toolsResult); err != nil {
			t.Fatalf("failed to parse tools from response: %v", err)
		}
		if len(toolsResult.Tools) != 3 {
			t.Errorf("tools count = %d, want 3", len(toolsResult.Tools))
		}

		// Verify tool names
		toolNames := make(map[string]bool)
		for _, tool := range toolsResult.Tools {
			toolNames[tool.Name] = true
		}
		for _, expected := range []string{"read_file", "write_file", "list_files"} {
			if !toolNames[expected] {
				t.Errorf("missing expected tool: %q", expected)
			}
		}
	})
}

// TestMCPRegression_PackagesCompile verifies that all critical MCP types and
// constructors are accessible and compatible. This is a compile-time assertion
// exercised at runtime — if any constructor signature changes, this test fails.
func TestMCPRegression_PackagesCompile(t *testing.T) {
	logger := testLogger()

	// Verify critical constructors exist and work
	normalizer := action.NewMCPNormalizer()
	if normalizer == nil {
		t.Fatal("NewMCPNormalizer() returned nil")
	}
	if normalizer.Protocol() != "mcp" {
		t.Errorf("MCPNormalizer.Protocol() = %q, want %q", normalizer.Protocol(), "mcp")
	}

	scanner := action.NewResponseScanner()
	if scanner == nil {
		t.Fatal("NewResponseScanner() returned nil")
	}

	resolver := action.NewDNSResolver(logger)
	if resolver == nil {
		t.Fatal("NewDNSResolver() returned nil")
	}

	// Verify action types are accessible
	if action.ActionToolCall != "tool_call" {
		t.Errorf("ActionToolCall = %q, want %q", action.ActionToolCall, "tool_call")
	}
	if action.ActionHTTPRequest != "http_request" {
		t.Errorf("ActionHTTPRequest = %q, want %q", action.ActionHTTPRequest, "http_request")
	}

	// Verify scan modes are accessible
	if action.ScanModeMonitor != "monitor" {
		t.Errorf("ScanModeMonitor = %q, want %q", action.ScanModeMonitor, "monitor")
	}
	if action.ScanModeEnforce != "enforce" {
		t.Errorf("ScanModeEnforce = %q, want %q", action.ScanModeEnforce, "enforce")
	}
}
