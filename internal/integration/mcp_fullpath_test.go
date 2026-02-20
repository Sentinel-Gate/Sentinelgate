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

// --- Mock types for MCP full path test ---

// mockPolicyEngine returns a configurable policy.Decision.
type mockPolicyEngine struct {
	decision policy.Decision
}

func (m *mockPolicyEngine) Evaluate(_ context.Context, _ policy.EvaluationContext) (policy.Decision, error) {
	return m.decision, nil
}

// mockAuditRecorder captures audit records.
type mockAuditRecorder struct {
	records []audit.AuditRecord
}

func (m *mockAuditRecorder) Record(record audit.AuditRecord) {
	m.records = append(m.records, record)
}

// mockStatsRecorder tracks allow/deny/rate-limit counts.
type mockStatsRecorder struct {
	allows      int
	denies      int
	rateLimited int
	protocols   []string
	frameworks  []string
}

func (m *mockStatsRecorder) RecordAllow()       { m.allows++ }
func (m *mockStatsRecorder) RecordDeny()        { m.denies++ }
func (m *mockStatsRecorder) RecordRateLimited() { m.rateLimited++ }
func (m *mockStatsRecorder) RecordProtocol(protocol string) {
	m.protocols = append(m.protocols, protocol)
}
func (m *mockStatsRecorder) RecordFramework(fw string) { m.frameworks = append(m.frameworks, fw) }

// newTestToolCallMessage creates an mcp.Message for a tools/call request with session context.
func newTestToolCallMessage(toolName string, args map[string]interface{}, sess *session.Session) *mcp.Message {
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	}
	paramsJSON, _ := json.Marshal(params)

	rawMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  json.RawMessage(paramsJSON),
	}
	rawBytes, _ := json.Marshal(rawMsg)

	id, _ := jsonrpc.MakeID(float64(1))
	req := &jsonrpc.Request{
		ID:     id,
		Method: "tools/call",
		Params: paramsJSON,
	}

	return &mcp.Message{
		Raw:       rawBytes,
		Direction: mcp.ClientToServer,
		Decoded:   req,
		Timestamp: time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC),
		Session:   sess,
	}
}

// newTestServerResponse creates a server-to-client mcp.Message simulating a tool result.
func newTestServerResponse() *mcp.Message {
	result := map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": "File contents: hello world"},
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

func newTestSession() *session.Session {
	return &session.Session{
		ID:           "sess-integ-001",
		IdentityID:   "id-integ-001",
		IdentityName: "integration-test-user",
		Roles:        []auth.Role{auth.RoleUser},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		LastAccess:   time.Now().UTC(),
	}
}

// TestMCPFullPath_AllowedToolCall validates the full MCP chain for an allowed tool call:
// AuditInterceptor -> InterceptorChain(MCPNormalizer -> PolicyActionInterceptor ->
// OutboundInterceptor -> ResponseScanInterceptor -> terminal) -> audit recording.
func TestMCPFullPath_AllowedToolCall(t *testing.T) {
	logger := testLogger()

	// 1. Mock policy engine returning allow
	engine := &mockPolicyEngine{
		decision: policy.Decision{
			Allowed:  true,
			RuleID:   "rule-allow-all",
			RuleName: "Allow All",
			Reason:   "allowed by test policy",
		},
	}

	// 2. ResponseScanner + terminal interceptor that returns a canned server response
	scanner := action.NewResponseScanner()
	serverResponse := newTestServerResponse()

	terminal := action.ActionInterceptorFunc(func(ctx context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
		// Simulate upstream router returning a server-to-client response
		a.OriginalMessage = serverResponse
		return a, nil
	})

	// 3. Wire: ResponseScanInterceptor -> terminal
	responseScanInterceptor := action.NewResponseScanInterceptor(scanner, terminal, action.ScanModeMonitor, true, logger)

	// 4. Wire: OutboundInterceptor (empty rules) -> ResponseScanInterceptor
	dnsResolver := action.NewDNSResolver(logger)
	outboundInterceptor := action.NewOutboundInterceptor(nil, dnsResolver, responseScanInterceptor, logger)

	// 5. Wire: PolicyActionInterceptor -> OutboundInterceptor
	policyInterceptor := action.NewPolicyActionInterceptor(engine, outboundInterceptor, logger)

	// 6. MCPNormalizer + InterceptorChain wrapping PolicyActionInterceptor
	normalizer := action.NewMCPNormalizer()
	chain := action.NewInterceptorChain(normalizer, policyInterceptor, logger)

	// 7. Mock AuditRecorder + StatsRecorder
	auditRec := &mockAuditRecorder{}
	statsRec := &mockStatsRecorder{}

	// 8. AuditInterceptor wrapping the InterceptorChain
	auditInterceptor := proxy.NewAuditInterceptor(auditRec, statsRec, chain, logger)

	// 9. Build a valid MCP tool call message with session context
	sess := newTestSession()
	toolCallMsg := newTestToolCallMessage("read_file", map[string]interface{}{"path": "/tmp/data.txt"}, sess)

	// Execute
	result, err := auditInterceptor.Intercept(context.Background(), toolCallMsg)

	// Assert: no error
	if err != nil {
		t.Fatalf("Intercept() returned error for allowed tool call: %v", err)
	}

	// Assert: response message is non-nil and is ServerToClient
	if result == nil {
		t.Fatal("Intercept() returned nil message for allowed tool call")
	}
	if result.Direction != mcp.ServerToClient {
		t.Errorf("result.Direction = %v, want ServerToClient", result.Direction)
	}

	// Assert: audit recorder received exactly 1 record
	if len(auditRec.records) != 1 {
		t.Fatalf("audit records count = %d, want 1", len(auditRec.records))
	}
	record := auditRec.records[0]
	if record.ToolName != "read_file" {
		t.Errorf("audit ToolName = %q, want %q", record.ToolName, "read_file")
	}
	if record.SessionID != "sess-integ-001" {
		t.Errorf("audit SessionID = %q, want %q", record.SessionID, "sess-integ-001")
	}
	if record.Decision != audit.DecisionAllow {
		t.Errorf("audit Decision = %q, want %q", record.Decision, audit.DecisionAllow)
	}

	// Assert: stats recorder had RecordAllow() called
	if statsRec.allows != 1 {
		t.Errorf("stats allows = %d, want 1", statsRec.allows)
	}
	if statsRec.denies != 0 {
		t.Errorf("stats denies = %d, want 0", statsRec.denies)
	}
}

// TestMCPFullPath_DeniedToolCall validates the full MCP chain for a denied tool call.
func TestMCPFullPath_DeniedToolCall(t *testing.T) {
	logger := testLogger()

	// 1. Mock policy engine returning deny
	engine := &mockPolicyEngine{
		decision: policy.Decision{
			Allowed:  false,
			RuleID:   "rule-deny-exec",
			RuleName: "Deny Exec",
			Reason:   "exec tools are blocked",
		},
	}

	// 2. Terminal interceptor (should NOT be reached for denied calls)
	terminal := action.ActionInterceptorFunc(func(ctx context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
		t.Error("terminal interceptor should not be called for denied tool calls")
		return a, nil
	})

	// 3. Wire the chain: scan -> terminal, outbound -> scan, policy -> outbound
	scanner := action.NewResponseScanner()
	responseScanInterceptor := action.NewResponseScanInterceptor(scanner, terminal, action.ScanModeMonitor, true, logger)
	dnsResolver := action.NewDNSResolver(logger)
	outboundInterceptor := action.NewOutboundInterceptor(nil, dnsResolver, responseScanInterceptor, logger)
	policyInterceptor := action.NewPolicyActionInterceptor(engine, outboundInterceptor, logger)

	// 4. InterceptorChain + AuditInterceptor
	normalizer := action.NewMCPNormalizer()
	chain := action.NewInterceptorChain(normalizer, policyInterceptor, logger)
	auditRec := &mockAuditRecorder{}
	statsRec := &mockStatsRecorder{}
	auditInterceptor := proxy.NewAuditInterceptor(auditRec, statsRec, chain, logger)

	// 5. Build tool call message
	sess := newTestSession()
	toolCallMsg := newTestToolCallMessage("exec_command", map[string]interface{}{"cmd": "rm -rf /"}, sess)

	// Execute
	_, err := auditInterceptor.Intercept(context.Background(), toolCallMsg)

	// Assert: error wraps proxy.ErrPolicyDenied
	if err == nil {
		t.Fatal("Intercept() should return error for denied tool call")
	}
	if !errors.Is(err, proxy.ErrPolicyDenied) {
		t.Errorf("error should wrap ErrPolicyDenied, got: %v", err)
	}

	// Assert: audit recorder received exactly 1 record with denied=true
	if len(auditRec.records) != 1 {
		t.Fatalf("audit records count = %d, want 1", len(auditRec.records))
	}
	record := auditRec.records[0]
	if record.Decision != audit.DecisionDeny {
		t.Errorf("audit Decision = %q, want %q", record.Decision, audit.DecisionDeny)
	}
	if record.ToolName != "exec_command" {
		t.Errorf("audit ToolName = %q, want %q", record.ToolName, "exec_command")
	}

	// Assert: stats recorder had RecordDeny() called
	if statsRec.denies != 1 {
		t.Errorf("stats denies = %d, want 1", statsRec.denies)
	}
	if statsRec.allows != 0 {
		t.Errorf("stats allows = %d, want 0", statsRec.allows)
	}
}
