package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// mockAuditRecorder captures recorded audit records for testing.
type mockAuditRecorder struct {
	records []audit.AuditRecord
}

func (m *mockAuditRecorder) Record(record audit.AuditRecord) {
	m.records = append(m.records, record)
}

// mockNextInterceptorAudit is a mock for testing AuditInterceptor.
type mockNextInterceptorAudit struct {
	returnMsg *mcp.Message
	returnErr error
	called    bool
}

func (m *mockNextInterceptorAudit) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	m.called = true
	if m.returnMsg != nil {
		return m.returnMsg, m.returnErr
	}
	return msg, m.returnErr
}

func TestAuditInterceptor_RecordsAllowedCall(t *testing.T) {
	recorder := &mockAuditRecorder{}
	nextInterceptor := &mockNextInterceptorAudit{returnErr: nil}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, nextInterceptor, logger)

	// Create a tool call message
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "read_file",
		"arguments": map[string]interface{}{"path": "/test"},
	})
	req := &jsonrpc.Request{
		Method: "tools/call",
		Params: params,
	}
	id, _ := jsonrpc.MakeID("req-123")
	req.ID = id

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Timestamp: time.Now(),
		Session: &session.Session{
			ID:         "session-123",
			IdentityID: "identity-456",
			Roles:      []auth.Role{auth.RoleUser},
		},
	}

	// Execute
	_, err := interceptor.Intercept(context.Background(), msg)

	// Verify
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !nextInterceptor.called {
		t.Error("expected next interceptor to be called")
	}
	if len(recorder.records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(recorder.records))
	}

	record := recorder.records[0]
	if record.Decision != audit.DecisionAllow {
		t.Errorf("expected decision %s, got %s", audit.DecisionAllow, record.Decision)
	}
	if record.ToolName != "read_file" {
		t.Errorf("expected tool name 'read_file', got %s", record.ToolName)
	}
	if record.SessionID != "session-123" {
		t.Errorf("expected session ID 'session-123', got %s", record.SessionID)
	}
	if record.RequestID != "req-123" {
		t.Errorf("expected request ID 'req-123', got %s", record.RequestID)
	}
}

func TestAuditInterceptor_RecordsDeniedCall(t *testing.T) {
	recorder := &mockAuditRecorder{}
	policyError := errors.New("policy denied: forbidden tool")
	nextInterceptor := &mockNextInterceptorAudit{returnErr: policyError}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, nextInterceptor, logger)

	// Create a tool call message
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "delete_file",
		"arguments": map[string]interface{}{"path": "/etc/passwd"},
	})
	req := &jsonrpc.Request{
		Method: "tools/call",
		Params: params,
	}
	id, _ := jsonrpc.MakeID(42.0) // Test numeric ID
	req.ID = id

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Timestamp: time.Now(),
		Session: &session.Session{
			ID:         "session-789",
			IdentityID: "identity-bad",
			Roles:      []auth.Role{auth.RoleUser},
		},
	}

	// Execute
	_, err := interceptor.Intercept(context.Background(), msg)

	// Verify error is passed through
	if err != policyError {
		t.Fatalf("expected policy error, got: %v", err)
	}

	if len(recorder.records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(recorder.records))
	}

	record := recorder.records[0]
	if record.Decision != audit.DecisionDeny {
		t.Errorf("expected decision %s, got %s", audit.DecisionDeny, record.Decision)
	}
	if record.Reason != "policy denied: forbidden tool" {
		t.Errorf("expected reason 'policy denied: forbidden tool', got %s", record.Reason)
	}
	if record.ToolName != "delete_file" {
		t.Errorf("expected tool name 'delete_file', got %s", record.ToolName)
	}
	if record.RequestID != "42" {
		t.Errorf("expected request ID '42', got %s", record.RequestID)
	}
}

func TestAuditInterceptor_PassesMessageThrough(t *testing.T) {
	recorder := &mockAuditRecorder{}
	expectedResult := &mcp.Message{Raw: []byte("modified")}
	nextInterceptor := &mockNextInterceptorAudit{returnMsg: expectedResult}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, nextInterceptor, logger)

	// Create a tool call message
	params, _ := json.Marshal(map[string]interface{}{
		"name": "test_tool",
	})
	req := &jsonrpc.Request{
		Method: "tools/call",
		Params: params,
	}

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Session:   &session.Session{ID: "s1", IdentityID: "i1"},
	}

	// Execute
	result, err := interceptor.Intercept(context.Background(), msg)

	// Verify
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != expectedResult {
		t.Error("expected result to be passed through from next interceptor")
	}
}

func TestAuditInterceptor_HandlesNilSession(t *testing.T) {
	recorder := &mockAuditRecorder{}
	nextInterceptor := &mockNextInterceptorAudit{returnErr: nil}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, nextInterceptor, logger)

	// Create a tool call message without session
	params, _ := json.Marshal(map[string]interface{}{
		"name": "anonymous_tool",
	})
	req := &jsonrpc.Request{
		Method: "tools/call",
		Params: params,
	}

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Session:   nil, // No session
	}

	// Execute - should not panic
	_, err := interceptor.Intercept(context.Background(), msg)

	// Verify
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(recorder.records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(recorder.records))
	}

	record := recorder.records[0]
	if record.SessionID != "anonymous" {
		t.Errorf("expected session ID 'anonymous', got %s", record.SessionID)
	}
	if record.IdentityID != "anonymous" {
		t.Errorf("expected identity ID 'anonymous', got %s", record.IdentityID)
	}
}

func TestAuditInterceptor_NonToolCall_NotAudited(t *testing.T) {
	recorder := &mockAuditRecorder{}
	nextInterceptor := &mockNextInterceptorAudit{returnErr: nil}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, nextInterceptor, logger)

	// Create a non-tool-call message
	req := &jsonrpc.Request{
		Method: "resources/list",
	}

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Session:   &session.Session{ID: "s1", IdentityID: "i1"},
	}

	// Execute
	_, err := interceptor.Intercept(context.Background(), msg)

	// Verify
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextInterceptor.called {
		t.Error("expected next interceptor to be called")
	}
	if len(recorder.records) != 0 {
		t.Errorf("expected 0 audit records for non-tool-call, got %d", len(recorder.records))
	}
}
