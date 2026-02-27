package proxy

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// mockPolicyEngine implements policy.PolicyEngine for testing.
type mockPolicyEngine struct {
	decision policy.Decision
	err      error
	// Track if Evaluate was called
	evaluateCalled bool
	capturedCtx    policy.EvaluationContext
}

func (m *mockPolicyEngine) Evaluate(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
	m.evaluateCalled = true
	m.capturedCtx = evalCtx
	return m.decision, m.err
}

// mockNextInterceptor tracks if Intercept was called.
type mockNextInterceptor struct {
	interceptCalled bool
	returnMsg       *mcp.Message
	returnErr       error
}

func (m *mockNextInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	m.interceptCalled = true
	if m.returnMsg != nil {
		return m.returnMsg, m.returnErr
	}
	return msg, m.returnErr
}

// createToolCallMessage creates a tools/call message with the given tool name and session.
func createToolCallMessage(toolName string, sess *session.Session) *mcp.Message {
	params := []byte(`{"name":"` + toolName + `","arguments":{"path":"/test/file"}}`)
	id, _ := jsonrpc.MakeID(float64(1))

	return &mcp.Message{
		Raw:       []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{}}`),
		Direction: mcp.ClientToServer,
		Decoded: &jsonrpc.Request{
			ID:     id,
			Method: "tools/call",
			Params: params,
		},
		Timestamp: time.Now(),
		Session:   sess,
	}
}

// createNonToolCallMessage creates a resources/list message.
func createNonToolCallMessage(sess *session.Session) *mcp.Message {
	params := []byte(`{}`)
	id, _ := jsonrpc.MakeID(float64(2))

	return &mcp.Message{
		Raw:       []byte(`{"jsonrpc":"2.0","method":"resources/list","params":{}}`),
		Direction: mcp.ClientToServer,
		Decoded: &jsonrpc.Request{
			ID:     id,
			Method: "resources/list",
			Params: params,
		},
		Timestamp: time.Now(),
		Session:   sess,
	}
}

// createTestSession creates a session with the given roles.
func createTestSession(roles ...auth.Role) *session.Session {
	return &session.Session{
		ID:         "test-session-123",
		IdentityID: "test-identity",
		Roles:      roles,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(30 * time.Minute),
		LastAccess: time.Now(),
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestPolicyInterceptor_NonToolCall(t *testing.T) {
	// Setup
	engine := &mockPolicyEngine{
		decision: policy.Decision{Allowed: true},
	}
	next := &mockNextInterceptor{}
	interceptor := NewPolicyInterceptor(engine, next, testLogger())

	sess := createTestSession(auth.RoleUser)
	msg := createNonToolCallMessage(sess)

	// Test
	result, err := interceptor.Intercept(context.Background(), msg)

	// Assert
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected message to be returned")
	}
	if !next.interceptCalled {
		t.Error("expected next.Intercept to be called")
	}
	if engine.evaluateCalled {
		t.Error("expected policy engine NOT to be called for non-tool-call")
	}
}

func TestPolicyInterceptor_AllowedToolCall(t *testing.T) {
	// Setup
	engine := &mockPolicyEngine{
		decision: policy.Decision{
			Allowed: true,
			RuleID:  "admin-bypass",
			Reason:  "matched rule admin-bypass",
		},
	}
	next := &mockNextInterceptor{}
	interceptor := NewPolicyInterceptor(engine, next, testLogger())

	sess := createTestSession(auth.RoleAdmin)
	msg := createToolCallMessage("read_file", sess)

	// Test
	result, err := interceptor.Intercept(context.Background(), msg)

	// Assert
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected message to be returned")
	}
	if !engine.evaluateCalled {
		t.Error("expected policy engine to be called")
	}
	if !next.interceptCalled {
		t.Error("expected next.Intercept to be called for allowed tool call")
	}
	if engine.capturedCtx.ToolName != "read_file" {
		t.Errorf("expected tool name 'read_file', got: %s", engine.capturedCtx.ToolName)
	}
}

func TestPolicyInterceptor_DeniedToolCall(t *testing.T) {
	// Setup
	engine := &mockPolicyEngine{
		decision: policy.Decision{
			Allowed: false,
			RuleID:  "block-delete",
			Reason:  "matched rule block-delete",
		},
	}
	next := &mockNextInterceptor{}
	interceptor := NewPolicyInterceptor(engine, next, testLogger())

	sess := createTestSession(auth.RoleUser)
	msg := createToolCallMessage("delete_file", sess)

	// Test
	result, err := interceptor.Intercept(context.Background(), msg)

	// Assert
	if err == nil {
		t.Fatal("expected error for denied tool call")
	}
	if !errors.Is(err, ErrPolicyDenied) {
		t.Errorf("expected ErrPolicyDenied, got: %v", err)
	}
	if result != nil {
		t.Error("expected nil message on denied tool call")
	}
	if !engine.evaluateCalled {
		t.Error("expected policy engine to be called")
	}
	if next.interceptCalled {
		t.Error("expected next.Intercept NOT to be called for denied tool call")
	}
}

func TestPolicyInterceptor_MissingSession(t *testing.T) {
	// Setup
	engine := &mockPolicyEngine{
		decision: policy.Decision{Allowed: true},
	}
	next := &mockNextInterceptor{}
	interceptor := NewPolicyInterceptor(engine, next, testLogger())

	msg := createToolCallMessage("read_file", nil) // nil session

	// Test
	result, err := interceptor.Intercept(context.Background(), msg)

	// Assert
	if err == nil {
		t.Fatal("expected error for missing session")
	}
	if !errors.Is(err, ErrMissingSession) {
		t.Errorf("expected ErrMissingSession, got: %v", err)
	}
	if result != nil {
		t.Error("expected nil message on missing session")
	}
	if engine.evaluateCalled {
		t.Error("expected policy engine NOT to be called for missing session")
	}
	if next.interceptCalled {
		t.Error("expected next.Intercept NOT to be called for missing session")
	}
}

func TestPolicyInterceptor_InvalidParams(t *testing.T) {
	// Setup
	engine := &mockPolicyEngine{
		decision: policy.Decision{Allowed: true},
	}
	next := &mockNextInterceptor{}
	interceptor := NewPolicyInterceptor(engine, next, testLogger())

	sess := createTestSession(auth.RoleUser)

	// Create message with invalid JSON params
	id, _ := jsonrpc.MakeID(float64(1))
	msg := &mcp.Message{
		Raw:       []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{}}`),
		Direction: mcp.ClientToServer,
		Decoded: &jsonrpc.Request{
			ID:     id,
			Method: "tools/call",
			Params: []byte(`{invalid json}`), // Invalid JSON
		},
		Timestamp: time.Now(),
		Session:   sess,
	}

	// Test
	result, err := interceptor.Intercept(context.Background(), msg)

	// Assert
	if err == nil {
		t.Fatal("expected error for invalid params")
	}
	if result != nil {
		t.Error("expected nil message on invalid params")
	}
	if engine.evaluateCalled {
		t.Error("expected policy engine NOT to be called for invalid params")
	}
	if next.interceptCalled {
		t.Error("expected next.Intercept NOT to be called for invalid params")
	}
}

func TestPolicyInterceptor_EngineError(t *testing.T) {
	// Setup
	engine := &mockPolicyEngine{
		err: errors.New("evaluation error"),
	}
	next := &mockNextInterceptor{}
	interceptor := NewPolicyInterceptor(engine, next, testLogger())

	sess := createTestSession(auth.RoleUser)
	msg := createToolCallMessage("read_file", sess)

	// Test
	result, err := interceptor.Intercept(context.Background(), msg)

	// Assert
	if err == nil {
		t.Fatal("expected error when policy engine fails")
	}
	if result != nil {
		t.Error("expected nil message on engine error")
	}
	if !engine.evaluateCalled {
		t.Error("expected policy engine to be called")
	}
	if next.interceptCalled {
		t.Error("expected next.Intercept NOT to be called on engine error")
	}
}

func TestBuildEvaluationContext(t *testing.T) {
	// Setup
	sess := &session.Session{
		ID:         "session-abc",
		IdentityID: "identity-xyz",
		Roles:      []auth.Role{auth.RoleAdmin, auth.RoleUser},
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(30 * time.Minute),
		LastAccess: time.Now(),
	}

	// Create message with known values
	params := []byte(`{"name":"write_file","arguments":{"path":"/tmp/test.txt","content":"hello"}}`)
	id, _ := jsonrpc.MakeID(float64(1))
	timestamp := time.Now()

	msg := &mcp.Message{
		Raw:       []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{}}`),
		Direction: mcp.ClientToServer,
		Decoded: &jsonrpc.Request{
			ID:     id,
			Method: "tools/call",
			Params: params,
		},
		Timestamp: timestamp,
		Session:   sess,
	}

	// Test
	evalCtx, err := buildEvaluationContext(msg)

	// Assert
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if evalCtx.ToolName != "write_file" {
		t.Errorf("expected tool name 'write_file', got: %s", evalCtx.ToolName)
	}
	if evalCtx.SessionID != "session-abc" {
		t.Errorf("expected session ID 'session-abc', got: %s", evalCtx.SessionID)
	}
	if evalCtx.IdentityID != "identity-xyz" {
		t.Errorf("expected identity ID 'identity-xyz', got: %s", evalCtx.IdentityID)
	}
	if len(evalCtx.UserRoles) != 2 {
		t.Errorf("expected 2 roles, got: %d", len(evalCtx.UserRoles))
	}
	if evalCtx.UserRoles[0] != "admin" {
		t.Errorf("expected first role 'admin', got: %s", evalCtx.UserRoles[0])
	}
	if evalCtx.UserRoles[1] != "user" {
		t.Errorf("expected second role 'user', got: %s", evalCtx.UserRoles[1])
	}
	if evalCtx.ToolArguments["path"] != "/tmp/test.txt" {
		t.Errorf("expected path '/tmp/test.txt', got: %v", evalCtx.ToolArguments["path"])
	}
	if evalCtx.ToolArguments["content"] != "hello" {
		t.Errorf("expected content 'hello', got: %v", evalCtx.ToolArguments["content"])
	}
	if evalCtx.RequestTime != timestamp {
		t.Errorf("expected request time %v, got: %v", timestamp, evalCtx.RequestTime)
	}
}

func TestBuildEvaluationContext_MissingToolName(t *testing.T) {
	// Setup
	sess := createTestSession(auth.RoleUser)

	// Create message without tool name
	params := []byte(`{"arguments":{"path":"/test"}}`)
	id, _ := jsonrpc.MakeID(float64(1))

	msg := &mcp.Message{
		Raw:       []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{}}`),
		Direction: mcp.ClientToServer,
		Decoded: &jsonrpc.Request{
			ID:     id,
			Method: "tools/call",
			Params: params,
		},
		Timestamp: time.Now(),
		Session:   sess,
	}

	// Test
	_, err := buildEvaluationContext(msg)

	// Assert
	if err == nil {
		t.Fatal("expected error for missing tool name")
	}
}
