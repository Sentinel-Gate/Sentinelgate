package action

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
)

// mockPolicyEngine implements policy.PolicyEngine for testing.
type mockPolicyEngine struct {
	evaluateFn func(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error)
}

func (m *mockPolicyEngine) Evaluate(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
	return m.evaluateFn(ctx, evalCtx)
}

// mockNextInterceptor records calls and returns configurable results.
type mockNextInterceptor struct {
	called     bool
	calledCtx  context.Context
	returnFunc func(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error)
}

func (m *mockNextInterceptor) Intercept(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error) {
	m.called = true
	m.calledCtx = ctx
	if m.returnFunc != nil {
		return m.returnFunc(ctx, action)
	}
	return action, nil
}

func newTestToolCallAction() *CanonicalAction {
	return &CanonicalAction{
		Type: ActionToolCall,
		Name: "read_file",
		Arguments: map[string]interface{}{
			"path": "/tmp/test",
		},
		Identity: ActionIdentity{
			ID:        "id-456",
			Name:      "test-user",
			SessionID: "sess-123",
			Roles:     []string{"user"},
		},
		Protocol:    "mcp",
		Gateway:     "mcp-gateway",
		RequestTime: time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC),
	}
}

func TestPolicyActionInterceptor_AllowToolCall(t *testing.T) {
	engine := &mockPolicyEngine{
		evaluateFn: func(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
			return policy.Decision{
				Allowed: true,
				RuleID:  "allow-all",
				Reason:  "default allow",
			}, nil
		},
	}

	next := &mockNextInterceptor{}
	interceptor := NewPolicyActionInterceptor(engine, next, testLogger())

	action := newTestToolCallAction()
	result, err := interceptor.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("Intercept() error = %v", err)
	}
	if result != action {
		t.Error("expected same action returned")
	}
	if !next.called {
		t.Error("next interceptor should have been called")
	}
}

func TestPolicyActionInterceptor_DenyToolCall(t *testing.T) {
	engine := &mockPolicyEngine{
		evaluateFn: func(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
			return policy.Decision{
				Allowed: false,
				RuleID:  "block-exec",
				Reason:  "blocked by security policy",
			}, nil
		},
	}

	next := &mockNextInterceptor{}
	interceptor := NewPolicyActionInterceptor(engine, next, testLogger())

	action := newTestToolCallAction()
	result, err := interceptor.Intercept(context.Background(), action)
	if err == nil {
		t.Fatal("Intercept() should return error for denied action")
	}
	if !errors.Is(err, proxy.ErrPolicyDenied) {
		t.Errorf("error should wrap ErrPolicyDenied, got: %v", err)
	}
	if result != nil {
		t.Error("result should be nil on deny")
	}
	if next.called {
		t.Error("next interceptor should NOT be called on deny")
	}
}

func TestPolicyActionInterceptor_NonToolCallPassthrough(t *testing.T) {
	engineCalled := false
	engine := &mockPolicyEngine{
		evaluateFn: func(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
			engineCalled = true
			return policy.Decision{}, nil
		},
	}

	next := &mockNextInterceptor{}
	interceptor := NewPolicyActionInterceptor(engine, next, testLogger())

	// Sampling action should bypass policy evaluation
	action := &CanonicalAction{
		Type:     ActionSampling,
		Name:     "sampling/createMessage",
		Protocol: "mcp",
		Identity: ActionIdentity{
			SessionID: "sess-123",
		},
	}

	result, err := interceptor.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("Intercept() error = %v", err)
	}
	if result != action {
		t.Error("expected same action returned")
	}
	if engineCalled {
		t.Error("policy engine should NOT be called for non-tool-call actions")
	}
	if !next.called {
		t.Error("next interceptor should be called for passthrough")
	}
}

func TestPolicyActionInterceptor_MissingIdentity(t *testing.T) {
	engine := &mockPolicyEngine{
		evaluateFn: func(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
			return policy.Decision{Allowed: true}, nil
		},
	}

	next := &mockNextInterceptor{}
	interceptor := NewPolicyActionInterceptor(engine, next, testLogger())

	// Tool call with empty identity (no session)
	action := &CanonicalAction{
		Type: ActionToolCall,
		Name: "read_file",
		// Identity is empty — SessionID == ""
	}

	result, err := interceptor.Intercept(context.Background(), action)
	if err == nil {
		t.Fatal("Intercept() should return error for missing identity")
	}
	if !errors.Is(err, proxy.ErrMissingSession) {
		t.Errorf("error should be ErrMissingSession, got: %v", err)
	}
	if result != nil {
		t.Error("result should be nil on error")
	}
	if next.called {
		t.Error("next interceptor should NOT be called")
	}
}

func TestPolicyActionInterceptor_ApprovalRequired(t *testing.T) {
	engine := &mockPolicyEngine{
		evaluateFn: func(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
			return policy.Decision{
				Allowed:          false,
				RequiresApproval: true,
				RuleID:           "approval-rule",
				Reason:           "requires human approval",
				ApprovalTimeout:  5 * time.Minute,
			}, nil
		},
	}

	next := &mockNextInterceptor{}
	interceptor := NewPolicyActionInterceptor(engine, next, testLogger())

	action := newTestToolCallAction()
	result, err := interceptor.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("Intercept() should NOT error for approval required, got: %v", err)
	}
	if result != action {
		t.Error("expected same action returned")
	}
	if !next.called {
		t.Error("next interceptor should be called (approval flows through)")
	}

	// Verify decision was stored in context
	decision := policy.DecisionFromContext(next.calledCtx)
	if decision == nil {
		t.Fatal("decision should be stored in context")
	}
	if !decision.RequiresApproval {
		t.Error("decision should have RequiresApproval=true")
	}
}

func TestPolicyActionInterceptor_EvalContextFields(t *testing.T) {
	var capturedCtx policy.EvaluationContext

	engine := &mockPolicyEngine{
		evaluateFn: func(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
			capturedCtx = evalCtx
			return policy.Decision{Allowed: true, RuleID: "test"}, nil
		},
	}

	next := &mockNextInterceptor{}
	interceptor := NewPolicyActionInterceptor(engine, next, testLogger())

	action := &CanonicalAction{
		Type: ActionToolCall,
		Name: "write_file",
		Arguments: map[string]interface{}{
			"path":    "/etc/config",
			"content": "test",
		},
		Identity: ActionIdentity{
			ID:        "id-789",
			Name:      "admin-user",
			SessionID: "sess-456",
			Roles:     []string{"admin", "user"},
		},
		Protocol:    "mcp",
		Gateway:     "mcp-gateway",
		Framework:   "crewai",
		RequestTime: time.Date(2026, 2, 11, 14, 30, 0, 0, time.UTC),
		Destination: Destination{
			URL:    "https://api.example.com/files",
			Domain: "api.example.com",
			Port:   443,
			Scheme: "https",
			Path:   "/files",
		},
	}

	_, err := interceptor.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("Intercept() error = %v", err)
	}

	// Verify all EvaluationContext fields are populated from CanonicalAction
	if capturedCtx.ToolName != "write_file" {
		t.Errorf("ToolName = %q, want %q", capturedCtx.ToolName, "write_file")
	}
	if capturedCtx.ToolArguments["path"] != "/etc/config" {
		t.Errorf("ToolArguments[path] = %v, want %q", capturedCtx.ToolArguments["path"], "/etc/config")
	}
	if len(capturedCtx.UserRoles) != 2 || capturedCtx.UserRoles[0] != "admin" {
		t.Errorf("UserRoles = %v, want [admin user]", capturedCtx.UserRoles)
	}
	if capturedCtx.SessionID != "sess-456" {
		t.Errorf("SessionID = %q, want %q", capturedCtx.SessionID, "sess-456")
	}
	if capturedCtx.IdentityID != "id-789" {
		t.Errorf("IdentityID = %q, want %q", capturedCtx.IdentityID, "id-789")
	}
	if capturedCtx.IdentityName != "admin-user" {
		t.Errorf("IdentityName = %q, want %q", capturedCtx.IdentityName, "admin-user")
	}
	if !capturedCtx.RequestTime.Equal(time.Date(2026, 2, 11, 14, 30, 0, 0, time.UTC)) {
		t.Errorf("RequestTime = %v, want 2026-02-11 14:30:00", capturedCtx.RequestTime)
	}

	// Universal fields
	if capturedCtx.ActionType != "tool_call" {
		t.Errorf("ActionType = %q, want %q", capturedCtx.ActionType, "tool_call")
	}
	if capturedCtx.ActionName != "write_file" {
		t.Errorf("ActionName = %q, want %q", capturedCtx.ActionName, "write_file")
	}
	if capturedCtx.Protocol != "mcp" {
		t.Errorf("Protocol = %q, want %q", capturedCtx.Protocol, "mcp")
	}
	if capturedCtx.Gateway != "mcp-gateway" {
		t.Errorf("Gateway = %q, want %q", capturedCtx.Gateway, "mcp-gateway")
	}
	if capturedCtx.Framework != "crewai" {
		t.Errorf("Framework = %q, want %q", capturedCtx.Framework, "crewai")
	}

	// Destination fields
	if capturedCtx.DestURL != "https://api.example.com/files" {
		t.Errorf("DestURL = %q, want %q", capturedCtx.DestURL, "https://api.example.com/files")
	}
	if capturedCtx.DestDomain != "api.example.com" {
		t.Errorf("DestDomain = %q, want %q", capturedCtx.DestDomain, "api.example.com")
	}
	if capturedCtx.DestPort != 443 {
		t.Errorf("DestPort = %d, want %d", capturedCtx.DestPort, 443)
	}
	if capturedCtx.DestScheme != "https" {
		t.Errorf("DestScheme = %q, want %q", capturedCtx.DestScheme, "https")
	}
	if capturedCtx.DestPath != "/files" {
		t.Errorf("DestPath = %q, want %q", capturedCtx.DestPath, "/files")
	}
}
