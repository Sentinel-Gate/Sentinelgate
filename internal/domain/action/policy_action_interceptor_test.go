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

// mockSessionUsageProvider implements SessionUsageProvider for testing.
type mockSessionUsageProvider struct {
	usage SessionUsageData
	found bool
}

func (m *mockSessionUsageProvider) GetUsage(sessionID string) (SessionUsageData, bool) {
	return m.usage, m.found
}

func TestPolicyActionInterceptor_SessionUsage_PopulatesEvalContext(t *testing.T) {
	startTime := time.Now().Add(-2 * time.Hour) // 2 hours ago

	var capturedCtx policy.EvaluationContext
	engine := &mockPolicyEngine{
		evaluateFn: func(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
			capturedCtx = evalCtx
			return policy.Decision{Allowed: true, RuleID: "test"}, nil
		},
	}

	provider := &mockSessionUsageProvider{
		usage: SessionUsageData{
			TotalCalls:  150,
			WriteCalls:  30,
			DeleteCalls: 5,
			StartedAt:   startTime,
		},
		found: true,
	}

	next := &mockNextInterceptor{}
	interceptor := NewPolicyActionInterceptor(engine, next, testLogger(), WithSessionUsage(provider))

	action := newTestToolCallAction()
	_, err := interceptor.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("Intercept() error = %v", err)
	}

	// Verify session fields were populated
	if capturedCtx.SessionCallCount != 150 {
		t.Errorf("SessionCallCount = %d, want 150", capturedCtx.SessionCallCount)
	}
	if capturedCtx.SessionWriteCount != 30 {
		t.Errorf("SessionWriteCount = %d, want 30", capturedCtx.SessionWriteCount)
	}
	if capturedCtx.SessionDeleteCount != 5 {
		t.Errorf("SessionDeleteCount = %d, want 5", capturedCtx.SessionDeleteCount)
	}
	// Duration should be approximately 7200 seconds (2 hours). Allow 10s tolerance.
	if capturedCtx.SessionDurationSeconds < 7190 || capturedCtx.SessionDurationSeconds > 7210 {
		t.Errorf("SessionDurationSeconds = %d, want ~7200", capturedCtx.SessionDurationSeconds)
	}
}

func TestPolicyActionInterceptor_SessionUsage_NilProvider_DefaultsZero(t *testing.T) {
	var capturedCtx policy.EvaluationContext
	engine := &mockPolicyEngine{
		evaluateFn: func(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
			capturedCtx = evalCtx
			return policy.Decision{Allowed: true, RuleID: "test"}, nil
		},
	}

	next := &mockNextInterceptor{}
	// No WithSessionUsage option — nil provider
	interceptor := NewPolicyActionInterceptor(engine, next, testLogger())

	action := newTestToolCallAction()
	_, err := interceptor.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("Intercept() error = %v", err)
	}

	if capturedCtx.SessionCallCount != 0 {
		t.Errorf("SessionCallCount = %d, want 0", capturedCtx.SessionCallCount)
	}
	if capturedCtx.SessionWriteCount != 0 {
		t.Errorf("SessionWriteCount = %d, want 0", capturedCtx.SessionWriteCount)
	}
	if capturedCtx.SessionDeleteCount != 0 {
		t.Errorf("SessionDeleteCount = %d, want 0", capturedCtx.SessionDeleteCount)
	}
	if capturedCtx.SessionDurationSeconds != 0 {
		t.Errorf("SessionDurationSeconds = %d, want 0", capturedCtx.SessionDurationSeconds)
	}
}

func TestPolicyActionInterceptor_SessionUsage_SessionNotFound(t *testing.T) {
	var capturedCtx policy.EvaluationContext
	engine := &mockPolicyEngine{
		evaluateFn: func(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
			capturedCtx = evalCtx
			return policy.Decision{Allowed: true, RuleID: "test"}, nil
		},
	}

	provider := &mockSessionUsageProvider{
		found: false, // Session not found
	}

	next := &mockNextInterceptor{}
	interceptor := NewPolicyActionInterceptor(engine, next, testLogger(), WithSessionUsage(provider))

	action := newTestToolCallAction()
	_, err := interceptor.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("Intercept() error = %v", err)
	}

	if capturedCtx.SessionCallCount != 0 {
		t.Errorf("SessionCallCount = %d, want 0 (session not found)", capturedCtx.SessionCallCount)
	}
	if capturedCtx.SessionWriteCount != 0 {
		t.Errorf("SessionWriteCount = %d, want 0 (session not found)", capturedCtx.SessionWriteCount)
	}
}

func TestPolicyActionInterceptor_BackwardCompat_NoOpts(t *testing.T) {
	engine := &mockPolicyEngine{
		evaluateFn: func(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
			return policy.Decision{Allowed: true, RuleID: "test"}, nil
		},
	}

	next := &mockNextInterceptor{}
	// Call without any opts — original signature still works
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

func TestPolicyActionInterceptor_SessionHistory(t *testing.T) {
	now := time.Now()

	var capturedCtx policy.EvaluationContext
	engine := &mockPolicyEngine{
		evaluateFn: func(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
			capturedCtx = evalCtx
			return policy.Decision{Allowed: true, RuleID: "test"}, nil
		},
	}

	provider := &mockSessionUsageProvider{
		usage: SessionUsageData{
			TotalCalls:  10,
			WriteCalls:  3,
			DeleteCalls: 1,
			StartedAt:   now.Add(-5 * time.Minute),
			ActionHistory: []SessionActionRecord{
				{ToolName: "read_file", CallType: "read", Timestamp: now.Add(-30 * time.Second), ArgKeys: []string{"path"}},
				{ToolName: "write_file", CallType: "write", Timestamp: now.Add(-20 * time.Second), ArgKeys: []string{"path", "content"}},
			},
			ActionSet: map[string]bool{"read_file": true, "write_file": true},
			ArgKeySet: map[string]bool{"path": true, "content": true},
		},
		found: true,
	}

	next := &mockNextInterceptor{}
	interceptor := NewPolicyActionInterceptor(engine, next, testLogger(), WithSessionUsage(provider))

	action := newTestToolCallAction()
	_, err := interceptor.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("Intercept() error = %v", err)
	}

	// Verify session action history was populated
	if len(capturedCtx.SessionActionHistory) != 2 {
		t.Fatalf("SessionActionHistory len = %d, want 2", len(capturedCtx.SessionActionHistory))
	}
	if capturedCtx.SessionActionHistory[0].ToolName != "read_file" {
		t.Errorf("SessionActionHistory[0].ToolName = %q, want %q", capturedCtx.SessionActionHistory[0].ToolName, "read_file")
	}
	if capturedCtx.SessionActionHistory[1].ToolName != "write_file" {
		t.Errorf("SessionActionHistory[1].ToolName = %q, want %q", capturedCtx.SessionActionHistory[1].ToolName, "write_file")
	}

	// Verify action set
	if !capturedCtx.SessionActionSet["read_file"] {
		t.Error("SessionActionSet should contain read_file")
	}
	if !capturedCtx.SessionActionSet["write_file"] {
		t.Error("SessionActionSet should contain write_file")
	}

	// Verify arg key set
	if !capturedCtx.SessionArgKeySet["path"] {
		t.Error("SessionArgKeySet should contain path")
	}
	if !capturedCtx.SessionArgKeySet["content"] {
		t.Error("SessionArgKeySet should contain content")
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
