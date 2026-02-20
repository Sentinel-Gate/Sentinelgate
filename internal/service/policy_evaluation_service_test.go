package service

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// mockEvalPolicyEngine implements policy.PolicyEngine for testing.
type mockEvalPolicyEngine struct {
	decision policy.Decision
	err      error
}

func (m *mockEvalPolicyEngine) Evaluate(_ context.Context, _ policy.EvaluationContext) (policy.Decision, error) {
	return m.decision, m.err
}

func testEvalLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestPolicyEvaluationService_Evaluate_Allow(t *testing.T) {
	engine := &mockEvalPolicyEngine{
		decision: policy.Decision{
			Allowed:  true,
			RuleID:   "admin-bypass",
			RuleName: "Admin Bypass",
			Reason:   "matched rule admin-bypass",
		},
	}

	svc := NewPolicyEvaluationService(engine, nil, nil, testEvalLogger())

	req := PolicyEvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "read_file",
		Protocol:      "mcp",
		IdentityName:  "alice",
		IdentityRoles: []string{"admin"},
	}

	resp, err := svc.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("expected decision 'allow', got %q", resp.Decision)
	}
	if resp.RequestID == "" {
		t.Error("expected non-empty request_id")
	}
	if resp.LatencyMs < 0 {
		t.Errorf("expected latency_ms >= 0, got %d", resp.LatencyMs)
	}
	if resp.HelpURL != "" {
		t.Error("expected empty help_url for allow decision")
	}
	if resp.HelpText != "" {
		t.Error("expected empty help_text for allow decision")
	}
}

func TestPolicyEvaluationService_Evaluate_Deny(t *testing.T) {
	engine := &mockEvalPolicyEngine{
		decision: policy.Decision{
			Allowed:  false,
			RuleID:   "block-exec",
			RuleName: "Block Dangerous Execution",
			Reason:   "matched rule block-exec",
		},
	}

	svc := NewPolicyEvaluationService(engine, nil, nil, testEvalLogger())

	req := PolicyEvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "exec_command",
		Protocol:      "mcp",
		IdentityName:  "bob",
		IdentityRoles: []string{"user"},
	}

	resp, err := svc.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected decision 'deny', got %q", resp.Decision)
	}
	if resp.HelpURL == "" {
		t.Error("expected non-empty help_url for deny decision")
	}
	if resp.HelpText == "" {
		t.Error("expected non-empty help_text for deny decision")
	}
	if resp.RuleID != "block-exec" {
		t.Errorf("expected rule_id 'block-exec', got %q", resp.RuleID)
	}
	if resp.RuleName != "Block Dangerous Execution" {
		t.Errorf("expected rule_name 'Block Dangerous Execution', got %q", resp.RuleName)
	}
}

func TestPolicyEvaluationService_Evaluate_ApprovalRequired(t *testing.T) {
	engine := &mockEvalPolicyEngine{
		decision: policy.Decision{
			Allowed:          false,
			RequiresApproval: true,
			RuleID:           "sensitive-op",
			RuleName:         "Sensitive Operation",
			Reason:           "matched rule sensitive-op",
		},
	}

	svc := NewPolicyEvaluationService(engine, nil, nil, testEvalLogger())

	req := PolicyEvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "delete_resource",
		Protocol:      "mcp",
		IdentityName:  "charlie",
		IdentityRoles: []string{"user"},
	}

	resp, err := svc.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "approval_required" {
		t.Errorf("expected decision 'approval_required', got %q", resp.Decision)
	}
	if resp.HelpURL == "" {
		t.Error("expected non-empty help_url for approval_required decision")
	}
	if resp.HelpText == "" {
		t.Error("expected non-empty help_text for approval_required decision")
	}
}

func TestPolicyEvaluationService_HelpText_Generation(t *testing.T) {
	tests := []struct {
		name     string
		decision policy.Decision
		contains string
	}{
		{
			name: "with rule name",
			decision: policy.Decision{
				RuleID:   "block-exec",
				RuleName: "Block Execution",
			},
			contains: "Block Execution",
		},
		{
			name: "with custom help text from rule",
			decision: policy.Decision{
				RuleID:   "block-exec",
				RuleName: "Block Execution",
				HelpText: "Custom guidance from admin.",
			},
			contains: "Custom guidance from admin.",
		},
		{
			name: "without rule name falls back to rule ID",
			decision: policy.Decision{
				RuleID: "block-exec",
			},
			contains: "block-exec",
		},
		{
			name:     "no rule info provides generic message",
			decision: policy.Decision{},
			contains: "Contact your administrator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			helpText := GenerateHelpText(tt.decision)
			if helpText == "" {
				t.Error("expected non-empty help text")
			}
			if !containsStr(helpText, tt.contains) {
				t.Errorf("expected help text to contain %q, got %q", tt.contains, helpText)
			}
		})
	}
}

func TestPolicyEvaluationService_HelpURL_Generation(t *testing.T) {
	tests := []struct {
		name     string
		ruleID   string
		expected string
	}{
		{
			name:     "with rule ID",
			ruleID:   "block-exec",
			expected: "/admin/policies#rule-block-exec",
		},
		{
			name:     "empty rule ID",
			ruleID:   "",
			expected: "/admin/policies",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := GenerateHelpURL(tt.ruleID)
			if url != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, url)
			}
		})
	}
}

func TestPolicyEvaluationService_StatusTracking(t *testing.T) {
	engine := &mockEvalPolicyEngine{
		decision: policy.Decision{
			Allowed:  false,
			RuleID:   "block-exec",
			RuleName: "Block Execution",
			Reason:   "denied",
		},
	}

	svc := NewPolicyEvaluationService(engine, nil, nil, testEvalLogger())

	req := PolicyEvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "exec_cmd",
		Protocol:      "mcp",
		Gateway:       "mcp-gateway",
		IdentityName:  "test-user",
		IdentityRoles: []string{"user"},
	}

	resp, err := svc.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check evaluation is stored.
	eval := svc.GetEvaluationStatus(resp.RequestID)
	if eval == nil {
		t.Fatal("expected evaluation to be stored")
	}
	if eval.RequestID != resp.RequestID {
		t.Errorf("expected request_id %q, got %q", resp.RequestID, eval.RequestID)
	}
	if eval.Decision != "deny" {
		t.Errorf("expected decision 'deny', got %q", eval.Decision)
	}
	if eval.Protocol != "mcp" {
		t.Errorf("expected protocol 'mcp', got %q", eval.Protocol)
	}
	if eval.Gateway != "mcp-gateway" {
		t.Errorf("expected gateway 'mcp-gateway', got %q", eval.Gateway)
	}

	// Unknown request returns nil.
	unknown := svc.GetEvaluationStatus("nonexistent")
	if unknown != nil {
		t.Error("expected nil for unknown request_id")
	}
}

// containsStr checks if s contains substr.
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
