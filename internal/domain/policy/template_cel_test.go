package policy_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	celeval "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/cel"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// mockTemplateStore implements policy.PolicyStore for template tests.
type mockTemplateStore struct {
	policies []policy.Policy
	mu       sync.RWMutex
}

func (m *mockTemplateStore) GetAllPolicies(_ context.Context) ([]policy.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]policy.Policy{}, m.policies...), nil
}

func (m *mockTemplateStore) GetPolicy(_ context.Context, id string) (*policy.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.policies {
		if m.policies[i].ID == id {
			return &m.policies[i], nil
		}
	}
	return nil, nil
}

func (m *mockTemplateStore) SavePolicy(_ context.Context, p *policy.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.policies {
		if m.policies[i].ID == p.ID {
			m.policies[i] = *p
			return nil
		}
	}
	m.policies = append(m.policies, *p)
	return nil
}

func (m *mockTemplateStore) DeletePolicy(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.policies {
		if m.policies[i].ID == id {
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *mockTemplateStore) GetPolicyWithRules(_ context.Context, id string) (*policy.Policy, error) {
	return m.GetPolicy(context.Background(), id)
}

func (m *mockTemplateStore) SaveRule(_ context.Context, _ string, _ *policy.Rule) error {
	return nil
}

func (m *mockTemplateStore) DeleteRule(_ context.Context, _, _ string) error {
	return nil
}

// TestTemplateConditions_CELCompilation verifies all 7 template conditions compile
// against the universal CEL environment without error.
func TestTemplateConditions_CELCompilation(t *testing.T) {
	evaluator, err := celeval.NewEvaluator()
	if err != nil {
		t.Fatalf("failed to create CEL evaluator: %v", err)
	}

	for _, tmpl := range policy.AllTemplates() {
		t.Run(tmpl.ID, func(t *testing.T) {
			for i, rule := range tmpl.Rules {
				err := evaluator.ValidateExpression(rule.Condition)
				if err != nil {
					t.Errorf("Rule[%d] %q condition failed to compile: %v", i, rule.Name, err)
				}
			}
		})
	}
}

// newServiceWithTemplate creates a PolicyService loaded with a single template-derived policy.
func newServiceWithTemplate(t *testing.T, templateID string) *service.PolicyService {
	t.Helper()
	tmpl, ok := policy.GetTemplate(templateID)
	if !ok {
		t.Fatalf("template %q not found", templateID)
	}
	p := tmpl.ToPolicy()
	p.ID = "test-" + templateID
	p.Enabled = true
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()

	store := &mockTemplateStore{policies: []policy.Policy{*p}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	svc, err := service.NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService failed: %v", err)
	}
	return svc
}

// TestTemplate_DataProtection_DenysSensitivePath verifies the data-protection template
// correctly denies writes to /etc/passwd and allows writes to /home/user/code.go.
func TestTemplate_DataProtection_DenysSensitivePath(t *testing.T) {
	svc := newServiceWithTemplate(t, "data-protection")
	ctx := context.Background()

	// write_file to /etc/passwd should be DENIED
	decision, err := svc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "write_file",
		ToolArguments: map[string]interface{}{"path": "/etc/passwd", "content": "pwned"},
		UserRoles:     []string{"user"},
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if decision.Allowed {
		t.Errorf("write_file to /etc/passwd should be DENIED, got ALLOWED (rule: %s)", decision.RuleName)
	}

	// write_file to /home/user/code.go should be ALLOWED
	decision, err = svc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "write_file",
		ToolArguments: map[string]interface{}{"path": "/home/user/code.go", "content": "package main"},
		UserRoles:     []string{"user"},
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("write_file to /home/user/code.go should be ALLOWED, got DENIED (rule: %s, reason: %s)", decision.RuleName, decision.Reason)
	}

	// write_file to .env path should be DENIED
	decision, err = svc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "write_file",
		ToolArguments: map[string]interface{}{"path": "/app/.env", "content": "SECRET=bad"},
		UserRoles:     []string{"user"},
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if decision.Allowed {
		t.Errorf("write_file to /app/.env should be DENIED, got ALLOWED (rule: %s)", decision.RuleName)
	}

	// write_file to credentials path should be DENIED
	decision, err = svc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "write_file",
		ToolArguments: map[string]interface{}{"path": "/home/user/credentials.json", "content": "{}"},
		UserRoles:     []string{"user"},
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if decision.Allowed {
		t.Errorf("write_file to credentials.json should be DENIED, got ALLOWED (rule: %s)", decision.RuleName)
	}
}

// TestTemplate_SafeCoding_AllowsNonSensitivePath verifies the safe-coding template
// allows writes to safe paths and blocks writes to /etc.
func TestTemplate_SafeCoding_AllowsNonSensitivePath(t *testing.T) {
	svc := newServiceWithTemplate(t, "safe-coding")
	ctx := context.Background()

	// write_file to /home/user/test.go should be ALLOWED
	decision, err := svc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "write_file",
		ToolArguments: map[string]interface{}{"path": "/home/user/test.go", "content": "package main"},
		UserRoles:     []string{"user"},
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("write_file to /home/user/test.go should be ALLOWED, got DENIED (rule: %s, reason: %s)", decision.RuleName, decision.Reason)
	}

	// write_file to /etc/shadow should be DENIED (the allow condition fails, so default deny catches it)
	decision, err = svc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "write_file",
		ToolArguments: map[string]interface{}{"path": "/etc/shadow", "content": "bad"},
		UserRoles:     []string{"user"},
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if decision.Allowed {
		t.Errorf("write_file to /etc/shadow should be DENIED, got ALLOWED (rule: %s)", decision.RuleName)
	}

	// write_file to /sys/kernel should be DENIED
	decision, err = svc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "write_file",
		ToolArguments: map[string]interface{}{"path": "/sys/kernel/debug", "content": "bad"},
		UserRoles:     []string{"user"},
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if decision.Allowed {
		t.Errorf("write_file to /sys/kernel should be DENIED, got ALLOWED (rule: %s)", decision.RuleName)
	}
}

// TestTemplate_Research_AllowsTmpWrites verifies the research template allows
// writes to /tmp and denies writes elsewhere.
func TestTemplate_Research_AllowsTmpWrites(t *testing.T) {
	svc := newServiceWithTemplate(t, "research")
	ctx := context.Background()

	// write_file to /tmp/notes.txt should be ALLOWED
	decision, err := svc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "write_file",
		ToolArguments: map[string]interface{}{"path": "/tmp/notes.txt", "content": "notes"},
		UserRoles:     []string{"user"},
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("write_file to /tmp/notes.txt should be ALLOWED, got DENIED (rule: %s, reason: %s)", decision.RuleName, decision.Reason)
	}

	// write_file to /home/user/file.txt should be DENIED
	decision, err = svc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "write_file",
		ToolArguments: map[string]interface{}{"path": "/home/user/file.txt", "content": "data"},
		UserRoles:     []string{"user"},
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if decision.Allowed {
		t.Errorf("write_file to /home/user/file.txt should be DENIED, got ALLOWED (rule: %s)", decision.RuleName)
	}
}

// TestTemplate_ReadOnly_AllowsExpandedReadTools verifies the read-only template
// allows all 10 read operations (including the 5 added in fix 4.1) and denies write_file.
func TestTemplate_ReadOnly_AllowsExpandedReadTools(t *testing.T) {
	svc := newServiceWithTemplate(t, "read-only")
	ctx := context.Background()

	// All these tools should be ALLOWED by the read-only template.
	allowedTools := []string{
		"read_file",
		"read_text_file",
		"read_multiple_files",
		"read_media_file",
		"list_directory",
		"list_directory_with_sizes",
		"list_allowed_directories",
		"search_files",
		"list_files",
		"get_file_info",
	}

	for _, toolName := range allowedTools {
		t.Run("allow_"+toolName, func(t *testing.T) {
			decision, err := svc.Evaluate(ctx, policy.EvaluationContext{
				ToolName:    toolName,
				UserRoles:   []string{"user"},
				RequestTime: time.Now(),
			})
			if err != nil {
				t.Fatalf("Evaluate(%s) failed: %v", toolName, err)
			}
			if !decision.Allowed {
				t.Errorf("%s should be ALLOWED by read-only template, got DENIED (rule: %s, reason: %s)",
					toolName, decision.RuleName, decision.Reason)
			}
		})
	}

	// write_file should be DENIED by the read-only template.
	t.Run("deny_write_file", func(t *testing.T) {
		decision, err := svc.Evaluate(ctx, policy.EvaluationContext{
			ToolName:      "write_file",
			ToolArguments: map[string]interface{}{"path": "/tmp/test.txt", "content": "hello"},
			UserRoles:     []string{"user"},
			RequestTime:   time.Now(),
		})
		if err != nil {
			t.Fatalf("Evaluate(write_file) failed: %v", err)
		}
		if decision.Allowed {
			t.Errorf("write_file should be DENIED by read-only template, got ALLOWED (rule: %s)", decision.RuleName)
		}
	})

	// execute_command should be DENIED (not in the allow list).
	t.Run("deny_execute_command", func(t *testing.T) {
		decision, err := svc.Evaluate(ctx, policy.EvaluationContext{
			ToolName:    "execute_command",
			UserRoles:   []string{"user"},
			RequestTime: time.Now(),
		})
		if err != nil {
			t.Fatalf("Evaluate(execute_command) failed: %v", err)
		}
		if decision.Allowed {
			t.Errorf("execute_command should be DENIED by read-only template, got ALLOWED (rule: %s)", decision.RuleName)
		}
	})
}
