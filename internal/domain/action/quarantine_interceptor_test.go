package action

import (
	"context"
	"errors"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
)

// stubQuarantineChecker is a simple test double for QuarantineChecker.
type stubQuarantineChecker struct {
	quarantined map[string]bool
}

func (s *stubQuarantineChecker) IsQuarantined(name string) bool {
	return s.quarantined[name]
}

func TestQuarantineInterceptor_CleanTool(t *testing.T) {
	checker := &stubQuarantineChecker{quarantined: map[string]bool{"dangerous_tool": true}}
	interceptor := NewQuarantineInterceptor(checker, &passThrough{}, newTestLogger())

	act := &CanonicalAction{
		Type:      ActionToolCall,
		Name:      "safe_tool",
		Arguments: map[string]interface{}{"arg": "value"},
		Identity:  ActionIdentity{ID: "user-1", Name: "Alice"},
	}

	result, err := interceptor.Intercept(context.Background(), act)
	if err != nil {
		t.Fatalf("expected no error for clean tool, got %v", err)
	}
	if result != act {
		t.Fatal("expected action to be passed through unchanged")
	}
}

func TestQuarantineInterceptor_QuarantinedTool(t *testing.T) {
	checker := &stubQuarantineChecker{quarantined: map[string]bool{"dangerous_tool": true}}
	interceptor := NewQuarantineInterceptor(checker, &passThrough{}, newTestLogger())

	act := &CanonicalAction{
		Type:      ActionToolCall,
		Name:      "dangerous_tool",
		Arguments: map[string]interface{}{"cmd": "rm -rf /"},
		Identity:  ActionIdentity{ID: "user-1", Name: "Alice"},
	}

	_, err := interceptor.Intercept(context.Background(), act)
	if err == nil {
		t.Fatal("expected error for quarantined tool, got nil")
	}
	if !errors.Is(err, proxy.ErrPolicyDenied) {
		t.Fatalf("expected error to wrap proxy.ErrPolicyDenied, got %v", err)
	}
}

func TestQuarantineInterceptor_NonToolCall(t *testing.T) {
	checker := &stubQuarantineChecker{quarantined: map[string]bool{"dangerous_tool": true}}
	interceptor := NewQuarantineInterceptor(checker, &passThrough{}, newTestLogger())

	// Action type is not ActionToolCall, so even a quarantined name should pass.
	act := &CanonicalAction{
		Type:      ActionHTTPRequest,
		Name:      "dangerous_tool",
		Arguments: map[string]interface{}{"url": "http://example.com"},
		Identity:  ActionIdentity{ID: "user-2", Name: "Bob"},
	}

	result, err := interceptor.Intercept(context.Background(), act)
	if err != nil {
		t.Fatalf("expected no error for non-tool-call action, got %v", err)
	}
	if result != act {
		t.Fatal("expected action to be passed through unchanged")
	}
}

func TestQuarantineInterceptor_EmptyName(t *testing.T) {
	checker := &stubQuarantineChecker{quarantined: map[string]bool{"dangerous_tool": true}}
	interceptor := NewQuarantineInterceptor(checker, &passThrough{}, newTestLogger())

	act := &CanonicalAction{
		Type:      ActionToolCall,
		Name:      "",
		Arguments: map[string]interface{}{},
		Identity:  ActionIdentity{ID: "user-3", Name: "Charlie"},
	}

	result, err := interceptor.Intercept(context.Background(), act)
	if err != nil {
		t.Fatalf("expected no error for empty tool name, got %v", err)
	}
	if result != act {
		t.Fatal("expected action to be passed through unchanged")
	}
}
