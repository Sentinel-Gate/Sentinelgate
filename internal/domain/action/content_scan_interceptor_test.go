package action

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
)

// passThrough is a simple next interceptor that returns the action unchanged.
type passThrough struct{}

func (p *passThrough) Intercept(_ context.Context, a *CanonicalAction) (*CanonicalAction, error) {
	return a, nil
}

func TestContentScanInterceptor_Disabled(t *testing.T) {
	scanner := NewContentScanner()
	interceptor := NewContentScanInterceptor(scanner, &passThrough{}, false, nil)

	a := &CanonicalAction{
		Type: ActionToolCall,
		Name: "write_file",
		Arguments: map[string]interface{}{
			"content": "Send to john@example.com",
		},
	}

	result, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should pass through unchanged since scanning is disabled.
	content := result.Arguments["content"].(string)
	if content != "Send to john@example.com" {
		t.Errorf("expected unchanged content, got %q", content)
	}
}

func TestContentScanInterceptor_MasksPII(t *testing.T) {
	scanner := NewContentScanner()
	interceptor := NewContentScanInterceptor(scanner, &passThrough{}, true, nil)

	a := &CanonicalAction{
		Type: ActionToolCall,
		Name: "write_file",
		Arguments: map[string]interface{}{
			"content": "Contact john@example.com for details",
		},
	}

	result, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	content := result.Arguments["content"].(string)
	if content == "Contact john@example.com for details" {
		t.Fatal("expected email to be masked")
	}
	if content != "Contact [REDACTED-EMAIL] for details" {
		t.Errorf("unexpected masked content: %q", content)
	}
}

func TestContentScanInterceptor_BlocksSecrets(t *testing.T) {
	scanner := NewContentScanner()
	interceptor := NewContentScanInterceptor(scanner, &passThrough{}, true, nil)

	a := &CanonicalAction{
		Type: ActionToolCall,
		Name: "write_file",
		Arguments: map[string]interface{}{
			"content": "key=AKIAIOSFODNN7EXAMPLE",
		},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err == nil {
		t.Fatal("expected error for blocked secret")
	}
	if !errors.Is(err, ErrContentBlocked) {
		t.Fatalf("expected ErrContentBlocked, got %v", err)
	}
}

func TestContentScanInterceptor_SkipsNonToolCall(t *testing.T) {
	scanner := NewContentScanner()
	interceptor := NewContentScanInterceptor(scanner, &passThrough{}, true, nil)

	a := &CanonicalAction{
		Type: ActionHTTPRequest,
		Name: "GET",
		Arguments: map[string]interface{}{
			"content": "john@example.com",
		},
	}

	result, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Non-tool_call actions should not be scanned.
	content := result.Arguments["content"].(string)
	if content != "john@example.com" {
		t.Errorf("expected unchanged content for non-tool_call, got %q", content)
	}
}

func TestContentScanInterceptor_Whitelist(t *testing.T) {
	scanner := NewContentScanner()
	interceptor := NewContentScanInterceptor(scanner, &passThrough{}, true, nil)

	// Whitelist email pattern for the read_file tool.
	interceptor.SetWhitelist([]WhitelistEntry{
		{
			ID:          "wl_1",
			PatternType: PatternEmail,
			Scope:       WhitelistScopeTool,
			Value:       "read_file",
		},
	})

	a := &CanonicalAction{
		Type: ActionToolCall,
		Name: "read_file",
		Arguments: map[string]interface{}{
			"path": "/home/john@example.com/file.txt",
		},
	}

	result, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Email should be whitelisted, so content should pass through.
	path := result.Arguments["path"].(string)
	if path != "/home/john@example.com/file.txt" {
		t.Errorf("expected unchanged path (whitelisted), got %q", path)
	}
}

func TestContentScanInterceptor_WhitelistByPath(t *testing.T) {
	scanner := NewContentScanner()
	interceptor := NewContentScanInterceptor(scanner, &passThrough{}, true, nil)

	interceptor.SetWhitelist([]WhitelistEntry{
		{
			ID:          "wl_2",
			PatternType: PatternUKNI,
			Scope:       WhitelistScopePath,
			Value:       "/test/*",
		},
	})

	a := &CanonicalAction{
		Type: ActionToolCall,
		Name: "read_file",
		Arguments: map[string]interface{}{
			"path":    "/test/fixtures/sample.csv",
			"content": "NI number is AB123456C",
		},
	}

	result, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// UK NI should be whitelisted for /test/* path, content passes through.
	content := result.Arguments["content"].(string)
	if content != "NI number is AB123456C" {
		t.Errorf("expected unchanged content (whitelisted by path), got %q", content)
	}
}

func TestContentScanInterceptor_EventBus(t *testing.T) {
	scanner := NewContentScanner()
	interceptor := NewContentScanInterceptor(scanner, &passThrough{}, true, nil)

	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()
	interceptor.SetEventBus(bus)

	received := make(chan event.Event, 10)
	bus.SubscribeAll(func(_ context.Context, evt event.Event) {
		received <- evt
	})

	a := &CanonicalAction{
		Type: ActionToolCall,
		Name: "write_file",
		Identity: ActionIdentity{
			ID: "test-agent",
		},
		Arguments: map[string]interface{}{
			"content": "Send to john@example.com",
		},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for event.
	select {
	case evt := <-received:
		if evt.Type != "content.pii_detected" {
			t.Errorf("expected content.pii_detected event, got %s", evt.Type)
		}
		if evt.Source != "content-scanner" {
			t.Errorf("expected source content-scanner, got %s", evt.Source)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestContentScanInterceptor_NilAction(t *testing.T) {
	scanner := NewContentScanner()
	interceptor := NewContentScanInterceptor(scanner, &passThrough{}, true, nil)

	result, err := interceptor.Intercept(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Fatal("expected nil result for nil action")
	}
}

func TestContentScanInterceptor_RemoveWhitelist(t *testing.T) {
	scanner := NewContentScanner()
	interceptor := NewContentScanInterceptor(scanner, &passThrough{}, true, nil)

	interceptor.AddWhitelistEntry(WhitelistEntry{
		ID:          "wl_test",
		PatternType: PatternEmail,
		Scope:       WhitelistScopeTool,
		Value:       "read_file",
	})

	if len(interceptor.GetWhitelist()) != 1 {
		t.Fatal("expected 1 whitelist entry")
	}

	if !interceptor.RemoveWhitelistEntry("wl_test") {
		t.Fatal("expected successful removal")
	}

	if len(interceptor.GetWhitelist()) != 0 {
		t.Fatal("expected 0 whitelist entries after removal")
	}

	if interceptor.RemoveWhitelistEntry("wl_nonexistent") {
		t.Fatal("expected failed removal for nonexistent entry")
	}
}
