package action

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

func TestActionUserRateLimit_Allow(t *testing.T) {
	limiter := memory.NewRateLimiter()
	cfg := ratelimit.RateLimitConfig{Rate: 10, Burst: 10, Period: time.Minute}
	interceptor := NewActionUserRateLimitInterceptor(limiter, cfg, &passThrough{}, newTestLogger())

	ctx := context.Background()
	act := &CanonicalAction{
		Type:      ActionToolCall,
		Name:      "read_file",
		Arguments: map[string]interface{}{"path": "/tmp/test.txt"},
		Identity:  ActionIdentity{ID: "user-100", Name: "Alice"},
	}

	result, err := interceptor.Intercept(ctx, act)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result != act {
		t.Fatal("expected action to be passed through unchanged")
	}
}

func TestActionUserRateLimit_Deny(t *testing.T) {
	limiter := memory.NewRateLimiter()
	// GCRA with Rate=1 Burst=1 allows up to (Burst+1) initial requests
	// before denying. Use Rate=1 Burst=1 and send 3 requests; the 3rd
	// will be denied because TAT exceeds the burst window.
	cfg := ratelimit.RateLimitConfig{Rate: 1, Burst: 1, Period: time.Minute}
	interceptor := NewActionUserRateLimitInterceptor(limiter, cfg, &passThrough{}, newTestLogger())

	ctx := context.Background()
	act := &CanonicalAction{
		Type:      ActionToolCall,
		Name:      "write_file",
		Arguments: map[string]interface{}{"content": "data"},
		Identity:  ActionIdentity{ID: "user-200", Name: "Bob"},
	}

	// First two requests should be allowed (burst window).
	for i := 0; i < 2; i++ {
		_, err := interceptor.Intercept(ctx, act)
		if err != nil {
			t.Fatalf("request %d: expected no error, got %v", i+1, err)
		}
	}

	// Third request should be denied (burst exhausted).
	_, err := interceptor.Intercept(ctx, act)
	if err == nil {
		t.Fatal("expected rate limit error, got nil")
	}
	var rateLimitErr *proxy.RateLimitError
	if !errors.As(err, &rateLimitErr) {
		t.Fatalf("expected *proxy.RateLimitError, got %T: %v", err, err)
	}
	if rateLimitErr.RetryAfter <= 0 {
		t.Errorf("expected positive RetryAfter, got %v", rateLimitErr.RetryAfter)
	}
}

func TestActionUserRateLimit_NoIdentity(t *testing.T) {
	limiter := memory.NewRateLimiter()
	// Rate of 1 so any check would quickly deny.
	cfg := ratelimit.RateLimitConfig{Rate: 1, Burst: 1, Period: time.Minute}
	interceptor := NewActionUserRateLimitInterceptor(limiter, cfg, &passThrough{}, newTestLogger())

	ctx := context.Background()
	act := &CanonicalAction{
		Type:      ActionToolCall,
		Name:      "read_file",
		Arguments: map[string]interface{}{"path": "/tmp/x"},
		Identity:  ActionIdentity{}, // Empty ID => skip rate limit check
	}

	// Multiple calls should all pass because empty Identity.ID skips the check.
	for i := 0; i < 5; i++ {
		result, err := interceptor.Intercept(ctx, act)
		if err != nil {
			t.Fatalf("call %d: expected no error for empty identity, got %v", i+1, err)
		}
		if result != act {
			t.Fatalf("call %d: expected action to be passed through", i+1)
		}
	}
}

func TestActionUserRateLimit_SkipsServerToClient(t *testing.T) {
	limiter := memory.NewRateLimiter()
	cfg := ratelimit.RateLimitConfig{Rate: 1, Burst: 1, Period: time.Minute}
	interceptor := NewActionUserRateLimitInterceptor(limiter, cfg, &passThrough{}, newTestLogger())

	ctx := context.Background()
	serverMsg := &mcp.Message{Direction: mcp.ServerToClient}

	act := &CanonicalAction{
		Type:            ActionToolCall,
		Name:            "list_tools",
		Identity:        ActionIdentity{ID: "user-300", Name: "Charlie"},
		OriginalMessage: serverMsg,
	}

	// Both calls should pass through because ServerToClient skips the rate check.
	for i := 0; i < 3; i++ {
		result, err := interceptor.Intercept(ctx, act)
		if err != nil {
			t.Fatalf("call %d: expected no error for server-to-client, got %v", i+1, err)
		}
		if result != act {
			t.Fatalf("call %d: expected action to be passed through", i+1)
		}
	}
}
