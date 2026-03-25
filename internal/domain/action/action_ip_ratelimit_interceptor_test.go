package action

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestActionIPRateLimit_Allow(t *testing.T) {
	limiter := memory.NewRateLimiter()
	cfg := ratelimit.RateLimitConfig{Rate: 10, Burst: 10, Period: time.Minute}
	interceptor := NewActionIPRateLimitInterceptor(limiter, cfg, &passThrough{}, newTestLogger())

	ctx := context.WithValue(context.Background(), proxy.IPAddressKey, "1.2.3.4")
	act := &CanonicalAction{
		Type:      ActionToolCall,
		Name:      "read_file",
		Arguments: map[string]interface{}{"path": "/tmp/test.txt"},
		Identity:  ActionIdentity{ID: "user-1", Name: "Alice"},
	}

	result, err := interceptor.Intercept(ctx, act)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result != act {
		t.Fatal("expected action to be passed through unchanged")
	}
}

func TestActionIPRateLimit_Deny(t *testing.T) {
	limiter := memory.NewRateLimiter()
	// GCRA with Rate=1 Burst=1 allows up to (Burst+1) initial requests
	// before denying. Use Rate=1 Burst=1 and send 3 requests; the 3rd
	// will be denied because TAT exceeds the burst window.
	cfg := ratelimit.RateLimitConfig{Rate: 1, Burst: 1, Period: time.Minute}
	interceptor := NewActionIPRateLimitInterceptor(limiter, cfg, &passThrough{}, newTestLogger())

	ctx := context.WithValue(context.Background(), proxy.IPAddressKey, "10.0.0.1")
	act := &CanonicalAction{
		Type:      ActionToolCall,
		Name:      "write_file",
		Arguments: map[string]interface{}{"content": "data"},
		Identity:  ActionIdentity{ID: "user-2", Name: "Bob"},
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

func TestActionIPRateLimit_SkipsServerToClient(t *testing.T) {
	limiter := memory.NewRateLimiter()
	// Rate of 1 so any second call would be denied if checked.
	cfg := ratelimit.RateLimitConfig{Rate: 1, Burst: 1, Period: time.Minute}
	interceptor := NewActionIPRateLimitInterceptor(limiter, cfg, &passThrough{}, newTestLogger())

	ctx := context.WithValue(context.Background(), proxy.IPAddressKey, "10.0.0.2")
	serverMsg := &mcp.Message{Direction: mcp.ServerToClient}

	act := &CanonicalAction{
		Type:            ActionToolCall,
		Name:            "list_tools",
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
