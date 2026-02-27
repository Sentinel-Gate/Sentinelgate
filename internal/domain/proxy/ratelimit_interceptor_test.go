package proxy

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// mockRateLimiter is a test mock for ratelimit.RateLimiter.
type mockRateLimiter struct {
	allowFunc func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error)
}

func (m *mockRateLimiter) Allow(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
	if m.allowFunc != nil {
		return m.allowFunc(ctx, key, config)
	}
	return ratelimit.RateLimitResult{Allowed: true, Remaining: 100}, nil
}

// recordingInterceptor records if Intercept was called.
type recordingInterceptor struct {
	called  bool
	message *mcp.Message
}

func (r *recordingInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	r.called = true
	r.message = msg
	return msg, nil
}

// ===================== IPRateLimitInterceptor Tests =====================

func TestIPRateLimitInterceptor_IPAllowed(t *testing.T) {
	logger := slog.Default()
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			return ratelimit.RateLimitResult{Allowed: true, Remaining: 99}, nil
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewIPRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 100, Burst: 100, Period: time.Minute},
		next,
		logger,
	)

	ctx := context.WithValue(context.Background(), IPAddressKey, "192.168.1.1")
	msg := &mcp.Message{Direction: mcp.ClientToServer}

	result, err := interceptor.Intercept(ctx, msg)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !next.called {
		t.Error("expected next interceptor to be called")
	}
	if result != msg {
		t.Error("expected message to be passed through")
	}
}

func TestIPRateLimitInterceptor_IPBlocked(t *testing.T) {
	logger := slog.Default()
	retryAfter := 5 * time.Second
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			return ratelimit.RateLimitResult{
				Allowed:    false,
				Remaining:  0,
				RetryAfter: retryAfter,
			}, nil
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewIPRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 100, Burst: 100, Period: time.Minute},
		next,
		logger,
	)

	ctx := context.WithValue(context.Background(), IPAddressKey, "192.168.1.1")
	msg := &mcp.Message{Direction: mcp.ClientToServer}

	result, err := interceptor.Intercept(ctx, msg)

	if err == nil {
		t.Error("expected error, got nil")
	}
	var rateLimitErr *RateLimitError
	if !errors.As(err, &rateLimitErr) {
		t.Errorf("expected RateLimitError, got %T", err)
	}
	if rateLimitErr.RetryAfter != retryAfter {
		t.Errorf("expected RetryAfter %v, got %v", retryAfter, rateLimitErr.RetryAfter)
	}
	if next.called {
		t.Error("expected next interceptor NOT to be called when rate limited")
	}
	if result != nil {
		t.Error("expected nil result when rate limited")
	}
}

func TestIPRateLimitInterceptor_IgnoresSession(t *testing.T) {
	logger := slog.Default()
	var checkedKeys []string
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			checkedKeys = append(checkedKeys, key)
			return ratelimit.RateLimitResult{Allowed: true, Remaining: 99}, nil
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewIPRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 100, Burst: 100, Period: time.Minute},
		next,
		logger,
	)

	ctx := context.WithValue(context.Background(), IPAddressKey, "192.168.1.1")
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Session: &session.Session{
			ID:         "sess-123",
			IdentityID: "user-456",
			Roles:      []auth.Role{auth.RoleUser},
		},
	}

	_, err := interceptor.Intercept(ctx, msg)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	// IPRateLimitInterceptor should only check IP, not user
	if len(checkedKeys) != 1 {
		t.Errorf("expected 1 rate limit check (IP only), got %d", len(checkedKeys))
	}
	if checkedKeys[0] != "ratelimit:ip:192.168.1.1" {
		t.Errorf("expected IP key, got %s", checkedKeys[0])
	}
}

func TestIPRateLimitInterceptor_RetryAfter(t *testing.T) {
	logger := slog.Default()
	expectedRetryAfter := 30 * time.Second
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			return ratelimit.RateLimitResult{
				Allowed:    false,
				Remaining:  0,
				RetryAfter: expectedRetryAfter,
				ResetAfter: time.Minute,
			}, nil
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewIPRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 100, Burst: 100, Period: time.Minute},
		next,
		logger,
	)

	ctx := context.WithValue(context.Background(), IPAddressKey, "192.168.1.1")
	msg := &mcp.Message{Direction: mcp.ClientToServer}

	_, err := interceptor.Intercept(ctx, msg)

	var rateLimitErr *RateLimitError
	if !errors.As(err, &rateLimitErr) {
		t.Fatalf("expected RateLimitError, got %T", err)
	}
	if rateLimitErr.RetryAfter != expectedRetryAfter {
		t.Errorf("expected RetryAfter %v, got %v", expectedRetryAfter, rateLimitErr.RetryAfter)
	}
}

func TestIPRateLimitInterceptor_NoIPInContext(t *testing.T) {
	logger := slog.Default()
	var checkedKey string
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			checkedKey = key
			return ratelimit.RateLimitResult{Allowed: true, Remaining: 99}, nil
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewIPRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 100, Burst: 100, Period: time.Minute},
		next,
		logger,
	)

	// No IP in context
	ctx := context.Background()
	msg := &mcp.Message{Direction: mcp.ClientToServer}

	_, err := interceptor.Intercept(ctx, msg)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	// Should use "unknown" as fallback
	if checkedKey != "ratelimit:ip:unknown" {
		t.Errorf("expected unknown IP key, got %s", checkedKey)
	}
}

func TestIPRateLimitInterceptor_ServerToClientPassthrough(t *testing.T) {
	logger := slog.Default()
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			t.Error("rate limiter should not be called for server-to-client messages")
			return ratelimit.RateLimitResult{Allowed: true}, nil
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewIPRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 100, Burst: 100, Period: time.Minute},
		next,
		logger,
	)

	ctx := context.Background()
	msg := &mcp.Message{Direction: mcp.ServerToClient}

	result, err := interceptor.Intercept(ctx, msg)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !next.called {
		t.Error("expected next interceptor to be called")
	}
	if result != msg {
		t.Error("expected message to be passed through")
	}
}

func TestIPRateLimitInterceptor_LimiterError(t *testing.T) {
	logger := slog.Default()
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			return ratelimit.RateLimitResult{}, errors.New("redis connection failed")
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewIPRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 100, Burst: 100, Period: time.Minute},
		next,
		logger,
	)

	ctx := context.WithValue(context.Background(), IPAddressKey, "192.168.1.1")
	msg := &mcp.Message{Direction: mcp.ClientToServer}

	// On error, should fail-open (allow through)
	result, err := interceptor.Intercept(ctx, msg)

	if err != nil {
		t.Errorf("expected no error on limiter failure (fail-open), got %v", err)
	}
	if !next.called {
		t.Error("expected next interceptor to be called (fail-open)")
	}
	if result != msg {
		t.Error("expected message to be passed through (fail-open)")
	}
}

// ===================== UserRateLimitInterceptor Tests =====================

func TestUserRateLimitInterceptor_UserAllowed(t *testing.T) {
	logger := slog.Default()
	var checkedKeys []string
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			checkedKeys = append(checkedKeys, key)
			return ratelimit.RateLimitResult{Allowed: true, Remaining: 99}, nil
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewUserRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 1000, Burst: 1000, Period: time.Minute},
		next,
		logger,
	)

	ctx := context.Background()
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Session: &session.Session{
			ID:         "sess-123",
			IdentityID: "user-456",
			Roles:      []auth.Role{auth.RoleUser},
		},
	}

	result, err := interceptor.Intercept(ctx, msg)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !next.called {
		t.Error("expected next interceptor to be called")
	}
	if result != msg {
		t.Error("expected message to be passed through")
	}

	// Verify user rate limit was checked
	if len(checkedKeys) != 1 {
		t.Errorf("expected 1 rate limit check, got %d", len(checkedKeys))
	}
	if checkedKeys[0] != "ratelimit:user:user-456" {
		t.Errorf("expected user key, got %s", checkedKeys[0])
	}
}

func TestUserRateLimitInterceptor_UserBlocked(t *testing.T) {
	logger := slog.Default()
	retryAfter := 10 * time.Second
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			return ratelimit.RateLimitResult{
				Allowed:    false,
				Remaining:  0,
				RetryAfter: retryAfter,
			}, nil
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewUserRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 1000, Burst: 1000, Period: time.Minute},
		next,
		logger,
	)

	ctx := context.Background()
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Session: &session.Session{
			ID:         "sess-123",
			IdentityID: "user-456",
			Roles:      []auth.Role{auth.RoleUser},
		},
	}

	result, err := interceptor.Intercept(ctx, msg)

	if err == nil {
		t.Error("expected error, got nil")
	}
	var rateLimitErr *RateLimitError
	if !errors.As(err, &rateLimitErr) {
		t.Errorf("expected RateLimitError, got %T", err)
	}
	if rateLimitErr.RetryAfter != retryAfter {
		t.Errorf("expected RetryAfter %v, got %v", retryAfter, rateLimitErr.RetryAfter)
	}
	if next.called {
		t.Error("expected next interceptor NOT to be called when rate limited")
	}
	if result != nil {
		t.Error("expected nil result when rate limited")
	}
}

func TestUserRateLimitInterceptor_NoSessionPassthrough(t *testing.T) {
	logger := slog.Default()
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			t.Error("rate limiter should not be called when session is nil")
			return ratelimit.RateLimitResult{Allowed: true}, nil
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewUserRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 1000, Burst: 1000, Period: time.Minute},
		next,
		logger,
	)

	ctx := context.Background()
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Session:   nil, // No session (unauthenticated)
	}

	result, err := interceptor.Intercept(ctx, msg)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !next.called {
		t.Error("expected next interceptor to be called")
	}
	if result != msg {
		t.Error("expected message to be passed through")
	}
}

func TestUserRateLimitInterceptor_EmptyIdentityPassthrough(t *testing.T) {
	logger := slog.Default()
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			t.Error("rate limiter should not be called when identity is empty")
			return ratelimit.RateLimitResult{Allowed: true}, nil
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewUserRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 1000, Burst: 1000, Period: time.Minute},
		next,
		logger,
	)

	ctx := context.Background()
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Session: &session.Session{
			ID:         "sess-123",
			IdentityID: "", // Empty identity
		},
	}

	result, err := interceptor.Intercept(ctx, msg)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !next.called {
		t.Error("expected next interceptor to be called")
	}
	if result != msg {
		t.Error("expected message to be passed through")
	}
}

func TestUserRateLimitInterceptor_ServerToClientPassthrough(t *testing.T) {
	logger := slog.Default()
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			t.Error("rate limiter should not be called for server-to-client messages")
			return ratelimit.RateLimitResult{Allowed: true}, nil
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewUserRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 1000, Burst: 1000, Period: time.Minute},
		next,
		logger,
	)

	ctx := context.Background()
	msg := &mcp.Message{Direction: mcp.ServerToClient}

	result, err := interceptor.Intercept(ctx, msg)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !next.called {
		t.Error("expected next interceptor to be called")
	}
	if result != msg {
		t.Error("expected message to be passed through")
	}
}

func TestUserRateLimitInterceptor_LimiterError(t *testing.T) {
	logger := slog.Default()
	limiter := &mockRateLimiter{
		allowFunc: func(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
			return ratelimit.RateLimitResult{}, errors.New("redis connection failed")
		},
	}
	next := &recordingInterceptor{}

	interceptor := NewUserRateLimitInterceptor(
		limiter,
		ratelimit.RateLimitConfig{Rate: 1000, Burst: 1000, Period: time.Minute},
		next,
		logger,
	)

	ctx := context.Background()
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Session: &session.Session{
			ID:         "sess-123",
			IdentityID: "user-456",
			Roles:      []auth.Role{auth.RoleUser},
		},
	}

	// On error, should fail-open (allow through)
	result, err := interceptor.Intercept(ctx, msg)

	if err != nil {
		t.Errorf("expected no error on limiter failure (fail-open), got %v", err)
	}
	if !next.called {
		t.Error("expected next interceptor to be called (fail-open)")
	}
	if result != msg {
		t.Error("expected message to be passed through (fail-open)")
	}
}
