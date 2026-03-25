package action

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
)

// setupAuthInterceptor creates a fully wired ActionAuthInterceptor for testing.
// It returns the interceptor and a cleanup function that must be deferred.
func setupAuthInterceptor(t *testing.T, addValidKey bool) *ActionAuthInterceptor {
	t.Helper()

	authStore := memory.NewAuthStore()
	authStore.AddIdentity(&auth.Identity{
		ID:    "test-id",
		Name:  "test-user",
		Roles: []auth.Role{auth.RoleUser},
	})

	if addValidKey {
		authStore.AddKey(&auth.APIKey{
			Key:        auth.HashKey("test-api-key"), //nolint:staticcheck // SHA-256 for test
			IdentityID: "test-id",
			CreatedAt:  time.Now(),
			Revoked:    false,
		})
	}

	sessionStore := memory.NewSessionStore()

	apiKeySvc := auth.NewAPIKeyService(authStore)
	sessionSvc := session.NewSessionService(sessionStore, session.Config{Timeout: 30 * time.Minute})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tracker := session.NewSessionTracker(1*time.Minute, session.DefaultClassifier())
	t.Cleanup(tracker.Stop)
	interceptor := NewActionAuthInterceptor(apiKeySvc, sessionSvc, &passThrough{}, logger, tracker)
	t.Cleanup(func() { interceptor.Stop() })

	return interceptor
}

func TestActionAuthInterceptor_ValidKey(t *testing.T) {
	interceptor := setupAuthInterceptor(t, true)

	ctx := context.WithValue(context.Background(), proxy.APIKeyContextKey, "test-api-key")
	ctx = context.WithValue(ctx, proxy.ConnectionIDKey, "conn-1")

	act := &CanonicalAction{
		Type:      ActionToolCall,
		Name:      "test_tool",
		Arguments: map[string]interface{}{"key": "value"},
	}

	result, err := interceptor.Intercept(ctx, act)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Identity.ID != "test-id" {
		t.Errorf("expected identity ID 'test-id', got %q", result.Identity.ID)
	}
	if result.Identity.Name != "test-user" {
		t.Errorf("expected identity name 'test-user', got %q", result.Identity.Name)
	}
	if result.Identity.SessionID == "" {
		t.Error("expected session ID to be populated")
	}
}

func TestActionAuthInterceptor_InvalidKey(t *testing.T) {
	interceptor := setupAuthInterceptor(t, true)

	ctx := context.WithValue(context.Background(), proxy.APIKeyContextKey, "wrong-api-key")
	ctx = context.WithValue(ctx, proxy.ConnectionIDKey, "conn-1")

	act := &CanonicalAction{
		Type: ActionToolCall,
		Name: "test_tool",
	}

	result, err := interceptor.Intercept(ctx, act)
	if err == nil {
		t.Fatal("expected error for invalid API key")
	}
	if !errors.Is(err, proxy.ErrInvalidAPIKey) {
		t.Errorf("expected ErrInvalidAPIKey, got: %v", err)
	}
	if result != nil {
		t.Error("expected nil result on auth failure")
	}
}

func TestActionAuthInterceptor_MissingKey(t *testing.T) {
	interceptor := setupAuthInterceptor(t, true)

	// No API key in context, no cached session
	ctx := context.WithValue(context.Background(), proxy.ConnectionIDKey, "conn-1")

	act := &CanonicalAction{
		Type: ActionToolCall,
		Name: "test_tool",
	}

	result, err := interceptor.Intercept(ctx, act)
	if err == nil {
		t.Fatal("expected error for missing API key")
	}
	if !errors.Is(err, proxy.ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated, got: %v", err)
	}
	if result != nil {
		t.Error("expected nil result on auth failure")
	}
}

func TestActionAuthInterceptor_SessionCache(t *testing.T) {
	interceptor := setupAuthInterceptor(t, true)

	connID := "conn-cache-1"
	ctx := context.WithValue(context.Background(), proxy.APIKeyContextKey, "test-api-key")
	ctx = context.WithValue(ctx, proxy.ConnectionIDKey, connID)

	act1 := &CanonicalAction{
		Type: ActionToolCall,
		Name: "first_call",
	}

	// First call creates a session
	result1, err := interceptor.Intercept(ctx, act1)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	firstSessionID := result1.Identity.SessionID

	// Second call on same connection should reuse cached session
	act2 := &CanonicalAction{
		Type: ActionToolCall,
		Name: "second_call",
	}

	// Use context without API key -- the cached session should suffice
	ctx2 := context.WithValue(context.Background(), proxy.ConnectionIDKey, connID)

	result2, err := interceptor.Intercept(ctx2, act2)
	if err != nil {
		t.Fatalf("second call failed (expected cached session): %v", err)
	}
	if result2.Identity.SessionID != firstSessionID {
		t.Errorf("expected reused session %q, got %q", firstSessionID, result2.Identity.SessionID)
	}
}

func TestActionAuthInterceptor_Stop(t *testing.T) {
	interceptor := setupAuthInterceptor(t, true)

	// Start the cleanup goroutine so Stop() has something to shut down
	interceptor.StartCleanup(context.Background())

	// Stop should complete without panic or hang
	interceptor.Stop()

	// Calling Stop again should be safe (sync.Once)
	interceptor.Stop()
}
