package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"go.uber.org/goleak"
)

// mockAuthStore implements auth.AuthStore for testing.
type mockAuthStore struct {
	keys       map[string]*auth.APIKey
	identities map[string]*auth.Identity
}

func newMockAuthStore() *mockAuthStore {
	return &mockAuthStore{
		keys:       make(map[string]*auth.APIKey),
		identities: make(map[string]*auth.Identity),
	}
}

func (m *mockAuthStore) GetAPIKey(ctx context.Context, keyHash string) (*auth.APIKey, error) {
	key, ok := m.keys[keyHash]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

func (m *mockAuthStore) GetIdentity(ctx context.Context, id string) (*auth.Identity, error) {
	identity, ok := m.identities[id]
	if !ok {
		return nil, errors.New("identity not found")
	}
	return identity, nil
}

func (m *mockAuthStore) ListAPIKeys(ctx context.Context) ([]*auth.APIKey, error) {
	result := make([]*auth.APIKey, 0, len(m.keys))
	for _, key := range m.keys {
		result = append(result, key)
	}
	return result, nil
}

func (m *mockAuthStore) AddKey(key *auth.APIKey) {
	m.keys[key.Key] = key
}

func (m *mockAuthStore) AddIdentity(identity *auth.Identity) {
	m.identities[identity.ID] = identity
}

// mockSessionStore implements session.SessionStore for testing.
type mockSessionStore struct {
	sessions map[string]*session.Session
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]*session.Session),
	}
}

func (m *mockSessionStore) Create(ctx context.Context, sess *session.Session) error {
	m.sessions[sess.ID] = sess
	return nil
}

func (m *mockSessionStore) Get(ctx context.Context, id string) (*session.Session, error) {
	sess, ok := m.sessions[id]
	if !ok {
		return nil, session.ErrSessionNotFound
	}
	return sess, nil
}

func (m *mockSessionStore) Update(ctx context.Context, sess *session.Session) error {
	if _, ok := m.sessions[sess.ID]; !ok {
		return session.ErrSessionNotFound
	}
	m.sessions[sess.ID] = sess
	return nil
}

func (m *mockSessionStore) Delete(ctx context.Context, id string) error {
	delete(m.sessions, id)
	return nil
}

// createTestMessage creates a test MCP message with the given API key in params.
func createTestMessage(apiKey string) *mcp.Message {
	var params []byte
	if apiKey != "" {
		params = []byte(`{"apiKey":"` + apiKey + `","other":"value"}`)
	} else {
		params = []byte(`{"other":"value"}`)
	}

	id, _ := jsonrpc.MakeID(float64(1))

	return &mcp.Message{
		Raw:       []byte(`{"jsonrpc":"2.0","method":"test","params":{}}`),
		Direction: mcp.ClientToServer,
		Decoded: &jsonrpc.Request{
			ID:     id,
			Method: "test",
			Params: params,
		},
		Timestamp: time.Now(),
	}
}

func TestAuthInterceptor_ValidAPIKey(t *testing.T) {
	// Setup
	authStore := newMockAuthStore()
	authStore.AddIdentity(&auth.Identity{
		ID:    "user-1",
		Name:  "Test User",
		Roles: []auth.Role{auth.RoleUser},
	})
	authStore.AddKey(&auth.APIKey{
		Key:        auth.HashKey("valid-api-key"),
		IdentityID: "user-1",
		CreatedAt:  time.Now(),
		Revoked:    false,
	})

	sessionStore := newMockSessionStore()

	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{Timeout: 30 * time.Minute})
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	passthrough := NewPassthroughInterceptor()

	interceptor := NewAuthInterceptor(apiKeyService, sessionService, passthrough, logger, false)

	// Test
	ctx := context.WithValue(context.Background(), ConnectionIDKey, "conn-1")
	msg := createTestMessage("valid-api-key")

	result, err := interceptor.Intercept(ctx, msg)

	// Assert
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected message to be returned")
		return
	}
	if result.Session == nil {
		t.Fatal("expected session to be attached")
		return
	}
	if result.Session.IdentityID != "user-1" {
		t.Errorf("expected identity ID 'user-1', got: %s", result.Session.IdentityID)
	}
}

func TestAuthInterceptor_InvalidAPIKey(t *testing.T) {
	// Setup
	authStore := newMockAuthStore()
	authStore.AddIdentity(&auth.Identity{
		ID:    "user-1",
		Name:  "Test User",
		Roles: []auth.Role{auth.RoleUser},
	})
	authStore.AddKey(&auth.APIKey{
		Key:        auth.HashKey("valid-api-key"),
		IdentityID: "user-1",
		CreatedAt:  time.Now(),
		Revoked:    false,
	})

	sessionStore := newMockSessionStore()

	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{Timeout: 30 * time.Minute})
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	passthrough := NewPassthroughInterceptor()

	interceptor := NewAuthInterceptor(apiKeyService, sessionService, passthrough, logger, false)

	// Test
	ctx := context.WithValue(context.Background(), ConnectionIDKey, "conn-1")
	msg := createTestMessage("invalid-api-key")

	result, err := interceptor.Intercept(ctx, msg)

	// Assert
	if err == nil {
		t.Fatal("expected error for invalid API key")
	}
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("expected ErrInvalidAPIKey, got: %v", err)
	}
	if result != nil {
		t.Error("expected nil message on auth failure")
	}
}

func TestAuthInterceptor_NoAPIKeyNoSession(t *testing.T) {
	// Setup
	authStore := newMockAuthStore()
	sessionStore := newMockSessionStore()

	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{Timeout: 30 * time.Minute})
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	passthrough := NewPassthroughInterceptor()

	interceptor := NewAuthInterceptor(apiKeyService, sessionService, passthrough, logger, false)

	// Test - message with no API key
	ctx := context.WithValue(context.Background(), ConnectionIDKey, "conn-1")
	msg := createTestMessage("")

	result, err := interceptor.Intercept(ctx, msg)

	// Assert
	if err == nil {
		t.Fatal("expected error for missing authentication")
	}
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated, got: %v", err)
	}
	if result != nil {
		t.Error("expected nil message on auth failure")
	}
}

func TestAuthInterceptor_CachedSession(t *testing.T) {
	// Setup
	authStore := newMockAuthStore()
	authStore.AddIdentity(&auth.Identity{
		ID:    "user-1",
		Name:  "Test User",
		Roles: []auth.Role{auth.RoleUser},
	})
	authStore.AddKey(&auth.APIKey{
		Key:        auth.HashKey("valid-api-key"),
		IdentityID: "user-1",
		CreatedAt:  time.Now(),
		Revoked:    false,
	})

	sessionStore := newMockSessionStore()

	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{Timeout: 30 * time.Minute})
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	passthrough := NewPassthroughInterceptor()

	interceptor := NewAuthInterceptor(apiKeyService, sessionService, passthrough, logger, false)

	ctx := context.WithValue(context.Background(), ConnectionIDKey, "conn-1")

	// First request with API key - creates session
	msg1 := createTestMessage("valid-api-key")
	result1, err := interceptor.Intercept(ctx, msg1)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	sessionID := result1.Session.ID

	// Second request without API key - should use cached session
	msg2 := createTestMessage("")
	result2, err := interceptor.Intercept(ctx, msg2)

	// Assert
	if err != nil {
		t.Fatalf("expected cached session to be used, got error: %v", err)
	}
	if result2.Session == nil {
		t.Fatal("expected session to be attached from cache")
	}
	if result2.Session.ID != sessionID {
		t.Errorf("expected same session ID, got different: %s vs %s", result2.Session.ID, sessionID)
	}
}

func TestAuthInterceptor_DifferentConnectionRequiresAuth(t *testing.T) {
	// Setup
	authStore := newMockAuthStore()
	authStore.AddIdentity(&auth.Identity{
		ID:    "user-1",
		Name:  "Test User",
		Roles: []auth.Role{auth.RoleUser},
	})
	authStore.AddKey(&auth.APIKey{
		Key:        auth.HashKey("valid-api-key"),
		IdentityID: "user-1",
		CreatedAt:  time.Now(),
		Revoked:    false,
	})

	sessionStore := newMockSessionStore()

	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{Timeout: 30 * time.Minute})
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	passthrough := NewPassthroughInterceptor()

	interceptor := NewAuthInterceptor(apiKeyService, sessionService, passthrough, logger, false)

	// First connection - authenticate
	ctx1 := context.WithValue(context.Background(), ConnectionIDKey, "conn-1")
	msg1 := createTestMessage("valid-api-key")
	_, err := interceptor.Intercept(ctx1, msg1)
	if err != nil {
		t.Fatalf("first connection failed: %v", err)
	}

	// Different connection without API key - should fail
	ctx2 := context.WithValue(context.Background(), ConnectionIDKey, "conn-2")
	msg2 := createTestMessage("")

	result, err := interceptor.Intercept(ctx2, msg2)

	// Assert
	if err == nil {
		t.Fatal("expected error for different connection without auth")
	}
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated, got: %v", err)
	}
	if result != nil {
		t.Error("expected nil message")
	}
}

func TestAuthInterceptor_ExpiredSession(t *testing.T) {
	// Setup
	authStore := newMockAuthStore()
	authStore.AddIdentity(&auth.Identity{
		ID:    "user-1",
		Name:  "Test User",
		Roles: []auth.Role{auth.RoleUser},
	})
	authStore.AddKey(&auth.APIKey{
		Key:        auth.HashKey("valid-api-key"),
		IdentityID: "user-1",
		CreatedAt:  time.Now(),
		Revoked:    false,
	})

	sessionStore := newMockSessionStore()

	apiKeyService := auth.NewAPIKeyService(authStore)
	// Very short timeout for test
	sessionService := session.NewSessionService(sessionStore, session.Config{Timeout: 1 * time.Millisecond})
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	passthrough := NewPassthroughInterceptor()

	interceptor := NewAuthInterceptor(apiKeyService, sessionService, passthrough, logger, false)

	ctx := context.WithValue(context.Background(), ConnectionIDKey, "conn-1")

	// First request with API key - creates session
	msg1 := createTestMessage("valid-api-key")
	_, err := interceptor.Intercept(ctx, msg1)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}

	// Wait for session to expire
	time.Sleep(10 * time.Millisecond)

	// Second request without API key - session should be expired
	msg2 := createTestMessage("")
	result, err := interceptor.Intercept(ctx, msg2)

	// Assert
	if err == nil {
		t.Fatal("expected error for expired session")
	}
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated, got: %v", err)
	}
	if result != nil {
		t.Error("expected nil message on expired session")
	}
}

func TestCreateJSONRPCError(t *testing.T) {
	result := CreateJSONRPCError("123", -32600, "Invalid Request")

	expected := `{"error":{"code":-32600,"message":"Invalid Request"},"id":"123","jsonrpc":"2.0"}`
	if string(result) != expected {
		t.Errorf("unexpected JSON-RPC error:\ngot:  %s\nwant: %s", string(result), expected)
	}
}

func TestCreateJSONRPCError_NilID(t *testing.T) {
	result := CreateJSONRPCError(nil, -32600, "Invalid Request")

	expected := `{"error":{"code":-32600,"message":"Invalid Request"},"id":null,"jsonrpc":"2.0"}`
	if string(result) != expected {
		t.Errorf("unexpected JSON-RPC error:\ngot:  %s\nwant: %s", string(result), expected)
	}
}

func TestAuthInterceptorCacheCleanup(t *testing.T) {
	// Create interceptor with short cleanup intervals for testing
	authStore := newMockAuthStore()
	sessionStore := newMockSessionStore()
	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{Timeout: 30 * time.Minute})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	passthrough := NewPassthroughInterceptor()

	interceptor := NewAuthInterceptorWithConfig(
		apiKeyService,
		sessionService,
		passthrough,
		logger,
		false,
		50*time.Millisecond,  // cleanupInterval
		100*time.Millisecond, // cacheMaxAge
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer interceptor.Stop()

	interceptor.StartCleanup(ctx)

	// Add test cache entries
	interceptor.SetTestCacheEntry("conn-1", "sess-1")
	interceptor.SetTestCacheEntry("conn-2", "sess-2")
	interceptor.SetTestCacheEntry("conn-3", "sess-3")

	// Verify entries exist
	if interceptor.CacheSize() != 3 {
		t.Errorf("expected cache size 3, got %d", interceptor.CacheSize())
	}

	// Wait for entries to expire and cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Verify entries were cleaned
	if interceptor.CacheSize() != 0 {
		t.Errorf("expected cache size 0 after cleanup, got %d", interceptor.CacheSize())
	}
}

func TestAuthInterceptorNoGoroutineLeak(t *testing.T) {
	defer goleak.VerifyNone(t)

	authStore := newMockAuthStore()
	sessionStore := newMockSessionStore()
	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{Timeout: 30 * time.Minute})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	passthrough := NewPassthroughInterceptor()

	interceptor := NewAuthInterceptorWithConfig(
		apiKeyService,
		sessionService,
		passthrough,
		logger,
		false,
		50*time.Millisecond,
		100*time.Millisecond,
	)

	ctx, cancel := context.WithCancel(context.Background())

	interceptor.StartCleanup(ctx)

	// Add some cache entries
	interceptor.SetTestCacheEntry("conn-1", "sess-1")
	interceptor.SetTestCacheEntry("conn-2", "sess-2")

	// Let cleanup run a few cycles
	time.Sleep(150 * time.Millisecond)

	// Stop cleanup
	cancel()
	interceptor.Stop()

	// goleak.VerifyNone will fail if goroutine leaked
}

func TestAuthInterceptorConcurrentCacheAccess(t *testing.T) {
	authStore := newMockAuthStore()
	sessionStore := newMockSessionStore()
	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{Timeout: 30 * time.Minute})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	passthrough := NewPassthroughInterceptor()

	interceptor := NewAuthInterceptorWithConfig(
		apiKeyService,
		sessionService,
		passthrough,
		logger,
		false,
		10*time.Millisecond, // Very short cleanup interval
		50*time.Millisecond,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer interceptor.Stop()

	interceptor.StartCleanup(ctx)

	// Launch concurrent goroutines
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				connID := "conn-" + string(rune('A'+id)) + "-" + string(rune('0'+j%10))
				interceptor.SetTestCacheEntry(connID, "sess-"+connID)
				_ = interceptor.CacheSize()
				interceptor.ClearSession(connID)
			}
		}(i)
	}

	wg.Wait()
}

func TestAuthInterceptorStopMultipleCalls(t *testing.T) {
	defer goleak.VerifyNone(t)

	authStore := newMockAuthStore()
	sessionStore := newMockSessionStore()
	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{Timeout: 30 * time.Minute})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	passthrough := NewPassthroughInterceptor()

	interceptor := NewAuthInterceptor(apiKeyService, sessionService, passthrough, logger, false)

	ctx, cancel := context.WithCancel(context.Background())
	interceptor.StartCleanup(ctx)

	cancel()

	// Multiple Stop() calls should not panic
	interceptor.Stop()
	interceptor.Stop()
	interceptor.Stop()
}

func TestLogDevModeWarning_DevModeDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := LogDevModeWarning(logger, false)
	if err != nil {
		t.Errorf("expected nil error for devMode=false, got %v", err)
	}
}

func TestLogDevModeWarning_DevModeEnabled(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	err := LogDevModeWarning(logger, true)
	if err != nil {
		t.Errorf("expected nil error for devMode=true without block, got %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "SECURITY WARNING") {
		t.Errorf("expected SECURITY WARNING in log output, got: %s", output)
	}
}

func TestLogDevModeWarning_Blocked(t *testing.T) {
	// Set env var to block DevMode
	t.Setenv("SENTINELGATE_ALLOW_DEVMODE", "false")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := LogDevModeWarning(logger, true)

	if err == nil {
		t.Error("expected error when DevMode is blocked")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("expected 'blocked' in error message, got: %v", err)
	}
}
