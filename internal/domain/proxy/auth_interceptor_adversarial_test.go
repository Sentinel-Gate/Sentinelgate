package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// setupAdversarialInterceptor creates an AuthInterceptor with the given identities and keys
// registered in mock stores. Returns the interceptor and session store for inspection.
func setupAdversarialInterceptor(t *testing.T, identities []*auth.Identity, keys []*auth.APIKey) (*AuthInterceptor, *mockSessionStore) {
	t.Helper()

	authStore := newMockAuthStore()
	for _, id := range identities {
		authStore.AddIdentity(id)
	}
	for _, k := range keys {
		authStore.AddKey(k)
	}

	sessionStore := newMockSessionStore()
	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{Timeout: 30 * time.Minute})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	passthrough := NewPassthroughInterceptor()

	interceptor := NewAuthInterceptor(apiKeyService, sessionService, passthrough, logger)
	return interceptor, sessionStore
}

// createTestMessageWithMethod creates a test MCP message with the given API key and method.
func createTestMessageWithMethod(apiKey, method string) *mcp.Message {
	var params []byte
	if apiKey != "" {
		params = []byte(`{"apiKey":"` + apiKey + `","other":"value"}`)
	} else {
		params = []byte(`{"other":"value"}`)
	}

	id, _ := jsonrpc.MakeID(float64(1))

	return &mcp.Message{
		Raw:       []byte(fmt.Sprintf(`{"jsonrpc":"2.0","method":"%s","params":{}}`, method)),
		Direction: mcp.ClientToServer,
		Decoded: &jsonrpc.Request{
			ID:     id,
			Method: method,
			Params: params,
		},
		Timestamp: time.Now(),
	}
}

// createTestMessageWithCustomParams creates a test MCP message with custom raw params JSON.
func createTestMessageWithCustomParams(paramsJSON string, method string) *mcp.Message {
	id, _ := jsonrpc.MakeID(float64(1))

	return &mcp.Message{
		Raw:       []byte(fmt.Sprintf(`{"jsonrpc":"2.0","method":"%s","params":%s}`, method, paramsJSON)),
		Direction: mcp.ClientToServer,
		Decoded: &jsonrpc.Request{
			ID:     id,
			Method: method,
			Params: json.RawMessage(paramsJSON),
		},
		Timestamp: time.Now(),
	}
}

// --- Test 3A.1: No API key returns generic error ---

func TestAuthInterceptor_NoAPIKey_GenericError(t *testing.T) {
	interceptor, _ := setupAdversarialInterceptor(t, nil, nil)

	ctx := context.WithValue(context.Background(), ConnectionIDKey, "conn-1")
	msg := createTestMessage("")

	_, err := interceptor.Intercept(ctx, msg)

	// Must return ErrUnauthenticated
	if err == nil {
		t.Fatal("expected error for missing API key, got nil")
	}
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected ErrUnauthenticated, got: %v", err)
	}

	// SafeErrorMessage must return generic message, not internal details
	safeMsg := SafeErrorMessage(err)
	if safeMsg != "Authentication required" {
		t.Errorf("SafeErrorMessage = %q, want %q", safeMsg, "Authentication required")
	}

	// Must NOT contain internal details like field paths
	for _, forbidden := range []string{"params", "_meta", "apiKey", "missing", "header"} {
		if contains(safeMsg, forbidden) {
			t.Errorf("SafeErrorMessage contains forbidden detail %q: %s", forbidden, safeMsg)
		}
	}
}

// contains is a simple substring check helper.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- Test 3A.2: API key in wrong position ---

func TestAuthInterceptor_APIKeyWrongPosition(t *testing.T) {
	identities := []*auth.Identity{{
		ID:    "user-1",
		Name:  "Test User",
		Roles: []auth.Role{auth.RoleUser},
	}}
	keys := []*auth.APIKey{{
		Key:        auth.HashKey("valid-key"), //nolint:staticcheck // SA1019: testing backward-compatible key lookup
		IdentityID: "user-1",
		CreatedAt:  time.Now(),
		Revoked:    false,
	}}
	interceptor, _ := setupAdversarialInterceptor(t, identities, keys)

	ctx := context.WithValue(context.Background(), ConnectionIDKey, "conn-1")

	// API key placed in params.key instead of params.apiKey or params._meta.apiKey
	msg := createTestMessageWithCustomParams(`{"key":"valid-key","other":"value"}`, "test")

	_, err := interceptor.Intercept(ctx, msg)

	// ExtractAPIKey() only checks params._meta.apiKey and params.apiKey
	// params.key is not checked, so this should fail as unauthenticated
	if err == nil {
		t.Fatal("expected error when API key is in wrong position, got nil")
	}
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated, got: %v", err)
	}
}

// --- Test 3A.3: Cached session expired ---

func TestAuthInterceptor_CachedSessionExpired(t *testing.T) {
	identities := []*auth.Identity{{
		ID:    "user-1",
		Name:  "Test User",
		Roles: []auth.Role{auth.RoleUser},
	}}
	keys := []*auth.APIKey{{
		Key:        auth.HashKey("valid-key"), //nolint:staticcheck // SA1019: testing backward-compatible key lookup
		IdentityID: "user-1",
		CreatedAt:  time.Now(),
		Revoked:    false,
	}}
	interceptor, sessionStore := setupAdversarialInterceptor(t, identities, keys)

	// Manually insert an expired session in the session store
	expiredSession := &session.Session{
		ID:           "expired-sess-id",
		IdentityID:   "user-1",
		IdentityName: "Test User",
		Roles:        []auth.Role{auth.RoleUser},
		CreatedAt:    time.Now().Add(-2 * time.Hour),
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // expired 1 hour ago
		LastAccess:   time.Now().Add(-1 * time.Hour),
	}
	sessionStore.sessions["expired-sess-id"] = expiredSession

	// Pre-cache the expired session
	interceptor.SetTestCacheEntry("conn-1", "expired-sess-id")

	ctx := context.WithValue(context.Background(), ConnectionIDKey, "conn-1")
	// No API key -- relies on cached session which is expired
	msg := createTestMessage("")

	_, err := interceptor.Intercept(ctx, msg)

	// The expired session should be evicted from cache.
	// Since no API key is provided, it should fail with ErrUnauthenticated.
	if err == nil {
		t.Fatal("expected error for expired cached session with no API key, got nil")
	}
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("expected ErrUnauthenticated, got: %v", err)
	}

	// Cache should be empty now
	if interceptor.CacheSize() != 0 {
		t.Errorf("expected cache size 0 after expired session eviction, got %d", interceptor.CacheSize())
	}
}

// --- Test 3A.4: SQL injection in API key ---

func TestAuthInterceptor_APIKeyInjection(t *testing.T) {
	identities := []*auth.Identity{{
		ID:    "user-1",
		Name:  "Test User",
		Roles: []auth.Role{auth.RoleUser},
	}}
	keys := []*auth.APIKey{{
		Key:        auth.HashKey("valid-key"), //nolint:staticcheck // SA1019: testing backward-compatible key lookup
		IdentityID: "user-1",
		CreatedAt:  time.Now(),
		Revoked:    false,
	}}
	interceptor, _ := setupAdversarialInterceptor(t, identities, keys)

	ctx := context.WithValue(context.Background(), ConnectionIDKey, "conn-1")

	// SQL injection attempt as API key — must be valid JSON so ExtractAPIKey can find it
	injectionKey := "'; DROP TABLE sessions; --"
	// Build params with proper JSON encoding
	paramsMap := map[string]interface{}{
		"apiKey": injectionKey,
		"other":  "value",
	}
	paramsJSON, _ := json.Marshal(paramsMap)
	msg := createTestMessageWithCustomParams(string(paramsJSON), "test")

	_, err := interceptor.Intercept(ctx, msg)

	// Must fail with ErrInvalidAPIKey (the key doesn't match any stored hash)
	if err == nil {
		t.Fatal("expected error for injection API key, got nil")
	}
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("expected ErrInvalidAPIKey, got: %v", err)
	}

	// SafeErrorMessage must NOT contain the SQL injection payload
	safeMsg := SafeErrorMessage(err)
	if safeMsg != "Invalid API key" {
		t.Errorf("SafeErrorMessage = %q, want %q", safeMsg, "Invalid API key")
	}
	for _, forbidden := range []string{"DROP", "TABLE", "sessions", "--", "SQL"} {
		if contains(safeMsg, forbidden) {
			t.Errorf("SafeErrorMessage leaks injection detail %q: %s", forbidden, safeMsg)
		}
	}
}

// --- Test 3A.5: Initialize resets session ---

func TestAuthInterceptor_InitializeResetsSession(t *testing.T) {
	identities := []*auth.Identity{
		{
			ID:    "user-A",
			Name:  "User A",
			Roles: []auth.Role{auth.RoleUser},
		},
		{
			ID:    "user-B",
			Name:  "User B",
			Roles: []auth.Role{auth.RoleUser},
		},
	}
	keys := []*auth.APIKey{
		{
			Key:        auth.HashKey("key-A"), //nolint:staticcheck // SA1019: backward-compatible key lookup
			IdentityID: "user-A",
			CreatedAt:  time.Now(),
			Revoked:    false,
		},
		{
			Key:        auth.HashKey("key-B"), //nolint:staticcheck // SA1019: backward-compatible key lookup
			IdentityID: "user-B",
			CreatedAt:  time.Now(),
			Revoked:    false,
		},
	}
	interceptor, _ := setupAdversarialInterceptor(t, identities, keys)

	connID := "conn-1"
	ctx := context.WithValue(context.Background(), ConnectionIDKey, connID)

	// First: authenticate with key-A
	msg1 := createTestMessageWithMethod("key-A", "test")
	result1, err := interceptor.Intercept(ctx, msg1)
	if err != nil {
		t.Fatalf("first request with key-A failed: %v", err)
	}
	if result1.Session.IdentityID != "user-A" {
		t.Fatalf("expected identity user-A, got %s", result1.Session.IdentityID)
	}
	sessionA := result1.Session.ID

	// Second: send "initialize" with key-B on same connID
	msg2 := createTestMessageWithMethod("key-B", "initialize")
	result2, err := interceptor.Intercept(ctx, msg2)
	if err != nil {
		t.Fatalf("initialize with key-B failed: %v", err)
	}

	// The initialize message should have cleared the cache and created a new session
	if result2.Session.ID == sessionA {
		t.Error("expected new session after initialize, got same session ID")
	}
	if result2.Session.IdentityID != "user-B" {
		t.Errorf("expected identity user-B after initialize with key-B, got %s", result2.Session.IdentityID)
	}
}

// --- Test 3A.6: Session cache bypass on same connID (EXPOSES BUG B3) ---

func TestAuthInterceptor_SessionCacheBypass_SameConnID(t *testing.T) {
	identities := []*auth.Identity{
		{
			ID:    "user-A",
			Name:  "User A",
			Roles: []auth.Role{auth.RoleUser},
		},
		{
			ID:    "user-B",
			Name:  "User B",
			Roles: []auth.Role{auth.RoleUser},
		},
	}
	keys := []*auth.APIKey{
		{
			Key:        auth.HashKey("key-A"), //nolint:staticcheck // SA1019: backward-compatible key lookup
			IdentityID: "user-A",
			CreatedAt:  time.Now(),
			Revoked:    false,
		},
		{
			Key:        auth.HashKey("key-B"), //nolint:staticcheck // SA1019: backward-compatible key lookup
			IdentityID: "user-B",
			CreatedAt:  time.Now(),
			Revoked:    false,
		},
	}
	interceptor, _ := setupAdversarialInterceptor(t, identities, keys)

	// Simulate stdio transport: all clients share connID="default"
	connID := "default"
	ctx := context.WithValue(context.Background(), ConnectionIDKey, connID)

	// Request 1: Client A authenticates with key-A
	msg1 := createTestMessageWithMethod("key-A", "test")
	result1, err := interceptor.Intercept(ctx, msg1)
	if err != nil {
		t.Fatalf("request 1 (key-A) failed: %v", err)
	}
	if result1.Session.IdentityID != "user-A" {
		t.Fatalf("request 1: expected identity user-A, got %s", result1.Session.IdentityID)
	}

	// Request 2: Client B sends request with key-B on SAME connID
	msg2 := createTestMessageWithMethod("key-B", "test")
	result2, err := interceptor.Intercept(ctx, msg2)
	if err != nil {
		t.Fatalf("request 2 (key-B) failed: %v", err)
	}

	// SECURITY CHECK: Request 2 must use key-B's identity (user-B), NOT key-A's (user-A).
	// BUG B3: The cached session path (lines 204-218) never re-validates the API key.
	// The cached session from key-A is returned to key-B without checking if the key changed.
	if result2.Session.IdentityID != "user-B" {
		t.Errorf("SECURITY BUG B3: request 2 with key-B got identity %q, want %q. "+
			"Cached session from key-A was reused without re-validating the API key!",
			result2.Session.IdentityID, "user-B")
	}

	// Additional: verify key-B resulted in a different session than key-A
	if result2.Session.ID == result1.Session.ID {
		t.Errorf("SECURITY BUG B3: request 2 with key-B got same session ID as key-A (%s). "+
			"Session from different API key should not be shared!", result1.Session.ID)
	}
}

// --- Test 3A.7: Session cache race condition ---

// concurrentMockSessionStore is a thread-safe version of mockSessionStore for race tests.
type concurrentMockSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*session.Session
}

func newConcurrentMockSessionStore() *concurrentMockSessionStore {
	return &concurrentMockSessionStore{
		sessions: make(map[string]*session.Session),
	}
}

func (m *concurrentMockSessionStore) Create(_ context.Context, sess *session.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sess.ID] = sess
	return nil
}

func (m *concurrentMockSessionStore) Get(_ context.Context, id string) (*session.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[id]
	if !ok {
		return nil, session.ErrSessionNotFound
	}
	// Return a copy to avoid races on session fields
	cp := *sess
	return &cp, nil
}

func (m *concurrentMockSessionStore) Update(_ context.Context, sess *session.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[sess.ID]; !ok {
		return session.ErrSessionNotFound
	}
	m.sessions[sess.ID] = sess
	return nil
}

func (m *concurrentMockSessionStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

func TestAuthInterceptor_SessionCacheRace(t *testing.T) {
	authStore := newMockAuthStore()
	authStore.AddIdentity(&auth.Identity{
		ID:    "user-1",
		Name:  "Test User",
		Roles: []auth.Role{auth.RoleUser},
	})
	authStore.AddKey(&auth.APIKey{
		Key:        auth.HashKey("shared-key"), //nolint:staticcheck // SA1019: backward-compatible key lookup
		IdentityID: "user-1",
		CreatedAt:  time.Now(),
		Revoked:    false,
	})

	sessionStore := newConcurrentMockSessionStore()
	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{Timeout: 30 * time.Minute})
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	passthrough := NewPassthroughInterceptor()
	interceptor := NewAuthInterceptor(apiKeyService, sessionService, passthrough, logger)

	connID := "shared-conn"
	const numGoroutines = 10

	var wg sync.WaitGroup
	errs := make([]error, numGoroutines)
	sessions := make([]*session.Session, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx := context.WithValue(context.Background(), ConnectionIDKey, connID)
			msg := createTestMessageWithMethod("shared-key", "test")
			result, err := interceptor.Intercept(ctx, msg)
			errs[idx] = err
			if result != nil {
				sessions[idx] = result.Session
			}
		}(i)
	}

	wg.Wait()

	// All goroutines must succeed
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d failed: %v", i, err)
		}
	}

	// All sessions must be non-nil and have the same identity
	for i, sess := range sessions {
		if sess == nil {
			t.Errorf("goroutine %d got nil session", i)
			continue
		}
		if sess.IdentityID != "user-1" {
			t.Errorf("goroutine %d got identity %q, want %q", i, sess.IdentityID, "user-1")
		}
	}

	// Cache should have exactly 1 entry for connID
	if interceptor.CacheSize() != 1 {
		t.Errorf("expected cache size 1, got %d", interceptor.CacheSize())
	}
}
