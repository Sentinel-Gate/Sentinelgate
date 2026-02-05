// Package proxy contains the core domain logic for the MCP proxy.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// cacheEntry stores session ID with last access time for TTL-based cleanup.
type cacheEntry struct {
	sessionID  string
	lastAccess time.Time
}

// apiKeyContextKey is the context key type for API key.
type apiKeyContextKey struct{}

// APIKeyContextKey is the context key for API key.
// HTTP transport should set this value in context before calling ProxyService.Run().
// Example: ctx = context.WithValue(ctx, proxy.APIKeyContextKey, "my-api-key")
var APIKeyContextKey = apiKeyContextKey{}

// Error types for authentication failures.
var (
	ErrUnauthenticated = errors.New("authentication required")
	ErrInvalidAPIKey   = errors.New("invalid API key")
	ErrSessionExpired  = errors.New("session expired")
	ErrInternalError   = errors.New("internal error")
)

// SafeErrorMessage returns a client-safe error message.
// Internal error details are logged but not exposed to clients.
// SECURITY: This function MUST be used for all client-facing error responses
// to prevent information leakage (stack traces, internal paths, credentials).
func SafeErrorMessage(err error) string {
	// Check for RateLimitError first (it's a pointer type, not sentinel)
	var rateLimitErr *RateLimitError
	if errors.As(err, &rateLimitErr) {
		return "Rate limit exceeded"
	}

	switch {
	case errors.Is(err, ErrUnauthenticated):
		return "Authentication required"
	case errors.Is(err, ErrInvalidAPIKey):
		return "Invalid API key"
	case errors.Is(err, ErrSessionExpired):
		return "Session expired"
	case errors.Is(err, ErrPolicyDenied):
		return "Access denied by policy"
	case errors.Is(err, ErrMissingSession):
		return "Session required"
	default:
		return "Internal error"
	}
}

// AuthInterceptor validates API keys and manages sessions.
// It wraps another MessageInterceptor (e.g., policy engine).
//
// SECURITY: API keys are NEVER logged. Only connection_id, session_id, and
// identity_id are logged. Raw key material must never appear in log output.
type AuthInterceptor struct {
	apiKeyService  *auth.APIKeyService
	sessionService *session.SessionService
	next           MessageInterceptor // Wrapped interceptor (PassthroughInterceptor for now)
	logger         *slog.Logger
	devMode        bool // Skip authentication when true

	// sessionCache maps connection ID to cacheEntry for session persistence
	// across multiple messages in the same connection (e.g., stdio session).
	// Protected by mutex for concurrent access.
	sessionCache map[string]*cacheEntry
	sessionMu    sync.RWMutex

	// Cleanup goroutine control
	stopChan        chan struct{}  // Signal to stop cleanup goroutine
	wg              sync.WaitGroup // Wait for cleanup goroutine on shutdown
	cleanupInterval time.Duration  // How often to run cleanup (default: 5 minutes)
	cacheMaxAge     time.Duration  // Max time since last access before entry is removed (default: 30 minutes)
	once            sync.Once      // Prevent double-close panic on Stop()
}

// NewAuthInterceptor creates a new AuthInterceptor with default cleanup settings.
// Default cleanupInterval: 5 minutes, default cacheMaxAge: 30 minutes.
func NewAuthInterceptor(
	apiKeyService *auth.APIKeyService,
	sessionService *session.SessionService,
	next MessageInterceptor,
	logger *slog.Logger,
	devMode bool,
) *AuthInterceptor {
	return &AuthInterceptor{
		apiKeyService:   apiKeyService,
		sessionService:  sessionService,
		next:            next,
		logger:          logger,
		devMode:         devMode,
		sessionCache:    make(map[string]*cacheEntry),
		stopChan:        make(chan struct{}),
		cleanupInterval: 5 * time.Minute,
		cacheMaxAge:     30 * time.Minute,
	}
}

// NewAuthInterceptorWithConfig creates a new AuthInterceptor with custom cleanup settings.
func NewAuthInterceptorWithConfig(
	apiKeyService *auth.APIKeyService,
	sessionService *session.SessionService,
	next MessageInterceptor,
	logger *slog.Logger,
	devMode bool,
	cleanupInterval time.Duration,
	cacheMaxAge time.Duration,
) *AuthInterceptor {
	return &AuthInterceptor{
		apiKeyService:   apiKeyService,
		sessionService:  sessionService,
		next:            next,
		logger:          logger,
		devMode:         devMode,
		sessionCache:    make(map[string]*cacheEntry),
		stopChan:        make(chan struct{}),
		cleanupInterval: cleanupInterval,
		cacheMaxAge:     cacheMaxAge,
	}
}

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

// ConnectionIDKey is the context key for connection ID.
const ConnectionIDKey contextKey = "connection_id"

// Intercept validates authentication before passing to next interceptor.
// Returns error to BLOCK message propagation - ProxyService MUST check error
// and send JSON-RPC error response back to client instead of forwarding.
func (a *AuthInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// Get connection ID from context (set by transport layer)
	connID, _ := ctx.Value(ConnectionIDKey).(string)
	if connID == "" {
		connID = "default" // Fallback for single-connection scenarios
	}

	// Dev mode: skip authentication, create anonymous session
	if a.devMode {
		devIdentity := &auth.Identity{
			ID:    "dev-user",
			Name:  "Development User",
			Roles: []auth.Role{auth.RoleAdmin, auth.RoleUser},
		}
		sess, err := a.sessionService.Create(ctx, devIdentity)
		if err != nil {
			a.logger.Error("failed to create dev session", "error", err)
			return nil, ErrInternalError
		}
		msg.Session = sess
		a.logger.Debug("dev mode: bypassing authentication",
			"connection_id", connID,
			"session_id", sess.ID,
		)
		return a.next.Intercept(ctx, msg)
	}

	// HTTP Bearer token (from context) takes precedence over JSON-RPC params
	apiKey, _ := ctx.Value(APIKeyContextKey).(string)

	// Fallback to JSON-RPC params (stdio transport)
	if apiKey == "" {
		apiKey = msg.ExtractAPIKey()
	}
	msg.APIKey = apiKey

	// Check sessionCache for existing session ID by connection ID
	a.sessionMu.RLock()
	entry, hasCachedSession := a.sessionCache[connID]
	a.sessionMu.RUnlock()

	var cachedSessionID string
	if hasCachedSession {
		cachedSessionID = entry.sessionID
		// Update last access time
		a.sessionMu.Lock()
		if e, ok := a.sessionCache[connID]; ok {
			e.lastAccess = time.Now()
		}
		a.sessionMu.Unlock()

		// Try to use cached session
		sess, err := a.sessionService.Get(ctx, cachedSessionID)
		if err == nil && !sess.IsExpired() {
			// Valid session - attach to message and continue
			msg.Session = sess
			// Refresh session (extend timeout)
			if err := a.sessionService.Refresh(ctx, sess.ID); err != nil {
				a.logger.Debug("failed to refresh session", "error", err)
			}
			a.logger.Debug("using cached session",
				"connection_id", connID,
				"session_id", sess.ID,
				"identity_id", sess.IdentityID,
			)
			return a.next.Intercept(ctx, msg)
		}
		// Session expired or not found - remove from cache
		a.sessionMu.Lock()
		delete(a.sessionCache, connID)
		a.sessionMu.Unlock()
		a.logger.Debug("cached session expired or not found",
			"connection_id", connID,
			"session_id", cachedSessionID,
		)
	}

	// No valid cached session - require API key
	if apiKey == "" {
		a.logger.Debug("no API key and no valid session",
			"connection_id", connID,
		)
		return nil, ErrUnauthenticated
	}

	// Validate API key
	identity, err := a.apiKeyService.Validate(ctx, apiKey)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidKey) {
			a.logger.Debug("invalid API key",
				"connection_id", connID,
			)
			return nil, ErrInvalidAPIKey
		}
		// Other errors (e.g., key not found)
		a.logger.Debug("API key validation failed",
			"connection_id", connID,
			"error", err,
		)
		return nil, ErrInvalidAPIKey
	}

	// Create new session
	sess, err := a.sessionService.Create(ctx, identity)
	if err != nil {
		a.logger.Error("failed to create session",
			"connection_id", connID,
			"identity_id", identity.ID,
			"error", err,
		)
		// Return safe error message - don't leak internal details
		return nil, ErrInternalError
	}

	// Cache session ID by connection ID
	a.sessionMu.Lock()
	a.sessionCache[connID] = &cacheEntry{
		sessionID:  sess.ID,
		lastAccess: time.Now(),
	}
	a.sessionMu.Unlock()

	// Attach session to message
	msg.Session = sess

	a.logger.Info("authenticated new session",
		"connection_id", connID,
		"session_id", sess.ID,
		"identity_id", identity.ID,
		"identity_name", identity.Name,
	)

	return a.next.Intercept(ctx, msg)
}

// ClearSession removes a session from the cache.
// Used when a connection closes or session is invalidated.
func (a *AuthInterceptor) ClearSession(connID string) {
	a.sessionMu.Lock()
	delete(a.sessionCache, connID)
	a.sessionMu.Unlock()
}

// StartCleanup starts a background goroutine that periodically cleans up stale cache entries.
// The goroutine runs until ctx is canceled or Stop() is called.
func (a *AuthInterceptor) StartCleanup(ctx context.Context) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		ticker := time.NewTicker(a.cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-a.stopChan:
				return
			case <-ticker.C:
				a.cleanupCache()
			}
		}
	}()
}

// cleanupCache removes cache entries that haven't been accessed within cacheMaxAge.
func (a *AuthInterceptor) cleanupCache() {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()

	cutoff := time.Now().Add(-a.cacheMaxAge)
	cleaned := 0

	for connID, entry := range a.sessionCache {
		if entry.lastAccess.Before(cutoff) {
			delete(a.sessionCache, connID)
			cleaned++
		}
	}

	if cleaned > 0 {
		a.logger.Debug("cleaned stale session cache entries",
			"count", cleaned,
		)
	}
}

// Stop signals the cleanup goroutine to stop and waits for it to exit.
// Safe to call multiple times (uses sync.Once internally).
func (a *AuthInterceptor) Stop() {
	a.once.Do(func() {
		close(a.stopChan)
	})
	a.wg.Wait()
}

// CacheSize returns the current number of entries in the session cache.
// Primarily for testing purposes.
func (a *AuthInterceptor) CacheSize() int {
	a.sessionMu.RLock()
	defer a.sessionMu.RUnlock()
	return len(a.sessionCache)
}

// SetTestCacheEntry adds a cache entry directly for testing purposes.
// This method is intended only for tests and should not be used in production code.
func (a *AuthInterceptor) SetTestCacheEntry(connID, sessionID string) {
	a.sessionMu.Lock()
	a.sessionCache[connID] = &cacheEntry{
		sessionID:  sessionID,
		lastAccess: time.Now(),
	}
	a.sessionMu.Unlock()
}

// SetTestCacheEntryWithTime adds a cache entry with a specific lastAccess time for testing.
func (a *AuthInterceptor) SetTestCacheEntryWithTime(connID, sessionID string, lastAccess time.Time) {
	a.sessionMu.Lock()
	a.sessionCache[connID] = &cacheEntry{
		sessionID:  sessionID,
		lastAccess: lastAccess,
	}
	a.sessionMu.Unlock()
}

// CreateJSONRPCError creates a JSON-RPC 2.0 error response.
// id: request ID (may be nil for notifications)
// code: JSON-RPC error code (e.g., -32600 for invalid request)
// message: human-readable error message
func CreateJSONRPCError(id interface{}, code int, message string) []byte {
	resp := map[string]interface{}{
		"jsonrpc": "2.0",
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
		"id": id,
	}
	b, _ := json.Marshal(resp)
	return b
}

// Compile-time check that AuthInterceptor implements MessageInterceptor.
var _ MessageInterceptor = (*AuthInterceptor)(nil)

// LogDevModeWarning logs prominent security warnings when DevMode is enabled.
// If SENTINELGATE_ALLOW_DEVMODE env var is set to "false", this function
// logs an error and returns an error to block startup.
// Returns nil if DevMode warnings were logged successfully or DevMode is disabled.
func LogDevModeWarning(logger *slog.Logger, devMode bool) error {
	if !devMode {
		return nil
	}

	// Check if DevMode is blocked by environment
	if os.Getenv("SENTINELGATE_ALLOW_DEVMODE") == "false" {
		logger.Error("SECURITY: DevMode is blocked by SENTINELGATE_ALLOW_DEVMODE=false",
			"action", "refusing to start")
		return errors.New("DevMode blocked by SENTINELGATE_ALLOW_DEVMODE=false")
	}

	// Prominent warning - use Warn level, not Debug
	logger.Warn("=== SECURITY WARNING: DevMode is ENABLED ===")
	logger.Warn("DevMode bypasses ALL authentication - DO NOT use in production!")
	logger.Warn("Set dev_mode: false in config or SENTINEL_GATE_DEV_MODE=false")
	logger.Warn("To block DevMode entirely: SENTINELGATE_ALLOW_DEVMODE=false")
	logger.Warn("===============================================")

	return nil
}
