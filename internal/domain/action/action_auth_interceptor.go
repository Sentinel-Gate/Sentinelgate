package action

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// authCacheEntry stores session ID with last access time for TTL-based cleanup.
type authCacheEntry struct {
	sessionID  string
	identityID string // identity that owns this session (for role-change invalidation)
	lastAccess time.Time
	apiKeyHash string
}

// ActionAuthInterceptor validates API keys and manages sessions.
// Native ActionInterceptor replacement for proxy.AuthInterceptor.
//
// SECURITY: API keys are NEVER logged. Only connection_id, session_id, and
// identity_id are logged. Raw key material must never appear in log output.
type ActionAuthInterceptor struct {
	apiKeyService  *auth.APIKeyService
	sessionService *session.SessionService
	next   ActionInterceptor
	logger *slog.Logger

	// sessionTracker pre-registers sessions so they appear in the Agents page
	// immediately, before any tool call.
	sessionTracker *session.SessionTracker

	// sessionCache maps connection ID to authCacheEntry for session persistence
	// across multiple messages in the same connection (e.g., stdio session).
	sessionCache map[string]*authCacheEntry
	sessionMu    sync.RWMutex

	// maxCacheSize caps the session cache to prevent unbounded memory growth.
	maxCacheSize int

	// Cleanup goroutine control
	stopChan        chan struct{}
	wg              sync.WaitGroup
	cleanupInterval time.Duration
	cacheMaxAge     time.Duration
	once            sync.Once
}

const defaultActionAuthMaxCacheSize = 10000

// Compile-time check that ActionAuthInterceptor implements ActionInterceptor.
var _ ActionInterceptor = (*ActionAuthInterceptor)(nil)

// NewActionAuthInterceptor creates a new ActionAuthInterceptor with default cleanup settings.
func NewActionAuthInterceptor(
	apiKeyService *auth.APIKeyService,
	sessionService *session.SessionService,
	next ActionInterceptor,
	logger *slog.Logger,
	tracker *session.SessionTracker,
) *ActionAuthInterceptor {
	return &ActionAuthInterceptor{
		apiKeyService:   apiKeyService,
		sessionService:  sessionService,
		next:            next,
		logger:          logger,
		sessionTracker:  tracker,
		sessionCache:    make(map[string]*authCacheEntry),
		maxCacheSize:    defaultActionAuthMaxCacheSize,
		stopChan:        make(chan struct{}),
		cleanupInterval: 5 * time.Minute,
		cacheMaxAge:     30 * time.Minute,
	}
}

// NewActionAuthInterceptorWithConfig creates a new ActionAuthInterceptor with custom settings.
func NewActionAuthInterceptorWithConfig(
	apiKeyService *auth.APIKeyService,
	sessionService *session.SessionService,
	next ActionInterceptor,
	logger *slog.Logger,
	cleanupInterval time.Duration,
	cacheMaxAge time.Duration,
	tracker *session.SessionTracker,
) *ActionAuthInterceptor {
	return &ActionAuthInterceptor{
		apiKeyService:   apiKeyService,
		sessionService:  sessionService,
		next:            next,
		logger:          logger,
		sessionTracker:  tracker,
		sessionCache:    make(map[string]*authCacheEntry),
		maxCacheSize:    defaultActionAuthMaxCacheSize,
		stopChan:        make(chan struct{}),
		cleanupInterval: cleanupInterval,
		cacheMaxAge:     cacheMaxAge,
	}
}

// Intercept validates authentication before passing to next interceptor.
func (a *ActionAuthInterceptor) Intercept(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
	// Get connection ID from context (set by transport layer)
	connID, _ := ctx.Value(proxy.ConnectionIDKey).(string)
	if connID == "" {
		connID = "default"
	}

	// Access original mcp.Message for backward compatibility
	mcpMsg, _ := act.OriginalMessage.(*mcp.Message)

	// HTTP Bearer token (from context) takes precedence over JSON-RPC params
	apiKey, _ := ctx.Value(proxy.APIKeyContextKey).(string)

	// Fallback to JSON-RPC params (stdio transport)
	if apiKey == "" && mcpMsg != nil {
		apiKey = mcpMsg.ExtractAPIKey()
	}
	if mcpMsg != nil {
		mcpMsg.APIKey = apiKey
	}

	// Check sessionCache for existing session ID by connection ID
	a.sessionMu.RLock()
	entry, hasCachedSession := a.sessionCache[connID]
	a.sessionMu.RUnlock()

	// On initialize (client reconnect), force new session so per-session
	// quota counters reset instead of carrying over from the old session.
	if hasCachedSession && act.Type == ActionProtocol && act.Name == "initialize" {
		a.sessionMu.Lock()
		delete(a.sessionCache, connID)
		a.sessionMu.Unlock()
		a.logger.Info("initialize received: clearing cached session for new quota counters",
			"connection_id", connID,
			"old_session_id", entry.sessionID,
		)
		hasCachedSession = false
	}

	var cachedSessionID string
	if hasCachedSession {
		cachedSessionID = entry.sessionID

		if apiKey != "" && entry.apiKeyHash != "" && actionAuthHashKey(apiKey) != entry.apiKeyHash {
			a.sessionMu.Lock()
			delete(a.sessionCache, connID)
			a.sessionMu.Unlock()
			a.logger.Info("API key changed on cached connection, invalidating session cache",
				"connection_id", connID,
				"old_session_id", cachedSessionID,
			)
			hasCachedSession = false
		}
	}

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
			a.setIdentity(act, sess, mcpMsg)
			// Write session ID to HTTP handler's slot so Mcp-Session-Id matches audit records
			if slot, ok := ctx.Value(proxy.SessionIDSlotKey).(*string); ok {
				*slot = sess.ID
			}
			if err := a.sessionService.Refresh(ctx, sess.ID); err != nil {
				a.logger.Debug("failed to refresh session", "error", err)
			}
			a.logger.Debug("using cached session",
				"connection_id", connID,
				"session_id", sess.ID,
				"identity_id", sess.IdentityID,
			)
			return a.next.Intercept(ctx, act)
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
		return nil, proxy.ErrUnauthenticated
	}

	// Validate API key
	identity, err := a.apiKeyService.Validate(ctx, apiKey)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidKey) {
			a.logger.Debug("invalid API key",
				"connection_id", connID,
			)
			return nil, proxy.ErrInvalidAPIKey
		}
		a.logger.Debug("API key validation failed",
			"connection_id", connID,
			"error", err,
		)
		return nil, proxy.ErrInvalidAPIKey
	}

	// Create new session
	sess, err := a.sessionService.Create(ctx, identity)
	if err != nil {
		a.logger.Error("failed to create session",
			"connection_id", connID,
			"identity_id", identity.ID,
			"error", err,
		)
		return nil, proxy.ErrInternalError
	}

	// Pre-register in usage tracker so the session appears in Agents page immediately
	if a.sessionTracker != nil {
		a.sessionTracker.TrackSession(sess.ID, identity.ID, identity.Name)
	}

	// Cache session ID by connection ID, evicting oldest entry if at capacity
	a.sessionMu.Lock()
	if len(a.sessionCache) >= a.maxCacheSize {
		a.evictOldestLocked()
	}
	a.sessionCache[connID] = &authCacheEntry{
		sessionID:  sess.ID,
		identityID: identity.ID,
		lastAccess: time.Now(),
		apiKeyHash: actionAuthHashKey(apiKey),
	}
	a.sessionMu.Unlock()

	a.setIdentity(act, sess, mcpMsg)

	// Write session ID to HTTP handler's slot so Mcp-Session-Id matches audit records
	if slot, ok := ctx.Value(proxy.SessionIDSlotKey).(*string); ok {
		*slot = sess.ID
	}

	a.logger.Info("authenticated new session",
		"connection_id", connID,
		"session_id", sess.ID,
		"identity_id", identity.ID,
		"identity_name", identity.Name,
	)

	return a.next.Intercept(ctx, act)
}

// setIdentity populates identity on both the CanonicalAction and the mcp.Message.
// Setting msg.Session ensures backward compatibility with downstream code that
// reads from mcp.Message (e.g., UpstreamRouter via LegacyAdapter).
func (a *ActionAuthInterceptor) setIdentity(act *CanonicalAction, sess *session.Session, mcpMsg *mcp.Message) {
	// Set on CanonicalAction (primary)
	roles := make([]string, len(sess.Roles))
	for i, r := range sess.Roles {
		roles[i] = string(r)
	}
	act.Identity = ActionIdentity{
		ID:        sess.IdentityID,
		Name:      sess.IdentityName,
		SessionID: sess.ID,
		Roles:     roles,
	}

	// Set on mcp.Message for backward compatibility
	if mcpMsg != nil {
		mcpMsg.Session = sess
	}
}

// InvalidateByIdentity removes all cached sessions belonging to the given identity.
// Called when an identity's roles are changed so stale roles are not used.
func (a *ActionAuthInterceptor) InvalidateByIdentity(identityID string) {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	for connID, entry := range a.sessionCache {
		if entry.identityID == identityID {
			delete(a.sessionCache, connID)
		}
	}
}

// InvalidateBySessionID removes all cached entries for a specific session ID.
// BUG-6 FIX: Called when a session is terminated via the admin UI so the agent
// cannot continue using the cached session without re-authenticating.
func (a *ActionAuthInterceptor) InvalidateBySessionID(sessionID string) {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	for connID, entry := range a.sessionCache {
		if entry.sessionID == sessionID {
			delete(a.sessionCache, connID)
		}
	}
}

// ClearSession removes a session from the cache.
func (a *ActionAuthInterceptor) ClearSession(connID string) {
	a.sessionMu.Lock()
	delete(a.sessionCache, connID)
	a.sessionMu.Unlock()
}

// StartCleanup starts a background goroutine that periodically cleans up stale cache entries.
func (a *ActionAuthInterceptor) StartCleanup(ctx context.Context) {
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

// evictOldestLocked removes the cache entry with the oldest lastAccess time.
// Must be called with a.sessionMu write lock held.
func (a *ActionAuthInterceptor) evictOldestLocked() {
	var oldestConnID string
	var oldestTime time.Time

	for connID, entry := range a.sessionCache {
		if oldestConnID == "" || entry.lastAccess.Before(oldestTime) {
			oldestConnID = connID
			oldestTime = entry.lastAccess
		}
	}

	if oldestConnID != "" {
		delete(a.sessionCache, oldestConnID)
		a.logger.Debug("evicted oldest session cache entry",
			"connection_id", oldestConnID,
			"last_access", oldestTime,
		)
	}
}

// cleanupCache removes cache entries that haven't been accessed within cacheMaxAge.
func (a *ActionAuthInterceptor) cleanupCache() {
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

func actionAuthHashKey(key string) string {
	if key == "" {
		return ""
	}
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// Stop signals the cleanup goroutine to stop and waits for it to exit.
func (a *ActionAuthInterceptor) Stop() {
	a.once.Do(func() {
		close(a.stopChan)
	})
	a.wg.Wait()
}

// CacheSize returns the current number of entries in the session cache.
func (a *ActionAuthInterceptor) CacheSize() int {
	a.sessionMu.RLock()
	defer a.sessionMu.RUnlock()
	return len(a.sessionCache)
}

// SetTestCacheEntry adds a cache entry directly for testing purposes.
func (a *ActionAuthInterceptor) SetTestCacheEntry(connID, sessionID string) {
	a.sessionMu.Lock()
	a.sessionCache[connID] = &authCacheEntry{
		sessionID:  sessionID,
		lastAccess: time.Now(),
		apiKeyHash: "",
	}
	a.sessionMu.Unlock()
}

// SetTestCacheEntryWithTime adds a cache entry with a specific lastAccess time for testing.
func (a *ActionAuthInterceptor) SetTestCacheEntryWithTime(connID, sessionID string, lastAccess time.Time) {
	a.sessionMu.Lock()
	a.sessionCache[connID] = &authCacheEntry{
		sessionID:  sessionID,
		lastAccess: lastAccess,
		apiKeyHash: "",
	}
	a.sessionMu.Unlock()
}
