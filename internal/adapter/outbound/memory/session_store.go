// Package memory provides in-memory implementations of outbound ports.
package memory

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
)

// Default cleanup interval for session expiration.
const DefaultCleanupInterval = 1 * time.Minute

// MemorySessionStore implements session.SessionStore with in-memory map.
// Thread-safe for concurrent access. For development/testing only.
// Background cleanup goroutine removes expired sessions periodically.
type MemorySessionStore struct {
	sessions        map[string]*session.Session
	mu              sync.RWMutex
	stopChan        chan struct{}
	wg              sync.WaitGroup
	cleanupInterval time.Duration
	once            sync.Once // Prevent double-close panic on Stop()
}

// NewSessionStore creates a new in-memory session store with default cleanup interval.
func NewSessionStore() *MemorySessionStore {
	return NewSessionStoreWithConfig(DefaultCleanupInterval)
}

// NewSessionStoreWithConfig creates a new in-memory session store with custom cleanup interval.
func NewSessionStoreWithConfig(cleanupInterval time.Duration) *MemorySessionStore {
	return &MemorySessionStore{
		sessions:        make(map[string]*session.Session),
		stopChan:        make(chan struct{}),
		cleanupInterval: cleanupInterval,
	}
}

// StartCleanup starts the background cleanup goroutine.
// The goroutine will periodically remove expired sessions.
// Call Stop() to stop the cleanup goroutine gracefully.
func (s *MemorySessionStore) StartCleanup(ctx context.Context) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-s.stopChan:
				return
			case <-ticker.C:
				s.cleanup()
			}
		}
	}()
}

// cleanup removes all expired sessions from the store.
func (s *MemorySessionStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleaned := 0
	for id, sess := range s.sessions {
		if sess.IsExpired() {
			delete(s.sessions, id)
			cleaned++
		}
	}

	if cleaned > 0 {
		slog.Debug("cleaned expired sessions", "count", cleaned)
	}
}

// Stop stops the background cleanup goroutine and waits for it to exit.
// Safe to call multiple times.
func (s *MemorySessionStore) Stop() {
	s.once.Do(func() {
		close(s.stopChan)
	})
	s.wg.Wait()
}

// Create stores a new session.
func (s *MemorySessionStore) Create(ctx context.Context, sess *session.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy to prevent external mutation
	sessCopy := copySession(sess)
	s.sessions[sess.ID] = sessCopy
	return nil
}

// Get retrieves a session by ID.
// Returns session.ErrSessionNotFound if session doesn't exist or is expired.
// Note: Expired sessions are NOT deleted here - background cleanup handles deletion.
func (s *MemorySessionStore) Get(ctx context.Context, id string) (*session.Session, error) {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()

	if !ok {
		return nil, session.ErrSessionNotFound
	}

	// Check expiration - but DO NOT delete!
	// Background cleanup will handle deletion
	if sess.IsExpired() {
		return nil, session.ErrSessionNotFound
	}

	// Return a copy to prevent mutation
	return copySession(sess), nil
}

// Update saves changes to an existing session.
func (s *MemorySessionStore) Update(ctx context.Context, sess *session.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.sessions[sess.ID]; !ok {
		return session.ErrSessionNotFound
	}

	s.sessions[sess.ID] = copySession(sess)
	return nil
}

// Delete removes a session.
func (s *MemorySessionStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, id)
	return nil
}

// Size returns the number of sessions currently stored.
// Useful for testing cleanup behavior.
func (s *MemorySessionStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

// copySession creates a deep copy of a session.
func copySession(sess *session.Session) *session.Session {
	sessCopy := &session.Session{
		ID:           sess.ID,
		IdentityID:   sess.IdentityID,
		IdentityName: sess.IdentityName,
		CreatedAt:    sess.CreatedAt,
		ExpiresAt:    sess.ExpiresAt,
		LastAccess:   sess.LastAccess,
		Roles:        make([]auth.Role, len(sess.Roles)),
	}
	copy(sessCopy.Roles, sess.Roles)
	return sessCopy
}

// Compile-time interface verification.
var _ session.SessionStore = (*MemorySessionStore)(nil)
