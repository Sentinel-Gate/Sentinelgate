package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
)

// DefaultTimeout is the default session timeout.
const DefaultTimeout = 30 * time.Minute

// Config holds session service configuration.
type Config struct {
	// Timeout is the session expiration duration. Default: 30 minutes.
	Timeout time.Duration
}

// SessionService manages session lifecycle.
type SessionService struct {
	store   SessionStore
	timeout time.Duration
}

// NewSessionService creates a new SessionService with the given store and config.
func NewSessionService(store SessionStore, cfg Config) *SessionService {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	return &SessionService{
		store:   store,
		timeout: timeout,
	}
}

// Create generates a new session for an identity.
func (s *SessionService) Create(ctx context.Context, identity *auth.Identity) (*Session, error) {
	id, err := GenerateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	session := &Session{
		ID:           id,
		IdentityID:   identity.ID,
		IdentityName: identity.Name,
		Roles:        identity.Roles,
		CreatedAt:    now,
		ExpiresAt:    now.Add(s.timeout),
		LastAccess:   now,
	}

	if err := s.store.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return session, nil
}

// Get retrieves a session by ID.
// Returns ErrSessionNotFound if the session doesn't exist.
func (s *SessionService) Get(ctx context.Context, id string) (*Session, error) {
	session, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// Double-check expiration (store might not enforce it)
	if session.IsExpired() {
		// Clean up expired session
		_ = s.store.Delete(ctx, id)
		return nil, ErrSessionNotFound
	}

	return session, nil
}

// Refresh extends session expiration and updates last access time.
func (s *SessionService) Refresh(ctx context.Context, id string) error {
	session, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}

	if session.IsExpired() {
		_ = s.store.Delete(ctx, id)
		return ErrSessionNotFound
	}

	session.Refresh(s.timeout)

	if err := s.store.Update(ctx, session); err != nil {
		return fmt.Errorf("failed to refresh session: %w", err)
	}

	return nil
}

// Delete terminates a session.
func (s *SessionService) Delete(ctx context.Context, id string) error {
	return s.store.Delete(ctx, id)
}

// GenerateSessionID creates a cryptographically random session ID.
// Uses crypto/rand for unpredictability (SESS-05 requirement).
// Returns 64 hex characters (32 bytes).
func GenerateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}
