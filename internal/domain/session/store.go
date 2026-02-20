package session

import (
	"context"
	"errors"
)

// SessionStore provides session persistence.
// This interface is defined in the domain to avoid circular imports.
// Implementations: Redis (prod), in-memory (test).
type SessionStore interface {
	// Create stores a new session.
	Create(ctx context.Context, session *Session) error

	// Get retrieves a session by ID.
	// Returns ErrSessionNotFound if session doesn't exist or is expired.
	Get(ctx context.Context, id string) (*Session, error)

	// Update saves changes to an existing session.
	Update(ctx context.Context, session *Session) error

	// Delete removes a session.
	Delete(ctx context.Context, id string) error
}

// ErrSessionNotFound is returned when a session doesn't exist or is expired.
var ErrSessionNotFound = errors.New("session not found")
