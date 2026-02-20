// Package session manages user sessions across MCP tool calls.
package session

import (
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
)

// Session tracks an authenticated user's context across tool calls.
type Session struct {
	// ID is a cryptographically random identifier, 32 bytes hex-encoded.
	ID string
	// IdentityID references the auth.Identity this session belongs to.
	IdentityID string
	// IdentityName is the human-readable name of the identity.
	IdentityName string
	// Roles are cached from the Identity for fast RBAC lookup.
	Roles []auth.Role
	// CreatedAt is when the session was created (UTC).
	CreatedAt time.Time
	// ExpiresAt is when the session will expire (UTC).
	ExpiresAt time.Time
	// LastAccess is the last time the session was used (UTC).
	LastAccess time.Time
}

// IsExpired checks if the session has exceeded its timeout.
func (s *Session) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}

// Refresh updates LastAccess and extends ExpiresAt by the given duration.
func (s *Session) Refresh(timeout time.Duration) {
	now := time.Now().UTC()
	s.LastAccess = now
	s.ExpiresAt = now.Add(timeout)
}
