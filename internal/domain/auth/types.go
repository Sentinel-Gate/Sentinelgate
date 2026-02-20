// Package auth contains the domain types and logic for authentication.
package auth

import (
	"time"
)

// Role represents a user role for authorization purposes.
type Role string

const (
	// RoleAdmin has full access to all operations.
	RoleAdmin Role = "admin"
	// RoleUser has standard access to most operations.
	RoleUser Role = "user"
	// RoleReadOnly has read-only access to operations.
	RoleReadOnly Role = "read-only"
)

// IsValid returns true if the role is a known valid role.
func (r Role) IsValid() bool {
	switch r {
	case RoleAdmin, RoleUser, RoleReadOnly:
		return true
	default:
		return false
	}
}

// Identity represents an authenticated user or service.
type Identity struct {
	// ID is the unique identifier for this identity.
	ID string
	// Name is the display name for this identity.
	Name string
	// Roles are the roles assigned to this identity.
	Roles []Role
}

// HasRole returns true if the identity has the specified role.
func (i *Identity) HasRole(role Role) bool {
	for _, r := range i.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAnyRole returns true if the identity has any of the specified roles.
func (i *Identity) HasAnyRole(roles ...Role) bool {
	for _, role := range roles {
		if i.HasRole(role) {
			return true
		}
	}
	return false
}

// APIKey represents an API key for authentication.
type APIKey struct {
	// Key is the hashed key value (SHA-256 hex or Argon2id PHC format).
	Key string
	// IdentityID maps this key to an Identity.
	IdentityID string
	// Name is a human-readable label for this key.
	Name string
	// CreatedAt is when the key was created (UTC).
	CreatedAt time.Time
	// ExpiresAt is when the key expires (nil = never expires).
	ExpiresAt *time.Time
	// Revoked indicates if the key has been revoked.
	Revoked bool
}

// IsExpired returns true if the API key has expired.
// A key with nil ExpiresAt never expires.
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().UTC().After(*k.ExpiresAt)
}
