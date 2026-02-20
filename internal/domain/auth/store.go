package auth

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors for user store operations.
var (
	// ErrUserNotFound is returned when a proxy user is not found.
	ErrUserNotFound = errors.New("user not found")
	// ErrUserKeyNotFound is returned when a proxy API key is not found.
	ErrUserKeyNotFound = errors.New("user API key not found")
)

// AuthStore provides credential lookup for authentication.
// This interface is defined in the domain to avoid circular imports.
// Implementations: in-memory (dev), PostgreSQL (prod).
type AuthStore interface {
	// GetAPIKey retrieves an API key by its hash.
	// Returns outbound.ErrKeyNotFound if key doesn't exist.
	GetAPIKey(ctx context.Context, keyHash string) (*APIKey, error)

	// GetIdentity retrieves user identity by ID.
	// Returns outbound.ErrIdentityNotFound if identity doesn't exist.
	GetIdentity(ctx context.Context, id string) (*Identity, error)

	// ListAPIKeys returns all stored API keys for iteration-based verification.
	ListAPIKeys(ctx context.Context) ([]*APIKey, error)
}

// UserStore provides admin CRUD operations for proxy users (identities).
// This interface is defined in the domain to avoid circular imports.
// Implementations: PostgreSQL (prod).
type UserStore interface {
	// ListUsers retrieves all proxy users.
	// Returns both enabled and disabled users.
	ListUsers(ctx context.Context) ([]Identity, error)

	// GetUser retrieves a proxy user by ID.
	// Returns ErrUserNotFound if the user doesn't exist.
	GetUser(ctx context.Context, id string) (*Identity, error)

	// CreateUser creates a new proxy user.
	// The ID field is set by the implementation if empty.
	CreateUser(ctx context.Context, user *Identity) error

	// UpdateUser updates an existing proxy user.
	// Updates Name, Roles, and Enabled fields.
	UpdateUser(ctx context.Context, user *Identity) error

	// DeleteUser deletes a proxy user by ID.
	// Also deletes associated API keys (cascade).
	// Returns ErrUserNotFound if the user doesn't exist.
	DeleteUser(ctx context.Context, id string) error

	// CreateUserAPIKey creates a new API key for a proxy user.
	// The keyHash should be the SHA-256 hex hash of the raw API key.
	// Returns ErrUserNotFound if the user doesn't exist.
	CreateUserAPIKey(ctx context.Context, userID, keyHash string, expiresAt *time.Time) error

	// RevokeUserAPIKey revokes a proxy user's API key by its hash.
	// Returns ErrUserKeyNotFound if the key doesn't exist.
	RevokeUserAPIKey(ctx context.Context, keyHash string) error
}

// ExtendedIdentity extends Identity with additional fields for admin operations.
type ExtendedIdentity struct {
	Identity
	// Enabled indicates if this user is active.
	Enabled bool
	// CreatedAt is when the user was created (UTC).
	CreatedAt time.Time
	// UpdatedAt is when the user was last modified (UTC).
	UpdatedAt time.Time
}
