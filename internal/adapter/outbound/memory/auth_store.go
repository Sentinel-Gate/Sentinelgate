// Package memory provides in-memory implementations of outbound ports.
package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
)

// Error types for auth store operations.
var (
	ErrKeyNotFound      = errors.New("api key not found")
	ErrIdentityNotFound = errors.New("identity not found")
)

// AuthStore implements auth.AuthStore with in-memory maps.
// Thread-safe for concurrent access. For development/testing only.
type AuthStore struct {
	keys       map[string]*auth.APIKey   // keyHash -> APIKey
	identities map[string]*auth.Identity // ID -> Identity
	mu         sync.RWMutex
}

// NewAuthStore creates a new in-memory auth store.
func NewAuthStore() *AuthStore {
	return &AuthStore{
		keys:       make(map[string]*auth.APIKey),
		identities: make(map[string]*auth.Identity),
	}
}

// GetAPIKey retrieves an API key by its hash.
// Returns ErrKeyNotFound if key doesn't exist.
func (s *AuthStore) GetAPIKey(ctx context.Context, keyHash string) (*auth.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[keyHash]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Return a copy to prevent mutation
	keyCopy := *key
	return &keyCopy, nil
}

// GetIdentity retrieves user identity by ID.
// Returns ErrIdentityNotFound if identity doesn't exist.
func (s *AuthStore) GetIdentity(ctx context.Context, id string) (*auth.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identity, ok := s.identities[id]
	if !ok {
		return nil, ErrIdentityNotFound
	}

	// Return a copy to prevent mutation
	identityCopy := *identity
	identityCopy.Roles = make([]auth.Role, len(identity.Roles))
	copy(identityCopy.Roles, identity.Roles)
	return &identityCopy, nil
}

// AddKey adds an API key (for testing/seeding).
func (s *AuthStore) AddKey(key *auth.APIKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy to prevent external mutation
	keyCopy := *key
	s.keys[key.Key] = &keyCopy
}

// AddIdentity adds an identity (for testing/seeding).
func (s *AuthStore) AddIdentity(identity *auth.Identity) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy to prevent external mutation
	identityCopy := *identity
	identityCopy.Roles = make([]auth.Role, len(identity.Roles))
	copy(identityCopy.Roles, identity.Roles)
	s.identities[identity.ID] = &identityCopy
}

// ListAPIKeys returns all stored API keys for iteration-based verification.
func (s *AuthStore) ListAPIKeys(ctx context.Context) ([]*auth.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*auth.APIKey, 0, len(s.keys))
	for _, key := range s.keys {
		keyCopy := *key
		result = append(result, &keyCopy)
	}
	return result, nil
}

// RemoveKey removes an API key by its stored hash/key field.
func (s *AuthStore) RemoveKey(keyField string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, keyField)
}

// Compile-time interface verification.
var _ auth.AuthStore = (*AuthStore)(nil)
