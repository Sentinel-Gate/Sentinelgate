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
// Thread-safe for concurrent access. Suitable for production single-process deployments.
type AuthStore struct {
	keys        map[string]*auth.APIKey   // keyHash -> APIKey
	identities  map[string]*auth.Identity // ID -> Identity
	prefixIndex map[string]string         // keyPrefix -> keyHash (for Argon2id fast-path)
	mu          sync.RWMutex
}

// NewAuthStore creates a new in-memory auth store.
func NewAuthStore() *AuthStore {
	return &AuthStore{
		keys:        make(map[string]*auth.APIKey),
		identities:  make(map[string]*auth.Identity),
		prefixIndex: make(map[string]string),
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

// GetAPIKeyByPrefix retrieves an API key by its cleartext prefix (first 8 chars).
// Returns ErrKeyNotFound if no key with that prefix exists.
// Used as fast-path for Argon2id keys to avoid O(n) iteration.
func (s *AuthStore) GetAPIKeyByPrefix(ctx context.Context, prefix string) (*auth.APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keyHash, ok := s.prefixIndex[prefix]
	if !ok {
		return nil, ErrKeyNotFound
	}

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
// If key.Prefix is non-empty, the prefix index is updated for fast-path Argon2id lookup.
func (s *AuthStore) AddKey(key *auth.APIKey) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy to prevent external mutation
	keyCopy := *key
	s.keys[key.Key] = &keyCopy

	// Maintain prefix index for Argon2id fast-path
	if key.Prefix != "" {
		s.prefixIndex[key.Prefix] = key.Key
	}
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
// Also removes the associated prefix index entry if present.
func (s *AuthStore) RemoveKey(keyField string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove from prefix index if this key has one
	if key, ok := s.keys[keyField]; ok && key.Prefix != "" {
		delete(s.prefixIndex, key.Prefix)
	}
	delete(s.keys, keyField)
}

// ListAllIdentities returns all stored identities.
// Used by permission health analysis to include both YAML-seeded and state.json identities.
func (s *AuthStore) ListAllIdentities() []*auth.Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*auth.Identity, 0, len(s.identities))
	for _, identity := range s.identities {
		identityCopy := *identity
		identityCopy.Roles = make([]auth.Role, len(identity.Roles))
		copy(identityCopy.Roles, identity.Roles)
		result = append(result, &identityCopy)
	}
	return result
}

// Compile-time interface verification.
var _ auth.AuthStore = (*AuthStore)(nil)
