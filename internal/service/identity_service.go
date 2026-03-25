package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
)

// IdentityService errors.
var (
	ErrIdentityNotFound = errors.New("identity not found")
	ErrAPIKeyNotFound   = errors.New("api key not found")
	ErrDuplicateName    = errors.New("identity name already exists")
	ErrReadOnly         = errors.New("cannot modify read-only resource")
)

// IdentityService provides CRUD operations on identities and API keys
// with Argon2id key hashing and persistence to state.json.
type IdentityService struct {
	stateStore *state.FileStateStore
	logger     *slog.Logger
	mu         sync.Mutex // serializes state reads and writes
	// In-memory cache to avoid re-reading state.json on every request.
	// Loaded at init, updated on every write operation.
	cachedIdentities []state.IdentityEntry
	cachedAPIKeys    []state.APIKeyEntry

	// postMutationHook is called after any successful state-mutating operation
	// (CreateIdentity, UpdateIdentity, DeleteIdentity, GenerateKey, RevokeKey).
	// Used to re-seed the in-memory auth store from state, keeping it consistent
	// without requiring manual sync at each call site.
	// The hook is called with the IdentityService mutex released.
	postMutationHook func()

	// sessionInvalidator is called when an identity's roles change, to clear
	// cached sessions so stale roles are not used (H-1).
	sessionInvalidator func(identityID string)
}

// NewIdentityService creates a new IdentityService.
func NewIdentityService(stateStore *state.FileStateStore, logger *slog.Logger) *IdentityService {
	return &IdentityService{
		stateStore: stateStore,
		logger:     logger,
	}
}

// SetPostMutationHook sets the hook called after any successful state-mutating
// operation. It is safe to call concurrently.
func (s *IdentityService) SetPostMutationHook(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.postMutationHook = fn
}

// SetSessionInvalidator sets the callback for invalidating cached sessions
// when an identity's roles change (H-1: prevent stale role usage).
func (s *IdentityService) SetSessionInvalidator(fn func(identityID string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionInvalidator = fn
}

// callPostMutationHook invokes s.postMutationHook if it is set.
// Must be called WITHOUT holding s.mu (the hook may need to call back into services).
func (s *IdentityService) callPostMutationHook() {
	s.mu.Lock()
	hook := s.postMutationHook
	s.mu.Unlock()

	if hook != nil {
		hook()
	}
}

// Init loads identities and API keys from state.json into memory.
// Must be called once after construction, before serving requests.
func (s *IdentityService) Init() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshCache()
}

// refreshCache reloads identities and API keys from state.json into the in-memory cache.
// Caller must hold s.mu.
func (s *IdentityService) refreshCache() error {
	appState, err := s.stateStore.Load()
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	// L-15: Deep-copy identity entries to prevent shared Roles slices
	// between the cache and the source — mutation of one must not affect the other.
	s.cachedIdentities = make([]state.IdentityEntry, len(appState.Identities))
	for i, e := range appState.Identities {
		roles := make([]string, len(e.Roles))
		copy(roles, e.Roles)
		ident := e
		ident.Roles = roles
		s.cachedIdentities[i] = ident
	}
	// M-22: Deep-copy APIKeyEntry to avoid sharing ExpiresAt pointer
	// between cache and state store.
	s.cachedAPIKeys = make([]state.APIKeyEntry, len(appState.APIKeys))
	for i, k := range appState.APIKeys {
		entry := k
		if k.ExpiresAt != nil {
			t := *k.ExpiresAt
			entry.ExpiresAt = &t
		}
		s.cachedAPIKeys[i] = entry
	}
	return nil
}

// ListIdentities returns all identities.
func (s *IdentityService) ListIdentities(_ context.Context) ([]state.IdentityEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// L-7: Deep-copy each entry so the returned Roles slices are independent
	// from the cache — callers cannot mutate cached state through shared slices.
	result := make([]state.IdentityEntry, len(s.cachedIdentities))
	for i, e := range s.cachedIdentities {
		roles := make([]string, len(e.Roles))
		copy(roles, e.Roles)
		entry := e
		entry.Roles = roles
		result[i] = entry
	}
	return result, nil
}

// GetIdentity returns a single identity by ID.
func (s *IdentityService) GetIdentity(_ context.Context, id string) (*state.IdentityEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.cachedIdentities {
		if s.cachedIdentities[i].ID == id {
			entry := s.cachedIdentities[i]
			return &entry, nil
		}
	}
	return nil, ErrIdentityNotFound
}

// CreateIdentityInput holds the input for creating an identity.
type CreateIdentityInput struct {
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

// CreateIdentity creates a new identity and persists it to state.json.
func (s *IdentityService) CreateIdentity(_ context.Context, input CreateIdentityInput) (*state.IdentityEntry, error) {
	if input.Name == "" {
		return nil, fmt.Errorf("name is required")
	}

	s.mu.Lock()

	var entry state.IdentityEntry
	err := s.stateStore.Mutate(func(appState *state.AppState) error {
		// Check name uniqueness.
		for _, existing := range appState.Identities {
			if existing.Name == input.Name {
				return ErrDuplicateName
			}
		}

		roles := input.Roles
		if roles == nil {
			roles = []string{}
		}

		now := time.Now().UTC()
		entry = state.IdentityEntry{
			ID:        uuid.New().String(),
			Name:      input.Name,
			Roles:     roles,
			CreatedAt: now,
			UpdatedAt: now, // M-20: set UpdatedAt on create
		}

		appState.Identities = append(appState.Identities, entry)
		return nil
	})
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}

	if err := s.refreshCache(); err != nil {
		s.logger.Error("cache refresh failed after identity create", "id", entry.ID, "error", err)
	}
	s.logger.Info("identity created", "id", entry.ID, "name", entry.Name)
	s.mu.Unlock()
	s.callPostMutationHook()
	return &entry, nil
}

// UpdateIdentityInput holds the input for updating an identity.
type UpdateIdentityInput struct {
	Name  *string  `json:"name,omitempty"`
	Roles []string `json:"roles,omitempty"`
}

// UpdateIdentity updates an existing identity and persists the change.
func (s *IdentityService) UpdateIdentity(_ context.Context, id string, input UpdateIdentityInput) (*state.IdentityEntry, error) {
	s.mu.Lock()

	var entry state.IdentityEntry
	var rolesChanged bool
	err := s.stateStore.Mutate(func(appState *state.AppState) error {
		idx := -1
		for i := range appState.Identities {
			if appState.Identities[i].ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			return ErrIdentityNotFound
		}

		if appState.Identities[idx].ReadOnly {
			return ErrReadOnly
		}

		// Check name uniqueness if name is being changed.
		if input.Name != nil && *input.Name != appState.Identities[idx].Name {
			if *input.Name == "" {
				return fmt.Errorf("name is required")
			}
			for _, existing := range appState.Identities {
				if existing.Name == *input.Name && existing.ID != id {
					return ErrDuplicateName
				}
			}
			appState.Identities[idx].Name = *input.Name
		}

		if input.Roles != nil {
			rolesChanged = !stringSlicesEqual(appState.Identities[idx].Roles, input.Roles)
			appState.Identities[idx].Roles = input.Roles
		}

		// M-21: Update the timestamp on every mutation.
		appState.Identities[idx].UpdatedAt = time.Now().UTC()
		entry = appState.Identities[idx]
		return nil
	})
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}

	invalidator := s.sessionInvalidator
	if err := s.refreshCache(); err != nil {
		s.logger.Error("cache refresh failed after identity update", "id", id, "error", err)
	}
	s.logger.Info("identity updated", "id", id, "name", entry.Name)
	s.mu.Unlock()
	s.callPostMutationHook()

	// H-1: Invalidate cached sessions when roles change so stale roles are not used.
	if rolesChanged && invalidator != nil {
		invalidator(id)
	}

	return &entry, nil
}

// stringSlicesEqual returns true if two string slices have the same elements in the same order.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// DeleteIdentity removes an identity and all its API keys.
func (s *IdentityService) DeleteIdentity(_ context.Context, id string) ([]string, error) {
	s.mu.Lock()

	var deletedKeyHashes []string
	err := s.stateStore.Mutate(func(appState *state.AppState) error {
		// Find and remove the identity.
		idx := -1
		for i := range appState.Identities {
			if appState.Identities[i].ID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			return ErrIdentityNotFound
		}

		if appState.Identities[idx].ReadOnly {
			return ErrReadOnly
		}

		// Remove the identity.
		appState.Identities = append(appState.Identities[:idx], appState.Identities[idx+1:]...)

		// Cascade: remove all API keys belonging to this identity.
		filtered := make([]state.APIKeyEntry, 0, len(appState.APIKeys))
		for _, key := range appState.APIKeys {
			if key.IdentityID != id {
				filtered = append(filtered, key)
			} else {
				deletedKeyHashes = append(deletedKeyHashes, key.KeyHash)
			}
		}
		appState.APIKeys = filtered
		return nil
	})
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}

	if err := s.refreshCache(); err != nil {
		s.logger.Error("cache refresh failed after identity delete", "id", id, "error", err)
	}
	invalidator := s.sessionInvalidator
	s.logger.Info("identity deleted (cascade)", "id", id, "keys_removed", len(deletedKeyHashes))
	s.mu.Unlock()
	s.callPostMutationHook()
	// L-61: Invalidate cached sessions for the deleted identity.
	if invalidator != nil {
		invalidator(id)
	}
	return deletedKeyHashes, nil
}

// GenerateKeyInput holds the input for generating an API key.
type GenerateKeyInput struct {
	IdentityID string `json:"identity_id"`
	Name       string `json:"name"`
}

// GenerateKeyResult holds the result of key generation.
// The CleartextKey is returned exactly once and never stored.
type GenerateKeyResult struct {
	KeyEntry     state.APIKeyEntry `json:"key_entry"`
	CleartextKey string            `json:"cleartext_key"`
}

// GenerateKey creates a new API key for the given identity.
// The cleartext key is returned exactly once in GenerateKeyResult and never stored.
// Only the Argon2id hash is persisted.
func (s *IdentityService) GenerateKey(_ context.Context, input GenerateKeyInput) (*GenerateKeyResult, error) {
	if input.IdentityID == "" {
		return nil, fmt.Errorf("identity_id is required")
	}
	if input.Name == "" {
		return nil, fmt.Errorf("name is required")
	}

	// Generate key material before acquiring locks (Argon2id is CPU-intensive).
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}
	defer func() {
		for i := range rawKey {
			rawKey[i] = 0
		}
	}()
	// M-17: cleartextKey is a Go string (immutable, cannot be zeroed).
	// rawKey bytes are zeroed via defer above; the string survives until GC.
	// This is a known Go limitation — defense in depth only.
	cleartextKey := "sg_" + hex.EncodeToString(rawKey)

	hash, err := auth.HashKeyArgon2id(cleartextKey)
	if err != nil {
		return nil, fmt.Errorf("hash key: %w", err)
	}

	keyPrefix := ""
	if len(cleartextKey) >= 8 {
		keyPrefix = cleartextKey[:8]
	}

	s.mu.Lock()

	var entry state.APIKeyEntry
	err = s.stateStore.Mutate(func(appState *state.AppState) error {
		// Verify the identity exists.
		found := false
		for _, identity := range appState.Identities {
			if identity.ID == input.IdentityID {
				found = true
				break
			}
		}
		if !found {
			return ErrIdentityNotFound
		}

		entry = state.APIKeyEntry{
			ID:         uuid.New().String(),
			KeyHash:    hash,
			KeyPrefix:  keyPrefix,
			IdentityID: input.IdentityID,
			Name:       input.Name,
			CreatedAt:  time.Now().UTC(),
		}

		appState.APIKeys = append(appState.APIKeys, entry)
		return nil
	})
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}

	if err := s.refreshCache(); err != nil {
		s.logger.Error("cache refresh failed after key generate", "key_id", entry.ID, "identity_id", input.IdentityID, "error", err)
	}
	s.logger.Info("api key generated", "key_id", entry.ID, "identity_id", input.IdentityID, "name", input.Name)
	s.mu.Unlock()
	s.callPostMutationHook()
	return &GenerateKeyResult{
		KeyEntry:     entry,
		CleartextKey: cleartextKey,
	}, nil
}

// RevokeKey marks an API key as revoked. It does not delete it.
// Returns the key hash of the revoked key so callers can sync in-memory stores.
func (s *IdentityService) RevokeKey(_ context.Context, keyID string) (string, error) {
	s.mu.Lock()

	var keyHash string
	err := s.stateStore.Mutate(func(appState *state.AppState) error {
		idx := -1
		for i := range appState.APIKeys {
			if appState.APIKeys[i].ID == keyID {
				idx = i
				break
			}
		}
		if idx == -1 {
			return ErrAPIKeyNotFound
		}

		if appState.APIKeys[idx].ReadOnly {
			return ErrReadOnly
		}

		keyHash = appState.APIKeys[idx].KeyHash
		appState.APIKeys[idx].Revoked = true
		return nil
	})
	if err != nil {
		s.mu.Unlock()
		return "", err
	}

	if err := s.refreshCache(); err != nil {
		s.logger.Error("cache refresh failed after key revoke", "key_id", keyID, "error", err)
	}
	s.logger.Info("api key revoked", "key_id", keyID)
	s.mu.Unlock()
	s.callPostMutationHook()
	return keyHash, nil
}

// ListKeys returns all API keys for a given identity.
func (s *IdentityService) ListKeys(_ context.Context, identityID string) ([]state.APIKeyEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []state.APIKeyEntry
	for _, key := range s.cachedAPIKeys {
		if key.IdentityID == identityID {
			result = append(result, key)
		}
	}

	if result == nil {
		result = []state.APIKeyEntry{}
	}
	return result, nil
}

// ListAllKeys returns all API keys across all identities.
func (s *IdentityService) ListAllKeys(_ context.Context) ([]state.APIKeyEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]state.APIKeyEntry, len(s.cachedAPIKeys))
	copy(result, s.cachedAPIKeys)
	return result, nil
}

// VerifyKey checks if a cleartext key matches any non-revoked API key.
// Returns the matching key entry or ErrAPIKeyNotFound.
func (s *IdentityService) VerifyKey(_ context.Context, cleartextKey string) (*state.APIKeyEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.cachedAPIKeys {
		key := &s.cachedAPIKeys[i]
		if key.Revoked {
			continue
		}

		match, err := auth.VerifyKey(cleartextKey, key.KeyHash)
		if err != nil {
			s.logger.Warn("failed to compare key hash", "key_id", key.ID, "error", err)
			continue
		}
		if match {
			entry := *key
			return &entry, nil
		}
	}

	return nil, ErrAPIKeyNotFound
}
