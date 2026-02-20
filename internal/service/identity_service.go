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

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
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
}

// NewIdentityService creates a new IdentityService.
func NewIdentityService(stateStore *state.FileStateStore, logger *slog.Logger) *IdentityService {
	return &IdentityService{
		stateStore: stateStore,
		logger:     logger,
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
	s.cachedIdentities = make([]state.IdentityEntry, len(appState.Identities))
	copy(s.cachedIdentities, appState.Identities)
	s.cachedAPIKeys = make([]state.APIKeyEntry, len(appState.APIKeys))
	copy(s.cachedAPIKeys, appState.APIKeys)
	return nil
}

// ListIdentities returns all identities.
func (s *IdentityService) ListIdentities(_ context.Context) ([]state.IdentityEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]state.IdentityEntry, len(s.cachedIdentities))
	copy(result, s.cachedIdentities)
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
	defer s.mu.Unlock()

	appState, err := s.stateStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}

	// Check name uniqueness.
	for _, existing := range appState.Identities {
		if existing.Name == input.Name {
			return nil, ErrDuplicateName
		}
	}

	roles := input.Roles
	if roles == nil {
		roles = []string{}
	}

	entry := state.IdentityEntry{
		ID:        uuid.New().String(),
		Name:      input.Name,
		Roles:     roles,
		CreatedAt: time.Now().UTC(),
	}

	appState.Identities = append(appState.Identities, entry)

	if err := s.stateStore.Save(appState); err != nil {
		return nil, fmt.Errorf("save state: %w", err)
	}

	// Update cache from the state we just saved.
	s.cachedIdentities = make([]state.IdentityEntry, len(appState.Identities))
	copy(s.cachedIdentities, appState.Identities)
	s.cachedAPIKeys = make([]state.APIKeyEntry, len(appState.APIKeys))
	copy(s.cachedAPIKeys, appState.APIKeys)

	s.logger.Info("identity created", "id", entry.ID, "name", entry.Name)
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
	defer s.mu.Unlock()

	appState, err := s.stateStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}

	idx := -1
	for i := range appState.Identities {
		if appState.Identities[i].ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, ErrIdentityNotFound
	}

	if appState.Identities[idx].ReadOnly {
		return nil, ErrReadOnly
	}

	// Check name uniqueness if name is being changed.
	if input.Name != nil && *input.Name != appState.Identities[idx].Name {
		if *input.Name == "" {
			return nil, fmt.Errorf("name is required")
		}
		for _, existing := range appState.Identities {
			if existing.Name == *input.Name && existing.ID != id {
				return nil, ErrDuplicateName
			}
		}
		appState.Identities[idx].Name = *input.Name
	}

	if input.Roles != nil {
		appState.Identities[idx].Roles = input.Roles
	}

	if err := s.stateStore.Save(appState); err != nil {
		return nil, fmt.Errorf("save state: %w", err)
	}

	// Update cache from the state we just saved.
	s.cachedIdentities = make([]state.IdentityEntry, len(appState.Identities))
	copy(s.cachedIdentities, appState.Identities)
	s.cachedAPIKeys = make([]state.APIKeyEntry, len(appState.APIKeys))
	copy(s.cachedAPIKeys, appState.APIKeys)

	entry := appState.Identities[idx]
	s.logger.Info("identity updated", "id", id, "name", entry.Name)
	return &entry, nil
}

// DeleteIdentity removes an identity and all its API keys.
func (s *IdentityService) DeleteIdentity(_ context.Context, id string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	appState, err := s.stateStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}

	// Find and remove the identity.
	idx := -1
	for i := range appState.Identities {
		if appState.Identities[i].ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, ErrIdentityNotFound
	}

	if appState.Identities[idx].ReadOnly {
		return nil, ErrReadOnly
	}

	// Remove the identity.
	appState.Identities = append(appState.Identities[:idx], appState.Identities[idx+1:]...)

	// Cascade: remove all API keys belonging to this identity.
	// Collect their key hashes so the caller can sync the auth store.
	var deletedKeyHashes []string
	filtered := make([]state.APIKeyEntry, 0, len(appState.APIKeys))
	for _, key := range appState.APIKeys {
		if key.IdentityID != id {
			filtered = append(filtered, key)
		} else {
			deletedKeyHashes = append(deletedKeyHashes, key.KeyHash)
		}
	}
	appState.APIKeys = filtered

	if err := s.stateStore.Save(appState); err != nil {
		return nil, fmt.Errorf("save state: %w", err)
	}

	// Update cache from the state we just saved.
	s.cachedIdentities = make([]state.IdentityEntry, len(appState.Identities))
	copy(s.cachedIdentities, appState.Identities)
	s.cachedAPIKeys = make([]state.APIKeyEntry, len(appState.APIKeys))
	copy(s.cachedAPIKeys, appState.APIKeys)

	s.logger.Info("identity deleted (cascade)", "id", id, "keys_removed", len(deletedKeyHashes))
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

	s.mu.Lock()
	defer s.mu.Unlock()

	appState, err := s.stateStore.Load()
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}

	// Verify the identity exists.
	found := false
	for _, identity := range appState.Identities {
		if identity.ID == input.IdentityID {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrIdentityNotFound
	}

	// Generate a cryptographically random 32-byte key.
	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	}
	cleartextKey := "sg_" + hex.EncodeToString(rawKey)

	// Hash with Argon2id.
	hash, err := argon2id.CreateHash(cleartextKey, argon2id.DefaultParams)
	if err != nil {
		return nil, fmt.Errorf("hash key: %w", err)
	}

	entry := state.APIKeyEntry{
		ID:         uuid.New().String(),
		KeyHash:    hash,
		IdentityID: input.IdentityID,
		Name:       input.Name,
		CreatedAt:  time.Now().UTC(),
	}

	appState.APIKeys = append(appState.APIKeys, entry)

	if err := s.stateStore.Save(appState); err != nil {
		return nil, fmt.Errorf("save state: %w", err)
	}

	// Update cache from the state we just saved.
	s.cachedIdentities = make([]state.IdentityEntry, len(appState.Identities))
	copy(s.cachedIdentities, appState.Identities)
	s.cachedAPIKeys = make([]state.APIKeyEntry, len(appState.APIKeys))
	copy(s.cachedAPIKeys, appState.APIKeys)

	s.logger.Info("api key generated", "key_id", entry.ID, "identity_id", input.IdentityID, "name", input.Name)

	return &GenerateKeyResult{
		KeyEntry:     entry,
		CleartextKey: cleartextKey,
	}, nil
}

// RevokeKey marks an API key as revoked. It does not delete it.
// Returns the key hash of the revoked key so callers can sync in-memory stores.
func (s *IdentityService) RevokeKey(_ context.Context, keyID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	appState, err := s.stateStore.Load()
	if err != nil {
		return "", fmt.Errorf("load state: %w", err)
	}

	idx := -1
	for i := range appState.APIKeys {
		if appState.APIKeys[i].ID == keyID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return "", ErrAPIKeyNotFound
	}

	if appState.APIKeys[idx].ReadOnly {
		return "", ErrReadOnly
	}

	keyHash := appState.APIKeys[idx].KeyHash
	appState.APIKeys[idx].Revoked = true

	if err := s.stateStore.Save(appState); err != nil {
		return "", fmt.Errorf("save state: %w", err)
	}

	// Update cache from the state we just saved.
	s.cachedIdentities = make([]state.IdentityEntry, len(appState.Identities))
	copy(s.cachedIdentities, appState.Identities)
	s.cachedAPIKeys = make([]state.APIKeyEntry, len(appState.APIKeys))
	copy(s.cachedAPIKeys, appState.APIKeys)

	s.logger.Info("api key revoked", "key_id", keyID)
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

		match, err := argon2id.ComparePasswordAndHash(cleartextKey, key.KeyHash)
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
