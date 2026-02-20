package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Test sentinel errors for mock store.
var (
	errKeyNotFound      = errors.New("api key not found")
	errIdentityNotFound = errors.New("identity not found")
)

// mockAuthStore implements AuthStore for testing.
type mockAuthStore struct {
	keys       map[string]*APIKey
	identities map[string]*Identity
}

func newMockAuthStore() *mockAuthStore {
	return &mockAuthStore{
		keys:       make(map[string]*APIKey),
		identities: make(map[string]*Identity),
	}
}

func (m *mockAuthStore) GetAPIKey(ctx context.Context, keyHash string) (*APIKey, error) {
	key, ok := m.keys[keyHash]
	if !ok {
		return nil, errKeyNotFound
	}
	return key, nil
}

func (m *mockAuthStore) GetIdentity(ctx context.Context, id string) (*Identity, error) {
	identity, ok := m.identities[id]
	if !ok {
		return nil, errIdentityNotFound
	}
	return identity, nil
}

func (m *mockAuthStore) ListAPIKeys(ctx context.Context) ([]*APIKey, error) {
	result := make([]*APIKey, 0, len(m.keys))
	for _, key := range m.keys {
		result = append(result, key)
	}
	return result, nil
}

// Compile-time check that mockAuthStore implements AuthStore.
var _ AuthStore = (*mockAuthStore)(nil)

func TestAPIKeyService_Validate(t *testing.T) {
	// Setup test data
	rawKey := "test-api-key-12345"
	keyHash := HashKey(rawKey)

	now := time.Now().UTC()
	pastTime := now.Add(-1 * time.Hour)
	futureTime := now.Add(1 * time.Hour)

	tests := []struct {
		name       string
		rawKey     string
		setupStore func(*mockAuthStore)
		wantErr    error
		wantID     string
		wantRoles  []Role
	}{
		{
			name:   "valid key returns identity with roles",
			rawKey: rawKey,
			setupStore: func(m *mockAuthStore) {
				m.keys[keyHash] = &APIKey{
					Key:        keyHash,
					IdentityID: "user-1",
					CreatedAt:  now,
					ExpiresAt:  &futureTime,
					Revoked:    false,
				}
				m.identities["user-1"] = &Identity{
					ID:    "user-1",
					Name:  "Test User",
					Roles: []Role{RoleUser, RoleReadOnly},
				}
			},
			wantErr:   nil,
			wantID:    "user-1",
			wantRoles: []Role{RoleUser, RoleReadOnly},
		},
		{
			name:   "valid key without expiry returns identity",
			rawKey: rawKey,
			setupStore: func(m *mockAuthStore) {
				m.keys[keyHash] = &APIKey{
					Key:        keyHash,
					IdentityID: "user-2",
					CreatedAt:  now,
					ExpiresAt:  nil, // never expires
					Revoked:    false,
				}
				m.identities["user-2"] = &Identity{
					ID:    "user-2",
					Name:  "Admin User",
					Roles: []Role{RoleAdmin},
				}
			},
			wantErr:   nil,
			wantID:    "user-2",
			wantRoles: []Role{RoleAdmin},
		},
		{
			name:   "expired key returns ErrInvalidKey",
			rawKey: rawKey,
			setupStore: func(m *mockAuthStore) {
				m.keys[keyHash] = &APIKey{
					Key:        keyHash,
					IdentityID: "user-1",
					CreatedAt:  now,
					ExpiresAt:  &pastTime,
					Revoked:    false,
				}
			},
			wantErr: ErrInvalidKey,
		},
		{
			name:   "revoked key returns ErrInvalidKey",
			rawKey: rawKey,
			setupStore: func(m *mockAuthStore) {
				m.keys[keyHash] = &APIKey{
					Key:        keyHash,
					IdentityID: "user-1",
					CreatedAt:  now,
					ExpiresAt:  &futureTime,
					Revoked:    true,
				}
			},
			wantErr: ErrInvalidKey,
		},
		{
			name:   "non-existent key returns error",
			rawKey: "non-existent-key",
			setupStore: func(m *mockAuthStore) {
				// No keys added
			},
			wantErr: ErrInvalidKey,
		},
		{
			name:   "identity not found returns error",
			rawKey: rawKey,
			setupStore: func(m *mockAuthStore) {
				m.keys[keyHash] = &APIKey{
					Key:        keyHash,
					IdentityID: "missing-user",
					CreatedAt:  now,
					ExpiresAt:  &futureTime,
					Revoked:    false,
				}
				// Identity not added
			},
			wantErr: errIdentityNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockAuthStore()
			tt.setupStore(store)

			svc := NewAPIKeyService(store)
			identity, err := svc.Validate(context.Background(), tt.rawKey)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("Validate() unexpected error = %v", err)
				return
			}

			if identity.ID != tt.wantID {
				t.Errorf("Validate() identity.ID = %v, want %v", identity.ID, tt.wantID)
			}

			if len(identity.Roles) != len(tt.wantRoles) {
				t.Errorf("Validate() identity.Roles = %v, want %v", identity.Roles, tt.wantRoles)
			}

			for i, role := range tt.wantRoles {
				if identity.Roles[i] != role {
					t.Errorf("Validate() identity.Roles[%d] = %v, want %v", i, identity.Roles[i], role)
				}
			}
		})
	}
}

func TestHashKey(t *testing.T) {
	// HashKey should produce consistent SHA-256 hex output
	rawKey := "test-key"
	hash1 := HashKey(rawKey)
	hash2 := HashKey(rawKey)

	if hash1 != hash2 {
		t.Errorf("HashKey() not deterministic: %v != %v", hash1, hash2)
	}

	// Hash should be 64 hex characters (256 bits / 4 bits per hex char)
	if len(hash1) != 64 {
		t.Errorf("HashKey() length = %d, want 64", len(hash1))
	}

	// Different keys should produce different hashes
	hash3 := HashKey("different-key")
	if hash1 == hash3 {
		t.Error("HashKey() produced same hash for different keys")
	}
}

func TestRole_IsValid(t *testing.T) {
	tests := []struct {
		role  Role
		valid bool
	}{
		{RoleAdmin, true},
		{RoleUser, true},
		{RoleReadOnly, true},
		{Role("invalid"), false},
		{Role(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			if got := tt.role.IsValid(); got != tt.valid {
				t.Errorf("Role(%q).IsValid() = %v, want %v", tt.role, got, tt.valid)
			}
		})
	}
}

func TestIdentity_HasRole(t *testing.T) {
	identity := &Identity{
		ID:    "test",
		Name:  "Test",
		Roles: []Role{RoleUser, RoleReadOnly},
	}

	if !identity.HasRole(RoleUser) {
		t.Error("HasRole(RoleUser) = false, want true")
	}

	if !identity.HasRole(RoleReadOnly) {
		t.Error("HasRole(RoleReadOnly) = false, want true")
	}

	if identity.HasRole(RoleAdmin) {
		t.Error("HasRole(RoleAdmin) = true, want false")
	}
}

func TestIdentity_HasAnyRole(t *testing.T) {
	identity := &Identity{
		ID:    "test",
		Name:  "Test",
		Roles: []Role{RoleUser},
	}

	if !identity.HasAnyRole(RoleAdmin, RoleUser) {
		t.Error("HasAnyRole(RoleAdmin, RoleUser) = false, want true")
	}

	if identity.HasAnyRole(RoleAdmin, RoleReadOnly) {
		t.Error("HasAnyRole(RoleAdmin, RoleReadOnly) = true, want false")
	}

	if identity.HasAnyRole() {
		t.Error("HasAnyRole() with no args = true, want false")
	}
}

func TestAPIKey_IsExpired(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	tests := []struct {
		name      string
		expiresAt *time.Time
		want      bool
	}{
		{"nil expiry never expires", nil, false},
		{"past expiry is expired", &past, true},
		{"future expiry not expired", &future, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{ExpiresAt: tt.expiresAt}
			if got := key.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ============================================================================
// Phase 03-01: Argon2id hashing tests
// ============================================================================

func TestHashKeyArgon2id(t *testing.T) {
	rawKey := "test-api-key-secure-12345"

	// Should return PHC format string starting with $argon2id$
	hash, err := HashKeyArgon2id(rawKey)
	if err != nil {
		t.Fatalf("HashKeyArgon2id() error = %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("HashKeyArgon2id() = %q, want prefix $argon2id$", hash)
	}

	// Should produce different hashes for same input (due to random salt)
	hash2, err := HashKeyArgon2id(rawKey)
	if err != nil {
		t.Fatalf("HashKeyArgon2id() second call error = %v", err)
	}

	if hash == hash2 {
		t.Error("HashKeyArgon2id() produced identical hashes - should use random salt")
	}
}

func TestDetectHashType(t *testing.T) {
	tests := []struct {
		name     string
		hash     string
		wantType string
	}{
		{
			name:     "argon2id PHC format",
			hash:     "$argon2id$v=19$m=47104,t=1,p=1$abc123$xyz789",
			wantType: "argon2id",
		},
		{
			name:     "sha256 prefixed",
			hash:     "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantType: "sha256",
		},
		{
			name:     "legacy bare SHA-256 hex (64 chars)",
			hash:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantType: "sha256",
		},
		{
			name:     "unknown format - too short",
			hash:     "abc123",
			wantType: "unknown",
		},
		{
			name:     "unknown format - wrong prefix",
			hash:     "$bcrypt$abc123",
			wantType: "unknown",
		},
		{
			name:     "empty string",
			hash:     "",
			wantType: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectHashType(tt.hash)
			if got != tt.wantType {
				t.Errorf("DetectHashType(%q) = %q, want %q", tt.hash, got, tt.wantType)
			}
		})
	}
}

func TestVerifyKey(t *testing.T) {
	rawKey := "test-api-key-verify-12345"

	// Create an Argon2id hash for testing
	argon2Hash, err := HashKeyArgon2id(rawKey)
	if err != nil {
		t.Fatalf("HashKeyArgon2id() setup error = %v", err)
	}

	// Create SHA-256 hashes for backward compatibility testing
	sha256Hash := HashKey(rawKey)                 // legacy bare hex
	sha256Prefixed := "sha256:" + HashKey(rawKey) // prefixed format

	tests := []struct {
		name       string
		rawKey     string
		storedHash string
		wantMatch  bool
		wantErr    error
	}{
		{
			name:       "argon2id hash - correct key",
			rawKey:     rawKey,
			storedHash: argon2Hash,
			wantMatch:  true,
			wantErr:    nil,
		},
		{
			name:       "argon2id hash - wrong key",
			rawKey:     "wrong-key",
			storedHash: argon2Hash,
			wantMatch:  false,
			wantErr:    nil,
		},
		{
			name:       "sha256 prefixed - correct key",
			rawKey:     rawKey,
			storedHash: sha256Prefixed,
			wantMatch:  true,
			wantErr:    nil,
		},
		{
			name:       "sha256 prefixed - wrong key",
			rawKey:     "wrong-key",
			storedHash: sha256Prefixed,
			wantMatch:  false,
			wantErr:    nil,
		},
		{
			name:       "legacy bare sha256 - correct key",
			rawKey:     rawKey,
			storedHash: sha256Hash,
			wantMatch:  true,
			wantErr:    nil,
		},
		{
			name:       "legacy bare sha256 - wrong key",
			rawKey:     "wrong-key",
			storedHash: sha256Hash,
			wantMatch:  false,
			wantErr:    nil,
		},
		{
			name:       "unknown hash type returns error",
			rawKey:     rawKey,
			storedHash: "invalid-hash-format",
			wantMatch:  false,
			wantErr:    ErrUnknownHashType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := VerifyKey(tt.rawKey, tt.storedHash)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("VerifyKey() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("VerifyKey() unexpected error = %v", err)
				return
			}

			if match != tt.wantMatch {
				t.Errorf("VerifyKey() = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func TestVerifyKey_ConstantTimeComparison(t *testing.T) {
	// This test verifies that SHA-256 path uses constant-time comparison
	// by checking it doesn't short-circuit on partial matches.
	// Note: This is a behavioral test - actual timing attack resistance
	// is ensured by using crypto/subtle.ConstantTimeCompare

	rawKey := "test-constant-time-key"
	sha256Hash := HashKey(rawKey)

	// Both should return false without error (not short-circuit on first mismatch)
	// Wrong key with same length
	wrongKey1 := "test-constant-time-xyz"
	match1, err1 := VerifyKey(wrongKey1, sha256Hash)
	if err1 != nil {
		t.Errorf("VerifyKey() error = %v", err1)
	}
	if match1 {
		t.Error("VerifyKey() should return false for wrong key")
	}

	// Completely different key
	wrongKey2 := "completely-different-key-here"
	match2, err2 := VerifyKey(wrongKey2, sha256Hash)
	if err2 != nil {
		t.Errorf("VerifyKey() error = %v", err2)
	}
	if match2 {
		t.Error("VerifyKey() should return false for wrong key")
	}
}
