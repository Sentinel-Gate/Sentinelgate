package service

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexedwards/argon2id"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
)

// testIdentityEnv sets up a fresh IdentityService with a temporary state file.
func testIdentityEnv(t *testing.T) (*IdentityService, *state.FileStateStore, string) {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)

	// Initialize the state file with defaults.
	defaultState := stateStore.DefaultState()
	if err := stateStore.Save(defaultState); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	svc := NewIdentityService(stateStore, logger)
	return svc, stateStore, statePath
}

// --- Identity CRUD Tests ---

func TestIdentityService_CreateIdentity(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	identity, err := svc.CreateIdentity(ctx, CreateIdentityInput{
		Name:  "test-user",
		Roles: []string{"admin", "user"},
	})
	if err != nil {
		t.Fatalf("CreateIdentity() unexpected error: %v", err)
	}

	if identity.ID == "" {
		t.Error("CreateIdentity() did not generate an ID")
	}
	if identity.Name != "test-user" {
		t.Errorf("CreateIdentity() Name = %q, want %q", identity.Name, "test-user")
	}
	if len(identity.Roles) != 2 {
		t.Errorf("CreateIdentity() Roles count = %d, want 2", len(identity.Roles))
	}
	if identity.CreatedAt.IsZero() {
		t.Error("CreateIdentity() did not set CreatedAt")
	}
}

func TestIdentityService_CreateIdentity_EmptyName(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	_, err := svc.CreateIdentity(ctx, CreateIdentityInput{
		Name: "",
	})
	if err == nil {
		t.Fatal("CreateIdentity() empty name should return error")
	}
}

func TestIdentityService_CreateIdentity_DuplicateName(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	_, err := svc.CreateIdentity(ctx, CreateIdentityInput{
		Name:  "test-user",
		Roles: []string{"user"},
	})
	if err != nil {
		t.Fatalf("CreateIdentity() first: %v", err)
	}

	_, err = svc.CreateIdentity(ctx, CreateIdentityInput{
		Name:  "test-user",
		Roles: []string{"admin"},
	})
	if err == nil {
		t.Fatal("CreateIdentity() duplicate name should return error")
	}
	if err != ErrDuplicateName {
		t.Errorf("CreateIdentity() error = %v, want %v", err, ErrDuplicateName)
	}
}

func TestIdentityService_CreateIdentity_NilRoles(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	identity, err := svc.CreateIdentity(ctx, CreateIdentityInput{
		Name: "no-roles",
	})
	if err != nil {
		t.Fatalf("CreateIdentity() unexpected error: %v", err)
	}

	if identity.Roles == nil {
		t.Fatal("CreateIdentity() should initialize nil roles to empty slice")
	}
	if len(identity.Roles) != 0 {
		t.Errorf("CreateIdentity() Roles count = %d, want 0", len(identity.Roles))
	}
}

func TestIdentityService_ListIdentities_Empty(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	identities, err := svc.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities() unexpected error: %v", err)
	}
	if len(identities) != 0 {
		t.Errorf("ListIdentities() count = %d, want 0", len(identities))
	}
}

func TestIdentityService_ListIdentities_Multiple(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	_, _ = svc.CreateIdentity(ctx, CreateIdentityInput{Name: "user-1"})
	_, _ = svc.CreateIdentity(ctx, CreateIdentityInput{Name: "user-2"})

	identities, err := svc.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities() unexpected error: %v", err)
	}
	if len(identities) != 2 {
		t.Errorf("ListIdentities() count = %d, want 2", len(identities))
	}
}

func TestIdentityService_GetIdentity(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	created, _ := svc.CreateIdentity(ctx, CreateIdentityInput{
		Name:  "test-user",
		Roles: []string{"admin"},
	})

	got, err := svc.GetIdentity(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetIdentity() unexpected error: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("GetIdentity() ID = %q, want %q", got.ID, created.ID)
	}
	if got.Name != "test-user" {
		t.Errorf("GetIdentity() Name = %q, want %q", got.Name, "test-user")
	}
}

func TestIdentityService_GetIdentity_NotFound(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	_, err := svc.GetIdentity(ctx, "nonexistent")
	if err == nil {
		t.Fatal("GetIdentity() nonexistent should return error")
	}
	if err != ErrIdentityNotFound {
		t.Errorf("GetIdentity() error = %v, want %v", err, ErrIdentityNotFound)
	}
}

func TestIdentityService_UpdateIdentity(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	created, _ := svc.CreateIdentity(ctx, CreateIdentityInput{
		Name:  "test-user",
		Roles: []string{"user"},
	})

	newName := "updated-user"
	updated, err := svc.UpdateIdentity(ctx, created.ID, UpdateIdentityInput{
		Name:  &newName,
		Roles: []string{"admin", "user"},
	})
	if err != nil {
		t.Fatalf("UpdateIdentity() unexpected error: %v", err)
	}
	if updated.Name != "updated-user" {
		t.Errorf("UpdateIdentity() Name = %q, want %q", updated.Name, "updated-user")
	}
	if len(updated.Roles) != 2 {
		t.Errorf("UpdateIdentity() Roles count = %d, want 2", len(updated.Roles))
	}
}

func TestIdentityService_UpdateIdentity_NotFound(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	name := "ghost"
	_, err := svc.UpdateIdentity(ctx, "nonexistent", UpdateIdentityInput{
		Name: &name,
	})
	if err == nil {
		t.Fatal("UpdateIdentity() nonexistent should return error")
	}
	if err != ErrIdentityNotFound {
		t.Errorf("UpdateIdentity() error = %v, want %v", err, ErrIdentityNotFound)
	}
}

func TestIdentityService_UpdateIdentity_DuplicateName(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	_, _ = svc.CreateIdentity(ctx, CreateIdentityInput{Name: "user-1"})
	created2, _ := svc.CreateIdentity(ctx, CreateIdentityInput{Name: "user-2"})

	name := "user-1"
	_, err := svc.UpdateIdentity(ctx, created2.ID, UpdateIdentityInput{
		Name: &name,
	})
	if err == nil {
		t.Fatal("UpdateIdentity() duplicate name should return error")
	}
	if err != ErrDuplicateName {
		t.Errorf("UpdateIdentity() error = %v, want %v", err, ErrDuplicateName)
	}
}

func TestIdentityService_UpdateIdentity_ReadOnly(t *testing.T) {
	svc, stateStore, _ := testIdentityEnv(t)
	ctx := context.Background()

	// Manually insert a read-only identity.
	appState, _ := stateStore.Load()
	appState.Identities = append(appState.Identities, state.IdentityEntry{
		ID:       "ro-identity",
		Name:     "read-only-user",
		ReadOnly: true,
	})
	_ = stateStore.Save(appState)

	name := "changed"
	_, err := svc.UpdateIdentity(ctx, "ro-identity", UpdateIdentityInput{
		Name: &name,
	})
	if err == nil {
		t.Fatal("UpdateIdentity() read-only should return error")
	}
	if err != ErrReadOnly {
		t.Errorf("UpdateIdentity() error = %v, want %v", err, ErrReadOnly)
	}
}

func TestIdentityService_DeleteIdentity(t *testing.T) {
	svc, stateStore, _ := testIdentityEnv(t)
	ctx := context.Background()

	created, _ := svc.CreateIdentity(ctx, CreateIdentityInput{Name: "to-delete"})

	if _, err := svc.DeleteIdentity(ctx, created.ID); err != nil {
		t.Fatalf("DeleteIdentity() unexpected error: %v", err)
	}

	// Verify gone.
	_, err := svc.GetIdentity(ctx, created.ID)
	if err != ErrIdentityNotFound {
		t.Errorf("GetIdentity() after delete error = %v, want %v", err, ErrIdentityNotFound)
	}

	// Verify persisted.
	appState, _ := stateStore.Load()
	if len(appState.Identities) != 0 {
		t.Errorf("Persisted identities count = %d, want 0", len(appState.Identities))
	}
}

func TestIdentityService_DeleteIdentity_NotFound(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	_, err := svc.DeleteIdentity(ctx, "nonexistent")
	if err == nil {
		t.Fatal("DeleteIdentity() nonexistent should return error")
	}
	if err != ErrIdentityNotFound {
		t.Errorf("DeleteIdentity() error = %v, want %v", err, ErrIdentityNotFound)
	}
}

func TestIdentityService_DeleteIdentity_CascadeKeys(t *testing.T) {
	svc, stateStore, _ := testIdentityEnv(t)
	ctx := context.Background()

	identity, _ := svc.CreateIdentity(ctx, CreateIdentityInput{
		Name: "with-keys",
	})

	// Generate 2 keys.
	_, _ = svc.GenerateKey(ctx, GenerateKeyInput{
		IdentityID: identity.ID,
		Name:       "key-1",
	})
	_, _ = svc.GenerateKey(ctx, GenerateKeyInput{
		IdentityID: identity.ID,
		Name:       "key-2",
	})

	// Verify 2 keys exist.
	keys, _ := svc.ListKeys(ctx, identity.ID)
	if len(keys) != 2 {
		t.Fatalf("ListKeys() count = %d, want 2", len(keys))
	}

	// Delete identity should cascade.
	deletedHashes, err := svc.DeleteIdentity(ctx, identity.ID)
	if err != nil {
		t.Fatalf("DeleteIdentity() unexpected error: %v", err)
	}
	if len(deletedHashes) != 2 {
		t.Errorf("DeleteIdentity() returned %d key hashes, want 2", len(deletedHashes))
	}

	// Verify keys are gone.
	appState, _ := stateStore.Load()
	if len(appState.APIKeys) != 0 {
		t.Errorf("Persisted API keys count = %d, want 0", len(appState.APIKeys))
	}
}

func TestIdentityService_DeleteIdentity_ReadOnly(t *testing.T) {
	svc, stateStore, _ := testIdentityEnv(t)
	ctx := context.Background()

	appState, _ := stateStore.Load()
	appState.Identities = append(appState.Identities, state.IdentityEntry{
		ID:       "ro-identity",
		Name:     "read-only-user",
		ReadOnly: true,
	})
	_ = stateStore.Save(appState)

	_, err := svc.DeleteIdentity(ctx, "ro-identity")
	if err == nil {
		t.Fatal("DeleteIdentity() read-only should return error")
	}
	if err != ErrReadOnly {
		t.Errorf("DeleteIdentity() error = %v, want %v", err, ErrReadOnly)
	}
}

// --- Key Generation/Revocation Tests ---

func TestIdentityService_GenerateKey(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	identity, _ := svc.CreateIdentity(ctx, CreateIdentityInput{
		Name: "keyed-user",
	})

	result, err := svc.GenerateKey(ctx, GenerateKeyInput{
		IdentityID: identity.ID,
		Name:       "my-key",
	})
	if err != nil {
		t.Fatalf("GenerateKey() unexpected error: %v", err)
	}

	// Verify cleartext key format.
	if !strings.HasPrefix(result.CleartextKey, "sg_") {
		t.Errorf("GenerateKey() cleartext key should start with sg_, got %q", result.CleartextKey[:10])
	}

	// Verify cleartext != hash.
	if result.CleartextKey == result.KeyEntry.KeyHash {
		t.Error("GenerateKey() cleartext key should not equal the hash")
	}

	// Verify hash is Argon2id format.
	if !strings.HasPrefix(result.KeyEntry.KeyHash, "$argon2id$") {
		t.Errorf("GenerateKey() hash should be Argon2id, got prefix %q", result.KeyEntry.KeyHash[:20])
	}

	// Verify the cleartext can be verified against the hash.
	match, err := argon2id.ComparePasswordAndHash(result.CleartextKey, result.KeyEntry.KeyHash)
	if err != nil {
		t.Fatalf("ComparePasswordAndHash() error: %v", err)
	}
	if !match {
		t.Error("GenerateKey() cleartext key does not match its hash")
	}

	// Verify entry fields.
	if result.KeyEntry.ID == "" {
		t.Error("GenerateKey() did not generate a key ID")
	}
	if result.KeyEntry.IdentityID != identity.ID {
		t.Errorf("GenerateKey() IdentityID = %q, want %q", result.KeyEntry.IdentityID, identity.ID)
	}
	if result.KeyEntry.Name != "my-key" {
		t.Errorf("GenerateKey() Name = %q, want %q", result.KeyEntry.Name, "my-key")
	}
	if result.KeyEntry.Revoked {
		t.Error("GenerateKey() new key should not be revoked")
	}
}

func TestIdentityService_GenerateKey_IdentityNotFound(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	_, err := svc.GenerateKey(ctx, GenerateKeyInput{
		IdentityID: "nonexistent",
		Name:       "my-key",
	})
	if err == nil {
		t.Fatal("GenerateKey() nonexistent identity should return error")
	}
	if err != ErrIdentityNotFound {
		t.Errorf("GenerateKey() error = %v, want %v", err, ErrIdentityNotFound)
	}
}

func TestIdentityService_GenerateKey_EmptyName(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	identity, _ := svc.CreateIdentity(ctx, CreateIdentityInput{Name: "user"})

	_, err := svc.GenerateKey(ctx, GenerateKeyInput{
		IdentityID: identity.ID,
		Name:       "",
	})
	if err == nil {
		t.Fatal("GenerateKey() empty name should return error")
	}
}

func TestIdentityService_GenerateKey_EmptyIdentityID(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	_, err := svc.GenerateKey(ctx, GenerateKeyInput{
		IdentityID: "",
		Name:       "my-key",
	})
	if err == nil {
		t.Fatal("GenerateKey() empty identity_id should return error")
	}
}

func TestIdentityService_RevokeKey(t *testing.T) {
	svc, stateStore, _ := testIdentityEnv(t)
	ctx := context.Background()

	identity, _ := svc.CreateIdentity(ctx, CreateIdentityInput{Name: "user"})
	result, _ := svc.GenerateKey(ctx, GenerateKeyInput{
		IdentityID: identity.ID,
		Name:       "to-revoke",
	})

	if _, err := svc.RevokeKey(ctx, result.KeyEntry.ID); err != nil {
		t.Fatalf("RevokeKey() unexpected error: %v", err)
	}

	// Verify revoked in state.
	appState, _ := stateStore.Load()
	for _, key := range appState.APIKeys {
		if key.ID == result.KeyEntry.ID {
			if !key.Revoked {
				t.Error("RevokeKey() key should be revoked in state")
			}
			return
		}
	}
	t.Error("RevokeKey() key not found in state after revocation")
}

func TestIdentityService_RevokeKey_NotFound(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	_, err := svc.RevokeKey(ctx, "nonexistent")
	if err == nil {
		t.Fatal("RevokeKey() nonexistent should return error")
	}
	if err != ErrAPIKeyNotFound {
		t.Errorf("RevokeKey() error = %v, want %v", err, ErrAPIKeyNotFound)
	}
}

func TestIdentityService_RevokeKey_ReadOnly(t *testing.T) {
	svc, stateStore, _ := testIdentityEnv(t)
	ctx := context.Background()

	appState, _ := stateStore.Load()
	appState.APIKeys = append(appState.APIKeys, state.APIKeyEntry{
		ID:       "ro-key",
		KeyHash:  "fake-hash",
		ReadOnly: true,
	})
	_ = stateStore.Save(appState)

	_, err := svc.RevokeKey(ctx, "ro-key")
	if err == nil {
		t.Fatal("RevokeKey() read-only should return error")
	}
	if err != ErrReadOnly {
		t.Errorf("RevokeKey() error = %v, want %v", err, ErrReadOnly)
	}
}

func TestIdentityService_ListKeys(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	identity, _ := svc.CreateIdentity(ctx, CreateIdentityInput{Name: "user"})

	// No keys yet.
	keys, err := svc.ListKeys(ctx, identity.ID)
	if err != nil {
		t.Fatalf("ListKeys() unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("ListKeys() empty count = %d, want 0", len(keys))
	}

	// Generate 2 keys.
	_, _ = svc.GenerateKey(ctx, GenerateKeyInput{IdentityID: identity.ID, Name: "key-1"})
	_, _ = svc.GenerateKey(ctx, GenerateKeyInput{IdentityID: identity.ID, Name: "key-2"})

	keys, err = svc.ListKeys(ctx, identity.ID)
	if err != nil {
		t.Fatalf("ListKeys() unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("ListKeys() count = %d, want 2", len(keys))
	}
}

func TestIdentityService_VerifyKey(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	identity, _ := svc.CreateIdentity(ctx, CreateIdentityInput{Name: "user"})
	result, _ := svc.GenerateKey(ctx, GenerateKeyInput{
		IdentityID: identity.ID,
		Name:       "my-key",
	})

	// Verify with correct key.
	entry, err := svc.VerifyKey(ctx, result.CleartextKey)
	if err != nil {
		t.Fatalf("VerifyKey() unexpected error: %v", err)
	}
	if entry.ID != result.KeyEntry.ID {
		t.Errorf("VerifyKey() ID = %q, want %q", entry.ID, result.KeyEntry.ID)
	}
	if entry.IdentityID != identity.ID {
		t.Errorf("VerifyKey() IdentityID = %q, want %q", entry.IdentityID, identity.ID)
	}
}

func TestIdentityService_VerifyKey_Wrong(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	identity, _ := svc.CreateIdentity(ctx, CreateIdentityInput{Name: "user"})
	_, _ = svc.GenerateKey(ctx, GenerateKeyInput{
		IdentityID: identity.ID,
		Name:       "my-key",
	})

	_, err := svc.VerifyKey(ctx, "sg_wrong_key_value_here")
	if err == nil {
		t.Fatal("VerifyKey() wrong key should return error")
	}
	if err != ErrAPIKeyNotFound {
		t.Errorf("VerifyKey() error = %v, want %v", err, ErrAPIKeyNotFound)
	}
}

func TestIdentityService_VerifyKey_Revoked(t *testing.T) {
	svc, _, _ := testIdentityEnv(t)
	ctx := context.Background()

	identity, _ := svc.CreateIdentity(ctx, CreateIdentityInput{Name: "user"})
	result, _ := svc.GenerateKey(ctx, GenerateKeyInput{
		IdentityID: identity.ID,
		Name:       "my-key",
	})

	_, _ = svc.RevokeKey(ctx, result.KeyEntry.ID)

	_, err := svc.VerifyKey(ctx, result.CleartextKey)
	if err == nil {
		t.Fatal("VerifyKey() revoked key should return error")
	}
	if err != ErrAPIKeyNotFound {
		t.Errorf("VerifyKey() error = %v, want %v", err, ErrAPIKeyNotFound)
	}
}

// --- Persistence Tests ---

func TestIdentityService_Persistence(t *testing.T) {
	svc, stateStore, _ := testIdentityEnv(t)
	ctx := context.Background()

	created, _ := svc.CreateIdentity(ctx, CreateIdentityInput{
		Name:  "persisted-user",
		Roles: []string{"admin"},
	})

	// Verify state.json has the identity.
	appState, _ := stateStore.Load()
	if len(appState.Identities) != 1 {
		t.Fatalf("Persisted identities count = %d, want 1", len(appState.Identities))
	}
	if appState.Identities[0].ID != created.ID {
		t.Errorf("Persisted ID = %q, want %q", appState.Identities[0].ID, created.ID)
	}
	if appState.Identities[0].Name != "persisted-user" {
		t.Errorf("Persisted Name = %q, want %q", appState.Identities[0].Name, "persisted-user")
	}
}

func TestIdentityService_GenerateKey_Persistence(t *testing.T) {
	svc, stateStore, _ := testIdentityEnv(t)
	ctx := context.Background()

	identity, _ := svc.CreateIdentity(ctx, CreateIdentityInput{Name: "user"})
	result, _ := svc.GenerateKey(ctx, GenerateKeyInput{
		IdentityID: identity.ID,
		Name:       "persisted-key",
	})

	// Verify state.json has the key.
	appState, _ := stateStore.Load()
	if len(appState.APIKeys) != 1 {
		t.Fatalf("Persisted API keys count = %d, want 1", len(appState.APIKeys))
	}

	key := appState.APIKeys[0]
	if key.ID != result.KeyEntry.ID {
		t.Errorf("Persisted key ID = %q, want %q", key.ID, result.KeyEntry.ID)
	}

	// The stored hash should NOT be the cleartext key.
	if key.KeyHash == result.CleartextKey {
		t.Error("Persisted key hash should not be cleartext")
	}

	// The stored hash should be Argon2id.
	if !strings.HasPrefix(key.KeyHash, "$argon2id$") {
		t.Errorf("Persisted key hash should be Argon2id format, got %q", key.KeyHash[:20])
	}
}
