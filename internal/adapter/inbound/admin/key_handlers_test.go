package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// --- Generate Key ---

func TestHandleGenerateKey(t *testing.T) {
	env := setupIdentityTestEnv(t)
	ctx := context.Background()

	// Create an identity first.
	identity, err := env.identityService.CreateIdentity(ctx, service.CreateIdentityInput{
		Name: "keyed-user",
	})
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}

	rec := env.doRequest(t, "POST", "/admin/api/keys", generateKeyRequest{
		IdentityID: identity.ID,
		Name:       "my-key",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/api/keys status = %d, want %d (body=%s)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var result generateKeyResponse
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Verify response.
	if result.ID == "" {
		t.Error("response missing ID")
	}
	if result.IdentityID != identity.ID {
		t.Errorf("response IdentityID = %q, want %q", result.IdentityID, identity.ID)
	}
	if result.Name != "my-key" {
		t.Errorf("response Name = %q, want %q", result.Name, "my-key")
	}
	if result.CleartextKey == "" {
		t.Error("response missing CleartextKey")
	}
	if !strings.HasPrefix(result.CleartextKey, "sg_") {
		t.Errorf("CleartextKey should start with sg_, got %q", result.CleartextKey[:10])
	}
	if result.CreatedAt == "" {
		t.Error("response missing CreatedAt")
	}
}

func TestHandleGenerateKey_IdentityNotFound(t *testing.T) {
	env := setupIdentityTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/keys", generateKeyRequest{
		IdentityID: "nonexistent",
		Name:       "my-key",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /admin/api/keys nonexistent identity status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleGenerateKey_MissingIdentityID(t *testing.T) {
	env := setupIdentityTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/keys", generateKeyRequest{
		IdentityID: "",
		Name:       "my-key",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /admin/api/keys missing identity_id status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleGenerateKey_MissingName(t *testing.T) {
	env := setupIdentityTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/keys", generateKeyRequest{
		IdentityID: "some-id",
		Name:       "",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /admin/api/keys missing name status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// --- Revoke Key ---

func TestHandleRevokeKey(t *testing.T) {
	env := setupIdentityTestEnv(t)
	ctx := context.Background()

	// Create identity and key.
	identity, _ := env.identityService.CreateIdentity(ctx, service.CreateIdentityInput{
		Name: "user-with-key",
	})
	keyResult, _ := env.identityService.GenerateKey(ctx, service.GenerateKeyInput{
		IdentityID: identity.ID,
		Name:       "to-revoke",
	})

	rec := env.doRequest(t, "DELETE", "/admin/api/keys/"+keyResult.KeyEntry.ID, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /admin/api/keys/{id} status = %d, want %d (body=%s)", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Verify key is revoked.
	appState, _ := env.stateStore.Load()
	for _, key := range appState.APIKeys {
		if key.ID == keyResult.KeyEntry.ID {
			if !key.Revoked {
				t.Error("key should be revoked after DELETE")
			}
			return
		}
	}
	t.Error("key not found in state after revocation")
}

func TestHandleRevokeKey_NotFound(t *testing.T) {
	env := setupIdentityTestEnv(t)

	rec := env.doRequest(t, "DELETE", "/admin/api/keys/nonexistent", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE nonexistent key status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// --- Key in response is returned exactly once ---

func TestHandleGenerateKey_CleartextInResponse(t *testing.T) {
	env := setupIdentityTestEnv(t)
	ctx := context.Background()

	identity, _ := env.identityService.CreateIdentity(ctx, service.CreateIdentityInput{
		Name: "user",
	})

	// Generate key via API.
	rec := env.doRequest(t, "POST", "/admin/api/keys", generateKeyRequest{
		IdentityID: identity.ID,
		Name:       "one-time-key",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/api/keys status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var result generateKeyResponse
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// The cleartext key should be present.
	if result.CleartextKey == "" {
		t.Fatal("CleartextKey should be present in generate response")
	}

	// Verify the cleartext key can authenticate via the service.
	entry, err := env.identityService.VerifyKey(ctx, result.CleartextKey)
	if err != nil {
		t.Fatalf("VerifyKey() failed: %v", err)
	}
	if entry.ID != result.ID {
		t.Errorf("VerifyKey() ID = %q, want %q", entry.ID, result.ID)
	}

	// Verify the cleartext key is NOT stored in state.json.
	appState, _ := env.stateStore.Load()
	for _, key := range appState.APIKeys {
		if key.ID == result.ID {
			if key.KeyHash == result.CleartextKey {
				t.Error("Cleartext key should NOT be stored in state.json")
			}
			if !strings.HasPrefix(key.KeyHash, "$argon2id$") {
				t.Error("Stored hash should be Argon2id format")
			}
			return
		}
	}
	t.Error("key not found in state.json")
}
