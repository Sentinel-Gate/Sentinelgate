package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenerateRuntimeAPIKey_Format(t *testing.T) {
	t.Parallel()

	plaintext, hash, err := GenerateRuntimeAPIKey()
	if err != nil {
		t.Fatalf("GenerateRuntimeAPIKey() error = %v", err)
	}

	// Verify prefix.
	if !strings.HasPrefix(plaintext, "sg_runtime_") {
		t.Errorf("plaintext key should start with sg_runtime_, got %q", plaintext)
	}

	// Verify total length: 11 prefix chars + 32 hex chars = 43.
	if len(plaintext) != 43 {
		t.Errorf("plaintext key length = %d, want 43", len(plaintext))
	}

	// Verify hex portion is valid hex.
	hexPart := plaintext[len("sg_runtime_"):]
	if len(hexPart) != 32 {
		t.Errorf("hex part length = %d, want 32", len(hexPart))
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		t.Errorf("hex part is not valid hex: %v", err)
	}

	// Verify hash matches SHA-256 of plaintext.
	expected := sha256.Sum256([]byte(plaintext))
	expectedHex := hex.EncodeToString(expected[:])
	if hash != expectedHex {
		t.Errorf("hash = %q, want sha256(%q) = %q", hash, plaintext, expectedHex)
	}
}

func TestGenerateRuntimeAPIKey_Unique(t *testing.T) {
	t.Parallel()

	key1, hash1, err := GenerateRuntimeAPIKey()
	if err != nil {
		t.Fatalf("GenerateRuntimeAPIKey() first call error = %v", err)
	}

	key2, hash2, err := GenerateRuntimeAPIKey()
	if err != nil {
		t.Fatalf("GenerateRuntimeAPIKey() second call error = %v", err)
	}

	if key1 == key2 {
		t.Error("two calls produced identical plaintext keys")
	}
	if hash1 == hash2 {
		t.Error("two calls produced identical hashes")
	}
}

func TestRegisterRuntimeKey_Success(t *testing.T) {
	t.Parallel()

	var gotIdentityName string
	var gotIdentityRoles []string
	var gotKeyIdentityID string
	var gotKeyName string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/admin/api/auth/status":
			http.SetCookie(w, &http.Cookie{Name: "sentinel_csrf_token", Value: "test-csrf-token"})
			w.WriteHeader(http.StatusOK)

		case r.Method == "POST" && r.URL.Path == "/admin/api/identities":
			var req createIdentityRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			gotIdentityName = req.Name
			gotIdentityRoles = req.Roles
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(createIdentityResponse{
				ID:   "test-identity-id",
				Name: req.Name,
			})

		case r.Method == "POST" && r.URL.Path == "/admin/api/keys":
			var req createKeyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			gotKeyIdentityID = req.IdentityID
			gotKeyName = req.Name
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(createKeyResponse{
				ID:           "test-key-id",
				CleartextKey: "sg_test_server_generated_key",
			})

		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	cleartextKey, result, err := RegisterRuntimeKey(server.URL, "agent-123")
	if err != nil {
		t.Fatalf("RegisterRuntimeKey() error = %v", err)
	}

	// Verify identity creation.
	if gotIdentityName != "runtime-agent-123" {
		t.Errorf("identity name = %q, want %q", gotIdentityName, "runtime-agent-123")
	}
	if len(gotIdentityRoles) != 1 || gotIdentityRoles[0] != "agent" {
		t.Errorf("identity roles = %v, want [agent]", gotIdentityRoles)
	}

	// Verify key generation.
	if gotKeyIdentityID != "test-identity-id" {
		t.Errorf("key identity_id = %q, want %q", gotKeyIdentityID, "test-identity-id")
	}
	if gotKeyName != "runtime-key-agent-123" {
		t.Errorf("key name = %q, want %q", gotKeyName, "runtime-key-agent-123")
	}

	// Verify return values.
	if cleartextKey != "sg_test_server_generated_key" {
		t.Errorf("cleartextKey = %q, want %q", cleartextKey, "sg_test_server_generated_key")
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.IdentityID != "test-identity-id" {
		t.Errorf("result.IdentityID = %q, want %q", result.IdentityID, "test-identity-id")
	}
}

func TestRegisterRuntimeKey_ServerUnreachable(t *testing.T) {
	t.Parallel()

	// Use an address that will fail to connect.
	_, _, err := RegisterRuntimeKey("http://127.0.0.1:1", "agent-456")
	if err == nil {
		t.Error("RegisterRuntimeKey() should return error when server is unreachable")
	}
}

func TestRegisterRuntimeKey_IdentityCreationFails(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/admin/api/auth/status" {
			http.SetCookie(w, &http.Cookie{Name: "sentinel_csrf_token", Value: "test-csrf-token"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer server.Close()

	_, _, err := RegisterRuntimeKey(server.URL, "agent-789")
	if err == nil {
		t.Error("RegisterRuntimeKey() should return error when identity creation fails")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention status code, got: %v", err)
	}
}

func TestRevokeRuntimeKey_Success(t *testing.T) {
	t.Parallel()

	var gotMethod string
	var gotPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/admin/api/auth/status" {
			http.SetCookie(w, &http.Cookie{Name: "sentinel_csrf_token", Value: "test-csrf-token"})
			w.WriteHeader(http.StatusOK)
			return
		}
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := RevokeRuntimeKey(server.URL, "test-identity-id")
	if err != nil {
		t.Fatalf("RevokeRuntimeKey() error = %v", err)
	}

	if gotMethod != "DELETE" {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/admin/api/identities/test-identity-id" {
		t.Errorf("path = %q, want %q", gotPath, "/admin/api/identities/test-identity-id")
	}
}

func TestRevokeRuntimeKey_NotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/admin/api/auth/status" {
			http.SetCookie(w, &http.Cookie{Name: "sentinel_csrf_token", Value: "test-csrf-token"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// NotFound is acceptable (identity already cleaned up).
	err := RevokeRuntimeKey(server.URL, "nonexistent")
	if err != nil {
		t.Errorf("RevokeRuntimeKey() should not error on 404, got: %v", err)
	}
}

func TestRevokeRuntimeKey_ServerError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	err := RevokeRuntimeKey(server.URL, "test-id")
	if err == nil {
		t.Error("RevokeRuntimeKey() should return error on 500")
	}
}
