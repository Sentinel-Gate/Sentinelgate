package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

type identityTestEnv struct {
	handler         *AdminAPIHandler
	identityService *service.IdentityService
	stateStore      *state.FileStateStore
	mux             http.Handler
}

func setupIdentityTestEnv(t *testing.T) *identityTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}
	identitySvc := service.NewIdentityService(stateStore, logger)
	handler := NewAdminAPIHandler(
		WithIdentityService(identitySvc),
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	return &identityTestEnv{
		handler:         handler,
		identityService: identitySvc,
		stateStore:      stateStore,
		mux:             handler.Routes(),
	}
}

// identityCSRFToken is a fixed CSRF token used across identity handler tests.
const identityCSRFToken = "test-csrf-token-for-identity-tests"

func (e *identityTestEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.RemoteAddr = "127.0.0.1:1234" // bypass auth middleware in tests
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Include CSRF token on state-changing requests.
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete {
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: identityCSRFToken})
		req.Header.Set("X-CSRF-Token", identityCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeIdentityJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

// --- List Identities ---

func TestHandleListIdentities_Empty(t *testing.T) {
	env := setupIdentityTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/identities", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/identities status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result []identityResponse
	decodeIdentityJSON(t, rec, &result)
	if len(result) != 0 {
		t.Errorf("response count = %d, want 0", len(result))
	}
}

func TestHandleListIdentities_WithData(t *testing.T) {
	env := setupIdentityTestEnv(t)

	// Create 2 identities.
	env.doRequest(t, "POST", "/admin/api/identities", identityRequest{
		Name:  "user-1",
		Roles: []string{"admin"},
	})
	env.doRequest(t, "POST", "/admin/api/identities", identityRequest{
		Name:  "user-2",
		Roles: []string{"user"},
	})

	rec := env.doRequest(t, "GET", "/admin/api/identities", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/identities status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result []identityResponse
	decodeIdentityJSON(t, rec, &result)
	if len(result) != 2 {
		t.Errorf("response count = %d, want 2", len(result))
	}
}

// --- Create Identity ---

func TestHandleCreateIdentity(t *testing.T) {
	env := setupIdentityTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/identities", identityRequest{
		Name:  "new-user",
		Roles: []string{"admin", "user"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/api/identities status = %d, want %d (body=%s)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var result identityResponse
	decodeIdentityJSON(t, rec, &result)
	if result.ID == "" {
		t.Error("response missing ID")
	}
	if result.Name != "new-user" {
		t.Errorf("response Name = %q, want %q", result.Name, "new-user")
	}
	if len(result.Roles) != 2 {
		t.Errorf("response Roles count = %d, want 2", len(result.Roles))
	}
	if result.CreatedAt == "" {
		t.Error("response missing CreatedAt")
	}
}

func TestHandleCreateIdentity_EmptyName(t *testing.T) {
	env := setupIdentityTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/identities", identityRequest{
		Name: "",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /admin/api/identities empty name status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHandleCreateIdentity_DuplicateName(t *testing.T) {
	env := setupIdentityTestEnv(t)

	env.doRequest(t, "POST", "/admin/api/identities", identityRequest{
		Name: "dup-user",
	})

	rec := env.doRequest(t, "POST", "/admin/api/identities", identityRequest{
		Name: "dup-user",
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST /admin/api/identities duplicate status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestHandleCreateIdentity_InvalidJSON(t *testing.T) {
	env := setupIdentityTestEnv(t)

	req := httptest.NewRequest("POST", "/admin/api/identities", bytes.NewReader([]byte("not json")))
	req.RemoteAddr = "127.0.0.1:1234" // bypass auth middleware in tests
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: identityCSRFToken})
	req.Header.Set("X-CSRF-Token", identityCSRFToken)
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST invalid JSON status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// --- Update Identity ---

func TestHandleUpdateIdentity(t *testing.T) {
	env := setupIdentityTestEnv(t)

	// Create first.
	createRec := env.doRequest(t, "POST", "/admin/api/identities", identityRequest{
		Name:  "original",
		Roles: []string{"user"},
	})
	var created identityResponse
	decodeIdentityJSON(t, createRec, &created)

	// Update.
	rec := env.doRequest(t, "PUT", "/admin/api/identities/"+created.ID, identityRequest{
		Name:  "updated",
		Roles: []string{"admin", "user"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/api/identities/{id} status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result identityResponse
	decodeIdentityJSON(t, rec, &result)
	if result.Name != "updated" {
		t.Errorf("response Name = %q, want %q", result.Name, "updated")
	}
	if len(result.Roles) != 2 {
		t.Errorf("response Roles count = %d, want 2", len(result.Roles))
	}
}

func TestHandleUpdateIdentity_NotFound(t *testing.T) {
	env := setupIdentityTestEnv(t)

	rec := env.doRequest(t, "PUT", "/admin/api/identities/nonexistent", identityRequest{
		Name: "ghost",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("PUT nonexistent status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// --- Delete Identity ---

func TestHandleDeleteIdentity(t *testing.T) {
	env := setupIdentityTestEnv(t)

	// Create.
	createRec := env.doRequest(t, "POST", "/admin/api/identities", identityRequest{
		Name: "to-delete",
	})
	var created identityResponse
	decodeIdentityJSON(t, createRec, &created)

	// Delete.
	rec := env.doRequest(t, "DELETE", "/admin/api/identities/"+created.ID, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /admin/api/identities/{id} status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// Verify gone.
	getRec := env.doRequest(t, "GET", "/admin/api/identities", nil)
	var list []identityResponse
	decodeIdentityJSON(t, getRec, &list)
	if len(list) != 0 {
		t.Errorf("GET after delete count = %d, want 0", len(list))
	}
}

func TestHandleDeleteIdentity_NotFound(t *testing.T) {
	env := setupIdentityTestEnv(t)

	rec := env.doRequest(t, "DELETE", "/admin/api/identities/nonexistent", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("DELETE nonexistent status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
