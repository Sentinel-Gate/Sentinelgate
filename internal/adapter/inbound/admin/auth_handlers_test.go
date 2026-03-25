package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
)

// authTestEnv provides a complete test environment for auth handler tests.
type authTestEnv struct {
	handler    *AdminAPIHandler
	stateStore *state.FileStateStore
	mux        http.Handler
}

func setupAuthTestEnv(t *testing.T) *authTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}
	handler := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	return &authTestEnv{
		handler:    handler,
		stateStore: stateStore,
		mux:        handler.Routes(),
	}
}

func (e *authTestEnv) doAuthRequest(t *testing.T, method, path string, body interface{}, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

// --- handleAuthStatus Tests ---

func TestHandleAuthStatus_Localhost(t *testing.T) {
	env := setupAuthTestEnv(t)

	rec := env.doAuthRequest(t, http.MethodGet, "/admin/api/auth/status", nil, "127.0.0.1:1234")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/auth/status from localhost status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp authStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.AuthRequired {
		t.Error("auth_required should be false for localhost")
	}
	if resp.PasswordSet {
		t.Error("password_set should always be false in OSS")
	}
	if !resp.Localhost {
		t.Error("localhost should be true for localhost request")
	}
}

func TestHandleAuthStatus_Remote(t *testing.T) {
	env := setupAuthTestEnv(t)

	rec := env.doAuthRequest(t, http.MethodGet, "/admin/api/auth/status", nil, "192.168.1.100:5555")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/auth/status from remote status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp authStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if !resp.AuthRequired {
		t.Error("auth_required should be true for remote")
	}
	if resp.PasswordSet {
		t.Error("password_set should always be false in OSS")
	}
	if resp.Localhost {
		t.Error("localhost should be false for remote request")
	}
}

// --- Removed endpoints return 404 ---

func TestRemovedEndpoints_PasswordReturns404(t *testing.T) {
	env := setupAuthTestEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/auth/password", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)

	// Route not registered, should get 404 or method not found
	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
		t.Errorf("POST /admin/api/auth/password should not succeed (route removed), got %d", rec.Code)
	}
}

func TestRemovedEndpoints_LoginReturns404(t *testing.T) {
	env := setupAuthTestEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/auth/login", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)

	// Route not registered, should get 404 or method not found
	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
		t.Errorf("POST /admin/api/auth/login should not succeed (route removed), got %d", rec.Code)
	}
}
