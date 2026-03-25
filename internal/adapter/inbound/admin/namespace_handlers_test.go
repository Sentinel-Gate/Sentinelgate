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
	"strings"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

type namespaceTestEnv struct {
	handler          *AdminAPIHandler
	namespaceService *service.NamespaceService
	stateStore       *state.FileStateStore
	mux              http.Handler
}

func setupNamespaceTestEnv(t *testing.T) *namespaceTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}
	namespaceSvc := service.NewNamespaceService(logger)
	handler := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	handler.SetNamespaceService(namespaceSvc)
	return &namespaceTestEnv{
		handler:          handler,
		namespaceService: namespaceSvc,
		stateStore:       stateStore,
		mux:              handler.Routes(),
	}
}

// namespaceCSRFToken is a fixed CSRF token used across namespace handler tests.
const namespaceCSRFToken = "test-csrf-token-for-namespace-tests"

func (e *namespaceTestEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
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
	req.RemoteAddr = "127.0.0.1:1234"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete {
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: namespaceCSRFToken})
		req.Header.Set("X-CSRF-Token", namespaceCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeNamespaceJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

// --- GET /admin/api/v1/namespaces/config ---

func TestHandleGetNamespaceConfig(t *testing.T) {
	env := setupNamespaceTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/namespaces/config", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/namespaces/config status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var cfg service.NamespaceConfig
	decodeNamespaceJSON(t, rec, &cfg)
	if cfg.Enabled {
		t.Error("default config Enabled = true, want false")
	}
	if cfg.Rules == nil {
		t.Error("default config Rules = nil, want non-nil map")
	}
}

// --- PUT /admin/api/v1/namespaces/config ---

func TestHandlePutNamespaceConfig_Valid(t *testing.T) {
	env := setupNamespaceTestEnv(t)

	input := service.NamespaceConfig{
		Enabled: true,
		Rules: map[string]*service.NamespaceRule{
			"admin": {VisibleTools: []string{"*"}},
			"user":  {HiddenTools: []string{"dangerous_tool"}},
		},
	}

	rec := env.doRequest(t, "PUT", "/admin/api/v1/namespaces/config", input)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/api/v1/namespaces/config status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var cfg service.NamespaceConfig
	decodeNamespaceJSON(t, rec, &cfg)
	if !cfg.Enabled {
		t.Error("response Enabled = false, want true")
	}
	if len(cfg.Rules) != 2 {
		t.Errorf("response Rules count = %d, want 2", len(cfg.Rules))
	}

	// Verify persisted by re-reading.
	getRec := env.doRequest(t, "GET", "/admin/api/v1/namespaces/config", nil)
	var persisted service.NamespaceConfig
	decodeNamespaceJSON(t, getRec, &persisted)
	if !persisted.Enabled {
		t.Error("persisted Enabled = false, want true")
	}
	if len(persisted.Rules) != 2 {
		t.Errorf("persisted Rules count = %d, want 2", len(persisted.Rules))
	}
}

func TestHandlePutNamespaceConfig_BothVisibleAndHidden(t *testing.T) {
	env := setupNamespaceTestEnv(t)

	input := service.NamespaceConfig{
		Enabled: true,
		Rules: map[string]*service.NamespaceRule{
			"conflicting": {
				VisibleTools: []string{"tool_a"},
				HiddenTools:  []string{"tool_b"},
			},
		},
	}

	rec := env.doRequest(t, "PUT", "/admin/api/v1/namespaces/config", input)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT both visible+hidden status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	var errResp map[string]string
	decodeNamespaceJSON(t, rec, &errResp)
	if !strings.Contains(errResp["error"], "conflicting") {
		t.Errorf("error message = %q, want mention of role name 'conflicting'", errResp["error"])
	}
}

// --- Nil service ---

func TestHandleGetNamespaceConfig_NilService(t *testing.T) {
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
	// Do NOT call SetNamespaceService — leave nil.
	mux := handler.Routes()

	req := httptest.NewRequest("GET", "/admin/api/v1/namespaces/config", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET nil service status = %d, want %d (body=%s)", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}

func TestHandlePutNamespaceConfig_NilService(t *testing.T) {
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
	mux := handler.Routes()

	body, _ := json.Marshal(service.NamespaceConfig{Enabled: true})
	req := httptest.NewRequest("PUT", "/admin/api/v1/namespaces/config", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: namespaceCSRFToken})
	req.Header.Set("X-CSRF-Token", namespaceCSRFToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("PUT nil service status = %d, want %d (body=%s)", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}
}
