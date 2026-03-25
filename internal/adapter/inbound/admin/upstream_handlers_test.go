package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

type upstreamTestEnv struct {
	handler         *AdminAPIHandler
	upstreamService *service.UpstreamService
	upstreamManager *service.UpstreamManager
	toolCache       *upstream.ToolCache
	stateStore      *state.FileStateStore
	mux             http.Handler
}

func noopClientFactory() service.ClientFactory {
	return func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return nil, fmt.Errorf("noop: connections disabled in tests")
	}
}

func setupUpstreamTestEnv(t *testing.T) *upstreamTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}
	memStore := memory.NewUpstreamStore()
	upstreamSvc := service.NewUpstreamService(memStore, stateStore, logger)
	manager := service.NewUpstreamManager(upstreamSvc, noopClientFactory(), logger)
	toolCache := upstream.NewToolCache()
	t.Cleanup(func() { _ = manager.Close() })
	handler := NewAdminAPIHandler(
		WithUpstreamService(upstreamSvc),
		WithUpstreamManager(manager),
		WithToolCache(toolCache),
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	return &upstreamTestEnv{
		handler:         handler,
		upstreamService: upstreamSvc,
		upstreamManager: manager,
		toolCache:       toolCache,
		stateStore:      stateStore,
		mux:             handler.Routes(),
	}
}

// testCSRFToken is a fixed CSRF token shared across test files in the admin package.
const testCSRFToken = "test-csrf-token-for-unit-tests-0000"

// upstreamCSRFToken is a fixed CSRF token used across upstream handler tests.
const upstreamCSRFToken = "test-csrf-token-for-upstream-tests"

func (e *upstreamTestEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
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
	// Include CSRF token on state-changing requests.
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete {
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: upstreamCSRFToken})
		req.Header.Set("X-CSRF-Token", upstreamCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeUpstreamJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

func (e *upstreamTestEnv) addTestUpstream(t *testing.T, name string) *upstream.Upstream {
	t.Helper()
	u := &upstream.Upstream{
		Name:    name,
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
		Args:    []string{"hello"},
	}
	created, err := e.upstreamService.Add(context.Background(), u)
	if err != nil {
		t.Fatalf("add upstream %q: %v", name, err)
	}
	return created
}

// --- List Upstreams ---

func TestHandleListUpstreams_Empty(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/upstreams", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/upstreams status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result []upstreamResponse
	decodeUpstreamJSON(t, rec, &result)
	if len(result) != 0 {
		t.Errorf("response count = %d, want 0", len(result))
	}
}

func TestHandleListUpstreams_WithData(t *testing.T) {
	env := setupUpstreamTestEnv(t)
	env.addTestUpstream(t, "server-a")
	env.addTestUpstream(t, "server-b")

	rec := env.doRequest(t, "GET", "/admin/api/upstreams", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/upstreams status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result []upstreamResponse
	decodeUpstreamJSON(t, rec, &result)
	if len(result) != 2 {
		t.Fatalf("response count = %d, want 2", len(result))
	}
	for _, u := range result {
		if u.ID == "" {
			t.Error("empty ID")
		}
		if u.Status == "" {
			t.Error("empty Status")
		}
		if u.CreatedAt == "" {
			t.Error("empty CreatedAt")
		}
	}
}

func TestHandleListUpstreams_WithToolCount(t *testing.T) {
	env := setupUpstreamTestEnv(t)
	u := env.addTestUpstream(t, "server-with-tools")
	env.toolCache.SetToolsForUpstream(u.ID, []*upstream.DiscoveredTool{
		{Name: "read_file", UpstreamID: u.ID},
		{Name: "write_file", UpstreamID: u.ID},
	})

	rec := env.doRequest(t, "GET", "/admin/api/upstreams", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result []upstreamResponse
	decodeUpstreamJSON(t, rec, &result)
	if len(result) != 1 {
		t.Fatalf("response count = %d, want 1", len(result))
	}
	if result[0].ToolCount != 2 {
		t.Errorf("ToolCount = %d, want 2", result[0].ToolCount)
	}
}

// --- Create Upstream ---

func TestHandleCreateUpstream_Stdio(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/upstreams", upstreamRequest{
		Name:    "test-stdio",
		Type:    "stdio",
		Command: "/usr/bin/echo",
		Args:    []string{"hello"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/api/upstreams status = %d, want %d (body=%s)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var result upstreamResponse
	decodeUpstreamJSON(t, rec, &result)
	if result.ID == "" {
		t.Error("response missing ID")
	}
	if result.Name != "test-stdio" {
		t.Errorf("response Name = %q, want %q", result.Name, "test-stdio")
	}
	if result.Type != "stdio" {
		t.Errorf("response Type = %q, want %q", result.Type, "stdio")
	}
	if !result.Enabled {
		t.Error("want Enabled=true by default")
	}
	if result.CreatedAt == "" {
		t.Error("response missing CreatedAt")
	}
}

func TestHandleCreateUpstream_HTTP(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/upstreams", upstreamRequest{
		Name: "test-http",
		Type: "http",
		URL:  "https://example.com/mcp",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/api/upstreams status = %d, want %d (body=%s)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var result upstreamResponse
	decodeUpstreamJSON(t, rec, &result)
	if result.Type != "http" {
		t.Errorf("response Type = %q, want %q", result.Type, "http")
	}
}

func TestHandleCreateUpstream_MissingName(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/upstreams", upstreamRequest{
		Name:    "",
		Type:    "stdio",
		Command: "/usr/bin/echo",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST missing name status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleCreateUpstream_InvalidType(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/upstreams", upstreamRequest{
		Name:    "bad-type",
		Type:    "grpc",
		Command: "/usr/bin/echo",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST invalid type status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleCreateUpstream_PathTraversal(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/upstreams", upstreamRequest{
		Name:    "traversal",
		Type:    "stdio",
		Command: "../../etc/passwd",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST path traversal status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleCreateUpstream_PathTraversalInArgs(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/upstreams", upstreamRequest{
		Name:    "trav-args",
		Type:    "stdio",
		Command: "/usr/bin/echo",
		Args:    []string{"../../secret"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST path traversal in args status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleCreateUpstream_DangerousEnv(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/upstreams", upstreamRequest{
		Name:    "dangerous-env",
		Type:    "stdio",
		Command: "/usr/bin/echo",
		Env:     map[string]string{"LD_PRELOAD": "/tmp/evil.so"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST dangerous env status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleCreateUpstream_DuplicateName(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	body := upstreamRequest{Name: "dup", Type: "stdio", Command: "/usr/bin/echo"}
	rec := env.doRequest(t, "POST", "/admin/api/upstreams", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, want %d", rec.Code, http.StatusCreated)
	}

	rec = env.doRequest(t, "POST", "/admin/api/upstreams", body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST duplicate name status = %d, want %d (body=%s)", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

func TestHandleCreateUpstream_Disabled(t *testing.T) {
	env := setupUpstreamTestEnv(t)
	enabled := false
	rec := env.doRequest(t, "POST", "/admin/api/upstreams", upstreamRequest{
		Name:    "off",
		Type:    "stdio",
		Command: "/usr/bin/echo",
		Enabled: &enabled,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST disabled status = %d, want %d (body=%s)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var result upstreamResponse
	decodeUpstreamJSON(t, rec, &result)
	if result.Enabled {
		t.Error("want Enabled=false")
	}
}

func TestHandleCreateUpstream_InvalidJSON(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	req := httptest.NewRequest("POST", "/admin/api/upstreams", bytes.NewReader([]byte("not json")))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: upstreamCSRFToken})
	req.Header.Set("X-CSRF-Token", upstreamCSRFToken)
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST invalid JSON status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// --- Update Upstream ---

func TestHandleUpdateUpstream(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	created := env.addTestUpstream(t, "original")

	rec := env.doRequest(t, "PUT", "/admin/api/upstreams/"+created.ID, upstreamRequest{
		Name:    "updated",
		Command: "/usr/bin/cat",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/api/upstreams/{id} status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result upstreamResponse
	decodeUpstreamJSON(t, rec, &result)
	if result.Name != "updated" {
		t.Errorf("response Name = %q, want %q", result.Name, "updated")
	}
	// Type is immutable.
	if result.Type != "stdio" {
		t.Errorf("response Type = %q, want immutable %q", result.Type, "stdio")
	}
}

func TestHandleUpdateUpstream_NotFound(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	rec := env.doRequest(t, "PUT", "/admin/api/upstreams/nonexistent", upstreamRequest{
		Name: "ghost",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("PUT nonexistent status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleUpdateUpstream_DuplicateName(t *testing.T) {
	env := setupUpstreamTestEnv(t)
	env.addTestUpstream(t, "a")
	b := env.addTestUpstream(t, "b")

	rec := env.doRequest(t, "PUT", "/admin/api/upstreams/"+b.ID, upstreamRequest{
		Name: "a",
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("PUT duplicate name status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestHandleUpdateUpstream_PathTraversalInCommand(t *testing.T) {
	env := setupUpstreamTestEnv(t)
	created := env.addTestUpstream(t, "update-trav")

	rec := env.doRequest(t, "PUT", "/admin/api/upstreams/"+created.ID, upstreamRequest{
		Name:    "update-trav",
		Command: "/opt/../../../etc/shadow",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT path traversal status = %d, want %d (body=%s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// --- Delete Upstream ---

func TestHandleDeleteUpstream(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	// Create first.
	created := env.addTestUpstream(t, "to-delete")

	// Delete.
	rec := env.doRequest(t, "DELETE", "/admin/api/upstreams/"+created.ID, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /admin/api/upstreams/{id} status = %d, want %d (body=%s)", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Verify gone.
	listRec := env.doRequest(t, "GET", "/admin/api/upstreams", nil)
	var list []upstreamResponse
	decodeUpstreamJSON(t, listRec, &list)
	if len(list) != 0 {
		t.Errorf("GET after delete count = %d, want 0", len(list))
	}
}

func TestHandleDeleteUpstream_NotFound(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	// Deleting a nonexistent upstream returns 204 for idempotency.
	rec := env.doRequest(t, "DELETE", "/admin/api/upstreams/nonexistent-id", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE nonexistent status = %d, want %d (idempotent)", rec.Code, http.StatusNoContent)
	}
}

func TestHandleDeleteUpstream_ClearsCache(t *testing.T) {
	env := setupUpstreamTestEnv(t)
	c := env.addTestUpstream(t, "cached")
	env.toolCache.SetToolsForUpstream(c.ID, []*upstream.DiscoveredTool{
		{Name: "t", UpstreamID: c.ID},
	})
	if env.toolCache.Count() != 1 {
		t.Fatalf("want 1 tool, got %d", env.toolCache.Count())
	}

	rec := env.doRequest(t, "DELETE", "/admin/api/upstreams/"+c.ID, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if env.toolCache.Count() != 0 {
		t.Errorf("want 0 tools after delete, got %d", env.toolCache.Count())
	}
}

// --- Restart Upstream ---

func TestHandleRestartUpstream_Existing(t *testing.T) {
	env := setupUpstreamTestEnv(t)
	c := env.addTestUpstream(t, "restart-me")

	rec := env.doRequest(t, "POST", "/admin/api/upstreams/"+c.ID+"/restart", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST restart status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result map[string]string
	decodeUpstreamJSON(t, rec, &result)
	if result["message"] != "upstream restarted" {
		t.Errorf("message = %q, want %q", result["message"], "upstream restarted")
	}
}

func TestHandleRestartUpstream_NotFound(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/upstreams/nonexistent-id/restart", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST restart nonexistent status = %d, want %d (body=%s)", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// --- Response format ---

func TestUpstreamResponseContentType(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/upstreams", nil)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestUpstreamErrorResponseFormat(t *testing.T) {
	env := setupUpstreamTestEnv(t)

	tests := []struct {
		name, method, path string
		body               interface{}
		want               int
	}{
		{"create no name", http.MethodPost, "/admin/api/upstreams", upstreamRequest{Type: "stdio", Command: "/bin/echo"}, 400},
		{"update 404", http.MethodPut, "/admin/api/upstreams/x", upstreamRequest{Name: "x"}, 404},
		{"restart 404", http.MethodPost, "/admin/api/upstreams/x/restart", nil, 404},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := env.doRequest(t, tt.method, tt.path, tt.body)
			if rec.Code != tt.want {
				t.Fatalf("want %d, got %d: %s", tt.want, rec.Code, rec.Body.String())
			}
			var errResp map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
				t.Fatalf("not JSON: %v", err)
			}
			if errResp["error"] == "" {
				t.Error("missing error field")
			}
		})
	}
}
