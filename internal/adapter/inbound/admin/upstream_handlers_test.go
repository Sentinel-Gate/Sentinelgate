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

type testEnv struct {
	handler   *AdminAPIHandler
	svc       *service.UpstreamService
	manager   *service.UpstreamManager
	toolCache *upstream.ToolCache
	mux       http.Handler
}

func noopClientFactory() service.ClientFactory {
	return func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return nil, fmt.Errorf("noop: connections disabled in tests")
	}
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}
	memStore := memory.NewUpstreamStore()
	svc := service.NewUpstreamService(memStore, stateStore, logger)
	manager := service.NewUpstreamManager(svc, noopClientFactory(), logger)
	toolCache := upstream.NewToolCache()
	t.Cleanup(func() { _ = manager.Close() })
	handler := NewAdminAPIHandler(
		WithUpstreamService(svc),
		WithUpstreamManager(manager),
		WithToolCache(toolCache),
		WithAPILogger(logger),
	)
	return &testEnv{handler: handler, svc: svc, manager: manager, toolCache: toolCache, mux: handler.Routes()}
}

// testCSRFToken is a fixed CSRF token used across all unit tests.
const testCSRFToken = "test-csrf-token-for-unit-tests-0000"

func (e *testEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
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
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: testCSRFToken})
		req.Header.Set("X-CSRF-Token", testCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

func (e *testEnv) addTestUpstream(t *testing.T, name string) *upstream.Upstream {
	t.Helper()
	u := &upstream.Upstream{Name: name, Type: upstream.UpstreamTypeStdio, Enabled: true, Command: "/usr/bin/echo", Args: []string{"hello"}}
	created, err := e.svc.Add(context.Background(), u)
	if err != nil {
		t.Fatalf("add upstream %q: %v", name, err)
	}
	return created
}

func TestHandleListUpstreams_EmptyList(t *testing.T) {
	env := setupTestEnv(t)
	rec := env.doRequest(t, http.MethodGet, "/admin/api/upstreams", nil)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var result []upstreamResponse
	decodeJSON(t, rec, &result)
	if result == nil {
		t.Fatal("want [], got null")
	}
	if len(result) != 0 {
		t.Fatalf("want 0, got %d", len(result))
	}
}

func TestHandleListUpstreams_WithUpstreams(t *testing.T) {
	env := setupTestEnv(t)
	env.addTestUpstream(t, "server-a")
	env.addTestUpstream(t, "server-b")
	rec := env.doRequest(t, http.MethodGet, "/admin/api/upstreams", nil)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var result []upstreamResponse
	decodeJSON(t, rec, &result)
	if len(result) != 2 {
		t.Fatalf("want 2, got %d", len(result))
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
	env := setupTestEnv(t)
	u := env.addTestUpstream(t, "server-with-tools")
	env.toolCache.SetToolsForUpstream(u.ID, []*upstream.DiscoveredTool{
		{Name: "read_file", UpstreamID: u.ID},
		{Name: "write_file", UpstreamID: u.ID},
	})
	rec := env.doRequest(t, http.MethodGet, "/admin/api/upstreams", nil)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var result []upstreamResponse
	decodeJSON(t, rec, &result)
	if len(result) != 1 {
		t.Fatalf("want 1, got %d", len(result))
	}
	if result[0].ToolCount != 2 {
		t.Errorf("want tool_count=2, got %d", result[0].ToolCount)
	}
}

func TestHandleCreateUpstream_ValidStdio(t *testing.T) {
	env := setupTestEnv(t)
	body := map[string]interface{}{"name": "my-mcp", "type": "stdio", "command": "/usr/bin/npx", "args": []string{"server"}}
	rec := env.doRequest(t, http.MethodPost, "/admin/api/upstreams", body)
	if rec.Code != 201 {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var result upstreamResponse
	decodeJSON(t, rec, &result)
	if result.ID == "" {
		t.Error("empty ID")
	}
	if result.Name != "my-mcp" {
		t.Errorf("want 'my-mcp', got %q", result.Name)
	}
	if result.Type != "stdio" {
		t.Errorf("want 'stdio', got %q", result.Type)
	}
	if !result.Enabled {
		t.Error("want enabled=true by default")
	}
}

func TestHandleCreateUpstream_ValidHTTP(t *testing.T) {
	env := setupTestEnv(t)
	body := map[string]interface{}{"name": "http-srv", "type": "http", "url": "http://localhost:9090/mcp"}
	rec := env.doRequest(t, http.MethodPost, "/admin/api/upstreams", body)
	if rec.Code != 201 {
		t.Fatalf("want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var result upstreamResponse
	decodeJSON(t, rec, &result)
	if result.Type != "http" {
		t.Errorf("want 'http', got %q", result.Type)
	}
}

func TestHandleCreateUpstream_MissingName(t *testing.T) {
	env := setupTestEnv(t)
	body := map[string]interface{}{"type": "stdio", "command": "/usr/bin/echo"}
	rec := env.doRequest(t, http.MethodPost, "/admin/api/upstreams", body)
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCreateUpstream_DuplicateName(t *testing.T) {
	env := setupTestEnv(t)
	body := map[string]interface{}{"name": "dup", "type": "stdio", "command": "/usr/bin/echo"}
	rec := env.doRequest(t, http.MethodPost, "/admin/api/upstreams", body)
	if rec.Code != 201 {
		t.Fatalf("first: want 201, got %d", rec.Code)
	}
	rec = env.doRequest(t, http.MethodPost, "/admin/api/upstreams", body)
	if rec.Code != 409 {
		t.Fatalf("want 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleCreateUpstream_InvalidType(t *testing.T) {
	env := setupTestEnv(t)
	body := map[string]interface{}{"name": "bad", "type": "websocket"}
	rec := env.doRequest(t, http.MethodPost, "/admin/api/upstreams", body)
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestHandleCreateUpstream_MissingCommand(t *testing.T) {
	env := setupTestEnv(t)
	body := map[string]interface{}{"name": "no-cmd", "type": "stdio"}
	rec := env.doRequest(t, http.MethodPost, "/admin/api/upstreams", body)
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestHandleCreateUpstream_InvalidJSON(t *testing.T) {
	env := setupTestEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/admin/api/upstreams", bytes.NewBufferString("not json"))
	req.RemoteAddr = "127.0.0.1:1234" // bypass auth middleware in tests
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: testCSRFToken})
	req.Header.Set("X-CSRF-Token", testCSRFToken)
	rec := httptest.NewRecorder()
	env.mux.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestHandleCreateUpstream_Disabled(t *testing.T) {
	env := setupTestEnv(t)
	body := map[string]interface{}{"name": "off", "type": "stdio", "command": "/usr/bin/echo", "enabled": false}
	rec := env.doRequest(t, http.MethodPost, "/admin/api/upstreams", body)
	if rec.Code != 201 {
		t.Fatalf("want 201, got %d", rec.Code)
	}
	var result upstreamResponse
	decodeJSON(t, rec, &result)
	if result.Enabled {
		t.Error("want enabled=false")
	}
}

func TestHandleUpdateUpstream_Valid(t *testing.T) {
	env := setupTestEnv(t)
	created := env.addTestUpstream(t, "orig")
	body := map[string]interface{}{"name": "updated", "command": "/usr/bin/cat"}
	rec := env.doRequest(t, http.MethodPut, "/admin/api/upstreams/"+created.ID, body)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var result upstreamResponse
	decodeJSON(t, rec, &result)
	if result.Name != "updated" {
		t.Errorf("want 'updated', got %q", result.Name)
	}
	if result.Type != "stdio" {
		t.Errorf("want immutable 'stdio', got %q", result.Type)
	}
}

func TestHandleUpdateUpstream_NotFound(t *testing.T) {
	env := setupTestEnv(t)
	body := map[string]interface{}{"name": "x"}
	rec := env.doRequest(t, http.MethodPut, "/admin/api/upstreams/nope", body)
	if rec.Code != 404 {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestHandleUpdateUpstream_DuplicateName(t *testing.T) {
	env := setupTestEnv(t)
	env.addTestUpstream(t, "a")
	b := env.addTestUpstream(t, "b")
	body := map[string]interface{}{"name": "a"}
	rec := env.doRequest(t, http.MethodPut, "/admin/api/upstreams/"+b.ID, body)
	if rec.Code != 409 {
		t.Fatalf("want 409, got %d", rec.Code)
	}
}

func TestHandleUpdateUpstream_KeepOwnName(t *testing.T) {
	env := setupTestEnv(t)
	c := env.addTestUpstream(t, "keep")
	body := map[string]interface{}{"name": "keep", "command": "/usr/bin/cat"}
	rec := env.doRequest(t, http.MethodPut, "/admin/api/upstreams/"+c.ID, body)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestHandleDeleteUpstream_Existing(t *testing.T) {
	env := setupTestEnv(t)
	c := env.addTestUpstream(t, "del")
	rec := env.doRequest(t, http.MethodDelete, "/admin/api/upstreams/"+c.ID, nil)
	if rec.Code != 204 {
		t.Fatalf("want 204, got %d", rec.Code)
	}
	rec = env.doRequest(t, http.MethodGet, "/admin/api/upstreams", nil)
	var result []upstreamResponse
	decodeJSON(t, rec, &result)
	if len(result) != 0 {
		t.Fatalf("want 0 after delete, got %d", len(result))
	}
}

func TestHandleDeleteUpstream_NotFound(t *testing.T) {
	env := setupTestEnv(t)
	rec := env.doRequest(t, http.MethodDelete, "/admin/api/upstreams/nope", nil)
	if rec.Code != 404 {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestHandleDeleteUpstream_ClearsCache(t *testing.T) {
	env := setupTestEnv(t)
	c := env.addTestUpstream(t, "cached")
	env.toolCache.SetToolsForUpstream(c.ID, []*upstream.DiscoveredTool{{Name: "t", UpstreamID: c.ID}})
	if env.toolCache.Count() != 1 {
		t.Fatalf("want 1 tool, got %d", env.toolCache.Count())
	}
	rec := env.doRequest(t, http.MethodDelete, "/admin/api/upstreams/"+c.ID, nil)
	if rec.Code != 204 {
		t.Fatalf("want 204, got %d", rec.Code)
	}
	if env.toolCache.Count() != 0 {
		t.Errorf("want 0 tools, got %d", env.toolCache.Count())
	}
}

func TestHandleRestartUpstream_Existing(t *testing.T) {
	env := setupTestEnv(t)
	c := env.addTestUpstream(t, "restart-me")
	rec := env.doRequest(t, http.MethodPost, "/admin/api/upstreams/"+c.ID+"/restart", nil)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	decodeJSON(t, rec, &result)
	if result["status"] == "" {
		t.Error("empty status")
	}
	if result["message"] != "upstream restarted" {
		t.Errorf("want 'upstream restarted', got %q", result["message"])
	}
}

func TestHandleRestartUpstream_NotFound(t *testing.T) {
	env := setupTestEnv(t)
	rec := env.doRequest(t, http.MethodPost, "/admin/api/upstreams/nope/restart", nil)
	if rec.Code != 404 {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestErrorResponseFormat(t *testing.T) {
	env := setupTestEnv(t)
	tests := []struct {
		name, method, path string
		body               interface{}
		want               int
	}{
		{"create no name", http.MethodPost, "/admin/api/upstreams", map[string]interface{}{"type": "stdio", "command": "/bin/echo"}, 400},
		{"update 404", http.MethodPut, "/admin/api/upstreams/x", map[string]interface{}{"name": "x"}, 404},
		{"delete 404", http.MethodDelete, "/admin/api/upstreams/x", nil, 404},
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

// ---------------------------------------------------------------------------
// SECU-08: Path traversal tests
// ---------------------------------------------------------------------------

func TestHandleCreateUpstream_PathTraversalInCommand(t *testing.T) {
	env := setupTestEnv(t)
	body := map[string]interface{}{"name": "evil", "type": "stdio", "command": "/usr/bin/../../../etc/passwd"}
	rec := env.doRequest(t, http.MethodPost, "/admin/api/upstreams", body)
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var errResp map[string]string
	decodeJSON(t, rec, &errResp)
	if errResp["error"] != "path traversal detected in command" {
		t.Errorf("unexpected error: %q", errResp["error"])
	}
}

func TestHandleCreateUpstream_PathTraversalInArgs(t *testing.T) {
	env := setupTestEnv(t)
	body := map[string]interface{}{"name": "evil2", "type": "stdio", "command": "/usr/bin/echo", "args": []string{"../../secret"}}
	rec := env.doRequest(t, http.MethodPost, "/admin/api/upstreams", body)
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var errResp map[string]string
	decodeJSON(t, rec, &errResp)
	if errResp["error"] != "path traversal detected in arguments" {
		t.Errorf("unexpected error: %q", errResp["error"])
	}
}

func TestHandleUpdateUpstream_PathTraversalInCommand(t *testing.T) {
	env := setupTestEnv(t)
	created := env.addTestUpstream(t, "update-trav")
	body := map[string]interface{}{"name": "update-trav", "command": "/opt/../../../etc/shadow"}
	rec := env.doRequest(t, http.MethodPut, "/admin/api/upstreams/"+created.ID, body)
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var errResp map[string]string
	decodeJSON(t, rec, &errResp)
	if errResp["error"] != "path traversal detected in command" {
		t.Errorf("unexpected error: %q", errResp["error"])
	}
}

func TestHandleUpdateUpstream_PathTraversalInArgs(t *testing.T) {
	env := setupTestEnv(t)
	created := env.addTestUpstream(t, "update-trav2")
	body := map[string]interface{}{"name": "update-trav2", "args": []string{"--config", "../../etc/passwd"}}
	rec := env.doRequest(t, http.MethodPut, "/admin/api/upstreams/"+created.ID, body)
	if rec.Code != 400 {
		t.Fatalf("want 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var errResp map[string]string
	decodeJSON(t, rec, &errResp)
	if errResp["error"] != "path traversal detected in arguments" {
		t.Errorf("unexpected error: %q", errResp["error"])
	}
}

func TestResponseContentType(t *testing.T) {
	env := setupTestEnv(t)
	rec := env.doRequest(t, http.MethodGet, "/admin/api/upstreams", nil)
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("want application/json, got %q", ct)
	}
}
