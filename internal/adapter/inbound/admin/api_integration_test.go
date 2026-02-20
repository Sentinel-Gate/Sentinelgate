package admin_test

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
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/admin"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// testEnv holds all the real services wired up for integration testing.
type testEnv struct {
	handler            *admin.AdminAPIHandler
	server             *httptest.Server
	stateStore         *state.FileStateStore
	upstreamService    *service.UpstreamService
	upstreamManager    *service.UpstreamManager
	policyService      *service.PolicyService
	policyAdminService *service.PolicyAdminService
	identityService    *service.IdentityService
	statsService       *service.StatsService
	policyStore        *memory.MemoryPolicyStore
	toolCache          *upstream.ToolCache
	auditReader        *mockIntegrationAuditReader
}

// mockIntegrationAuditReader implements admin.AuditReader for integration tests.
type mockIntegrationAuditReader struct {
	records []audit.AuditRecord
}

func (m *mockIntegrationAuditReader) GetRecent(n int) []audit.AuditRecord {
	if n > len(m.records) {
		n = len(m.records)
	}
	return m.records[:n]
}

func (m *mockIntegrationAuditReader) Query(filter audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	var result []audit.AuditRecord
	for _, rec := range m.records {
		if filter.Decision != "" && rec.Decision != filter.Decision {
			continue
		}
		result = append(result, rec)
	}
	if filter.Limit > 0 && len(result) > filter.Limit {
		result = result[:filter.Limit]
	}
	if result == nil {
		result = []audit.AuditRecord{}
	}
	return result, "", nil
}

// setupTestEnv creates a full integration test environment with real services.
func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	// Create temp directory for state.json
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create state store
	stateStore := state.NewFileStateStore(statePath, logger)

	// Initialize state file
	appState := stateStore.DefaultState()
	if err := stateStore.Save(appState); err != nil {
		t.Fatalf("save initial state: %v", err)
	}

	// Create in-memory stores
	policyStore := memory.NewPolicyStore()
	upstreamStore := memory.NewUpstreamStore()

	// Create services
	upstreamService := service.NewUpstreamService(upstreamStore, stateStore, logger)

	// Client factory that always returns an error (no real MCP connections needed in tests).
	failFactory := service.ClientFactory(func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return nil, fmt.Errorf("test: no real upstream connections")
	})

	// Create upstream manager with the failing factory.
	manager := service.NewUpstreamManager(upstreamService, failFactory, logger)
	t.Cleanup(func() { _ = manager.Close() })

	// Tool cache
	toolCache := upstream.NewToolCache()

	// Discovery service (with the same failing factory).
	discoveryService := service.NewToolDiscoveryService(upstreamService, toolCache, failFactory, logger)
	t.Cleanup(func() { discoveryService.Stop() })

	// Policy service
	policyService, err := service.NewPolicyService(context.Background(), policyStore, logger)
	if err != nil {
		t.Fatalf("create policy service: %v", err)
	}

	// Audit store + service (in-memory, write to discard)
	auditStore := memory.NewAuditStoreWithWriter(io.Discard)
	auditService := service.NewAuditService(auditStore, logger)
	auditService.Start(context.Background())
	t.Cleanup(func() { auditService.Stop() })

	// Admin services
	policyAdminService := service.NewPolicyAdminService(policyStore, stateStore, policyService, logger)
	identityService := service.NewIdentityService(stateStore, logger)
	statsService := service.NewStatsService()

	// Audit reader (mock for integration tests)
	auditReader := &mockIntegrationAuditReader{}

	// Create handler
	handler := admin.NewAdminAPIHandler(
		admin.WithUpstreamService(upstreamService),
		admin.WithUpstreamManager(manager),
		admin.WithDiscoveryService(discoveryService),
		admin.WithToolCache(toolCache),
		admin.WithPolicyService(policyService),
		admin.WithPolicyStore(policyStore),
		admin.WithPolicyAdminService(policyAdminService),
		admin.WithIdentityService(identityService),
		admin.WithAuditService(auditService),
		admin.WithAuditReader(auditReader),
		admin.WithStatsService(statsService),
		admin.WithStateStore(stateStore),
		admin.WithAPILogger(logger),
		admin.WithBuildInfo(&admin.BuildInfo{
			Version:   "test-1.0.0",
			Commit:    "abc1234",
			BuildDate: "2026-02-05",
		}),
		admin.WithStartTime(time.Now().UTC()),
	)

	// Create test server using the handler's Routes()
	server := httptest.NewServer(handler.Routes())
	t.Cleanup(func() { server.Close() })

	return &testEnv{
		handler:            handler,
		server:             server,
		stateStore:         stateStore,
		upstreamService:    upstreamService,
		upstreamManager:    manager,
		policyService:      policyService,
		policyAdminService: policyAdminService,
		identityService:    identityService,
		statsService:       statsService,
		policyStore:        policyStore,
		toolCache:          toolCache,
		auditReader:        auditReader,
	}
}

// doJSON performs a JSON request and returns the response.
func (e *testEnv) doJSON(t *testing.T, method, path string, body interface{}) *http.Response {
	t.Helper()
	return e.doJSONWithCookie(t, method, path, body, nil)
}

// integrationCSRFToken is a fixed CSRF token used across integration tests.
const integrationCSRFToken = "test-csrf-token-for-integration-tests"

// doJSONWithCookie performs a JSON request with an optional cookie and returns the response.
func (e *testEnv) doJSONWithCookie(t *testing.T, method, path string, body interface{}, cookies []*http.Cookie) *http.Response {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, e.server.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Include CSRF token on state-changing requests.
	if method == "POST" || method == "PUT" || method == "DELETE" {
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: integrationCSRFToken})
		req.Header.Set("X-CSRF-Token", integrationCSRFToken)
	}

	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// decodeJSON decodes the response body into the target.
func decodeJSON(t *testing.T, resp *http.Response, target interface{}) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// readBody reads and returns the response body as a string.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(data)
}

// --- Integration Tests ---

// TestIntegrationUpstreamLifecycle tests the full upstream CRUD lifecycle:
// create -> list -> update -> list again -> restart -> delete -> list empty.
func TestIntegrationUpstreamLifecycle(t *testing.T) {
	env := setupTestEnv(t)

	// Step 1: Create upstream
	createReq := map[string]interface{}{
		"name":    "test-upstream",
		"type":    "http",
		"url":     "http://localhost:9999/mcp",
		"enabled": true,
	}
	resp := env.doJSON(t, "POST", "/admin/api/upstreams", createReq)
	if resp.StatusCode != http.StatusCreated {
		body := readBody(t, resp)
		t.Fatalf("create upstream: status=%d, body=%s", resp.StatusCode, body)
	}

	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	upstreamID, ok := created["id"].(string)
	if !ok || upstreamID == "" {
		t.Fatalf("created upstream missing ID: %v", created)
	}
	if created["name"] != "test-upstream" {
		t.Errorf("name = %v, want test-upstream", created["name"])
	}

	// Step 2: List upstreams -> should have 1
	resp = env.doJSON(t, "GET", "/admin/api/upstreams", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list upstreams: status=%d", resp.StatusCode)
	}
	var upstreams []map[string]interface{}
	decodeJSON(t, resp, &upstreams)
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(upstreams))
	}

	// Step 3: Update upstream name
	updateReq := map[string]interface{}{
		"name": "renamed-upstream",
		"url":  "http://localhost:9999/mcp",
	}
	resp = env.doJSON(t, "PUT", "/admin/api/upstreams/"+upstreamID, updateReq)
	if resp.StatusCode != http.StatusOK {
		body := readBody(t, resp)
		t.Fatalf("update upstream: status=%d, body=%s", resp.StatusCode, body)
	}

	var updated map[string]interface{}
	decodeJSON(t, resp, &updated)
	if updated["name"] != "renamed-upstream" {
		t.Errorf("updated name = %v, want renamed-upstream", updated["name"])
	}

	// Step 4: Verify name changed via list
	resp = env.doJSON(t, "GET", "/admin/api/upstreams", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list upstreams after update: status=%d", resp.StatusCode)
	}
	decodeJSON(t, resp, &upstreams)
	if len(upstreams) != 1 {
		t.Fatalf("expected 1 upstream after update, got %d", len(upstreams))
	}
	if upstreams[0]["name"] != "renamed-upstream" {
		t.Errorf("listed name = %v, want renamed-upstream", upstreams[0]["name"])
	}

	// Step 5: Restart upstream
	resp = env.doJSON(t, "POST", "/admin/api/upstreams/"+upstreamID+"/restart", nil)
	if resp.StatusCode != http.StatusOK {
		body := readBody(t, resp)
		t.Fatalf("restart upstream: status=%d, body=%s", resp.StatusCode, body)
	}

	// Step 6: Delete upstream
	resp = env.doJSON(t, "DELETE", "/admin/api/upstreams/"+upstreamID, nil)
	if resp.StatusCode != http.StatusNoContent {
		body := readBody(t, resp)
		t.Fatalf("delete upstream: status=%d, body=%s", resp.StatusCode, body)
	}

	// Step 7: List upstreams -> should be empty
	resp = env.doJSON(t, "GET", "/admin/api/upstreams", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list upstreams after delete: status=%d", resp.StatusCode)
	}
	decodeJSON(t, resp, &upstreams)
	if len(upstreams) != 0 {
		t.Errorf("expected 0 upstreams after delete, got %d", len(upstreams))
	}
}

// TestIntegrationPolicyFlow tests the complete policy CRUD and evaluation flow:
// create policy -> list -> test evaluation -> update to deny -> test again -> delete -> protect default.
func TestIntegrationPolicyFlow(t *testing.T) {
	env := setupTestEnv(t)

	// Step 1: Create a policy with an allow rule for tools matching "test_*"
	createReq := map[string]interface{}{
		"name":    "Test Allow Policy",
		"enabled": true,
		"rules": []map[string]interface{}{
			{
				"name":       "allow-test-tools",
				"priority":   100,
				"tool_match": "test_*",
				"condition":  `"admin" in user_roles`,
				"action":     "allow",
			},
		},
	}
	resp := env.doJSON(t, "POST", "/admin/api/policies", createReq)
	if resp.StatusCode != http.StatusCreated {
		body := readBody(t, resp)
		t.Fatalf("create policy: status=%d, body=%s", resp.StatusCode, body)
	}

	var created map[string]interface{}
	decodeJSON(t, resp, &created)
	policyID, ok := created["id"].(string)
	if !ok || policyID == "" {
		t.Fatalf("created policy missing ID: %v", created)
	}

	// Step 2: List policies -> should have the created policy
	resp = env.doJSON(t, "GET", "/admin/api/policies", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list policies: status=%d", resp.StatusCode)
	}
	var policies []map[string]interface{}
	decodeJSON(t, resp, &policies)
	found := false
	for _, p := range policies {
		if p["id"] == policyID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("created policy not found in list: %v", policies)
	}

	// Step 3: Test policy - tool matching "test_read" with admin role -> should be allowed
	testReq := map[string]interface{}{
		"tool_name": "test_read",
		"roles":     []string{"admin"},
	}
	resp = env.doJSON(t, "POST", "/admin/api/policies/test", testReq)
	if resp.StatusCode != http.StatusOK {
		body := readBody(t, resp)
		t.Fatalf("test policy (allow): status=%d, body=%s", resp.StatusCode, body)
	}
	var testResult map[string]interface{}
	decodeJSON(t, resp, &testResult)
	if testResult["decision"] != "allow" {
		t.Errorf("test_read with admin: decision=%v, want allow", testResult["decision"])
	}

	// Step 4: Test policy - tool "other_tool" with user role -> should be allowed (no matching rule -> default allow)
	testReq = map[string]interface{}{
		"tool_name": "other_tool",
		"roles":     []string{"user"},
	}
	resp = env.doJSON(t, "POST", "/admin/api/policies/test", testReq)
	if resp.StatusCode != http.StatusOK {
		body := readBody(t, resp)
		t.Fatalf("test policy (default allow): status=%d, body=%s", resp.StatusCode, body)
	}
	decodeJSON(t, resp, &testResult)
	if testResult["decision"] != "allow" {
		t.Errorf("other_tool with user: decision=%v, want allow", testResult["decision"])
	}

	// Step 5: Update the policy to change the rule action to deny
	updateReq := map[string]interface{}{
		"name":    "Test Deny Policy",
		"enabled": true,
		"rules": []map[string]interface{}{
			{
				"name":       "deny-test-tools",
				"priority":   100,
				"tool_match": "test_*",
				"condition":  `"admin" in user_roles`,
				"action":     "deny",
			},
		},
	}
	resp = env.doJSON(t, "PUT", "/admin/api/policies/"+policyID, updateReq)
	if resp.StatusCode != http.StatusOK {
		body := readBody(t, resp)
		t.Fatalf("update policy: status=%d, body=%s", resp.StatusCode, body)
	}

	// Step 6: Test again with same tool+roles -> should now be denied
	testReq = map[string]interface{}{
		"tool_name": "test_read",
		"roles":     []string{"admin"},
	}
	resp = env.doJSON(t, "POST", "/admin/api/policies/test", testReq)
	if resp.StatusCode != http.StatusOK {
		body := readBody(t, resp)
		t.Fatalf("test policy after update: status=%d, body=%s", resp.StatusCode, body)
	}
	decodeJSON(t, resp, &testResult)
	if testResult["decision"] != "deny" {
		t.Errorf("test_read with admin after deny update: decision=%v, want deny", testResult["decision"])
	}

	// Step 7: Delete the policy
	resp = env.doJSON(t, "DELETE", "/admin/api/policies/"+policyID, nil)
	if resp.StatusCode != http.StatusNoContent {
		body := readBody(t, resp)
		t.Fatalf("delete policy: status=%d, body=%s", resp.StatusCode, body)
	}

	// Step 8: Attempt to delete a default policy -> should fail with 403
	defaultReq := map[string]interface{}{
		"name":    "Default RBAC Policy",
		"enabled": true,
		"rules": []map[string]interface{}{
			{
				"name":       "default-rule",
				"priority":   0,
				"tool_match": "*",
				"condition":  "true",
				"action":     "deny",
			},
		},
	}
	resp = env.doJSON(t, "POST", "/admin/api/policies", defaultReq)
	if resp.StatusCode != http.StatusCreated {
		body := readBody(t, resp)
		t.Fatalf("create default policy: status=%d, body=%s", resp.StatusCode, body)
	}
	var defaultPolicy map[string]interface{}
	decodeJSON(t, resp, &defaultPolicy)
	defaultPolicyID := defaultPolicy["id"].(string)

	resp = env.doJSON(t, "DELETE", "/admin/api/policies/"+defaultPolicyID, nil)
	if resp.StatusCode != http.StatusForbidden {
		body := readBody(t, resp)
		t.Errorf("delete default policy: status=%d (want 403), body=%s", resp.StatusCode, body)
	}
	_ = resp.Body.Close()
}

// TestIntegrationIdentityKeyFlow tests the complete identity and API key lifecycle:
// create identity -> generate key -> verify cleartext returned -> list identities -> revoke key -> delete identity.
func TestIntegrationIdentityKeyFlow(t *testing.T) {
	env := setupTestEnv(t)

	// Step 1: Create identity
	createReq := map[string]interface{}{
		"name":  "test-user",
		"roles": []string{"user", "reader"},
	}
	resp := env.doJSON(t, "POST", "/admin/api/identities", createReq)
	if resp.StatusCode != http.StatusCreated {
		body := readBody(t, resp)
		t.Fatalf("create identity: status=%d, body=%s", resp.StatusCode, body)
	}

	var createdIdentity map[string]interface{}
	decodeJSON(t, resp, &createdIdentity)
	identityID, ok := createdIdentity["id"].(string)
	if !ok || identityID == "" {
		t.Fatalf("created identity missing ID: %v", createdIdentity)
	}

	// Verify roles
	roles, ok := createdIdentity["roles"].([]interface{})
	if !ok || len(roles) != 2 {
		t.Errorf("roles = %v, want [user, reader]", createdIdentity["roles"])
	}

	// Step 2: Generate API key
	keyReq := map[string]interface{}{
		"identity_id": identityID,
		"name":        "test-key",
	}
	resp = env.doJSON(t, "POST", "/admin/api/keys", keyReq)
	if resp.StatusCode != http.StatusCreated {
		body := readBody(t, resp)
		t.Fatalf("generate key: status=%d, body=%s", resp.StatusCode, body)
	}

	var keyResult map[string]interface{}
	decodeJSON(t, resp, &keyResult)

	// Verify cleartext key is returned
	cleartextKey, ok := keyResult["cleartext_key"].(string)
	if !ok || cleartextKey == "" {
		t.Fatalf("cleartext_key missing or empty: %v", keyResult)
	}

	// Verify key format: sg_ prefix + 64 hex chars
	if !strings.HasPrefix(cleartextKey, "sg_") {
		t.Errorf("cleartext_key should start with 'sg_', got: %s", cleartextKey[:10])
	}
	if len(cleartextKey) != 67 { // "sg_" (3) + 64 hex chars
		t.Errorf("cleartext_key length = %d, want 67", len(cleartextKey))
	}

	keyID, ok := keyResult["id"].(string)
	if !ok || keyID == "" {
		t.Fatalf("key missing ID: %v", keyResult)
	}

	// Step 3: List identities -> should contain our identity
	resp = env.doJSON(t, "GET", "/admin/api/identities", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list identities: status=%d", resp.StatusCode)
	}
	var identities []map[string]interface{}
	decodeJSON(t, resp, &identities)
	found := false
	for _, ident := range identities {
		if ident["id"] == identityID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("created identity not in list")
	}

	// Step 4: Revoke the API key
	resp = env.doJSON(t, "DELETE", "/admin/api/keys/"+keyID, nil)
	if resp.StatusCode != http.StatusNoContent {
		body := readBody(t, resp)
		t.Fatalf("revoke key: status=%d, body=%s", resp.StatusCode, body)
	}

	// Step 5: Delete the identity (cascades to remove keys)
	resp = env.doJSON(t, "DELETE", "/admin/api/identities/"+identityID, nil)
	if resp.StatusCode != http.StatusNoContent {
		body := readBody(t, resp)
		t.Fatalf("delete identity: status=%d, body=%s", resp.StatusCode, body)
	}

	// Verify identity is gone
	resp = env.doJSON(t, "GET", "/admin/api/identities", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list identities after delete: status=%d", resp.StatusCode)
	}
	decodeJSON(t, resp, &identities)
	for _, ident := range identities {
		if ident["id"] == identityID {
			t.Errorf("identity %s still in list after delete", identityID)
		}
	}
}

// TestIntegrationAdminAuth tests the admin auth status endpoint and localhost bypass.
func TestIntegrationAdminAuth(t *testing.T) {
	env := setupTestEnv(t)

	// Step 1: Auth status from localhost (test server connects via loopback)
	resp := env.doJSON(t, "GET", "/admin/api/auth/status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("auth status: status=%d", resp.StatusCode)
	}
	var authStatus map[string]interface{}
	decodeJSON(t, resp, &authStatus)

	// From httptest server (127.0.0.1), localhost should be true
	if authStatus["localhost"] != true {
		t.Errorf("localhost = %v, want true (httptest uses loopback)", authStatus["localhost"])
	}

	// password_set should always be false in OSS
	if authStatus["password_set"] != false {
		t.Errorf("password_set = %v, want false (no remote auth in OSS)", authStatus["password_set"])
	}

	// Step 2: Test that localhost bypasses auth (can access protected endpoint without session)
	resp = env.doJSON(t, "GET", "/admin/api/upstreams", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET upstreams from localhost without auth: status=%d (want 200, localhost bypass)", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Step 3: Verify password/login endpoints are removed (not found)
	passwordReq := map[string]interface{}{
		"password": "testpassword123",
	}
	resp = env.doJSON(t, "POST", "/admin/api/auth/password", passwordReq)
	// Should not succeed — route removed
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST /admin/api/auth/password should not succeed (route removed), got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	loginReq := map[string]interface{}{
		"password": "testpassword123",
	}
	resp = env.doJSON(t, "POST", "/admin/api/auth/login", loginReq)
	// Should not succeed — route removed
	if resp.StatusCode == http.StatusOK {
		t.Errorf("POST /admin/api/auth/login should not succeed (route removed), got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// TestIntegrationStatsAndAudit tests stats, system info, and audit endpoints.
func TestIntegrationStatsAndAudit(t *testing.T) {
	env := setupTestEnv(t)

	// Step 1: GET /admin/api/stats -> all fields present, counts are 0
	resp := env.doJSON(t, "GET", "/admin/api/stats", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stats: status=%d", resp.StatusCode)
	}
	var stats map[string]interface{}
	decodeJSON(t, resp, &stats)

	// Verify fields exist
	for _, field := range []string{"upstreams", "tools", "policies", "allowed", "denied", "rate_limited", "errors"} {
		if _, ok := stats[field]; !ok {
			t.Errorf("stats missing field: %s", field)
		}
	}
	// Counters should be 0 initially
	if stats["allowed"] != float64(0) {
		t.Errorf("allowed = %v, want 0", stats["allowed"])
	}
	if stats["denied"] != float64(0) {
		t.Errorf("denied = %v, want 0", stats["denied"])
	}

	// Step 2: GET /admin/api/system -> version, go_version, os, arch present
	resp = env.doJSON(t, "GET", "/admin/api/system", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("system: status=%d", resp.StatusCode)
	}
	var sysInfo map[string]interface{}
	decodeJSON(t, resp, &sysInfo)

	for _, field := range []string{"version", "commit", "build_date", "go_version", "os", "arch", "uptime", "uptime_seconds"} {
		if _, ok := sysInfo[field]; !ok {
			t.Errorf("system info missing field: %s", field)
		}
	}
	if sysInfo["version"] != "test-1.0.0" {
		t.Errorf("version = %v, want test-1.0.0", sysInfo["version"])
	}
	if sysInfo["commit"] != "abc1234" {
		t.Errorf("commit = %v, want abc1234", sysInfo["commit"])
	}

	// Step 3: GET /admin/api/audit -> empty records array
	resp = env.doJSON(t, "GET", "/admin/api/audit", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit: status=%d", resp.StatusCode)
	}
	var auditResp map[string]interface{}
	decodeJSON(t, resp, &auditResp)
	records, ok := auditResp["records"].([]interface{})
	if !ok {
		t.Fatalf("records field missing or not array: %v", auditResp)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 audit records, got %d", len(records))
	}

	// Step 4: GET /admin/api/audit/export -> CSV with headers
	resp = env.doJSON(t, "GET", "/admin/api/audit/export", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit export: status=%d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if ct != "text/csv" {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	csvBody := readBody(t, resp)
	if !strings.Contains(csvBody, "timestamp") {
		t.Errorf("CSV export should contain 'timestamp' header, got: %s", csvBody[:min(100, len(csvBody))])
	}
}

// Helper to suppress "unused" import of os in test builds.
var _ = os.TempDir
