package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/admin"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/recording"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// csrfToken is a fixed CSRF token used across admin API flow tests.
const csrfToken = "test-csrf-token-for-admin-flow-tests"

// adminIntegrationEnv holds the wired-up admin API handler and services for integration tests.
type adminIntegrationEnv struct {
	mux             http.Handler
	stateStore      *state.FileStateStore
	identityService *service.IdentityService
	upstreamService *service.UpstreamService
	upstreamManager *service.UpstreamManager
	policyAdmin     *service.PolicyAdminService
	recorder        *recording.FileRecorder
	statePath       string
}

// noopClientFactory returns a ClientFactory that always fails (connections are disabled in tests).
func noopClientFactory() service.ClientFactory {
	return func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return nil, fmt.Errorf("noop: connections disabled in tests")
	}
}

// setupAdminIntegrationEnv creates a fully wired admin API environment for integration testing.
// Each call returns a fresh environment with its own temp dir and state file.
func setupAdminIntegrationEnv(t *testing.T) *adminIntegrationEnv {
	t.Helper()

	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := testLogger()

	// Create state store and initialize with default state.
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	// Create identity service.
	identitySvc := service.NewIdentityService(stateStore, logger)
	if err := identitySvc.Init(); err != nil {
		t.Fatalf("init identity service: %v", err)
	}

	// Create upstream service with in-memory store.
	upstreamStore := memory.NewUpstreamStore()
	upstreamSvc := service.NewUpstreamService(upstreamStore, stateStore, logger)

	// Create upstream manager with noop client factory (no real connections in tests).
	manager := service.NewUpstreamManager(upstreamSvc, noopClientFactory(), logger)
	t.Cleanup(func() { _ = manager.Close() })

	// Create tool cache.
	toolCache := upstream.NewToolCache()

	// Create policy service and policy admin service.
	policyStore := memory.NewPolicyStore()
	policySvc, err := service.NewPolicyService(context.Background(), policyStore, logger)
	if err != nil {
		t.Fatalf("create policy service: %v", err)
	}
	policyAdminSvc := service.NewPolicyAdminService(policyStore, stateStore, policySvc, logger)

	// Create recording service with temp storage dir.
	recordingDir := filepath.Join(tmpDir, "recordings")
	recCfg := recording.DefaultConfig()
	recCfg.StorageDir = recordingDir
	recorder, err := recording.NewFileRecorder(recCfg, logger)
	if err != nil {
		t.Fatalf("create file recorder: %v", err)
	}
	t.Cleanup(func() { recorder.StopReaper() })

	// Wire everything into AdminAPIHandler.
	handler := admin.NewAdminAPIHandler(
		admin.WithIdentityService(identitySvc),
		admin.WithUpstreamService(upstreamSvc),
		admin.WithUpstreamManager(manager),
		admin.WithToolCache(toolCache),
		admin.WithStateStore(stateStore),
		admin.WithPolicyAdminService(policyAdminSvc),
		admin.WithAPILogger(logger),
	)
	handler.SetRecordingService(recorder)

	return &adminIntegrationEnv{
		mux:             handler.Routes(),
		stateStore:      stateStore,
		identityService: identitySvc,
		upstreamService: upstreamSvc,
		upstreamManager: manager,
		policyAdmin:     policyAdminSvc,
		recorder:        recorder,
		statePath:       statePath,
	}
}

// doRequest performs an HTTP request against the admin API mux.
// Automatically sets RemoteAddr, Content-Type, and CSRF tokens for state-changing methods.
func (e *adminIntegrationEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
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
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: csrfToken})
		req.Header.Set("X-CSRF-Token", csrfToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

// decodeJSON decodes the response body into the given value.
func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode JSON response: %v (body=%q)", err, rec.Body.String())
	}
}

// --- Test 1: Identity Lifecycle E2E ---

func TestIdentityLifecycleE2E(t *testing.T) {
	env := setupAdminIntegrationEnv(t)
	ctx := t.Context()

	// Step 1: Create identity via API.
	createRec := env.doRequest(t, "POST", "/admin/api/identities", map[string]interface{}{
		"name":  "test-agent",
		"roles": []string{"admin"},
	})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/api/identities: status=%d, want %d (body=%s)",
			createRec.Code, http.StatusCreated, createRec.Body.String())
	}

	var identity struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		Roles     []string `json:"roles"`
		CreatedAt string   `json:"created_at"`
	}
	decodeJSON(t, createRec, &identity)
	if identity.ID == "" {
		t.Fatal("created identity missing ID")
	}
	if identity.Name != "test-agent" {
		t.Errorf("identity Name = %q, want %q", identity.Name, "test-agent")
	}

	// Step 2: Generate API key for the identity.
	keyRec := env.doRequest(t, "POST", "/admin/api/keys", map[string]interface{}{
		"identity_id": identity.ID,
		"name":        "test-key",
	})
	if keyRec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/api/keys: status=%d, want %d (body=%s)",
			keyRec.Code, http.StatusCreated, keyRec.Body.String())
	}

	var keyResp struct {
		ID           string `json:"id"`
		IdentityID   string `json:"identity_id"`
		Name         string `json:"name"`
		CleartextKey string `json:"cleartext_key"`
	}
	decodeJSON(t, keyRec, &keyResp)
	if keyResp.ID == "" {
		t.Fatal("generated key missing ID")
	}
	if keyResp.CleartextKey == "" {
		t.Fatal("generated key missing cleartext_key")
	}

	// Step 3: Verify key starts with "sg_" prefix.
	if !strings.HasPrefix(keyResp.CleartextKey, "sg_") {
		t.Errorf("cleartext key prefix = %q, want \"sg_\" prefix", keyResp.CleartextKey[:4])
	}

	// Step 4: Verify key authenticates via identity service directly.
	verifiedKey, err := env.identityService.VerifyKey(ctx, keyResp.CleartextKey)
	if err != nil {
		t.Fatalf("VerifyKey() for valid key: unexpected error: %v", err)
	}
	if verifiedKey.IdentityID != identity.ID {
		t.Errorf("verified key IdentityID = %q, want %q", verifiedKey.IdentityID, identity.ID)
	}

	// Step 5: Revoke the key via API.
	revokeRec := env.doRequest(t, "DELETE", "/admin/api/keys/"+keyResp.ID, nil)
	if revokeRec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /admin/api/keys/%s: status=%d, want %d (body=%s)",
			keyResp.ID, revokeRec.Code, http.StatusNoContent, revokeRec.Body.String())
	}

	// Step 6: Verify revoked key fails authentication.
	_, err = env.identityService.VerifyKey(ctx, keyResp.CleartextKey)
	if err == nil {
		t.Fatal("VerifyKey() for revoked key: expected error, got nil")
	}
}

// --- Test 2: Upstream CRUD E2E ---

func TestUpstreamCRUDE2E(t *testing.T) {
	env := setupAdminIntegrationEnv(t)

	// Step 1: GET upstreams — should be empty.
	listRec := env.doRequest(t, "GET", "/admin/api/upstreams", nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/upstreams: status=%d, want %d", listRec.Code, http.StatusOK)
	}
	var initialList []map[string]interface{}
	decodeJSON(t, listRec, &initialList)
	if len(initialList) != 0 {
		t.Fatalf("initial upstream count = %d, want 0", len(initialList))
	}

	// Step 2: POST — create a stdio upstream.
	createRec := env.doRequest(t, "POST", "/admin/api/upstreams", map[string]interface{}{
		"name":    "test-mcp-server",
		"type":    "stdio",
		"command": "/usr/local/bin/mcp-test",
		"args":    []string{"--verbose"},
	})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/api/upstreams: status=%d, want %d (body=%s)",
			createRec.Code, http.StatusCreated, createRec.Body.String())
	}
	var created struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	}
	decodeJSON(t, createRec, &created)
	if created.ID == "" {
		t.Fatal("created upstream missing ID")
	}
	if created.Name != "test-mcp-server" {
		t.Errorf("upstream Name = %q, want %q", created.Name, "test-mcp-server")
	}
	if created.Type != "stdio" {
		t.Errorf("upstream Type = %q, want %q", created.Type, "stdio")
	}

	// Step 3: GET — verify upstream is in list.
	listRec = env.doRequest(t, "GET", "/admin/api/upstreams", nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/upstreams after create: status=%d", listRec.Code)
	}
	var afterCreate []map[string]interface{}
	decodeJSON(t, listRec, &afterCreate)
	if len(afterCreate) != 1 {
		t.Fatalf("upstream count after create = %d, want 1", len(afterCreate))
	}

	// Step 4: PUT — update the upstream name.
	updateRec := env.doRequest(t, "PUT", "/admin/api/upstreams/"+created.ID, map[string]interface{}{
		"name": "updated-mcp-server",
	})
	if updateRec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/api/upstreams/%s: status=%d, want %d (body=%s)",
			created.ID, updateRec.Code, http.StatusOK, updateRec.Body.String())
	}
	var updated struct {
		Name string `json:"name"`
	}
	decodeJSON(t, updateRec, &updated)
	if updated.Name != "updated-mcp-server" {
		t.Errorf("updated upstream Name = %q, want %q", updated.Name, "updated-mcp-server")
	}

	// Step 5: GET — verify updated name is reflected.
	listRec = env.doRequest(t, "GET", "/admin/api/upstreams", nil)
	var afterUpdate []struct {
		Name string `json:"name"`
	}
	decodeJSON(t, listRec, &afterUpdate)
	if len(afterUpdate) != 1 {
		t.Fatalf("upstream count after update = %d, want 1", len(afterUpdate))
	}
	if afterUpdate[0].Name != "updated-mcp-server" {
		t.Errorf("list after update: Name = %q, want %q", afterUpdate[0].Name, "updated-mcp-server")
	}

	// Step 6: DELETE — remove the upstream.
	deleteRec := env.doRequest(t, "DELETE", "/admin/api/upstreams/"+created.ID, nil)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /admin/api/upstreams/%s: status=%d, want %d",
			created.ID, deleteRec.Code, http.StatusNoContent)
	}

	// Step 7: GET — verify upstream is removed.
	listRec = env.doRequest(t, "GET", "/admin/api/upstreams", nil)
	var afterDelete []map[string]interface{}
	decodeJSON(t, listRec, &afterDelete)
	if len(afterDelete) != 0 {
		t.Fatalf("upstream count after delete = %d, want 0", len(afterDelete))
	}
}

// --- Test 3: State Persistence E2E ---

func TestStatePersistenceE2E(t *testing.T) {
	env := setupAdminIntegrationEnv(t)

	// Step 1: Create identity via API.
	createRec := env.doRequest(t, "POST", "/admin/api/identities", map[string]interface{}{
		"name":  "persist-user",
		"roles": []string{"user"},
	})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/api/identities: status=%d, want %d (body=%s)",
			createRec.Code, http.StatusCreated, createRec.Body.String())
	}
	var identity struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	decodeJSON(t, createRec, &identity)

	// Step 2: Generate API key via API.
	keyRec := env.doRequest(t, "POST", "/admin/api/keys", map[string]interface{}{
		"identity_id": identity.ID,
		"name":        "persist-key",
	})
	if keyRec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/api/keys: status=%d, want %d (body=%s)",
			keyRec.Code, http.StatusCreated, keyRec.Body.String())
	}
	var keyResp struct {
		ID           string `json:"id"`
		CleartextKey string `json:"cleartext_key"`
	}
	decodeJSON(t, keyRec, &keyResp)

	// Step 3: Create a NEW state store from the same file (simulate restart).
	logger := testLogger()
	newStateStore := state.NewFileStateStore(env.statePath, logger)
	reloadedState, err := newStateStore.Load()
	if err != nil {
		t.Fatalf("Load() from same state file: %v", err)
	}

	// Step 4: Verify identity survived the "restart".
	foundIdentity := false
	for _, ident := range reloadedState.Identities {
		if ident.ID == identity.ID && ident.Name == "persist-user" {
			foundIdentity = true
			break
		}
	}
	if !foundIdentity {
		t.Error("identity not found in reloaded state")
	}

	// Step 5: Verify API key survived the "restart".
	foundKey := false
	for _, key := range reloadedState.APIKeys {
		if key.ID == keyResp.ID && key.IdentityID == identity.ID {
			foundKey = true
			break
		}
	}
	if !foundKey {
		t.Error("API key not found in reloaded state")
	}

	// Step 6: Create a new IdentityService from the reloaded state and verify key works.
	newIdentitySvc := service.NewIdentityService(newStateStore, logger)
	if err := newIdentitySvc.Init(); err != nil {
		t.Fatalf("init new identity service: %v", err)
	}
	verifiedKey, err := newIdentitySvc.VerifyKey(t.Context(), keyResp.CleartextKey)
	if err != nil {
		t.Fatalf("VerifyKey() after restart: unexpected error: %v", err)
	}
	if verifiedKey.IdentityID != identity.ID {
		t.Errorf("verified key IdentityID after restart = %q, want %q",
			verifiedKey.IdentityID, identity.ID)
	}
}

// --- Test 4: Policy Lifecycle E2E ---

func TestPolicyLifecycleE2E(t *testing.T) {
	env := setupAdminIntegrationEnv(t)

	// Step 1: GET policies — initially empty (no default policy seeded).
	listRec := env.doRequest(t, "GET", "/admin/api/policies", nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/policies: status=%d, want %d", listRec.Code, http.StatusOK)
	}
	var initialPolicies []map[string]interface{}
	decodeJSON(t, listRec, &initialPolicies)
	initialCount := len(initialPolicies)

	// Step 2: POST — create a policy with one rule.
	createRec := env.doRequest(t, "POST", "/admin/api/policies", map[string]interface{}{
		"name":        "Test Allow Read",
		"description": "Allow all read operations",
		"priority":    10,
		"enabled":     true,
		"rules": []map[string]interface{}{
			{
				"name":       "allow-read",
				"priority":   10,
				"tool_match": "read_*",
				"condition":  "true",
				"action":     "allow",
			},
		},
	})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/api/policies: status=%d, want %d (body=%s)",
			createRec.Code, http.StatusCreated, createRec.Body.String())
	}
	var createdPolicy struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
		Rules   []struct {
			ID     string `json:"id"`
			Action string `json:"action"`
		} `json:"rules"`
	}
	decodeJSON(t, createRec, &createdPolicy)
	if createdPolicy.ID == "" {
		t.Fatal("created policy missing ID")
	}
	if createdPolicy.Name != "Test Allow Read" {
		t.Errorf("policy Name = %q, want %q", createdPolicy.Name, "Test Allow Read")
	}
	if !createdPolicy.Enabled {
		t.Error("policy should be enabled")
	}
	if len(createdPolicy.Rules) != 1 {
		t.Fatalf("policy rules count = %d, want 1", len(createdPolicy.Rules))
	}

	// Step 3: GET — verify policy is in list.
	listRec = env.doRequest(t, "GET", "/admin/api/policies", nil)
	var afterCreate []map[string]interface{}
	decodeJSON(t, listRec, &afterCreate)
	if len(afterCreate) != initialCount+1 {
		t.Fatalf("policy count after create = %d, want %d", len(afterCreate), initialCount+1)
	}

	// Step 4: DELETE — remove the policy.
	deleteRec := env.doRequest(t, "DELETE", "/admin/api/policies/"+createdPolicy.ID, nil)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /admin/api/policies/%s: status=%d, want %d (body=%s)",
			createdPolicy.ID, deleteRec.Code, http.StatusNoContent, deleteRec.Body.String())
	}

	// Step 5: GET — verify policy is removed.
	listRec = env.doRequest(t, "GET", "/admin/api/policies", nil)
	var afterDelete []map[string]interface{}
	decodeJSON(t, listRec, &afterDelete)
	if len(afterDelete) != initialCount {
		t.Fatalf("policy count after delete = %d, want %d", len(afterDelete), initialCount)
	}
}

// --- Test 5: Recording Config E2E ---

func TestRecordingConfigE2E(t *testing.T) {
	env := setupAdminIntegrationEnv(t)

	// Step 1: GET default recording config.
	getRec := env.doRequest(t, "GET", "/admin/api/v1/recordings/config", nil)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/recordings/config: status=%d, want %d (body=%s)",
			getRec.Code, http.StatusOK, getRec.Body.String())
	}
	var defaultCfg struct {
		Enabled        bool   `json:"enabled"`
		RecordPayloads bool   `json:"record_payloads"`
		RetentionDays  int    `json:"retention_days"`
		StorageDir     string `json:"storage_dir"`
	}
	decodeJSON(t, getRec, &defaultCfg)
	// Recording is disabled by default.
	if defaultCfg.Enabled {
		t.Error("default recording config should have enabled=false")
	}

	// Step 2: PUT — update recording config.
	updatedDir := filepath.Join(t.TempDir(), "updated-recordings")
	putRec := env.doRequest(t, "PUT", "/admin/api/v1/recordings/config", map[string]interface{}{
		"enabled":         true,
		"record_payloads": true,
		"retention_days":  30,
		"max_file_size":   10485760,
		"storage_dir":     updatedDir,
	})
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/api/v1/recordings/config: status=%d, want %d (body=%s)",
			putRec.Code, http.StatusOK, putRec.Body.String())
	}
	var putResp struct {
		Enabled        bool `json:"enabled"`
		RecordPayloads bool `json:"record_payloads"`
		RetentionDays  int  `json:"retention_days"`
	}
	decodeJSON(t, putRec, &putResp)
	if !putResp.Enabled {
		t.Error("updated config should have enabled=true")
	}
	if !putResp.RecordPayloads {
		t.Error("updated config should have record_payloads=true")
	}
	if putResp.RetentionDays != 30 {
		t.Errorf("updated config retention_days = %d, want 30", putResp.RetentionDays)
	}

	// Step 3: GET — verify the updated config persisted.
	getRec = env.doRequest(t, "GET", "/admin/api/v1/recordings/config", nil)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/recordings/config after update: status=%d", getRec.Code)
	}
	var verifiedCfg struct {
		Enabled        bool `json:"enabled"`
		RecordPayloads bool `json:"record_payloads"`
		RetentionDays  int  `json:"retention_days"`
	}
	decodeJSON(t, getRec, &verifiedCfg)
	if !verifiedCfg.Enabled {
		t.Error("verified config should have enabled=true after update")
	}
	if !verifiedCfg.RecordPayloads {
		t.Error("verified config should have record_payloads=true after update")
	}
	if verifiedCfg.RetentionDays != 30 {
		t.Errorf("verified config retention_days = %d, want 30", verifiedCfg.RetentionDays)
	}
}
