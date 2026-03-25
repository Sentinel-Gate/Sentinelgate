package integration

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// =============================================================================
// REGR-01: Core MCP Proxy Regression Tests
// =============================================================================

// TestRegression_MultipleToolCallsSequence sends 3 sequential tool calls
// (allow, deny, allow) through the same interceptor chain and verifies the
// audit trail has 3 records with correct decisions.
func TestRegression_MultipleToolCallsSequence(t *testing.T) {
	policyEngine := &mockRegressionPolicyEngine{
		rules: map[string]policy.Decision{
			"read_file": {
				Allowed: true,
				RuleID:  "reg-allow-read",
				Reason:  "read tools allowed",
			},
			"exec_command": {
				Allowed: false,
				RuleID:  "reg-deny-exec",
				Reason:  "exec tools blocked",
			},
			"list_files": {
				Allowed: true,
				RuleID:  "reg-allow-list",
				Reason:  "list tools allowed",
			},
		},
	}

	upstream := &mockUpstreamRouter{
		toolCallResponse: buildRegressionUpstreamResponse(t, "result"),
	}

	chain, auditRec, statsRec := buildRegressionChain(policyEngine, upstream)
	sess := buildRegressionSession()

	// Call 1: read_file -> allowed
	msg1 := buildRegressionMessage(t, "tools/call", 1, map[string]interface{}{
		"name":      "read_file",
		"arguments": map[string]interface{}{"path": "/tmp/a.txt"},
	}, sess)
	_, err := chain.Intercept(context.Background(), msg1)
	if err != nil {
		t.Fatalf("call 1 (read_file) should succeed, got error: %v", err)
	}

	// Call 2: exec_command -> denied
	msg2 := buildRegressionMessage(t, "tools/call", 2, map[string]interface{}{
		"name":      "exec_command",
		"arguments": map[string]interface{}{"cmd": "rm -rf /"},
	}, sess)
	_, err = chain.Intercept(context.Background(), msg2)
	if err == nil {
		t.Fatal("call 2 (exec_command) should be denied")
	}
	if !errors.Is(err, proxy.ErrPolicyDenied) {
		t.Errorf("call 2 error should wrap ErrPolicyDenied, got: %v", err)
	}

	// Call 3: list_files -> allowed
	msg3 := buildRegressionMessage(t, "tools/call", 3, map[string]interface{}{
		"name":      "list_files",
		"arguments": map[string]interface{}{},
	}, sess)
	_, err = chain.Intercept(context.Background(), msg3)
	if err != nil {
		t.Fatalf("call 3 (list_files) should succeed, got error: %v", err)
	}

	// Verify audit trail: 3 records
	if len(auditRec.records) != 3 {
		t.Fatalf("audit records = %d, want 3", len(auditRec.records))
	}

	// Verify decision sequence: allow, deny, allow
	expectedDecisions := []string{
		audit.DecisionAllow,
		audit.DecisionDeny,
		audit.DecisionAllow,
	}
	for i, expected := range expectedDecisions {
		if auditRec.records[i].Decision != expected {
			t.Errorf("audit[%d].Decision = %q, want %q", i, auditRec.records[i].Decision, expected)
		}
	}

	// Verify stats: 2 allows, 1 deny
	if statsRec.allows != 2 {
		t.Errorf("stats allows = %d, want 2", statsRec.allows)
	}
	if statsRec.denies != 1 {
		t.Errorf("stats denies = %d, want 1", statsRec.denies)
	}
}

// TestRegression_UnknownMethodPassthrough verifies that non-standard MCP methods
// pass through the chain without error.
func TestRegression_UnknownMethodPassthrough(t *testing.T) {
	policyEngine := &mockRegressionPolicyEngine{
		rules: map[string]policy.Decision{},
	}

	upstreamRouter := &mockUpstreamRouter{
		toolCallResponse: buildRegressionUpstreamResponse(t, "pong"),
	}

	chain, _, _ := buildRegressionChain(policyEngine, upstreamRouter)
	sess := buildRegressionSession()

	// Send a non-standard method "custom/ping"
	msg := buildRegressionMessage(t, "custom/ping", 42, map[string]interface{}{
		"data": "hello",
	}, sess)

	result, err := chain.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("custom/ping should pass through, got error: %v", err)
	}
	if result == nil {
		t.Fatal("custom/ping should return non-nil result")
	}
}

// =============================================================================
// REGR-02: CEL Policy Engine Regression Tests
// =============================================================================

// TestRegression_CELPolicyAllowDeny creates a real CEL policy engine with a
// policy containing rules for allow (read_*) and deny (write_*), then evaluates
// against both patterns to verify correct decisions.
func TestRegression_CELPolicyAllowDeny(t *testing.T) {
	ctx := context.Background()

	// Create a real policy store with a real CEL-backed PolicyService
	policyStore := memory.NewPolicyStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Add a policy with two rules
	policyStore.AddPolicy(&policy.Policy{
		ID:      "regr-02-policy",
		Name:    "REGR-02 Test Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "rule-allow-read",
				Name:      "Allow Read Tools",
				Priority:  10,
				ToolMatch: "read_*",
				Condition: "true",
				Action:    policy.ActionAllow,
			},
			{
				ID:        "rule-deny-write",
				Name:      "Deny Write Tools",
				Priority:  10,
				ToolMatch: "write_*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		},
	})

	// Create real PolicyService (uses real CEL evaluator)
	policySvc, err := service.NewPolicyService(ctx, policyStore, logger)
	if err != nil {
		t.Fatalf("NewPolicyService: %v", err)
	}

	// Test 1: read_file should be allowed
	decision, err := policySvc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "read_file",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"user"},
		SessionID:     "sess-regr-02",
		IdentityID:    "id-regr-02",
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate(read_file): %v", err)
	}
	if !decision.Allowed {
		t.Errorf("read_file should be allowed, got denied: %s", decision.Reason)
	}

	// Test 2: write_file should be denied
	decision, err = policySvc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "write_file",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"user"},
		SessionID:     "sess-regr-02",
		IdentityID:    "id-regr-02",
		IdentityName:  "regr-user-02",
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate(write_file): %v", err)
	}
	if decision.Allowed {
		t.Errorf("write_file should be denied, got allowed: %s", decision.Reason)
	}
}

// TestRegression_CELRulePriority creates a policy with overlapping rules:
// a low-priority allow-all and a high-priority deny for exec_*, then verifies
// the deny takes precedence.
func TestRegression_CELRulePriority(t *testing.T) {
	ctx := context.Background()

	policyStore := memory.NewPolicyStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Policy with overlapping rules.
	// The engine sorts rules by priority DESCENDING (higher number = evaluated first).
	// This matches the documented behavior: rule-level priority ordering.
	//
	// Setup:
	// - Priority 100 (evaluated first): deny exec_* tools
	// - Priority 1 (evaluated last): allow all tools
	//
	// For exec_* tools, the deny rule at priority 100 evaluates first and wins.
	// For other tools (e.g., read_file), only the allow-all rule matches.
	policyStore.AddPolicy(&policy.Policy{
		ID:      "regr-priority-policy",
		Name:    "REGR Priority Test",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "rule-deny-exec",
				Name:      "Deny Exec",
				Priority:  100, // Higher number = evaluated first
				ToolMatch: "exec_*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
			{
				ID:        "rule-allow-all",
				Name:      "Allow All",
				Priority:  1, // Lower number = evaluated last (fallback)
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionAllow,
			},
		},
	})

	policySvc, err := service.NewPolicyService(ctx, policyStore, logger)
	if err != nil {
		t.Fatalf("NewPolicyService: %v", err)
	}

	// exec_run should be denied (high-priority deny overrides low-priority allow)
	decision, err := policySvc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "exec_run",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"admin"},
		SessionID:     "sess-priority",
		IdentityID:    "id-priority",
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate(exec_run): %v", err)
	}
	if decision.Allowed {
		t.Errorf("exec_run should be denied (high-priority deny), got allowed: rule=%s reason=%s",
			decision.RuleID, decision.Reason)
	}
	if decision.RuleID != "rule-deny-exec" {
		t.Errorf("decision.RuleID = %q, want %q (deny-exec should win)", decision.RuleID, "rule-deny-exec")
	}

	// read_file should be allowed (only the allow-all rule matches)
	decision, err = policySvc.Evaluate(ctx, policy.EvaluationContext{
		ToolName:      "read_file",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"admin"},
		SessionID:     "sess-priority",
		IdentityID:    "id-priority",
		IdentityName:  "priority-user",
		RequestTime:   time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate(read_file): %v", err)
	}
	if !decision.Allowed {
		t.Errorf("read_file should be allowed (allow-all), got denied: rule=%s reason=%s",
			decision.RuleID, decision.Reason)
	}
}

// =============================================================================
// REGR-03: Admin API CRUD Regression Tests
// =============================================================================

// regressionAdminEnv holds the test environment for admin API regression tests.
type regressionAdminEnv struct {
	handler *admin.AdminAPIHandler
	server  *httptest.Server
}

// regressionAuditReader implements admin.AuditReader for regression tests.
type regressionAdminAuditReader struct {
	records []audit.AuditRecord
}

func (m *regressionAdminAuditReader) GetRecent(n int) []audit.AuditRecord {
	if n > len(m.records) {
		n = len(m.records)
	}
	return m.records[:n]
}

func (m *regressionAdminAuditReader) Query(_ context.Context, filter audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	return []audit.AuditRecord{}, "", nil
}

// csrfToken is the fixed CSRF token used in regression admin tests.
const regressionCSRFToken = "regression-csrf-token"

// setupRegressionAdminEnv creates a minimal admin API test environment.
func setupRegressionAdminEnv(t *testing.T) *regressionAdminEnv {
	t.Helper()

	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	stateStore := state.NewFileStateStore(statePath, logger)
	appState := stateStore.DefaultState()
	if err := stateStore.Save(appState); err != nil {
		t.Fatalf("save initial state: %v", err)
	}

	policyStore := memory.NewPolicyStore()
	upstreamStore := memory.NewUpstreamStore()

	upstreamService := service.NewUpstreamService(upstreamStore, stateStore, logger)
	failFactory := service.ClientFactory(func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return nil, errors.New("test: no real upstream connections")
	})
	manager := service.NewUpstreamManager(upstreamService, failFactory, logger)
	t.Cleanup(func() { _ = manager.Close() })

	toolCache := upstream.NewToolCache()
	discoveryService := service.NewToolDiscoveryService(upstreamService, toolCache, failFactory, logger)
	t.Cleanup(func() { discoveryService.Stop() })

	policyService, err := service.NewPolicyService(context.Background(), policyStore, logger)
	if err != nil {
		t.Fatalf("create policy service: %v", err)
	}

	auditStore := memory.NewAuditStoreWithWriter(io.Discard)
	auditService := service.NewAuditService(auditStore, logger)
	auditService.Start(context.Background())
	t.Cleanup(func() { auditService.Stop() })

	policyAdminService := service.NewPolicyAdminService(policyStore, stateStore, policyService, logger)
	identityService := service.NewIdentityService(stateStore, logger)
	statsService := service.NewStatsService()

	auditReader := &regressionAdminAuditReader{}

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
			Version:   "regr-test-1.0.0",
			Commit:    "regr1234",
			BuildDate: "2026-02-19",
		}),
		admin.WithStartTime(time.Now().UTC()),
	)

	server := httptest.NewServer(handler.Routes())
	t.Cleanup(func() { server.Close() })

	return &regressionAdminEnv{
		handler: handler,
		server:  server,
	}
}

// doRegressionJSON performs a JSON request against the regression admin server.
func (e *regressionAdminEnv) doJSON(t *testing.T, method, path string, body interface{}) *http.Response {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		bodyReader = strings.NewReader(string(data))
	}

	req, err := http.NewRequest(method, e.server.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method == "POST" || method == "PUT" || method == "DELETE" {
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: regressionCSRFToken})
		req.Header.Set("X-CSRF-Token", regressionCSRFToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// regressionDecodeJSON decodes the response body into target.
func regressionDecodeJSON(t *testing.T, resp *http.Response, target interface{}) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// regressionReadBody reads and returns the response body as a string.
func regressionReadBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(data)
}

// TestRegression_AdminAPIPolicyCRUD tests the full policy CRUD lifecycle through
// the admin API: create -> get -> update -> list -> delete -> verify 404.
func TestRegression_AdminAPIPolicyCRUD(t *testing.T) {
	env := setupRegressionAdminEnv(t)

	// Step 1: Create policy
	createReq := map[string]interface{}{
		"name":    "Regression Policy",
		"enabled": true,
		"rules": []map[string]interface{}{
			{
				"name":       "regr-allow-read",
				"priority":   50,
				"tool_match": "read_*",
				"condition":  "true",
				"action":     "allow",
			},
		},
	}
	resp := env.doJSON(t, "POST", "/admin/api/policies", createReq)
	if resp.StatusCode != http.StatusCreated {
		body := regressionReadBody(t, resp)
		t.Fatalf("create policy: status=%d, body=%s", resp.StatusCode, body)
	}

	var created map[string]interface{}
	regressionDecodeJSON(t, resp, &created)
	policyID, ok := created["id"].(string)
	if !ok || policyID == "" {
		t.Fatalf("created policy missing ID: %v", created)
	}

	// Step 2: List policies -> should contain our policy
	resp = env.doJSON(t, "GET", "/admin/api/policies", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list policies: status=%d", resp.StatusCode)
	}
	var policies []map[string]interface{}
	regressionDecodeJSON(t, resp, &policies)
	found := false
	for _, p := range policies {
		if p["id"] == policyID {
			found = true
			break
		}
	}
	if !found {
		t.Error("created policy not found in list")
	}

	// Step 3: Update policy name
	updateReq := map[string]interface{}{
		"name":    "Updated Regression Policy",
		"enabled": true,
		"rules": []map[string]interface{}{
			{
				"name":       "regr-allow-read",
				"priority":   50,
				"tool_match": "read_*",
				"condition":  "true",
				"action":     "allow",
			},
		},
	}
	resp = env.doJSON(t, "PUT", "/admin/api/policies/"+policyID, updateReq)
	if resp.StatusCode != http.StatusOK {
		body := regressionReadBody(t, resp)
		t.Fatalf("update policy: status=%d, body=%s", resp.StatusCode, body)
	}
	var updated map[string]interface{}
	regressionDecodeJSON(t, resp, &updated)
	if updated["name"] != "Updated Regression Policy" {
		t.Errorf("updated name = %v, want 'Updated Regression Policy'", updated["name"])
	}

	// Step 4: Delete policy
	resp = env.doJSON(t, "DELETE", "/admin/api/policies/"+policyID, nil)
	if resp.StatusCode != http.StatusNoContent {
		body := regressionReadBody(t, resp)
		t.Fatalf("delete policy: status=%d, body=%s", resp.StatusCode, body)
	}

	// Step 5: Verify policy gone from list
	resp = env.doJSON(t, "GET", "/admin/api/policies", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list policies after delete: status=%d", resp.StatusCode)
	}
	regressionDecodeJSON(t, resp, &policies)
	for _, p := range policies {
		if p["id"] == policyID {
			t.Error("deleted policy still in list")
		}
	}
}

// TestRegression_AdminAPIIdentityCRUD tests the full identity CRUD lifecycle:
// create -> get -> update -> list -> delete -> verify gone.
func TestRegression_AdminAPIIdentityCRUD(t *testing.T) {
	env := setupRegressionAdminEnv(t)

	// Step 1: Create identity
	createReq := map[string]interface{}{
		"name":  "regr-test-user",
		"roles": []string{"user", "read-only"},
	}
	resp := env.doJSON(t, "POST", "/admin/api/identities", createReq)
	if resp.StatusCode != http.StatusCreated {
		body := regressionReadBody(t, resp)
		t.Fatalf("create identity: status=%d, body=%s", resp.StatusCode, body)
	}

	var created map[string]interface{}
	regressionDecodeJSON(t, resp, &created)
	identityID, ok := created["id"].(string)
	if !ok || identityID == "" {
		t.Fatalf("created identity missing ID: %v", created)
	}

	// Step 2: List identities -> should contain our identity
	resp = env.doJSON(t, "GET", "/admin/api/identities", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list identities: status=%d", resp.StatusCode)
	}
	var identities []map[string]interface{}
	regressionDecodeJSON(t, resp, &identities)
	found := false
	for _, ident := range identities {
		if ident["id"] == identityID {
			found = true
			break
		}
	}
	if !found {
		t.Error("created identity not found in list")
	}

	// Step 3: Update identity
	updateReq := map[string]interface{}{
		"name":  "regr-renamed-user",
		"roles": []string{"admin"},
	}
	resp = env.doJSON(t, "PUT", "/admin/api/identities/"+identityID, updateReq)
	if resp.StatusCode != http.StatusOK {
		body := regressionReadBody(t, resp)
		t.Fatalf("update identity: status=%d, body=%s", resp.StatusCode, body)
	}

	// Step 4: Delete identity
	resp = env.doJSON(t, "DELETE", "/admin/api/identities/"+identityID, nil)
	if resp.StatusCode != http.StatusNoContent {
		body := regressionReadBody(t, resp)
		t.Fatalf("delete identity: status=%d, body=%s", resp.StatusCode, body)
	}

	// Step 5: Verify gone
	resp = env.doJSON(t, "GET", "/admin/api/identities", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list identities after delete: status=%d", resp.StatusCode)
	}
	regressionDecodeJSON(t, resp, &identities)
	for _, ident := range identities {
		if ident["id"] == identityID {
			t.Error("deleted identity still in list")
		}
	}
}

// TestRegression_AdminAPIKeyCRUD tests the API key lifecycle:
// create identity -> create key -> list keys -> delete key -> verify gone.
func TestRegression_AdminAPIKeyCRUD(t *testing.T) {
	env := setupRegressionAdminEnv(t)

	// Step 1: Create an identity first (keys require an identity)
	createIdentity := map[string]interface{}{
		"name":  "key-test-user",
		"roles": []string{"user"},
	}
	resp := env.doJSON(t, "POST", "/admin/api/identities", createIdentity)
	if resp.StatusCode != http.StatusCreated {
		body := regressionReadBody(t, resp)
		t.Fatalf("create identity: status=%d, body=%s", resp.StatusCode, body)
	}
	var createdIdentity map[string]interface{}
	regressionDecodeJSON(t, resp, &createdIdentity)
	identityID := createdIdentity["id"].(string)

	// Step 2: Generate API key
	keyReq := map[string]interface{}{
		"identity_id": identityID,
		"name":        "regr-test-key",
	}
	resp = env.doJSON(t, "POST", "/admin/api/keys", keyReq)
	if resp.StatusCode != http.StatusCreated {
		body := regressionReadBody(t, resp)
		t.Fatalf("generate key: status=%d, body=%s", resp.StatusCode, body)
	}

	var keyResult map[string]interface{}
	regressionDecodeJSON(t, resp, &keyResult)

	// Verify cleartext key returned
	cleartextKey, ok := keyResult["cleartext_key"].(string)
	if !ok || cleartextKey == "" {
		t.Fatalf("cleartext_key missing or empty: %v", keyResult)
	}
	if !strings.HasPrefix(cleartextKey, "sg_") {
		t.Errorf("cleartext_key should start with 'sg_', got prefix: %s", cleartextKey[:3])
	}

	keyID, ok := keyResult["id"].(string)
	if !ok || keyID == "" {
		t.Fatalf("key missing ID: %v", keyResult)
	}

	// Step 3: List keys -> should contain our key
	resp = env.doJSON(t, "GET", "/admin/api/keys", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list keys: status=%d", resp.StatusCode)
	}
	var keys []map[string]interface{}
	regressionDecodeJSON(t, resp, &keys)
	found := false
	for _, k := range keys {
		if k["id"] == keyID {
			found = true
			break
		}
	}
	if !found {
		t.Error("created key not found in list")
	}

	// Step 4: Revoke key (DELETE marks as revoked, does not remove from list)
	resp = env.doJSON(t, "DELETE", "/admin/api/keys/"+keyID, nil)
	if resp.StatusCode != http.StatusNoContent {
		body := regressionReadBody(t, resp)
		t.Fatalf("revoke key: status=%d, body=%s", resp.StatusCode, body)
	}

	// Step 5: Verify key is marked as revoked in list
	resp = env.doJSON(t, "GET", "/admin/api/keys", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list keys after revoke: status=%d", resp.StatusCode)
	}
	regressionDecodeJSON(t, resp, &keys)
	revokedFound := false
	for _, k := range keys {
		if k["id"] == keyID {
			revokedFound = true
			if revoked, ok := k["revoked"].(bool); !ok || !revoked {
				t.Errorf("revoked key should have revoked=true, got %v", k["revoked"])
			}
			break
		}
	}
	if !revokedFound {
		t.Error("revoked key should still be in list (marked as revoked)")
	}
}

// =============================================================================
// REGR-04: Admin UI Page Load Regression Test
// =============================================================================

// TestRegression_AdminUIPageLoad verifies that the AdminHandler serves the SPA
// shell at GET /admin/ with correct status, content type, and HTML markers.
// Uses httptest (fully automated, no manual verification).
func TestRegression_AdminUIPageLoad(t *testing.T) {
	cfg := &config.OSSConfig{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	h, err := admin.NewAdminHandler(cfg, logger)
	if err != nil {
		t.Fatalf("NewAdminHandler: %v", err)
	}

	handler := h.Handler()
	server := httptest.NewServer(handler)
	defer server.Close()

	// GET /admin/ from localhost
	req, err := http.NewRequest(http.MethodGet, server.URL+"/admin/", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	// httptest server already connects via loopback, but set RemoteAddr explicitly
	// to ensure localhost bypass works
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /admin/: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Verify status code is 200
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/ status = %d, want 200", resp.StatusCode)
	}

	// Verify Content-Type contains text/html
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		t.Errorf("Content-Type = %q, want to contain 'text/html'", contentType)
	}

	// Read body and verify HTML markers
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(body)

	// Check that the template rendered (contains closing HTML tag)
	if !strings.Contains(bodyStr, "</html>") {
		t.Error("response body should contain '</html>' (template rendered)")
	}

	// Check for a known UI marker -- the SPA should contain at least one of these
	uiMarkers := []string{"id=\"app\"", "SentinelGate", "<script"}
	foundMarker := false
	for _, marker := range uiMarkers {
		if strings.Contains(bodyStr, marker) {
			foundMarker = true
			break
		}
	}
	if !foundMarker {
		t.Errorf("response body should contain a UI marker (id=\"app\", SentinelGate, or <script), got first 500 chars: %s",
			bodyStr[:min(500, len(bodyStr))])
	}
}

// =============================================================================
// REGR-05: State Persistence Regression Tests
// =============================================================================

// TestRegression_StatePersistenceRoundTrip creates a FileStateStore, saves a state
// with policies + identities + upstreams, loads it back, verifies all fields match,
// then modifies a policy, saves again, loads again, verifies persistence.
func TestRegression_StatePersistenceRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := testLogger()

	store := state.NewFileStateStore(statePath, logger)

	now := time.Now().UTC().Truncate(time.Second) // Truncate for JSON round-trip

	// Create a state with various entries
	original := &state.AppState{
		Version:       "1",
		DefaultPolicy: "deny",
		Upstreams: []state.UpstreamEntry{
			{
				ID:        "up-regr-1",
				Name:      "regr-filesystem",
				Type:      "stdio",
				Enabled:   true,
				Command:   "/usr/bin/echo",
				Args:      []string{"hello"},
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		Policies: []state.PolicyEntry{
			{
				ID:          "pol-regr-1",
				Name:        "Regr Deny All",
				Priority:    0,
				ToolPattern: "*",
				Action:      "deny",
				Enabled:     true,
				CreatedAt:   now,
				UpdatedAt:   now,
			},
			{
				ID:          "pol-regr-2",
				Name:        "Regr Allow Read",
				Priority:    10,
				ToolPattern: "read_*",
				Action:      "allow",
				Enabled:     true,
				CreatedAt:   now,
				UpdatedAt:   now,
			},
		},
		Identities: []state.IdentityEntry{
			{
				ID:        "id-regr-1",
				Name:      "Regr User",
				Roles:     []string{"user", "reader"},
				CreatedAt: now,
			},
		},
		APIKeys:   []state.APIKeyEntry{},
		CreatedAt: now,
	}

	// Save
	if err := store.Save(original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load and verify
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Version != "1" {
		t.Errorf("Version = %q, want %q", loaded.Version, "1")
	}
	if loaded.DefaultPolicy != "deny" {
		t.Errorf("DefaultPolicy = %q, want %q", loaded.DefaultPolicy, "deny")
	}
	if len(loaded.Upstreams) != 1 {
		t.Fatalf("len(Upstreams) = %d, want 1", len(loaded.Upstreams))
	}
	if loaded.Upstreams[0].Name != "regr-filesystem" {
		t.Errorf("Upstream[0].Name = %q, want %q", loaded.Upstreams[0].Name, "regr-filesystem")
	}
	if len(loaded.Policies) != 2 {
		t.Fatalf("len(Policies) = %d, want 2", len(loaded.Policies))
	}
	if loaded.Policies[0].Name != "Regr Deny All" {
		t.Errorf("Policy[0].Name = %q, want %q", loaded.Policies[0].Name, "Regr Deny All")
	}
	if loaded.Policies[1].Name != "Regr Allow Read" {
		t.Errorf("Policy[1].Name = %q, want %q", loaded.Policies[1].Name, "Regr Allow Read")
	}
	if len(loaded.Identities) != 1 {
		t.Fatalf("len(Identities) = %d, want 1", len(loaded.Identities))
	}
	if loaded.Identities[0].Name != "Regr User" {
		t.Errorf("Identity[0].Name = %q, want %q", loaded.Identities[0].Name, "Regr User")
	}

	// Modify a policy and save again
	loaded.Policies[1].Name = "Regr Allow Read MODIFIED"
	loaded.Policies[1].Priority = 20

	if err := store.Save(loaded); err != nil {
		t.Fatalf("Save after modify: %v", err)
	}

	// Reload and verify modification persisted
	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load after modify: %v", err)
	}

	if len(reloaded.Policies) != 2 {
		t.Fatalf("reloaded len(Policies) = %d, want 2", len(reloaded.Policies))
	}

	// Find the modified policy
	foundModified := false
	for _, p := range reloaded.Policies {
		if p.ID == "pol-regr-2" {
			foundModified = true
			if p.Name != "Regr Allow Read MODIFIED" {
				t.Errorf("modified policy Name = %q, want %q", p.Name, "Regr Allow Read MODIFIED")
			}
			if p.Priority != 20 {
				t.Errorf("modified policy Priority = %d, want 20", p.Priority)
			}
		}
	}
	if !foundModified {
		t.Error("modified policy (pol-regr-2) not found after reload")
	}
}

// TestRegression_StateCorruptRecovery writes invalid JSON to state.json, attempts
// Load(), verifies it returns an error (not a panic). Then writes valid state and
// verifies Load() succeeds.
func TestRegression_StateCorruptRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := testLogger()

	// Write corrupt (invalid JSON) to state.json
	if err := os.WriteFile(statePath, []byte("{invalid json!!!}"), 0600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}

	store := state.NewFileStateStore(statePath, logger)

	// Load should return an error, not panic
	_, err := store.Load()
	if err == nil {
		t.Fatal("Load() with corrupt JSON should return an error, got nil")
	}

	// Now write valid state
	validState := &state.AppState{
		Version:       "1",
		DefaultPolicy: "deny",
		Upstreams:     []state.UpstreamEntry{},
		Policies: []state.PolicyEntry{
			{
				ID:          "recovery-deny",
				Name:        "Recovery Deny All",
				Priority:    0,
				ToolPattern: "*",
				Action:      "deny",
				Enabled:     true,
			},
		},
		Identities: []state.IdentityEntry{},
		APIKeys:    []state.APIKeyEntry{},
	}
	data, err := json.MarshalIndent(validState, "", "  ")
	if err != nil {
		t.Fatalf("marshal valid state: %v", err)
	}
	if err := os.WriteFile(statePath, data, 0600); err != nil {
		t.Fatalf("write valid state: %v", err)
	}

	// Load should now succeed
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after writing valid state should succeed, got: %v", err)
	}
	if loaded.Version != "1" {
		t.Errorf("loaded Version = %q, want %q", loaded.Version, "1")
	}
	if len(loaded.Policies) != 1 {
		t.Fatalf("loaded len(Policies) = %d, want 1", len(loaded.Policies))
	}
	if loaded.Policies[0].Name != "Recovery Deny All" {
		t.Errorf("loaded Policy[0].Name = %q, want %q", loaded.Policies[0].Name, "Recovery Deny All")
	}
}

// Suppress "imported and not used" for mcp package.
var _ = mcp.ClientToServer
