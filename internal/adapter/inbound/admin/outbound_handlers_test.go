package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// testOutboundEnv creates a test environment for outbound handler tests.
// Returns the AdminAPIHandler and the OutboundAdminService for setup operations.
func testOutboundEnv(t *testing.T) (*AdminAPIHandler, *service.OutboundAdminService) {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	defaultState := stateStore.DefaultState()
	if err := stateStore.Save(defaultState); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	store := action.NewMemoryOutboundStore()

	// Create a mock interceptor for the outbound interceptor.
	resolver := action.NewDNSResolver(logger, action.WithLookupFunc(func(host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}))
	next := &testPassthroughInterceptor{}
	interceptor := action.NewOutboundInterceptor(nil, resolver, next, logger)

	svc := service.NewOutboundAdminService(store, stateStore, logger, interceptor)

	// Load defaults so we have default blocklist rules.
	appState := &state.AppState{}
	if err := svc.LoadFromState(context.Background(), appState); err != nil {
		t.Fatalf("load defaults: %v", err)
	}

	// Enable default rules for testing (they ship disabled by default).
	ctx := context.Background()
	rules, _ := svc.List(ctx)
	for _, r := range rules {
		r.Enabled = true
		if _, err := svc.Update(ctx, r.ID, &r); err != nil {
			t.Fatalf("enable rule %s: %v", r.ID, err)
		}
	}

	h := NewAdminAPIHandler(
		WithOutboundAdminService(svc),
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)

	return h, svc
}

// testOutboundEnvEmpty creates a test environment with NO default rules loaded.
func testOutboundEnvEmpty(t *testing.T) (*AdminAPIHandler, *service.OutboundAdminService) {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	defaultState := stateStore.DefaultState()
	if err := stateStore.Save(defaultState); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	store := action.NewMemoryOutboundStore()
	resolver := action.NewDNSResolver(logger, action.WithLookupFunc(func(host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}))
	next := &testPassthroughInterceptor{}
	interceptor := action.NewOutboundInterceptor(nil, resolver, next, logger)

	svc := service.NewOutboundAdminService(store, stateStore, logger, interceptor)

	h := NewAdminAPIHandler(
		WithOutboundAdminService(svc),
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)

	return h, svc
}

// testPassthroughInterceptor is a mock interceptor that passes through.
type testPassthroughInterceptor struct{}

func (m *testPassthroughInterceptor) Intercept(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
	return a, nil
}

// createTestRule creates a custom rule via the admin service for testing.
func createTestRule(t *testing.T, svc *service.OutboundAdminService, name string, priority int) *action.OutboundRule {
	t.Helper()
	rule := &action.OutboundRule{
		Name:     name,
		Mode:     action.RuleModeBlocklist,
		Action:   action.RuleActionBlock,
		Enabled:  true,
		Priority: priority,
		Targets: []action.OutboundTarget{
			{Type: action.TargetDomain, Value: "test-target.com"},
		},
	}
	created, err := svc.Create(context.Background(), rule)
	if err != nil {
		t.Fatalf("create test rule: %v", err)
	}
	return created
}

// --- Tests ---

func TestOutbound_ListEmpty(t *testing.T) {
	h, _ := testOutboundEnvEmpty(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/security/outbound/rules", nil)
	w := httptest.NewRecorder()

	h.handleListOutboundRules(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var rules []outboundRuleResponse
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestOutbound_ListWithRules(t *testing.T) {
	h, _ := testOutboundEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/security/outbound/rules", nil)
	w := httptest.NewRecorder()

	h.handleListOutboundRules(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var rules []outboundRuleResponse
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		t.Fatalf("decode: %v", err)
	}

	defaults := action.DefaultBlocklistRules()
	if len(rules) != len(defaults) {
		t.Fatalf("expected %d rules, got %d", len(defaults), len(rules))
	}

	// Verify sorted by priority.
	for i := 1; i < len(rules); i++ {
		if rules[i].Priority < rules[i-1].Priority {
			t.Errorf("rules not sorted by priority: [%d].Priority=%d < [%d].Priority=%d",
				i, rules[i].Priority, i-1, rules[i-1].Priority)
		}
	}

	// Default rules should be read-only.
	for _, r := range rules {
		if !r.ReadOnly {
			t.Errorf("default rule %q should be read_only", r.Name)
		}
	}
}

func TestOutbound_CreateValidRule(t *testing.T) {
	h, _ := testOutboundEnvEmpty(t)

	body := `{
		"name": "Block Test",
		"mode": "blocklist",
		"action": "block",
		"priority": 200,
		"enabled": true,
		"targets": [{"type": "domain", "value": "evil.com"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/security/outbound/rules", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleCreateOutboundRule(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	var rule outboundRuleResponse
	if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rule.ID == "" {
		t.Error("expected non-empty ID")
	}
	if rule.Name != "Block Test" {
		t.Errorf("name = %q, want 'Block Test'", rule.Name)
	}
	if rule.ReadOnly {
		t.Error("custom rule should not be read_only")
	}
}

func TestOutbound_CreateMissingName(t *testing.T) {
	h, _ := testOutboundEnvEmpty(t)

	body := `{
		"mode": "blocklist",
		"action": "block",
		"targets": [{"type": "domain", "value": "evil.com"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/security/outbound/rules", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleCreateOutboundRule(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Result().StatusCode, http.StatusBadRequest)
	}
}

func TestOutbound_CreateInvalidMode(t *testing.T) {
	h, _ := testOutboundEnvEmpty(t)

	body := `{
		"name": "Bad Mode",
		"mode": "invalid",
		"action": "block",
		"targets": [{"type": "domain", "value": "evil.com"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/security/outbound/rules", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleCreateOutboundRule(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Result().StatusCode, http.StatusBadRequest)
	}
}

func TestOutbound_GetExisting(t *testing.T) {
	h, svc := testOutboundEnvEmpty(t)

	// Create a rule via service.
	created := createTestRule(t, svc, "Get Me", 100)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/security/outbound/rules/"+created.ID, nil)
	req.SetPathValue("id", created.ID)
	w := httptest.NewRecorder()

	h.handleGetOutboundRule(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var rule outboundRuleResponse
	if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rule.Name != "Get Me" {
		t.Errorf("name = %q, want 'Get Me'", rule.Name)
	}
}

func TestOutbound_GetNonExistent(t *testing.T) {
	h, _ := testOutboundEnvEmpty(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/security/outbound/rules/does-not-exist", nil)
	req.SetPathValue("id", "does-not-exist")
	w := httptest.NewRecorder()

	h.handleGetOutboundRule(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Result().StatusCode, http.StatusNotFound)
	}
}

func TestOutbound_UpdateExisting(t *testing.T) {
	h, svc := testOutboundEnvEmpty(t)

	created := createTestRule(t, svc, "Original", 100)

	body := `{
		"name": "Updated",
		"mode": "blocklist",
		"action": "alert",
		"priority": 150,
		"enabled": true,
		"targets": [{"type": "domain", "value": "updated.com"}]
	}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/security/outbound/rules/"+created.ID, bytes.NewBufferString(body))
	req.SetPathValue("id", created.ID)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleUpdateOutboundRule(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var rule outboundRuleResponse
	if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rule.Name != "Updated" {
		t.Errorf("name = %q, want 'Updated'", rule.Name)
	}
	if rule.Action != "alert" {
		t.Errorf("action = %q, want 'alert'", rule.Action)
	}
}

func TestOutbound_UpdateDefaultRule_ToggleEnabled(t *testing.T) {
	h, _ := testOutboundEnv(t) // loads defaults

	// Default rules allow toggling enabled (other fields are preserved).
	body := `{
		"name": "Hacked Default",
		"mode": "blocklist",
		"action": "block",
		"enabled": false,
		"targets": [{"type": "domain", "value": "evil.com"}]
	}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/security/outbound/rules/default-blocklist-1", bytes.NewBufferString(body))
	req.SetPathValue("id", "default-blocklist-1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleUpdateOutboundRule(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}

	var rule outboundRuleResponse
	if err := json.NewDecoder(w.Result().Body).Decode(&rule); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rule.Enabled {
		t.Error("expected default rule to be disabled after toggle")
	}
	// Name should NOT be overwritten.
	if rule.Name == "Hacked Default" {
		t.Error("default rule name should be preserved, not overwritten")
	}
}

func TestOutbound_DeleteExisting(t *testing.T) {
	h, svc := testOutboundEnvEmpty(t)

	created := createTestRule(t, svc, "Delete Me", 100)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/v1/security/outbound/rules/"+created.ID, nil)
	req.SetPathValue("id", created.ID)
	w := httptest.NewRecorder()

	h.handleDeleteOutboundRule(w, req)

	if w.Result().StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", w.Result().StatusCode, http.StatusNoContent)
	}

	// Verify it's gone.
	_, err := svc.Get(context.Background(), created.ID)
	if err == nil {
		t.Fatal("expected rule to be deleted")
	}
}

func TestOutbound_DeleteDefaultRule(t *testing.T) {
	h, _ := testOutboundEnv(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/v1/security/outbound/rules/default-blocklist-1", nil)
	req.SetPathValue("id", "default-blocklist-1")
	w := httptest.NewRecorder()

	h.handleDeleteOutboundRule(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Result().StatusCode, http.StatusForbidden)
	}
}

func TestOutbound_TestBlocked(t *testing.T) {
	h, _ := testOutboundEnv(t) // has default blocklist with *.ngrok.io

	body := `{"domain": "evil.ngrok.io", "port": 443}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/security/outbound/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleTestOutbound(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result outboundTestResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !result.Blocked {
		t.Error("expected blocked=true for ngrok domain")
	}
	if result.Rule == nil {
		t.Error("expected matching rule in response")
	}
}

func TestOutbound_TestAllowed(t *testing.T) {
	h, _ := testOutboundEnv(t)

	body := `{"domain": "github.com", "port": 443}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/security/outbound/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleTestOutbound(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result outboundTestResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Blocked {
		t.Error("expected blocked=false for github.com")
	}
	if result.Rule != nil {
		t.Error("expected no matching rule")
	}
}

func TestOutbound_Stats(t *testing.T) {
	h, svc := testOutboundEnv(t)

	// Create a custom rule in addition to defaults.
	createTestRule(t, svc, "Custom Stat Rule", 500)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/security/outbound/stats", nil)
	w := httptest.NewRecorder()

	h.handleOutboundStats(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var stats service.OutboundStats
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatalf("decode: %v", err)
	}

	defaults := action.DefaultBlocklistRules()
	expectedTotal := len(defaults) + 1

	if stats.TotalRules != expectedTotal {
		t.Errorf("total_rules = %d, want %d", stats.TotalRules, expectedTotal)
	}
	if stats.DefaultRules != len(defaults) {
		t.Errorf("default_rules = %d, want %d", stats.DefaultRules, len(defaults))
	}
	if stats.CustomRules != 1 {
		t.Errorf("custom_rules = %d, want 1", stats.CustomRules)
	}
}

func TestOutbound_NoService_Returns503(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	h := NewAdminAPIHandler(WithAPILogger(logger))

	// Test each handler returns 503 when outboundAdminService is nil.
	tests := []struct {
		name    string
		method  string
		path    string
		handler func(http.ResponseWriter, *http.Request)
		body    string
	}{
		{"List", "GET", "/admin/api/v1/security/outbound/rules", h.handleListOutboundRules, ""},
		{"Get", "GET", "/admin/api/v1/security/outbound/rules/123", h.handleGetOutboundRule, ""},
		{"Create", "POST", "/admin/api/v1/security/outbound/rules", h.handleCreateOutboundRule, `{"name":"test"}`},
		{"Update", "PUT", "/admin/api/v1/security/outbound/rules/123", h.handleUpdateOutboundRule, `{"name":"test"}`},
		{"Delete", "DELETE", "/admin/api/v1/security/outbound/rules/123", h.handleDeleteOutboundRule, ""},
		{"Test", "POST", "/admin/api/v1/security/outbound/test", h.handleTestOutbound, `{"domain":"test.com"}`},
		{"Stats", "GET", "/admin/api/v1/security/outbound/stats", h.handleOutboundStats, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var reqBody *bytes.Buffer
			if tc.body != "" {
				reqBody = bytes.NewBufferString(tc.body)
			} else {
				reqBody = &bytes.Buffer{}
			}
			req := httptest.NewRequest(tc.method, tc.path, reqBody)
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()

			tc.handler(w, req)

			if w.Result().StatusCode != http.StatusServiceUnavailable {
				t.Errorf("%s: status = %d, want %d", tc.name, w.Result().StatusCode, http.StatusServiceUnavailable)
			}
		})
	}
}
