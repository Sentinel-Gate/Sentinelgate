package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// testPolicyHandlerEnv creates a complete test environment for policy handler tests.
func testPolicyHandlerEnv(t *testing.T) (*AdminAPIHandler, *service.PolicyAdminService) {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	defaultState := stateStore.DefaultState()
	if err := stateStore.Save(defaultState); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	// Create policy store with a default policy.
	policyStore := memory.NewPolicyStore()
	defaultPolicy := service.DefaultPolicy()
	defaultPolicy.ID = "default-policy-id"
	for i := range defaultPolicy.Rules {
		defaultPolicy.Rules[i].ID = defaultPolicy.Rules[i].Name
	}
	policyStore.AddPolicy(defaultPolicy)

	// Create policy service.
	policySvc, err := service.NewPolicyService(context.Background(), policyStore, logger)
	if err != nil {
		t.Fatalf("NewPolicyService: %v", err)
	}

	// Create admin service.
	adminSvc := service.NewPolicyAdminService(policyStore, stateStore, policySvc, logger)

	// Create API handler with the admin service.
	h := NewAdminAPIHandler(
		WithPolicyAdminService(adminSvc),
		WithAPILogger(logger),
	)

	return h, adminSvc
}

// helper: decode JSON response body into target.
func decodePolicyJSON(t *testing.T, body io.Reader, target interface{}) {
	t.Helper()
	if err := json.NewDecoder(body).Decode(target); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

// --- handleListPolicies Tests ---

func TestHandlePolicies_List(t *testing.T) {
	h, _ := testPolicyHandlerEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/policies", nil)
	w := httptest.NewRecorder()

	h.handleListPolicies(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleListPolicies status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var policies []policyResponse
	decodePolicyJSON(t, resp.Body, &policies)

	if len(policies) == 0 {
		t.Error("handleListPolicies should return at least the default policy")
	}
}

// --- handleCreatePolicy Tests ---

func TestHandlePolicies_Create_Valid(t *testing.T) {
	h, _ := testPolicyHandlerEnv(t)

	body := `{"name":"Test Policy","description":"A test","priority":10,"enabled":true,"rules":[{"name":"allow-all","priority":100,"tool_match":"*","condition":"true","action":"allow"}]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/policies", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleCreatePolicy(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("handleCreatePolicy status = %d, want %d, body: %s", resp.StatusCode, http.StatusCreated, string(bodyBytes))
	}

	var created policyResponse
	decodePolicyJSON(t, resp.Body, &created)

	if created.ID == "" {
		t.Error("handleCreatePolicy should return policy with ID")
	}
	if created.Name != "Test Policy" {
		t.Errorf("handleCreatePolicy Name = %q, want %q", created.Name, "Test Policy")
	}
	if len(created.Rules) != 1 {
		t.Errorf("handleCreatePolicy Rules count = %d, want 1", len(created.Rules))
	}
}

func TestHandlePolicies_Create_InvalidJSON(t *testing.T) {
	h, _ := testPolicyHandlerEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/policies", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleCreatePolicy(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("handleCreatePolicy invalid JSON status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestHandlePolicies_Create_EmptyName(t *testing.T) {
	h, _ := testPolicyHandlerEnv(t)

	body := `{"name":"","rules":[]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/policies", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleCreatePolicy(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("handleCreatePolicy empty name status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

// --- handleUpdatePolicy Tests ---

func TestHandlePolicies_Update_Valid(t *testing.T) {
	h, adminSvc := testPolicyHandlerEnv(t)
	ctx := context.Background()

	// Create a policy first.
	p := &policy.Policy{
		Name:    "Original",
		Enabled: true,
		Rules: []policy.Rule{
			{Name: "rule-1", Priority: 100, ToolMatch: "*", Condition: "true", Action: policy.ActionAllow},
		},
	}
	created, err := adminSvc.Create(ctx, p)
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}

	// Update via handler.
	body := `{"name":"Updated","description":"Updated desc","priority":20,"enabled":true,"rules":[{"name":"new-rule","priority":200,"tool_match":"read_*","condition":"true","action":"allow"}]}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/policies/"+created.ID, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", created.ID)
	w := httptest.NewRecorder()

	h.handleUpdatePolicy(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Fatalf("handleUpdatePolicy status = %d, want %d, body: %s", resp.StatusCode, http.StatusOK, string(bodyBytes))
	}

	var updated policyResponse
	decodePolicyJSON(t, resp.Body, &updated)

	if updated.Name != "Updated" {
		t.Errorf("handleUpdatePolicy Name = %q, want %q", updated.Name, "Updated")
	}
}

func TestHandlePolicies_Update_NotFound(t *testing.T) {
	h, _ := testPolicyHandlerEnv(t)

	body := `{"name":"Ghost","rules":[]}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/policies/nonexistent", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	h.handleUpdatePolicy(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("handleUpdatePolicy not found status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// --- handleDeletePolicy Tests ---

func TestHandlePolicies_Delete_Existing(t *testing.T) {
	h, adminSvc := testPolicyHandlerEnv(t)
	ctx := context.Background()

	// Create a deletable policy.
	p := &policy.Policy{
		Name:    "Deletable",
		Enabled: true,
		Rules: []policy.Rule{
			{Name: "rule-1", Priority: 100, ToolMatch: "*", Condition: "true", Action: policy.ActionAllow},
		},
	}
	created, err := adminSvc.Create(ctx, p)
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/policies/"+created.ID, nil)
	req.SetPathValue("id", created.ID)
	w := httptest.NewRecorder()

	h.handleDeletePolicy(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Errorf("handleDeletePolicy status = %d, want %d, body: %s", resp.StatusCode, http.StatusNoContent, string(bodyBytes))
	}
}

func TestHandlePolicies_Delete_Default(t *testing.T) {
	h, _ := testPolicyHandlerEnv(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/policies/default-policy-id", nil)
	req.SetPathValue("id", "default-policy-id")
	w := httptest.NewRecorder()

	h.handleDeletePolicy(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		bodyBytes, _ := io.ReadAll(resp.Body)
		t.Errorf("handleDeletePolicy default status = %d, want %d, body: %s", resp.StatusCode, http.StatusForbidden, string(bodyBytes))
	}
}

func TestHandlePolicies_Delete_NotFound(t *testing.T) {
	h, _ := testPolicyHandlerEnv(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/policies/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	h.handleDeletePolicy(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("handleDeletePolicy not found status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}
