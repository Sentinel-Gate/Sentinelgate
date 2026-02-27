package admin

import (
	"context"
	"encoding/json"
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

// testTemplateHandlerEnv creates a test environment for template handler tests.
// It sets up a real TemplateService backed by MemoryPolicyStore + PolicyService + PolicyAdminService.
func testTemplateHandlerEnv(t *testing.T) (*AdminAPIHandler, *service.PolicyAdminService) {
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

	// Create template service.
	tmplSvc := service.NewTemplateService(adminSvc, logger)

	// Create API handler.
	h := NewAdminAPIHandler(
		WithPolicyAdminService(adminSvc),
		WithTemplateService(tmplSvc),
		WithAPILogger(logger),
	)

	return h, adminSvc
}

func TestHandleListTemplates(t *testing.T) {
	h, _ := testTemplateHandlerEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/templates", nil)
	w := httptest.NewRecorder()

	h.handleListTemplates(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var items []templateListItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if len(items) != 7 {
		t.Fatalf("template count = %d, want 7", len(items))
	}

	// Verify each item has required fields.
	for _, item := range items {
		if item.ID == "" {
			t.Error("template ID is empty")
		}
		if item.Name == "" {
			t.Errorf("template %q Name is empty", item.ID)
		}
		if item.Description == "" {
			t.Errorf("template %q Description is empty", item.ID)
		}
		if item.Category == "" {
			t.Errorf("template %q Category is empty", item.ID)
		}
		if item.Icon == "" {
			t.Errorf("template %q Icon is empty", item.ID)
		}
		if item.RuleCount == 0 {
			t.Errorf("template %q RuleCount = 0", item.ID)
		}
	}

	// Verify "safe-coding" appears in the list.
	found := false
	for _, item := range items {
		if item.ID == "safe-coding" {
			found = true
			break
		}
	}
	if !found {
		t.Error("safe-coding template not found in list")
	}
}

func TestHandleGetTemplate_Found(t *testing.T) {
	h, _ := testTemplateHandlerEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/templates/safe-coding", nil)
	req.SetPathValue("id", "safe-coding")
	w := httptest.NewRecorder()

	h.handleGetTemplate(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var detail templateDetailResponse
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if detail.ID != "safe-coding" {
		t.Errorf("ID = %q, want %q", detail.ID, "safe-coding")
	}
	if detail.Name != "Safe Coding" {
		t.Errorf("Name = %q, want %q", detail.Name, "Safe Coding")
	}
	if len(detail.Rules) == 0 {
		t.Fatal("rules array is empty")
	}

	// Verify each rule has required fields.
	for i, rule := range detail.Rules {
		if rule.Name == "" {
			t.Errorf("rule[%d] Name is empty", i)
		}
		if rule.ToolMatch == "" {
			t.Errorf("rule[%d] ToolMatch is empty", i)
		}
		if rule.Condition == "" {
			t.Errorf("rule[%d] Condition is empty", i)
		}
		if rule.Action == "" {
			t.Errorf("rule[%d] Action is empty", i)
		}
	}
}

func TestHandleGetTemplate_NotFound(t *testing.T) {
	h, _ := testTemplateHandlerEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/templates/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	h.handleGetTemplate(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	var errResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if errResp["error"] != "template not found" {
		t.Errorf("error message = %q, want %q", errResp["error"], "template not found")
	}
}

func TestHandleApplyTemplate_Success(t *testing.T) {
	h, adminSvc := testTemplateHandlerEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/templates/read-only/apply", nil)
	req.SetPathValue("id", "read-only")
	w := httptest.NewRecorder()

	h.handleApplyTemplate(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	var created policyResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if created.ID == "" {
		t.Error("created policy ID is empty")
	}
	if created.Name != "Read Only" {
		t.Errorf("Name = %q, want %q", created.Name, "Read Only")
	}
	if len(created.Rules) == 0 {
		t.Error("created policy has no rules")
	}

	// Verify the policy actually exists in the store.
	policies, err := adminSvc.List(context.Background())
	if err != nil {
		t.Fatalf("List(): %v", err)
	}

	found := false
	for _, p := range policies {
		if p.ID == created.ID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("policy %q not found in store after apply", created.ID)
	}
}

func TestHandleApplyTemplate_NotFound(t *testing.T) {
	h, _ := testTemplateHandlerEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/templates/nonexistent/apply", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	h.handleApplyTemplate(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestHandleApplyTemplate_IndependentPolicies(t *testing.T) {
	h, _ := testTemplateHandlerEnv(t)

	// Apply the same template twice.
	var ids [2]string
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/templates/lockdown/apply", nil)
		req.SetPathValue("id", "lockdown")
		w := httptest.NewRecorder()

		h.handleApplyTemplate(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("apply #%d status = %d, want %d", i+1, resp.StatusCode, http.StatusCreated)
		}

		var created policyResponse
		if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
			t.Fatalf("apply #%d decode JSON: %v", i+1, err)
		}
		ids[i] = created.ID
	}

	if ids[0] == ids[1] {
		t.Errorf("applying same template twice yielded same policy ID: %s", ids[0])
	}
}

// Verify that policy.AllTemplates returns at least one template with RuleCount > 0
// for the "audit-only" template (which has exactly 1 rule).
func TestTemplateListIncludesAuditOnly(t *testing.T) {
	templates := policy.AllTemplates()
	for _, tmpl := range templates {
		if tmpl.ID == "audit-only" {
			if len(tmpl.Rules) != 1 {
				t.Errorf("audit-only rule count = %d, want 1", len(tmpl.Rules))
			}
			return
		}
	}
	t.Error("audit-only template not found")
}
