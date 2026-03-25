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

// --- test environment ---

type templateTestEnv struct {
	handler         *AdminAPIHandler
	templateService *service.TemplateService
	policyAdmin     *service.PolicyAdminService
	stateStore      *state.FileStateStore
	mux             http.Handler
}

const templateCSRFToken = "test-csrf-token-for-template-tests"

func setupTemplateTestEnv(t *testing.T) *templateTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
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

	// Create admin service and template service.
	adminSvc := service.NewPolicyAdminService(policyStore, stateStore, policySvc, logger)
	tmplSvc := service.NewTemplateService(adminSvc, logger)

	handler := NewAdminAPIHandler(
		WithPolicyAdminService(adminSvc),
		WithTemplateService(tmplSvc),
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	return &templateTestEnv{
		handler:         handler,
		templateService: tmplSvc,
		policyAdmin:     adminSvc,
		stateStore:      stateStore,
		mux:             handler.Routes(),
	}
}

func (e *templateTestEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
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
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: templateCSRFToken})
		req.Header.Set("X-CSRF-Token", templateCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeTemplateJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

// --- Tests ---

func TestHandleListTemplates(t *testing.T) {
	env := setupTemplateTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/templates", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/templates status = %d, want %d", rec.Code, http.StatusOK)
	}

	var items []templateListItem
	decodeTemplateJSON(t, rec, &items)
	if len(items) == 0 {
		t.Fatal("expected non-empty template list")
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
}

func TestHandleGetTemplate(t *testing.T) {
	env := setupTemplateTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/templates/safe-coding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/templates/safe-coding status = %d, want %d", rec.Code, http.StatusOK)
	}

	var detail templateDetailResponse
	decodeTemplateJSON(t, rec, &detail)
	if detail.ID != "safe-coding" {
		t.Errorf("ID = %q, want %q", detail.ID, "safe-coding")
	}
	if detail.Name == "" {
		t.Error("Name is empty")
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
	env := setupTemplateTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/templates/nonexistent", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET nonexistent template status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	var errResp map[string]string
	decodeTemplateJSON(t, rec, &errResp)
	if errResp["error"] != "template not found" {
		t.Errorf("error message = %q, want %q", errResp["error"], "template not found")
	}
}

func TestHandleApplyTemplate(t *testing.T) {
	env := setupTemplateTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/templates/read-only/apply", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST apply template status = %d, want %d (body=%s)", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var created policyResponse
	decodeTemplateJSON(t, rec, &created)
	if created.ID == "" {
		t.Error("created policy ID is empty")
	}
	if len(created.Rules) == 0 {
		t.Error("created policy has no rules")
	}

	// Verify the policy actually exists in the store.
	policies, err := env.policyAdmin.List(context.Background())
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
	env := setupTemplateTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/templates/nonexistent/apply", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST apply nonexistent template status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleListTemplates_NilService(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	// Create handler without template service.
	handler := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)
	mux := handler.Routes()

	req := httptest.NewRequest("GET", "/admin/api/v1/templates", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GET templates nil service status = %d, want %d", rec.Code, http.StatusInternalServerError)
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
