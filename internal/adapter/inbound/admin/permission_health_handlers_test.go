package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// --- test mocks for permission health handlers ---

type phMockAuditReader struct {
	records []audit.AuditRecord
}

func (m *phMockAuditReader) Query(_ context.Context, filter audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	var result []audit.AuditRecord
	for _, r := range m.records {
		if filter.UserID != "" && r.IdentityID != filter.UserID {
			continue
		}
		result = append(result, r)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result, "", nil
}

type phMockToolLister struct {
	tools []string
}

func (m *phMockToolLister) GetAllToolNames() []string { return m.tools }

type phMockIdentityLister struct {
	identities []service.IdentityInfo
}

func (m *phMockIdentityLister) GetAllIdentities() []service.IdentityInfo { return m.identities }

type phMockPolicyEval struct{}

func (m *phMockPolicyEval) Evaluate(_ context.Context, _ policy.EvaluationContext) (policy.Decision, error) {
	return policy.Decision{Allowed: true, Reason: "allow"}, nil
}

func newTestPHHandler() (*AdminAPIHandler, *service.PermissionHealthService) {
	now := time.Now()
	reader := &phMockAuditReader{
		records: []audit.AuditRecord{
			{IdentityID: "a1", ToolName: "read_file", Timestamp: now, Decision: "allow"},
		},
	}
	identities := []service.IdentityInfo{
		{ID: "a1", Name: "Agent 1", Roles: []string{"user"}},
	}
	svc := service.NewPermissionHealthService(
		reader,
		&phMockToolLister{tools: []string{"read_file", "write_file"}},
		&phMockIdentityLister{identities: identities},
		&phMockPolicyEval{},
		slog.Default(),
	)

	h := NewAdminAPIHandler()
	h.SetPermissionHealthService(svc)
	return h, svc
}

func TestHandleGetAllPermissionHealth(t *testing.T) {
	h, _ := newTestPHHandler()
	req := httptest.NewRequest("GET", "/admin/api/v1/permissions/health", nil)
	w := httptest.NewRecorder()
	h.handleGetAllPermissionHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var reports []service.PermissionHealthReport
	if err := json.Unmarshal(w.Body.Bytes(), &reports); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(reports) != 1 {
		t.Errorf("expected 1 report, got %d", len(reports))
	}
}

func TestHandleGetPermissionHealth_Single(t *testing.T) {
	h, _ := newTestPHHandler()
	req := httptest.NewRequest("GET", "/admin/api/v1/permissions/health/a1", nil)
	req.SetPathValue("identity_id", "a1")
	w := httptest.NewRecorder()
	h.handleGetPermissionHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleGetPermissionHealth_NotFound(t *testing.T) {
	h, _ := newTestPHHandler()
	req := httptest.NewRequest("GET", "/admin/api/v1/permissions/health/nonexistent", nil)
	req.SetPathValue("identity_id", "nonexistent")
	w := httptest.NewRecorder()
	h.handleGetPermissionHealth(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleGetPermissionSuggestions(t *testing.T) {
	h, _ := newTestPHHandler()
	req := httptest.NewRequest("GET", "/admin/api/v1/permissions/suggestions/a1", nil)
	req.SetPathValue("identity_id", "a1")
	w := httptest.NewRecorder()
	h.handleGetPermissionSuggestions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleApplySuggestions(t *testing.T) {
	h, _ := newTestPHHandler()
	body := map[string]interface{}{
		"identity_id":    "a1",
		"suggestion_ids": []string{"suggest-a1-0"},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/admin/api/v1/permissions/apply", bytes.NewReader(b))
	w := httptest.NewRecorder()
	h.handleApplySuggestions(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleApplySuggestions_MissingIdentity(t *testing.T) {
	h, _ := newTestPHHandler()
	body := map[string]interface{}{
		"suggestion_ids": []string{"s1"},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/admin/api/v1/permissions/apply", bytes.NewReader(b))
	w := httptest.NewRecorder()
	h.handleApplySuggestions(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleGetPermissionHealthConfig(t *testing.T) {
	h, _ := newTestPHHandler()
	req := httptest.NewRequest("GET", "/admin/api/v1/permissions/config", nil)
	w := httptest.NewRecorder()
	h.handleGetPermissionHealthConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var cfg service.PermissionHealthConfig
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != service.ShadowModeShadow {
		t.Errorf("expected shadow, got %s", cfg.Mode)
	}
}

func TestHandleUpdatePermissionHealthConfig(t *testing.T) {
	h, _ := newTestPHHandler()
	body := map[string]interface{}{
		"mode":              "suggest",
		"learning_days":     7,
		"grace_period_days": 3,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/admin/api/v1/permissions/config", bytes.NewReader(b))
	w := httptest.NewRecorder()
	h.handleUpdatePermissionHealthConfig(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdatePermissionHealthConfig_Persistence(t *testing.T) {
	h, svc := newTestPHHandler()

	// Wire a real stateStore.
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}
	h.stateStore = stateStore

	body := map[string]interface{}{
		"mode":              "suggest",
		"learning_days":     7,
		"grace_period_days": 3,
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/admin/api/v1/permissions/config", bytes.NewReader(b))
	w := httptest.NewRecorder()
	h.handleUpdatePermissionHealthConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify in-memory service was updated.
	cfg := svc.Config()
	if cfg.Mode != service.ShadowModeSuggest {
		t.Errorf("in-memory mode = %s, want suggest", cfg.Mode)
	}

	// Verify state.json was updated.
	appState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if appState.PermissionHealthConfig == nil {
		t.Fatal("PermissionHealthConfig not persisted to state.json")
	}
	if appState.PermissionHealthConfig.Mode != "suggest" {
		t.Errorf("persisted mode = %s, want suggest", appState.PermissionHealthConfig.Mode)
	}
	if appState.PermissionHealthConfig.LearningDays != 7 {
		t.Errorf("persisted learning_days = %d, want 7", appState.PermissionHealthConfig.LearningDays)
	}
}

func TestHandleUpdatePermissionHealthConfig_InvalidMode(t *testing.T) {
	h, _ := newTestPHHandler()
	body := map[string]interface{}{
		"mode": "invalid",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/admin/api/v1/permissions/config", bytes.NewReader(b))
	w := httptest.NewRecorder()
	h.handleUpdatePermissionHealthConfig(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleNoService(t *testing.T) {
	h := NewAdminAPIHandler()
	// No permission health service set
	req := httptest.NewRequest("GET", "/admin/api/v1/permissions/health", nil)
	w := httptest.NewRecorder()
	h.handleGetAllPermissionHealth(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}
