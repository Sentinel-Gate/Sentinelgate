package admin

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/quota"
)

// quotaTestEnv holds test dependencies for quota handler tests.
type quotaTestEnv struct {
	handler    *AdminAPIHandler
	quotaStore *quota.MemoryQuotaStore
	stateStore *state.FileStateStore
}

// setupQuotaTestEnv creates a test environment for quota handler tests.
func setupQuotaTestEnv(t *testing.T) *quotaTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	qs := quota.NewMemoryQuotaStore()
	h := NewAdminAPIHandler(
		WithQuotaStore(qs),
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)

	return &quotaTestEnv{
		handler:    h,
		quotaStore: qs,
		stateStore: stateStore,
	}
}

func TestHandleListQuotas_Empty(t *testing.T) {
	env := setupQuotaTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/quotas", nil)
	w := httptest.NewRecorder()

	env.handler.handleListQuotas(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var items []quotaResponse
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if len(items) != 0 {
		t.Fatalf("quota count = %d, want 0", len(items))
	}
}

func TestHandleListQuotas_WithData(t *testing.T) {
	env := setupQuotaTestEnv(t)

	// Seed two quotas directly in store.
	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_ = env.quotaStore.Put(ctx, &quota.QuotaConfig{
		IdentityID:         "id-1",
		MaxCallsPerSession: 100,
		Action:             quota.QuotaActionDeny,
		Enabled:            true,
	})
	_ = env.quotaStore.Put(ctx, &quota.QuotaConfig{
		IdentityID:        "id-2",
		MaxCallsPerMinute: 10,
		Action:            quota.QuotaActionWarn,
		Enabled:           true,
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/quotas", nil)
	w := httptest.NewRecorder()

	env.handler.handleListQuotas(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var items []quotaResponse
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if len(items) != 2 {
		t.Fatalf("quota count = %d, want 2", len(items))
	}
}

func TestHandleGetQuota_Found(t *testing.T) {
	env := setupQuotaTestEnv(t)

	ctx := httptest.NewRequest(http.MethodGet, "/", nil).Context()
	_ = env.quotaStore.Put(ctx, &quota.QuotaConfig{
		IdentityID:         "id-1",
		MaxCallsPerSession: 50,
		Action:             quota.QuotaActionDeny,
		Enabled:            true,
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/quotas/id-1", nil)
	req.SetPathValue("identity_id", "id-1")
	w := httptest.NewRecorder()

	env.handler.handleGetQuota(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var item quotaResponse
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if item.IdentityID != "id-1" {
		t.Errorf("IdentityID = %q, want %q", item.IdentityID, "id-1")
	}
	if item.MaxCallsPerSession != 50 {
		t.Errorf("MaxCallsPerSession = %d, want 50", item.MaxCallsPerSession)
	}
	if item.Action != "deny" {
		t.Errorf("Action = %q, want %q", item.Action, "deny")
	}
}

func TestHandleGetQuota_NotFound(t *testing.T) {
	env := setupQuotaTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/quotas/nonexistent", nil)
	req.SetPathValue("identity_id", "nonexistent")
	w := httptest.NewRecorder()

	env.handler.handleGetQuota(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestHandlePutQuota_Create(t *testing.T) {
	env := setupQuotaTestEnv(t)

	body := quotaRequest{
		MaxCallsPerSession: 100,
		MaxWritesPerSession: 20,
		Action:             "deny",
		Enabled:            true,
	}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/quotas/id-1", bytes.NewReader(data))
	req.SetPathValue("identity_id", "id-1")
	w := httptest.NewRecorder()

	env.handler.handlePutQuota(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var item quotaResponse
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if item.IdentityID != "id-1" {
		t.Errorf("IdentityID = %q, want %q", item.IdentityID, "id-1")
	}
	if item.MaxCallsPerSession != 100 {
		t.Errorf("MaxCallsPerSession = %d, want 100", item.MaxCallsPerSession)
	}
	if item.MaxWritesPerSession != 20 {
		t.Errorf("MaxWritesPerSession = %d, want 20", item.MaxWritesPerSession)
	}

	// Verify persistence: check state.json has the quota.
	appState, err := env.stateStore.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(appState.Quotas) != 1 {
		t.Fatalf("state quotas count = %d, want 1", len(appState.Quotas))
	}
	if appState.Quotas[0].IdentityID != "id-1" {
		t.Errorf("state quota identity = %q, want %q", appState.Quotas[0].IdentityID, "id-1")
	}
}

func TestHandlePutQuota_Update(t *testing.T) {
	env := setupQuotaTestEnv(t)

	// Create initial quota.
	body := quotaRequest{
		MaxCallsPerSession: 100,
		Action:             "deny",
		Enabled:            true,
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/quotas/id-1", bytes.NewReader(data))
	req.SetPathValue("identity_id", "id-1")
	w := httptest.NewRecorder()
	env.handler.handlePutQuota(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("create status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}

	// Update quota.
	body.MaxCallsPerSession = 200
	body.Action = "warn"
	data, _ = json.Marshal(body)
	req = httptest.NewRequest(http.MethodPut, "/admin/api/v1/quotas/id-1", bytes.NewReader(data))
	req.SetPathValue("identity_id", "id-1")
	w = httptest.NewRecorder()
	env.handler.handlePutQuota(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var item quotaResponse
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if item.MaxCallsPerSession != 200 {
		t.Errorf("MaxCallsPerSession = %d, want 200", item.MaxCallsPerSession)
	}
	if item.Action != "warn" {
		t.Errorf("Action = %q, want %q", item.Action, "warn")
	}
}

func TestHandlePutQuota_WithToolLimits(t *testing.T) {
	env := setupQuotaTestEnv(t)

	body := quotaRequest{
		MaxCallsPerSession: 100,
		Action:             "deny",
		Enabled:            true,
		ToolLimits:         map[string]int64{"write_file": 5, "read_file": 10},
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/quotas/id-tl", bytes.NewReader(data))
	req.SetPathValue("identity_id", "id-tl")
	w := httptest.NewRecorder()
	env.handler.handlePutQuota(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var item quotaResponse
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if len(item.ToolLimits) != 2 {
		t.Fatalf("ToolLimits count = %d, want 2", len(item.ToolLimits))
	}
	if item.ToolLimits["write_file"] != 5 {
		t.Errorf("ToolLimits[write_file] = %d, want 5", item.ToolLimits["write_file"])
	}
	if item.ToolLimits["read_file"] != 10 {
		t.Errorf("ToolLimits[read_file] = %d, want 10", item.ToolLimits["read_file"])
	}

	// Verify persistence in state.json.
	appState, err := env.stateStore.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(appState.Quotas) != 1 {
		t.Fatalf("state quotas count = %d, want 1", len(appState.Quotas))
	}
	if len(appState.Quotas[0].ToolLimits) != 2 {
		t.Fatalf("state ToolLimits count = %d, want 2", len(appState.Quotas[0].ToolLimits))
	}

	// Verify GET returns tool_limits.
	req2 := httptest.NewRequest(http.MethodGet, "/admin/api/v1/quotas/id-tl", nil)
	req2.SetPathValue("identity_id", "id-tl")
	w2 := httptest.NewRecorder()
	env.handler.handleGetQuota(w2, req2)
	resp2 := w2.Result()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", resp2.StatusCode, http.StatusOK)
	}
	var getItem quotaResponse
	if err := json.NewDecoder(resp2.Body).Decode(&getItem); err != nil {
		t.Fatalf("GET decode: %v", err)
	}
	if getItem.ToolLimits["write_file"] != 5 {
		t.Errorf("GET ToolLimits[write_file] = %d, want 5", getItem.ToolLimits["write_file"])
	}
}

func TestHandlePutQuota_InvalidAction(t *testing.T) {
	env := setupQuotaTestEnv(t)

	body := quotaRequest{
		MaxCallsPerSession: 100,
		Action:             "invalid",
		Enabled:            true,
	}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/quotas/id-1", bytes.NewReader(data))
	req.SetPathValue("identity_id", "id-1")
	w := httptest.NewRecorder()

	env.handler.handlePutQuota(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestHandlePutQuota_NegativeLimit(t *testing.T) {
	env := setupQuotaTestEnv(t)

	body := quotaRequest{
		MaxCallsPerSession: -5,
		Action:             "deny",
		Enabled:            true,
	}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/quotas/id-1", bytes.NewReader(data))
	req.SetPathValue("identity_id", "id-1")
	w := httptest.NewRecorder()

	env.handler.handlePutQuota(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestHandleDeleteQuota(t *testing.T) {
	env := setupQuotaTestEnv(t)

	// Create a quota first.
	body := quotaRequest{
		MaxCallsPerSession: 100,
		Action:             "deny",
		Enabled:            true,
	}
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/quotas/id-1", bytes.NewReader(data))
	req.SetPathValue("identity_id", "id-1")
	w := httptest.NewRecorder()
	env.handler.handlePutQuota(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("create status = %d, want %d", w.Result().StatusCode, http.StatusOK)
	}

	// Delete it.
	req = httptest.NewRequest(http.MethodDelete, "/admin/api/v1/quotas/id-1", nil)
	req.SetPathValue("identity_id", "id-1")
	w = httptest.NewRecorder()
	env.handler.handleDeleteQuota(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// Verify GET returns 404 now.
	req = httptest.NewRequest(http.MethodGet, "/admin/api/v1/quotas/id-1", nil)
	req.SetPathValue("identity_id", "id-1")
	w = httptest.NewRecorder()
	env.handler.handleGetQuota(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("get after delete status = %d, want %d", w.Result().StatusCode, http.StatusNotFound)
	}

	// Verify persistence: state.json has no quotas.
	appState, err := env.stateStore.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(appState.Quotas) != 0 {
		t.Fatalf("state quotas count = %d, want 0", len(appState.Quotas))
	}
}
