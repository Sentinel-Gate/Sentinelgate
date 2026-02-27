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
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/transform"
)

// transformTestEnv holds test dependencies for transform handler tests.
type transformTestEnv struct {
	handler    *AdminAPIHandler
	store      *transform.MemoryTransformStore
	executor   *transform.TransformExecutor
	stateStore *state.FileStateStore
}

// setupTransformTestEnv creates a test environment for transform handler tests.
func setupTransformTestEnv(t *testing.T) *transformTestEnv {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	ts := transform.NewMemoryTransformStore()
	te := transform.NewTransformExecutor(logger)
	h := NewAdminAPIHandler(
		WithTransformStore(ts),
		WithTransformExecutor(te),
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)

	return &transformTestEnv{
		handler:    h,
		store:      ts,
		executor:   te,
		stateStore: stateStore,
	}
}

func TestHandleListTransforms_Empty(t *testing.T) {
	env := setupTransformTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/transforms", nil)
	w := httptest.NewRecorder()

	env.handler.handleListTransforms(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var items []transformResponse
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if len(items) != 0 {
		t.Fatalf("transform count = %d, want 0", len(items))
	}
}

func TestHandleCreateTransform_Valid(t *testing.T) {
	env := setupTransformTestEnv(t)

	body := transformRequest{
		Name:      "Redact SSN",
		Type:      "redact",
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config: transform.TransformConfig{
			Patterns:    []string{`\d{3}-\d{2}-\d{4}`},
			Replacement: "[SSN REDACTED]",
		},
	}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/transforms", bytes.NewReader(data))
	w := httptest.NewRecorder()

	env.handler.handleCreateTransform(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}

	var item transformResponse
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if item.ID == "" {
		t.Error("ID should not be empty")
	}
	if item.Name != "Redact SSN" {
		t.Errorf("Name = %q, want %q", item.Name, "Redact SSN")
	}
	if item.Type != "redact" {
		t.Errorf("Type = %q, want %q", item.Type, "redact")
	}
	if item.ToolMatch != "*" {
		t.Errorf("ToolMatch = %q, want %q", item.ToolMatch, "*")
	}
	if item.Priority != 10 {
		t.Errorf("Priority = %d, want 10", item.Priority)
	}
	if !item.Enabled {
		t.Error("Enabled should be true")
	}

	// Verify persistence in state.json.
	appState, err := env.stateStore.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(appState.Transforms) != 1 {
		t.Fatalf("state transforms count = %d, want 1", len(appState.Transforms))
	}
	if appState.Transforms[0].Name != "Redact SSN" {
		t.Errorf("state transform name = %q, want %q", appState.Transforms[0].Name, "Redact SSN")
	}
}

func TestHandleCreateTransform_InvalidType(t *testing.T) {
	env := setupTransformTestEnv(t)

	body := transformRequest{
		Name:      "Bad Type",
		Type:      "invalid_type",
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
	}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/transforms", bytes.NewReader(data))
	w := httptest.NewRecorder()

	env.handler.handleCreateTransform(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestHandleCreateTransform_BadRegex(t *testing.T) {
	env := setupTransformTestEnv(t)

	body := transformRequest{
		Name:      "Bad Regex",
		Type:      "redact",
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config: transform.TransformConfig{
			Patterns: []string{`[invalid regex`},
		},
	}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/transforms", bytes.NewReader(data))
	w := httptest.NewRecorder()

	env.handler.handleCreateTransform(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	// Verify error message mentions regex.
	var errResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errResp["error"] == "" {
		t.Error("error message should not be empty")
	}
}

func TestHandleGetTransform(t *testing.T) {
	env := setupTransformTestEnv(t)

	// Create a rule first.
	createBody := transformRequest{
		Name:      "Test Rule",
		Type:      "truncate",
		ToolMatch: "read_file",
		Priority:  5,
		Enabled:   true,
		Config: transform.TransformConfig{
			MaxLines: 100,
		},
	}
	createData, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/api/v1/transforms", bytes.NewReader(createData))
	createW := httptest.NewRecorder()
	env.handler.handleCreateTransform(createW, createReq)

	if createW.Result().StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want %d", createW.Result().StatusCode, http.StatusCreated)
	}

	var created transformResponse
	_ = json.NewDecoder(createW.Result().Body).Decode(&created)

	// GET by ID.
	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/transforms/"+created.ID, nil)
	req.SetPathValue("id", created.ID)
	w := httptest.NewRecorder()

	env.handler.handleGetTransform(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var item transformResponse
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if item.ID != created.ID {
		t.Errorf("ID = %q, want %q", item.ID, created.ID)
	}
	if item.Name != "Test Rule" {
		t.Errorf("Name = %q, want %q", item.Name, "Test Rule")
	}
}

func TestHandleGetTransform_NotFound(t *testing.T) {
	env := setupTransformTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/transforms/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	env.handler.handleGetTransform(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestHandleUpdateTransform(t *testing.T) {
	env := setupTransformTestEnv(t)

	// Create a rule first.
	createBody := transformRequest{
		Name:      "Original Name",
		Type:      "inject",
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config: transform.TransformConfig{
			Prepend: "WARNING: unverified output",
		},
	}
	createData, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/api/v1/transforms", bytes.NewReader(createData))
	createW := httptest.NewRecorder()
	env.handler.handleCreateTransform(createW, createReq)

	var created transformResponse
	_ = json.NewDecoder(createW.Result().Body).Decode(&created)

	// Update the rule.
	updateBody := transformRequest{
		Name:      "Updated Name",
		Type:      "inject",
		ToolMatch: "file_*",
		Priority:  20,
		Enabled:   false,
		Config: transform.TransformConfig{
			Prepend: "UPDATED WARNING",
			Append:  "END OF OUTPUT",
		},
	}
	updateData, _ := json.Marshal(updateBody)
	updateReq := httptest.NewRequest(http.MethodPut, "/admin/api/v1/transforms/"+created.ID, bytes.NewReader(updateData))
	updateReq.SetPathValue("id", created.ID)
	updateW := httptest.NewRecorder()

	env.handler.handleUpdateTransform(updateW, updateReq)

	resp := updateW.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var updated transformResponse
	if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if updated.ID != created.ID {
		t.Errorf("ID changed: %q -> %q", created.ID, updated.ID)
	}
	if updated.Name != "Updated Name" {
		t.Errorf("Name = %q, want %q", updated.Name, "Updated Name")
	}
	if updated.ToolMatch != "file_*" {
		t.Errorf("ToolMatch = %q, want %q", updated.ToolMatch, "file_*")
	}
	if updated.Priority != 20 {
		t.Errorf("Priority = %d, want 20", updated.Priority)
	}
	if updated.Enabled {
		t.Error("Enabled should be false after update")
	}
	if updated.CreatedAt.IsZero() {
		t.Error("CreatedAt should be preserved")
	}
	if !updated.UpdatedAt.After(created.UpdatedAt) {
		t.Error("UpdatedAt should be newer than original")
	}
}

func TestHandleDeleteTransform(t *testing.T) {
	env := setupTransformTestEnv(t)

	// Create a rule first.
	createBody := transformRequest{
		Name:      "To Delete",
		Type:      "truncate",
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config: transform.TransformConfig{
			MaxBytes: 1000,
		},
	}
	createData, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, "/admin/api/v1/transforms", bytes.NewReader(createData))
	createW := httptest.NewRecorder()
	env.handler.handleCreateTransform(createW, createReq)

	var created transformResponse
	_ = json.NewDecoder(createW.Result().Body).Decode(&created)

	// Delete the rule.
	deleteReq := httptest.NewRequest(http.MethodDelete, "/admin/api/v1/transforms/"+created.ID, nil)
	deleteReq.SetPathValue("id", created.ID)
	deleteW := httptest.NewRecorder()

	env.handler.handleDeleteTransform(deleteW, deleteReq)

	resp := deleteW.Result()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	// Verify GET returns 404 now.
	getReq := httptest.NewRequest(http.MethodGet, "/admin/api/v1/transforms/"+created.ID, nil)
	getReq.SetPathValue("id", created.ID)
	getW := httptest.NewRecorder()
	env.handler.handleGetTransform(getW, getReq)

	if getW.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("get after delete status = %d, want %d", getW.Result().StatusCode, http.StatusNotFound)
	}

	// Verify persistence: state.json has no transforms.
	appState, err := env.stateStore.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if len(appState.Transforms) != 0 {
		t.Fatalf("state transforms count = %d, want 0", len(appState.Transforms))
	}
}

func TestHandleTestTransform_Redact(t *testing.T) {
	env := setupTransformTestEnv(t)

	body := transformTestRequest{
		Text: "My SSN is 123-45-6789 and my phone is 555-1234",
		Rules: []transformRequest{
			{
				Name:      "Redact SSN",
				Type:      "redact",
				ToolMatch: "*",
				Priority:  10,
				Enabled:   true,
				Config: transform.TransformConfig{
					Patterns:    []string{`\d{3}-\d{2}-\d{4}`},
					Replacement: "[SSN REDACTED]",
				},
			},
		},
	}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/transforms/test", bytes.NewReader(data))
	w := httptest.NewRecorder()

	env.handler.handleTestTransform(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result transformTestResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if result.Output == "" {
		t.Error("output should not be empty")
	}
	// SSN should be redacted.
	if bytes.Contains([]byte(result.Output), []byte("123-45-6789")) {
		t.Error("SSN should have been redacted from output")
	}
	if !bytes.Contains([]byte(result.Output), []byte("[SSN REDACTED]")) {
		t.Error("output should contain redaction placeholder")
	}
	if len(result.Results) != 1 {
		t.Fatalf("results count = %d, want 1", len(result.Results))
	}
	if !result.Results[0].Applied {
		t.Error("transform should have been applied")
	}
}

func TestHandleTestTransform_MultipleRules(t *testing.T) {
	env := setupTransformTestEnv(t)

	body := transformTestRequest{
		Text: "Secret: password123\nLine 1\nLine 2\nLine 3\nLine 4\nLine 5",
		Rules: []transformRequest{
			{
				Name:      "Redact Secrets",
				Type:      "redact",
				ToolMatch: "*",
				Priority:  1,
				Enabled:   true,
				Config: transform.TransformConfig{
					Patterns:    []string{`password\w+`},
					Replacement: "[REDACTED]",
				},
			},
			{
				Name:      "Truncate Lines",
				Type:      "truncate",
				ToolMatch: "*",
				Priority:  2,
				Enabled:   true,
				Config: transform.TransformConfig{
					MaxLines: 3,
				},
			},
		},
	}
	data, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/transforms/test", bytes.NewReader(data))
	w := httptest.NewRecorder()

	env.handler.handleTestTransform(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result transformTestResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if len(result.Results) != 2 {
		t.Fatalf("results count = %d, want 2", len(result.Results))
	}

	// Both rules should have been applied.
	for i, r := range result.Results {
		if !r.Applied {
			t.Errorf("result[%d] (%s) should have been applied", i, r.RuleName)
		}
	}
}

func TestHandleListTransforms_AfterCRUD(t *testing.T) {
	env := setupTransformTestEnv(t)

	// Create two rules.
	rules := []transformRequest{
		{
			Name:      "Rule A",
			Type:      "redact",
			ToolMatch: "*",
			Priority:  10,
			Enabled:   true,
			Config: transform.TransformConfig{
				Patterns: []string{`secret`},
			},
		},
		{
			Name:      "Rule B",
			Type:      "truncate",
			ToolMatch: "read_*",
			Priority:  20,
			Enabled:   true,
			Config: transform.TransformConfig{
				MaxLines: 50,
			},
		},
	}

	for _, rule := range rules {
		data, _ := json.Marshal(rule)
		req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/transforms", bytes.NewReader(data))
		w := httptest.NewRecorder()
		env.handler.handleCreateTransform(w, req)
		if w.Result().StatusCode != http.StatusCreated {
			t.Fatalf("create status = %d, want %d", w.Result().StatusCode, http.StatusCreated)
		}
	}

	// List should return 2 rules.
	listReq := httptest.NewRequest(http.MethodGet, "/admin/api/v1/transforms", nil)
	listW := httptest.NewRecorder()
	env.handler.handleListTransforms(listW, listReq)

	if listW.Result().StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listW.Result().StatusCode, http.StatusOK)
	}

	var items []transformResponse
	if err := json.NewDecoder(listW.Result().Body).Decode(&items); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if len(items) != 2 {
		t.Fatalf("transform count = %d, want 2", len(items))
	}
}
