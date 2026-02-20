package admin

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// mockPolicyEvalEngine implements policy.PolicyEngine for handler tests.
type mockPolicyEvalEngine struct {
	decision policy.Decision
	err      error
}

func (m *mockPolicyEvalEngine) Evaluate(_ context.Context, _ policy.EvaluationContext) (policy.Decision, error) {
	return m.decision, m.err
}

func setupPolicyEvalHandler(t *testing.T, engine policy.PolicyEngine) *AdminAPIHandler {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)

	policyStore := memory.NewPolicyStore()

	evalService := service.NewPolicyEvaluationService(engine, policyStore, stateStore, logger)

	h := NewAdminAPIHandler(
		WithPolicyEvalService(evalService),
		WithAPILogger(logger),
	)
	return h
}

func TestHandlePolicyEvaluate_Allow(t *testing.T) {
	engine := &mockPolicyEvalEngine{
		decision: policy.Decision{
			Allowed:  true,
			RuleID:   "admin-bypass",
			RuleName: "Admin Bypass",
			Reason:   "matched rule admin-bypass",
		},
	}
	h := setupPolicyEvalHandler(t, engine)

	body := `{
		"action_type": "tool_call",
		"action_name": "read_file",
		"protocol": "mcp",
		"identity_name": "alice",
		"identity_roles": ["admin"]
	}`

	req := httptest.NewRequest("POST", "/admin/api/v1/policy/evaluate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handlePolicyEvaluate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp service.PolicyEvaluateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("expected decision 'allow', got %q", resp.Decision)
	}
	if resp.RequestID == "" {
		t.Error("expected non-empty request_id")
	}
}

func TestHandlePolicyEvaluate_Deny(t *testing.T) {
	engine := &mockPolicyEvalEngine{
		decision: policy.Decision{
			Allowed:  false,
			RuleID:   "block-exec",
			RuleName: "Block Dangerous Execution",
			Reason:   "matched rule block-exec",
		},
	}
	h := setupPolicyEvalHandler(t, engine)

	body := `{
		"action_type": "tool_call",
		"action_name": "exec_command",
		"protocol": "mcp",
		"identity_name": "bob",
		"identity_roles": ["user"]
	}`

	req := httptest.NewRequest("POST", "/admin/api/v1/policy/evaluate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handlePolicyEvaluate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp service.PolicyEvaluateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected decision 'deny', got %q", resp.Decision)
	}
	if resp.HelpURL == "" {
		t.Error("expected non-empty help_url for deny")
	}
	if resp.HelpText == "" {
		t.Error("expected non-empty help_text for deny")
	}
	if resp.RuleName != "Block Dangerous Execution" {
		t.Errorf("expected rule_name 'Block Dangerous Execution', got %q", resp.RuleName)
	}
}

func TestHandlePolicyEvaluate_InvalidBody(t *testing.T) {
	engine := &mockPolicyEvalEngine{
		decision: policy.Decision{Allowed: true},
	}
	h := setupPolicyEvalHandler(t, engine)

	req := httptest.NewRequest("POST", "/admin/api/v1/policy/evaluate", strings.NewReader("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handlePolicyEvaluate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandlePolicyEvaluate_MissingFields(t *testing.T) {
	engine := &mockPolicyEvalEngine{
		decision: policy.Decision{Allowed: true},
	}
	h := setupPolicyEvalHandler(t, engine)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing action_type",
			body: `{"action_name":"read","identity_name":"alice","identity_roles":["user"]}`,
		},
		{
			name: "missing action_name",
			body: `{"action_type":"tool_call","identity_name":"alice","identity_roles":["user"]}`,
		},
		{
			name: "missing identity_name",
			body: `{"action_type":"tool_call","action_name":"read","identity_roles":["user"]}`,
		},
		{
			name: "missing identity_roles",
			body: `{"action_type":"tool_call","action_name":"read","identity_name":"alice"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/admin/api/v1/policy/evaluate", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			h.handlePolicyEvaluate(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandlePolicyEvaluateStatus_Found(t *testing.T) {
	engine := &mockPolicyEvalEngine{
		decision: policy.Decision{
			Allowed:  false,
			RuleID:   "block-exec",
			RuleName: "Block Execution",
			Reason:   "denied",
		},
	}
	h := setupPolicyEvalHandler(t, engine)

	// First, create an evaluation.
	body := `{
		"action_type": "tool_call",
		"action_name": "exec_cmd",
		"protocol": "mcp",
		"identity_name": "test",
		"identity_roles": ["user"]
	}`

	evalReq := httptest.NewRequest("POST", "/admin/api/v1/policy/evaluate", strings.NewReader(body))
	evalReq.Header.Set("Content-Type", "application/json")
	evalW := httptest.NewRecorder()
	h.handlePolicyEvaluate(evalW, evalReq)

	var evalResp service.PolicyEvaluateResponse
	if err := json.Unmarshal(evalW.Body.Bytes(), &evalResp); err != nil {
		t.Fatalf("failed to parse evaluation response: %v", err)
	}

	// Now query status using Go 1.22 PathValue.
	statusReq := httptest.NewRequest("GET", "/admin/api/v1/policy/evaluate/"+evalResp.RequestID+"/status", nil)
	statusReq.SetPathValue("request_id", evalResp.RequestID)
	statusW := httptest.NewRecorder()
	h.handlePolicyEvaluateStatus(statusW, statusReq)

	if statusW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", statusW.Code, statusW.Body.String())
	}

	var statusResp PolicyEvaluateStatusResponse
	if err := json.Unmarshal(statusW.Body.Bytes(), &statusResp); err != nil {
		t.Fatalf("failed to parse status response: %v", err)
	}
	if statusResp.RequestID != evalResp.RequestID {
		t.Errorf("expected request_id %q, got %q", evalResp.RequestID, statusResp.RequestID)
	}
	if statusResp.Status != "deny" {
		t.Errorf("expected status 'deny', got %q", statusResp.Status)
	}
}

func TestHandlePolicyEvaluateStatus_NotFound(t *testing.T) {
	engine := &mockPolicyEvalEngine{
		decision: policy.Decision{Allowed: true},
	}
	h := setupPolicyEvalHandler(t, engine)

	req := httptest.NewRequest("GET", "/admin/api/v1/policy/evaluate/nonexistent-id/status", nil)
	req.SetPathValue("request_id", "nonexistent-id")
	w := httptest.NewRecorder()

	h.handlePolicyEvaluateStatus(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}
