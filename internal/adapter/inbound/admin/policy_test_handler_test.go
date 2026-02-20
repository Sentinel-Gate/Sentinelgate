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
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// testPolicyTestEnv creates a test environment with the default RBAC policy loaded.
// The default policy includes role-based rules (no catch-all deny rule).
// Unmatched tools fall through to the default-allow policy.
// Roles are plain strings with no implicit privileges.
func testPolicyTestEnv(t *testing.T) *AdminAPIHandler {
	t.Helper()

	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	defaultState := stateStore.DefaultState()
	if err := stateStore.Save(defaultState); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	// Create policy store with the default RBAC policy.
	policyStore := memory.NewPolicyStore()
	defaultPolicy := service.DefaultPolicy()
	defaultPolicy.ID = "default-policy-id"
	for i := range defaultPolicy.Rules {
		defaultPolicy.Rules[i].ID = defaultPolicy.Rules[i].Name
	}
	policyStore.AddPolicy(defaultPolicy)

	// Create policy service with compiled rules.
	policySvc, err := service.NewPolicyService(context.Background(), policyStore, logger)
	if err != nil {
		t.Fatalf("NewPolicyService: %v", err)
	}

	h := NewAdminAPIHandler(
		WithPolicyService(policySvc),
		WithPolicyStore(policyStore),
		WithAPILogger(logger),
	)

	return h
}

func TestHandleTestPolicy(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantStatus     int
		wantAllowed    *bool // nil means don't check
		wantDecision   string
		wantRuleID     string
		wantRuleName   string
		wantHasMatched bool
	}{
		{
			name:           "admin role has no implicit privileges",
			body:           `{"tool_name":"read_file","roles":["admin"]}`,
			wantStatus:     http.StatusOK,
			wantAllowed:    boolPtr(true),
			wantDecision:   "allow",
			wantRuleID:     "",
			wantRuleName:   "",
			wantHasMatched: false,
		},
		{
			name:           "user role allowed unknown tool (default allow)",
			body:           `{"tool_name":"unknown_tool","roles":["user"]}`,
			wantStatus:     http.StatusOK,
			wantAllowed:    boolPtr(true),
			wantDecision:   "allow",
			wantRuleID:     "",
			wantRuleName:   "",
			wantHasMatched: false,
		},
		{
			name:           "no roles allowed (default allow)",
			body:           `{"tool_name":"anything","roles":[]}`,
			wantStatus:     http.StatusOK,
			wantAllowed:    boolPtr(true),
			wantDecision:   "allow",
			wantRuleID:     "",
			wantRuleName:   "",
			wantHasMatched: false,
		},
		{
			name:       "missing tool_name returns 400",
			body:       `{"roles":["admin"]}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty body returns 400",
			body:       `{}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:           "admin role allowed write without user role (default allow)",
			body:           `{"tool_name":"write_file","arguments":{"path":"/tmp/test"},"roles":["admin"]}`,
			wantStatus:     http.StatusOK,
			wantAllowed:    boolPtr(true),
			wantDecision:   "allow",
			wantRuleID:     "",
			wantRuleName:   "",
			wantHasMatched: false,
		},
		{
			name:           "user role allowed read operations",
			body:           `{"tool_name":"read_file","roles":["user"]}`,
			wantStatus:     http.StatusOK,
			wantAllowed:    boolPtr(true),
			wantDecision:   "allow",
			wantRuleID:     "user-read",
			wantRuleName:   "user-read",
			wantHasMatched: true,
		},
		{
			name:           "read-only role allowed read operations",
			body:           `{"tool_name":"read_file","roles":["read-only"]}`,
			wantStatus:     http.StatusOK,
			wantAllowed:    boolPtr(true),
			wantDecision:   "allow",
			wantRuleID:     "readonly-read",
			wantRuleName:   "readonly-read",
			wantHasMatched: true,
		},
		{
			name:           "user role denied delete operations",
			body:           `{"tool_name":"delete_file","roles":["user"]}`,
			wantStatus:     http.StatusOK,
			wantAllowed:    boolPtr(false),
			wantDecision:   "deny",
			wantRuleID:     "block-delete",
			wantRuleName:   "block-delete",
			wantHasMatched: true,
		},
		{
			name:           "with identity_id and user role",
			body:           `{"tool_name":"read_file","roles":["user"],"identity_id":"user-123"}`,
			wantStatus:     http.StatusOK,
			wantAllowed:    boolPtr(true),
			wantDecision:   "allow",
			wantRuleID:     "user-read",
			wantHasMatched: true,
		},
		{
			name:       "invalid JSON returns 400",
			body:       `not json`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := testPolicyTestEnv(t)

			req := httptest.NewRequest(http.MethodPost, "/admin/api/policies/test", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			h.handleTestPolicy(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.wantStatus {
				bodyBytes, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want %d, body: %s", resp.StatusCode, tt.wantStatus, string(bodyBytes))
			}

			// Only check response body for 200 OK responses.
			if tt.wantStatus != http.StatusOK {
				return
			}

			var result PolicyTestResponse
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				t.Fatalf("decode response: %v", err)
			}

			if tt.wantAllowed != nil && result.Allowed != *tt.wantAllowed {
				t.Errorf("allowed = %v, want %v", result.Allowed, *tt.wantAllowed)
			}

			if tt.wantDecision != "" && result.Decision != tt.wantDecision {
				t.Errorf("decision = %q, want %q", result.Decision, tt.wantDecision)
			}

			if tt.wantRuleID != "" && result.RuleID != tt.wantRuleID {
				t.Errorf("rule_id = %q, want %q", result.RuleID, tt.wantRuleID)
			}

			if tt.wantRuleName != "" && result.RuleName != tt.wantRuleName {
				t.Errorf("rule_name = %q, want %q", result.RuleName, tt.wantRuleName)
			}

			if result.Reason == "" {
				t.Error("reason should not be empty")
			}

			if tt.wantHasMatched && result.MatchedRule == nil {
				t.Error("matched_rule should not be nil when a rule matched")
			}

			if tt.wantHasMatched && result.MatchedRule != nil {
				if result.MatchedRule.Action == "" {
					t.Error("matched_rule.action should not be empty")
				}
				if result.MatchedRule.Condition == "" {
					t.Error("matched_rule.condition should not be empty")
				}
			}
		})
	}
}

func TestHandleTestPolicy_NoPolicyService(t *testing.T) {
	h := NewAdminAPIHandler(
		WithAPILogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))),
	)

	body := `{"tool_name":"read_file","roles":["admin"]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/policies/test", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleTestPolicy(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d (no policy service configured)", resp.StatusCode, http.StatusInternalServerError)
	}
}

func boolPtr(b bool) *bool {
	return &b
}
