package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleLintPolicy(t *testing.T) {
	h, _ := testPolicyHandlerEnv(t)

	tests := []struct {
		name       string
		body       lintRequest
		wantValid  bool
		wantTypes  []string // expected warning types
		wantStatus int
	}{
		{
			name:       "valid condition no conflict at unique priority",
			body:       lintRequest{Condition: `tool_name == "bash"`, ToolMatch: "bash", Action: "deny", Priority: 200},
			wantValid:  true,
			wantTypes:  nil,
			wantStatus: http.StatusOK,
		},
		{
			name:       "conflict detected at same priority as default rules",
			body:       lintRequest{Condition: `tool_name == "bash"`, ToolMatch: "*", Action: "deny", Priority: 100},
			wantValid:  true,
			wantTypes:  []string{"conflict"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "syntax error in CEL",
			body:       lintRequest{Condition: `tool_name ==`, ToolMatch: "*", Action: "deny", Priority: 100},
			wantValid:  false,
			wantTypes:  []string{"syntax"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "permissive allow all",
			body:       lintRequest{Condition: "true", ToolMatch: "*", Action: "allow", Priority: 100},
			wantValid:  true,
			wantTypes:  []string{"permissive"},
			wantStatus: http.StatusOK,
		},
		{
			// BUG-9 FIX: empty condition now returns 400 instead of silently valid:true
			name:       "empty condition returns error",
			body:       lintRequest{Condition: "", ToolMatch: "*", Action: "allow", Priority: 100},
			wantValid:  false,
			wantTypes:  nil,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "allow with identity check is fine",
			body:       lintRequest{Condition: `"admin" in identity_roles`, ToolMatch: "*", Action: "allow", Priority: 100},
			wantValid:  true,
			wantTypes:  nil,
			wantStatus: http.StatusOK,
		},
		{
			name:       "deny specific tool no warnings",
			body:       lintRequest{Condition: `!("admin" in identity_roles)`, ToolMatch: "bash", Action: "deny", Priority: 50},
			wantValid:  true,
			wantTypes:  nil,
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tt.body)
			req := httptest.NewRequest(http.MethodPost, "/admin/api/policies/lint", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			h.handleLintPolicy(w, req)

			resp := w.Result()
			defer resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			// Skip lint response assertions for non-OK statuses (e.g. 400 error responses)
			if tt.wantStatus != http.StatusOK {
				return
			}

			data, _ := io.ReadAll(resp.Body)
			var result lintResponse
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatalf("unmarshal: %v (body: %s)", err, string(data))
			}

			if result.Valid != tt.wantValid {
				t.Errorf("valid = %v, want %v (warnings: %+v)", result.Valid, tt.wantValid, result.Warnings)
			}

			if len(tt.wantTypes) == 0 && len(result.Warnings) > 0 {
				t.Errorf("expected no warnings, got %d: %+v", len(result.Warnings), result.Warnings)
			}

			for _, wt := range tt.wantTypes {
				found := false
				for _, w := range result.Warnings {
					if w.Type == wt {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected warning type %q not found in %+v", wt, result.Warnings)
				}
			}
		})
	}
}

func TestHandleLintPolicy_InvalidJSON(t *testing.T) {
	h, _ := testPolicyHandlerEnv(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/policies/lint", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.handleLintPolicy(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
