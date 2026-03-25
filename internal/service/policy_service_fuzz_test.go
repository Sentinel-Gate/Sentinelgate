package service

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// FuzzCELEvaluation (6.5) fuzzes the PolicyService.Evaluate method with
// arbitrary tool names and JSON argument strings. The CEL rule
// `tool_name == "allowed_tool"` is compiled once; every fuzz input is
// evaluated against it. The test fails on any panic.
func FuzzCELEvaluation(f *testing.F) {
	// Seed corpus: representative edge-case inputs.
	f.Add("read_file", `{"path":"/tmp"}`)
	f.Add("", "{}")
	f.Add("../traversal", `{"key":"value"}`)
	f.Add("tool\x00null", `null`)
	f.Add(strings.Repeat("x", 100000), `{"nested":{"deep":"value"}}`)
	f.Add("<script>", `{"<key>":"<value>"}`)
	f.Add("allowed_tool", `{"a":"b"}`)
	f.Add("*", `[]`)
	f.Add("read_*", `{"path":"../../etc/passwd"}`)
	f.Add("tool with spaces", `{"":""}`)
	f.Add("\t\n\r", `{"tab":"\t"}`)
	f.Add("admin/secret", ``)
	f.Add("[invalid-glob", `{"x":1}`)

	f.Fuzz(func(t *testing.T, toolName string, argsJSON string) {
		// Build arguments map from fuzzed JSON. If it does not
		// unmarshal into a map we use an empty map -- the focus is
		// on exercising Evaluate, not JSON parsing.
		var args map[string]interface{}
		if err := json.Unmarshal([]byte(argsJSON), &args); err != nil || args == nil {
			args = map[string]interface{}{}
		}

		// Create a fresh PolicyService for each fuzz iteration to
		// avoid cross-contamination through the LRU cache. The
		// policy has one CEL rule that only matches "allowed_tool".
		store := newMockPolicyStore(policy.Policy{
			ID:      "fuzz-policy",
			Name:    "Fuzz Policy",
			Enabled: true,
			Rules: []policy.Rule{
				{
					ID:        "fuzz-rule",
					Name:      "Allow allowed_tool",
					Priority:  100,
					ToolMatch: "*",
					Condition: `tool_name == "allowed_tool"`,
					Action:    policy.ActionAllow,
				},
				{
					ID:        "fuzz-deny",
					Name:      "Deny everything else",
					Priority:  50,
					ToolMatch: "*",
					Condition: "true",
					Action:    policy.ActionDeny,
				},
			},
		})

		svc, err := NewPolicyService(context.Background(), store, quietLogger())
		if err != nil {
			t.Fatalf("NewPolicyService failed: %v", err)
		}

		evalCtx := policy.EvaluationContext{
			ToolName:      toolName,
			ToolArguments: args,
			UserRoles:     []string{"user"},
			SessionID:     "fuzz-session",
			IdentityID:    "fuzz-identity",
			IdentityName:  "fuzz-user",
			RequestTime:   time.Now(),
			SkipCache:     true,
		}

		// Evaluate must not panic. Errors are acceptable (e.g., CEL
		// evaluation errors on weird input) but panics are not.
		_, _ = svc.Evaluate(context.Background(), evalCtx)
	})
}
