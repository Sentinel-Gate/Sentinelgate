package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/runtime"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// TestRuntimeFullPath_EvaluateAllow validates the runtime protection path for an allowed action:
// PolicyEvaluationService.Evaluate -> policy engine -> allow decision with metadata.
func TestRuntimeFullPath_EvaluateAllow(t *testing.T) {
	logger := testLogger()

	// 1. Mock policy engine returning allow
	engine := &mockPolicyEngine{
		decision: policy.Decision{
			Allowed:  true,
			RuleID:   "rule-allow-runtime",
			RuleName: "Allow Runtime",
			Reason:   "runtime action allowed",
		},
	}

	// 2. Create PolicyEvaluationService (store and stateStore are nil -- Evaluate
	//    only uses policyEngine, not the store or stateStore)
	svc := service.NewPolicyEvaluationService(engine, nil, nil, logger)

	// 3. Build a PolicyEvaluateRequest simulating what the runtime bootstrap sends
	req := service.PolicyEvaluateRequest{
		ActionType:    "command_exec",
		ActionName:    "subprocess.run",
		Protocol:      "runtime",
		Framework:     "langchain",
		IdentityName:  "sg_runtime_test-agent",
		IdentityRoles: []string{"runtime"},
		Arguments: map[string]interface{}{
			"command": "curl",
			"args":    []interface{}{"https://example.com"},
		},
	}

	// 4. Execute
	resp, err := svc.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	// Assert: decision is "allow"
	if resp.Decision != "allow" {
		t.Errorf("Decision = %q, want %q", resp.Decision, "allow")
	}

	// Assert: RequestID is non-empty
	if resp.RequestID == "" {
		t.Error("RequestID should be non-empty")
	}

	// Assert: LatencyMs >= 0
	if resp.LatencyMs < 0 {
		t.Errorf("LatencyMs = %d, want >= 0", resp.LatencyMs)
	}
}

// TestRuntimeFullPath_EvaluateDeny validates the runtime protection path for a denied action:
// PolicyEvaluationService.Evaluate -> policy engine -> deny decision with help info.
func TestRuntimeFullPath_EvaluateDeny(t *testing.T) {
	logger := testLogger()

	// 1. Mock policy engine returning deny with help metadata
	engine := &mockPolicyEngine{
		decision: policy.Decision{
			Allowed:  false,
			RuleID:   "rule-deny-curl",
			RuleName: "Block External Curl",
			Reason:   "curl to external hosts is blocked",
			HelpURL:  "/admin/policies#rule-deny-curl",
			HelpText: "Contact admin to allow curl access",
		},
	}

	// 2. Create PolicyEvaluationService
	svc := service.NewPolicyEvaluationService(engine, nil, nil, logger)

	// 3. Build evaluation request
	req := service.PolicyEvaluateRequest{
		ActionType:    "command_exec",
		ActionName:    "subprocess.run",
		Protocol:      "runtime",
		Framework:     "langchain",
		IdentityName:  "sg_runtime_test-agent",
		IdentityRoles: []string{"runtime"},
		Arguments: map[string]interface{}{
			"command": "curl",
			"args":    []interface{}{"https://evil.example.com"},
		},
	}

	// 4. Execute
	resp, err := svc.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}

	// Assert: decision is "deny"
	if resp.Decision != "deny" {
		t.Errorf("Decision = %q, want %q", resp.Decision, "deny")
	}

	// Assert: RuleName matches expected
	if resp.RuleName != "Block External Curl" {
		t.Errorf("RuleName = %q, want %q", resp.RuleName, "Block External Curl")
	}

	// Assert: HelpURL is non-empty
	if resp.HelpURL == "" {
		t.Error("HelpURL should be non-empty for denied actions")
	}

	// Assert: HelpText is non-empty
	if resp.HelpText == "" {
		t.Error("HelpText should be non-empty for denied actions")
	}
}

// TestRuntimeFullPath_BootstrapEnvVars validates the bootstrap configuration side:
// BootstrapConfig -> BuildEnvVars -> correct SENTINELGATE_* environment variables.
func TestRuntimeFullPath_BootstrapEnvVars(t *testing.T) {
	// 1. Create a BootstrapConfig
	cfg := runtime.BootstrapConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "sk-test-runtime-key",
		AgentID:    "agent-test-001",
		CacheTTL:   10 * time.Second,
		FailMode:   "closed",
		Framework:  "langchain",
	}

	// 2. Create bootstrap environment with a temp dir
	tmpDir := t.TempDir()
	cfg.BootstrapDir = tmpDir
	env, err := runtime.PrepareBootstrap(cfg)
	if err != nil {
		t.Fatalf("PrepareBootstrap() error = %v", err)
	}
	defer func() { _ = runtime.Cleanup(env) }()

	// 3. Build environment variables
	vars := runtime.BuildEnvVars(env, cfg)

	// Convert to map for easy lookup
	envMap := make(map[string]string)
	for _, v := range vars {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// Assert: SENTINELGATE_SERVER_ADDR is present and correct
	if v, ok := envMap["SENTINELGATE_SERVER_ADDR"]; !ok || v != "http://localhost:8080" {
		t.Errorf("SENTINELGATE_SERVER_ADDR = %q, want %q", v, "http://localhost:8080")
	}

	// Assert: SENTINELGATE_API_KEY is present and correct
	if v, ok := envMap["SENTINELGATE_API_KEY"]; !ok || v != "sk-test-runtime-key" {
		t.Errorf("SENTINELGATE_API_KEY = %q, want %q", v, "sk-test-runtime-key")
	}

	// Assert: SENTINELGATE_AGENT_ID is present and correct
	if v, ok := envMap["SENTINELGATE_AGENT_ID"]; !ok || v != "agent-test-001" {
		t.Errorf("SENTINELGATE_AGENT_ID = %q, want %q", v, "agent-test-001")
	}

	// Assert: SENTINELGATE_CACHE_TTL is present
	if v, ok := envMap["SENTINELGATE_CACHE_TTL"]; !ok || v != "10" {
		t.Errorf("SENTINELGATE_CACHE_TTL = %q, want %q", v, "10")
	}

	// Assert: SENTINELGATE_FAIL_MODE is present and correct
	if v, ok := envMap["SENTINELGATE_FAIL_MODE"]; !ok || v != "closed" {
		t.Errorf("SENTINELGATE_FAIL_MODE = %q, want %q", v, "closed")
	}

	// Assert: SENTINELGATE_FRAMEWORK is present and correct
	if v, ok := envMap["SENTINELGATE_FRAMEWORK"]; !ok || v != "langchain" {
		t.Errorf("SENTINELGATE_FRAMEWORK = %q, want %q", v, "langchain")
	}

	// Assert: PYTHONPATH is present and includes the bootstrap python dir
	if v, ok := envMap["PYTHONPATH"]; !ok || !strings.Contains(v, env.PythonDir) {
		t.Errorf("PYTHONPATH = %q, should contain %q", v, env.PythonDir)
	}

	// Assert: NODE_OPTIONS is present and includes the bootstrap node hook
	if v, ok := envMap["NODE_OPTIONS"]; !ok || !strings.Contains(v, "sentinelgate-hook.js") {
		t.Errorf("NODE_OPTIONS = %q, should contain sentinelgate-hook.js", v)
	}
}
