package integration

import (
	"context"
	"encoding/json"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// --- Helpers for performance benchmarks ---

// buildPerfPolicyService creates a PolicyService with a policy containing 10 rules
// (mix of exact match and wildcard patterns) for benchmark testing.
func buildPerfPolicyService(t testing.TB) *service.PolicyService {
	t.Helper()
	logger := testLogger()

	rules := []policy.Rule{
		// Exact match rules
		{ID: "perf-rule-1", Priority: 200, ToolMatch: "delete_file", Condition: "true", Action: policy.ActionDeny},
		{ID: "perf-rule-2", Priority: 200, ToolMatch: "exec_command", Condition: "true", Action: policy.ActionDeny},
		{ID: "perf-rule-3", Priority: 150, ToolMatch: "admin_panel", Condition: "true", Action: policy.ActionDeny},
		// Wildcard rules
		{ID: "perf-rule-4", Priority: 100, ToolMatch: "read_*", Condition: `"user" in user_roles`, Action: policy.ActionAllow},
		{ID: "perf-rule-5", Priority: 100, ToolMatch: "write_*", Condition: `"user" in user_roles`, Action: policy.ActionAllow},
		{ID: "perf-rule-6", Priority: 100, ToolMatch: "list_*", Condition: `"user" in user_roles`, Action: policy.ActionAllow},
		{ID: "perf-rule-7", Priority: 100, ToolMatch: "create_*", Condition: `"user" in user_roles`, Action: policy.ActionAllow},
		{ID: "perf-rule-8", Priority: 50, ToolMatch: "search_*", Condition: `"read-only" in user_roles`, Action: policy.ActionAllow},
		{ID: "perf-rule-9", Priority: 50, ToolMatch: "get_*", Condition: `"read-only" in user_roles`, Action: policy.ActionAllow},
		// Default deny
		{ID: "perf-rule-10", Priority: 0, ToolMatch: "*", Condition: "true", Action: policy.ActionDeny},
	}

	store := &mockPolicyEngine_policyStore{
		policies: []policy.Policy{
			{
				ID:      "perf-policy",
				Name:    "Performance Test Policy",
				Enabled: true,
				Rules:   rules,
			},
		},
	}

	svc, err := service.NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService: %v", err)
	}
	return svc
}

// mockPolicyEngine_policyStore implements policy.PolicyStore for benchmarks.
type mockPolicyEngine_policyStore struct {
	policies []policy.Policy
}

func (m *mockPolicyEngine_policyStore) GetAllPolicies(_ context.Context) ([]policy.Policy, error) {
	return m.policies, nil
}
func (m *mockPolicyEngine_policyStore) GetPolicy(_ context.Context, id string) (*policy.Policy, error) {
	for i := range m.policies {
		if m.policies[i].ID == id {
			return &m.policies[i], nil
		}
	}
	return nil, nil
}
func (m *mockPolicyEngine_policyStore) SavePolicy(_ context.Context, _ *policy.Policy) error {
	return nil
}
func (m *mockPolicyEngine_policyStore) SaveRule(_ context.Context, _ string, _ *policy.Rule) error {
	return nil
}
func (m *mockPolicyEngine_policyStore) DeleteRule(_ context.Context, _ string, _ string) error {
	return nil
}
func (m *mockPolicyEngine_policyStore) DeletePolicy(_ context.Context, _ string) error {
	return nil
}
func (m *mockPolicyEngine_policyStore) GetPolicyWithRules(_ context.Context, id string) (*policy.Policy, error) {
	return m.GetPolicy(context.Background(), id)
}

// buildPerfChain creates the full ActionInterceptor chain:
// PolicyActionInterceptor -> OutboundInterceptor -> ResponseScanInterceptor -> terminal
func buildPerfChain(t testing.TB, policyEngine policy.PolicyEngine) action.ActionInterceptor {
	t.Helper()
	logger := testLogger()

	// Terminal interceptor: passthrough that simulates upstream response
	terminal := action.ActionInterceptorFunc(func(ctx context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
		return a, nil
	})

	// ResponseScanInterceptor (monitor mode, enabled)
	scanner := action.NewResponseScanner()
	responseScan := action.NewResponseScanInterceptor(scanner, terminal, action.ScanModeMonitor, true, logger)

	// OutboundInterceptor (default blocklist rules)
	resolver := action.NewDNSResolver(logger)
	outbound := action.NewOutboundInterceptor(action.DefaultBlocklistRules(), resolver, responseScan, logger)

	// PolicyActionInterceptor
	policyInterceptor := action.NewPolicyActionInterceptor(policyEngine, outbound, logger)

	return policyInterceptor
}

// buildTestAction creates a CanonicalAction representing a tool_call with full
// Identity, Arguments, and Destination for benchmark testing.
func buildTestAction() *action.CanonicalAction {
	return &action.CanonicalAction{
		Type: action.ActionToolCall,
		Name: "read_file",
		Identity: action.ActionIdentity{
			ID:        "bench-identity",
			Name:      "benchmark-user",
			SessionID: "bench-session-001",
			Roles:     []string{"user"},
		},
		Arguments: map[string]interface{}{
			"path":      "/tmp/data.txt",
			"encoding":  "utf-8",
			"max_lines": float64(100),
		},
		Destination: action.Destination{
			URL:    "file:///tmp/data.txt",
			Path:   "/tmp/data.txt",
			Scheme: "file",
		},
		Protocol:    "mcp",
		Gateway:     "mcp-gateway",
		RequestTime: time.Now(),
		RequestID:   "bench-req-001",
		Metadata:    map[string]interface{}{},
	}
}

// --- Benchmarks ---

// BenchmarkPolicyEvaluationChain measures the full ActionInterceptor chain
// (policy -> outbound -> response scan -> terminal) under single-threaded load.
func BenchmarkPolicyEvaluationChain(b *testing.B) {
	policyService := buildPerfPolicyService(b)
	chain := buildPerfChain(b, policyService)
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		_, _ = chain.Intercept(ctx, buildTestAction())
	}
}

// BenchmarkPolicyEvaluationChainParallel measures the full chain under parallel load
// with GOMAXPROCS goroutines.
func BenchmarkPolicyEvaluationChainParallel(b *testing.B) {
	policyService := buildPerfPolicyService(b)
	chain := buildPerfChain(b, policyService)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		for pb.Next() {
			_, _ = chain.Intercept(ctx, buildTestAction())
		}
	})
}

// BenchmarkFullMCPChain measures the complete MCP path including InterceptorChain
// (normalize + full chain + denormalize) plus AuditInterceptor.
func BenchmarkFullMCPChain(b *testing.B) {
	logger := testLogger()
	policyService := buildPerfPolicyService(b)
	head := buildPerfChain(b, policyService)

	// Build InterceptorChain (MCPNormalizer -> ActionInterceptor chain)
	normalizer := action.NewMCPNormalizer()
	chain := action.NewInterceptorChain(normalizer, head, logger)

	// Wrap in AuditInterceptor
	auditRec := &perfAuditRecorder{}
	statsRec := &perfStatsRecorder{}
	auditInterceptor := proxy.NewAuditInterceptor(auditRec, statsRec, chain, logger)

	// Build a valid MCP tool call message with session context
	sess := &session.Session{
		ID:           "bench-sess",
		IdentityID:   "bench-id",
		IdentityName: "bench-user",
		Roles:        []auth.Role{auth.RoleUser},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		LastAccess:   time.Now().UTC(),
	}
	msg := buildPerfMCPMessage("read_file", map[string]interface{}{"path": "/tmp/data.txt"}, sess)
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		_, _ = auditInterceptor.Intercept(ctx, msg)
	}
}

// --- P99 Latency Test (TEST-10) ---

// TestPolicyEvaluationP99Under5ms runs 1000+ evaluations under parallel load
// and asserts p99 < threshold (5ms without race detector, 25ms with).
func TestPolicyEvaluationP99Under5ms(t *testing.T) {
	policyService := buildPerfPolicyService(t)
	chain := buildPerfChain(t, policyService)

	numGoroutines := runtime.GOMAXPROCS(0)
	if numGoroutines < 2 {
		numGoroutines = 2
	}
	iterationsPerGoroutine := 500 / numGoroutines
	if iterationsPerGoroutine < 50 {
		iterationsPerGoroutine = 50
	}
	totalExpected := numGoroutines * iterationsPerGoroutine

	var mu sync.Mutex
	latencies := make([]time.Duration, 0, totalExpected)

	// Warm up the policy cache
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		_, _ = chain.Intercept(ctx, buildTestAction())
	}

	// Run parallel evaluations collecting latencies
	var wg sync.WaitGroup
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			localLatencies := make([]time.Duration, 0, iterationsPerGoroutine)
			for i := 0; i < iterationsPerGoroutine; i++ {
				start := time.Now()
				_, err := chain.Intercept(ctx, buildTestAction())
				elapsed := time.Since(start)
				if err != nil {
					t.Errorf("Intercept() returned error: %v", err)
					return
				}
				localLatencies = append(localLatencies, elapsed)
			}
			mu.Lock()
			latencies = append(latencies, localLatencies...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(latencies) == 0 {
		t.Fatal("no latencies collected")
	}

	// Sort and compute percentiles
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	p50Idx := len(latencies) * 50 / 100
	p99Idx := len(latencies) * 99 / 100
	if p99Idx >= len(latencies) {
		p99Idx = len(latencies) - 1
	}

	p50 := latencies[p50Idx]
	p99 := latencies[p99Idx]
	pMax := latencies[len(latencies)-1]

	t.Logf("Policy evaluation chain latency (n=%d, goroutines=%d):", len(latencies), numGoroutines)
	t.Logf("  p50:  %v", p50)
	t.Logf("  p99:  %v", p99)
	t.Logf("  max:  %v", pMax)
	t.Logf("  p99 threshold: %v", perfP99Threshold)
	t.Logf("  p50 threshold: %v", perfP50Threshold)

	if p99 > perfP99Threshold {
		t.Errorf("p99 latency %v exceeds threshold %v", p99, perfP99Threshold)
	}
	if p50 > perfP50Threshold {
		t.Errorf("p50 latency %v exceeds threshold %v", p50, perfP50Threshold)
	}
}

// --- Helpers for full MCP chain benchmark ---

// perfAuditRecorder is a no-op audit recorder for benchmarks.
type perfAuditRecorder struct{}

func (p *perfAuditRecorder) Record(_ audit.AuditRecord) {}

// perfStatsRecorder is a no-op stats recorder for benchmarks.
type perfStatsRecorder struct{}

func (p *perfStatsRecorder) RecordAllow()             {}
func (p *perfStatsRecorder) RecordDeny()              {}
func (p *perfStatsRecorder) RecordRateLimited()       {}
func (p *perfStatsRecorder) RecordProtocol(_ string)  {}
func (p *perfStatsRecorder) RecordFramework(_ string) {}

// buildPerfMCPMessage creates a valid MCP tool call message for benchmarks.
func buildPerfMCPMessage(toolName string, args map[string]interface{}, sess *session.Session) *mcp.Message {
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	}
	paramsJSON, _ := json.Marshal(params)

	rawMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  json.RawMessage(paramsJSON),
	}
	rawBytes, _ := json.Marshal(rawMsg)

	id, _ := jsonrpc.MakeID(float64(1))
	req := &jsonrpc.Request{
		ID:     id,
		Method: "tools/call",
		Params: paramsJSON,
	}

	return &mcp.Message{
		Raw:       rawBytes,
		Direction: mcp.ClientToServer,
		Decoded:   req,
		Timestamp: time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC),
		Session:   sess,
	}
}
