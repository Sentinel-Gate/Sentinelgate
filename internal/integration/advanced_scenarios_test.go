package integration

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// =============================================================================
// Test 1: Drift Detection E2E
// =============================================================================

// TestDriftDetectionE2E verifies the full drift detection lifecycle:
// capture baseline, modify tool set, detect drift, and verify reports.
func TestDriftDetectionE2E(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	stateStore := state.NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("Save default state: %v", err)
	}

	toolCache := upstream.NewToolCache()
	toolCache.SetToolsForUpstream("upstream-1", []*upstream.DiscoveredTool{
		{Name: "read_file", Description: "Read a file", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "write_file", Description: "Write a file", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
	})

	svc := service.NewToolSecurityService(toolCache, stateStore, logger)

	// Capture baseline with 2 tools.
	count, err := svc.CaptureBaseline(context.Background())
	if err != nil {
		t.Fatalf("CaptureBaseline() error: %v", err)
	}
	if count != 2 {
		t.Fatalf("CaptureBaseline() count = %d, want 2", count)
	}

	// Verify baseline contents.
	baseline := svc.GetBaseline()
	if len(baseline) != 2 {
		t.Fatalf("GetBaseline() len = %d, want 2", len(baseline))
	}
	if _, ok := baseline["read_file"]; !ok {
		t.Error("baseline missing read_file")
	}
	if _, ok := baseline["write_file"]; !ok {
		t.Error("baseline missing write_file")
	}

	// No drift when nothing changed.
	drifts, err := svc.DetectDrift(context.Background())
	if err != nil {
		t.Fatalf("DetectDrift() (no changes) error: %v", err)
	}
	if len(drifts) != 0 {
		t.Fatalf("DetectDrift() (no changes) found %d drifts, want 0", len(drifts))
	}

	// Modify tools: remove write_file, add delete_file.
	toolCache.SetToolsForUpstream("upstream-1", []*upstream.DiscoveredTool{
		{Name: "read_file", Description: "Read a file", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "delete_file", Description: "Delete a file", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
	})

	// Detect drift.
	drifts, err = svc.DetectDrift(context.Background())
	if err != nil {
		t.Fatalf("DetectDrift() error: %v", err)
	}

	// Expect 2 drifts: write_file removed, delete_file added.
	if len(drifts) != 2 {
		t.Fatalf("DetectDrift() found %d drifts, want 2", len(drifts))
	}

	driftMap := make(map[string]service.DriftReport)
	for _, d := range drifts {
		driftMap[d.ToolName] = d
	}

	removedDrift, ok := driftMap["write_file"]
	if !ok {
		t.Fatal("expected drift for write_file (removed)")
	}
	if removedDrift.DriftType != "removed" {
		t.Errorf("write_file drift type = %q, want %q", removedDrift.DriftType, "removed")
	}

	addedDrift, ok := driftMap["delete_file"]
	if !ok {
		t.Fatal("expected drift for delete_file (added)")
	}
	if addedDrift.DriftType != "added" {
		t.Errorf("delete_file drift type = %q, want %q", addedDrift.DriftType, "added")
	}

	// Also test "changed" drift: modify description of read_file.
	toolCache.SetToolsForUpstream("upstream-1", []*upstream.DiscoveredTool{
		{Name: "read_file", Description: "Read a file (v2)", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "delete_file", Description: "Delete a file", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
	})

	drifts, err = svc.DetectDrift(context.Background())
	if err != nil {
		t.Fatalf("DetectDrift() (changed) error: %v", err)
	}

	// Expect 3 drifts: write_file removed, delete_file added, read_file changed.
	if len(drifts) != 3 {
		t.Fatalf("DetectDrift() (changed) found %d drifts, want 3", len(drifts))
	}

	driftMap = make(map[string]service.DriftReport)
	for _, d := range drifts {
		driftMap[d.ToolName] = d
	}

	changedDrift, ok := driftMap["read_file"]
	if !ok {
		t.Fatal("expected drift for read_file (changed)")
	}
	if changedDrift.DriftType != "changed" {
		t.Errorf("read_file drift type = %q, want %q", changedDrift.DriftType, "changed")
	}
}

// =============================================================================
// Test 2: Red Team Simulation E2E
// =============================================================================

// TestRedTeamSimulationE2E verifies the red team service runs a simulation
// against a real policy engine and produces a meaningful report.
func TestRedTeamSimulationE2E(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	// Build a real policy store with a deny-all rule.
	policyStore := memory.NewPolicyStore()
	policyStore.AddPolicy(&policy.Policy{
		ID:      "deny-all",
		Name:    "Deny All",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "rule-deny-all",
				Name:      "Deny everything",
				Priority:  1,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		},
	})

	policySvc, err := service.NewPolicyService(ctx, policyStore, logger)
	if err != nil {
		t.Fatalf("NewPolicyService: %v", err)
	}

	// Create RedTeamService backed by the real policy service.
	rtSvc := service.NewRedTeamService(policySvc, logger)

	// Run the full suite.
	report, err := rtSvc.RunSuite(ctx, "test-identity", []string{"user"})
	if err != nil {
		t.Fatalf("RunSuite() error: %v", err)
	}

	// Verify report structure.
	if report == nil {
		t.Fatal("RunSuite() returned nil report")
	}
	if report.CorpusSize == 0 {
		t.Error("report.CorpusSize = 0, expected > 0")
	}
	if report.ID == "" {
		t.Error("report.ID is empty")
	}
	if report.TargetID != "test-identity" {
		t.Errorf("report.TargetID = %q, want %q", report.TargetID, "test-identity")
	}

	// With deny-all policy, all attacks should be blocked.
	if report.TotalBlocked != report.CorpusSize {
		t.Errorf("deny-all policy: TotalBlocked = %d, want %d (CorpusSize)", report.TotalBlocked, report.CorpusSize)
	}
	if report.TotalPassed != 0 {
		t.Errorf("deny-all policy: TotalPassed = %d, want 0", report.TotalPassed)
	}
	if report.BlockRate != 100.0 {
		t.Errorf("deny-all policy: BlockRate = %.1f, want 100.0", report.BlockRate)
	}

	// Verify report is stored and retrievable.
	reports := rtSvc.GetReports()
	if len(reports) != 1 {
		t.Fatalf("GetReports() len = %d, want 1", len(reports))
	}

	fetched := rtSvc.GetReport(report.ID)
	if fetched == nil {
		t.Fatal("GetReport() returned nil for existing report")
	}
	if fetched.ID != report.ID {
		t.Errorf("GetReport().ID = %q, want %q", fetched.ID, report.ID)
	}

	// Verify AllResults populated.
	if len(report.AllResults) == 0 {
		t.Error("report.AllResults is empty")
	}
	for _, r := range report.AllResults {
		if !r.Blocked {
			t.Errorf("result for pattern %q not blocked under deny-all", r.PatternID)
		}
	}

	// Verify scores populated.
	if len(report.Scores) == 0 {
		t.Error("report.Scores is empty")
	}
}

// =============================================================================
// Test 3: Rate Limiting E2E
// =============================================================================

// TestRateLimitingE2E verifies the rate limiting chain using real in-memory
// rate limiter and both IP and User rate limit interceptors.
func TestRateLimitingE2E(t *testing.T) {
	logger := testLogger()
	limiter := memory.NewRateLimiter()
	defer limiter.Stop()

	// Terminal interceptor that passes through.
	terminal := action.ActionInterceptorFunc(func(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
		return a, nil
	})

	// GCRA with Rate=2 Burst=2: allows up to (Burst+1)=3 initial requests.
	// The 4th request should be denied.
	ipConfig := ratelimit.RateLimitConfig{Rate: 2, Burst: 2, Period: time.Minute}
	userConfig := ratelimit.RateLimitConfig{Rate: 2, Burst: 2, Period: time.Minute}

	// Build chain: IP rate limit -> User rate limit -> terminal.
	userRL := action.NewActionUserRateLimitInterceptor(limiter, userConfig, terminal, logger)
	ipRL := action.NewActionIPRateLimitInterceptor(limiter, ipConfig, userRL, logger)

	testIP := "10.0.0.99"
	ctx := context.WithValue(context.Background(), proxy.IPAddressKey, testIP)

	makeAction := func() *action.CanonicalAction {
		return &action.CanonicalAction{
			Type:      action.ActionToolCall,
			Name:      "read_file",
			Arguments: map[string]interface{}{"path": "/tmp/test.txt"},
			Identity:  action.ActionIdentity{ID: "user-rl-test", Name: "Rate Limit User"},
		}
	}

	// First few requests should be allowed.
	allowedCount := 0
	for i := 0; i < 10; i++ {
		_, err := ipRL.Intercept(ctx, makeAction())
		if err == nil {
			allowedCount++
		} else {
			// Verify it is a RateLimitError.
			var rateLimitErr *proxy.RateLimitError
			if !errors.As(err, &rateLimitErr) {
				t.Fatalf("request %d: expected *proxy.RateLimitError, got %T: %v", i+1, err, err)
			}
			if rateLimitErr.RetryAfter <= 0 {
				t.Errorf("request %d: RetryAfter = %v, expected positive", i+1, rateLimitErr.RetryAfter)
			}
		}
	}

	// At least some requests should be allowed, and at least some denied.
	if allowedCount == 0 {
		t.Error("expected at least one request to be allowed")
	}
	if allowedCount == 10 {
		t.Error("expected at least one request to be rate limited")
	}

	t.Logf("rate limiting allowed %d/10 requests", allowedCount)
}

// =============================================================================
// Test 4: Tool Quarantine E2E
// =============================================================================

// TestToolQuarantineE2E verifies the quarantine lifecycle: quarantine a tool,
// verify it is blocked by the QuarantineInterceptor, unquarantine, verify it passes.
func TestToolQuarantineE2E(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	stateStore := state.NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("Save default state: %v", err)
	}

	toolCache := upstream.NewToolCache()
	toolCache.SetToolsForUpstream("upstream-1", []*upstream.DiscoveredTool{
		{Name: "safe_tool", Description: "Safe tool", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "dangerous_tool", Description: "Dangerous tool", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
	})

	svc := service.NewToolSecurityService(toolCache, stateStore, logger)

	// Terminal interceptor that passes through.
	terminal := action.ActionInterceptorFunc(func(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
		return a, nil
	})

	// Create QuarantineInterceptor backed by the real service.
	quarantineInterceptor := action.NewQuarantineInterceptor(svc, terminal, logger)

	makeDangerousAction := func() *action.CanonicalAction {
		return &action.CanonicalAction{
			Type:      action.ActionToolCall,
			Name:      "dangerous_tool",
			Arguments: map[string]interface{}{},
			Identity:  action.ActionIdentity{ID: "user-q", Name: "Quarantine User"},
		}
	}

	makeSafeAction := func() *action.CanonicalAction {
		return &action.CanonicalAction{
			Type:      action.ActionToolCall,
			Name:      "safe_tool",
			Arguments: map[string]interface{}{},
			Identity:  action.ActionIdentity{ID: "user-q", Name: "Quarantine User"},
		}
	}

	// Before quarantine: dangerous_tool should pass through.
	_, err := quarantineInterceptor.Intercept(context.Background(), makeDangerousAction())
	if err != nil {
		t.Fatalf("before quarantine: dangerous_tool should be allowed, got error: %v", err)
	}

	// Quarantine the dangerous tool.
	if err := svc.Quarantine("dangerous_tool"); err != nil {
		t.Fatalf("Quarantine() error: %v", err)
	}

	// Verify it is quarantined.
	if !svc.IsQuarantined("dangerous_tool") {
		t.Fatal("IsQuarantined() = false after Quarantine()")
	}
	quarantined := svc.GetQuarantinedTools()
	if len(quarantined) != 1 || quarantined[0] != "dangerous_tool" {
		t.Errorf("GetQuarantinedTools() = %v, want [dangerous_tool]", quarantined)
	}

	// After quarantine: dangerous_tool should be blocked.
	_, err = quarantineInterceptor.Intercept(context.Background(), makeDangerousAction())
	if err == nil {
		t.Fatal("after quarantine: dangerous_tool should be blocked, got nil error")
	}
	if !errors.Is(err, proxy.ErrPolicyDenied) {
		t.Errorf("quarantined tool error should wrap ErrPolicyDenied, got: %v", err)
	}

	// safe_tool should still pass through.
	_, err = quarantineInterceptor.Intercept(context.Background(), makeSafeAction())
	if err != nil {
		t.Fatalf("safe_tool should not be blocked, got error: %v", err)
	}

	// Unquarantine the dangerous tool.
	if err := svc.Unquarantine("dangerous_tool"); err != nil {
		t.Fatalf("Unquarantine() error: %v", err)
	}

	// After unquarantine: dangerous_tool should pass through again.
	if svc.IsQuarantined("dangerous_tool") {
		t.Fatal("IsQuarantined() = true after Unquarantine()")
	}

	_, err = quarantineInterceptor.Intercept(context.Background(), makeDangerousAction())
	if err != nil {
		t.Fatalf("after unquarantine: dangerous_tool should be allowed, got error: %v", err)
	}

	// Unquarantine a non-quarantined tool should return ErrNotQuarantined.
	err = svc.Unquarantine("nonexistent_tool")
	if !errors.Is(err, service.ErrNotQuarantined) {
		t.Errorf("Unquarantine(nonexistent) should return ErrNotQuarantined, got: %v", err)
	}
}

// =============================================================================
// Test 5: State Persistence Across Restart E2E
// =============================================================================

// TestStatePersistenceAcrossRestartE2E verifies that all state (identities,
// policies, upstreams, quotas) persists across a simulated restart.
func TestStatePersistenceAcrossRestartE2E(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	// Create first state store and populate it.
	store1 := state.NewFileStateStore(statePath, logger)

	original := store1.DefaultState()

	// Add identities.
	original.Identities = []state.IdentityEntry{
		{ID: "id-1", Name: "Alice", Roles: []string{"admin", "user"}},
		{ID: "id-2", Name: "Bob", Roles: []string{"user"}},
	}

	// Add policies.
	original.Policies = []state.PolicyEntry{
		{
			ID:          "pol-deny-all",
			Name:        "Deny All",
			Priority:    0,
			ToolPattern: "*",
			Action:      "deny",
			Enabled:     true,
		},
		{
			ID:          "pol-allow-read",
			Name:        "Allow Read",
			Priority:    10,
			ToolPattern: "read_*",
			Action:      "allow",
			Enabled:     true,
		},
	}

	// Add upstreams.
	original.Upstreams = []state.UpstreamEntry{
		{
			ID:      "up-1",
			Name:    "fs-server",
			Type:    "stdio",
			Enabled: true,
			Command: "/usr/bin/mcp-fs",
			Args:    []string{"/tmp"},
		},
		{
			ID:      "up-2",
			Name:    "web-search",
			Type:    "http",
			Enabled: true,
			URL:     "http://localhost:3001/mcp",
		},
	}

	// Add quotas.
	original.Quotas = []state.QuotaConfigEntry{
		{
			IdentityID:         "id-1",
			MaxCallsPerSession: 100,
			MaxCallsPerMinute:  10,
			Action:             "deny",
			Enabled:            true,
		},
	}

	// Add API keys.
	original.APIKeys = []state.APIKeyEntry{
		{
			ID:         "key-1",
			KeyHash:    "sha256:test123",
			IdentityID: "id-1",
			Name:       "Alice Key",
		},
	}

	// Save state.
	if err := store1.Save(original); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Simulate restart: create a NEW state store from the same file.
	store2 := state.NewFileStateStore(statePath, logger)

	loaded, err := store2.Load()
	if err != nil {
		t.Fatalf("Load() error on restart: %v", err)
	}

	// Verify all data persisted.

	// Version.
	if loaded.Version != "1" {
		t.Errorf("Version = %q, want %q", loaded.Version, "1")
	}
	if loaded.DefaultPolicy != "deny" {
		t.Errorf("DefaultPolicy = %q, want %q", loaded.DefaultPolicy, "deny")
	}

	// Identities.
	if len(loaded.Identities) != 2 {
		t.Fatalf("len(Identities) = %d, want 2", len(loaded.Identities))
	}
	if loaded.Identities[0].ID != "id-1" || loaded.Identities[0].Name != "Alice" {
		t.Errorf("Identities[0] = {%s, %s}, want {id-1, Alice}", loaded.Identities[0].ID, loaded.Identities[0].Name)
	}
	if len(loaded.Identities[0].Roles) != 2 {
		t.Errorf("Identities[0].Roles len = %d, want 2", len(loaded.Identities[0].Roles))
	}
	if loaded.Identities[1].ID != "id-2" || loaded.Identities[1].Name != "Bob" {
		t.Errorf("Identities[1] = {%s, %s}, want {id-2, Bob}", loaded.Identities[1].ID, loaded.Identities[1].Name)
	}

	// Policies.
	if len(loaded.Policies) != 2 {
		t.Fatalf("len(Policies) = %d, want 2", len(loaded.Policies))
	}
	if loaded.Policies[0].ID != "pol-deny-all" {
		t.Errorf("Policies[0].ID = %q, want %q", loaded.Policies[0].ID, "pol-deny-all")
	}
	if loaded.Policies[0].ToolPattern != "*" {
		t.Errorf("Policies[0].ToolPattern = %q, want %q", loaded.Policies[0].ToolPattern, "*")
	}
	if loaded.Policies[1].ID != "pol-allow-read" {
		t.Errorf("Policies[1].ID = %q, want %q", loaded.Policies[1].ID, "pol-allow-read")
	}

	// Upstreams.
	if len(loaded.Upstreams) != 2 {
		t.Fatalf("len(Upstreams) = %d, want 2", len(loaded.Upstreams))
	}
	if loaded.Upstreams[0].ID != "up-1" || loaded.Upstreams[0].Name != "fs-server" {
		t.Errorf("Upstreams[0] = {%s, %s}, want {up-1, fs-server}", loaded.Upstreams[0].ID, loaded.Upstreams[0].Name)
	}
	if loaded.Upstreams[0].Type != "stdio" {
		t.Errorf("Upstreams[0].Type = %q, want %q", loaded.Upstreams[0].Type, "stdio")
	}
	if loaded.Upstreams[0].Command != "/usr/bin/mcp-fs" {
		t.Errorf("Upstreams[0].Command = %q, want %q", loaded.Upstreams[0].Command, "/usr/bin/mcp-fs")
	}
	if len(loaded.Upstreams[0].Args) != 1 || loaded.Upstreams[0].Args[0] != "/tmp" {
		t.Errorf("Upstreams[0].Args = %v, want [/tmp]", loaded.Upstreams[0].Args)
	}
	if loaded.Upstreams[1].ID != "up-2" || loaded.Upstreams[1].Type != "http" {
		t.Errorf("Upstreams[1] = {%s, %s}, want {up-2, http}", loaded.Upstreams[1].ID, loaded.Upstreams[1].Type)
	}
	if loaded.Upstreams[1].URL != "http://localhost:3001/mcp" {
		t.Errorf("Upstreams[1].URL = %q, want %q", loaded.Upstreams[1].URL, "http://localhost:3001/mcp")
	}

	// Quotas.
	if len(loaded.Quotas) != 1 {
		t.Fatalf("len(Quotas) = %d, want 1", len(loaded.Quotas))
	}
	if loaded.Quotas[0].IdentityID != "id-1" {
		t.Errorf("Quotas[0].IdentityID = %q, want %q", loaded.Quotas[0].IdentityID, "id-1")
	}
	if loaded.Quotas[0].MaxCallsPerSession != 100 {
		t.Errorf("Quotas[0].MaxCallsPerSession = %d, want 100", loaded.Quotas[0].MaxCallsPerSession)
	}
	if loaded.Quotas[0].MaxCallsPerMinute != 10 {
		t.Errorf("Quotas[0].MaxCallsPerMinute = %d, want 10", loaded.Quotas[0].MaxCallsPerMinute)
	}
	if loaded.Quotas[0].Action != "deny" {
		t.Errorf("Quotas[0].Action = %q, want %q", loaded.Quotas[0].Action, "deny")
	}
	if !loaded.Quotas[0].Enabled {
		t.Error("Quotas[0].Enabled = false, want true")
	}

	// API Keys.
	if len(loaded.APIKeys) != 1 {
		t.Fatalf("len(APIKeys) = %d, want 1", len(loaded.APIKeys))
	}
	if loaded.APIKeys[0].ID != "key-1" {
		t.Errorf("APIKeys[0].ID = %q, want %q", loaded.APIKeys[0].ID, "key-1")
	}
	if loaded.APIKeys[0].IdentityID != "id-1" {
		t.Errorf("APIKeys[0].IdentityID = %q, want %q", loaded.APIKeys[0].IdentityID, "id-1")
	}
	if loaded.APIKeys[0].Name != "Alice Key" {
		t.Errorf("APIKeys[0].Name = %q, want %q", loaded.APIKeys[0].Name, "Alice Key")
	}
}
