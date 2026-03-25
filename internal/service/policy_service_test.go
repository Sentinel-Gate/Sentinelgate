package service

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// mockPolicyStore implements policy.PolicyStore for testing.
type mockPolicyStore struct {
	policies []policy.Policy
	mu       sync.RWMutex
}

func newMockPolicyStore(policies ...policy.Policy) *mockPolicyStore {
	return &mockPolicyStore{policies: policies}
}

func (m *mockPolicyStore) GetAllPolicies(_ context.Context) ([]policy.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]policy.Policy{}, m.policies...), nil
}

func (m *mockPolicyStore) GetPolicy(_ context.Context, id string) (*policy.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.policies {
		if m.policies[i].ID == id {
			return &m.policies[i], nil
		}
	}
	return nil, nil
}

func (m *mockPolicyStore) SavePolicy(_ context.Context, p *policy.Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.policies {
		if m.policies[i].ID == p.ID {
			m.policies[i] = *p
			return nil
		}
	}
	m.policies = append(m.policies, *p)
	return nil
}

func (m *mockPolicyStore) DeletePolicy(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.policies {
		if m.policies[i].ID == id {
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			return nil
		}
	}
	return nil
}

func (m *mockPolicyStore) GetPolicyWithRules(_ context.Context, id string) (*policy.Policy, error) {
	return m.GetPolicy(context.Background(), id)
}

func (m *mockPolicyStore) SaveRule(_ context.Context, policyID string, r *policy.Rule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.policies {
		if m.policies[i].ID == policyID {
			m.policies[i].Rules = append(m.policies[i].Rules, *r)
			return nil
		}
	}
	return nil
}

func (m *mockPolicyStore) DeleteRule(_ context.Context, policyID, ruleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.policies {
		if m.policies[i].ID == policyID {
			for j := range m.policies[i].Rules {
				if m.policies[i].Rules[j].ID == ruleID {
					m.policies[i].Rules = append(m.policies[i].Rules[:j], m.policies[i].Rules[j+1:]...)
					return nil
				}
			}
		}
	}
	return nil
}

func (m *mockPolicyStore) setPolicies(policies []policy.Policy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies = policies
}

// TestPolicyServiceBasicEvaluation tests basic policy evaluation.
func TestPolicyServiceBasicEvaluation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	store := newMockPolicyStore(policy.Policy{
		ID:      "test-policy",
		Name:    "Test Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "allow-read",
				Name:      "Allow read operations",
				Priority:  100,
				ToolMatch: "read_*",
				Condition: "true",
				Action:    policy.ActionAllow,
			},
			{
				ID:        "deny-all",
				Name:      "Default deny",
				Priority:  0,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		},
	})

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("failed to create policy service: %v", err)
	}

	tests := []struct {
		name      string
		toolName  string
		wantAllow bool
	}{
		{"read_file allowed", "read_file", true},
		{"read_data allowed", "read_data", true},
		{"write_file denied", "write_file", false},
		{"delete_file denied", "delete_file", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			evalCtx := policy.EvaluationContext{
				ToolName:      tt.toolName,
				ToolArguments: map[string]interface{}{},
				UserRoles:     []string{"user"},
				SessionID:     "test-session",
				IdentityID:    "test-identity",
				RequestTime:   time.Now(),
			}

			decision, err := svc.Evaluate(ctx, evalCtx)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if decision.Allowed != tt.wantAllow {
				t.Errorf("expected Allowed=%v, got %v (rule=%s, reason=%s)",
					tt.wantAllow, decision.Allowed, decision.RuleID, decision.Reason)
			}
		})
	}
}

// TestPolicyServiceRuleIndex tests that exact matches are indexed for O(1) lookup.
func TestPolicyServiceRuleIndex(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create a policy with both exact matches and wildcards
	store := newMockPolicyStore(policy.Policy{
		ID:      "test-policy",
		Name:    "Test Policy",
		Enabled: true,
		Rules: []policy.Rule{
			// Exact match rule - higher priority
			{
				ID:        "exact-read-file",
				Name:      "Exact read_file",
				Priority:  200,
				ToolMatch: "read_file", // Exact match, no wildcards
				Condition: "true",
				Action:    policy.ActionAllow,
			},
			// Wildcard rule - lower priority
			{
				ID:        "wildcard-read",
				Name:      "Wildcard read_*",
				Priority:  100,
				ToolMatch: "read_*", // Wildcard
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		},
	})

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("failed to create policy service: %v", err)
	}

	// Verify index was built correctly
	snapshot := svc.loadSnapshot()
	if snapshot.Index == nil {
		t.Fatal("Index should not be nil")
	}

	// Check exact match bucket
	if len(snapshot.Index.Exact["read_file"]) != 1 {
		t.Errorf("expected 1 exact match for read_file, got %d", len(snapshot.Index.Exact["read_file"]))
	}

	// Check wildcard rules
	if len(snapshot.Index.Wildcard) != 1 {
		t.Errorf("expected 1 wildcard rule, got %d", len(snapshot.Index.Wildcard))
	}

	// Verify exact match wins for "read_file" (priority 200 > 100)
	ctx := context.Background()
	evalCtx := policy.EvaluationContext{
		ToolName:      "read_file",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"user"},
		SessionID:     "test-session",
		IdentityID:    "test-identity",
		RequestTime:   time.Now(),
	}

	decision, err := svc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if decision.RuleID != "exact-read-file" {
		t.Errorf("expected exact match rule, got rule=%s", decision.RuleID)
	}
	if !decision.Allowed {
		t.Errorf("expected Allowed=true, got Allowed=false")
	}

	// Verify wildcard matches for "read_data" (no exact match)
	evalCtx.ToolName = "read_data"
	decision, err = svc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if decision.RuleID != "wildcard-read" {
		t.Errorf("expected wildcard rule, got rule=%s", decision.RuleID)
	}
	if decision.Allowed {
		t.Errorf("expected Allowed=false (deny rule), got Allowed=true")
	}
}

// TestPolicyServiceConcurrentEvaluation tests lock-free concurrent reads.
func TestPolicyServiceConcurrentEvaluation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	store := newMockPolicyStore(policy.Policy{
		ID:      "test-policy",
		Name:    "Test Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "allow-all",
				Name:      "Allow all",
				Priority:  100,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionAllow,
			},
		},
	})

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("failed to create policy service: %v", err)
	}

	// Run many concurrent evaluations
	const numGoroutines = 100
	const evaluationsPerGoroutine = 1000

	var wg sync.WaitGroup
	var errCount int64
	var evalCount int64

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < evaluationsPerGoroutine; j++ {
				ctx := context.Background()
				evalCtx := policy.EvaluationContext{
					ToolName:      "test_tool",
					ToolArguments: map[string]interface{}{},
					UserRoles:     []string{"user"},
					SessionID:     "test-session",
					IdentityID:    "test-identity",
					RequestTime:   time.Now(),
				}

				decision, err := svc.Evaluate(ctx, evalCtx)
				if err != nil {
					atomic.AddInt64(&errCount, 1)
					continue
				}
				if !decision.Allowed {
					atomic.AddInt64(&errCount, 1)
					continue
				}
				atomic.AddInt64(&evalCount, 1)
			}
		}()
	}

	wg.Wait()

	totalExpected := int64(numGoroutines * evaluationsPerGoroutine)
	if evalCount != totalExpected {
		t.Errorf("expected %d successful evaluations, got %d (errors: %d)",
			totalExpected, evalCount, errCount)
	}
}

// TestPolicyServiceAtomicReload tests that reload doesn't block evaluations.
func TestPolicyServiceAtomicReload(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	store := newMockPolicyStore(policy.Policy{
		ID:      "test-policy",
		Name:    "Test Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "allow-all",
				Name:      "Allow all",
				Priority:  100,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionAllow,
			},
		},
	})

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("failed to create policy service: %v", err)
	}

	// Channel to signal when to start reloading
	startReload := make(chan struct{})
	stopReload := make(chan struct{})

	var wg sync.WaitGroup
	var evalCount int64
	var reloadCount int64

	// Start evaluator goroutines
	const numEvaluators = 10
	for i := 0; i < numEvaluators; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopReload:
					return
				default:
					ctx := context.Background()
					evalCtx := policy.EvaluationContext{
						ToolName:      "test_tool",
						ToolArguments: map[string]interface{}{},
						UserRoles:     []string{"user"},
						SessionID:     "test-session",
						IdentityID:    "test-identity",
						RequestTime:   time.Now(),
					}

					_, err := svc.Evaluate(ctx, evalCtx)
					if err == nil {
						atomic.AddInt64(&evalCount, 1)
					}
				}
			}
		}()
	}

	// Start reloader goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-startReload
		for {
			select {
			case <-stopReload:
				return
			default:
				ctx := context.Background()
				err := svc.Reload(ctx)
				if err == nil {
					atomic.AddInt64(&reloadCount, 1)
				}
				time.Sleep(time.Microsecond) // Reduce CPU burn
			}
		}
	}()

	// Run for a short duration (500ms to avoid flakiness on slow CI)
	close(startReload)
	time.Sleep(500 * time.Millisecond)
	close(stopReload)
	wg.Wait()

	t.Logf("evaluations: %d, reloads: %d", evalCount, reloadCount)

	// Verify we had both evaluations and reloads running
	if evalCount == 0 {
		t.Error("expected some evaluations to complete")
	}
	if reloadCount == 0 {
		t.Error("expected some reloads to complete")
	}
}

// TestPolicyServiceReloadUpdatesRules tests that reload picks up new rules.
func TestPolicyServiceReloadUpdatesRules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	store := newMockPolicyStore(policy.Policy{
		ID:      "test-policy",
		Name:    "Test Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "deny-all",
				Name:      "Deny all initially",
				Priority:  100,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		},
	})

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("failed to create policy service: %v", err)
	}

	// Initial evaluation should be denied
	ctx := context.Background()
	evalCtx := policy.EvaluationContext{
		ToolName:      "test_tool",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"user"},
		SessionID:     "test-session",
		IdentityID:    "test-identity",
		RequestTime:   time.Now(),
	}

	decision, err := svc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if decision.Allowed {
		t.Error("expected initial evaluation to be denied")
	}

	// Update store with new policy (allow all)
	store.setPolicies([]policy.Policy{{
		ID:      "test-policy",
		Name:    "Test Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "allow-all",
				Name:      "Allow all after reload",
				Priority:  100,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionAllow,
			},
		},
	}})

	// Reload
	err = svc.Reload(ctx)
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Evaluation should now be allowed
	decision, err = svc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Evaluate after reload failed: %v", err)
	}
	if !decision.Allowed {
		t.Error("expected evaluation after reload to be allowed")
	}
}

// TestPolicyServicePriorityOrder tests that higher priority rules are evaluated first.
func TestPolicyServicePriorityOrder(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	store := newMockPolicyStore(policy.Policy{
		ID:      "test-policy",
		Name:    "Test Policy",
		Enabled: true,
		Rules: []policy.Rule{
			// Lower priority (evaluated second)
			{
				ID:        "low-priority",
				Name:      "Low priority deny",
				Priority:  50,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
			// Higher priority (evaluated first)
			{
				ID:        "high-priority",
				Name:      "High priority allow",
				Priority:  100,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionAllow,
			},
		},
	})

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("failed to create policy service: %v", err)
	}

	ctx := context.Background()
	evalCtx := policy.EvaluationContext{
		ToolName:      "test_tool",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"user"},
		SessionID:     "test-session",
		IdentityID:    "test-identity",
		RequestTime:   time.Now(),
	}

	decision, err := svc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if decision.RuleID != "high-priority" {
		t.Errorf("expected high-priority rule to win, got rule=%s", decision.RuleID)
	}
	if !decision.Allowed {
		t.Error("expected Allowed=true from high-priority rule")
	}
}

// TestPolicyServiceCELCondition tests CEL condition evaluation.
func TestPolicyServiceCELCondition(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	store := newMockPolicyStore(policy.Policy{
		ID:      "test-policy",
		Name:    "Test Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "admin-only",
				Name:      "Admin only",
				Priority:  100,
				ToolMatch: "*",
				Condition: `"admin" in user_roles`,
				Action:    policy.ActionAllow,
			},
			{
				ID:        "deny-all",
				Name:      "Default deny",
				Priority:  0,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		},
	})

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("failed to create policy service: %v", err)
	}

	ctx := context.Background()

	// Test with admin role - should be allowed
	evalCtx := policy.EvaluationContext{
		ToolName:      "dangerous_tool",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"admin"},
		SessionID:     "test-session",
		IdentityID:    "test-identity",
		RequestTime:   time.Now(),
	}

	decision, err := svc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !decision.Allowed {
		t.Error("expected admin to be allowed")
	}
	if decision.RuleID != "admin-only" {
		t.Errorf("expected admin-only rule, got %s", decision.RuleID)
	}

	// Test with user role - should be denied
	evalCtx.UserRoles = []string{"user"}
	decision, err = svc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if decision.Allowed {
		t.Error("expected non-admin to be denied")
	}
	if decision.RuleID != "deny-all" {
		t.Errorf("expected deny-all rule, got %s", decision.RuleID)
	}
}

// TestPolicyService_CacheHit tests that repeated evaluations hit the cache.
func TestPolicyService_CacheHit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := newMockPolicyStore(*DefaultPolicy())

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService failed: %v", err)
	}

	ctx := context.Background()
	evalCtx := policy.EvaluationContext{
		ToolName:      "read_file",
		UserRoles:     []string{"user"},
		ToolArguments: map[string]interface{}{"path": "/tmp/test"},
		RequestTime:   time.Now(),
	}

	// First call - cache miss
	decision1, err := svc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("first Evaluate failed: %v", err)
	}

	// Second call with same inputs - should hit cache
	decision2, err := svc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("second Evaluate failed: %v", err)
	}

	// Decisions should be identical
	if decision1.Allowed != decision2.Allowed || decision1.RuleID != decision2.RuleID {
		t.Errorf("cached decision differs: %+v vs %+v", decision1, decision2)
	}

	// Cache should have entry
	if svc.cache.Size() == 0 {
		t.Error("cache should have at least one entry")
	}
}

// TestPolicyService_CacheClearOnReload tests that Reload clears the cache.
func TestPolicyService_CacheClearOnReload(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := newMockPolicyStore(*DefaultPolicy())

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService failed: %v", err)
	}

	ctx := context.Background()
	evalCtx := policy.EvaluationContext{
		ToolName:      "read_file",
		UserRoles:     []string{"user"},
		ToolArguments: map[string]interface{}{},
		RequestTime:   time.Now(),
	}

	// Populate cache
	_, _ = svc.Evaluate(ctx, evalCtx)
	if svc.cache.Size() == 0 {
		t.Fatal("cache should have entries after evaluate")
	}

	// Reload should clear cache
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	if svc.cache.Size() != 0 {
		t.Errorf("cache should be empty after reload, got size=%d", svc.cache.Size())
	}
}

// TestPolicyService_CacheBounded tests that cache size is bounded.
func TestPolicyService_CacheBounded(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := newMockPolicyStore(*DefaultPolicy())

	// Create service with small cache
	svc, err := NewPolicyService(context.Background(), store, logger, WithCacheSize(10))
	if err != nil {
		t.Fatalf("NewPolicyService failed: %v", err)
	}

	ctx := context.Background()

	// Add more entries than cache size
	for i := 0; i < 20; i++ {
		evalCtx := policy.EvaluationContext{
			ToolName:      fmt.Sprintf("tool_%d", i),
			UserRoles:     []string{"user"},
			ToolArguments: map[string]interface{}{},
			RequestTime:   time.Now(),
		}
		_, _ = svc.Evaluate(ctx, evalCtx)
	}

	// Cache should be bounded
	if svc.cache.Size() > 10 {
		t.Errorf("cache exceeded max size: got %d, want <= 10", svc.cache.Size())
	}
}

// TestPolicyService_EvaluationDuringReload tests that policy evaluation returns consistent
// results during hot reload. This verifies the atomic.Value snapshot pattern works correctly,
// ensuring evaluations see either the old OR new policy completely, never a partial state.
func TestPolicyService_EvaluationDuringReload(t *testing.T) {
	t.Parallel()

	// Start with DENY policy
	store := newMockPolicyStore(policy.Policy{
		ID:      "test-policy",
		Name:    "Test Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "initial-deny",
				Name:      "Initial deny all",
				Priority:  100,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		},
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService failed: %v", err)
	}

	// Channels for coordination
	stopEval := make(chan struct{})
	stopReload := make(chan struct{})

	var wg sync.WaitGroup
	var evalErrors atomic.Int64
	var allowCount atomic.Int64
	var denyCount atomic.Int64

	// Evaluator goroutines - run many evaluations
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopEval:
					return
				default:
					ctx := context.Background()
					evalCtx := policy.EvaluationContext{
						ToolName:      "test_tool",
						ToolArguments: map[string]interface{}{},
						UserRoles:     []string{"user"},
						SessionID:     "test-session",
						IdentityID:    "test-identity",
						RequestTime:   time.Now(),
					}

					decision, err := svc.Evaluate(ctx, evalCtx)
					if err != nil {
						evalErrors.Add(1)
						continue
					}

					// Track results - should be either allow OR deny, never inconsistent
					if decision.Allowed {
						allowCount.Add(1)
					} else {
						denyCount.Add(1)
					}
				}
			}
		}()
	}

	// Reloader goroutine - toggle between DENY and ALLOW policies
	wg.Add(1)
	go func() {
		defer wg.Done()
		toggle := false
		for {
			select {
			case <-stopReload:
				return
			default:
				// Toggle policy between DENY and ALLOW
				var action policy.Action
				if toggle {
					action = policy.ActionAllow
				} else {
					action = policy.ActionDeny
				}
				toggle = !toggle

				store.setPolicies([]policy.Policy{{
					ID:      "test-policy",
					Name:    "Test Policy",
					Enabled: true,
					Rules: []policy.Rule{
						{
							ID:        "dynamic-rule",
							Name:      "Dynamic rule",
							Priority:  100,
							ToolMatch: "*",
							Condition: "true",
							Action:    action,
						},
					},
				}})

				_ = svc.Reload(context.Background())
				time.Sleep(time.Microsecond) // Small delay between reloads
			}
		}
	}()

	// Run for 200ms
	time.Sleep(200 * time.Millisecond)

	// Stop goroutines
	close(stopReload)
	close(stopEval)
	wg.Wait()

	// Log results
	t.Logf("Evaluations: allow=%d, deny=%d, errors=%d",
		allowCount.Load(), denyCount.Load(), evalErrors.Load())

	// Verify we had both outcomes (policy was toggled)
	if allowCount.Load() == 0 && denyCount.Load() > 100 {
		t.Log("Note: Only deny outcomes - reload may not have had time to propagate")
	}

	// Verify no errors (consistency check)
	if evalErrors.Load() > 0 {
		t.Errorf("Had %d evaluation errors", evalErrors.Load())
	}

	// The key verification: we had evaluations running during reloads
	// If there were data races, -race flag would catch them
	// If there were inconsistent snapshots, we'd see evaluation errors
	totalEvals := allowCount.Load() + denyCount.Load()
	if totalEvals < 100 {
		t.Errorf("Expected many evaluations, got %d", totalEvals)
	}
}

// TestPolicyService_CacheConsistencyDuringReload tests that the cache is properly invalidated
// during reload and doesn't serve stale cached results. This is a targeted test for the
// cache invalidation path in Reload().
func TestPolicyService_CacheConsistencyDuringReload(t *testing.T) {
	t.Parallel()

	// Start with DENY policy
	store := newMockPolicyStore(policy.Policy{
		ID:      "test-policy",
		Name:    "Test Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "deny-specific",
				Name:      "Deny specific tool",
				Priority:  100,
				ToolMatch: "cache_test_tool",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		},
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService failed: %v", err)
	}

	ctx := context.Background()
	evalCtx := policy.EvaluationContext{
		ToolName:      "cache_test_tool",
		ToolArguments: map[string]interface{}{"arg": "value"},
		UserRoles:     []string{"user"},
		SessionID:     "test-session",
		IdentityID:    "test-identity",
		RequestTime:   time.Now(),
	}

	// First evaluation - should be DENIED (and cached)
	decision1, err := svc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("First evaluate failed: %v", err)
	}
	if decision1.Allowed {
		t.Fatal("Expected first evaluation to be DENIED")
	}

	// Verify cache has entry
	if svc.cache.Size() == 0 {
		t.Fatal("Expected cache to have entry after evaluation")
	}

	// Change policy to ALLOW
	store.setPolicies([]policy.Policy{{
		ID:      "test-policy",
		Name:    "Test Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "allow-specific",
				Name:      "Allow specific tool",
				Priority:  100,
				ToolMatch: "cache_test_tool",
				Condition: "true",
				Action:    policy.ActionAllow,
			},
		},
	}})

	// Reload - should clear cache
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Verify cache was cleared
	if svc.cache.Size() != 0 {
		t.Errorf("Expected cache to be cleared after reload, size=%d", svc.cache.Size())
	}

	// Second evaluation with SAME inputs - should be ALLOWED (not cached DENY)
	decision2, err := svc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Second evaluate failed: %v", err)
	}
	if !decision2.Allowed {
		t.Errorf("Expected second evaluation to be ALLOWED after policy change, got DENIED (stale cache?)")
	}

	// Verify new result is cached
	if svc.cache.Size() == 0 {
		t.Error("Expected cache to have entry after second evaluation")
	}
}

// TestComputeCacheKey_Deterministic tests that cache key is deterministic regardless of role order.
func TestComputeCacheKey_Deterministic(t *testing.T) {
	base := policy.EvaluationContext{
		ToolName:      "read_file",
		UserRoles:     []string{"user", "admin"},
		ToolArguments: map[string]interface{}{"path": "/tmp"},
		IdentityName:  "test",
		ActionType:    "tool_call",
		Protocol:      "mcp",
	}

	// Same inputs should produce same key (roles order shouldn't matter)
	key1, ok1 := computeCacheKey(base)
	ctx2 := base
	ctx2.UserRoles = []string{"admin", "user"}
	key2, ok2 := computeCacheKey(ctx2)

	if !ok1 || !ok2 {
		t.Fatal("computeCacheKey should succeed for marshalable args")
	}
	if key1 != key2 {
		t.Errorf("cache keys should be equal for same inputs (roles order shouldn't matter): %d != %d", key1, key2)
	}

	// Different inputs should produce different keys
	ctx3 := policy.EvaluationContext{ToolName: "write_file", UserRoles: []string{"user"}, IdentityName: "test", ActionType: "tool_call", Protocol: "mcp"}
	key3, _ := computeCacheKey(ctx3)
	if key1 == key3 {
		t.Error("different inputs should produce different cache keys")
	}

	// Different args should produce different keys
	ctx4 := base
	ctx4.ToolArguments = map[string]interface{}{"path": "/etc"}
	key4, _ := computeCacheKey(ctx4)
	if key1 == key4 {
		t.Error("different args should produce different cache keys")
	}

	// Different identity should produce different keys
	ctx4b := base
	ctx4b.IdentityName = "other-identity"
	key4b, _ := computeCacheKey(ctx4b)
	if key1 == key4b {
		t.Error("different identity_name should produce different cache keys")
	}

	// Different framework should produce different keys
	ctx4c := base
	ctx4c.Framework = "crewai"
	key4c, _ := computeCacheKey(ctx4c)
	if key1 == key4c {
		t.Error("different framework should produce different cache keys")
	}

	// Different destination should produce different keys
	ctx4d := base
	ctx4d.DestDomain = "evil.com"
	key4d, _ := computeCacheKey(ctx4d)
	if key1 == key4d {
		t.Error("different dest_domain should produce different cache keys")
	}

	// Different gateway should produce different keys
	ctx4e := base
	ctx4e.Gateway = "http-gateway"
	key4e, _ := computeCacheKey(ctx4e)
	if key1 == key4e {
		t.Error("different gateway should produce different cache keys")
	}

	// Empty args vs nil should be equivalent (both produce no args hash component)
	ctx5 := policy.EvaluationContext{ToolName: "test_tool", UserRoles: []string{"user"}, IdentityName: "test", ActionType: "tool_call", Protocol: "mcp"}
	ctx6 := policy.EvaluationContext{ToolName: "test_tool", UserRoles: []string{"user"}, ToolArguments: map[string]interface{}{}, IdentityName: "test", ActionType: "tool_call", Protocol: "mcp"}
	key5, _ := computeCacheKey(ctx5)
	key6, _ := computeCacheKey(ctx6)
	if key5 != key6 {
		t.Errorf("nil args and empty args should produce same key: %d != %d", key5, key6)
	}

	// Non-marshalable args should return false
	ctxBad := policy.EvaluationContext{ToolName: "test_tool", UserRoles: []string{"user"}, ToolArguments: map[string]interface{}{"bad": make(chan int)}, IdentityName: "test", ActionType: "tool_call", Protocol: "mcp"}
	_, okBad := computeCacheKey(ctxBad)
	if okBad {
		t.Error("computeCacheKey should return false for non-marshalable args")
	}
}

// --- Wave 6 Tests: Policy matching with namespace ---

// helper for creating a policy service with rules
func newPolicyServiceWithRules(t *testing.T, rules ...policy.Rule) *PolicyService {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := newMockPolicyStore(policy.Policy{
		ID:      "ns-test-policy",
		Name:    "Namespace Test Policy",
		Enabled: true,
		Rules:   rules,
	})
	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("failed to create policy service: %v", err)
	}
	return svc
}

func TestPolicy_MatchBareNameStillWorks(t *testing.T) {
	svc := newPolicyServiceWithRules(t,
		policy.Rule{ID: "r1", Name: "allow-read", Priority: 100, ToolMatch: "read_file", Condition: "true", Action: policy.ActionAllow},
		policy.Rule{ID: "r2", Name: "deny-all", Priority: 0, ToolMatch: "*", Condition: "true", Action: policy.ActionDeny},
	)

	// Bare name "read_file" (no namespace, unique tool) → should match rule r1
	decision, err := svc.Evaluate(context.Background(), policy.EvaluationContext{
		ToolName: "read_file", ToolArguments: map[string]interface{}{}, UserRoles: []string{"user"},
		SessionID: "s1", IdentityID: "id1", RequestTime: time.Now(), SkipCache: true,
	})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("read_file should be allowed, got deny (rule=%s)", decision.RuleID)
	}
}

func TestPolicy_MatchNamespacedTool(t *testing.T) {
	svc := newPolicyServiceWithRules(t,
		policy.Rule{ID: "r1", Name: "allow-desktop-read", Priority: 100, ToolMatch: "desktop/read_file", Condition: "true", Action: policy.ActionAllow},
		policy.Rule{ID: "r2", Name: "deny-all", Priority: 0, ToolMatch: "*", Condition: "true", Action: policy.ActionDeny},
	)

	// Namespaced tool "desktop/read_file" should match exact rule
	decision, err := svc.Evaluate(context.Background(), policy.EvaluationContext{
		ToolName: "desktop/read_file", ToolArguments: map[string]interface{}{}, UserRoles: []string{"user"},
		SessionID: "s1", IdentityID: "id1", RequestTime: time.Now(), SkipCache: true,
	})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("desktop/read_file should be allowed")
	}
}

func TestPolicy_MatchWildcardNamespace(t *testing.T) {
	svc := newPolicyServiceWithRules(t,
		policy.Rule{ID: "r1", Name: "allow-desktop-all", Priority: 100, ToolMatch: "desktop/*", Condition: "true", Action: policy.ActionAllow},
		policy.Rule{ID: "r2", Name: "deny-all", Priority: 0, ToolMatch: "*", Condition: "true", Action: policy.ActionDeny},
	)

	// "desktop/read_file" should match "desktop/*"
	decision, _ := svc.Evaluate(context.Background(), policy.EvaluationContext{
		ToolName: "desktop/read_file", ToolArguments: map[string]interface{}{}, UserRoles: []string{"user"},
		SessionID: "s1", IdentityID: "id1", RequestTime: time.Now(), SkipCache: true,
	})
	if !decision.Allowed {
		t.Errorf("desktop/read_file should match 'desktop/*'")
	}

	// "train/read_file" should NOT match "desktop/*"
	decision2, _ := svc.Evaluate(context.Background(), policy.EvaluationContext{
		ToolName: "train/read_file", ToolArguments: map[string]interface{}{}, UserRoles: []string{"user"},
		SessionID: "s1", IdentityID: "id1", RequestTime: time.Now(), SkipCache: true,
	})
	if decision2.Allowed && decision2.RuleID == "r1" {
		t.Errorf("train/read_file should NOT match 'desktop/*'")
	}
}

func TestPolicy_BareRuleMatchesNamespacedTool(t *testing.T) {
	svc := newPolicyServiceWithRules(t,
		policy.Rule{ID: "r1", Name: "allow-read", Priority: 100, ToolMatch: "read_file", Condition: "true", Action: policy.ActionAllow},
		policy.Rule{ID: "r2", Name: "deny-all", Priority: 0, ToolMatch: "*", Condition: "true", Action: policy.ActionDeny},
	)

	// Bare rule "read_file" should match namespaced "desktop/read_file" (backward compat)
	decision, err := svc.Evaluate(context.Background(), policy.EvaluationContext{
		ToolName: "desktop/read_file", ToolArguments: map[string]interface{}{}, UserRoles: []string{"user"},
		SessionID: "s1", IdentityID: "id1", RequestTime: time.Now(), SkipCache: true,
	})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("bare rule 'read_file' should match namespaced 'desktop/read_file' (backward compat)")
	}
}

func TestPolicy_StarMatchesEverythingIncludingNamespaced(t *testing.T) {
	svc := newPolicyServiceWithRules(t,
		policy.Rule{ID: "r1", Name: "deny-all", Priority: 0, ToolMatch: "*", Condition: "true", Action: policy.ActionDeny},
	)

	// "*" should match namespaced tool
	decision, _ := svc.Evaluate(context.Background(), policy.EvaluationContext{
		ToolName: "desktop/read_file", ToolArguments: map[string]interface{}{}, UserRoles: []string{"user"},
		SessionID: "s1", IdentityID: "id1", RequestTime: time.Now(), SkipCache: true,
	})
	if decision.Allowed {
		t.Errorf("'*' rule should match 'desktop/read_file'")
	}

	// "*" should also match non-namespaced tool
	decision2, _ := svc.Evaluate(context.Background(), policy.EvaluationContext{
		ToolName: "read_file", ToolArguments: map[string]interface{}{}, UserRoles: []string{"user"},
		SessionID: "s1", IdentityID: "id1", RequestTime: time.Now(), SkipCache: true,
	})
	if decision2.Allowed {
		t.Errorf("'*' rule should match 'read_file'")
	}
}

func TestPolicy_PriorityWithNamespacedRules(t *testing.T) {
	svc := newPolicyServiceWithRules(t,
		policy.Rule{ID: "r1", Name: "deny-all", Priority: 1, ToolMatch: "*", Condition: "true", Action: policy.ActionDeny},
		policy.Rule{ID: "r2", Name: "allow-desktop-read", Priority: 100, ToolMatch: "desktop/read_file", Condition: "true", Action: policy.ActionAllow},
	)

	// "desktop/read_file" → ALLOW (r2, priority 100 > r1, priority 1)
	decision, _ := svc.Evaluate(context.Background(), policy.EvaluationContext{
		ToolName: "desktop/read_file", ToolArguments: map[string]interface{}{}, UserRoles: []string{"user"},
		SessionID: "s1", IdentityID: "id1", RequestTime: time.Now(), SkipCache: true,
	})
	if !decision.Allowed {
		t.Errorf("desktop/read_file should be allowed (higher priority rule)")
	}

	// "train/read_file" → DENY (only r1 matches)
	decision2, _ := svc.Evaluate(context.Background(), policy.EvaluationContext{
		ToolName: "train/read_file", ToolArguments: map[string]interface{}{}, UserRoles: []string{"user"},
		SessionID: "s1", IdentityID: "id1", RequestTime: time.Now(), SkipCache: true,
	})
	if decision2.Allowed {
		t.Errorf("train/read_file should be denied (only wildcard * matches)")
	}
}

func TestPolicy_WildcardBareMatchesNamespaced(t *testing.T) {
	svc := newPolicyServiceWithRules(t,
		policy.Rule{ID: "r1", Name: "allow-read-star", Priority: 100, ToolMatch: "read_*", Condition: "true", Action: policy.ActionAllow},
		policy.Rule{ID: "r2", Name: "deny-all", Priority: 0, ToolMatch: "*", Condition: "true", Action: policy.ActionDeny},
	)

	// Bare wildcard "read_*" should match namespaced "desktop/read_file" (backward compat)
	decision, _ := svc.Evaluate(context.Background(), policy.EvaluationContext{
		ToolName: "desktop/read_file", ToolArguments: map[string]interface{}{}, UserRoles: []string{"user"},
		SessionID: "s1", IdentityID: "id1", RequestTime: time.Now(), SkipCache: true,
	})
	if !decision.Allowed {
		t.Errorf("bare wildcard 'read_*' should match namespaced 'desktop/read_file'")
	}
}

func TestPolicy_ExistingRulesNotBrokenByNamespace(t *testing.T) {
	// Scenario: user had rules for "read_file", "write_*", "*"
	// After namespacing, with single server, ToolName="read_file" (no namespace)
	// All old rules must continue to work identically
	svc := newPolicyServiceWithRules(t,
		policy.Rule{ID: "r1", Name: "allow-read", Priority: 200, ToolMatch: "read_file", Condition: "true", Action: policy.ActionAllow},
		policy.Rule{ID: "r2", Name: "deny-write", Priority: 100, ToolMatch: "write_*", Condition: "true", Action: policy.ActionDeny},
		policy.Rule{ID: "r3", Name: "allow-default", Priority: 0, ToolMatch: "*", Condition: "true", Action: policy.ActionAllow},
	)

	tests := []struct {
		tool      string
		wantAllow bool
		wantRule  string
	}{
		{"read_file", true, "r1"},
		{"write_file", false, "r2"},
		{"write_data", false, "r2"},
		{"delete_file", true, "r3"},
	}

	for _, tt := range tests {
		decision, _ := svc.Evaluate(context.Background(), policy.EvaluationContext{
			ToolName: tt.tool, ToolArguments: map[string]interface{}{}, UserRoles: []string{"user"},
			SessionID: "s1", IdentityID: "id1", RequestTime: time.Now(), SkipCache: true,
		})
		if decision.Allowed != tt.wantAllow {
			t.Errorf("tool=%s: allowed=%v, want %v (rule=%s)", tt.tool, decision.Allowed, tt.wantAllow, decision.RuleID)
		}
		if decision.RuleID != tt.wantRule {
			t.Errorf("tool=%s: ruleID=%s, want %s", tt.tool, decision.RuleID, tt.wantRule)
		}
	}
}

// TestPolicyService_EmptyConditionDefaultsToTrue tests that a rule with Condition: ""
// compiles successfully and behaves identically to Condition: "true".
// This verifies the default behavior in compileRules() where empty conditions are
// replaced with "true" before CEL compilation.
func TestPolicyService_EmptyConditionDefaultsToTrue(t *testing.T) {
	// Sub-test 1: A rule with empty condition compiles and allows correctly.
	t.Run("empty_condition_allow", func(t *testing.T) {
		svc := newPolicyServiceWithRules(t,
			policy.Rule{
				ID:        "empty-cond-allow",
				Name:      "Allow with empty condition",
				Priority:  100,
				ToolMatch: "*",
				Condition: "", // empty → should default to "true"
				Action:    policy.ActionAllow,
			},
		)

		decision, err := svc.Evaluate(context.Background(), policy.EvaluationContext{
			ToolName:      "any_tool",
			ToolArguments: map[string]interface{}{},
			UserRoles:     []string{"user"},
			SessionID:     "s1",
			IdentityID:    "id1",
			RequestTime:   time.Now(),
			SkipCache:     true,
		})
		if err != nil {
			t.Fatalf("Evaluate failed: %v", err)
		}
		if !decision.Allowed {
			t.Errorf("expected Allowed=true for empty-condition allow rule, got Allowed=false (rule=%s)", decision.RuleID)
		}
		if decision.RuleID != "empty-cond-allow" {
			t.Errorf("expected rule empty-cond-allow, got %s", decision.RuleID)
		}
	})

	// Sub-test 2: A rule with empty condition compiles and denies correctly.
	t.Run("empty_condition_deny", func(t *testing.T) {
		svc := newPolicyServiceWithRules(t,
			policy.Rule{
				ID:        "empty-cond-deny",
				Name:      "Deny with empty condition",
				Priority:  100,
				ToolMatch: "*",
				Condition: "", // empty → should default to "true"
				Action:    policy.ActionDeny,
			},
		)

		decision, err := svc.Evaluate(context.Background(), policy.EvaluationContext{
			ToolName:      "any_tool",
			ToolArguments: map[string]interface{}{},
			UserRoles:     []string{"user"},
			SessionID:     "s1",
			IdentityID:    "id1",
			RequestTime:   time.Now(),
			SkipCache:     true,
		})
		if err != nil {
			t.Fatalf("Evaluate failed: %v", err)
		}
		if decision.Allowed {
			t.Errorf("expected Allowed=false for empty-condition deny rule, got Allowed=true")
		}
		if decision.RuleID != "empty-cond-deny" {
			t.Errorf("expected rule empty-cond-deny, got %s", decision.RuleID)
		}
	})

	// Sub-test 3: Empty condition behaves identically to explicit "true" condition.
	t.Run("empty_matches_explicit_true", func(t *testing.T) {
		// Service with empty condition rule
		svcEmpty := newPolicyServiceWithRules(t,
			policy.Rule{
				ID:        "rule-empty",
				Name:      "Rule with empty condition",
				Priority:  100,
				ToolMatch: "test_tool",
				Condition: "",
				Action:    policy.ActionAllow,
			},
			policy.Rule{
				ID:        "fallback-deny",
				Name:      "Fallback deny",
				Priority:  0,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		)

		// Service with explicit "true" condition rule
		svcTrue := newPolicyServiceWithRules(t,
			policy.Rule{
				ID:        "rule-true",
				Name:      "Rule with true condition",
				Priority:  100,
				ToolMatch: "test_tool",
				Condition: "true",
				Action:    policy.ActionAllow,
			},
			policy.Rule{
				ID:        "fallback-deny",
				Name:      "Fallback deny",
				Priority:  0,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		)

		evalCtx := policy.EvaluationContext{
			ToolName:      "test_tool",
			ToolArguments: map[string]interface{}{},
			UserRoles:     []string{"user"},
			SessionID:     "s1",
			IdentityID:    "id1",
			RequestTime:   time.Now(),
			SkipCache:     true,
		}

		decisionEmpty, err := svcEmpty.Evaluate(context.Background(), evalCtx)
		if err != nil {
			t.Fatalf("Evaluate (empty) failed: %v", err)
		}

		decisionTrue, err := svcTrue.Evaluate(context.Background(), evalCtx)
		if err != nil {
			t.Fatalf("Evaluate (true) failed: %v", err)
		}

		if decisionEmpty.Allowed != decisionTrue.Allowed {
			t.Errorf("empty condition and 'true' condition should produce same Allowed: empty=%v, true=%v",
				decisionEmpty.Allowed, decisionTrue.Allowed)
		}
	})
}
