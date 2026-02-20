package service

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// BenchmarkPolicyEvaluate measures single-threaded policy evaluation.
// Uses Go 1.24+ b.Loop() for robust measurements.
func BenchmarkPolicyEvaluate(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &mockPolicyStore{
		policies: []policy.Policy{*DefaultPolicy()},
	}

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		b.Fatalf("NewPolicyService failed: %v", err)
	}

	ctx := context.Background()
	evalCtx := policy.EvaluationContext{
		ToolName:    "read_file",
		UserRoles:   []string{"user"},
		RequestTime: time.Now(),
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = svc.Evaluate(ctx, evalCtx)
	}
}

// BenchmarkPolicyEvaluateParallel measures concurrent policy evaluation.
// Tests lock-free atomic.Value performance under contention.
func BenchmarkPolicyEvaluateParallel(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &mockPolicyStore{
		policies: []policy.Policy{*DefaultPolicy()},
	}

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		b.Fatalf("NewPolicyService failed: %v", err)
	}

	evalCtx := policy.EvaluationContext{
		ToolName:    "read_file",
		UserRoles:   []string{"user"},
		RequestTime: time.Now(),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		for pb.Next() {
			_, _ = svc.Evaluate(ctx, evalCtx)
		}
	})
}

// BenchmarkPolicyEvaluateCacheHit measures cached evaluation performance.
// Should be significantly faster than uncached due to cache lookup.
func BenchmarkPolicyEvaluateCacheHit(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &mockPolicyStore{
		policies: []policy.Policy{*DefaultPolicy()},
	}

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		b.Fatalf("NewPolicyService failed: %v", err)
	}

	ctx := context.Background()
	evalCtx := policy.EvaluationContext{
		ToolName:    "read_file",
		UserRoles:   []string{"user"},
		RequestTime: time.Now(),
	}

	// Prime the cache
	_, _ = svc.Evaluate(ctx, evalCtx)

	b.ResetTimer()
	for b.Loop() {
		_, _ = svc.Evaluate(ctx, evalCtx)
	}
}

// BenchmarkPolicyEvaluateExactMatch measures exact tool name match (O(1) lookup).
// Creates many rules to demonstrate RuleIndex performance benefit.
func BenchmarkPolicyEvaluateExactMatch(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create policy with many exact-match rules to show index benefit
	rules := make([]policy.Rule, 100)
	for i := 0; i < 100; i++ {
		rules[i] = policy.Rule{
			ID:        fmt.Sprintf("rule-%d", i),
			Priority:  i,
			ToolMatch: fmt.Sprintf("tool_%d", i), // Exact match
			Condition: "true",
			Action:    policy.ActionAllow,
		}
	}

	store := &mockPolicyStore{
		policies: []policy.Policy{{
			ID:      "bench",
			Name:    "Benchmark Policy",
			Enabled: true,
			Rules:   rules,
		}},
	}

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		b.Fatalf("NewPolicyService failed: %v", err)
	}

	ctx := context.Background()
	evalCtx := policy.EvaluationContext{
		ToolName:    "tool_50", // Tool in the middle of the list
		RequestTime: time.Now(),
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = svc.Evaluate(ctx, evalCtx)
	}
}

// BenchmarkPolicyReload measures hot reload performance.
// Uses atomic.Value.Store() which is brief but worth measuring.
func BenchmarkPolicyReload(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &mockPolicyStore{
		policies: []policy.Policy{*DefaultPolicy()},
	}

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		b.Fatalf("NewPolicyService failed: %v", err)
	}

	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		_ = svc.Reload(ctx)
	}
}

// BenchmarkComputeCacheKey measures cache key computation overhead.
// Uses xxhash for fast deterministic hashing.
func BenchmarkComputeCacheKey(b *testing.B) {
	roles := []string{"user", "admin", "developer"}
	args := map[string]interface{}{
		"path":    "/home/user/file.txt",
		"options": map[string]interface{}{"recursive": true},
	}

	b.ResetTimer()
	for b.Loop() {
		_ = computeCacheKey("read_file", roles, args, "test-identity", "tool_call", "mcp", "")
	}
}

// BenchmarkPolicyEvaluateWildcard measures wildcard pattern matching.
// Wildcards require glob matching which is slower than exact match.
func BenchmarkPolicyEvaluateWildcard(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &mockPolicyStore{
		policies: []policy.Policy{{
			ID:      "wildcard-policy",
			Name:    "Wildcard Policy",
			Enabled: true,
			Rules: []policy.Rule{
				{
					ID:        "allow-read",
					Priority:  100,
					ToolMatch: "read_*", // Wildcard pattern
					Condition: "true",
					Action:    policy.ActionAllow,
				},
				{
					ID:        "deny-all",
					Priority:  0,
					ToolMatch: "*",
					Condition: "true",
					Action:    policy.ActionDeny,
				},
			},
		}},
	}

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		b.Fatalf("NewPolicyService failed: %v", err)
	}

	ctx := context.Background()
	evalCtx := policy.EvaluationContext{
		ToolName:    "read_file",
		UserRoles:   []string{"user"},
		RequestTime: time.Now(),
	}

	b.ResetTimer()
	for b.Loop() {
		_, _ = svc.Evaluate(ctx, evalCtx)
	}
}
