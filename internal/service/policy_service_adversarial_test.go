package service

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// quietLogger returns a logger that discards all output.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// evalCtx is a helper to build a minimal EvaluationContext for testing.
func evalCtx(toolName string) policy.EvaluationContext {
	return policy.EvaluationContext{
		ToolName:      toolName,
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"user"},
		SessionID:     "test-session",
		IdentityID:    "test-identity",
		RequestTime:   time.Now(),
		SkipCache:     true, // avoid cache interference between subtests
	}
}

// TestPolicy_WildcardMatchUnexpected (3B.1) tests glob edge cases in tool matching.
// filepath.Match("db_*", "db_") should match (star matches empty string).
// filepath.Match is case-sensitive, so "DB_READ" should not match "db_*".
func TestPolicy_WildcardMatchUnexpected(t *testing.T) {
	t.Parallel()

	logger := quietLogger()

	store := newMockPolicyStore(policy.Policy{
		ID:      "wildcard-policy",
		Name:    "Wildcard Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "deny-db",
				Name:      "Deny db tools",
				Priority:  100,
				ToolMatch: "db_*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		},
	})

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService failed: %v", err)
	}

	tests := []struct {
		name      string
		toolName  string
		wantAllow bool
		wantRule  string
	}{
		{
			name:      "db_read matches db_* (normal case)",
			toolName:  "db_read",
			wantAllow: false,
			wantRule:  "deny-db",
		},
		{
			name:      "db_ matches db_* (empty suffix, star matches empty)",
			toolName:  "db_",
			wantAllow: false,
			wantRule:  "deny-db",
		},
		{
			name:      "DB_READ does NOT match db_* (case sensitive)",
			toolName:  "DB_READ",
			wantAllow: true, // default allow — no matching rule
			wantRule:  "",
		},
		{
			name:      "db does NOT match db_* (missing underscore)",
			toolName:  "db",
			wantAllow: true,
			wantRule:  "",
		},
		{
			name:      "xdb_read does NOT match db_* (prefix mismatch)",
			toolName:  "xdb_read",
			wantAllow: true,
			wantRule:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			decision, err := svc.Evaluate(ctx, evalCtx(tt.toolName))
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}

			if decision.Allowed != tt.wantAllow {
				t.Errorf("tool=%q: want Allowed=%v, got Allowed=%v (rule=%s, reason=%s)",
					tt.toolName, tt.wantAllow, decision.Allowed, decision.RuleID, decision.Reason)
			}
			if decision.RuleID != tt.wantRule {
				t.Errorf("tool=%q: want RuleID=%q, got RuleID=%q",
					tt.toolName, tt.wantRule, decision.RuleID)
			}
		})
	}
}

// TestPolicy_StaleCacheAfterReload (3B.2) verifies that Reload() clears the
// result cache so stale deny decisions are not served after a policy is disabled.
func TestPolicy_StaleCacheAfterReload(t *testing.T) {
	t.Parallel()

	logger := quietLogger()

	store := newMockPolicyStore(policy.Policy{
		ID:      "secret-policy",
		Name:    "Secret Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "deny-secret",
				Name:      "Deny secret_tool",
				Priority:  100,
				ToolMatch: "secret_tool",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		},
	})

	// Use cache (SkipCache=false) to exercise the cache path.
	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService failed: %v", err)
	}

	ctx := context.Background()
	ec := policy.EvaluationContext{
		ToolName:      "secret_tool",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"user"},
		SessionID:     "test-session",
		IdentityID:    "test-identity",
		RequestTime:   time.Now(),
		SkipCache:     false, // explicitly use cache
	}

	// Step 1: Evaluate — should be DENIED and cached.
	decision, err := svc.Evaluate(ctx, ec)
	if err != nil {
		t.Fatalf("first Evaluate failed: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected first evaluation to be DENIED")
	}
	// NOTE: Intentionally accessing unexported field svc.cache to verify
	// caching behavior — this is an internal (same-package) test.
	if svc.cache.Size() == 0 {
		t.Fatal("expected cache to have an entry after first evaluation")
	}

	// Step 2: Disable the policy in the store.
	store.setPolicies([]policy.Policy{
		{
			ID:      "secret-policy",
			Name:    "Secret Policy",
			Enabled: false, // DISABLED
			Rules: []policy.Rule{
				{
					ID:        "deny-secret",
					Name:      "Deny secret_tool",
					Priority:  100,
					ToolMatch: "secret_tool",
					Condition: "true",
					Action:    policy.ActionDeny,
				},
			},
		},
	})

	// Step 3: Reload — should clear cache and exclude disabled policies.
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}
	if svc.cache.Size() != 0 {
		t.Errorf("expected cache to be empty after Reload, got size=%d", svc.cache.Size())
	}

	// Step 4: Evaluate again — should be ALLOWED (default allow, no matching rule).
	decision, err = svc.Evaluate(ctx, ec)
	if err != nil {
		t.Fatalf("second Evaluate failed: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("expected second evaluation to be ALLOWED after disabling policy, got DENIED (stale cache?): rule=%s reason=%s",
			decision.RuleID, decision.Reason)
	}
}

// TestPolicy_ToolNamePathTraversal (3B.3) verifies that path traversal in tool
// names does not bypass glob patterns. filepath.Match does not match ".." segments
// against simple patterns.
func TestPolicy_ToolNamePathTraversal(t *testing.T) {
	t.Parallel()

	logger := quietLogger()

	store := newMockPolicyStore(policy.Policy{
		ID:      "admin-policy",
		Name:    "Admin Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "deny-admin",
				Name:      "Deny admin tools",
				Priority:  100,
				ToolMatch: "admin/*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		},
	})

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService failed: %v", err)
	}

	tests := []struct {
		name      string
		toolName  string
		wantAllow bool
	}{
		{
			name:      "admin/secret_tool matches admin/*",
			toolName:  "admin/secret_tool",
			wantAllow: false, // matches the deny rule
		},
		{
			name:      "../admin/secret_tool does NOT match admin/*",
			toolName:  "../admin/secret_tool",
			wantAllow: true, // filepath.Match won't match "../" prefix
		},
		{
			name:      "admin/../admin/secret_tool does NOT match admin/*",
			toolName:  "admin/../admin/secret_tool",
			wantAllow: true, // filepath.Match requires single segment after "admin/"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			decision, err := svc.Evaluate(ctx, evalCtx(tt.toolName))
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}
			if decision.Allowed != tt.wantAllow {
				t.Errorf("tool=%q: want Allowed=%v, got Allowed=%v (rule=%s, reason=%s)",
					tt.toolName, tt.wantAllow, decision.Allowed, decision.RuleID, decision.Reason)
			}
		})
	}
}

// TestPolicy_ToolNameNullByte (3B.4) verifies that null bytes in tool names
// do not cause truncation in glob matching or CEL evaluation. Go strings are
// not null-terminated, so \x00 is just a regular byte.
func TestPolicy_ToolNameNullByte(t *testing.T) {
	t.Parallel()

	logger := quietLogger()

	store := newMockPolicyStore(policy.Policy{
		ID:      "null-byte-policy",
		Name:    "Null Byte Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{
				ID:        "deny-read",
				Name:      "Deny read_file tools",
				Priority:  100,
				ToolMatch: "read_file",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
		},
	})

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService failed: %v", err)
	}

	ctx := context.Background()

	// "read_file\x00.exe" should NOT match the exact pattern "read_file"
	// because Go strings are not null-terminated — the full string is compared.
	toolWithNull := "read_file\x00.exe"
	decision, err := svc.Evaluate(ctx, evalCtx(toolWithNull))
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if !decision.Allowed {
		t.Errorf("tool=%q should NOT match exact pattern 'read_file' — Go does not truncate at null byte. Got DENIED (rule=%s)",
			toolWithNull, decision.RuleID)
	}

	// Exact "read_file" should still be denied.
	decision, err = svc.Evaluate(ctx, evalCtx("read_file"))
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if decision.Allowed {
		t.Error("tool='read_file' should match exact pattern 'read_file' and be DENIED")
	}

	// Test with wildcard pattern: "read_*" should NOT match "read_file\x00.exe"
	// if there's no such wildcard rule. But let's add one to test glob behavior.
	store.setPolicies([]policy.Policy{
		{
			ID:      "null-byte-policy",
			Name:    "Null Byte Policy",
			Enabled: true,
			Rules: []policy.Rule{
				{
					ID:        "deny-read-glob",
					Name:      "Deny read_* tools (glob)",
					Priority:  100,
					ToolMatch: "read_*",
					Condition: "true",
					Action:    policy.ActionDeny,
				},
			},
		},
	})
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// "read_file\x00.exe" with glob "read_*": filepath.Match treats \x00 as a
	// regular character. The tool name has a \x00 in it, which filepath.Match
	// should handle without truncation.
	decision, err = svc.Evaluate(ctx, evalCtx(toolWithNull))
	if err != nil {
		t.Fatalf("Evaluate with glob failed: %v", err)
	}
	if decision.Allowed {
		t.Error("tool with null byte should still match 'read_*' glob — filepath.Match treats \\x00 as regular char")
	}
}

// TestPolicy_DisabledPolicyEnforcedAtStartup (3B.5) — EXPOSES BUG B7.
//
// BUG B7: NewPolicyService loads ALL policies without checking Enabled.
// Reload() correctly filters by Enabled. This means disabled policies are
// enforced from boot until the first Reload().
//
// This test:
// 1. Creates a store with one enabled policy and one DISABLED policy
// 2. Calls NewPolicyService — expects the disabled policy's rules to NOT be enforced
// 3. If the disabled policy IS enforced (pre-fix), the test fails
// 4. After Reload(), verifies the disabled policy is correctly excluded
func TestPolicy_DisabledPolicyEnforcedAtStartup(t *testing.T) {
	t.Parallel()

	logger := quietLogger()

	store := newMockPolicyStore(
		// Policy 1: ENABLED — allow safe_* tools
		policy.Policy{
			ID:      "enabled-policy",
			Name:    "Enabled Policy",
			Enabled: true,
			Rules: []policy.Rule{
				{
					ID:        "allow-safe",
					Name:      "Allow safe tools",
					Priority:  50,
					ToolMatch: "safe_*",
					Condition: "true",
					Action:    policy.ActionAllow,
				},
			},
		},
		// Policy 2: DISABLED — deny dangerous_tool
		// This should NOT be enforced at all!
		policy.Policy{
			ID:      "disabled-policy",
			Name:    "Disabled Policy",
			Enabled: false, // <-- DISABLED
			Rules: []policy.Rule{
				{
					ID:        "deny-dangerous",
					Name:      "Deny dangerous tool",
					Priority:  100, // higher priority than allow-safe
					ToolMatch: "dangerous_tool",
					Condition: "true",
					Action:    policy.ActionDeny,
				},
			},
		},
	)

	svc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService failed: %v", err)
	}

	ctx := context.Background()

	// Step 1: Evaluate "dangerous_tool" right after boot.
	// EXPECTED (correct behavior): ALLOWED (default allow, disabled policy not enforced)
	// BUG B7 (broken behavior): DENIED (disabled policy incorrectly enforced)
	decision, err := svc.Evaluate(ctx, evalCtx("dangerous_tool"))
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if !decision.Allowed {
		t.Errorf("BUG B7: disabled policy enforced at boot! "+
			"'dangerous_tool' was DENIED by rule=%q but the policy is Enabled=false. "+
			"NewPolicyService does not filter by Enabled.",
			decision.RuleID)
	}

	// Step 2: Verify safe_* tools work (enabled policy).
	decision, err = svc.Evaluate(ctx, evalCtx("safe_read"))
	if err != nil {
		t.Fatalf("Evaluate safe_read failed: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("safe_read should be ALLOWED by enabled policy, got DENIED (rule=%s)", decision.RuleID)
	}

	// Step 3: Reload — should filter out the disabled policy.
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Step 4: Evaluate "dangerous_tool" after Reload.
	// Both pre-fix and post-fix: should be ALLOWED (disabled policy filtered by Reload).
	decision, err = svc.Evaluate(ctx, evalCtx("dangerous_tool"))
	if err != nil {
		t.Fatalf("Evaluate after Reload failed: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("after Reload(), 'dangerous_tool' should be ALLOWED (disabled policy filtered), "+
			"got DENIED (rule=%s)", decision.RuleID)
	}

	// Step 5: Verify consistency — behavior should be the SAME before and after Reload.
	// If we get here and Step 1 also passed, the fix is correct: boot == reload behavior.
}
