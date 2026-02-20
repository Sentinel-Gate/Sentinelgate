// Package memory provides in-memory implementations of outbound ports.
package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

func TestPolicyStore_GetAllPolicies(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	// Add enabled and disabled policies
	store.AddPolicy(&policy.Policy{
		ID:      "policy-enabled-1",
		Name:    "Enabled Policy 1",
		Enabled: true,
	})
	store.AddPolicy(&policy.Policy{
		ID:      "policy-enabled-2",
		Name:    "Enabled Policy 2",
		Enabled: true,
	})
	store.AddPolicy(&policy.Policy{
		ID:      "policy-disabled",
		Name:    "Disabled Policy",
		Enabled: false,
	})

	policies, err := store.GetAllPolicies(ctx)
	if err != nil {
		t.Fatalf("GetAllPolicies() error: %v", err)
	}

	// Should only return enabled policies
	if len(policies) != 2 {
		t.Errorf("GetAllPolicies() returned %d policies, want 2", len(policies))
	}

	// Verify all returned policies are enabled
	for _, p := range policies {
		if !p.Enabled {
			t.Errorf("GetAllPolicies() returned disabled policy %q", p.ID)
		}
	}
}

func TestPolicyStore_GetAllPolicies_Empty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	policies, err := store.GetAllPolicies(ctx)
	if err != nil {
		t.Fatalf("GetAllPolicies() error: %v", err)
	}

	if len(policies) != 0 {
		t.Errorf("GetAllPolicies() on empty store returned %d policies, want 0", len(policies))
	}
}

func TestPolicyStore_GetPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setup    func(*MemoryPolicyStore)
		policyID string
		wantErr  error
	}{
		{
			name: "existing policy",
			setup: func(s *MemoryPolicyStore) {
				s.AddPolicy(&policy.Policy{
					ID:      "existing-policy",
					Name:    "Test Policy",
					Enabled: true,
				})
			},
			policyID: "existing-policy",
			wantErr:  nil,
		},
		{
			name:     "non-existent policy",
			setup:    func(s *MemoryPolicyStore) {},
			policyID: "missing",
			wantErr:  ErrPolicyNotFound,
		},
		{
			name: "disabled policy still retrievable",
			setup: func(s *MemoryPolicyStore) {
				s.AddPolicy(&policy.Policy{
					ID:      "disabled-policy",
					Name:    "Disabled Policy",
					Enabled: false,
				})
			},
			policyID: "disabled-policy",
			wantErr:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			store := NewPolicyStore()
			tt.setup(store)

			got, err := store.GetPolicy(ctx, tt.policyID)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("GetPolicy() error = %v, want %v", err, tt.wantErr)
				return
			}

			if tt.wantErr == nil && got == nil {
				t.Error("GetPolicy() returned nil for existing policy")
			}
		})
	}
}

func TestPolicyStore_SavePolicy_Create(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	p := &policy.Policy{
		ID:          "new-policy",
		Name:        "New Policy",
		Description: "A new policy",
		Priority:    1,
		Enabled:     true,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}

	if err := store.SavePolicy(ctx, p); err != nil {
		t.Fatalf("SavePolicy() error: %v", err)
	}

	// Verify policy was saved
	got, err := store.GetPolicy(ctx, "new-policy")
	if err != nil {
		t.Fatalf("GetPolicy() error: %v", err)
	}

	if got.Name != "New Policy" {
		t.Errorf("Name = %q, want %q", got.Name, "New Policy")
	}
	if got.Description != "A new policy" {
		t.Errorf("Description = %q, want %q", got.Description, "A new policy")
	}
}

func TestPolicyStore_SavePolicy_Update(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	// Create initial policy
	p := &policy.Policy{
		ID:   "update-policy",
		Name: "Original Name",
	}
	if err := store.SavePolicy(ctx, p); err != nil {
		t.Fatalf("SavePolicy() create error: %v", err)
	}

	// Update the policy
	p.Name = "Updated Name"
	p.Description = "Updated description"
	if err := store.SavePolicy(ctx, p); err != nil {
		t.Fatalf("SavePolicy() update error: %v", err)
	}

	// Verify update
	got, err := store.GetPolicy(ctx, "update-policy")
	if err != nil {
		t.Fatalf("GetPolicy() error: %v", err)
	}

	if got.Name != "Updated Name" {
		t.Errorf("Name = %q, want %q", got.Name, "Updated Name")
	}
	if got.Description != "Updated description" {
		t.Errorf("Description = %q, want %q", got.Description, "Updated description")
	}
}

func TestPolicyStore_DeletePolicy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	// Add policy
	store.AddPolicy(&policy.Policy{
		ID:   "delete-me",
		Name: "To Delete",
	})

	// Delete it
	if err := store.DeletePolicy(ctx, "delete-me"); err != nil {
		t.Fatalf("DeletePolicy() error: %v", err)
	}

	// Verify it's gone
	_, err := store.GetPolicy(ctx, "delete-me")
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("GetPolicy() after delete error = %v, want ErrPolicyNotFound", err)
	}
}

func TestPolicyStore_DeletePolicy_NonExistent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	err := store.DeletePolicy(ctx, "nonexistent")
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("DeletePolicy() for non-existent error = %v, want ErrPolicyNotFound", err)
	}
}

func TestPolicyStore_SaveRule_AddNew(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	// Create policy first
	store.AddPolicy(&policy.Policy{
		ID:    "policy-with-rules",
		Name:  "Policy With Rules",
		Rules: []policy.Rule{},
	})

	// Add a new rule (no ID means new rule)
	rule := &policy.Rule{
		Name:      "New Rule",
		Priority:  1,
		ToolMatch: "test_*",
		Condition: "true",
		Action:    policy.ActionAllow,
	}

	if err := store.SaveRule(ctx, "policy-with-rules", rule); err != nil {
		t.Fatalf("SaveRule() error: %v", err)
	}

	// Verify rule was added
	got, err := store.GetPolicyWithRules(ctx, "policy-with-rules")
	if err != nil {
		t.Fatalf("GetPolicyWithRules() error: %v", err)
	}

	if len(got.Rules) != 1 {
		t.Errorf("Rules count = %d, want 1", len(got.Rules))
	}

	if got.Rules[0].Name != "New Rule" {
		t.Errorf("Rule.Name = %q, want %q", got.Rules[0].Name, "New Rule")
	}

	// Verify ID was generated
	if got.Rules[0].ID == "" {
		t.Error("Rule.ID should be generated for new rules")
	}
}

func TestPolicyStore_SaveRule_Update(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	// Create policy with existing rule
	store.AddPolicy(&policy.Policy{
		ID:   "policy-update-rule",
		Name: "Policy Update Rule",
		Rules: []policy.Rule{
			{
				ID:        "rule-1",
				Name:      "Original Rule",
				ToolMatch: "test_*",
				Action:    policy.ActionAllow,
			},
		},
	})

	// Update the existing rule
	rule := &policy.Rule{
		ID:        "rule-1",
		Name:      "Updated Rule",
		ToolMatch: "updated_*",
		Action:    policy.ActionDeny,
	}

	if err := store.SaveRule(ctx, "policy-update-rule", rule); err != nil {
		t.Fatalf("SaveRule() update error: %v", err)
	}

	// Verify rule was updated
	got, err := store.GetPolicyWithRules(ctx, "policy-update-rule")
	if err != nil {
		t.Fatalf("GetPolicyWithRules() error: %v", err)
	}

	if len(got.Rules) != 1 {
		t.Errorf("Rules count = %d, want 1", len(got.Rules))
	}

	if got.Rules[0].Name != "Updated Rule" {
		t.Errorf("Rule.Name = %q, want %q", got.Rules[0].Name, "Updated Rule")
	}
	if got.Rules[0].Action != policy.ActionDeny {
		t.Errorf("Rule.Action = %q, want %q", got.Rules[0].Action, policy.ActionDeny)
	}
}

func TestPolicyStore_SaveRule_NonExistentRule(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	// Create policy
	store.AddPolicy(&policy.Policy{
		ID:    "policy-missing-rule",
		Name:  "Policy",
		Rules: []policy.Rule{},
	})

	// Try to update non-existent rule (has ID but rule doesn't exist)
	rule := &policy.Rule{
		ID:   "nonexistent-rule",
		Name: "Should Fail",
	}

	err := store.SaveRule(ctx, "policy-missing-rule", rule)
	if err == nil {
		t.Error("SaveRule() with non-existent rule ID should return error")
	}
}

func TestPolicyStore_SaveRule_NonExistentPolicy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	rule := &policy.Rule{
		Name: "Test Rule",
	}

	err := store.SaveRule(ctx, "nonexistent-policy", rule)
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("SaveRule() to non-existent policy error = %v, want ErrPolicyNotFound", err)
	}
}

func TestPolicyStore_DeleteRule(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	// Create policy with rules
	store.AddPolicy(&policy.Policy{
		ID:   "policy-delete-rule",
		Name: "Policy",
		Rules: []policy.Rule{
			{ID: "rule-1", Name: "Rule 1"},
			{ID: "rule-2", Name: "Rule 2"},
		},
	})

	// Delete rule-1
	if err := store.DeleteRule(ctx, "policy-delete-rule", "rule-1"); err != nil {
		t.Fatalf("DeleteRule() error: %v", err)
	}

	// Verify rule was deleted
	got, err := store.GetPolicyWithRules(ctx, "policy-delete-rule")
	if err != nil {
		t.Fatalf("GetPolicyWithRules() error: %v", err)
	}

	if len(got.Rules) != 1 {
		t.Errorf("Rules count = %d, want 1", len(got.Rules))
	}
	if got.Rules[0].ID != "rule-2" {
		t.Errorf("Remaining rule ID = %q, want %q", got.Rules[0].ID, "rule-2")
	}
}

func TestPolicyStore_DeleteRule_NonExistent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	// Create policy
	store.AddPolicy(&policy.Policy{
		ID:    "policy-no-rule",
		Name:  "Policy",
		Rules: []policy.Rule{},
	})

	err := store.DeleteRule(ctx, "policy-no-rule", "nonexistent")
	if err == nil {
		t.Error("DeleteRule() for non-existent rule should return error")
	}
}

func TestPolicyStore_DeleteRule_NonExistentPolicy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	err := store.DeleteRule(ctx, "nonexistent-policy", "rule-1")
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Errorf("DeleteRule() from non-existent policy error = %v, want ErrPolicyNotFound", err)
	}
}

func TestPolicyStore_CopyOnReturn(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	store.AddPolicy(&policy.Policy{
		ID:   "copy-test-policy",
		Name: "Original Name",
		Rules: []policy.Rule{
			{ID: "rule-1", Name: "Original Rule"},
		},
	})

	// Get and modify
	got1, err := store.GetPolicy(ctx, "copy-test-policy")
	if err != nil {
		t.Fatalf("GetPolicy() error: %v", err)
	}
	got1.Name = "Modified Name"
	got1.Rules[0].Name = "Modified Rule"
	got1.Rules = append(got1.Rules, policy.Rule{ID: "rule-new", Name: "New Rule"})

	// Get again - should not be modified
	got2, err := store.GetPolicy(ctx, "copy-test-policy")
	if err != nil {
		t.Fatalf("GetPolicy() second call error: %v", err)
	}

	if got2.Name == "Modified Name" {
		t.Error("Store returned reference instead of copy (Name was modified)")
	}
	if len(got2.Rules) != 1 {
		t.Errorf("Store returned reference instead of copy (Rules length = %d, want 1)", len(got2.Rules))
	}
	if got2.Rules[0].Name == "Modified Rule" {
		t.Error("Store returned reference instead of copy (Rule.Name was modified)")
	}
}

func TestPolicyStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	// Add some policies
	for i := 0; i < 10; i++ {
		store.AddPolicy(&policy.Policy{
			ID:      "policy-" + string(rune('0'+i)),
			Name:    "Policy " + string(rune('0'+i)),
			Enabled: true,
		})
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 500)

	// 100 goroutines reading all policies
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.GetAllPolicies(ctx)
			if err != nil {
				errCh <- err
			}
		}()
	}

	// 100 goroutines reading individual policies
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			policyID := "policy-" + string(rune('0'+(idx%10)))
			_, err := store.GetPolicy(ctx, policyID)
			if err != nil && !errors.Is(err, ErrPolicyNotFound) {
				errCh <- err
			}
		}(i)
	}

	// 50 goroutines saving policies
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			p := &policy.Policy{
				ID:      "new-policy-" + string(rune('a'+idx)),
				Name:    "New Policy",
				Enabled: true,
			}
			if err := store.SavePolicy(ctx, p); err != nil {
				errCh <- err
			}
		}(i)
	}

	// 50 goroutines deleting policies
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			policyID := "policy-" + string(rune('0'+(idx%10)))
			// Ignore error - policy might be deleted by another goroutine
			_ = store.DeletePolicy(ctx, policyID)
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent access error: %v", err)
	}
}

func TestPolicyStore_GetPolicyWithRules(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewPolicyStore()

	store.AddPolicy(&policy.Policy{
		ID:   "policy-with-rules",
		Name: "Policy With Rules",
		Rules: []policy.Rule{
			{ID: "rule-1", Name: "Rule 1", ToolMatch: "test_*"},
			{ID: "rule-2", Name: "Rule 2", ToolMatch: "file_*"},
		},
	})

	got, err := store.GetPolicyWithRules(ctx, "policy-with-rules")
	if err != nil {
		t.Fatalf("GetPolicyWithRules() error: %v", err)
	}

	if len(got.Rules) != 2 {
		t.Errorf("Rules count = %d, want 2", len(got.Rules))
	}
}
