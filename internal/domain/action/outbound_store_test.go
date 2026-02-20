package action

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestOutboundStoreListEmptyReturnsEmptySlice(t *testing.T) {
	store := NewMemoryOutboundStore()
	rules, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rules == nil {
		t.Fatal("expected empty slice, got nil")
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(rules))
	}
}

func TestOutboundStoreSaveAndGet(t *testing.T) {
	store := NewMemoryOutboundStore()
	ctx := context.Background()

	rule := &OutboundRule{
		ID:       "rule-1",
		Name:     "Test Rule",
		Mode:     RuleModeBlocklist,
		Action:   RuleActionBlock,
		Enabled:  true,
		Priority: 100,
		Targets: []OutboundTarget{
			{Type: TargetDomain, Value: "evil.com"},
		},
		HelpText: "Blocked",
	}

	if err := store.Save(ctx, rule); err != nil {
		t.Fatalf("unexpected error on Save: %v", err)
	}

	got, err := store.Get(ctx, "rule-1")
	if err != nil {
		t.Fatalf("unexpected error on Get: %v", err)
	}
	if got.ID != "rule-1" {
		t.Errorf("expected ID 'rule-1', got %q", got.ID)
	}
	if got.Name != "Test Rule" {
		t.Errorf("expected Name 'Test Rule', got %q", got.Name)
	}
	if len(got.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(got.Targets))
	}
	if got.Targets[0].Value != "evil.com" {
		t.Errorf("expected target value 'evil.com', got %q", got.Targets[0].Value)
	}
}

func TestOutboundStoreSaveUpdatesExisting(t *testing.T) {
	store := NewMemoryOutboundStore()
	ctx := context.Background()

	rule := &OutboundRule{
		ID:       "rule-1",
		Name:     "Original",
		Mode:     RuleModeBlocklist,
		Priority: 100,
	}
	if err := store.Save(ctx, rule); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Update the same rule
	updated := &OutboundRule{
		ID:       "rule-1",
		Name:     "Updated",
		Mode:     RuleModeAllowlist,
		Priority: 50,
	}
	if err := store.Save(ctx, updated); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.Get(ctx, "rule-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "Updated" {
		t.Errorf("expected Name 'Updated', got %q", got.Name)
	}
	if got.Mode != RuleModeAllowlist {
		t.Errorf("expected Mode allowlist, got %q", got.Mode)
	}
	if got.Priority != 50 {
		t.Errorf("expected Priority 50, got %d", got.Priority)
	}
}

func TestOutboundStoreDelete(t *testing.T) {
	store := NewMemoryOutboundStore()
	ctx := context.Background()

	rule := &OutboundRule{ID: "rule-1", Name: "ToDelete", Priority: 100}
	if err := store.Save(ctx, rule); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.Delete(ctx, "rule-1"); err != nil {
		t.Fatalf("unexpected error on Delete: %v", err)
	}

	_, err := store.Get(ctx, "rule-1")
	if !errors.Is(err, ErrOutboundRuleNotFound) {
		t.Fatalf("expected ErrOutboundRuleNotFound after delete, got: %v", err)
	}
}

func TestOutboundStoreDeleteNonExistent(t *testing.T) {
	store := NewMemoryOutboundStore()
	err := store.Delete(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrOutboundRuleNotFound) {
		t.Fatalf("expected ErrOutboundRuleNotFound, got: %v", err)
	}
}

func TestOutboundStoreGetNonExistent(t *testing.T) {
	store := NewMemoryOutboundStore()
	_, err := store.Get(context.Background(), "does-not-exist")
	if !errors.Is(err, ErrOutboundRuleNotFound) {
		t.Fatalf("expected ErrOutboundRuleNotFound, got: %v", err)
	}
}

func TestOutboundStoreListSortedByPriority(t *testing.T) {
	store := NewMemoryOutboundStore()
	ctx := context.Background()

	rules := []*OutboundRule{
		{ID: "r3", Name: "Third", Priority: 300},
		{ID: "r1", Name: "First", Priority: 100},
		{ID: "r2", Name: "Second", Priority: 200},
	}
	for _, r := range rules {
		if err := store.Save(ctx, r); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	listed, err := store.List(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(listed) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(listed))
	}
	if listed[0].Name != "First" || listed[1].Name != "Second" || listed[2].Name != "Third" {
		t.Errorf("rules not sorted by priority: %s, %s, %s",
			listed[0].Name, listed[1].Name, listed[2].Name)
	}
}

func TestOutboundStoreConcurrentAccess(t *testing.T) {
	store := NewMemoryOutboundStore()
	ctx := context.Background()
	const goroutines = 20

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Concurrent Saves
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			r := &OutboundRule{
				ID:       "concurrent-" + string(rune('A'+idx)),
				Name:     "Concurrent",
				Priority: idx,
			}
			_ = store.Save(ctx, r)
		}(i)
	}

	// Concurrent Lists
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.List(ctx)
		}()
	}

	// Concurrent Deletes (some will fail with not found, that's fine)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_ = store.Delete(ctx, "concurrent-"+string(rune('A'+idx)))
		}(i)
	}

	wg.Wait()
}

func TestOutboundStoreReturnedRulesAreCopies(t *testing.T) {
	store := NewMemoryOutboundStore()
	ctx := context.Background()

	rule := &OutboundRule{
		ID:       "rule-1",
		Name:     "Original",
		Priority: 100,
		Targets: []OutboundTarget{
			{Type: TargetDomain, Value: "example.com"},
		},
	}
	if err := store.Save(ctx, rule); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Get a copy and modify it
	got, err := store.Get(ctx, "rule-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got.Name = "Modified"
	got.Targets[0].Value = "hacked.com"

	// Verify original in store is unchanged
	original, err := store.Get(ctx, "rule-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if original.Name != "Original" {
		t.Errorf("store data was modified: expected 'Original', got %q", original.Name)
	}
	if original.Targets[0].Value != "example.com" {
		t.Errorf("store target was modified: expected 'example.com', got %q", original.Targets[0].Value)
	}

	// Also verify that modifying input to Save doesn't affect stored data
	rule.Name = "InputModified"
	rule.Targets[0].Value = "inputhacked.com"

	stored, err := store.Get(ctx, "rule-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stored.Name != "Original" {
		t.Errorf("stored data affected by input modification: expected 'Original', got %q", stored.Name)
	}
	if stored.Targets[0].Value != "example.com" {
		t.Errorf("stored target affected by input modification: expected 'example.com', got %q", stored.Targets[0].Value)
	}
}
