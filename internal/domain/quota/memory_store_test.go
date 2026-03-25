package quota

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestMemoryQuotaStore_PutAndGet(t *testing.T) {
	store := NewMemoryQuotaStore()
	ctx := context.Background()

	cfg := &QuotaConfig{
		IdentityID:         "id-1",
		MaxCallsPerSession: 100,
		ToolLimits:         map[string]int64{"read_file": 50},
		Action:             QuotaActionDeny,
		Enabled:            true,
	}

	// Put
	if err := store.Put(ctx, cfg); err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Get
	got, err := store.Get(ctx, "id-1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if got.IdentityID != "id-1" {
		t.Errorf("expected IdentityID 'id-1', got %q", got.IdentityID)
	}
	if got.MaxCallsPerSession != 100 {
		t.Errorf("expected MaxCallsPerSession 100, got %d", got.MaxCallsPerSession)
	}
	if got.ToolLimits["read_file"] != 50 {
		t.Errorf("expected ToolLimits[read_file]=50, got %d", got.ToolLimits["read_file"])
	}

	// Verify it's a copy (modifying returned config should not affect store)
	got.MaxCallsPerSession = 999
	got2, _ := store.Get(ctx, "id-1")
	if got2.MaxCallsPerSession != 100 {
		t.Errorf("store was mutated through returned copy")
	}
}

func TestMemoryQuotaStore_GetNotFound(t *testing.T) {
	store := NewMemoryQuotaStore()
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	if !errors.Is(err, ErrQuotaNotFound) {
		t.Errorf("expected ErrQuotaNotFound, got %v", err)
	}
}

func TestMemoryQuotaStore_Delete(t *testing.T) {
	store := NewMemoryQuotaStore()
	ctx := context.Background()

	cfg := &QuotaConfig{
		IdentityID:         "id-1",
		MaxCallsPerSession: 10,
		Action:             QuotaActionDeny,
		Enabled:            true,
	}
	_ = store.Put(ctx, cfg)

	// Delete
	if err := store.Delete(ctx, "id-1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Should not be found
	_, err := store.Get(ctx, "id-1")
	if !errors.Is(err, ErrQuotaNotFound) {
		t.Errorf("expected ErrQuotaNotFound after delete, got %v", err)
	}

	// Delete nonexistent should not error
	if err := store.Delete(ctx, "nonexistent"); err != nil {
		t.Errorf("Delete nonexistent should not error, got %v", err)
	}
}

func TestMemoryQuotaStore_List(t *testing.T) {
	store := NewMemoryQuotaStore()
	ctx := context.Background()

	// Empty list
	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d items", len(list))
	}

	// Add configs
	_ = store.Put(ctx, &QuotaConfig{IdentityID: "id-1", MaxCallsPerSession: 10, Action: QuotaActionDeny, Enabled: true})
	_ = store.Put(ctx, &QuotaConfig{IdentityID: "id-2", MaxCallsPerSession: 20, Action: QuotaActionWarn, Enabled: true})

	list, err = store.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 items, got %d", len(list))
	}

	// Verify configs are present (order not guaranteed)
	found := map[string]bool{}
	for _, cfg := range list {
		found[cfg.IdentityID] = true
	}
	if !found["id-1"] || !found["id-2"] {
		t.Errorf("expected both id-1 and id-2 in list, got %v", found)
	}
}

func TestMemoryQuotaStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryQuotaStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	const goroutines = 50

	// Concurrent puts
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			cfg := &QuotaConfig{
				IdentityID:         "id-concurrent",
				MaxCallsPerSession: int64(n),
				Action:             QuotaActionDeny,
				Enabled:            true,
			}
			_ = store.Put(ctx, cfg)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = store.Get(ctx, "id-concurrent")
		}()
	}

	// Concurrent lists
	for i := 0; i < goroutines/5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = store.List(ctx)
		}()
	}

	wg.Wait()

	// Verify one config exists
	got, err := store.Get(ctx, "id-concurrent")
	if err != nil {
		t.Fatalf("expected config to exist after concurrent access: %v", err)
	}
	if got.IdentityID != "id-concurrent" {
		t.Errorf("wrong identity ID: %s", got.IdentityID)
	}
}
