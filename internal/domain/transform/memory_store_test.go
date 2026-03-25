package transform

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestMemoryTransformStore_PutAndGet(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	rule := &TransformRule{
		ID:        "r1",
		Name:      "test-redact",
		Type:      TransformRedact,
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config: TransformConfig{
			Patterns:    []string{`\d{3}-\d{2}-\d{4}`},
			Replacement: "[SSN]",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := store.Put(ctx, rule); err != nil {
		t.Fatalf("Put: unexpected error: %v", err)
	}

	got, err := store.Get(ctx, "r1")
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if got.ID != "r1" {
		t.Errorf("Get: expected ID r1, got %s", got.ID)
	}
	if got.Name != "test-redact" {
		t.Errorf("Get: expected Name test-redact, got %s", got.Name)
	}
	if got.Config.Replacement != "[SSN]" {
		t.Errorf("Get: expected Replacement [SSN], got %s", got.Config.Replacement)
	}
}

func TestMemoryTransformStore_GetNotFound(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	if !errors.Is(err, ErrTransformNotFound) {
		t.Errorf("Get: expected ErrTransformNotFound, got %v", err)
	}
}

func TestMemoryTransformStore_PutUpdate(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	rule := &TransformRule{
		ID:        "r1",
		Name:      "original",
		Type:      TransformTruncate,
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config:    TransformConfig{MaxBytes: 100},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := store.Put(ctx, rule); err != nil {
		t.Fatalf("Put: unexpected error: %v", err)
	}

	// Update the rule
	rule.Name = "updated"
	rule.Config.MaxBytes = 200
	if err := store.Put(ctx, rule); err != nil {
		t.Fatalf("Put update: unexpected error: %v", err)
	}

	got, err := store.Get(ctx, "r1")
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if got.Name != "updated" {
		t.Errorf("Get after update: expected Name updated, got %s", got.Name)
	}
	if got.Config.MaxBytes != 200 {
		t.Errorf("Get after update: expected MaxBytes 200, got %d", got.Config.MaxBytes)
	}
}

func TestMemoryTransformStore_Delete(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	rule := &TransformRule{
		ID:        "r1",
		Name:      "to-delete",
		Type:      TransformTruncate,
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config:    TransformConfig{MaxBytes: 100},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := store.Put(ctx, rule); err != nil {
		t.Fatalf("Put: unexpected error: %v", err)
	}

	if err := store.Delete(ctx, "r1"); err != nil {
		t.Fatalf("Delete: unexpected error: %v", err)
	}

	_, err := store.Get(ctx, "r1")
	if !errors.Is(err, ErrTransformNotFound) {
		t.Errorf("Get after Delete: expected ErrTransformNotFound, got %v", err)
	}
}

func TestMemoryTransformStore_DeleteNotFound(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	// Delete a non-existent rule should not error
	if err := store.Delete(ctx, "nonexistent"); err != nil {
		t.Errorf("Delete non-existent: unexpected error: %v", err)
	}
}

func TestMemoryTransformStore_List(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	rules := []*TransformRule{
		{
			ID: "r1", Name: "rule-1", Type: TransformRedact, ToolMatch: "*",
			Priority: 10, Enabled: true,
			Config:    TransformConfig{Patterns: []string{`secret`}},
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		{
			ID: "r2", Name: "rule-2", Type: TransformTruncate, ToolMatch: "read_*",
			Priority: 20, Enabled: true,
			Config:    TransformConfig{MaxBytes: 500},
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
		{
			ID: "r3", Name: "rule-3", Type: TransformInject, ToolMatch: "write_*",
			Priority: 30, Enabled: true,
			Config:    TransformConfig{Prepend: "WARNING"},
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
	}

	for _, r := range rules {
		if err := store.Put(ctx, r); err != nil {
			t.Fatalf("Put %s: unexpected error: %v", r.ID, err)
		}
	}

	listed, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: unexpected error: %v", err)
	}
	if len(listed) != 3 {
		t.Errorf("List: expected 3 rules, got %d", len(listed))
	}

	// Verify all IDs present
	ids := make(map[string]bool)
	for _, r := range listed {
		ids[r.ID] = true
	}
	for _, id := range []string{"r1", "r2", "r3"} {
		if !ids[id] {
			t.Errorf("List: missing rule %s", id)
		}
	}
}

func TestMemoryTransformStore_ConcurrentAccess(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	const goroutines = 20

	// Concurrent writers
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rule := &TransformRule{
				ID:        "concurrent-rule",
				Name:      "concurrent",
				Type:      TransformTruncate,
				ToolMatch: "*",
				Priority:  idx,
				Enabled:   true,
				Config:    TransformConfig{MaxBytes: idx * 100},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			_ = store.Put(ctx, rule)
		}(i)
	}

	// Concurrent readers
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = store.Get(ctx, "concurrent-rule")
			_, _ = store.List(ctx)
		}()
	}

	// Concurrent deleters
	for i := 0; i < goroutines/4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = store.Delete(ctx, "concurrent-rule")
		}()
	}

	wg.Wait()
	// No race condition detected is the success criterion.
}
