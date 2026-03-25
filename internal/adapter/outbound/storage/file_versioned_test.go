package storage

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/storage"
)

func newTestVersionedStore(t *testing.T) *FileVersionedStore {
	t.Helper()
	dir := t.TempDir()
	s, err := NewFileVersionedStore(dir)
	if err != nil {
		t.Fatalf("NewFileVersionedStore: %v", err)
	}
	return s
}

func TestVersionedStore_PutAndGet(t *testing.T) {
	s := newTestVersionedStore(t)
	ctx := context.Background()

	data := json.RawMessage(`{"name":"baseline-v1"}`)
	err := s.Put(ctx, "tool/read_file", storage.Value{Data: data})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get(ctx, "tool/read_file")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("version = %d, want 1", got.Version)
	}
	if string(got.Data) != `{"name":"baseline-v1"}` {
		t.Errorf("data = %s", got.Data)
	}
}

func TestVersionedStore_GetNotFound(t *testing.T) {
	s := newTestVersionedStore(t)
	ctx := context.Background()

	_, err := s.Get(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
	var notFound *storage.ErrNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestVersionedStore_VersionIncrement(t *testing.T) {
	s := newTestVersionedStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		data := json.RawMessage(`{"v":` + string(rune('0'+i)) + `}`)
		if err := s.Put(ctx, "key", storage.Value{Data: data}); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}

	got, err := s.Get(ctx, "key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Version != 5 {
		t.Errorf("version = %d, want 5", got.Version)
	}
}

func TestVersionedStore_History(t *testing.T) {
	s := newTestVersionedStore(t)
	ctx := context.Background()

	// Put 4 versions.
	for i := 1; i <= 4; i++ {
		data := json.RawMessage(`{"version":` + string(rune('0'+i)) + `}`)
		if err := s.Put(ctx, "key", storage.Value{
			Data:      data,
			UpdatedAt: time.Date(2026, 3, 5, 10, 0, i, 0, time.UTC),
		}); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}

	// History should contain versions 1-3 (not the current version 4).
	history, err := s.History(ctx, "key", 10)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("history length = %d, want 3", len(history))
	}

	// Newest first.
	if history[0].Version != 3 {
		t.Errorf("history[0].Version = %d, want 3", history[0].Version)
	}
	if history[2].Version != 1 {
		t.Errorf("history[2].Version = %d, want 1", history[2].Version)
	}
}

func TestVersionedStore_HistoryLimit(t *testing.T) {
	s := newTestVersionedStore(t)
	ctx := context.Background()

	for i := 1; i <= 10; i++ {
		_ = s.Put(ctx, "key", storage.Value{
			Data:      json.RawMessage(`{}`),
			UpdatedAt: time.Date(2026, 3, 5, 10, 0, i, 0, time.UTC),
		})
	}

	history, err := s.History(ctx, "key", 3)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("history length = %d, want 3", len(history))
	}
}

func TestVersionedStore_HistoryEmpty(t *testing.T) {
	s := newTestVersionedStore(t)
	ctx := context.Background()

	history, err := s.History(ctx, "nonexistent", 10)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("expected empty history, got %d", len(history))
	}
}

func TestVersionedStore_Delete(t *testing.T) {
	s := newTestVersionedStore(t)
	ctx := context.Background()

	_ = s.Put(ctx, "key", storage.Value{Data: json.RawMessage(`{}`)})
	_ = s.Put(ctx, "key", storage.Value{Data: json.RawMessage(`{}`)})

	if err := s.Delete(ctx, "key"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := s.Get(ctx, "key")
	if err == nil {
		t.Error("expected error after delete")
	}

	history, _ := s.History(ctx, "key", 10)
	if len(history) != 0 {
		t.Errorf("history should be empty after delete, got %d", len(history))
	}
}

func TestVersionedStore_List(t *testing.T) {
	s := newTestVersionedStore(t)
	ctx := context.Background()

	_ = s.Put(ctx, "tool/read_file", storage.Value{Data: json.RawMessage(`{}`)})
	_ = s.Put(ctx, "tool/write_file", storage.Value{Data: json.RawMessage(`{}`)})
	_ = s.Put(ctx, "evidence/chain", storage.Value{Data: json.RawMessage(`{}`)})

	// List all.
	all, err := s.List(ctx, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("list length = %d, want 3", len(all))
	}

	// List by prefix.
	tools, _ := s.List(ctx, "tool/")
	if len(tools) != 2 {
		t.Fatalf("tool prefix = %d, want 2", len(tools))
	}
}

func TestVersionedStore_Metadata(t *testing.T) {
	s := newTestVersionedStore(t)
	ctx := context.Background()

	meta := map[string]string{"source": "tool-integrity", "upstream": "mcp-server"}
	_ = s.Put(ctx, "key", storage.Value{
		Data:     json.RawMessage(`{}`),
		Metadata: meta,
	})

	got, _ := s.Get(ctx, "key")
	if got.Metadata["source"] != "tool-integrity" {
		t.Errorf("metadata = %v", got.Metadata)
	}
}

func TestVersionedStore_KeySanitization(t *testing.T) {
	s := newTestVersionedStore(t)
	ctx := context.Background()

	// Keys with path separators should be sanitized.
	_ = s.Put(ctx, "a/b/c", storage.Value{Data: json.RawMessage(`{"k":"v"}`)})
	got, err := s.Get(ctx, "a/b/c")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got.Data) != `{"k":"v"}` {
		t.Errorf("data = %s", got.Data)
	}
}

func TestVersionedStore_ConcurrentPuts(t *testing.T) {
	s := newTestVersionedStore(t)
	ctx := context.Background()

	done := make(chan struct{}, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_ = s.Put(ctx, "shared", storage.Value{Data: json.RawMessage(`{}`)})
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}

	got, err := s.Get(ctx, "shared")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Version < 1 || got.Version > 10 {
		t.Errorf("version = %d, expected 1-10", got.Version)
	}
}
