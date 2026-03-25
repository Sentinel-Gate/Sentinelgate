package lifecycle

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestShutdown_PhaseOrder(t *testing.T) {
	m := NewManager(testLogger())
	var order []string

	m.Register(Hook{Name: "cleanup", Phase: PhaseCleanup, Fn: func(ctx context.Context) error {
		order = append(order, "cleanup")
		return nil
	}})
	m.Register(Hook{Name: "flush", Phase: PhaseFlushBuffers, Fn: func(ctx context.Context) error {
		order = append(order, "flush")
		return nil
	}})
	m.Register(Hook{Name: "stop", Phase: PhaseStopAccepting, Fn: func(ctx context.Context) error {
		order = append(order, "stop")
		return nil
	}})
	m.Register(Hook{Name: "drain", Phase: PhaseDrainRequests, Fn: func(ctx context.Context) error {
		order = append(order, "drain")
		return nil
	}})

	err := m.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}

	expected := []string{"stop", "drain", "flush", "cleanup"}
	if len(order) != len(expected) {
		t.Fatalf("expected %d hooks, got %d: %v", len(expected), len(order), order)
	}
	for i, name := range expected {
		if order[i] != name {
			t.Errorf("position %d: expected %q, got %q", i, name, order[i])
		}
	}
}

func TestShutdown_ErrorDoesNotBlock(t *testing.T) {
	m := NewManager(testLogger())
	var count int32

	m.Register(Hook{Name: "fail", Phase: PhaseFlushBuffers, Fn: func(ctx context.Context) error {
		atomic.AddInt32(&count, 1)
		return errors.New("flush failed")
	}})
	m.Register(Hook{Name: "ok", Phase: PhaseSaveState, Fn: func(ctx context.Context) error {
		atomic.AddInt32(&count, 1)
		return nil
	}})

	err := m.Shutdown(context.Background())
	if err == nil {
		t.Fatal("expected aggregated error")
	}
	if atomic.LoadInt32(&count) != 2 {
		t.Errorf("expected both hooks to run, got %d", count)
	}
}

func TestShutdown_HookTimeout(t *testing.T) {
	m := NewManager(testLogger())

	m.Register(Hook{
		Name: "slow", Phase: PhaseFlushBuffers,
		Timeout: 50 * time.Millisecond,
		Fn: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
				return nil
			}
		},
	})

	start := time.Now()
	err := m.Shutdown(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > 1*time.Second {
		t.Errorf("shutdown took too long: %v (should be ~50ms)", elapsed)
	}
}

func TestShutdown_Empty(t *testing.T) {
	m := NewManager(testLogger())
	err := m.Shutdown(context.Background())
	if err != nil {
		t.Fatalf("empty shutdown should return nil, got: %v", err)
	}
}

func TestHookCount(t *testing.T) {
	m := NewManager(testLogger())
	if m.HookCount() != 0 {
		t.Errorf("expected 0, got %d", m.HookCount())
	}
	m.Register(Hook{Name: "a", Phase: PhaseCleanup, Fn: func(ctx context.Context) error { return nil }})
	m.Register(Hook{Name: "b", Phase: PhaseCleanup, Fn: func(ctx context.Context) error { return nil }})
	if m.HookCount() != 2 {
		t.Errorf("expected 2, got %d", m.HookCount())
	}
}

func TestPhaseString(t *testing.T) {
	tests := []struct {
		phase Phase
		want  string
	}{
		{PhaseStopAccepting, "stop-accepting"},
		{PhaseDrainRequests, "drain-requests"},
		{PhaseFlushBuffers, "flush-buffers"},
		{PhaseCloseConnections, "close-connections"},
		{PhaseSaveState, "save-state"},
		{PhaseCleanup, "cleanup"},
		{Phase(99), "phase-99"},
	}
	for _, tt := range tests {
		if got := tt.phase.String(); got != tt.want {
			t.Errorf("Phase(%d).String() = %q, want %q", tt.phase, got, tt.want)
		}
	}
}
