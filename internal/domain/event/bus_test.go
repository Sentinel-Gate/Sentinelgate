package event

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBus_PublishSubscribe(t *testing.T) {
	bus := NewBus(100)
	bus.Start()
	defer bus.Stop()

	var received atomic.Int32
	bus.Subscribe("test.event", func(ctx context.Context, e Event) {
		received.Add(1)
	})

	bus.Publish(context.Background(), Event{Type: "test.event", Source: "test"})
	bus.Publish(context.Background(), Event{Type: "test.event", Source: "test"})
	bus.Publish(context.Background(), Event{Type: "other.event", Source: "test"})

	// Wait for async dispatch.
	time.Sleep(50 * time.Millisecond)

	if got := received.Load(); got != 2 {
		t.Errorf("received %d events, want 2", got)
	}
}

func TestBus_SubscribeAll(t *testing.T) {
	bus := NewBus(100)
	bus.Start()
	defer bus.Stop()

	var received atomic.Int32
	bus.SubscribeAll(func(ctx context.Context, e Event) {
		received.Add(1)
	})

	bus.Publish(context.Background(), Event{Type: "a", Source: "test"})
	bus.Publish(context.Background(), Event{Type: "b", Source: "test"})
	bus.Publish(context.Background(), Event{Type: "c", Source: "test"})

	time.Sleep(50 * time.Millisecond)

	if got := received.Load(); got != 3 {
		t.Errorf("received %d events, want 3", got)
	}
}

func TestBus_Unsubscribe(t *testing.T) {
	bus := NewBus(100)
	bus.Start()
	defer bus.Stop()

	var received atomic.Int32
	unsub := bus.Subscribe("test.event", func(ctx context.Context, e Event) {
		received.Add(1)
	})

	bus.Publish(context.Background(), Event{Type: "test.event"})
	time.Sleep(50 * time.Millisecond)

	unsub()

	bus.Publish(context.Background(), Event{Type: "test.event"})
	time.Sleep(50 * time.Millisecond)

	if got := received.Load(); got != 1 {
		t.Errorf("received %d events after unsub, want 1", got)
	}
}

func TestBus_UnsubscribeAll(t *testing.T) {
	bus := NewBus(100)
	bus.Start()
	defer bus.Stop()

	var received atomic.Int32
	unsub := bus.SubscribeAll(func(ctx context.Context, e Event) {
		received.Add(1)
	})

	bus.Publish(context.Background(), Event{Type: "x"})
	time.Sleep(50 * time.Millisecond)

	unsub()

	bus.Publish(context.Background(), Event{Type: "y"})
	time.Sleep(50 * time.Millisecond)

	if got := received.Load(); got != 1 {
		t.Errorf("received %d events after unsub, want 1", got)
	}
}

func TestBus_Backpressure(t *testing.T) {
	bus := NewBus(2) // tiny buffer
	// Do NOT start the dispatch loop — events will pile up and be dropped.

	bus.Publish(context.Background(), Event{Type: "a"})
	bus.Publish(context.Background(), Event{Type: "b"})
	// Buffer full now.
	bus.Publish(context.Background(), Event{Type: "c"})
	bus.Publish(context.Background(), Event{Type: "d"})

	if dropped := bus.DroppedCount(); dropped != 2 {
		t.Errorf("dropped = %d, want 2", dropped)
	}
}

func TestBus_MultipleSubscribers(t *testing.T) {
	bus := NewBus(100)
	bus.Start()
	defer bus.Stop()

	var countA, countB atomic.Int32
	bus.Subscribe("tool.changed", func(ctx context.Context, e Event) {
		countA.Add(1)
	})
	bus.Subscribe("tool.changed", func(ctx context.Context, e Event) {
		countB.Add(1)
	})

	bus.Publish(context.Background(), Event{Type: "tool.changed"})
	time.Sleep(50 * time.Millisecond)

	if countA.Load() != 1 || countB.Load() != 1 {
		t.Errorf("countA=%d, countB=%d, want both 1", countA.Load(), countB.Load())
	}
}

func TestBus_TypedPlusGlobal(t *testing.T) {
	bus := NewBus(100)
	bus.Start()
	defer bus.Stop()

	var typed, global atomic.Int32
	bus.Subscribe("tool.changed", func(ctx context.Context, e Event) {
		typed.Add(1)
	})
	bus.SubscribeAll(func(ctx context.Context, e Event) {
		global.Add(1)
	})

	bus.Publish(context.Background(), Event{Type: "tool.changed"})
	bus.Publish(context.Background(), Event{Type: "drift.anomaly"})
	time.Sleep(50 * time.Millisecond)

	if typed.Load() != 1 {
		t.Errorf("typed = %d, want 1", typed.Load())
	}
	if global.Load() != 2 {
		t.Errorf("global = %d, want 2", global.Load())
	}
}

func TestBus_ConcurrentPublish(t *testing.T) {
	bus := NewBus(1000)
	bus.Start()
	defer bus.Stop()

	var received atomic.Int32
	bus.Subscribe("concurrent", func(ctx context.Context, e Event) {
		received.Add(1)
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bus.Publish(context.Background(), Event{Type: "concurrent"})
		}()
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	if got := received.Load(); got != 100 {
		t.Errorf("received %d events, want 100", got)
	}
}

func TestBus_TimestampAutoFill(t *testing.T) {
	bus := NewBus(100)
	bus.Start()
	defer bus.Stop()

	ch := make(chan Event, 1)
	bus.Subscribe("ts.test", func(ctx context.Context, e Event) {
		ch <- e
	})

	bus.Publish(context.Background(), Event{Type: "ts.test"})

	select {
	case captured := <-ch:
		if captured.Timestamp.IsZero() {
			t.Error("timestamp should be auto-filled")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for event")
	}
}

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		s    Severity
		want string
	}{
		{SeverityInfo, "info"},
		{SeverityWarning, "warning"},
		{SeverityCritical, "critical"},
		{Severity(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}
