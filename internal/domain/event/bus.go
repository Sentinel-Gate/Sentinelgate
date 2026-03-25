// Package event provides an in-process event bus for internal pub/sub communication.
// All upgrades emit events through this bus; consumers (Notification Center, Webhook Engine,
// Audit Enricher, SSE Broadcaster) subscribe to receive them.
//
// Design decisions:
//   - In-process, goroutine-safe (no Kafka/Redis — consistent with zero-dependency identity)
//   - Async delivery via buffered channels (default 1000)
//   - Backpressure: slow consumers get events dropped with counter
//   - No persistence: consumers are responsible for persisting what they need
package event

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// Severity classifies event importance.
type Severity int

const (
	SeverityInfo     Severity = iota // Informational, no action needed
	SeverityWarning                  // Attention recommended
	SeverityCritical                 // Immediate action required
)

// String returns the severity as a human-readable string.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Event is the standard internal event type emitted by all upgrades.
type Event struct {
	Type           string    `json:"type"`            // e.g. "tool.changed", "drift.anomaly"
	Source         string    `json:"source"`          // e.g. "tool-integrity", "drift-detector"
	Severity       Severity  `json:"severity"`        // Critical, Warning, Info
	Payload        any       `json:"payload"`         // Type-specific data
	Timestamp      time.Time `json:"timestamp"`       // When the event was created
	RequiresAction bool      `json:"requires_action"` // If true, shows in Action Queue
}

// Subscriber is a callback invoked when an event is published.
type Subscriber func(ctx context.Context, event Event)

// Bus is the internal event bus interface.
type Bus interface {
	// Publish sends an event to all matching subscribers.
	Publish(ctx context.Context, event Event)
	// Subscribe registers a handler for a specific event type.
	// Returns an unsubscribe function.
	Subscribe(eventType string, handler Subscriber) (unsubscribe func())
	// SubscribeAll registers a handler that receives all events.
	// Returns an unsubscribe function.
	SubscribeAll(handler Subscriber) (unsubscribe func())
	// DroppedCount returns the total number of events dropped due to backpressure.
	DroppedCount() uint64
}

// subscription holds a subscriber and its ID for unsubscription.
type subscription struct {
	id      uint64
	handler Subscriber
}

// InProcessBus is a goroutine-safe, in-process event bus with async delivery.
type InProcessBus struct {
	mu           sync.RWMutex
	typed        map[string][]subscription // subscribers for specific event types
	global       []subscription            // subscribers for all events
	nextID       uint64 // L-1: theoretical wrap-around after 2^64 subscribe/unsubscribe cycles; practically unreachable
	bufferSize   int
	ch           chan dispatchItem
	dropped      atomic.Uint64
	startOnce    sync.Once // M-1: guard against multiple Start() calls
	stopOnce     sync.Once
	done         chan struct{}
	wasStarted   atomic.Bool // L-36: tracks whether Start() was ever called
}

type dispatchItem struct {
	ctx   context.Context
	event Event
}

// NewBus creates a new in-process event bus with the given buffer size.
// Call Start() to begin async dispatch. Call Stop() for graceful shutdown.
func NewBus(bufferSize int) *InProcessBus {
	if bufferSize <= 0 {
		bufferSize = 1000
	}
	return &InProcessBus{
		typed:      make(map[string][]subscription),
		bufferSize: bufferSize,
		ch:         make(chan dispatchItem, bufferSize),
		done:       make(chan struct{}),
	}
}

// Start begins the async dispatch goroutine.
// M-1: Uses sync.Once to guarantee only one dispatch goroutine is launched.
func (b *InProcessBus) Start() {
	b.startOnce.Do(func() {
		b.wasStarted.Store(true)
		go b.dispatchLoop()
	})
}

// Stop gracefully shuts down the bus, draining pending events.
// If Start() was never called there is no dispatch goroutine, so we
// close the channel but skip waiting on b.done (L-36).
func (b *InProcessBus) Stop() {
	b.stopOnce.Do(func() {
		close(b.ch)
		if b.wasStarted.Load() {
			<-b.done
		}
	})
}

// Publish sends an event to the dispatch queue.
// If the queue is full, the event is dropped and the drop counter incremented.
func (b *InProcessBus) Publish(ctx context.Context, event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	select {
	case <-b.done:
		b.dropped.Add(1)
		return
	default:
	}
	defer func() {
		if r := recover(); r != nil {
			// L-29: log the panic value so send-on-closed-channel panics are diagnosable.
			slog.Error("event bus publish panic recovered", "event", event.Type, "panic", fmt.Sprint(r))
			b.dropped.Add(1)
		}
	}()
	select {
	case b.ch <- dispatchItem{ctx: ctx, event: event}:
	default:
		b.dropped.Add(1)
	}
}

// Subscribe registers a handler for a specific event type.
func (b *InProcessBus) Subscribe(eventType string, handler Subscriber) func() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	id := b.nextID
	b.typed[eventType] = append(b.typed[eventType], subscription{id: id, handler: handler})
	return func() { b.unsubscribe(eventType, id) }
}

// SubscribeAll registers a handler that receives all events.
func (b *InProcessBus) SubscribeAll(handler Subscriber) func() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	id := b.nextID
	b.global = append(b.global, subscription{id: id, handler: handler})
	return func() { b.unsubscribeGlobal(id) }
}

// DroppedCount returns the total number of dropped events.
func (b *InProcessBus) DroppedCount() uint64 {
	return b.dropped.Load()
}

func (b *InProcessBus) dispatchLoop() {
	defer close(b.done)
	for item := range b.ch {
		b.dispatch(item.ctx, item.event)
	}
}

func (b *InProcessBus) dispatch(ctx context.Context, event Event) {
	b.mu.RLock()
	// Copy subscriber lists to avoid holding the lock during handler execution.
	typed := make([]Subscriber, 0, len(b.typed[event.Type]))
	for _, s := range b.typed[event.Type] {
		typed = append(typed, s.handler)
	}
	global := make([]Subscriber, 0, len(b.global))
	for _, s := range b.global {
		global = append(global, s.handler)
	}
	b.mu.RUnlock()

	for _, h := range typed {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// L-28: include stack trace so the panic is diagnosable.
					slog.Error("subscriber panic recovered",
						"event", event.Type,
						"panic", fmt.Sprint(r),
						"stack", string(debug.Stack()))
				}
			}()
			h(ctx, event)
		}()
	}
	for _, h := range global {
		func() {
			defer func() {
				if r := recover(); r != nil {
					// L-28: include stack trace so the panic is diagnosable.
					slog.Error("subscriber panic recovered",
						"event", event.Type,
						"panic", fmt.Sprint(r),
						"stack", string(debug.Stack()))
				}
			}()
			h(ctx, event)
		}()
	}
}

func (b *InProcessBus) unsubscribe(eventType string, id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.typed[eventType]
	for i, s := range subs {
		if s.id == id {
			subs = append(subs[:i], subs[i+1:]...)
			if len(subs) == 0 {
				delete(b.typed, eventType)
			} else {
				b.typed[eventType] = subs
			}
			return
		}
	}
}

func (b *InProcessBus) unsubscribeGlobal(id uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, s := range b.global {
		if s.id == id {
			b.global = append(b.global[:i], b.global[i+1:]...)
			return
		}
	}
}
