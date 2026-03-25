package action

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// approvalTestLogger returns a logger for approval tests.
// (testLogger is already declared in chain_test.go as a function)
func approvalTestLogger() *slog.Logger { return slog.Default() }

// testEventBus captures events published during tests.
type testEventBus struct {
	mu     sync.Mutex
	events []event.Event
}

func newTestEventBus() *testEventBus {
	return &testEventBus{events: make([]event.Event, 0)}
}

func (b *testEventBus) Publish(_ context.Context, evt event.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now()
	}
	b.events = append(b.events, evt)
}

func (b *testEventBus) Subscribe(_ string, _ event.Subscriber) func() { return func() {} }
func (b *testEventBus) SubscribeAll(_ event.Subscriber) func()        { return func() {} }
func (b *testEventBus) DroppedCount() uint64                          { return 0 }

func (b *testEventBus) Events() []event.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]event.Event, len(b.events))
	copy(cp, b.events)
	return cp
}

func (b *testEventBus) EventsByType(t string) []event.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	var result []event.Event
	for _, e := range b.events {
		if e.Type == t {
			result = append(result, e)
		}
	}
	return result
}

func TestApprovalStore_AddAndList(t *testing.T) {
	store := NewApprovalStore(10)
	p := &PendingApproval{
		ID:       "test-1",
		ToolName: "read_file",
		Status:   "pending",
		Timeout:  5 * time.Minute,
		result:   make(chan ApprovalResult, 1),
	}
	store.Add(p)

	list := store.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(list))
	}
	if list[0].ID != "test-1" {
		t.Errorf("expected ID test-1, got %s", list[0].ID)
	}
}

func TestApprovalStore_Get(t *testing.T) {
	store := NewApprovalStore(10)
	p := &PendingApproval{
		ID:       "test-get",
		ToolName: "bash",
		Status:   "pending",
		result:   make(chan ApprovalResult, 1),
	}
	store.Add(p)

	got := store.Get("test-get")
	if got == nil {
		t.Fatal("expected non-nil approval")
	}
	if got.ToolName != "bash" {
		t.Errorf("expected tool_name bash, got %s", got.ToolName)
	}

	notFound := store.Get("nonexistent")
	if notFound != nil {
		t.Error("expected nil for nonexistent ID")
	}
}

func TestApprovalStore_Approve(t *testing.T) {
	bus := newTestEventBus()
	store := NewApprovalStore(10)
	store.SetEventBus(bus)

	p := &PendingApproval{
		ID:           "test-approve",
		ToolName:     "delete_file",
		IdentityName: "claude-prod",
		IdentityID:   "agent-1",
		Status:       "pending",
		Timeout:      5 * time.Minute,
		result:       make(chan ApprovalResult, 1),
	}
	store.Add(p)

	err := store.Approve("test-approve", "legitimate cleanup")
	if err != nil {
		t.Fatalf("Approve failed: %v", err)
	}

	// Check result was sent
	select {
	case res := <-p.result:
		if !res.Approved {
			t.Error("expected Approved=true")
		}
	default:
		t.Error("no result on channel")
	}

	// Check status
	got := store.Get("test-approve")
	if got.Status != "approved" {
		t.Errorf("expected status approved, got %s", got.Status)
	}
	if got.ResolvedAt == nil {
		t.Error("expected ResolvedAt to be set")
	}
	if got.AuditNote != "legitimate cleanup" {
		t.Errorf("expected audit note, got %q", got.AuditNote)
	}

	// Check event emitted
	events := bus.EventsByType("approval.approved")
	if len(events) != 1 {
		t.Fatalf("expected 1 approval.approved event, got %d", len(events))
	}
	payload := events[0].Payload.(map[string]interface{})
	if payload["tool_name"] != "delete_file" {
		t.Errorf("expected tool_name delete_file, got %v", payload["tool_name"])
	}
}

func TestApprovalStore_Deny(t *testing.T) {
	bus := newTestEventBus()
	store := NewApprovalStore(10)
	store.SetEventBus(bus)

	p := &PendingApproval{
		ID:           "test-deny",
		ToolName:     "execute_command",
		IdentityName: "data-agent",
		IdentityID:   "agent-2",
		Status:       "pending",
		Timeout:      5 * time.Minute,
		result:       make(chan ApprovalResult, 1),
	}
	store.Add(p)

	err := store.Deny("test-deny", "suspicious activity", "blocked per policy")
	if err != nil {
		t.Fatalf("Deny failed: %v", err)
	}

	select {
	case res := <-p.result:
		if res.Approved {
			t.Error("expected Approved=false")
		}
		if res.Reason != "suspicious activity" {
			t.Errorf("expected reason 'suspicious activity', got %q", res.Reason)
		}
	default:
		t.Error("no result on channel")
	}

	got := store.Get("test-deny")
	if got.Status != "denied" {
		t.Errorf("expected status denied, got %s", got.Status)
	}
	if got.AuditNote != "blocked per policy" {
		t.Errorf("expected audit note 'blocked per policy', got %q", got.AuditNote)
	}

	events := bus.EventsByType("approval.rejected")
	if len(events) != 1 {
		t.Fatalf("expected 1 approval.rejected event, got %d", len(events))
	}
}

func TestApprovalStore_RejectWhenFull(t *testing.T) {
	store := NewApprovalStore(2)

	p1 := &PendingApproval{ID: "ev-1", Status: "pending", result: make(chan ApprovalResult, 1)}
	p2 := &PendingApproval{ID: "ev-2", Status: "pending", result: make(chan ApprovalResult, 1)}
	p3 := &PendingApproval{ID: "ev-3", Status: "pending", result: make(chan ApprovalResult, 1)}

	if err := store.Add(p1); err != nil {
		t.Fatalf("unexpected error adding p1: %v", err)
	}
	if err := store.Add(p2); err != nil {
		t.Fatalf("unexpected error adding p2: %v", err)
	}
	err := store.Add(p3) // should be rejected — queue full
	if err == nil {
		t.Fatal("expected error when queue is full, got nil")
	}

	list := store.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 pending, got %d", len(list))
	}
	if store.Get("ev-3") != nil {
		t.Error("ev-3 should not have been added")
	}
}

func TestApprovalStore_ApproveNotFound(t *testing.T) {
	store := NewApprovalStore(10)
	err := store.Approve("nonexistent", "")
	if err == nil {
		t.Error("expected error for nonexistent approval")
	}
}

func TestApprovalStore_DenyNotFound(t *testing.T) {
	store := NewApprovalStore(10)
	err := store.Deny("nonexistent", "reason", "note")
	if err == nil {
		t.Error("expected error for nonexistent approval")
	}
}

func TestApprovalStore_DoubleApprove(t *testing.T) {
	store := NewApprovalStore(10)
	p := &PendingApproval{
		ID:     "double",
		Status: "pending",
		result: make(chan ApprovalResult, 1),
	}
	store.Add(p)

	if err := store.Approve("double", ""); err != nil {
		t.Fatal(err)
	}
	err := store.Approve("double", "")
	if err == nil {
		t.Error("expected error for double approve")
	}
}

func TestApprovalStore_EventBusHold(t *testing.T) {
	bus := newTestEventBus()
	store := NewApprovalStore(10)
	store.SetEventBus(bus)

	p := &PendingApproval{
		ID:           "hold-event",
		ToolName:     "delete_database",
		IdentityName: "claude-prod",
		IdentityID:   "agent-3",
		SessionID:    "sess-123",
		RuleID:       "rule-1",
		RuleName:     "deny-destructive",
		Status:       "pending",
		Timeout:      5 * time.Minute,
		result:       make(chan ApprovalResult, 1),
	}
	store.Add(p)
	store.emitEvent("approval.hold", snapshotApproval(p), "", "")

	events := bus.EventsByType("approval.hold")
	if len(events) != 1 {
		t.Fatalf("expected 1 approval.hold event, got %d", len(events))
	}

	evt := events[0]
	if evt.Source != "escrow" {
		t.Errorf("expected source 'escrow', got %q", evt.Source)
	}
	if evt.Severity != event.SeverityCritical {
		t.Errorf("expected severity critical, got %v", evt.Severity)
	}
	if !evt.RequiresAction {
		t.Error("hold event should require action")
	}

	payload := evt.Payload.(map[string]interface{})
	if payload["approval_id"] != "hold-event" {
		t.Errorf("expected approval_id hold-event, got %v", payload["approval_id"])
	}
	if payload["tool_name"] != "delete_database" {
		t.Errorf("expected tool_name delete_database, got %v", payload["tool_name"])
	}
	if payload["session_id"] != "sess-123" {
		t.Errorf("expected session_id sess-123, got %v", payload["session_id"])
	}
}

func TestApprovalStore_NoEventBus(t *testing.T) {
	// Should not panic when event bus is nil
	store := NewApprovalStore(10)
	p := &PendingApproval{
		ID:     "no-bus",
		Status: "pending",
		result: make(chan ApprovalResult, 1),
	}
	store.Add(p)
	if err := store.Approve("no-bus", "note"); err != nil {
		t.Fatalf("should not fail without event bus: %v", err)
	}
}

func TestApprovalStore_ConcurrentAccess(t *testing.T) {
	store := NewApprovalStore(100)
	var wg sync.WaitGroup

	// Concurrent adds
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			p := &PendingApproval{
				ID:     "concurrent-" + time.Now().String(),
				Status: "pending",
				result: make(chan ApprovalResult, 1),
			}
			store.Add(p)
		}(i)
	}
	wg.Wait()

	list := store.List()
	if len(list) == 0 {
		t.Error("expected some pending approvals after concurrent adds")
	}
}

func TestApprovalInterceptor_NoApprovalNeeded(t *testing.T) {
	store := NewApprovalStore(10)
	nextCalled := false
	next := &mockInterceptor{fn: func(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
		nextCalled = true
		return act, nil
	}}
	interceptor := NewApprovalInterceptor(store, next, approvalTestLogger())

	// Context with decision that does NOT require approval
	ctx := policy.WithDecision(context.Background(), &policy.Decision{
		Allowed:          true,
		RequiresApproval: false,
	})
	act := &CanonicalAction{
		Name:     "read_file",
		Identity: ActionIdentity{Name: "test", ID: "test-id"},
	}

	_, err := interceptor.Intercept(ctx, act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextCalled {
		t.Error("next interceptor should have been called")
	}
}

func TestApprovalInterceptor_ApprovalGranted(t *testing.T) {
	bus := newTestEventBus()
	store := NewApprovalStore(10)
	store.SetEventBus(bus)

	nextCalled := false
	next := &mockInterceptor{fn: func(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
		nextCalled = true
		return act, nil
	}}
	interceptor := NewApprovalInterceptor(store, next, approvalTestLogger())

	ctx := policy.WithDecision(context.Background(), &policy.Decision{
		Allowed:          true,
		RequiresApproval: true,
		ApprovalTimeout:  1 * time.Second,
		RuleID:           "rule-1",
		RuleName:         "require-approval",
	})
	act := &CanonicalAction{
		Name:     "delete_file",
		Identity: ActionIdentity{Name: "agent", ID: "agent-1", SessionID: "s1"},
	}

	// Approve asynchronously — poll until the pending approval appears
	// instead of using a fixed sleep.
	go func() {
		for {
			list := store.List()
			if len(list) > 0 {
				_ = store.Approve(list[0].ID, "approved for testing")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	_, err := interceptor.Intercept(ctx, act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextCalled {
		t.Error("next interceptor should have been called after approval")
	}

	// Check hold event was emitted
	holdEvents := bus.EventsByType("approval.hold")
	if len(holdEvents) != 1 {
		t.Errorf("expected 1 hold event, got %d", len(holdEvents))
	}
}

func TestApprovalInterceptor_ApprovalDenied(t *testing.T) {
	store := NewApprovalStore(10)
	next := &mockInterceptor{fn: func(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
		t.Error("next should not be called on denial")
		return act, nil
	}}
	interceptor := NewApprovalInterceptor(store, next, approvalTestLogger())

	ctx := policy.WithDecision(context.Background(), &policy.Decision{
		Allowed:          true,
		RequiresApproval: true,
		ApprovalTimeout:  1 * time.Second,
	})
	act := &CanonicalAction{
		Name:     "dangerous_tool",
		Identity: ActionIdentity{Name: "agent", ID: "agent-1"},
	}

	// Deny asynchronously — poll until the pending approval appears
	// instead of using a fixed sleep.
	go func() {
		for {
			list := store.List()
			if len(list) > 0 {
				_ = store.Deny(list[0].ID, "not allowed", "")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	_, err := interceptor.Intercept(ctx, act)
	if err == nil {
		t.Fatal("expected error on denial")
	}
}

func TestApprovalInterceptor_Timeout_DefaultDeny(t *testing.T) {
	bus := newTestEventBus()
	store := NewApprovalStore(10)
	store.SetEventBus(bus)

	next := &mockInterceptor{fn: func(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
		t.Error("next should not be called on timeout with deny")
		return act, nil
	}}
	interceptor := NewApprovalInterceptor(store, next, approvalTestLogger())

	ctx := policy.WithDecision(context.Background(), &policy.Decision{
		Allowed:               true,
		RequiresApproval:      true,
		ApprovalTimeout:       100 * time.Millisecond,
		ApprovalTimeoutAction: policy.ActionDeny,
	})
	act := &CanonicalAction{
		Name:     "test_tool",
		Identity: ActionIdentity{Name: "agent", ID: "agent-1"},
	}

	_, err := interceptor.Intercept(ctx, act)
	if err == nil {
		t.Fatal("expected error on timeout deny")
	}

	// Check timeout event was emitted
	timeoutEvents := bus.EventsByType("approval.timeout")
	if len(timeoutEvents) != 1 {
		t.Errorf("expected 1 timeout event, got %d", len(timeoutEvents))
	}
}

func TestApprovalInterceptor_Timeout_DefaultAllow(t *testing.T) {
	store := NewApprovalStore(10)
	nextCalled := false
	next := &mockInterceptor{fn: func(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
		nextCalled = true
		return act, nil
	}}
	interceptor := NewApprovalInterceptor(store, next, approvalTestLogger())

	ctx := policy.WithDecision(context.Background(), &policy.Decision{
		Allowed:               true,
		RequiresApproval:      true,
		ApprovalTimeout:       100 * time.Millisecond,
		ApprovalTimeoutAction: policy.ActionAllow,
	})
	act := &CanonicalAction{
		Name:     "test_tool",
		Identity: ActionIdentity{Name: "agent", ID: "agent-1"},
	}

	_, err := interceptor.Intercept(ctx, act)
	if err != nil {
		t.Fatalf("unexpected error on timeout allow: %v", err)
	}
	if !nextCalled {
		t.Error("next interceptor should have been called after timeout allow")
	}
}

func TestApprovalInterceptor_NilDecision(t *testing.T) {
	store := NewApprovalStore(10)
	nextCalled := false
	next := &mockInterceptor{fn: func(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
		nextCalled = true
		return act, nil
	}}
	interceptor := NewApprovalInterceptor(store, next, approvalTestLogger())

	// No decision in context
	act := &CanonicalAction{
		Name:     "read_file",
		Identity: ActionIdentity{Name: "test", ID: "test-id"},
	}

	_, err := interceptor.Intercept(context.Background(), act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextCalled {
		t.Error("next should be called when no decision in context")
	}
}

// mockInterceptor is a test helper that calls a configurable function.
type mockInterceptor struct {
	fn func(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error)
}

func (m *mockInterceptor) Intercept(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
	return m.fn(ctx, act)
}
