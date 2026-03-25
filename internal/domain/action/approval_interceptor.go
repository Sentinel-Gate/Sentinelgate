package action

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
)

var ErrAlreadyResolved = errors.New("approval already resolved")

// ErrApprovalNotFound is returned when an approval ID does not exist.
var ErrApprovalNotFound = errors.New("approval not found")

const (
	// DefaultApprovalTimeout is the default timeout for pending approvals.
	DefaultApprovalTimeout = 5 * time.Minute
	// DefaultMaxPending is the default maximum number of pending approvals.
	DefaultMaxPending = 100
)

// PendingApproval represents a tool call that is blocked pending human approval.
type PendingApproval struct {
	ID            string                 `json:"id"`
	ToolName      string                 `json:"tool_name"`
	Arguments     map[string]interface{} `json:"arguments,omitempty"`
	IdentityName  string                 `json:"identity_name"`
	IdentityID    string                 `json:"identity_id"`
	SessionID     string                 `json:"session_id,omitempty"`
	RuleID        string                 `json:"rule_id,omitempty"`
	RuleName      string                 `json:"rule_name,omitempty"`
	Condition     string                 `json:"condition,omitempty"`
	Status        string                 `json:"status"` // "pending", "approved", "denied", "timed_out"
	CreatedAt     time.Time              `json:"created_at"`
	ResolvedAt    *time.Time             `json:"resolved_at,omitempty"`
	AuditNote     string                 `json:"audit_note,omitempty"`
	Timeout       time.Duration          `json:"-"`
	TimeoutAction policy.Action          `json:"-"`
	result        chan ApprovalResult
}

// ApprovalResult carries the outcome of an approval decision.
type ApprovalResult struct {
	Approved bool
	Reason   string
}

// ApprovalStore manages pending approval requests with bounded capacity.
// It is thread-safe and supports FIFO eviction when capacity is reached.
type ApprovalStore struct {
	mu       sync.RWMutex
	pending  map[string]*PendingApproval
	order    []string
	maxSize  int
	eventBus event.Bus
}

// SetEventBus wires the event bus for emitting approval events.
func (s *ApprovalStore) SetEventBus(bus event.Bus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventBus = bus
}

// NewApprovalStore creates a new ApprovalStore with the given maximum capacity.
func NewApprovalStore(maxSize int) *ApprovalStore {
	if maxSize <= 0 {
		maxSize = DefaultMaxPending
	}
	return &ApprovalStore{
		pending: make(map[string]*PendingApproval),
		order:   make([]string, 0, maxSize),
		maxSize: maxSize,
	}
}

// Add stores a new pending approval.
// Returns an error if the store is at capacity.
func (s *ApprovalStore) Add(approval *PendingApproval) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// M-9: Count only truly pending entries, not resolved ones.
	pendingCount := 0
	for _, id := range s.order {
		if p, ok := s.pending[id]; ok && p.Status == "pending" {
			pendingCount++
		}
	}
	if pendingCount >= s.maxSize {
		return fmt.Errorf("approval queue full (%d pending)", s.maxSize)
	}

	s.pending[approval.ID] = approval
	s.order = append(s.order, approval.ID)
	return nil
}

// List returns all pending approvals (status == "pending").
// Returns defensive copies so callers cannot mutate live objects.
func (s *ApprovalStore) List() []*PendingApproval {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*PendingApproval
	for _, id := range s.order {
		if p, ok := s.pending[id]; ok && p.Status == "pending" {
			cp := *p
			if p.Arguments != nil {
				cp.Arguments = make(map[string]interface{}, len(p.Arguments))
				for k, v := range p.Arguments {
					cp.Arguments[k] = v
				}
			}
			cp.result = nil // internal channel must not be shared
			result = append(result, &cp)
		}
	}
	return result
}

// Get returns a pending approval by ID, or nil if not found.
func (s *ApprovalStore) Get(id string) *PendingApproval {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.pending[id]
	if !ok {
		return nil
	}
	cp := *p
	if p.Arguments != nil {
		cp.Arguments = make(map[string]interface{}, len(p.Arguments))
		for k, v := range p.Arguments {
			cp.Arguments[k] = v
		}
	}
	cp.result = nil
	return &cp
}

// Approve sends an approval result to the blocked goroutine and removes the entry.
func (s *ApprovalStore) Approve(id, note string) error {
	s.mu.Lock()

	p, ok := s.pending[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrApprovalNotFound, id)
	}
	if p.Status != "pending" {
		s.mu.Unlock()
		return fmt.Errorf("%w: approval %s is already %s", ErrAlreadyResolved, id, p.Status)
	}

	now := time.Now().UTC()
	p.Status = "approved"
	p.ResolvedAt = &now
	p.AuditNote = note
	snap := snapshotApproval(p)
	// M-9: Remove resolved entry from order so it doesn't count against capacity.
	s.removeFromOrderLocked(id)
	// L-46: Send result outside of lock to avoid blocking under mutex.
	resultCh := p.result
	s.mu.Unlock()
	select {
	case resultCh <- ApprovalResult{Approved: true}:
	default:
	}

	s.emitEvent("approval.approved", snap, "", note)
	return nil
}

// Deny sends a denial result to the blocked goroutine and removes the entry.
func (s *ApprovalStore) Deny(id, reason, note string) error {
	s.mu.Lock()

	p, ok := s.pending[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrApprovalNotFound, id)
	}
	if p.Status != "pending" {
		s.mu.Unlock()
		return fmt.Errorf("%w: approval %s is already %s", ErrAlreadyResolved, id, p.Status)
	}

	now := time.Now().UTC()
	p.Status = "denied"
	p.ResolvedAt = &now
	p.AuditNote = note
	snap := snapshotApproval(p)
	// M-9: Remove resolved entry from order.
	s.removeFromOrderLocked(id)
	// L-46: Send result outside of lock.
	resultCh := p.result
	s.mu.Unlock()
	select {
	case resultCh <- ApprovalResult{Approved: false, Reason: reason}:
	default:
	}

	s.emitEvent("approval.rejected", snap, reason, note)
	return nil
}

// removeFromOrderLocked removes an ID from the order slice. Caller must hold s.mu.
func (s *ApprovalStore) removeFromOrderLocked(id string) {
	for i, oid := range s.order {
		if oid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			return
		}
	}
}

// approvalEventPayload captures immutable fields from a PendingApproval for event emission.
// This avoids data races by snapshotting values under the lock.
type approvalEventPayload struct {
	ID           string
	ToolName     string
	IdentityName string
	IdentityID   string
	SessionID    string
	RuleID       string
	RuleName     string
	TimeoutSecs  int
}

func snapshotApproval(p *PendingApproval) approvalEventPayload {
	return approvalEventPayload{
		ID:           p.ID,
		ToolName:     p.ToolName,
		IdentityName: p.IdentityName,
		IdentityID:   p.IdentityID,
		SessionID:    p.SessionID,
		RuleID:       p.RuleID,
		RuleName:     p.RuleName,
		TimeoutSecs:  int(p.Timeout.Seconds()),
	}
}

// emitEvent publishes an approval event on the bus if wired.
// Uses a snapshot to avoid reading PendingApproval fields concurrently.
func (s *ApprovalStore) emitEvent(eventType string, snap approvalEventPayload, reason, note string) {
	s.mu.RLock()
	bus := s.eventBus
	s.mu.RUnlock()
	if bus == nil {
		return
	}
	severity := event.SeverityWarning
	if eventType == "approval.hold" {
		severity = event.SeverityCritical
	}
	bus.Publish(context.Background(), event.Event{
		Type:           eventType,
		Source:         "escrow",
		Severity:       severity,
		RequiresAction: eventType == "approval.hold",
		Payload: map[string]interface{}{
			"approval_id":   snap.ID,
			"tool_name":     snap.ToolName,
			"identity_name": snap.IdentityName,
			"identity_id":   snap.IdentityID,
			"session_id":    snap.SessionID,
			"rule_id":       snap.RuleID,
			"rule_name":     snap.RuleName,
			"timeout_secs":  snap.TimeoutSecs,
			"reason":        reason,
			"audit_note":    note,
		},
	})
}

// CancelAll cancels all pending approvals (used during shutdown).
func (s *ApprovalStore) CancelAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for _, p := range s.pending {
		if p.Status == "pending" {
			p.Status = "denied"
			p.ResolvedAt = &now
			select {
			case p.result <- ApprovalResult{Approved: false, Reason: "server shutting down"}:
			default:
			}
		}
	}
}

// DeletePending marks a pending approval as timed-out, sets its resolved time,
// and removes it from the pending map and order slice so it no longer counts
// against the capacity check.
// M-24: Previously timed-out entries stayed in the map/order, causing premature
// "queue full" errors under burst conditions.
func (s *ApprovalStore) DeletePending(id string, status string, resolvedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.pending[id]; ok {
		p.Status = status
		p.ResolvedAt = &resolvedAt
	}
	delete(s.pending, id)
	for i, oid := range s.order {
		if oid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

// remove removes a pending approval from the store (called after resolution).
func (s *ApprovalStore) remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, id)
	for i, oid := range s.order {
		if oid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

// NewTestPendingApproval creates a PendingApproval for testing.
func NewTestPendingApproval(id, toolName, identityName, identityID, sessionID, ruleID, ruleName string, timeout time.Duration) *PendingApproval {
	return &PendingApproval{
		ID:            id,
		ToolName:      toolName,
		IdentityName:  identityName,
		IdentityID:    identityID,
		SessionID:     sessionID,
		RuleID:        ruleID,
		RuleName:      ruleName,
		Status:        "pending",
		CreatedAt:     time.Now().UTC(),
		Timeout:       timeout,
		TimeoutAction: policy.ActionDeny,
		result:        make(chan ApprovalResult, 1),
	}
}

// ApprovalInterceptor blocks tool calls that require human approval.
// It reads the policy Decision from context (set by PolicyActionInterceptor).
// If RequiresApproval is true, it creates a PendingApproval entry and blocks
// until the request is approved, denied, or times out.
type ApprovalInterceptor struct {
	store  *ApprovalStore
	next   ActionInterceptor
	logger *slog.Logger
}

// Compile-time check that ApprovalInterceptor implements ActionInterceptor.
var _ ActionInterceptor = (*ApprovalInterceptor)(nil)

// NewApprovalInterceptor creates a new ApprovalInterceptor.
func NewApprovalInterceptor(store *ApprovalStore, next ActionInterceptor, logger *slog.Logger) *ApprovalInterceptor {
	return &ApprovalInterceptor{
		store:  store,
		next:   next,
		logger: logger,
	}
}

// Intercept checks if the tool call requires approval. If so, it blocks until
// the request is approved, denied, or times out. Otherwise, it passes through.
func (a *ApprovalInterceptor) Intercept(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
	// Read decision from context (set by PolicyActionInterceptor)
	decision := policy.DecisionFromContext(ctx)
	if decision == nil || !decision.RequiresApproval {
		// No approval needed -- pass through
		return a.next.Intercept(ctx, act)
	}

	// Determine timeout
	timeout := decision.ApprovalTimeout
	if timeout <= 0 {
		timeout = DefaultApprovalTimeout
	}

	// Determine timeout action
	timeoutAction := decision.ApprovalTimeoutAction
	if timeoutAction == "" {
		timeoutAction = policy.ActionDeny
	}

	// Create pending approval
	pending := &PendingApproval{
		ID:            uuid.New().String(),
		ToolName:      act.Name,
		Arguments:     act.Arguments,
		IdentityName:  act.Identity.Name,
		IdentityID:    act.Identity.ID,
		SessionID:     act.Identity.SessionID,
		RuleID:        decision.RuleID,
		RuleName:      decision.RuleName,
		Condition:     decision.Reason,
		Status:        "pending",
		CreatedAt:     time.Now().UTC(),
		Timeout:       timeout,
		TimeoutAction: timeoutAction,
		result:        make(chan ApprovalResult, 1),
	}

	if err := a.store.Add(pending); err != nil {
		return nil, fmt.Errorf("approval system unavailable: %w", err)
	}
	a.store.emitEvent("approval.hold", snapshotApproval(pending), "", "")

	a.logger.Info("tool call blocked pending approval",
		"approval_id", pending.ID,
		"tool", act.Name,
		"identity", act.Identity.Name,
		"timeout", timeout,
		"timeout_action", timeoutAction,
	)

	// Wait for approval, denial, or timeout
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var result ApprovalResult
	select {
	case result = <-pending.result:
		// Approval or denial received
	case <-timer.C:
		// Timeout -- apply timeout action
		a.logger.Info("approval timed out",
			"approval_id", pending.ID,
			"tool", act.Name,
			"timeout_action", timeoutAction,
		)
		if timeoutAction == policy.ActionAllow {
			result = ApprovalResult{Approved: true, Reason: "approval timed out (default: allow)"}
		} else {
			result = ApprovalResult{Approved: false, Reason: "approval timed out (default: deny)"}
		}
		// Update status via store abstraction
		a.store.DeletePending(pending.ID, "timed_out", time.Now().UTC())
		a.store.emitEvent("approval.timeout", snapshotApproval(pending), result.Reason, "")
	case <-ctx.Done():
		// Context cancelled
		a.store.remove(pending.ID)
		return nil, ctx.Err()
	}

	// Clean up the store entry after resolution
	defer a.store.remove(pending.ID)

	if result.Approved {
		a.logger.Info("tool call approved",
			"approval_id", pending.ID,
			"tool", act.Name,
		)
		return a.next.Intercept(ctx, act)
	}

	reason := "approval denied"
	if result.Reason != "" {
		reason = result.Reason
	}

	a.logger.Info("tool call denied by approval",
		"approval_id", pending.ID,
		"tool", act.Name,
		"reason", reason,
	)
	return nil, fmt.Errorf("%w: %s", proxy.ErrPolicyDenied, reason)
}
