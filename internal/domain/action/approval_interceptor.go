package action

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
)

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
	Status        string                 `json:"status"` // "pending", "approved", "denied", "timed_out"
	CreatedAt     time.Time              `json:"created_at"`
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
	mu      sync.RWMutex
	pending map[string]*PendingApproval
	order   []string
	maxSize int
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

// Add stores a new pending approval and returns its ID.
// If the store is at capacity, the oldest pending approval is evicted (auto-denied).
func (s *ApprovalStore) Add(approval *PendingApproval) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Evict oldest if at capacity
	if len(s.order) >= s.maxSize {
		oldID := s.order[0]
		s.order = s.order[1:]
		if old, ok := s.pending[oldID]; ok {
			old.Status = "denied"
			// Non-blocking send to unblock any waiting goroutine
			select {
			case old.result <- ApprovalResult{Approved: false, Reason: "evicted: store at capacity"}:
			default:
			}
			delete(s.pending, oldID)
		}
	}

	s.pending[approval.ID] = approval
	s.order = append(s.order, approval.ID)
	return approval.ID
}

// List returns all pending approvals (status == "pending").
func (s *ApprovalStore) List() []*PendingApproval {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*PendingApproval
	for _, id := range s.order {
		if p, ok := s.pending[id]; ok && p.Status == "pending" {
			result = append(result, p)
		}
	}
	return result
}

// Get returns a pending approval by ID, or nil if not found.
func (s *ApprovalStore) Get(id string) *PendingApproval {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pending[id]
}

// Approve sends an approval result to the blocked goroutine and removes the entry.
func (s *ApprovalStore) Approve(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.pending[id]
	if !ok {
		return fmt.Errorf("approval %s not found", id)
	}
	if p.Status != "pending" {
		return fmt.Errorf("approval %s is already %s", id, p.Status)
	}

	p.Status = "approved"
	select {
	case p.result <- ApprovalResult{Approved: true}:
	default:
	}
	return nil
}

// Deny sends a denial result to the blocked goroutine and removes the entry.
func (s *ApprovalStore) Deny(id, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.pending[id]
	if !ok {
		return fmt.Errorf("approval %s not found", id)
	}
	if p.Status != "pending" {
		return fmt.Errorf("approval %s is already %s", id, p.Status)
	}

	p.Status = "denied"
	select {
	case p.result <- ApprovalResult{Approved: false, Reason: reason}:
	default:
	}
	return nil
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
		Status:        "pending",
		CreatedAt:     time.Now().UTC(),
		Timeout:       timeout,
		TimeoutAction: timeoutAction,
		result:        make(chan ApprovalResult, 1),
	}

	a.store.Add(pending)

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
		// Update status
		a.store.mu.Lock()
		if p, ok := a.store.pending[pending.ID]; ok {
			p.Status = "timed_out"
		}
		a.store.mu.Unlock()
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
