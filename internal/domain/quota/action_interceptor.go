package quota

import (
	"context"
	"log/slog"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
)

// CostEstimator estimates the cost of a tool call for session cost tracking.
type CostEstimator interface {
	EstimateCost(toolName string, argsSize int) float64
}

// ActionQuotaInterceptor enforces per-identity quota limits on tool calls.
// Native ActionInterceptor replacement for QuotaInterceptor.
type ActionQuotaInterceptor struct {
	mu            sync.RWMutex
	quotaService  *QuotaService
	tracker       *session.SessionTracker
	costEstimator CostEstimator // optional, nil = no cost tracking
	next          action.ActionInterceptor
	logger        *slog.Logger
}

// Compile-time check that ActionQuotaInterceptor implements ActionInterceptor.
var _ action.ActionInterceptor = (*ActionQuotaInterceptor)(nil)

// NewActionQuotaInterceptor creates a new ActionQuotaInterceptor.
func NewActionQuotaInterceptor(
	quotaService *QuotaService,
	tracker *session.SessionTracker,
	next action.ActionInterceptor,
	logger *slog.Logger,
) *ActionQuotaInterceptor {
	return &ActionQuotaInterceptor{
		quotaService: quotaService,
		tracker:      tracker,
		next:         next,
		logger:       logger,
	}
}

// SetCostEstimator sets the cost estimator for session cost tracking.
func (q *ActionQuotaInterceptor) SetCostEstimator(ce CostEstimator) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.costEstimator = ce
}

// Intercept enforces quota limits on tool calls.
// Non-tool-call actions and anonymous actions pass through unchanged.
func (q *ActionQuotaInterceptor) Intercept(ctx context.Context, act *action.CanonicalAction) (*action.CanonicalAction, error) {
	// Non-tool-call actions pass through
	if act.Type != action.ActionToolCall || act.Name == "" {
		return q.next.Intercept(ctx, act)
	}

	// No identity means anonymous — no quota applicable
	if act.Identity.SessionID == "" {
		return q.next.Intercept(ctx, act)
	}

	// Check quota
	result := q.quotaService.Check(ctx, act.Identity.ID, act.Identity.SessionID, act.Name)

	if !result.Allowed {
		return nil, &QuotaDenyError{
			Reason:     result.DenyReason,
			IdentityID: act.Identity.ID,
		}
	}

	// Log warnings and propagate to audit via context holder
	if len(result.Warnings) > 0 {
		for _, w := range result.Warnings {
			q.logger.Warn("quota warning",
				"identity_id", act.Identity.ID,
				"session_id", act.Identity.SessionID,
				"warning", w,
			)
		}
		if holder := audit.QuotaWarningFromContext(ctx); holder != nil {
			holder.Warnings = result.Warnings
		}
	}

	// Proceed with the call
	argKeys := extractArgKeysFromAction(act)
	out, err := q.next.Intercept(ctx, act)

	// Record every call attempt (including policy denials) so denied
	// calls count toward quota limits (#22).
	q.tracker.RecordCall(act.Identity.SessionID, act.Name, act.Identity.ID, act.Identity.Name, argKeys)

	// Only record cost for calls that actually executed
	if err == nil {
		q.mu.RLock()
		ce := q.costEstimator
		q.mu.RUnlock()
		if ce != nil {
			cost := ce.EstimateCost(act.Name, len(act.Arguments))
			q.tracker.RecordCost(act.Identity.SessionID, cost)
		}
	}
	return out, err
}

// extractArgKeysFromAction extracts argument key names from the CanonicalAction.
func extractArgKeysFromAction(act *action.CanonicalAction) []string {
	if len(act.Arguments) == 0 {
		return nil
	}
	keys := make([]string, 0, len(act.Arguments))
	for k := range act.Arguments {
		keys = append(keys, k)
	}
	return keys
}
