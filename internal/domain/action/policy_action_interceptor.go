package action

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
)

// SessionUsageProvider provides session usage data for CEL policy evaluation.
// Implemented by session.SessionTracker (via adapter in start.go to avoid import cycle).
type SessionUsageProvider interface {
	GetUsage(sessionID string) (SessionUsageData, bool)
}

// SessionActionRecord captures a single tool call for session history analysis.
// This is an action-package mirror of session.ActionRecord and policy.SessionActionRecord
// to avoid import cycles between the three packages.
type SessionActionRecord struct {
	ToolName  string
	CallType  string
	Timestamp time.Time
	ArgKeys   []string
}

// SessionUsageData contains session usage metrics for policy evaluation.
type SessionUsageData struct {
	TotalCalls  int64
	WriteCalls  int64
	DeleteCalls int64
	StartedAt   time.Time

	// Session history fields (Phase 17: Session-Aware Policies)
	ActionHistory []SessionActionRecord // ordered list of actions
	ActionSet     map[string]bool       // unique tool names
	ArgKeySet     map[string]bool       // unique arg key names
}

// PolicyActionInterceptor evaluates CanonicalActions against RBAC policies.
// This is the natively migrated version of proxy.PolicyInterceptor -- it
// operates directly on CanonicalAction instead of going through LegacyAdapter.
// It proves the CANON-10 migration path: each interceptor can be individually
// rewritten to use CanonicalAction fields directly.
type PolicyActionInterceptor struct {
	policyEngine policy.PolicyEngine
	sessionUsage SessionUsageProvider // optional, nil = no session data
	next         ActionInterceptor
	logger       *slog.Logger
}

// Compile-time check that PolicyActionInterceptor implements ActionInterceptor.
var _ ActionInterceptor = (*PolicyActionInterceptor)(nil)

// PolicyActionOption is a functional option for PolicyActionInterceptor.
type PolicyActionOption func(*PolicyActionInterceptor)

// WithSessionUsage sets the SessionUsageProvider for populating CEL session variables.
func WithSessionUsage(p SessionUsageProvider) PolicyActionOption {
	return func(i *PolicyActionInterceptor) { i.sessionUsage = p }
}

// NewPolicyActionInterceptor creates a new PolicyActionInterceptor.
// Accepts optional PolicyActionOption values for backward compatibility.
func NewPolicyActionInterceptor(engine policy.PolicyEngine, next ActionInterceptor, logger *slog.Logger, opts ...PolicyActionOption) *PolicyActionInterceptor {
	p := &PolicyActionInterceptor{
		policyEngine: engine,
		next:         next,
		logger:       logger,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Intercept evaluates tool calls and HTTP requests against policies before passing
// to the next interceptor. Other action types pass through without policy evaluation.
func (p *PolicyActionInterceptor) Intercept(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error) {
	// Only evaluate tool calls and HTTP requests (incl. WebSocket upgrades)
	if action.Type != ActionToolCall && action.Type != ActionHTTPRequest {
		return p.next.Intercept(ctx, action)
	}

	// Identity check: session must be set by AuthInterceptor upstream
	if action.Identity.SessionID == "" {
		p.logger.Warn("action without session context", "type", action.Type)
		return nil, proxy.ErrMissingSession
	}

	// Build EvaluationContext directly from CanonicalAction fields
	evalCtx := policy.EvaluationContext{
		ToolName:      action.Name,
		ToolArguments: action.Arguments,
		UserRoles:     action.Identity.Roles,
		SessionID:     action.Identity.SessionID,
		IdentityID:    action.Identity.ID,
		IdentityName:  action.Identity.Name,
		RequestTime:   action.RequestTime,

		// Universal fields populated natively from CanonicalAction
		ActionType: string(action.Type),
		ActionName: action.Name,
		Protocol:   action.Protocol,
		Gateway:    action.Gateway,
		Framework:  action.Framework,

		// Destination fields
		DestURL:     action.Destination.URL,
		DestDomain:  action.Destination.Domain,
		DestIP:      action.Destination.IP,
		DestPort:    action.Destination.Port,
		DestScheme:  action.Destination.Scheme,
		DestPath:    action.Destination.Path,
		DestCommand: action.Destination.Command,
	}

	// Populate session usage from tracker if available
	if p.sessionUsage != nil && action.Identity.SessionID != "" {
		if usage, ok := p.sessionUsage.GetUsage(action.Identity.SessionID); ok {
			evalCtx.SessionCallCount = usage.TotalCalls
			evalCtx.SessionWriteCount = usage.WriteCalls
			evalCtx.SessionDeleteCount = usage.DeleteCalls
			if !usage.StartedAt.IsZero() {
				evalCtx.SessionDurationSeconds = int64(time.Since(usage.StartedAt).Seconds())
			}

			// Populate session action history for CEL session functions (Phase 17)
			if len(usage.ActionHistory) > 0 {
				evalCtx.SessionActionHistory = make([]policy.SessionActionRecord, len(usage.ActionHistory))
				for i, rec := range usage.ActionHistory {
					evalCtx.SessionActionHistory[i] = policy.SessionActionRecord{
						ToolName:  rec.ToolName,
						CallType:  rec.CallType,
						Timestamp: rec.Timestamp,
						ArgKeys:   rec.ArgKeys,
					}
				}
			}
			evalCtx.SessionActionSet = usage.ActionSet
			evalCtx.SessionArgKeySet = usage.ArgKeySet
		}
	}

	// Evaluate against policy engine
	decision, err := p.policyEngine.Evaluate(ctx, evalCtx)
	if err != nil {
		p.logger.Error("policy evaluation failed",
			"error", err,
			"tool", evalCtx.ToolName,
			"session_id", action.Identity.SessionID,
		)
		return nil, fmt.Errorf("policy evaluation error: %w", err)
	}

	// Check decision
	if !decision.Allowed && !decision.RequiresApproval {
		p.logger.Info("tool call denied by policy",
			"tool", evalCtx.ToolName,
			"rule_id", decision.RuleID,
			"reason", decision.Reason,
			"session_id", action.Identity.SessionID,
			"identity_id", action.Identity.ID,
		)
		return nil, fmt.Errorf("%w: %s", proxy.ErrPolicyDenied, decision.Reason)
	}

	// Store decision in context for downstream interceptors (ApprovalInterceptor)
	ctx = policy.WithDecision(ctx, &decision)

	// Log decision
	if decision.RequiresApproval {
		p.logger.Info("tool call requires approval",
			"tool", evalCtx.ToolName,
			"rule_id", decision.RuleID,
			"session_id", action.Identity.SessionID,
			"timeout", decision.ApprovalTimeout,
		)
	} else {
		p.logger.Debug("tool call allowed by policy",
			"tool", evalCtx.ToolName,
			"rule_id", decision.RuleID,
			"session_id", action.Identity.SessionID,
		)
	}

	return p.next.Intercept(ctx, action)
}
