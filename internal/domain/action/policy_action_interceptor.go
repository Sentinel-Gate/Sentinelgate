package action

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
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
	TotalCalls     int64
	ReadCalls      int64
	WriteCalls     int64
	DeleteCalls    int64
	CumulativeCost float64 // running cost total for the session
	StartedAt      time.Time

	// Session history fields (Phase 17: Session-Aware Policies)
	ActionHistory []SessionActionRecord // ordered list of actions
	ActionSet     map[string]bool       // unique tool names
	ArgKeySet     map[string]bool       // unique arg key names
}

// HealthMetricsData holds agent health metrics for CEL policy evaluation.
type HealthMetricsData struct {
	DenyRate       float64
	DriftScore     float64
	ViolationCount int64
	TotalCalls     int64
	ErrorRate      float64
}

// HealthMetricsProvider provides cached health metrics for policy evaluation.
// Implemented by service.HealthService.
type HealthMetricsProvider interface {
	GetHealthMetrics(ctx context.Context, identityID string) HealthMetricsData
}

// PolicyActionInterceptor evaluates CanonicalActions against RBAC policies.
// This is the natively migrated version of proxy.PolicyInterceptor -- it
// operates directly on CanonicalAction instead of going through LegacyAdapter.
// It proves the CANON-10 migration path: each interceptor can be individually
// rewritten to use CanonicalAction fields directly.
type PolicyActionInterceptor struct {
	mu            sync.RWMutex
	policyEngine  policy.PolicyEngine
	sessionUsage  SessionUsageProvider  // optional, nil = no session data
	healthMetrics HealthMetricsProvider // optional, nil = no health data
	next          ActionInterceptor
	logger        *slog.Logger
}

// Compile-time check that PolicyActionInterceptor implements ActionInterceptor.
var _ ActionInterceptor = (*PolicyActionInterceptor)(nil)

// PolicyActionOption is a functional option for PolicyActionInterceptor.
type PolicyActionOption func(*PolicyActionInterceptor)

// WithSessionUsage sets the SessionUsageProvider for populating CEL session variables.
func WithSessionUsage(p SessionUsageProvider) PolicyActionOption {
	return func(i *PolicyActionInterceptor) { i.sessionUsage = p }
}

// WithHealthMetrics sets the HealthMetricsProvider for populating CEL health variables.
func WithHealthMetrics(p HealthMetricsProvider) PolicyActionOption {
	return func(i *PolicyActionInterceptor) { i.healthMetrics = p }
}

// SetHealthMetrics sets the health metrics provider after construction (late binding).
func (p *PolicyActionInterceptor) SetHealthMetrics(provider HealthMetricsProvider) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.healthMetrics = provider
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
	// Evaluate tool calls, HTTP requests, sampling, and elicitation against policies.
	switch action.Type {
	case ActionToolCall, ActionHTTPRequest, ActionSampling, ActionElicitation:
		// Fall through to policy evaluation
	default:
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
			evalCtx.SessionCumulativeCost = usage.CumulativeCost
			if !usage.StartedAt.IsZero() {
				evalCtx.SessionDurationSeconds = int64(time.Since(usage.StartedAt).Seconds())
			}

			// Populate session action history for CEL session functions (Phase 17).
			// Include the current action at the end so functions like session_sequence
			// can reference it via action_name. RecordCall happens AFTER policy evaluation
			// in the interceptor chain, so without this the current action is invisible.
			histLen := len(usage.ActionHistory)
			evalCtx.SessionActionHistory = make([]policy.SessionActionRecord, histLen+1)
			for i, rec := range usage.ActionHistory {
				evalCtx.SessionActionHistory[i] = policy.SessionActionRecord{
					ToolName:  rec.ToolName,
					CallType:  rec.CallType,
					Timestamp: rec.Timestamp,
					ArgKeys:   rec.ArgKeys,
				}
			}
			// Append current action as last entry
			var currentArgKeys []string
			for k := range action.Arguments {
				currentArgKeys = append(currentArgKeys, k)
			}
			evalCtx.SessionActionHistory[histLen] = policy.SessionActionRecord{
				ToolName:  action.Name,
				Timestamp: action.RequestTime,
				ArgKeys:   currentArgKeys,
			}

			// Copy action set with current action included
			evalCtx.SessionActionSet = make(map[string]bool, len(usage.ActionSet)+1)
			for k, v := range usage.ActionSet {
				evalCtx.SessionActionSet[k] = v
			}
			evalCtx.SessionActionSet[action.Name] = true

			// Copy arg key set with current action's arg keys included
			evalCtx.SessionArgKeySet = make(map[string]bool, len(usage.ArgKeySet)+len(action.Arguments))
			for k, v := range usage.ArgKeySet {
				evalCtx.SessionArgKeySet[k] = v
			}
			for k := range action.Arguments {
				evalCtx.SessionArgKeySet[k] = true
			}
		}
	}

	// Populate agent health metrics (Upgrade 11)
	p.mu.RLock()
	healthProvider := p.healthMetrics
	p.mu.RUnlock()
	if healthProvider != nil && action.Identity.ID != "" {
		hm := healthProvider.GetHealthMetrics(ctx, action.Identity.ID)
		evalCtx.UserDenyRate = hm.DenyRate
		evalCtx.UserDriftScore = hm.DriftScore
		evalCtx.UserViolationCount = hm.ViolationCount
		evalCtx.UserTotalCalls = hm.TotalCalls
		evalCtx.UserErrorRate = hm.ErrorRate
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

	// Propagate rule ID to the audit interceptor via context holder
	if holder := audit.PolicyDecisionFromContext(ctx); holder != nil {
		holder.RuleID = decision.RuleID
		holder.RuleName = decision.RuleName
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
