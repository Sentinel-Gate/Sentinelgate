package policy

import (
	"context"
	"time"
)

// EvaluationContext contains all information needed to evaluate a policy rule.
type EvaluationContext struct {
	// ToolName is the name of the tool being invoked.
	ToolName string
	// ToolArguments are the arguments passed to the tool.
	ToolArguments map[string]interface{}
	// UserRoles are the roles assigned to the user making the request.
	UserRoles []string
	// SessionID is the current session identifier.
	SessionID string
	// IdentityID is the authenticated user's identity identifier.
	IdentityID string
	// RequestTime is when the tool call was received.
	RequestTime time.Time

	// Framework context (Phase 19)
	// Framework identifies which framework is in use ("crewai", "autogen", or "").
	Framework string
	// FrameworkAttrs contains framework-specific attributes for CEL evaluation.
	// Keys follow the pattern "crewai.role", "autogen.agent_type", etc.
	FrameworkAttrs map[string]string
}

// policyDecisionKey is the context key type for policy decisions.
type policyDecisionKey struct{}

// WithDecision stores a policy decision in the context.
// This allows downstream interceptors (e.g., ApprovalInterceptor) to access
// the decision made by PolicyInterceptor.
func WithDecision(ctx context.Context, d *Decision) context.Context {
	return context.WithValue(ctx, policyDecisionKey{}, d)
}

// DecisionFromContext retrieves a policy decision from the context.
// Returns nil if no decision is stored.
func DecisionFromContext(ctx context.Context) *Decision {
	d, _ := ctx.Value(policyDecisionKey{}).(*Decision)
	return d
}
