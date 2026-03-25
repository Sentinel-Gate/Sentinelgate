package audit

import "context"

// policyDecisionContextKey is the context key type for policy decision propagation.
type policyDecisionContextKey struct{}

// PolicyDecisionHolder is a mutable container placed in context by the
// AuditInterceptor. The PolicyActionInterceptor populates it with the
// matched rule ID. The AuditInterceptor reads it after the chain completes
// to populate the audit record's RuleID field.
type PolicyDecisionHolder struct {
	// RuleID is the ID of the policy rule that matched (if any).
	RuleID string
	// RuleName is the name of the policy rule that matched (if any).
	RuleName string
}

// NewPolicyDecisionContext returns a new context with an empty PolicyDecisionHolder.
// The AuditInterceptor calls this before invoking the chain.
func NewPolicyDecisionContext(ctx context.Context) (context.Context, *PolicyDecisionHolder) {
	holder := &PolicyDecisionHolder{}
	return context.WithValue(ctx, policyDecisionContextKey{}, holder), holder
}

// PolicyDecisionFromContext retrieves the PolicyDecisionHolder from context.
// Returns nil if not present.
func PolicyDecisionFromContext(ctx context.Context) *PolicyDecisionHolder {
	holder, _ := ctx.Value(policyDecisionContextKey{}).(*PolicyDecisionHolder)
	return holder
}
