package audit

import "context"

// TransformApplied records one transform that was applied to a response.
type TransformApplied struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Type     string `json:"type"`
	Detail   string `json:"detail,omitempty"`
}

// TransformResultHolder stores transform results in context for the audit interceptor.
type TransformResultHolder struct {
	Results []TransformApplied
}

// transformResultKeyType is the context key type for transform result propagation.
type transformResultKeyType struct{}

// transformResultKey is the context key for TransformResultHolder.
var transformResultKey = transformResultKeyType{}

// NewTransformResultContext returns a new context with an empty TransformResultHolder.
// The AuditInterceptor calls this before invoking the chain.
func NewTransformResultContext(ctx context.Context) (context.Context, *TransformResultHolder) {
	holder := &TransformResultHolder{}
	return context.WithValue(ctx, transformResultKey, holder), holder
}

// TransformResultFromContext retrieves the TransformResultHolder from context.
// Returns nil if not present.
func TransformResultFromContext(ctx context.Context) *TransformResultHolder {
	holder, _ := ctx.Value(transformResultKey).(*TransformResultHolder)
	return holder
}
