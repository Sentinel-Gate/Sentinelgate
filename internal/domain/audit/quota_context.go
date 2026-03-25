package audit

import "context"

// quotaWarningContextKey is the context key type for quota warning propagation.
type quotaWarningContextKey struct{}

// QuotaWarningHolder is a mutable container placed in context by the
// AuditInterceptor. The QuotaInterceptor populates it with any quota
// warnings (e.g., nearing limits in warn mode). The AuditInterceptor
// reads it after the chain completes to set Decision = "warn".
type QuotaWarningHolder struct {
	// Warnings contains quota warning messages (e.g., "calls per minute at 90%: 9/10").
	Warnings []string
}

// NewQuotaWarningContext returns a new context with an empty QuotaWarningHolder.
// The AuditInterceptor calls this before invoking the chain.
func NewQuotaWarningContext(ctx context.Context) (context.Context, *QuotaWarningHolder) {
	holder := &QuotaWarningHolder{}
	return context.WithValue(ctx, quotaWarningContextKey{}, holder), holder
}

// QuotaWarningFromContext retrieves the QuotaWarningHolder from context.
// Returns nil if not present.
func QuotaWarningFromContext(ctx context.Context) *QuotaWarningHolder {
	holder, _ := ctx.Value(quotaWarningContextKey{}).(*QuotaWarningHolder)
	return holder
}
