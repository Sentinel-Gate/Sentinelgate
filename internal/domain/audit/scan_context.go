package audit

import "context"

// scanResultContextKey is the context key type for scan result propagation.
type scanResultContextKey struct{}

// ScanResultHolder is a mutable container placed in context by the
// AuditInterceptor. Downstream interceptors (e.g., ResponseScanInterceptor)
// populate it with scan findings. The AuditInterceptor reads it after the
// chain completes to populate audit record scan fields.
type ScanResultHolder struct {
	// Detections is the number of scan findings.
	Detections int
	// Action is the action taken: "blocked" (enforce) or "monitored" (monitor).
	Action string
	// Types is a comma-separated list of unique finding categories (e.g., "prompt_injection").
	Types string
}

// NewScanResultContext returns a new context with an empty ScanResultHolder.
// The AuditInterceptor calls this before invoking the chain.
func NewScanResultContext(ctx context.Context) (context.Context, *ScanResultHolder) {
	holder := &ScanResultHolder{}
	return context.WithValue(ctx, scanResultContextKey{}, holder), holder
}

// ScanResultFromContext retrieves the ScanResultHolder from context.
// Returns nil if not present.
func ScanResultFromContext(ctx context.Context) *ScanResultHolder {
	holder, _ := ctx.Value(scanResultContextKey{}).(*ScanResultHolder)
	return holder
}
