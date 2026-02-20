// Package ctxkey defines shared context key types used across multiple packages.
// This package should have no dependencies on other internal packages to avoid import cycles.
package ctxkey

// LoggerKey is the context key type for the enriched logger.
// Used by HTTP middleware to store and retrieve the logger with request_id/tenant_id fields.
type LoggerKey struct{}
