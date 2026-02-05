// Package proxy contains the core domain logic for the MCP proxy.
package proxy

import (
	"context"

	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// MessageInterceptor inspects and optionally modifies messages.
// Phase 1: Passthrough only. Phase 3+: Policy evaluation.
type MessageInterceptor interface {
	// Intercept inspects a message and returns it (possibly modified).
	// Returns the message to forward, or an error to block/reject.
	// For passthrough, return the same message unchanged.
	Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error)
}

// PassthroughInterceptor forwards all messages unchanged.
// Used in Phase 1 before policy engine is implemented.
type PassthroughInterceptor struct{}

// NewPassthroughInterceptor creates a passthrough interceptor.
func NewPassthroughInterceptor() *PassthroughInterceptor {
	return &PassthroughInterceptor{}
}

// Intercept returns the message unchanged.
func (i *PassthroughInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	return msg, nil
}

// Compile-time check that PassthroughInterceptor implements MessageInterceptor.
var _ MessageInterceptor = (*PassthroughInterceptor)(nil)
