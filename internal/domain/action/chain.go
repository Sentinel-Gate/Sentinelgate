package action

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// InterceptorChain wraps the legacy MessageInterceptor chain with
// normalize/denormalize. It implements proxy.MessageInterceptor so it
// can be used as a drop-in replacement in ProxyService without modifying
// the proxy service code.
//
// Flow: mcp.Message -> MCPNormalizer.Normalize -> ActionInterceptors -> extract mcp.Message from CanonicalAction.OriginalMessage
type InterceptorChain struct {
	normalizer Normalizer
	head       ActionInterceptor // First interceptor in the chain
	logger     *slog.Logger
}

// Compile-time check that InterceptorChain implements proxy.MessageInterceptor.
var _ proxy.MessageInterceptor = (*InterceptorChain)(nil)

// NewInterceptorChain creates an InterceptorChain that normalizes incoming
// mcp.Messages into CanonicalActions, runs them through the ActionInterceptor
// chain, and extracts the resulting mcp.Message.
func NewInterceptorChain(normalizer Normalizer, head ActionInterceptor, logger *slog.Logger) *InterceptorChain {
	return &InterceptorChain{
		normalizer: normalizer,
		head:       head,
		logger:     logger,
	}
}

// Intercept implements proxy.MessageInterceptor. It normalizes the mcp.Message
// into a CanonicalAction, runs the ActionInterceptor chain, and extracts the
// resulting mcp.Message from the CanonicalAction.
func (c *InterceptorChain) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// 1. Normalize: mcp.Message -> CanonicalAction
	action, err := c.normalizer.Normalize(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("normalize failed: %w", err)
	}

	// 2. Run through ActionInterceptor chain
	result, err := c.head.Intercept(ctx, action)
	if err != nil {
		return nil, err // Preserve original error (SafeErrorMessage compatibility)
	}

	// 3. Extract the (potentially modified) mcp.Message from result
	if result == nil {
		return nil, nil
	}
	mcpMsg, ok := result.OriginalMessage.(*mcp.Message)
	if !ok {
		return nil, fmt.Errorf("unexpected message type after chain: %T", result.OriginalMessage)
	}
	return mcpMsg, nil
}
