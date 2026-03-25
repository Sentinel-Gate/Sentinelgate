package action

import (
	"context"
	"log/slog"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// ActionIPRateLimitInterceptor enforces IP-based rate limits on requests.
// It runs before authentication to prevent brute-force attacks.
// Native ActionInterceptor replacement for proxy.IPRateLimitInterceptor.
type ActionIPRateLimitInterceptor struct {
	limiter  ratelimit.RateLimiter
	ipConfig ratelimit.RateLimitConfig
	next     ActionInterceptor
	logger   *slog.Logger
}

// Compile-time check that ActionIPRateLimitInterceptor implements ActionInterceptor.
var _ ActionInterceptor = (*ActionIPRateLimitInterceptor)(nil)

// NewActionIPRateLimitInterceptor creates a new ActionIPRateLimitInterceptor.
func NewActionIPRateLimitInterceptor(
	limiter ratelimit.RateLimiter,
	ipConfig ratelimit.RateLimitConfig,
	next ActionInterceptor,
	logger *slog.Logger,
) *ActionIPRateLimitInterceptor {
	return &ActionIPRateLimitInterceptor{
		limiter:  limiter,
		ipConfig: ipConfig,
		next:     next,
		logger:   logger,
	}
}

// Intercept checks IP rate limits before passing to the next interceptor.
func (r *ActionIPRateLimitInterceptor) Intercept(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
	// Only rate limit client-to-server requests
	if mcpMsg, ok := act.OriginalMessage.(*mcp.Message); ok {
		if mcpMsg.Direction != mcp.ClientToServer {
			return r.next.Intercept(ctx, act)
		}
	}

	// Extract IP from context
	ip, _ := ctx.Value(proxy.IPAddressKey).(string)
	if ip == "" {
		ip = "unknown"
	}

	// Check IP rate limit
	ipKey := ratelimit.FormatKey(ratelimit.KeyTypeIP, ip)
	ipResult, err := r.limiter.Allow(ctx, ipKey, r.ipConfig)
	if err != nil {
		r.logger.Error("failed to check IP rate limit",
			"ip", ip,
			"error", err,
		)
		// On error, allow through (fail-open for availability)
		return r.next.Intercept(ctx, act)
	}

	if !ipResult.Allowed {
		r.logger.Warn("IP rate limited",
			"ip", ip,
			"retry_after", ipResult.RetryAfter,
		)
		return nil, &proxy.RateLimitError{RetryAfter: ipResult.RetryAfter}
	}

	r.logger.Debug("IP rate limit check passed",
		"ip", ip,
		"remaining", ipResult.Remaining,
	)

	return r.next.Intercept(ctx, act)
}
