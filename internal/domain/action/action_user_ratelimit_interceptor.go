package action

import (
	"context"
	"log/slog"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// ActionUserRateLimitInterceptor enforces per-user rate limits on authenticated requests.
// It runs after authentication so action.Identity is populated.
// Native ActionInterceptor replacement for proxy.UserRateLimitInterceptor.
type ActionUserRateLimitInterceptor struct {
	limiter    ratelimit.RateLimiter
	userConfig ratelimit.RateLimitConfig
	next       ActionInterceptor
	logger     *slog.Logger
}

// Compile-time check that ActionUserRateLimitInterceptor implements ActionInterceptor.
var _ ActionInterceptor = (*ActionUserRateLimitInterceptor)(nil)

// NewActionUserRateLimitInterceptor creates a new ActionUserRateLimitInterceptor.
func NewActionUserRateLimitInterceptor(
	limiter ratelimit.RateLimiter,
	userConfig ratelimit.RateLimitConfig,
	next ActionInterceptor,
	logger *slog.Logger,
) *ActionUserRateLimitInterceptor {
	return &ActionUserRateLimitInterceptor{
		limiter:    limiter,
		userConfig: userConfig,
		next:       next,
		logger:     logger,
	}
}

// Intercept checks per-user rate limits for authenticated requests.
func (r *ActionUserRateLimitInterceptor) Intercept(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
	// Only rate limit client-to-server requests
	if mcpMsg, ok := act.OriginalMessage.(*mcp.Message); ok {
		if mcpMsg.Direction != mcp.ClientToServer {
			return r.next.Intercept(ctx, act)
		}
	}

	// Rate limit by identity (skip if not authenticated)
	if act.Identity.ID != "" {
		userKey := ratelimit.FormatKey(ratelimit.KeyTypeUser, act.Identity.ID)
		userResult, err := r.limiter.Allow(ctx, userKey, r.userConfig)
		if err != nil {
			r.logger.Error("failed to check user rate limit",
				"identity_id", act.Identity.ID,
				"error", err,
			)
			// On error, allow through (fail-open)
			return r.next.Intercept(ctx, act)
		}

		if !userResult.Allowed {
			r.logger.Warn("user rate limited",
				"identity_id", act.Identity.ID,
				"retry_after", userResult.RetryAfter,
			)
			return nil, &proxy.RateLimitError{RetryAfter: userResult.RetryAfter}
		}

		r.logger.Debug("user rate limit check passed",
			"identity_id", act.Identity.ID,
			"remaining", userResult.Remaining,
		)
	}

	return r.next.Intercept(ctx, act)
}
