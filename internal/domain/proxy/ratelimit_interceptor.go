// Package proxy contains the core domain logic for the MCP proxy.
package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// ipAddressContextKey is the context key type for IP address.
type ipAddressContextKey struct{}

// IPAddressKey is the context key for IP address.
// Transports should set this value in context before calling ProxyService.Run().
// Example: ctx = context.WithValue(ctx, proxy.IPAddressKey, "192.168.1.1")
var IPAddressKey = ipAddressContextKey{}

// RateLimitError is returned when a request is rate limited.
type RateLimitError struct {
	// RetryAfter indicates how long to wait before retrying.
	RetryAfter time.Duration
}

// Error implements the error interface.
func (e *RateLimitError) Error() string {
	return fmt.Sprintf("rate limited, retry after %v", e.RetryAfter)
}

// RateLimitInterceptor enforces rate limits on requests.
// It checks IP-based limits first (before authentication) and user-based
// limits after authentication. This prevents brute-force attacks on the
// authentication mechanism.
//
// Position in chain: After Validation, before Auth.
// Chain order: Validation -> RateLimit -> Auth -> ToolFilter -> Audit -> Policy -> Passthrough
type RateLimitInterceptor struct {
	limiter    ratelimit.RateLimiter
	ipConfig   ratelimit.RateLimitConfig
	userConfig ratelimit.RateLimitConfig
	next       MessageInterceptor
	logger     *slog.Logger
}

// NewRateLimitInterceptor creates a new RateLimitInterceptor.
//
// Parameters:
//   - limiter: The rate limiter implementation (e.g., RedisRateLimiter)
//   - ipConfig: Rate limit config for IP-based limiting
//   - userConfig: Rate limit config for user-based limiting (after auth)
//   - next: The next interceptor in the chain (typically AuthInterceptor)
//   - logger: Logger for rate limit events
func NewRateLimitInterceptor(
	limiter ratelimit.RateLimiter,
	ipConfig ratelimit.RateLimitConfig,
	userConfig ratelimit.RateLimitConfig,
	next MessageInterceptor,
	logger *slog.Logger,
) *RateLimitInterceptor {
	return &RateLimitInterceptor{
		limiter:    limiter,
		ipConfig:   ipConfig,
		userConfig: userConfig,
		next:       next,
		logger:     logger,
	}
}

// Intercept checks rate limits before passing to the next interceptor.
// Returns RateLimitError if the request is rate limited.
func (r *RateLimitInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// Only rate limit client-to-server requests
	if msg.Direction != mcp.ClientToServer {
		return r.next.Intercept(ctx, msg)
	}

	// Extract IP from context
	ip, _ := ctx.Value(IPAddressKey).(string)
	if ip == "" {
		ip = "unknown"
	}

	// Check IP rate limit first (before auth to prevent brute-force)
	ipKey := ratelimit.FormatKey(ratelimit.KeyTypeIP, ip)
	ipResult, err := r.limiter.Allow(ctx, ipKey, r.ipConfig)
	if err != nil {
		r.logger.Error("failed to check IP rate limit",
			"ip", ip,
			"error", err,
		)
		// On error, allow through (fail-open for availability)
		// In production, you might want fail-closed behavior
		return r.next.Intercept(ctx, msg)
	}

	if !ipResult.Allowed {
		r.logger.Warn("IP rate limited",
			"ip", ip,
			"retry_after", ipResult.RetryAfter,
		)
		return nil, &RateLimitError{RetryAfter: ipResult.RetryAfter}
	}

	r.logger.Debug("IP rate limit check passed",
		"ip", ip,
		"remaining", ipResult.Remaining,
	)

	// If authenticated (has session), check user rate limit
	if msg.Session != nil {
		userKey := ratelimit.FormatKey(ratelimit.KeyTypeUser, msg.Session.IdentityID)
		userResult, err := r.limiter.Allow(ctx, userKey, r.userConfig)
		if err != nil {
			r.logger.Error("failed to check user rate limit",
				"identity_id", msg.Session.IdentityID,
				"error", err,
			)
			// On error, allow through (fail-open)
			return r.next.Intercept(ctx, msg)
		}

		if !userResult.Allowed {
			r.logger.Warn("user rate limited",
				"identity_id", msg.Session.IdentityID,
				"retry_after", userResult.RetryAfter,
			)
			return nil, &RateLimitError{RetryAfter: userResult.RetryAfter}
		}

		r.logger.Debug("user rate limit check passed",
			"identity_id", msg.Session.IdentityID,
			"remaining", userResult.Remaining,
		)
	}

	// Pass to next interceptor
	return r.next.Intercept(ctx, msg)
}

// Compile-time check that RateLimitInterceptor implements MessageInterceptor.
var _ MessageInterceptor = (*RateLimitInterceptor)(nil)
