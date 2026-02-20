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

// IPRateLimitInterceptor enforces IP-based rate limits on requests.
// It runs before authentication to prevent brute-force attacks.
//
// Position in chain: After Validation, before Auth.
// Chain order: Validation -> IPRateLimit -> Auth -> UserRateLimit -> Audit -> Policy -> ...
type IPRateLimitInterceptor struct {
	limiter  ratelimit.RateLimiter
	ipConfig ratelimit.RateLimitConfig
	next     MessageInterceptor
	logger   *slog.Logger
}

// NewIPRateLimitInterceptor creates a new IPRateLimitInterceptor.
//
// Parameters:
//   - limiter: The rate limiter implementation
//   - ipConfig: Rate limit config for IP-based limiting
//   - next: The next interceptor in the chain (typically AuthInterceptor)
//   - logger: Logger for rate limit events
func NewIPRateLimitInterceptor(
	limiter ratelimit.RateLimiter,
	ipConfig ratelimit.RateLimitConfig,
	next MessageInterceptor,
	logger *slog.Logger,
) *IPRateLimitInterceptor {
	return &IPRateLimitInterceptor{
		limiter:  limiter,
		ipConfig: ipConfig,
		next:     next,
		logger:   logger,
	}
}

// Intercept checks IP rate limits before passing to the next interceptor.
// Returns RateLimitError if the request is rate limited.
func (r *IPRateLimitInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// Only rate limit client-to-server requests
	if msg.Direction != mcp.ClientToServer {
		return r.next.Intercept(ctx, msg)
	}

	// Extract IP from context
	ip, _ := ctx.Value(IPAddressKey).(string)
	if ip == "" {
		ip = "unknown"
	}

	// Check IP rate limit (before auth to prevent brute-force)
	ipKey := ratelimit.FormatKey(ratelimit.KeyTypeIP, ip)
	ipResult, err := r.limiter.Allow(ctx, ipKey, r.ipConfig)
	if err != nil {
		r.logger.Error("failed to check IP rate limit",
			"ip", ip,
			"error", err,
		)
		// On error, allow through (fail-open for availability)
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

	// Pass to next interceptor (auth)
	return r.next.Intercept(ctx, msg)
}

// UserRateLimitInterceptor enforces per-user rate limits on authenticated requests.
// It runs after authentication so msg.Session is populated with identity info.
//
// Position in chain: After Auth, before Audit.
// Chain order: Validation -> IPRateLimit -> Auth -> UserRateLimit -> Audit -> Policy -> ...
type UserRateLimitInterceptor struct {
	limiter    ratelimit.RateLimiter
	userConfig ratelimit.RateLimitConfig
	next       MessageInterceptor
	logger     *slog.Logger
}

// NewUserRateLimitInterceptor creates a new UserRateLimitInterceptor.
//
// Parameters:
//   - limiter: The rate limiter implementation
//   - userConfig: Rate limit config for user-based limiting
//   - next: The next interceptor in the chain (typically AuditInterceptor)
//   - logger: Logger for rate limit events
func NewUserRateLimitInterceptor(
	limiter ratelimit.RateLimiter,
	userConfig ratelimit.RateLimitConfig,
	next MessageInterceptor,
	logger *slog.Logger,
) *UserRateLimitInterceptor {
	return &UserRateLimitInterceptor{
		limiter:    limiter,
		userConfig: userConfig,
		next:       next,
		logger:     logger,
	}
}

// Intercept checks user rate limits for authenticated requests.
// If msg.Session is nil (unauthenticated), it passes through without checking.
// Returns RateLimitError if the request is rate limited.
func (r *UserRateLimitInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// Only rate limit client-to-server requests
	if msg.Direction != mcp.ClientToServer {
		return r.next.Intercept(ctx, msg)
	}

	// Check user rate limit if authenticated (has session with identity)
	if msg.Session != nil && msg.Session.IdentityID != "" {
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

	// Pass to next interceptor (audit)
	return r.next.Intercept(ctx, msg)
}

// Compile-time checks that both interceptors implement MessageInterceptor.
var _ MessageInterceptor = (*IPRateLimitInterceptor)(nil)
var _ MessageInterceptor = (*UserRateLimitInterceptor)(nil)
