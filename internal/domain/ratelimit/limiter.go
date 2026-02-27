package ratelimit

import "context"

// RateLimiter is the interface for rate limiting operations.
//
// Implementations should use the GCRA (Generic Cell Rate Algorithm)
// for smooth rate limiting without burst issues at window boundaries.
// GCRA provides more consistent behavior than fixed-window or sliding-window
// algorithms by spreading requests evenly over time.
//
// The interface is designed to be storage-agnostic, allowing implementations
// backed by Redis, in-memory stores, or other backends.
type RateLimiter interface {
	// Allow checks if a request identified by key is allowed under the given config.
	// It returns the result of the check and any error that occurred.
	//
	// The key should be a structured identifier created by FormatKey.
	// The config specifies the rate limit parameters (rate, burst, period).
	//
	// Allow atomically decrements the rate limit counter and returns the result.
	// If the request is not allowed, RetryAfter in the result indicates when
	// the next request will be allowed.
	Allow(ctx context.Context, key string, config RateLimitConfig) (RateLimitResult, error)
}
