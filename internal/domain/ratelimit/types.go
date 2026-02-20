// Package ratelimit provides rate limiting domain types.
package ratelimit

import (
	"fmt"
	"time"
)

// RateLimitConfig defines the rate limiting parameters.
type RateLimitConfig struct {
	// Rate is the number of allowed events in the period.
	Rate int

	// Burst is the maximum number of events that can occur at once.
	// Burst should be >= Rate for meaningful operation.
	Burst int

	// Period is the time window for the rate limit.
	Period time.Duration
}

// RateLimitResult contains the result of a rate limit check.
type RateLimitResult struct {
	// Allowed indicates whether the request is allowed.
	Allowed bool

	// Remaining is the number of remaining requests in the current window.
	Remaining int

	// RetryAfter is the duration until the next request will be allowed.
	// Only meaningful when Allowed is false.
	RetryAfter time.Duration

	// ResetAfter is the duration until the rate limit resets.
	ResetAfter time.Duration
}

// KeyType identifies the type of rate limit key.
type KeyType string

const (
	// KeyTypeIP is for IP-based rate limiting.
	KeyTypeIP KeyType = "ip"

	// KeyTypeUser is for user/API key-based rate limiting.
	KeyTypeUser KeyType = "user"
)

// keyPrefix is the base prefix for all rate limit keys.
const keyPrefix = "ratelimit"

// FormatKey returns a structured rate limit key.
// Format: "ratelimit:{type}:{value}"
// Examples:
//   - FormatKey(KeyTypeIP, "192.168.1.1") -> "ratelimit:ip:192.168.1.1"
//   - FormatKey(KeyTypeUser, "user-123") -> "ratelimit:user:user-123"
func FormatKey(keyType KeyType, value string) string {
	return fmt.Sprintf("%s:%s:%s", keyPrefix, keyType, value)
}
