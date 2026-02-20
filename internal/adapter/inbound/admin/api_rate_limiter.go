package admin

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// apiRateLimitEntry tracks request counts for a single IP address.
type apiRateLimitEntry struct {
	count   int
	resetAt time.Time
}

// apiRateLimiter provides per-IP rate limiting for admin API endpoints (SECU-09).
// It limits to maxRequests per window per IP to prevent scripted abuse.
type apiRateLimiter struct {
	mu          sync.Mutex
	entries     map[string]*apiRateLimitEntry
	maxRequests int
	window      time.Duration
}

// newAPIRateLimiter creates a rate limiter with the given limits.
func newAPIRateLimiter(maxRequests int, window time.Duration) *apiRateLimiter {
	return &apiRateLimiter{
		entries:     make(map[string]*apiRateLimitEntry),
		maxRequests: maxRequests,
		window:      window,
	}
}

// allow checks if the given IP is allowed to make another request.
// Returns (allowed, secondsUntilReset).
func (rl *apiRateLimiter) allow(ip string) (bool, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// Lazy cleanup: remove expired entries.
	for k, e := range rl.entries {
		if now.After(e.resetAt) {
			delete(rl.entries, k)
		}
	}

	entry, ok := rl.entries[ip]
	if !ok {
		rl.entries[ip] = &apiRateLimitEntry{
			count:   1,
			resetAt: now.Add(rl.window),
		}
		return true, 0
	}

	// If window has expired, reset.
	if now.After(entry.resetAt) {
		entry.count = 1
		entry.resetAt = now.Add(rl.window)
		return true, 0
	}

	// Within window, check limit.
	if entry.count >= rl.maxRequests {
		retryAfter := int(entry.resetAt.Sub(now).Seconds()) + 1
		if retryAfter < 1 {
			retryAfter = 1
		}
		return false, retryAfter
	}

	entry.count++
	return true, 0
}

// apiRateLimitMiddleware wraps an http.Handler with per-IP rate limiting (SECU-09).
// Requests from localhost are exempt (consistent with auth bypass for localhost).
// When rate limit is exceeded, responds with 429 Too Many Requests and a Retry-After header.
func apiRateLimitMiddleware(maxRequests int, window time.Duration, next http.Handler) http.Handler {
	limiter := newAPIRateLimiter(maxRequests, window)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exempt localhost from API rate limiting (consistent with auth bypass).
		if isLocalhost(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract client IP.
		clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			clientIP = r.RemoteAddr
		}

		allowed, retryAfter := limiter.allow(clientIP)
		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprintf(w, `{"error":"rate limit exceeded"}`)
			return
		}

		next.ServeHTTP(w, r)
	})
}
