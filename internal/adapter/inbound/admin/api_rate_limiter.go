package admin

import (
	"fmt"
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
// L-7: Uses amortized cleanup (every 100 calls) instead of O(n) scan on every call.
type apiRateLimiter struct {
	mu           sync.Mutex
	entries      map[string]*apiRateLimitEntry
	maxRequests  int
	window       time.Duration
	callsSince   int // calls since last cleanup
}

const cleanupEveryNCalls = 100

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

	// L-7: Amortized cleanup — only scan expired entries every N calls.
	rl.callsSince++
	if rl.callsSince >= cleanupEveryNCalls {
		rl.callsSince = 0
		for k, e := range rl.entries {
			if now.After(e.resetAt) {
				delete(rl.entries, k)
			}
		}
		// L-41: Shrink map by rebuilding when mostly empty.
		if len(rl.entries) == 0 {
			rl.entries = make(map[string]*apiRateLimitEntry)
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
// M-15: All connections are rate limited, including localhost. Since the admin API
// only accepts localhost connections, exempting localhost would disable rate limiting
// entirely, allowing CPU exhaustion via compute-intensive operations (e.g. Argon2id).
// When rate limit is exceeded, responds with 429 Too Many Requests and a Retry-After header.
//
// Uses h.clientIP(r) for XFF-aware IP resolution so that when trusted proxies are
// configured, each real client gets its own rate-limit bucket (EDGE-02).
func (h *AdminAPIHandler) apiRateLimitMiddleware(maxRequests int, window time.Duration, next http.Handler) http.Handler {
	limiter := newAPIRateLimiter(maxRequests, window)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Resolve the effective client IP (XFF-aware when trusted proxies configured).
		ip := h.clientIP(r)

		allowed, retryAfter := limiter.allow(ip)
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
