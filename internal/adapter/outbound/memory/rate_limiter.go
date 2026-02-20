// Package memory provides in-memory implementations of outbound ports.
package memory

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
)

// MemoryRateLimiter implements ratelimit.RateLimiter using GCRA in memory.
// Thread-safe for concurrent access. For development/testing only.
// Includes background cleanup to prevent unbounded memory growth.
type MemoryRateLimiter struct {
	cells           map[string]time.Time // Theoretical Arrival Time per key
	mu              sync.Mutex
	stopChan        chan struct{}
	wg              sync.WaitGroup
	once            sync.Once
	cleanupInterval time.Duration
	maxTTL          time.Duration
}

// NewRateLimiter creates a new in-memory rate limiter with default cleanup settings.
// Default cleanup interval: 5 minutes, default maxTTL: 1 hour.
func NewRateLimiter() *MemoryRateLimiter {
	return NewRateLimiterWithConfig(5*time.Minute, 1*time.Hour)
}

// NewRateLimiterWithConfig creates a new in-memory rate limiter with custom cleanup settings.
// cleanupInterval: how often to run cleanup (e.g., 5 minutes)
// maxTTL: maximum age of a key before removal (e.g., 1 hour)
func NewRateLimiterWithConfig(cleanupInterval, maxTTL time.Duration) *MemoryRateLimiter {
	return &MemoryRateLimiter{
		cells:           make(map[string]time.Time),
		stopChan:        make(chan struct{}),
		cleanupInterval: cleanupInterval,
		maxTTL:          maxTTL,
	}
}

// Allow checks if a request is allowed under the given rate limit config.
// Uses GCRA (Generic Cell Rate Algorithm) for smooth rate limiting.
func (r *MemoryRateLimiter) Allow(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Calculate emission interval (time between allowed requests)
	if config.Rate <= 0 {
		config.Rate = 1
	}
	emission := config.Period / time.Duration(config.Rate)

	// Burst offset allows burst number of requests at once
	if config.Burst <= 0 {
		config.Burst = config.Rate
	}
	burstOffset := time.Duration(config.Burst) * emission

	// Get or initialize TAT (Theoretical Arrival Time)
	tat, exists := r.cells[key]
	if !exists || tat.Before(now) {
		tat = now
	}

	// Calculate when this request would be allowed
	allowAt := tat.Add(-burstOffset)

	if now.Before(allowAt) {
		// Request not allowed yet
		return ratelimit.RateLimitResult{
			Allowed:    false,
			Remaining:  0,
			RetryAfter: allowAt.Sub(now),
			ResetAfter: tat.Sub(now),
		}, nil
	}

	// Allow request, advance TAT
	newTAT := tat.Add(emission)
	if newTAT.Before(now) {
		newTAT = now.Add(emission)
	}
	r.cells[key] = newTAT

	// Calculate remaining requests
	remaining := int((burstOffset - newTAT.Sub(now)) / emission)
	if remaining < 0 {
		remaining = 0
	}
	if remaining > config.Burst {
		remaining = config.Burst
	}

	return ratelimit.RateLimitResult{
		Allowed:    true,
		Remaining:  remaining,
		RetryAfter: 0,
		ResetAfter: newTAT.Sub(now),
	}, nil
}

// StartCleanup starts the background cleanup goroutine.
// The goroutine periodically removes keys older than maxTTL.
// It stops when ctx is cancelled or Stop() is called.
func (r *MemoryRateLimiter) StartCleanup(ctx context.Context) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(r.cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stopChan:
				return
			case <-ticker.C:
				r.cleanup()
			}
		}
	}()
}

// cleanup removes keys older than maxTTL from the rate limiter.
// This method acquires a write lock and should only be called
// by the background cleanup goroutine.
func (r *MemoryRateLimiter) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.maxTTL)
	cleaned := 0

	for key, tat := range r.cells {
		if tat.Before(cutoff) {
			delete(r.cells, key)
			cleaned++
		}
	}

	if cleaned > 0 {
		slog.Debug("rate limiter cleanup completed",
			"cleaned_keys", cleaned,
			"remaining_keys", len(r.cells))
	}
}

// Stop gracefully stops the cleanup goroutine and waits for it to exit.
// Safe to call multiple times.
func (r *MemoryRateLimiter) Stop() {
	r.once.Do(func() {
		close(r.stopChan)
	})
	r.wg.Wait()
}

// Size returns the current number of tracked keys.
// Useful for testing and monitoring memory usage.
func (r *MemoryRateLimiter) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cells)
}

// Compile-time interface verification.
var _ ratelimit.RateLimiter = (*MemoryRateLimiter)(nil)
