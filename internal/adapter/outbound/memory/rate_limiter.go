// Package memory provides in-memory implementations of outbound ports.
package memory

import (
	"context"
	"hash/fnv"
	"log/slog"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
)

const numShards = 16

// rateLimiterShard holds a subset of rate limit keys with its own mutex.
// Sharding reduces lock contention: cleanup locks one shard at a time (1/16
// of keys) instead of blocking all requests (A7b).
type rateLimiterShard struct {
	mu    sync.Mutex
	cells map[string]time.Time // Theoretical Arrival Time per key
}

// MemoryRateLimiter implements ratelimit.RateLimiter using GCRA in memory.
// Thread-safe for concurrent access. Uses sharded maps to reduce lock contention
// during cleanup. Suitable for production single-process deployments.
type MemoryRateLimiter struct {
	shards          [numShards]rateLimiterShard
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
func NewRateLimiterWithConfig(cleanupInterval, maxTTL time.Duration) *MemoryRateLimiter {
	rl := &MemoryRateLimiter{
		stopChan:        make(chan struct{}),
		cleanupInterval: cleanupInterval,
		maxTTL:          maxTTL,
	}
	for i := range rl.shards {
		rl.shards[i].cells = make(map[string]time.Time)
	}
	return rl
}

// shard returns the shard for a given key using FNV-1a hash.
func (r *MemoryRateLimiter) shard(key string) *rateLimiterShard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return &r.shards[h.Sum32()%numShards]
}

// Allow checks if a request is allowed under the given rate limit config.
// Uses GCRA (Generic Cell Rate Algorithm) for smooth rate limiting.
func (r *MemoryRateLimiter) Allow(ctx context.Context, key string, config ratelimit.RateLimitConfig) (ratelimit.RateLimitResult, error) {
	s := r.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()

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
	tat, exists := s.cells[key]
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
	s.cells[key] = newTAT

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
// The goroutine periodically removes keys older than maxTTL,
// one shard at a time to minimize lock contention.
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

// cleanup removes keys older than maxTTL, one shard at a time.
// Each shard is locked independently so only 1/16 of keys are blocked at a time.
func (r *MemoryRateLimiter) cleanup() {
	now := time.Now()
	cutoff := now.Add(-r.maxTTL)
	totalCleaned := 0

	for i := range r.shards {
		s := &r.shards[i]
		s.mu.Lock()
		for key, tat := range s.cells {
			if tat.Before(cutoff) {
				delete(s.cells, key)
				totalCleaned++
			}
		}
		s.mu.Unlock()
	}

	if totalCleaned > 0 {
		slog.Debug("rate limiter cleanup completed",
			"cleaned_keys", totalCleaned,
			"remaining_keys", r.Size())
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

// Size returns the current number of tracked keys across all shards.
func (r *MemoryRateLimiter) Size() int {
	total := 0
	for i := range r.shards {
		s := &r.shards[i]
		s.mu.Lock()
		total += len(s.cells)
		s.mu.Unlock()
	}
	return total
}

// Compile-time interface verification.
var _ ratelimit.RateLimiter = (*MemoryRateLimiter)(nil)
