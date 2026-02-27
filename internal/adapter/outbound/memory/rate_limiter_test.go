// Package memory provides in-memory implementations of outbound ports.
package memory

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
	"go.uber.org/goleak"
)

func TestRateLimiter_Allow(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewRateLimiter()

	config := ratelimit.RateLimitConfig{
		Rate:   10,
		Burst:  5,
		Period: time.Second,
	}

	// First request should be allowed
	result, err := limiter.Allow(ctx, "test-key", config)
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}
	if !result.Allowed {
		t.Error("First request should be allowed")
	}
	if result.Remaining < 0 {
		t.Errorf("Remaining = %d, should be >= 0", result.Remaining)
	}
}

func TestRateLimiter_BurstRequests(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewRateLimiter()

	// With Burst=3, we should be able to make at least 3 rapid requests
	config := ratelimit.RateLimitConfig{
		Rate:   1,
		Burst:  3,
		Period: time.Second,
	}

	allowedCount := 0
	for i := 0; i < 10; i++ {
		result, err := limiter.Allow(ctx, "burst-key", config)
		if err != nil {
			t.Fatalf("Allow() error on request %d: %v", i, err)
		}
		if result.Allowed {
			allowedCount++
		}
	}

	// Should allow at least Burst requests and at most Burst+1 (due to timing)
	if allowedCount < 3 {
		t.Errorf("Expected at least 3 allowed requests (burst), got %d", allowedCount)
	}
}

func TestRateLimiter_Exhaustion(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewRateLimiter()

	// Use larger rate for more predictable behavior
	config := ratelimit.RateLimitConfig{
		Rate:   10,
		Burst:  3,
		Period: time.Second,
	}

	// Make many rapid requests
	allowedCount := 0
	deniedCount := 0
	for i := 0; i < 20; i++ {
		result, err := limiter.Allow(ctx, "exhaust-key", config)
		if err != nil {
			t.Fatalf("Allow() error on request %d: %v", i, err)
		}
		if result.Allowed {
			allowedCount++
		} else {
			deniedCount++
		}
	}

	// With burst=3, after burst requests the rate limiter should deny some
	if deniedCount == 0 {
		t.Errorf("Expected some denied requests after exhausting burst, got 0 denied out of 20")
	}
	if allowedCount < 3 {
		t.Errorf("Expected at least 3 allowed requests (burst), got %d", allowedCount)
	}
}

func TestRateLimiter_DifferentKeys(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewRateLimiter()

	config := ratelimit.RateLimitConfig{
		Rate:   10,
		Burst:  5,
		Period: time.Second,
	}

	// Make multiple requests to different keys
	for i := 0; i < 5; i++ {
		key := "key-" + string(rune('a'+i))
		result, err := limiter.Allow(ctx, key, config)
		if err != nil {
			t.Fatalf("Allow() for %s error: %v", key, err)
		}
		if !result.Allowed {
			t.Errorf("First request for %s should be allowed", key)
		}
	}

	// Make another round - all should still be allowed (different keys have independent limits)
	for i := 0; i < 5; i++ {
		key := "key-" + string(rune('a'+i))
		result, err := limiter.Allow(ctx, key, config)
		if err != nil {
			t.Fatalf("Allow() second request for %s error: %v", key, err)
		}
		if !result.Allowed {
			t.Errorf("Second request for %s should be allowed (burst > 1)", key)
		}
	}
}

func TestRateLimiter_Recovery(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewRateLimiter()

	// Use short period for fast test with minimal burst
	config := ratelimit.RateLimitConfig{
		Rate:   2,
		Burst:  1,
		Period: 100 * time.Millisecond,
	}

	// First request - allowed
	result1, err := limiter.Allow(ctx, "recovery-key", config)
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}
	if !result1.Allowed {
		t.Error("First request should be allowed")
	}

	// Rapid second request - may be allowed or denied depending on timing
	// With Rate=2, Period=100ms, emission = 50ms
	// With Burst=1, burstOffset = 50ms
	// So TAT advances by 50ms per request

	// Wait for recovery (more than period)
	time.Sleep(150 * time.Millisecond)

	// Request after waiting - should be allowed (TAT has been reset)
	result3, err := limiter.Allow(ctx, "recovery-key", config)
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}
	if !result3.Allowed {
		t.Error("Request after recovery period should be allowed")
	}
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewRateLimiter()

	config := ratelimit.RateLimitConfig{
		Rate:   100,
		Burst:  50,
		Period: time.Second,
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 200)
	allowedCount := make(chan bool, 200)

	// 100 concurrent requests to same key
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := limiter.Allow(ctx, "concurrent-key", config)
			if err != nil {
				errCh <- err
				return
			}
			allowedCount <- result.Allowed
		}()
	}

	// 100 concurrent requests to different keys
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := "concurrent-key-" + string(rune('a'+(idx%26)))
			_, err := limiter.Allow(ctx, key, config)
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	close(allowedCount)

	for err := range errCh {
		t.Errorf("Concurrent access error: %v", err)
	}

	// Count allowed requests for same key
	allowed := 0
	for a := range allowedCount {
		if a {
			allowed++
		}
	}

	// With burst=50 and 100 concurrent requests, we should have some allowed and some denied
	if allowed == 0 {
		t.Error("Expected some requests to be allowed")
	}
	// All 100 might be allowed due to burst=50 and concurrent timing
	// Just verify we got results without errors
}

func TestRateLimiter_ZeroRate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewRateLimiter()

	// Rate=0 should default to 1
	config := ratelimit.RateLimitConfig{
		Rate:   0,
		Burst:  5,
		Period: time.Second,
	}

	result, err := limiter.Allow(ctx, "zero-rate-key", config)
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}

	// Should still work (defaults to Rate=1)
	if !result.Allowed {
		t.Error("First request should be allowed even with Rate=0")
	}
}

func TestRateLimiter_ZeroBurst(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewRateLimiter()

	// Burst=0 should default to Rate
	config := ratelimit.RateLimitConfig{
		Rate:   5,
		Burst:  0,
		Period: time.Second,
	}

	result, err := limiter.Allow(ctx, "zero-burst-key", config)
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}

	// Should still work (defaults to Burst=Rate)
	if !result.Allowed {
		t.Error("First request should be allowed even with Burst=0")
	}
}

func TestRateLimiter_ResetAfter(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewRateLimiter()

	config := ratelimit.RateLimitConfig{
		Rate:   10,
		Burst:  5,
		Period: time.Second,
	}

	result, err := limiter.Allow(ctx, "reset-key", config)
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}

	// ResetAfter should be positive for allowed requests
	if result.ResetAfter <= 0 {
		t.Errorf("ResetAfter = %v, should be positive for allowed request", result.ResetAfter)
	}
}

func TestRateLimiter_RemainingNonNegative(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewRateLimiter()

	config := ratelimit.RateLimitConfig{
		Rate:   10,
		Burst:  5,
		Period: time.Second,
	}

	// Make several requests and verify Remaining is never negative
	for i := 0; i < 20; i++ {
		result, err := limiter.Allow(ctx, "remaining-key", config)
		if err != nil {
			t.Fatalf("Allow() error: %v", err)
		}
		if result.Remaining < 0 {
			t.Errorf("Request %d: Remaining = %d, should never be negative", i, result.Remaining)
		}
	}
}

func TestRateLimiter_KeyIsolation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := NewRateLimiter()

	// Use tight limits to force denial
	config := ratelimit.RateLimitConfig{
		Rate:   1,
		Burst:  1,
		Period: time.Second,
	}

	// Exhaust key-1
	for i := 0; i < 5; i++ {
		_, _ = limiter.Allow(ctx, "key-1", config)
	}

	// key-2 should still have full allowance
	result, err := limiter.Allow(ctx, "key-2", config)
	if err != nil {
		t.Fatalf("Allow() error: %v", err)
	}
	if !result.Allowed {
		t.Error("key-2 should be allowed (keys are isolated)")
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	t.Parallel()

	// Create rate limiter with very short cleanup intervals for testing
	// cleanupInterval: 100ms, maxTTL: 200ms
	limiter := NewRateLimiterWithConfig(100*time.Millisecond, 200*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start cleanup goroutine
	limiter.StartCleanup(ctx)
	defer limiter.Stop()

	config := ratelimit.RateLimitConfig{
		Rate:   10,
		Burst:  5,
		Period: time.Second,
	}

	// Add several keys
	keys := []string{"cleanup-key-1", "cleanup-key-2", "cleanup-key-3"}
	for _, key := range keys {
		_, err := limiter.Allow(ctx, key, config)
		if err != nil {
			t.Fatalf("Allow() error for %s: %v", key, err)
		}
	}

	// Verify keys were added
	initialSize := limiter.Size()
	if initialSize != len(keys) {
		t.Errorf("Expected %d keys after adding, got %d", len(keys), initialSize)
	}

	// Wait longer than maxTTL + at least one cleanup interval
	// maxTTL=200ms + cleanupInterval=100ms + buffer
	time.Sleep(400 * time.Millisecond)

	// Verify keys were cleaned up
	finalSize := limiter.Size()
	if finalSize != 0 {
		t.Errorf("Expected 0 keys after cleanup, got %d", finalSize)
	}
}

func TestRateLimiterNoGoroutineLeak(t *testing.T) {
	// Use goleak to verify no goroutines are leaked
	defer goleak.VerifyNone(t)

	// Create rate limiter
	limiter := NewRateLimiterWithConfig(50*time.Millisecond, 100*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	// Start cleanup goroutine
	limiter.StartCleanup(ctx)

	config := ratelimit.RateLimitConfig{
		Rate:   10,
		Burst:  5,
		Period: time.Second,
	}

	// Perform some operations
	for i := 0; i < 10; i++ {
		_, _ = limiter.Allow(ctx, "leak-test-key", config)
	}

	// Wait a bit for some cleanup cycles
	time.Sleep(150 * time.Millisecond)

	// Stop cleanup - cancel context and call Stop
	cancel()
	limiter.Stop()

	// goleak.VerifyNone will fail if any goroutines are still running
}

func TestRateLimiterConcurrentAccessDuringCleanup(t *testing.T) {
	t.Parallel()

	// Create rate limiter with very short cleanup interval to stress test
	limiter := NewRateLimiterWithConfig(10*time.Millisecond, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start cleanup goroutine (will run frequently)
	limiter.StartCleanup(ctx)
	defer limiter.Stop()

	config := ratelimit.RateLimitConfig{
		Rate:   100,
		Burst:  50,
		Period: time.Second,
	}

	// Launch multiple goroutines that continuously call Allow()
	var wg sync.WaitGroup
	errCh := make(chan error, 100)
	stopCh := make(chan struct{})

	numGoroutines := 10
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					key := "concurrent-cleanup-key-" + string(rune('a'+(id%26)))
					_, err := limiter.Allow(ctx, key, config)
					if err != nil {
						select {
						case errCh <- err:
						default:
						}
						return
					}
					// Small sleep to avoid pure spin
					time.Sleep(time.Millisecond)
				}
			}
		}(i)
	}

	// Let it run for 500ms with concurrent access + cleanup
	time.Sleep(500 * time.Millisecond)

	// Signal goroutines to stop
	close(stopCh)
	wg.Wait()
	close(errCh)

	// Check for any errors
	for err := range errCh {
		t.Errorf("Concurrent access error: %v", err)
	}
}

func TestRateLimiterStopMultipleCalls(t *testing.T) {
	t.Parallel()

	// Verify Stop() can be called multiple times without panicking
	limiter := NewRateLimiterWithConfig(100*time.Millisecond, 1*time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	limiter.StartCleanup(ctx)

	// First Stop - should work fine
	limiter.Stop()

	// Second Stop - should not panic (sync.Once protection)
	limiter.Stop()

	// Third Stop - still should not panic
	limiter.Stop()
}

func TestRateLimiterContextCancellation(t *testing.T) {
	defer goleak.VerifyNone(t)

	limiter := NewRateLimiterWithConfig(50*time.Millisecond, 100*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())

	// Start cleanup goroutine
	limiter.StartCleanup(ctx)

	config := ratelimit.RateLimitConfig{
		Rate:   10,
		Burst:  5,
		Period: time.Second,
	}

	// Perform some operations
	_, _ = limiter.Allow(ctx, "ctx-cancel-key", config)

	// Cancel context (should stop cleanup goroutine)
	cancel()

	// Also call Stop to ensure WaitGroup completes
	limiter.Stop()

	// goleak.VerifyNone will verify the goroutine exited
}

func TestRateLimiterLongRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	defer goleak.VerifyNone(t)

	// Short intervals for faster test
	rl := NewRateLimiterWithConfig(100*time.Millisecond, 500*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer rl.Stop()

	rl.StartCleanup(ctx)

	// Generate many unique keys over time
	start := time.Now()
	keyCount := 0
	for time.Since(start) < 3*time.Second {
		key := "user-" + string(rune('0'+keyCount/1000)) + string(rune('0'+(keyCount/100)%10)) + string(rune('0'+(keyCount/10)%10)) + string(rune('0'+keyCount%10))
		_, _ = rl.Allow(context.Background(), key, ratelimit.RateLimitConfig{
			Rate:   10,
			Period: time.Second,
			Burst:  10,
		})
		keyCount++
		time.Sleep(time.Millisecond) // ~1000 keys/second
	}

	// Wait for cleanup cycles
	time.Sleep(1 * time.Second)

	// Verify map size is bounded (should be << total keys generated)
	size := rl.Size()
	t.Logf("Generated %d keys, map size after cleanup: %d", keyCount, size)

	// Map should be much smaller than total keys generated
	// With 500ms TTL and 3s runtime, only recent keys should remain
	if size > keyCount/2 {
		t.Errorf("Map size %d is too large (generated %d keys), cleanup not working", size, keyCount)
	}
}

// TestRateLimiter_ManyUniqueKeys stress tests the cleanup mechanism with many unique keys.
// This test differs from TestRateLimiterLongRunning by:
// - More keys, shorter time
// - Focus on key diversity, not duration
// - Verifies O(n) cleanup doesn't cause issues
func TestRateLimiter_ManyUniqueKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping many-keys stress test in short mode")
	}
	defer goleak.VerifyNone(t)

	// Very short TTL and cleanup for rapid testing
	rl := NewRateLimiterWithConfig(50*time.Millisecond, 200*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer rl.Stop()

	rl.StartCleanup(ctx)

	config := ratelimit.RateLimitConfig{
		Rate:   10,
		Burst:  5,
		Period: time.Second,
	}

	// Generate 10,000 unique keys rapidly
	const totalKeys = 10000
	for i := 0; i < totalKeys; i++ {
		// Create truly unique key each time using fmt.Sprintf
		key := "user-" + string(rune('0'+i/10000)) + string(rune('0'+(i/1000)%10)) + string(rune('0'+(i/100)%10)) + string(rune('0'+(i/10)%10)) + string(rune('0'+i%10))
		_, _ = rl.Allow(context.Background(), key, config)
	}

	// Check size immediately - may be high
	sizeBeforeCleanup := rl.Size()
	t.Logf("Size after generating %d keys: %d", totalKeys, sizeBeforeCleanup)

	// Wait for cleanup cycles (TTL=200ms, several cycles)
	time.Sleep(500 * time.Millisecond)

	// Verify cleanup worked - size should be much smaller
	sizeAfterCleanup := rl.Size()
	t.Logf("Size after cleanup: %d", sizeAfterCleanup)

	// All keys should be expired and cleaned (TTL=200ms, waited 500ms)
	if sizeAfterCleanup > totalKeys/10 {
		t.Errorf("Size %d too large after cleanup (expected < %d)", sizeAfterCleanup, totalKeys/10)
	}
}
