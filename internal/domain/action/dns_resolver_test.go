package action

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNS_FreshResolve(t *testing.T) {
	callCount := 0
	resolver := NewDNSResolver(slog.Default(),
		WithLookupFunc(func(host string) ([]string, error) {
			callCount++
			return []string{"1.2.3.4", "5.6.7.8"}, nil
		}),
	)

	result, err := resolver.Resolve(context.Background(), "example.com", "req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 lookup call, got %d", callCount)
	}
	if result.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", result.Domain, "example.com")
	}
	if result.PinnedIP != "1.2.3.4" {
		t.Errorf("PinnedIP = %q, want %q", result.PinnedIP, "1.2.3.4")
	}
	if len(result.IPs) != 2 {
		t.Errorf("IPs count = %d, want 2", len(result.IPs))
	}
}

func TestDNS_CachedResolve(t *testing.T) {
	callCount := 0
	resolver := NewDNSResolver(slog.Default(),
		WithLookupFunc(func(host string) ([]string, error) {
			callCount++
			return []string{"1.2.3.4"}, nil
		}),
		WithDefaultTTL(1*time.Minute),
	)

	// First call: lookup
	_, err := resolver.Resolve(context.Background(), "example.com", "req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 call after first resolve, got %d", callCount)
	}

	// Second call with different request ID but same domain: should use cache
	_, err = resolver.Resolve(context.Background(), "example.com", "req-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected no additional lookup (cached), got %d total calls", callCount)
	}
}

func TestDNS_RequestPinning(t *testing.T) {
	callCount := 0
	resolver := NewDNSResolver(slog.Default(),
		WithLookupFunc(func(host string) ([]string, error) {
			callCount++
			return []string{"1.2.3.4"}, nil
		}),
		WithDefaultTTL(1*time.Millisecond), // Very short TTL
	)

	// First resolve pins the result
	result1, err := resolver.Resolve(context.Background(), "example.com", "req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for cache to expire
	time.Sleep(5 * time.Millisecond)

	// Same request ID should still get pinned result, even if cache expired
	result2, err := resolver.Resolve(context.Background(), "example.com", "req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result2.PinnedIP != result1.PinnedIP {
		t.Errorf("pinned IP changed: %q vs %q", result1.PinnedIP, result2.PinnedIP)
	}
	// Should not have called lookup again because result is pinned
	if callCount != 1 {
		t.Errorf("expected 1 lookup call (pinned), got %d", callCount)
	}
}

func TestDNS_IndependentPins(t *testing.T) {
	callIdx := 0
	responses := [][]string{{"1.1.1.1"}, {"2.2.2.2"}}
	resolver := NewDNSResolver(slog.Default(),
		WithLookupFunc(func(host string) ([]string, error) {
			idx := callIdx
			callIdx++
			if idx < len(responses) {
				return responses[idx], nil
			}
			return []string{"9.9.9.9"}, nil
		}),
		WithDefaultTTL(1*time.Millisecond),
	)

	// Request 1 resolves
	r1, err := resolver.Resolve(context.Background(), "example.com", "req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for cache to expire
	time.Sleep(5 * time.Millisecond)

	// Request 2 resolves (cache expired, fresh lookup)
	r2, err := resolver.Resolve(context.Background(), "example.com", "req-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Different requests may get different IPs
	if r1.PinnedIP == r2.PinnedIP {
		t.Log("Note: both requests happened to get same IP (depends on timing)")
	}

	// But each keeps its own pin
	r1Again, _ := resolver.Resolve(context.Background(), "example.com", "req-1")
	if r1Again.PinnedIP != r1.PinnedIP {
		t.Errorf("req-1 pin changed: %q vs %q", r1.PinnedIP, r1Again.PinnedIP)
	}
	r2Again, _ := resolver.Resolve(context.Background(), "example.com", "req-2")
	if r2Again.PinnedIP != r2.PinnedIP {
		t.Errorf("req-2 pin changed: %q vs %q", r2.PinnedIP, r2Again.PinnedIP)
	}
}

func TestDNS_TTLExpiry(t *testing.T) {
	callCount := 0
	resolver := NewDNSResolver(slog.Default(),
		WithLookupFunc(func(host string) ([]string, error) {
			callCount++
			return []string{"1.2.3.4"}, nil
		}),
		WithDefaultTTL(1*time.Millisecond),
	)

	// First resolve
	_, err := resolver.Resolve(context.Background(), "example.com", "req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(5 * time.Millisecond)

	// New request should trigger fresh lookup (cache expired)
	_, err = resolver.Resolve(context.Background(), "example.com", "req-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if callCount != 2 {
		t.Errorf("expected 2 lookup calls (TTL expired), got %d", callCount)
	}
}

func TestDNS_ReleaseRequest(t *testing.T) {
	resolver := NewDNSResolver(slog.Default(),
		WithLookupFunc(func(host string) ([]string, error) {
			return []string{"1.2.3.4"}, nil
		}),
	)

	_, err := resolver.Resolve(context.Background(), "example.com", "req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify pin exists
	resolver.mu.RLock()
	_, hasPins := resolver.requestPins["req-1"]
	resolver.mu.RUnlock()
	if !hasPins {
		t.Fatal("expected pins for req-1")
	}

	// Release the request
	resolver.ReleaseRequest("req-1")

	// Verify pin is gone
	resolver.mu.RLock()
	_, hasPins = resolver.requestPins["req-1"]
	resolver.mu.RUnlock()
	if hasPins {
		t.Error("expected no pins for req-1 after release")
	}
}

func TestDNS_CleanExpired(t *testing.T) {
	resolver := NewDNSResolver(slog.Default(),
		WithLookupFunc(func(host string) ([]string, error) {
			return []string{"1.2.3.4"}, nil
		}),
		WithDefaultTTL(1*time.Millisecond),
	)

	_, err := resolver.Resolve(context.Background(), "example.com", "req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify cache has entry
	resolver.mu.RLock()
	_, inCache := resolver.cache["example.com"]
	resolver.mu.RUnlock()
	if !inCache {
		t.Fatal("expected cache entry for example.com")
	}

	// Wait for TTL to expire
	time.Sleep(5 * time.Millisecond)

	// Clean expired entries
	resolver.CleanExpired()

	// Verify cache is empty
	resolver.mu.RLock()
	_, inCache = resolver.cache["example.com"]
	resolver.mu.RUnlock()
	if inCache {
		t.Error("expected cache entry to be cleaned after TTL expiry")
	}
}

func TestDNS_LookupFailure(t *testing.T) {
	resolver := NewDNSResolver(slog.Default(),
		WithLookupFunc(func(host string) ([]string, error) {
			return nil, errors.New("dns: NXDOMAIN")
		}),
	)

	_, err := resolver.Resolve(context.Background(), "nonexistent.example.com", "req-1")
	if err == nil {
		t.Fatal("expected error for failed lookup")
	}

	// Verify failed lookup is not cached
	resolver.mu.RLock()
	_, inCache := resolver.cache["nonexistent.example.com"]
	resolver.mu.RUnlock()
	if inCache {
		t.Error("failed lookup should not be cached")
	}
}

func TestDNS_EmptyDomain(t *testing.T) {
	resolver := NewDNSResolver(slog.Default())

	_, err := resolver.Resolve(context.Background(), "", "req-1")
	if err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestDNS_ConcurrentAccess(t *testing.T) {
	var lookupCount atomic.Int64
	resolver := NewDNSResolver(slog.Default(),
		WithLookupFunc(func(host string) ([]string, error) {
			lookupCount.Add(1)
			return []string{"1.2.3.4"}, nil
		}),
	)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			reqID := "req-concurrent"
			if idx%2 == 0 {
				reqID = "req-concurrent-alt"
			}
			_, err := resolver.Resolve(context.Background(), "example.com", reqID)
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent resolve error: %v", err)
	}

	// With caching, we should have far fewer than 50 lookups
	if lookupCount.Load() > 10 {
		t.Logf("note: %d lookups for %d goroutines (some races expected)", lookupCount.Load(), goroutines)
	}
}
