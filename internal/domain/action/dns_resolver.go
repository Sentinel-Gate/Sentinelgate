package action

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// ResolvedDest holds the result of a DNS resolution, including all resolved IPs
// and the pinned IP for a specific request.
type ResolvedDest struct {
	// Domain is the original domain that was resolved.
	Domain string
	// IPs contains all resolved IP addresses.
	IPs []string
	// PinnedIP is the first resolved IP, pinned for the request lifetime
	// to prevent DNS rebinding attacks.
	PinnedIP string
	// CachedAt is when this resolution was cached.
	CachedAt time.Time
	// TTL is how long this cache entry is valid.
	TTL time.Duration
}

// isExpired returns true if the cache entry has expired.
func (r *ResolvedDest) isExpired(now time.Time) bool {
	return now.After(r.CachedAt.Add(r.TTL))
}

// DNSResolver provides DNS resolution with per-request pinning and TTL-based caching.
// It prevents DNS rebinding attacks by pinning the first resolution result
// for the lifetime of a request.
type DNSResolver struct {
	cache       map[string]*ResolvedDest            // domain -> cached resolution
	requestPins map[string]map[string]*ResolvedDest // requestID -> domain -> pinned resolution
	mu          sync.RWMutex
	lookupFunc  func(host string) ([]string, error)
	defaultTTL  time.Duration
	logger      *slog.Logger
}

// DNSResolverOption configures a DNSResolver.
type DNSResolverOption func(*DNSResolver)

// WithLookupFunc sets a custom DNS lookup function (useful for testing).
func WithLookupFunc(fn func(host string) ([]string, error)) DNSResolverOption {
	return func(r *DNSResolver) {
		r.lookupFunc = fn
	}
}

// WithDefaultTTL sets the default cache TTL for resolved entries.
func WithDefaultTTL(ttl time.Duration) DNSResolverOption {
	return func(r *DNSResolver) {
		r.defaultTTL = ttl
	}
}

// NewDNSResolver creates a new DNS resolver with optional configuration.
func NewDNSResolver(logger *slog.Logger, opts ...DNSResolverOption) *DNSResolver {
	if logger == nil {
		logger = slog.Default()
	}

	r := &DNSResolver{
		cache:       make(map[string]*ResolvedDest),
		requestPins: make(map[string]map[string]*ResolvedDest),
		lookupFunc:  net.LookupHost,
		defaultTTL:  30 * time.Second,
		logger:      logger,
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Resolve resolves a domain to IPs with per-request pinning.
// For a given requestID+domain combination, it always returns the same PinnedIP,
// even if the underlying DNS record changes (rebinding protection).
func (r *DNSResolver) Resolve(ctx context.Context, domain string, requestID string) (*ResolvedDest, error) {
	if domain == "" {
		return nil, errors.New("dns: empty domain")
	}

	r.mu.RLock()
	// 1. Check request pins first (rebinding protection)
	if pins, ok := r.requestPins[requestID]; ok {
		if pinned, ok := pins[domain]; ok {
			r.mu.RUnlock()
			return pinned, nil
		}
	}

	// 2. Check global cache
	if cached, ok := r.cache[domain]; ok && !cached.isExpired(time.Now()) {
		r.mu.RUnlock()
		// Pin to this request
		r.PinForRequest(requestID, domain, cached)
		return cached, nil
	}
	r.mu.RUnlock()

	// 3. Perform fresh lookup
	ips, err := r.lookupFunc(domain)
	if err != nil {
		return nil, fmt.Errorf("dns: lookup %q failed: %w", domain, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("dns: lookup %q returned no results", domain)
	}

	resolved := &ResolvedDest{
		Domain:   domain,
		IPs:      ips,
		PinnedIP: ips[0],
		CachedAt: time.Now(),
		TTL:      r.defaultTTL,
	}

	r.mu.Lock()
	r.cache[domain] = resolved
	r.mu.Unlock()

	// Pin to this request
	r.PinForRequest(requestID, domain, resolved)

	r.logger.Debug("dns resolved",
		"domain", domain,
		"ips", ips,
		"pinned_ip", resolved.PinnedIP,
		"request_id", requestID,
	)

	return resolved, nil
}

// PinForRequest stores a resolution result pinned to a specific request.
func (r *DNSResolver) PinForRequest(requestID string, domain string, resolved *ResolvedDest) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.requestPins[requestID]; !ok {
		r.requestPins[requestID] = make(map[string]*ResolvedDest)
	}
	r.requestPins[requestID][domain] = resolved
}

// ReleaseRequest removes all pinned resolutions for a completed request.
// Should be called when request processing is done to free memory.
func (r *DNSResolver) ReleaseRequest(requestID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.requestPins, requestID)
}

// CleanExpired removes expired cache entries.
func (r *DNSResolver) CleanExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for domain, entry := range r.cache {
		if entry.isExpired(now) {
			delete(r.cache, domain)
		}
	}
}
