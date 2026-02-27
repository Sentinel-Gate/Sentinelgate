package httpgw

import (
	"crypto/tls"
	"log/slog"
	"sync"
	"time"
)

// cacheEntry holds a cached TLS certificate and its expiration time.
type cacheEntry struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

// CertCache is a thread-safe per-domain TLS certificate cache.
// On cache miss it delegates to a CAManager to generate a new leaf cert.
// Entries expire after the configured TTL, at which point the next access
// triggers a fresh certificate generation.
//
// The RWMutex pattern follows the existing dns_resolver.go approach:
// read lock for fast-path cache hits, write lock only on cache miss.
type CertCache struct {
	mu     sync.RWMutex
	certs  map[string]*cacheEntry
	ca     *CAManager
	ttl    time.Duration
	logger *slog.Logger
}

// NewCertCache creates a new CertCache backed by the given CAManager.
// The ttl controls how long cached certificates remain valid before
// regeneration on the next access.
func NewCertCache(ca *CAManager, ttl time.Duration, logger *slog.Logger) *CertCache {
	return &CertCache{
		certs:  make(map[string]*cacheEntry),
		ca:     ca,
		ttl:    ttl,
		logger: logger,
	}
}

// GetCert returns a TLS certificate for the given domain.
// If the domain is cached and not expired, the cached cert is returned (fast path).
// Otherwise a new cert is generated via the CAManager and cached.
func (cc *CertCache) GetCert(domain string) (*tls.Certificate, error) {
	// Fast path: read lock
	cc.mu.RLock()
	entry, ok := cc.certs[domain]
	if ok && time.Now().Before(entry.expiresAt) {
		cc.mu.RUnlock()
		cc.logger.Debug("cert cache hit", "domain", domain)
		return entry.cert, nil
	}
	cc.mu.RUnlock()

	// Slow path: write lock for cache miss or expired entry
	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Double-check: another goroutine may have filled while we waited
	entry, ok = cc.certs[domain]
	if ok && time.Now().Before(entry.expiresAt) {
		cc.logger.Debug("cert cache hit (after lock upgrade)", "domain", domain)
		return entry.cert, nil
	}

	// Generate new cert
	cc.logger.Debug("cert cache miss, generating", "domain", domain)
	cert, err := cc.ca.GenerateCert(domain)
	if err != nil {
		return nil, err
	}

	cc.certs[domain] = &cacheEntry{
		cert:      cert,
		expiresAt: time.Now().Add(cc.ttl),
	}

	return cert, nil
}

// Size returns the current number of cached certificates.
func (cc *CertCache) Size() int {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return len(cc.certs)
}

// Clear removes all cached certificates. Useful for CA rotation.
func (cc *CertCache) Clear() {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.certs = make(map[string]*cacheEntry)
}
