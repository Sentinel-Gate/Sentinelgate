// Package service contains application services.
package service

import (
	"sync"
	"sync/atomic"
)

// StatsService tracks runtime statistics using lock-free atomic counters.
// All counter operations are safe for concurrent access from multiple goroutines.
type StatsService struct {
	allowed     atomic.Int64
	denied      atomic.Int64
	rateLimited atomic.Int64
	errors      atomic.Int64

	// Protocol and framework counters (mutex-protected maps).
	mu              sync.Mutex
	protocolCounts  map[string]int64
	frameworkCounts map[string]int64
}

// NewStatsService creates a new StatsService with all counters initialized to zero.
func NewStatsService() *StatsService {
	return &StatsService{
		protocolCounts:  make(map[string]int64),
		frameworkCounts: make(map[string]int64),
	}
}

// RecordAllow increments the allowed counter.
func (s *StatsService) RecordAllow() {
	s.allowed.Add(1)
}

// RecordDeny increments the denied counter.
func (s *StatsService) RecordDeny() {
	s.denied.Add(1)
}

// RecordRateLimited increments the rate-limited counter.
func (s *StatsService) RecordRateLimited() {
	s.rateLimited.Add(1)
}

// RecordError increments the error counter.
func (s *StatsService) RecordError() {
	s.errors.Add(1)
}

// RecordProtocol increments the counter for the given protocol.
func (s *StatsService) RecordProtocol(protocol string) {
	if protocol == "" {
		return
	}
	s.mu.Lock()
	s.protocolCounts[protocol]++
	s.mu.Unlock()
}

// RecordFramework increments the counter for the given framework.
// Empty strings are skipped.
func (s *StatsService) RecordFramework(framework string) {
	if framework == "" {
		return
	}
	s.mu.Lock()
	s.frameworkCounts[framework]++
	s.mu.Unlock()
}

// Stats holds a snapshot of all counters at a point in time.
type Stats struct {
	Allowed         int64            `json:"allowed"`
	Denied          int64            `json:"denied"`
	RateLimited     int64            `json:"rate_limited"`
	Errors          int64            `json:"errors"`
	ProtocolCounts  map[string]int64 `json:"protocol_counts"`
	FrameworkCounts map[string]int64 `json:"framework_counts"`
}

// GetStats returns a snapshot of all counters.
// The snapshot is consistent per-counter but not atomically across all counters.
func (s *StatsService) GetStats() Stats {
	s.mu.Lock()
	pc := make(map[string]int64, len(s.protocolCounts))
	for k, v := range s.protocolCounts {
		pc[k] = v
	}
	fc := make(map[string]int64, len(s.frameworkCounts))
	for k, v := range s.frameworkCounts {
		fc[k] = v
	}
	s.mu.Unlock()

	return Stats{
		Allowed:         s.allowed.Load(),
		Denied:          s.denied.Load(),
		RateLimited:     s.rateLimited.Load(),
		Errors:          s.errors.Load(),
		ProtocolCounts:  pc,
		FrameworkCounts: fc,
	}
}

// Reset sets all counters to zero.
func (s *StatsService) Reset() {
	s.allowed.Store(0)
	s.denied.Store(0)
	s.rateLimited.Store(0)
	s.errors.Store(0)

	s.mu.Lock()
	s.protocolCounts = make(map[string]int64)
	s.frameworkCounts = make(map[string]int64)
	s.mu.Unlock()
}
