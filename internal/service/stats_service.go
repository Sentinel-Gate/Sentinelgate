// Package service contains application services.
package service

import (
	"log/slog"
	"sync"
	"sync/atomic"
)

// maxMapEntries is the upper bound on distinct keys tracked in protocol/framework maps
// to prevent unbounded memory growth from arbitrary input (L-22).
const maxMapEntries = 1000

// StatsService tracks runtime statistics using lock-free atomic counters.
// All counter operations are safe for concurrent access from multiple goroutines.
type StatsService struct {
	allowed     atomic.Int64
	denied      atomic.Int64
	blocked     atomic.Int64
	rateLimited atomic.Int64
	warned      atomic.Int64
	errors      atomic.Int64

	// Protocol and framework counters (mutex-protected maps).
	mu              sync.Mutex
	protocolCounts  map[string]int64
	frameworkCounts map[string]int64
	mapCapWarned    bool // log the cap warning only once
	logger          *slog.Logger
}

// NewStatsService creates a new StatsService with all counters initialized to zero.
func NewStatsService() *StatsService {
	return &StatsService{
		protocolCounts:  make(map[string]int64),
		frameworkCounts: make(map[string]int64),
		logger:          slog.Default(),
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

// RecordBlocked increments the blocked counter (quota enforcement denials).
func (s *StatsService) RecordBlocked() {
	s.blocked.Add(1)
}

// RecordRateLimited increments the rate-limited counter.
func (s *StatsService) RecordRateLimited() {
	s.rateLimited.Add(1)
}

// RecordWarned increments the warned counter (quota warnings).
func (s *StatsService) RecordWarned() {
	s.warned.Add(1)
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
	if _, exists := s.protocolCounts[protocol]; !exists && len(s.protocolCounts) >= maxMapEntries {
		if !s.mapCapWarned {
			s.mapCapWarned = true
			s.logger.Warn("stats: protocol map reached size cap, new protocols will not be tracked", "cap", maxMapEntries)
		}
		s.mu.Unlock()
		return
	}
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
	if _, exists := s.frameworkCounts[framework]; !exists && len(s.frameworkCounts) >= maxMapEntries {
		if !s.mapCapWarned {
			s.mapCapWarned = true
			s.logger.Warn("stats: framework map reached size cap, new frameworks will not be tracked", "cap", maxMapEntries)
		}
		s.mu.Unlock()
		return
	}
	s.frameworkCounts[framework]++
	s.mu.Unlock()
}

// Stats holds a snapshot of all counters at a point in time.
type Stats struct {
	Allowed         int64            `json:"allowed"`
	Denied          int64            `json:"denied"`
	Blocked         int64            `json:"blocked"`
	RateLimited     int64            `json:"rate_limited"`
	Warned          int64            `json:"warned"`
	Errors          int64            `json:"errors"`
	ProtocolCounts  map[string]int64 `json:"protocol_counts"`
	FrameworkCounts map[string]int64 `json:"framework_counts"`
}

// GetStats returns a consistent snapshot of all counters.
// Atomic counters are read while holding the mutex so that the snapshot
// is coherent with the map counters (M-35).
func (s *StatsService) GetStats() Stats {
	s.mu.Lock()
	allowed := s.allowed.Load()
	denied := s.denied.Load()
	blocked := s.blocked.Load()
	rateLimited := s.rateLimited.Load()
	warned := s.warned.Load()
	errors := s.errors.Load()
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
		Allowed:         allowed,
		Denied:          denied,
		Blocked:         blocked,
		RateLimited:     rateLimited,
		Warned:          warned,
		Errors:          errors,
		ProtocolCounts:  pc,
		FrameworkCounts: fc,
	}
}

// Reset sets all counters to zero.
// Atomic stores are performed under the mutex to keep them coherent
// with the map reset (L-50).
func (s *StatsService) Reset() {
	s.mu.Lock()
	s.allowed.Store(0)
	s.denied.Store(0)
	s.blocked.Store(0)
	s.rateLimited.Store(0)
	s.warned.Store(0)
	s.errors.Store(0)
	s.protocolCounts = make(map[string]int64)
	s.frameworkCounts = make(map[string]int64)
	s.mapCapWarned = false
	s.mu.Unlock()
}
