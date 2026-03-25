package service

import (
	"context"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/storage"
)

// HealthMetrics holds computed health metrics for a single agent.
type HealthMetrics struct {
	IdentityID     string    `json:"identity_id"`
	IdentityName   string    `json:"identity_name,omitempty"`
	TotalCalls     int64     `json:"total_calls"`
	DeniedCalls    int64     `json:"denied_calls"`
	ErrorCalls     int64     `json:"error_calls"`
	ViolationCount int64     `json:"violation_count"` // scan_blocked + policy denials
	DenyRate       float64   `json:"deny_rate"`       // 0.0 to 1.0
	ErrorRate      float64   `json:"error_rate"`      // 0.0 to 1.0
	DriftScore     float64   `json:"drift_score"`     // 0.0 to 1.0
	ComputedAt     time.Time `json:"computed_at"`
}

// HealthTrendPoint is a single data point for sparkline rendering.
type HealthTrendPoint struct {
	Date           string  `json:"date"` // YYYY-MM-DD
	DenyRate       float64 `json:"deny_rate"`
	DriftScore     float64 `json:"drift_score"`
	ErrorRate      float64 `json:"error_rate"`
	ViolationCount int64   `json:"violation_count"`
	CallVolume     int64   `json:"call_volume"`
}

// BaselineComparison compares current (7d) vs baseline (14d) metrics.
type BaselineComparison struct {
	Metric   string  `json:"metric"`
	Baseline float64 `json:"baseline"` // average over baseline window
	Current  float64 `json:"current"`  // average over current window
	Status   string  `json:"status"`   // "stable", "improved", "degraded"
}

// AgentHealthReport is the full health report for a single agent.
type AgentHealthReport struct {
	Identity    HealthMetrics        `json:"identity"`
	Trend       []HealthTrendPoint   `json:"trend"`       // 30-day sparkline data
	Comparisons []BaselineComparison `json:"comparisons"` // baseline vs current
	Status      string               `json:"status"`      // "healthy", "attention", "critical"
}

// HealthOverviewEntry is one row in the cross-agent health overview.
type HealthOverviewEntry struct {
	IdentityID   string  `json:"identity_id"`
	IdentityName string  `json:"identity_name"`
	DenyRate     float64 `json:"deny_rate"`
	DriftScore   float64 `json:"drift_score"`
	ErrorRate    float64 `json:"error_rate"`
	Violations   int64   `json:"violations"`
	TotalCalls   int64   `json:"total_calls"`
	Status       string  `json:"status"` // "healthy", "attention", "critical"
}

// HealthConfig holds configurable thresholds for health alerting.
type HealthConfig struct {
	DenyRateWarning    float64 `json:"deny_rate_warning"`    // default 0.10
	DenyRateCritical   float64 `json:"deny_rate_critical"`   // default 0.25
	DriftScoreWarning  float64 `json:"drift_score_warning"`  // default 0.30
	DriftScoreCritical float64 `json:"drift_score_critical"` // default 0.60
	ErrorRateWarning   float64 `json:"error_rate_warning"`   // default 0.05
	ErrorRateCritical  float64 `json:"error_rate_critical"`  // default 0.15
}

// DefaultHealthConfig returns sensible defaults.
func DefaultHealthConfig() HealthConfig {
	return HealthConfig{
		DenyRateWarning:    0.10,
		DenyRateCritical:   0.25,
		DriftScoreWarning:  0.30,
		DriftScoreCritical: 0.60,
		ErrorRateWarning:   0.05,
		ErrorRateCritical:  0.15,
	}
}

// HealthAuditReader provides audit records for health analysis.
type HealthAuditReader interface {
	Query(ctx context.Context, filter audit.AuditFilter) ([]audit.AuditRecord, string, error)
}

// healthCacheEntry bundles cached metrics with a per-entry timestamp,
// so that refreshing one identity's entry does not reset the TTL for others.
type healthCacheEntry struct {
	metrics  *HealthMetrics
	cachedAt time.Time
}

// healthInflight tracks an in-progress ComputeMetrics call so concurrent
// requests for the same identity coalesce instead of stampeding.
type healthInflight struct {
	done    chan struct{}
	metrics *HealthMetrics
	err     error
}

// maxHealthCacheSize is the upper bound on cached identity entries.
// When exceeded, expired entries are evicted; if still over, oldest entries are dropped.
const maxHealthCacheSize = 10000

// HealthService computes health metrics per agent from audit data.
type HealthService struct {
	mu           sync.RWMutex
	reader       HealthAuditReader
	driftService *DriftService
	tsStore      storage.TimeSeriesStore
	eventBus     event.Bus
	config       HealthConfig
	logger       *slog.Logger
	cache        map[string]healthCacheEntry
	cacheTTL     time.Duration
	inflight     map[string]*healthInflight // coalesces concurrent compute calls
	alertSentAt  map[string]time.Time       // identity_id+status -> last emit time (24h dedup)
}

// NewHealthService creates a health metrics service.
func NewHealthService(reader HealthAuditReader, logger *slog.Logger) *HealthService {
	return &HealthService{
		reader:      reader,
		config:      DefaultHealthConfig(),
		logger:      logger,
		cache:       make(map[string]healthCacheEntry),
		cacheTTL:    2 * time.Minute,
		inflight:    make(map[string]*healthInflight),
		alertSentAt: make(map[string]time.Time),
	}
}

// SetDriftService wires the drift service for drift score retrieval.
func (s *HealthService) SetDriftService(ds *DriftService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.driftService = ds
}

// SetTimeSeriesStore wires the time series store for trend data.
func (s *HealthService) SetTimeSeriesStore(ts storage.TimeSeriesStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tsStore = ts
}

// SetEventBus wires the event bus for health alerts.
func (s *HealthService) SetEventBus(bus event.Bus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventBus = bus
}

// SetConfig updates the health alerting thresholds.
func (s *HealthService) SetConfig(cfg HealthConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg
}

// ClearCache removes all cached health metrics, inflight requests,
// and alert dedup state. Used by factory reset.
func (s *HealthService) ClearCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = make(map[string]healthCacheEntry)
	s.inflight = make(map[string]*healthInflight)
	s.alertSentAt = make(map[string]time.Time)
}

// Config returns the current health config.
func (s *HealthService) Config() HealthConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// ComputeMetrics calculates health metrics for a single agent over a time window.
func (s *HealthService) ComputeMetrics(ctx context.Context, identityID string, window time.Duration) (*HealthMetrics, error) {
	now := time.Now()
	start := now.Add(-window)

	records, _, err := s.reader.Query(ctx, audit.AuditFilter{
		UserID:    identityID,
		StartTime: start,
		EndTime:   now,
		Limit:     10000,
	})
	if err != nil {
		return nil, err
	}

	metrics := &HealthMetrics{
		IdentityID: identityID,
		ComputedAt: now,
	}

	for _, r := range records {
		if metrics.IdentityName == "" && r.IdentityName != "" {
			metrics.IdentityName = r.IdentityName
		}
		metrics.TotalCalls++
		switch r.Decision {
		case "deny", "blocked":
			metrics.DeniedCalls++
			metrics.ViolationCount++
		case "error":
			metrics.ErrorCalls++
		}
		if r.ScanAction == "block" || r.ScanAction == "blocked" {
			metrics.ViolationCount++
		}
	}

	if metrics.TotalCalls > 0 {
		metrics.DenyRate = float64(metrics.DeniedCalls) / float64(metrics.TotalCalls)
		metrics.ErrorRate = float64(metrics.ErrorCalls) / float64(metrics.TotalCalls)
	}

	// Get drift score from drift service
	s.mu.RLock()
	ds := s.driftService
	s.mu.RUnlock()

	if ds != nil {
		report, driftErr := ds.DetectDrift(ctx, identityID)
		if driftErr == nil && report != nil {
			metrics.DriftScore = report.DriftScore
		}
	}

	return metrics, nil
}

// GetHealthReport returns the full health report for a single agent.
func (s *HealthService) GetHealthReport(ctx context.Context, identityID string) (*AgentHealthReport, error) {
	// Current metrics (last 24h)
	metrics, err := s.ComputeMetrics(ctx, identityID, 24*time.Hour)
	if err != nil {
		return nil, err
	}

	// 30-day trend
	trend, err := s.computeTrend(ctx, identityID, 30)
	if err != nil {
		s.logger.Warn("failed to compute health trend", "identity", identityID, "error", err)
		trend = []HealthTrendPoint{}
	}

	// Baseline comparison (14d baseline vs 7d current)
	comparisons, err := s.computeBaselineComparison(ctx, identityID)
	if err != nil {
		s.logger.Warn("failed to compute baseline comparison", "identity", identityID, "error", err)
		comparisons = []BaselineComparison{}
	}

	status := s.ClassifyStatus(metrics)

	// Emit alert if needed
	s.emitHealthAlert(ctx, metrics, status)

	return &AgentHealthReport{
		Identity:    *metrics,
		Trend:       trend,
		Comparisons: comparisons,
		Status:      status,
	}, nil
}

// GetHealthOverview returns health status for all agents with recent activity.
func (s *HealthService) GetHealthOverview(ctx context.Context) ([]HealthOverviewEntry, error) {
	// Find all identities with activity in the last 7 days
	now := time.Now()
	start := now.Add(-7 * 24 * time.Hour)

	records, _, err := s.reader.Query(ctx, audit.AuditFilter{
		StartTime: start,
		EndTime:   now,
		Limit:     50000,
	})
	if err != nil {
		return nil, err
	}

	// Aggregate per identity
	type identityAgg struct {
		total, denied, errors, violations int64
		name                              string
	}
	aggs := make(map[string]*identityAgg)
	for _, r := range records {
		id := r.IdentityID
		if id == "" {
			continue
		}
		a, ok := aggs[id]
		if !ok {
			name := r.IdentityName
			if name == "" {
				name = r.IdentityID
			}
			a = &identityAgg{name: name}
			aggs[id] = a
		}
		a.total++
		switch r.Decision {
		case "deny", "blocked":
			a.denied++
			a.violations++
		case "error":
			a.errors++
		}
		if r.ScanAction == "block" || r.ScanAction == "blocked" {
			a.violations++
		}
	}

	s.mu.RLock()
	ds := s.driftService
	s.mu.RUnlock()

	entries := make([]HealthOverviewEntry, 0, len(aggs))
	for id, a := range aggs {
		var denyRate, errorRate float64
		if a.total > 0 {
			denyRate = float64(a.denied) / float64(a.total)
			errorRate = float64(a.errors) / float64(a.total)
		}

		// Drift score
		var driftScore float64
		if ds != nil {
			report, driftErr := ds.DetectDrift(ctx, id)
			if driftErr == nil && report != nil {
				driftScore = report.DriftScore
			}
		}

		metrics := &HealthMetrics{
			DenyRate:   denyRate,
			ErrorRate:  errorRate,
			DriftScore: driftScore,
		}

		entries = append(entries, HealthOverviewEntry{
			IdentityID:   id,
			IdentityName: a.name,
			DenyRate:     denyRate,
			DriftScore:   driftScore,
			ErrorRate:    errorRate,
			Violations:   a.violations,
			TotalCalls:   a.total,
			Status:       s.ClassifyStatus(metrics),
		})
	}

	// Sort by status severity, then by deny rate
	statusOrder := map[string]int{"critical": 0, "attention": 1, "healthy": 2}
	sort.Slice(entries, func(i, j int) bool {
		oi, oj := statusOrder[entries[i].Status], statusOrder[entries[j].Status]
		if oi != oj {
			return oi < oj
		}
		return entries[i].DenyRate > entries[j].DenyRate
	})

	return entries, nil
}

// GetMetricsForCEL returns cached health metrics for policy evaluation.
// This is called on every policy evaluation, so it must be fast.
// Uses singleflight-style coalescing to prevent cache stampede when
// multiple goroutines miss the cache for the same identity simultaneously.
func (s *HealthService) GetMetricsForCEL(ctx context.Context, identityID string) *HealthMetrics {
	// Check cache — each entry has its own timestamp.
	s.mu.RLock()
	if entry, ok := s.cache[identityID]; ok && time.Since(entry.cachedAt) < s.cacheTTL {
		s.mu.RUnlock()
		return entry.metrics
	}
	s.mu.RUnlock()

	// Coalesce concurrent compute calls for the same identity.
	s.mu.Lock()
	// Double-check cache under write lock.
	if entry, ok := s.cache[identityID]; ok && time.Since(entry.cachedAt) < s.cacheTTL {
		s.mu.Unlock()
		return entry.metrics
	}
	if inf, ok := s.inflight[identityID]; ok {
		// Another goroutine is already computing; wait for it or ctx cancellation (M-37).
		s.mu.Unlock()
		select {
		case <-inf.done:
		case <-ctx.Done():
			return &HealthMetrics{IdentityID: identityID}
		}
		if inf.err != nil {
			return &HealthMetrics{IdentityID: identityID}
		}
		return inf.metrics
	}
	inf := &healthInflight{done: make(chan struct{})}
	s.inflight[identityID] = inf
	s.mu.Unlock()

	metrics, err := s.ComputeMetrics(ctx, identityID, 24*time.Hour)
	inf.metrics = metrics
	inf.err = err
	close(inf.done)

	s.mu.Lock()
	delete(s.inflight, identityID)
	if err == nil {
		s.cache[identityID] = healthCacheEntry{metrics: metrics, cachedAt: time.Now()}
		s.evictCacheLocked()
	}
	s.mu.Unlock()

	if err != nil {
		return &HealthMetrics{IdentityID: identityID}
	}
	return metrics
}

// evictCacheLocked removes expired entries when cache exceeds maxHealthCacheSize.
// Must be called with s.mu held for writing.
func (s *HealthService) evictCacheLocked() {
	if len(s.cache) <= maxHealthCacheSize {
		return
	}
	// First pass: remove expired entries.
	for id, entry := range s.cache {
		if time.Since(entry.cachedAt) >= s.cacheTTL {
			delete(s.cache, id)
		}
	}
	// If still over limit, drop oldest entries.
	for len(s.cache) > maxHealthCacheSize {
		var oldestID string
		var oldestTime time.Time
		for id, entry := range s.cache {
			if oldestID == "" || entry.cachedAt.Before(oldestTime) {
				oldestID = id
				oldestTime = entry.cachedAt
			}
		}
		delete(s.cache, oldestID)
	}
}

// computeTrend calculates daily health metrics for the last N days.
func (s *HealthService) computeTrend(ctx context.Context, identityID string, days int) ([]HealthTrendPoint, error) {
	now := time.Now()
	start := now.Add(-time.Duration(days) * 24 * time.Hour)

	records, _, err := s.reader.Query(ctx, audit.AuditFilter{
		UserID:    identityID,
		StartTime: start,
		EndTime:   now,
		Limit:     50000,
	})
	if err != nil {
		return nil, err
	}

	// Group records by date
	type dayAgg struct {
		total, denied, errors, violations int64
	}
	byDay := make(map[string]*dayAgg)

	for _, r := range records {
		day := r.Timestamp.Format("2006-01-02")
		d, ok := byDay[day]
		if !ok {
			d = &dayAgg{}
			byDay[day] = d
		}
		d.total++
		switch r.Decision {
		case "deny", "blocked":
			d.denied++
			d.violations++
		case "error":
			d.errors++
		}
		if r.ScanAction == "block" || r.ScanAction == "blocked" {
			d.violations++
		}
	}

	// Build trend points for each day
	points := make([]HealthTrendPoint, 0, days)
	for i := 0; i < days; i++ {
		date := now.Add(-time.Duration(days-1-i) * 24 * time.Hour).Format("2006-01-02")
		d := byDay[date]
		pt := HealthTrendPoint{Date: date}
		if d != nil && d.total > 0 {
			pt.DenyRate = float64(d.denied) / float64(d.total)
			pt.ErrorRate = float64(d.errors) / float64(d.total)
			pt.ViolationCount = d.violations
			pt.CallVolume = d.total
		}
		points = append(points, pt)
	}

	return points, nil
}

// computeBaselineComparison compares baseline (14d) vs current (7d) windows.
func (s *HealthService) computeBaselineComparison(ctx context.Context, identityID string) ([]BaselineComparison, error) {
	now := time.Now()
	currentStart := now.Add(-7 * 24 * time.Hour)
	baselineStart := now.Add(-21 * 24 * time.Hour) // 14d baseline, ending where current starts

	// Query baseline window
	baselineRecs, _, err := s.reader.Query(ctx, audit.AuditFilter{
		UserID:    identityID,
		StartTime: baselineStart,
		EndTime:   currentStart,
		Limit:     50000,
	})
	if err != nil {
		return nil, err
	}

	// Query current window
	currentRecs, _, err := s.reader.Query(ctx, audit.AuditFilter{
		UserID:    identityID,
		StartTime: currentStart,
		EndTime:   now,
		Limit:     50000,
	})
	if err != nil {
		return nil, err
	}

	baselineMetrics := aggregateMetrics(baselineRecs)
	currentMetrics := aggregateMetrics(currentRecs)

	comparisons := []BaselineComparison{
		{
			Metric:   "deny_rate",
			Baseline: baselineMetrics.denyRate,
			Current:  currentMetrics.denyRate,
			Status:   compareStatus(baselineMetrics.denyRate, currentMetrics.denyRate, true),
		},
		{
			Metric:   "error_rate",
			Baseline: baselineMetrics.errorRate,
			Current:  currentMetrics.errorRate,
			Status:   compareStatus(baselineMetrics.errorRate, currentMetrics.errorRate, true),
		},
		{
			Metric:   "violation_count",
			Baseline: float64(baselineMetrics.violations) / 14.0, // per day
			Current:  float64(currentMetrics.violations) / 7.0,   // per day
			Status:   compareStatus(float64(baselineMetrics.violations)/14.0, float64(currentMetrics.violations)/7.0, true),
		},
		{
			Metric:   "call_volume",
			Baseline: float64(baselineMetrics.total) / 14.0, // per day
			Current:  float64(currentMetrics.total) / 7.0,   // per day
			Status:   "stable",                              // call volume changes are informational
		},
	}

	// Add drift score comparison if drift service is available
	s.mu.RLock()
	dsCmp := s.driftService
	s.mu.RUnlock()

	if dsCmp != nil {
		report, driftErr := dsCmp.DetectDrift(ctx, identityID)
		if driftErr == nil && report != nil {
			var baselineDrift float64
			if report.Baseline != nil {
				baselineDrift = report.Baseline.DenyRate // use as proxy
			}
			comparisons = append(comparisons, BaselineComparison{
				Metric:   "drift_score",
				Baseline: baselineDrift,
				Current:  report.DriftScore,
				Status:   compareStatus(baselineDrift, report.DriftScore, true),
			})
		}
	}

	return comparisons, nil
}

type metricsAgg struct {
	total, denied, errors, violations int64
	denyRate, errorRate               float64
}

func aggregateMetrics(records []audit.AuditRecord) metricsAgg {
	var m metricsAgg
	for _, r := range records {
		m.total++
		switch r.Decision {
		case "deny", "blocked":
			m.denied++
			m.violations++
		case "error":
			m.errors++
		}
		if r.ScanAction == "block" || r.ScanAction == "blocked" {
			m.violations++
		}
	}
	if m.total > 0 {
		m.denyRate = float64(m.denied) / float64(m.total)
		m.errorRate = float64(m.errors) / float64(m.total)
	}
	return m
}

// compareStatus determines if the metric improved, degraded, or stayed stable.
// lowerIsBetter=true means a decrease is an improvement.
func compareStatus(baseline, current float64, lowerIsBetter bool) string {
	if baseline == 0 && current == 0 {
		return "stable"
	}
	threshold := 0.1 // 10% relative change threshold
	if baseline == 0 {
		if current > 0 {
			if lowerIsBetter {
				return "degraded"
			}
			return "improved"
		}
		return "stable"
	}
	relChange := (current - baseline) / math.Max(math.Abs(baseline), 0.001)
	if math.Abs(relChange) < threshold {
		return "stable"
	}
	if lowerIsBetter {
		if relChange > 0 {
			return "degraded"
		}
		return "improved"
	}
	if relChange > 0 {
		return "improved"
	}
	return "degraded"
}

// ClassifyStatus determines overall health status from metrics.
func (s *HealthService) ClassifyStatus(m *HealthMetrics) string {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if m.DenyRate >= cfg.DenyRateCritical || m.DriftScore >= cfg.DriftScoreCritical || m.ErrorRate >= cfg.ErrorRateCritical {
		return "critical"
	}
	if m.DenyRate >= cfg.DenyRateWarning || m.DriftScore >= cfg.DriftScoreWarning || m.ErrorRate >= cfg.ErrorRateWarning {
		return "attention"
	}
	return "healthy"
}

// emitHealthAlert publishes a health alert event if the status warrants it.
// Deduplicates: same identity+status within 24 hours is suppressed.
func (s *HealthService) emitHealthAlert(ctx context.Context, m *HealthMetrics, status string) {
	s.mu.RLock()
	bus := s.eventBus
	s.mu.RUnlock()

	if bus == nil || status == "healthy" {
		return
	}

	// 24-hour dedup per identity+status
	dedupKey := m.IdentityID + ":" + status
	s.mu.Lock()
	if lastSent, ok := s.alertSentAt[dedupKey]; ok && time.Since(lastSent) < 24*time.Hour {
		s.mu.Unlock()
		return
	}
	s.alertSentAt[dedupKey] = time.Now()
	s.mu.Unlock()

	sev := event.SeverityWarning
	if status == "critical" {
		sev = event.SeverityCritical
	}

	bus.Publish(ctx, event.Event{
		Type:           "health.alert",
		Source:         "health-monitor",
		Severity:       sev,
		RequiresAction: status == "critical",
		Payload: map[string]interface{}{
			"identity_id":     m.IdentityID,
			"identity_name":   m.IdentityName,
			"status":          status,
			"deny_rate":       m.DenyRate,
			"drift_score":     m.DriftScore,
			"error_rate":      m.ErrorRate,
			"violation_count": m.ViolationCount,
		},
	})
}

// AcknowledgeAlert marks a health alert as acknowledged, suppressing
// duplicate notifications for 24 hours.
func (s *HealthService) AcknowledgeAlert(identityID, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertSentAt[identityID+":"+status] = time.Now()
}
