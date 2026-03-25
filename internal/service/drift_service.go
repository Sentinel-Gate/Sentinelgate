package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/storage"
)

// DriftProfile is a behavioral baseline for an identity over a time window.
type DriftProfile struct {
	IdentityID       string                        `json:"identity_id"`
	ToolDistribution map[string]float64            `json:"tool_distribution"`     // tool -> % of total
	ArgKeysByTool    map[string]map[string]float64 `json:"arg_keys_by_tool"`      // tool -> argKey -> frequency
	TotalCalls       int                           `json:"total_calls"`
	DenyRate         float64                       `json:"deny_rate"`
	ErrorRate        float64                       `json:"error_rate"`
	AvgLatencyUs     float64                       `json:"avg_latency_us"`
	HourlyPattern    [24]float64                   `json:"hourly_pattern"` // calls per hour (normalized)
	ComputedAt       time.Time                     `json:"computed_at"`
	WindowDays       int                           `json:"window_days"`
}

// DriftAnomaly represents a detected behavioral deviation.
type DriftAnomaly struct {
	Type        string  `json:"type"`        // tool_shift, deny_rate, error_rate, temporal, latency
	Severity    string  `json:"severity"`    // high, medium, low
	Description string  `json:"description"` // human-readable
	Baseline    float64 `json:"baseline"`
	Current     float64 `json:"current"`
	Deviation   float64 `json:"deviation"` // percentage change
	ToolName    string  `json:"tool_name,omitempty"`
}

// BehavioralDriftReport is the result of drift detection for a single identity.
type BehavioralDriftReport struct {
	IdentityID   string         `json:"identity_id"`
	IdentityName string         `json:"identity_name,omitempty"`
	DriftScore float64        `json:"drift_score"` // 0.0 = no drift, 1.0 = max drift
	Anomalies  []DriftAnomaly `json:"anomalies"`
	Baseline   *DriftProfile  `json:"baseline,omitempty"`
	Current    *DriftProfile  `json:"current,omitempty"`
	DetectedAt time.Time      `json:"detected_at"`
}

// DriftConfig holds tunable thresholds for drift detection.
type DriftConfig struct {
	BaselineWindowDays int     // how many days of history for the baseline (default 14)
	CurrentWindowDays  int     // how many days for current behavior (default 1)
	ToolShiftThreshold float64 // % change in tool distribution to flag (default 0.20 = 20%)
	DenyRateThreshold  float64 // absolute change in deny rate (default 0.10)
	ErrorRateThreshold float64 // absolute change in error rate (default 0.10)
	LatencyThreshold   float64 // % change in avg latency (default 0.50 = 50%)
	TemporalThreshold  float64 // KL divergence for hourly pattern (default 0.30)
	ArgShiftThreshold  float64 // % of new/missing arg keys to flag (default 0.30 = 30%)
	MinCallsBaseline   int     // minimum calls in baseline to enable detection (default 10)
}

// DefaultDriftConfig returns sensible defaults.
func DefaultDriftConfig() DriftConfig {
	return DriftConfig{
		BaselineWindowDays: 14,
		CurrentWindowDays:  1,
		ToolShiftThreshold: 0.20,
		DenyRateThreshold:  0.10,
		ErrorRateThreshold: 0.10,
		LatencyThreshold:   0.50,
		TemporalThreshold:  0.30,
		ArgShiftThreshold:  0.30,
		MinCallsBaseline:   10,
	}
}

// DriftAuditReader provides audit records for drift analysis.
type DriftAuditReader interface {
	Query(ctx context.Context, filter audit.AuditFilter) ([]audit.AuditRecord, string, error)
}

// maxDriftCacheSize is the maximum number of identity entries kept in the cache.
// When exceeded, all entries are evicted to prevent unbounded memory growth
// from inactive identities.
const maxDriftCacheSize = 1000

// driftCacheEntry bundles a cached report with its individual timestamp,
// so that refreshing one identity's entry does not reset the TTL for others.
type driftCacheEntry struct {
	report   *BehavioralDriftReport
	cachedAt time.Time
}

// DriftService detects behavioral drift by comparing agent behavior against baselines.
type DriftService struct {
	mu         sync.RWMutex
	reader     DriftAuditReader
	tsStore    storage.TimeSeriesStore
	config     DriftConfig
	eventBus   event.Bus
	logger     *slog.Logger
	// Cache of recent reports — each entry tracks its own timestamp.
	cache      map[string]driftCacheEntry
	cacheTTL   time.Duration
	// done is closed by Stop to signal the eviction goroutine to exit.
	done       chan struct{}
	stopped    bool
	wg         sync.WaitGroup
}

// NewDriftService creates a drift detection service.
// It starts a background goroutine that periodically evicts stale cache entries.
// Call Stop() to release the goroutine when the service is no longer needed.
func NewDriftService(reader DriftAuditReader, tsStore storage.TimeSeriesStore, logger *slog.Logger) *DriftService {
	s := &DriftService{
		reader:   reader,
		tsStore:  tsStore,
		config:   DefaultDriftConfig(),
		logger:   logger,
		cache:    make(map[string]driftCacheEntry),
		cacheTTL: 5 * time.Minute,
		done:     make(chan struct{}),
	}

	// Start periodic cache eviction goroutine.
	s.wg.Add(1)
	go s.evictionLoop()

	return s
}

// evictionLoop periodically calls EvictStaleCache to prevent unbounded cache growth.
func (s *DriftService) evictionLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.EvictStaleCache()
		case <-s.done:
			return
		}
	}
}

// Stop shuts down the background eviction goroutine and waits for it to exit.
// Safe to call multiple times. wg.Wait() is always called so that a second
// caller also blocks until the goroutine has fully exited (L-40).
func (s *DriftService) Stop() {
	s.mu.Lock()
	alreadyStopped := s.stopped
	if !alreadyStopped {
		s.stopped = true
		close(s.done)
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// EvictStaleCache removes individual cache entries that have exceeded the TTL,
// or evicts all entries if the cache exceeds the maximum size limit.
// This should be called periodically to prevent unbounded growth.
func (s *DriftService) EvictStaleCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) > maxDriftCacheSize {
		s.cache = make(map[string]driftCacheEntry)
		return
	}
	for id, entry := range s.cache {
		if time.Since(entry.cachedAt) > s.cacheTTL {
			delete(s.cache, id)
		}
	}
}

// ClearCache unconditionally removes all cached drift reports.
// Unlike EvictStaleCache (which only removes expired entries), this clears
// everything. Used by factory reset.
func (s *DriftService) ClearCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = make(map[string]driftCacheEntry)
}

// SetEventBus wires the event bus for drift event emission.
func (s *DriftService) SetEventBus(bus event.Bus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventBus = bus
}

// SetConfig updates the drift detection thresholds.
func (s *DriftService) SetConfig(cfg DriftConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg
}

// Config returns the current drift detection config.
func (s *DriftService) Config() DriftConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// BuildProfile computes a behavioral profile from audit records.
func (s *DriftService) BuildProfile(identityID string, records []audit.AuditRecord) *DriftProfile {
	if len(records) == 0 {
		return &DriftProfile{
			IdentityID:       identityID,
			ToolDistribution: map[string]float64{},
			ArgKeysByTool:    map[string]map[string]float64{},
			ComputedAt:       time.Now().UTC(),
		}
	}

	toolCounts := make(map[string]int)
	toolArgKeys := make(map[string]map[string]int) // tool -> argKey -> count
	var totalLatency int64
	var denyCount, errorCount int
	hourCounts := [24]int{}

	for _, r := range records {
		if r.ToolName != "" {
			toolCounts[r.ToolName]++
			// Track argument keys per tool
			if len(r.ToolArguments) > 0 {
				if toolArgKeys[r.ToolName] == nil {
					toolArgKeys[r.ToolName] = make(map[string]int)
				}
				for key := range r.ToolArguments {
					toolArgKeys[r.ToolName][key]++
				}
			}
		}
		switch r.Decision {
		case "deny", "blocked":
			denyCount++
		case "error":
			errorCount++
		}
		totalLatency += r.LatencyMicros
		hourCounts[r.Timestamp.UTC().Hour()]++ // L-27: Use UTC for consistent timezone
	}

	total := len(records)
	toolDist := make(map[string]float64, len(toolCounts))
	for name, count := range toolCounts {
		toolDist[name] = float64(count) / float64(total)
	}

	// Normalize hourly pattern
	var hourlyPattern [24]float64
	var maxHour float64
	for _, c := range hourCounts {
		if float64(c) > maxHour {
			maxHour = float64(c)
		}
	}
	if maxHour > 0 {
		for i, c := range hourCounts {
			hourlyPattern[i] = float64(c) / maxHour
		}
	}

	// Build arg key frequency per tool (normalized to 0-1 by tool call count)
	argKeysByTool := make(map[string]map[string]float64, len(toolArgKeys))
	for tool, keys := range toolArgKeys {
		tc := toolCounts[tool]
		if tc == 0 {
			continue
		}
		argKeysByTool[tool] = make(map[string]float64, len(keys))
		for key, count := range keys {
			argKeysByTool[tool][key] = float64(count) / float64(tc)
		}
	}

	return &DriftProfile{
		IdentityID:       identityID,
		ToolDistribution: toolDist,
		ArgKeysByTool:    argKeysByTool,
		TotalCalls:       total,
		DenyRate:         float64(denyCount) / float64(total),
		ErrorRate:        float64(errorCount) / float64(total),
		AvgLatencyUs:     float64(totalLatency) / float64(total),
		HourlyPattern:    hourlyPattern,
		ComputedAt:       time.Now().UTC(),
	}
}

// DetectDrift compares current behavior against baseline for an identity.
func (s *DriftService) DetectDrift(ctx context.Context, identityID string) (*BehavioralDriftReport, error) {
	s.mu.RLock()
	if s.stopped {
		s.mu.RUnlock()
		return nil, fmt.Errorf("drift service is stopped")
	}
	cfg := s.config
	s.mu.RUnlock()

	now := time.Now()
	baselineEnd := now.Add(-time.Duration(cfg.CurrentWindowDays) * 24 * time.Hour)
	baselineStart := baselineEnd.Add(-time.Duration(cfg.BaselineWindowDays) * 24 * time.Hour)
	currentStart := baselineEnd

	// Query baseline records
	baselineRecords, _, err := s.reader.Query(ctx, audit.AuditFilter{
		UserID:    identityID,
		StartTime: baselineStart,
		EndTime:   baselineEnd,
		Limit:     10000,
	})
	if err != nil {
		return nil, fmt.Errorf("query baseline: %w", err)
	}

	// Query current records
	currentRecords, _, err := s.reader.Query(ctx, audit.AuditFilter{
		UserID:    identityID,
		StartTime: currentStart,
		EndTime:   now,
		Limit:     10000,
	})
	if err != nil {
		return nil, fmt.Errorf("query current: %w", err)
	}

	baseline := s.BuildProfile(identityID, baselineRecords)
	baseline.WindowDays = cfg.BaselineWindowDays
	current := s.BuildProfile(identityID, currentRecords)
	current.WindowDays = cfg.CurrentWindowDays

	// Resolve identity name from most recent records
	var identityName string
	for _, r := range currentRecords {
		if r.IdentityName != "" {
			identityName = r.IdentityName
			break
		}
	}

	report := &BehavioralDriftReport{
		IdentityID:   identityID,
		IdentityName: identityName,
		Baseline:     baseline,
		Current:      current,
		DetectedAt:   now,
	}

	// Need minimum calls in baseline
	if baseline.TotalCalls < cfg.MinCallsBaseline {
		return report, nil
	}

	// Detect anomalies
	var anomalies []DriftAnomaly

	// 1. Tool distribution shift
	toolAnomalies := s.detectToolShift(baseline, current, cfg.ToolShiftThreshold)
	anomalies = append(anomalies, toolAnomalies...)

	// 2. Deny rate change
	if denyAnomaly := s.detectRateChange("deny_rate", baseline.DenyRate, current.DenyRate, cfg.DenyRateThreshold); denyAnomaly != nil {
		anomalies = append(anomalies, *denyAnomaly)
	}

	// 3. Error rate change
	if errAnomaly := s.detectRateChange("error_rate", baseline.ErrorRate, current.ErrorRate, cfg.ErrorRateThreshold); errAnomaly != nil {
		anomalies = append(anomalies, *errAnomaly)
	}

	// 4. Latency change
	if baseline.AvgLatencyUs > 0 && current.TotalCalls > 0 {
		latencyChange := (current.AvgLatencyUs - baseline.AvgLatencyUs) / baseline.AvgLatencyUs
		if math.Abs(latencyChange) > cfg.LatencyThreshold {
			sev := "medium"
			if math.Abs(latencyChange) > cfg.LatencyThreshold*2 {
				sev = "high"
			}
			anomalies = append(anomalies, DriftAnomaly{
				Type:        "latency",
				Severity:    sev,
				Description: fmt.Sprintf("Average latency changed by %.0f%%", latencyChange*100),
				Baseline:    baseline.AvgLatencyUs,
				Current:     current.AvgLatencyUs,
				Deviation:   latencyChange * 100,
			})
		}
	}

	// 5. Argument pattern shift
	argAnomalies := s.detectArgShift(baseline, current, cfg.ArgShiftThreshold)
	anomalies = append(anomalies, argAnomalies...)

	// 6. Temporal pattern shift (KL divergence)
	if current.TotalCalls >= 5 {
		kl := klDivergence(baseline.HourlyPattern[:], current.HourlyPattern[:])
		if kl > cfg.TemporalThreshold {
			sev := "low"
			if kl > cfg.TemporalThreshold*2 {
				sev = "medium"
			}
			if kl > cfg.TemporalThreshold*4 {
				sev = "high"
			}
			anomalies = append(anomalies, DriftAnomaly{
				Type:        "temporal",
				Severity:    sev,
				Description: fmt.Sprintf("Activity pattern divergence: %.2f", kl),
				Baseline:    0,
				Current:     kl,
				Deviation:   kl,
			})
		}
	}

	report.Anomalies = anomalies
	report.DriftScore = computeDriftScore(anomalies)

	// Store baseline snapshot in time series
	if s.tsStore != nil {
		s.storeProfileSnapshot(ctx, identityID, baseline)
	}

	// Emit events for significant anomalies
	s.emitAnomalyEvents(ctx, report)

	// Cache the report with its own per-entry timestamp for accurate TTL eviction.
	s.mu.Lock()
	s.cache[identityID] = driftCacheEntry{report: report, cachedAt: time.Now()}
	s.mu.Unlock()

	return report, nil
}

// DetectAll runs drift detection for all identities with recent activity.
func (s *DriftService) DetectAll(ctx context.Context) ([]BehavioralDriftReport, error) {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	// Get all identities with activity in the current window
	now := time.Now()
	currentStart := now.Add(-time.Duration(cfg.CurrentWindowDays) * 24 * time.Hour)
	records, _, err := s.reader.Query(ctx, audit.AuditFilter{
		StartTime: currentStart,
		EndTime:   now,
		Limit:     10000,
	})
	if err != nil {
		return nil, fmt.Errorf("query recent activity: %w", err)
	}

	// Collect unique identity IDs
	identities := make(map[string]bool)
	for _, r := range records {
		if r.IdentityID != "" {
			identities[r.IdentityID] = true
		}
	}

	var reports []BehavioralDriftReport
	for id := range identities {
		report, detectErr := s.DetectDrift(ctx, id)
		if detectErr != nil {
			s.logger.Warn("drift detection failed for identity", "identity", id, "error", detectErr)
			continue
		}
		if report != nil {
			reports = append(reports, *report)
		}
	}

	// Sort by drift score descending
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].DriftScore > reports[j].DriftScore
	})

	return reports, nil
}

// ResetBaseline clears the stored baseline for an identity.
func (s *DriftService) ResetBaseline(ctx context.Context, identityID string) error {
	if s.tsStore == nil {
		return nil
	}
	series := "drift:profile:" + identityID
	if _, err := s.tsStore.DeleteSeries(ctx, series); err != nil {
		return fmt.Errorf("delete drift series for %s: %w", identityID, err)
	}

	s.mu.Lock()
	// Resolve name from cached report before clearing
	var identityName string
	if cached, ok := s.cache[identityID]; ok && cached.report != nil {
		identityName = cached.report.IdentityName
	}
	delete(s.cache, identityID)
	bus := s.eventBus
	s.mu.Unlock()

	if bus != nil {
		bus.Publish(ctx, event.Event{
			Type:     "drift.baseline_reset",
			Source:   "drift-detector",
			Severity: event.SeverityInfo,
			Payload: map[string]interface{}{
				"identity_id":   identityID,
				"identity_name": identityName,
			},
		})
	}
	return nil
}

// --- internal helpers ---

func (s *DriftService) detectToolShift(baseline, current *DriftProfile, threshold float64) []DriftAnomaly {
	var anomalies []DriftAnomaly
	if current.TotalCalls == 0 {
		return anomalies
	}

	// Check each tool in baseline or current
	allTools := make(map[string]bool)
	for t := range baseline.ToolDistribution {
		allTools[t] = true
	}
	for t := range current.ToolDistribution {
		allTools[t] = true
	}

	for tool := range allTools {
		bPct := baseline.ToolDistribution[tool]
		cPct := current.ToolDistribution[tool]
		diff := cPct - bPct

		if math.Abs(diff) > threshold {
			sev := "medium"
			if math.Abs(diff) > threshold*2 {
				sev = "high"
			}
			desc := fmt.Sprintf("%s usage changed from %.0f%% to %.0f%% (%+.0f%%)", tool, bPct*100, cPct*100, diff*100)
			anomalies = append(anomalies, DriftAnomaly{
				Type:        "tool_shift",
				Severity:    sev,
				Description: desc,
				Baseline:    bPct * 100,
				Current:     cPct * 100,
				Deviation:   diff * 100,
				ToolName:    tool,
			})
		}
	}
	return anomalies
}

func (s *DriftService) detectArgShift(baseline, current *DriftProfile, threshold float64) []DriftAnomaly {
	var anomalies []DriftAnomaly
	if current.TotalCalls == 0 {
		return anomalies
	}

	// For each tool present in both baseline and current, compare arg keys
	for tool, bKeys := range baseline.ArgKeysByTool {
		cKeys := current.ArgKeysByTool[tool]
		if cKeys == nil {
			continue // tool not used in current period
		}

		// Count new keys (in current but not in baseline)
		var newKeys, missingKeys int
		allKeys := make(map[string]bool)
		for k := range bKeys {
			allKeys[k] = true
		}
		for k := range cKeys {
			allKeys[k] = true
		}

		for k := range allKeys {
			_, inBaseline := bKeys[k]
			_, inCurrent := cKeys[k]
			if inCurrent && !inBaseline {
				newKeys++
			}
			if inBaseline && !inCurrent {
				missingKeys++
			}
		}

		totalKeys := len(allKeys)
		if totalKeys == 0 {
			continue
		}

		shiftRatio := float64(newKeys+missingKeys) / float64(totalKeys)
		if shiftRatio > threshold {
			sev := "medium"
			if shiftRatio > threshold*2 {
				sev = "high"
			}
			anomalies = append(anomalies, DriftAnomaly{
				Type:        "arg_shift",
				Severity:    sev,
				Description: fmt.Sprintf("%s: %d new and %d missing argument keys (%.0f%% shift)", tool, newKeys, missingKeys, shiftRatio*100),
				Baseline:    float64(len(bKeys)),
				Current:     float64(len(cKeys)),
				Deviation:   shiftRatio * 100,
				ToolName:    tool,
			})
		}
	}
	return anomalies
}

func (s *DriftService) detectRateChange(anomalyType string, baselineRate, currentRate, threshold float64) *DriftAnomaly {
	diff := currentRate - baselineRate
	if math.Abs(diff) <= threshold {
		return nil
	}

	sev := "medium"
	if math.Abs(diff) > threshold*2 {
		sev = "high"
	}

	label := "Deny"
	if anomalyType == "error_rate" {
		label = "Error"
	}

	return &DriftAnomaly{
		Type:        anomalyType,
		Severity:    sev,
		Description: fmt.Sprintf("%s rate changed from %.1f%% to %.1f%% (%+.1f%%)", label, baselineRate*100, currentRate*100, diff*100),
		Baseline:    baselineRate * 100,
		Current:     currentRate * 100,
		Deviation:   diff * 100,
	}
}

func (s *DriftService) storeProfileSnapshot(ctx context.Context, identityID string, profile *DriftProfile) {
	data, err := json.Marshal(profile)
	if err != nil {
		return
	}
	if err := s.tsStore.Append(ctx, "drift:profile:"+identityID, storage.DataPoint{
		Timestamp: profile.ComputedAt,
		Value:     float64(profile.TotalCalls),
		Tags:      map[string]string{"identity": identityID},
		Payload:   data,
	}); err != nil {
		s.logger.Error("failed to store profile snapshot", "error", err)
	}
}

func (s *DriftService) emitAnomalyEvents(ctx context.Context, report *BehavioralDriftReport) {
	s.mu.RLock()
	bus := s.eventBus
	s.mu.RUnlock()

	if bus == nil || len(report.Anomalies) == 0 {
		return
	}

	// Find the highest severity
	maxSev := event.SeverityInfo
	for _, a := range report.Anomalies {
		switch a.Severity {
		case "high":
			if event.SeverityCritical > maxSev {
				maxSev = event.SeverityCritical
			}
		case "medium":
			if maxSev < event.SeverityWarning {
				maxSev = event.SeverityWarning
			}
		}
	}

	// Build anomaly summaries
	anomalySummaries := make([]map[string]interface{}, 0, len(report.Anomalies))
	for _, a := range report.Anomalies {
		anomalySummaries = append(anomalySummaries, map[string]interface{}{
			"type":        a.Type,
			"severity":    a.Severity,
			"description": a.Description,
			"tool_name":   a.ToolName,
			"deviation":   a.Deviation,
		})
	}

	bus.Publish(ctx, event.Event{
		Type:           "drift.anomaly",
		Source:         "drift-detector",
		Severity:       maxSev,
		RequiresAction: maxSev >= event.SeverityWarning,
		Payload: map[string]interface{}{
			"identity_id":   report.IdentityID,
			"identity_name": report.IdentityName,
			"drift_score":   report.DriftScore,
			"anomalies":     anomalySummaries,
		},
	})
}

// klDivergence computes KL divergence between two distributions (with smoothing).
func klDivergence(p, q []float64) float64 {
	if len(p) != len(q) || len(p) == 0 {
		return 0
	}

	// Add smoothing to avoid log(0)
	epsilon := 0.001
	var pSum, qSum float64
	for i := range p {
		pSum += p[i] + epsilon
		qSum += q[i] + epsilon
	}
	if pSum == 0 || qSum == 0 {
		return 0
	}

	var kl float64
	for i := range p {
		pi := (p[i] + epsilon) / pSum
		qi := (q[i] + epsilon) / qSum
		if pi > 0 && qi > 0 {
			kl += pi * math.Log(pi/qi)
		}
	}
	return math.Abs(kl)
}

// computeDriftScore normalizes anomalies to a 0-1 score.
func computeDriftScore(anomalies []DriftAnomaly) float64 {
	if len(anomalies) == 0 {
		return 0
	}

	var score float64
	for _, a := range anomalies {
		switch a.Severity {
		case "high":
			score += 0.4
		case "medium":
			score += 0.2
		case "low":
			score += 0.1
		}
	}
	if score > 1.0 {
		score = 1.0
	}
	return score
}
