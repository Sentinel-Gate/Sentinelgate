package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/storage"
)

// ShadowMode defines the permission health analysis mode.
type ShadowMode string

const (
	ShadowModeDisabled ShadowMode = "disabled"
	ShadowModeShadow   ShadowMode = "shadow"  // report only
	ShadowModeSuggest  ShadowMode = "suggest"  // report + notify admin
	ShadowModeAuto     ShadowMode = "auto"     // apply after grace period
)

var (
	// ErrPermissionHealthDisabled indicates the service is not enabled.
	ErrPermissionHealthDisabled = errors.New("permission health is disabled")
)

// PermissionHealthConfig holds shadow mode configuration.
type PermissionHealthConfig struct {
	Mode            ShadowMode `json:"mode"`
	LearningDays    int        `json:"learning_days"`     // observation window (default 14)
	GracePeriodDays int        `json:"grace_period_days"` // days before auto-apply (default 7)
	WhitelistTools  []string   `json:"whitelist_tools"`   // tools never to suggest removing
	UpdatedAt       time.Time  `json:"updated_at"`
}

// DefaultPermissionHealthConfig returns sensible defaults.
func DefaultPermissionHealthConfig() PermissionHealthConfig {
	return PermissionHealthConfig{
		Mode:            ShadowModeShadow,
		LearningDays:    14,
		GracePeriodDays: 7,
	}
}

// UsageProfile represents tool usage data for an identity over an observation window.
type UsageProfile struct {
	IdentityID string                   `json:"identity_id"`
	ToolUsage  map[string]*ToolUsageInfo `json:"tool_usage"` // tool name -> usage info
	TotalCalls int                      `json:"total_calls"`
	WindowDays int                      `json:"window_days"`
	ComputedAt time.Time                `json:"computed_at"`
}

// ToolUsageInfo holds usage details for a single tool.
type ToolUsageInfo struct {
	CallCount   int                    `json:"call_count"`
	LastUsed    time.Time              `json:"last_used"`
	ArgKeys     map[string]int         `json:"arg_keys,omitempty"`      // argument key frequencies
	HourlyUsage [24]int               `json:"hourly_usage,omitempty"`  // calls per hour of day
}

// PermissionGapType categorizes permission gaps.
type PermissionGapType string

const (
	GapNeverUsed    PermissionGapType = "never_used"    // permitted but 0 calls in window
	GapRarelyUsed   PermissionGapType = "rarely_used"   // permitted but < 3 calls in window
	GapTemporalExcess PermissionGapType = "temporal_excess" // used only at specific times
)

// PermissionGap represents an over-privileged tool for an identity.
type PermissionGap struct {
	ToolName    string            `json:"tool_name"`
	GapType     PermissionGapType `json:"gap_type"`
	DaysUnused  int               `json:"days_unused"`
	CallCount   int               `json:"call_count"`    // calls in window (0 for never_used)
	Description string            `json:"description"`
}

// SuggestedPolicy is a CEL rule suggestion for tightening permissions.
type SuggestedPolicy struct {
	ID          string `json:"id"`
	ToolName    string `json:"tool_name"`
	RuleName    string `json:"rule_name"`
	Condition   string `json:"condition"`   // CEL expression
	Action      string `json:"action"`      // "deny"
	Reason      string `json:"reason"`      // human explanation
	ToolPattern string `json:"tool_pattern"`
}

// PermissionHealthReport is the full health analysis for an identity.
type PermissionHealthReport struct {
	IdentityID       string             `json:"identity_id"`
	IdentityName     string             `json:"identity_name"`
	Roles            []string           `json:"roles"`
	LeastPrivScore   float64            `json:"least_privilege_score"` // 0-100, higher = better
	PermittedTools   int                `json:"permitted_tools"`
	UsedTools        int                `json:"used_tools"`
	Gaps             []PermissionGap    `json:"gaps"`
	Suggestions      []SuggestedPolicy  `json:"suggestions"`
	DriftScore       float64            `json:"drift_score,omitempty"`
	AnomalyCount     int                `json:"anomaly_count,omitempty"`
	ComputedAt       time.Time          `json:"computed_at"`
}

// PermissionHealthAuditReader provides audit records for permission analysis.
type PermissionHealthAuditReader interface {
	Query(ctx context.Context, filter audit.AuditFilter) ([]audit.AuditRecord, string, error)
}

// PermissionHealthToolLister provides the list of all known tools.
type PermissionHealthToolLister interface {
	GetAllToolNames() []string
}

// PermissionHealthIdentityLister provides identity information.
type PermissionHealthIdentityLister interface {
	GetAllIdentities() []IdentityInfo
}

// IdentityInfo is a minimal identity view for permission health analysis.
type IdentityInfo struct {
	ID    string
	Name  string
	Roles []string
}

// PermissionHealthPolicyEvaluator evaluates a tool for an identity.
type PermissionHealthPolicyEvaluator interface {
	Evaluate(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error)
}

// permHealthCacheEntry bundles a cached report with its individual timestamp,
// so that refreshing one identity's entry does not reset the TTL for others.
type permHealthCacheEntry struct {
	report   *PermissionHealthReport
	cachedAt time.Time
}

// maxPermHealthCacheSize is the maximum number of identity entries kept in the
// permission health cache. When exceeded, all entries are evicted to prevent
// unbounded memory growth.
const maxPermHealthCacheSize = 10000

// PermissionHealthService implements shadow mode and permission gap analysis.
type PermissionHealthService struct {
	mu              sync.RWMutex
	reader          PermissionHealthAuditReader
	toolLister      PermissionHealthToolLister
	identityLister  PermissionHealthIdentityLister
	policyEvaluator PermissionHealthPolicyEvaluator
	driftService    *DriftService
	tsStore         storage.TimeSeriesStore
	eventBus        event.Bus
	config          PermissionHealthConfig
	logger          *slog.Logger

	// Cache of recent reports — each entry tracks its own timestamp.
	cache    map[string]permHealthCacheEntry
	cacheTTL time.Duration
}

// NewPermissionHealthService creates a new permission health analysis service.
func NewPermissionHealthService(
	reader PermissionHealthAuditReader,
	toolLister PermissionHealthToolLister,
	identityLister PermissionHealthIdentityLister,
	policyEvaluator PermissionHealthPolicyEvaluator,
	logger *slog.Logger,
) *PermissionHealthService {
	return &PermissionHealthService{
		reader:          reader,
		toolLister:      toolLister,
		identityLister:  identityLister,
		policyEvaluator: policyEvaluator,
		config:          DefaultPermissionHealthConfig(),
		logger:          logger,
		cache:           make(map[string]permHealthCacheEntry),
		cacheTTL:        5 * time.Minute,
	}
}

// SetEventBus wires the event bus for permission health events.
func (s *PermissionHealthService) SetEventBus(bus event.Bus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventBus = bus
}

// SetDriftService connects drift data for enrichment.
func (s *PermissionHealthService) SetDriftService(ds *DriftService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.driftService = ds
}

// SetTimeSeriesStore connects storage for usage profile persistence.
func (s *PermissionHealthService) SetTimeSeriesStore(ts storage.TimeSeriesStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tsStore = ts
}

// Config returns the current configuration.
func (s *PermissionHealthService) Config() PermissionHealthConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// SetConfig updates the shadow mode configuration.
func (s *PermissionHealthService) SetConfig(cfg PermissionHealthConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg.UpdatedAt = time.Now().UTC()
	s.config = cfg
	// Invalidate cache on config change
	s.cache = make(map[string]permHealthCacheEntry)
}

// BuildUsageProfile computes tool usage for an identity over the observation window.
func (s *PermissionHealthService) BuildUsageProfile(ctx context.Context, identityID string) (*UsageProfile, error) {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	now := time.Now()
	start := now.Add(-time.Duration(cfg.LearningDays) * 24 * time.Hour)

	records, _, err := s.reader.Query(ctx, audit.AuditFilter{
		UserID:    identityID,
		StartTime: start,
		EndTime:   now,
		Limit:     10000,
	})
	if err != nil {
		return nil, fmt.Errorf("query audit: %w", err)
	}

	profile := &UsageProfile{
		IdentityID: identityID,
		ToolUsage:  make(map[string]*ToolUsageInfo),
		TotalCalls: len(records),
		WindowDays: cfg.LearningDays,
		ComputedAt: now,
	}

	for _, r := range records {
		if r.ToolName == "" {
			continue
		}
		info, ok := profile.ToolUsage[r.ToolName]
		if !ok {
			info = &ToolUsageInfo{
				ArgKeys: make(map[string]int),
			}
			profile.ToolUsage[r.ToolName] = info
		}
		info.CallCount++
		if r.Timestamp.After(info.LastUsed) {
			info.LastUsed = r.Timestamp
		}
		for key := range r.ToolArguments {
			info.ArgKeys[key]++
		}
		info.HourlyUsage[r.Timestamp.UTC().Hour()]++
	}

	// Store profile snapshot
	if s.tsStore != nil {
		s.storeUsageSnapshot(ctx, identityID, profile)
	}

	return profile, nil
}

// GetPermittedTools returns the set of tools an identity is allowed to call.
// It simulates policy evaluation for each known tool with the identity's roles.
func (s *PermissionHealthService) GetPermittedTools(ctx context.Context, identityID string, roles []string) (map[string]bool, error) {
	allTools := s.toolLister.GetAllToolNames()
	permitted := make(map[string]bool)

	for _, toolName := range allTools {
		evalCtx := policy.EvaluationContext{
			ToolName:     toolName,
			UserRoles:    roles,
			IdentityID:   identityID,
			IdentityName: identityID,
			RequestTime:  time.Now(),
			ActionType:   "tool_call",
			Protocol:     "mcp",
			SkipCache:    true, // don't pollute production cache
		}

		decision, err := s.policyEvaluator.Evaluate(ctx, evalCtx)
		if err != nil {
			s.logger.Debug("policy eval failed for permission check",
				"tool", toolName, "identity", identityID, "error", err)
			continue
		}

		if decision.Allowed {
			permitted[toolName] = true
		}
	}

	return permitted, nil
}

// AnalyzePermissionGaps identifies over-privileged tools for an identity.
func (s *PermissionHealthService) AnalyzePermissionGaps(
	ctx context.Context,
	identityID string,
	roles []string,
	usageProfile *UsageProfile,
) ([]PermissionGap, error) {
	permitted, err := s.GetPermittedTools(ctx, identityID, roles)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	now := time.Now()
	var gaps []PermissionGap

	// Check whitelisted tools
	whitelist := make(map[string]bool)
	for _, t := range cfg.WhitelistTools {
		whitelist[t] = true
	}

	for toolName := range permitted {
		if whitelist[toolName] {
			continue
		}

		usage, hasUsage := usageProfile.ToolUsage[toolName]
		if !hasUsage || usage.CallCount == 0 {
			// Never used in observation window
			gaps = append(gaps, PermissionGap{
				ToolName:    toolName,
				GapType:     GapNeverUsed,
				DaysUnused:  cfg.LearningDays,
				CallCount:   0,
				Description: fmt.Sprintf("%s is permitted but never used in %d days", toolName, cfg.LearningDays),
			})
		} else if usage.CallCount <= 2 {
			// Rarely used
			daysSinceUse := int(now.Sub(usage.LastUsed).Hours() / 24)
			gaps = append(gaps, PermissionGap{
				ToolName:    toolName,
				GapType:     GapRarelyUsed,
				DaysUnused:  daysSinceUse,
				CallCount:   usage.CallCount,
				Description: fmt.Sprintf("%s used only %d times in %d days (last: %d days ago)", toolName, usage.CallCount, cfg.LearningDays, daysSinceUse),
			})
		} else {
			// Check temporal excess: used only at specific hours
			activeHours := 0
			for _, count := range usage.HourlyUsage {
				if count > 0 {
					activeHours++
				}
			}
			if activeHours <= 4 && activeHours > 0 {
				gaps = append(gaps, PermissionGap{
					ToolName:    toolName,
					GapType:     GapTemporalExcess,
					DaysUnused:  0,
					CallCount:   usage.CallCount,
					Description: fmt.Sprintf("%s active only %d hours/day — consider time-based restriction", toolName, activeHours),
				})
			}
		}
	}

	// Sort by gap type priority: never_used > rarely_used > temporal_excess
	sort.Slice(gaps, func(i, j int) bool {
		return gapPriority(gaps[i].GapType) > gapPriority(gaps[j].GapType)
	})

	return gaps, nil
}

func gapPriority(gt PermissionGapType) int {
	switch gt {
	case GapNeverUsed:
		return 3
	case GapRarelyUsed:
		return 2
	case GapTemporalExcess:
		return 1
	default:
		return 0
	}
}

// GenerateSuggestions creates CEL policy suggestions to close permission gaps.
// Uses identity_name in conditions (human-readable) instead of identity_id (UUID).
func (s *PermissionHealthService) GenerateSuggestions(identityID, identityName string, gaps []PermissionGap) []SuggestedPolicy {
	var suggestions []SuggestedPolicy

	// Use identity_name for readable CEL conditions and rule names; fall back to identity_id if name is empty.
	nameForRules := identityName
	condTarget := fmt.Sprintf(`identity_name == "%s"`, identityName)
	if identityName == "" {
		nameForRules = identityID
		condTarget = fmt.Sprintf(`identity_id == "%s"`, identityID)
	}

	for i, gap := range gaps {
		switch gap.GapType {
		case GapNeverUsed:
			suggestions = append(suggestions, SuggestedPolicy{
				ID:          fmt.Sprintf("suggest-%s-%d", identityID, i),
				ToolName:    gap.ToolName,
				RuleName:    fmt.Sprintf("auto-tighten-%s-%s", nameForRules, gap.ToolName),
				Condition:   condTarget,
				Action:      "deny",
				ToolPattern: gap.ToolName,
				Reason:      fmt.Sprintf("Never used in %d days", gap.DaysUnused),
			})
		case GapRarelyUsed:
			suggestions = append(suggestions, SuggestedPolicy{
				ID:          fmt.Sprintf("suggest-%s-%d", identityID, i),
				ToolName:    gap.ToolName,
				RuleName:    fmt.Sprintf("auto-tighten-%s-%s", nameForRules, gap.ToolName),
				Condition:   condTarget,
				Action:      "deny",
				ToolPattern: gap.ToolName,
				Reason:      fmt.Sprintf("Used only %d times in %d days", gap.CallCount, gap.DaysUnused),
			})
		case GapTemporalExcess:
			suggestions = append(suggestions, SuggestedPolicy{
				ID:          fmt.Sprintf("suggest-%s-%d", identityID, i),
				ToolName:    gap.ToolName,
				RuleName:    fmt.Sprintf("temporal-restrict-%s-%s", nameForRules, gap.ToolName),
				Condition:   condTarget + ` && !(request_hour >= 9 && request_hour <= 17)`,
				Action:      "deny",
				ToolPattern: gap.ToolName,
				Reason:      gap.Description,
			})
		}
	}

	return suggestions
}

// ComputeHealthReport builds a full permission health report for an identity.
func (s *PermissionHealthService) ComputeHealthReport(ctx context.Context, identityID string) (*PermissionHealthReport, error) {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if cfg.Mode == ShadowModeDisabled {
		return nil, ErrPermissionHealthDisabled
	}

	// Check cache — each entry has its own timestamp.
	s.mu.RLock()
	if entry, ok := s.cache[identityID]; ok && time.Since(entry.cachedAt) < s.cacheTTL {
		s.mu.RUnlock()
		return entry.report, nil
	}
	s.mu.RUnlock()

	// Find identity info
	identities := s.identityLister.GetAllIdentities()
	var identity *IdentityInfo
	for _, id := range identities {
		if id.ID == identityID {
			identity = &id
			break
		}
	}
	if identity == nil {
		return nil, fmt.Errorf("%w: %s", ErrIdentityNotFound, identityID)
	}

	// Build usage profile
	usageProfile, err := s.BuildUsageProfile(ctx, identityID)
	if err != nil {
		return nil, fmt.Errorf("build usage profile: %w", err)
	}

	// Get permitted tools
	permitted, err := s.GetPermittedTools(ctx, identityID, identity.Roles)
	if err != nil {
		return nil, fmt.Errorf("get permitted tools: %w", err)
	}

	// Analyze gaps
	gaps, err := s.AnalyzePermissionGaps(ctx, identityID, identity.Roles, usageProfile)
	if err != nil {
		return nil, fmt.Errorf("analyze gaps: %w", err)
	}

	// Generate suggestions
	suggestions := s.GenerateSuggestions(identityID, identity.Name, gaps)

	// Compute least privilege score: penalize for permission gaps.
	// Score = proportion of permitted tools that are NOT over-privileged.
	permittedCount := len(permitted)
	usedCount := len(usageProfile.ToolUsage)
	gapCount := len(gaps)
	var score float64
	if permittedCount > 0 {
		score = float64(permittedCount-gapCount) / float64(permittedCount) * 100
		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}
	}

	report := &PermissionHealthReport{
		IdentityID:     identityID,
		IdentityName:   identity.Name,
		Roles:          identity.Roles,
		LeastPrivScore: score,
		PermittedTools: permittedCount,
		UsedTools:      usedCount,
		Gaps:           gaps,
		Suggestions:    suggestions,
		ComputedAt:     time.Now().UTC(),
	}

	// Enrich with drift data
	s.mu.RLock()
	dsSvc := s.driftService
	s.mu.RUnlock()

	if dsSvc != nil {
		driftReport, driftErr := dsSvc.DetectDrift(ctx, identityID)
		if driftErr == nil && driftReport != nil {
			report.DriftScore = driftReport.DriftScore
			report.AnomalyCount = len(driftReport.Anomalies)
		}
	}

	// Cache the report with its own timestamp.
	s.mu.Lock()
	s.cache[identityID] = permHealthCacheEntry{report: report, cachedAt: time.Now()}
	if len(s.cache) > maxPermHealthCacheSize {
		s.cache = make(map[string]permHealthCacheEntry)
	}
	s.mu.Unlock()

	// Emit events if in suggest or auto mode
	if cfg.Mode == ShadowModeSuggest || cfg.Mode == ShadowModeAuto {
		s.emitGapEvents(ctx, report)
	}

	return report, nil
}

// GetAllHealthReports computes health reports for all identities with activity.
func (s *PermissionHealthService) GetAllHealthReports(ctx context.Context) ([]PermissionHealthReport, error) {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if cfg.Mode == ShadowModeDisabled {
		return nil, ErrPermissionHealthDisabled
	}

	// Get all identities with recent activity
	now := time.Now()
	start := now.Add(-time.Duration(cfg.LearningDays) * 24 * time.Hour)
	records, _, err := s.reader.Query(ctx, audit.AuditFilter{
		StartTime: start,
		EndTime:   now,
		Limit:     10000,
	})
	if err != nil {
		return nil, fmt.Errorf("query recent activity: %w", err)
	}

	// Collect unique identities
	identitySeen := make(map[string]bool)
	for _, r := range records {
		if r.IdentityID != "" {
			identitySeen[r.IdentityID] = true
		}
	}

	var reports []PermissionHealthReport
	for id := range identitySeen {
		report, rErr := s.ComputeHealthReport(ctx, id)
		if rErr != nil {
			s.logger.Debug("health report failed", "identity", id, "error", rErr)
			continue
		}
		if report != nil {
			reports = append(reports, *report)
		}
	}

	// Sort by score ascending (worst first)
	sort.Slice(reports, func(i, j int) bool {
		return reports[i].LeastPrivScore < reports[j].LeastPrivScore
	})

	return reports, nil
}

// ApplySuggestions applies selected policy suggestions.
// Returns the number of policies created.
func (s *PermissionHealthService) ApplySuggestions(ctx context.Context, identityID string, suggestionIDs []string) (int, error) {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if cfg.Mode == ShadowModeDisabled {
		return 0, ErrPermissionHealthDisabled
	}

	// Get the current report with suggestions
	report, err := s.ComputeHealthReport(ctx, identityID)
	if err != nil {
		return 0, err
	}

	// Build a map of requested suggestion IDs
	requested := make(map[string]bool)
	for _, id := range suggestionIDs {
		requested[id] = true
	}

	// Collect matching suggestions
	var toApply []SuggestedPolicy
	for _, sug := range report.Suggestions {
		if requested[sug.ID] {
			toApply = append(toApply, sug)
		}
	}

	if len(toApply) == 0 {
		return 0, nil
	}

	// Emit apply event
	s.mu.RLock()
	applyBus := s.eventBus
	s.mu.RUnlock()

	if applyBus != nil {
		toolNames := make([]string, len(toApply))
		for i, sug := range toApply {
			toolNames[i] = sug.ToolName
		}
		applyBus.Publish(ctx, event.Event{
			Type:           "permissions.auto_tighten_applied",
			Source:         "permission-health",
			Severity:       event.SeverityWarning,
			RequiresAction: true,
			Payload: map[string]interface{}{
				"identity_id":   identityID,
				"identity_name": report.IdentityName,
				"tools":         toolNames,
				"count":         len(toApply),
			},
		})
	}

	// Invalidate cache
	s.mu.Lock()
	delete(s.cache, identityID)
	s.mu.Unlock()

	return len(toApply), nil
}

// --- internal helpers ---

func (s *PermissionHealthService) storeUsageSnapshot(ctx context.Context, identityID string, profile *UsageProfile) {
	data, err := json.Marshal(profile)
	if err != nil {
		return
	}
	if err := s.tsStore.Append(ctx, "permissions:usage:"+identityID, storage.DataPoint{
		Timestamp: profile.ComputedAt,
		Value:     float64(profile.TotalCalls),
		Tags:      map[string]string{"identity": identityID},
		Payload:   data,
	}); err != nil {
		s.logger.Error("failed to store usage snapshot", "error", err)
	}
}

func (s *PermissionHealthService) emitGapEvents(ctx context.Context, report *PermissionHealthReport) {
	s.mu.RLock()
	bus := s.eventBus
	s.mu.RUnlock()

	if bus == nil || len(report.Gaps) == 0 {
		return
	}

	neverUsed := 0
	for _, g := range report.Gaps {
		if g.GapType == GapNeverUsed {
			neverUsed++
		}
	}

	sev := event.SeverityInfo
	if report.LeastPrivScore < 50 {
		sev = event.SeverityWarning
	}
	if report.LeastPrivScore < 25 {
		sev = event.SeverityCritical
	}

	bus.Publish(ctx, event.Event{
		Type:           "permissions.gap_detected",
		Source:         "permission-health",
		Severity:       sev,
		RequiresAction: sev >= event.SeverityWarning,
		Payload: map[string]interface{}{
			"identity_id":       report.IdentityID,
			"identity_name":     report.IdentityName,
			"least_priv_score":  report.LeastPrivScore,
			"gap_count":         len(report.Gaps),
			"never_used_count":  neverUsed,
			"suggestion_count":  len(report.Suggestions),
		},
	})
}
