package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/redteam"
)

// ErrUnknownPattern is returned when RunSingle is called with a pattern ID not in the corpus.
var ErrUnknownPattern = errors.New("unknown pattern")

// RedTeamPolicyEvaluator evaluates a policy context for red team testing.
type RedTeamPolicyEvaluator interface {
	Evaluate(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error)
}

// RedTeamService provides red team testing against the current SentinelGate
// configuration. It simulates attacks and reports which ones pass through.
type RedTeamService struct {
	policyEval    RedTeamPolicyEvaluator
	contentScanFn func(args map[string]interface{}) (detected, blocked bool)
	eventBus      event.Bus
	logger        *slog.Logger

	mu      sync.RWMutex
	reports []*redteam.Report
}

const maxReports = 20

func NewRedTeamService(policyEval RedTeamPolicyEvaluator, logger *slog.Logger) *RedTeamService {
	return &RedTeamService{
		policyEval: policyEval,
		logger:     logger,
		reports:    make([]*redteam.Report, 0, maxReports),
	}
}

func (s *RedTeamService) SetContentScanFn(fn func(args map[string]interface{}) (detected, blocked bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contentScanFn = fn
}

func (s *RedTeamService) SetEventBus(bus event.Bus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventBus = bus
}

// RunSuite runs all attack patterns against the current configuration.
func (s *RedTeamService) RunSuite(ctx context.Context, targetIdentity string, roles []string) (*redteam.Report, error) {
	return s.runPatterns(ctx, redteam.Corpus(), targetIdentity, roles)
}

// RunCategory runs attack patterns from a specific category.
func (s *RedTeamService) RunCategory(ctx context.Context, category redteam.AttackCategory, targetIdentity string, roles []string) (*redteam.Report, error) {
	var filtered []redteam.AttackPattern
	for _, p := range redteam.Corpus() {
		if p.Category == category {
			filtered = append(filtered, p)
		}
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("no patterns for category: %s", category)
	}
	return s.runPatterns(ctx, filtered, targetIdentity, roles)
}

// RunSingle runs a single attack pattern by ID.
func (s *RedTeamService) RunSingle(ctx context.Context, patternID string, targetIdentity string, roles []string) (*redteam.TestResult, error) {
	for _, p := range redteam.Corpus() {
		if p.ID == patternID {
			return s.runSinglePattern(ctx, p, targetIdentity, roles), nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownPattern, patternID)
}

// GetCorpus returns available attack patterns.
func (s *RedTeamService) GetCorpus() []redteam.AttackPattern {
	return redteam.Corpus()
}

// GetReports returns stored reports (most recent first).
func (s *RedTeamService) GetReports() []*redteam.Report {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*redteam.Report, len(s.reports))
	copy(result, s.reports)
	// reverse for most recent first
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

// GetReport returns a specific report by ID.
func (s *RedTeamService) GetReport(id string) *redteam.Report {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.reports {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (s *RedTeamService) runPatterns(ctx context.Context, patterns []redteam.AttackPattern, targetIdentity string, roles []string) (*redteam.Report, error) {
	start := time.Now()

	results := make([]redteam.TestResult, 0, len(patterns))
	for _, p := range patterns {
		results = append(results, *s.runSinglePattern(ctx, p, targetIdentity, roles))
	}

	// Build category scores (ordered by category)
	scoreMap := make(map[redteam.AttackCategory]*redteam.CategoryScore)
	for i := range results {
		r := &results[i]
		cs, ok := scoreMap[r.Category]
		if !ok {
			cs = &redteam.CategoryScore{Category: r.Category}
			scoreMap[r.Category] = cs
		}
		cs.Total++
		if r.Blocked {
			cs.Blocked++
		} else {
			cs.Passed++
		}
	}

	scores := make([]redteam.CategoryScore, 0, len(scoreMap))
	for _, cs := range scoreMap {
		scores = append(scores, *cs)
	}
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Category < scores[j].Category
	})

	var vulns []redteam.TestResult
	totalBlocked := 0
	for _, r := range results {
		if r.Blocked {
			totalBlocked++
		} else {
			vulns = append(vulns, r)
		}
	}
	if vulns == nil {
		vulns = []redteam.TestResult{}
	}

	blockRate := 0.0
	if len(results) > 0 {
		blockRate = float64(totalBlocked) / float64(len(results)) * 100
	}

	report := &redteam.Report{
		ID:              fmt.Sprintf("rt_%s", time.Now().Format("20060102_150405")),
		Timestamp:       time.Now(),
		TargetID:        targetIdentity,
		Roles:           roles,
		CorpusSize:      len(patterns),
		DurationMs:      time.Since(start).Milliseconds(),
		Scores:          scores,
		TotalBlocked:    totalBlocked,
		TotalPassed:     len(results) - totalBlocked,
		BlockRate:       blockRate,
		Vulnerabilities: vulns,
		AllResults:      results,
	}

	s.storeReport(report)
	// Manual scans (all current scans are admin-triggered) do not emit
	// notifications — results are already shown inline. When automatic
	// scheduled scans are added, call s.emitEvent(ctx, report) from the
	// scheduler path instead.

	s.logger.Info("red team scan complete",
		"report_id", report.ID,
		"target", targetIdentity,
		"blocked", report.TotalBlocked,
		"vulnerabilities", report.TotalPassed,
		"block_rate", fmt.Sprintf("%.1f%%", report.BlockRate),
	)

	return report, nil
}

func (s *RedTeamService) runSinglePattern(ctx context.Context, p redteam.AttackPattern, targetIdentity string, roles []string) *redteam.TestResult {
	testRoles := roles
	if len(testRoles) == 0 {
		testRoles = p.Roles
	}
	testIdentity := targetIdentity
	if testIdentity == "" {
		testIdentity = "redteam-test"
	}

	result := &redteam.TestResult{
		PatternID:   p.ID,
		PatternName: p.Name,
		Category:    p.Category,
		Severity:    p.Severity,
		Description: p.Description,
	}

	// Check content scanning first
	s.mu.RLock()
	scanFn := s.contentScanFn
	s.mu.RUnlock()

	if scanFn != nil && len(p.Arguments) > 0 {
		_, blocked := scanFn(p.Arguments)
		if blocked {
			result.Blocked = true
			result.Method = "content_scan"
			result.Reason = "Content scanner blocked the request"
			return result
		}
	}

	// Evaluate against policy engine
	evalCtx := policy.EvaluationContext{
		ToolName:      p.ToolName,
		UserRoles:     testRoles,
		ToolArguments: p.Arguments,
		IdentityID:    testIdentity,
		IdentityName:  testIdentity,
		ActionType:    p.ActionType,
		Protocol:      p.Protocol,
		RequestTime:   time.Now(),
		SkipCache:     true,
	}

	decision, err := s.policyEval.Evaluate(ctx, evalCtx)
	if err != nil {
		result.Blocked = true
		result.Method = "error"
		result.Reason = fmt.Sprintf("Policy evaluation error (fail-safe): %v", err)
		return result
	}

	if decision.RequiresApproval {
		result.Blocked = true
		result.Method = "approval_required"
		result.RuleID = decision.RuleID
		result.RuleName = decision.RuleName
		result.Reason = "Requires human approval (HITL)"
		return result
	}

	if !decision.Allowed {
		result.Blocked = true
		result.Method = "policy"
		result.RuleID = decision.RuleID
		result.RuleName = decision.RuleName
		result.Reason = decision.Reason
		return result
	}

	// Not blocked — vulnerability
	result.Blocked = false
	result.Method = "none"
	result.Reason = "Attack was allowed through"
	result.Explanation = buildExplanation(p, decision)
	result.Remediation = p.Remediation

	return result
}

func buildExplanation(p redteam.AttackPattern, decision policy.Decision) string {
	if decision.RuleID != "" {
		return fmt.Sprintf(
			"Rule '%s' (ID: %s) allowed this action. The rule does not cover %s attack patterns.",
			decision.RuleName, decision.RuleID, p.Category,
		)
	}
	return fmt.Sprintf(
		"No policy rule matched this action (default allow). Add a deny rule for %s patterns.",
		p.Category,
	)
}

func (s *RedTeamService) storeReport(report *redteam.Report) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reports) >= maxReports {
		s.reports = s.reports[1:]
	}
	s.reports = append(s.reports, report)
}

// ClearReports removes all stored red team reports.
// Used by factory reset to discard reports referencing deleted identities.
func (s *RedTeamService) ClearReports() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = make([]*redteam.Report, 0, maxReports)
}

// emitEvent was removed because all current scans are manual (#57).
// When automatic scheduled scans are added, re-implement event emission
// for "redteam.scan_complete" from the scheduler path.
