package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/compliance"
)

// ComplianceContext provides the current system state needed for compliance checks
// that cannot be determined from audit data alone (e.g., "is content scanning enabled?").
type ComplianceContext struct {
	EvidenceEnabled     bool
	ContentScanEnabled  bool
	InputScanEnabled    bool
	ToolIntegrityActive bool // true if baseline has been captured
	RateLimitEnabled    bool
	IdentityCount       int
	PolicyCount         int
	APIKeyCount         int  // number of active API keys
	DenyRuleCount       int  // number of deny/block rules (not just wildcard allow)
	HITLAvailable       bool // true if approval store is wired
}

// ComplianceAuditReader abstracts audit data access for compliance analysis.
// Both MemoryAuditStore and FileAuditStore satisfy this via their Query + GetRecent methods.
type ComplianceAuditReader interface {
	GetRecent(n int) []AuditRecordCompat
}

// AuditRecordCompat is a minimal audit record type for compliance checks.
// The compliance service needs decision counts, identity/tool info, and timestamps
// for inclusion in evidence bundles.
type AuditRecordCompat struct {
	Timestamp      time.Time
	Decision       string
	Reason         string
	ToolName       string
	IdentityID     string
	IdentityName   string
	SessionID      string
	ToolArguments  map[string]interface{}
	ScanDetections int
	ScanTypes      string
}

// ComplianceService analyzes audit evidence against regulatory requirements.
type ComplianceService struct {
	auditReader func(n int) []AuditRecordCompat
	logger      *slog.Logger
}

// NewComplianceService creates a new compliance service.
// auditReaderFn returns the N most recent audit records for analysis.
func NewComplianceService(auditReaderFn func(n int) []AuditRecordCompat, logger *slog.Logger) *ComplianceService {
	return &ComplianceService{
		auditReader: auditReaderFn,
		logger:      logger,
	}
}

// ListPacks returns all available policy packs.
func (s *ComplianceService) ListPacks() []*compliance.PolicyPack {
	packs := make([]*compliance.PolicyPack, 0, len(compliance.BuiltinPacks))
	for _, p := range compliance.BuiltinPacks {
		packs = append(packs, p)
	}
	return packs
}

// GetPack returns a single policy pack by ID.
func (s *ComplianceService) GetPack(id string) (*compliance.PolicyPack, error) {
	p, ok := compliance.BuiltinPacks[id]
	if !ok {
		return nil, fmt.Errorf("policy pack %q not found", id)
	}
	return p, nil
}

// auditStats holds aggregated audit statistics computed from recent records.
type auditStats struct {
	totalCalls       int64
	uniqueIdentities int64
	uniqueSessions   int64
	uniqueTools      int64
	byDecision       map[string]int64
}

// computeAuditStats reads recent audit records and computes aggregated stats.
// If start/end are non-zero, only records within the period are counted.
func (s *ComplianceService) computeAuditStats(start, end time.Time) *auditStats {
	if s.auditReader == nil {
		return nil
	}

	records := s.auditReader(10000)
	if len(records) == 0 {
		return &auditStats{byDecision: map[string]int64{}}
	}

	filterByPeriod := !start.IsZero() || !end.IsZero()

	identities := make(map[string]bool)
	sessions := make(map[string]bool)
	tools := make(map[string]bool)
	decisions := make(map[string]int64)
	counted := 0

	for _, r := range records {
		if filterByPeriod {
			if !start.IsZero() && r.Timestamp.Before(start) {
				continue
			}
			if !end.IsZero() && r.Timestamp.After(end) {
				continue
			}
		}
		counted++
		decisions[r.Decision]++
		if r.IdentityID != "" {
			identities[r.IdentityID] = true
		}
		if r.SessionID != "" {
			sessions[r.SessionID] = true
		}
		if r.ToolName != "" {
			tools[r.ToolName] = true
		}
	}

	return &auditStats{
		totalCalls:       int64(counted),
		uniqueIdentities: int64(len(identities)),
		uniqueSessions:   int64(len(sessions)),
		uniqueTools:      int64(len(tools)),
		byDecision:       decisions,
	}
}

// AnalyzeCoverage evaluates how well a policy pack's requirements are met.
func (s *ComplianceService) AnalyzeCoverage(
	_ context.Context,
	packID string,
	start, end time.Time,
	sysCtx ComplianceContext,
) (*compliance.CoverageReport, error) {
	pack, err := s.GetPack(packID)
	if err != nil {
		return nil, err
	}

	stats := s.computeAuditStats(start, end)

	reqCoverages := make([]compliance.RequirementCoverage, 0, len(pack.Requirements))
	totalScore := 0.0

	for _, req := range pack.Requirements {
		rc := s.evaluateRequirement(req, stats, sysCtx)
		reqCoverages = append(reqCoverages, rc)
		totalScore += rc.Score
	}

	overallScore := 0.0
	if len(reqCoverages) > 0 {
		overallScore = totalScore / float64(len(reqCoverages))
	}

	return &compliance.CoverageReport{
		PackID:       pack.ID,
		PackName:     pack.Name,
		Framework:    pack.Framework,
		Period:       compliance.CoveragePeriod{Start: start, End: end},
		OverallScore: overallScore,
		Requirements: reqCoverages,
		GeneratedAt:  time.Now().UTC(),
	}, nil
}

// GenerateBundle creates a complete compliance evidence bundle.
func (s *ComplianceService) GenerateBundle(
	ctx context.Context,
	packID string,
	start, end time.Time,
	sysCtx ComplianceContext,
	instanceID string,
) (*compliance.Bundle, error) {
	coverage, err := s.AnalyzeCoverage(ctx, packID, start, end, sysCtx)
	if err != nil {
		return nil, fmt.Errorf("coverage analysis failed: %w", err)
	}

	// Reuse the same audit reader call for both stats and records.
	// AnalyzeCoverage already computed stats internally, but we need
	// the summary here too. Single read to avoid consistency gaps.
	stats := s.computeAuditStats(start, end)

	var summary compliance.EvidenceSummary
	summary.Period = compliance.CoveragePeriod{Start: start, End: end}
	if stats != nil {
		summary.TotalAuditRecords = stats.totalCalls
		summary.UniqueIdentities = stats.uniqueIdentities
		summary.UniqueSessions = stats.uniqueSessions
		summary.UniqueTools = stats.uniqueTools
		summary.DecisionBreakdown = stats.byDecision
	}

	// Include a sample of actual audit records in the bundle.
	auditRecords := make([]compliance.AuditRecordSummary, 0)
	if s.auditReader != nil {
		records := s.auditReader(compliance.MaxBundleAuditRecords)
		for _, r := range records {
			auditRecords = append(auditRecords, compliance.AuditRecordSummary{
				Timestamp:      r.Timestamp,
				IdentityID:     r.IdentityID,
				IdentityName:   r.IdentityName,
				SessionID:      r.SessionID,
				ToolName:       r.ToolName,
				Decision:       r.Decision,
				Reason:         r.Reason,
				RequestArgs:    r.ToolArguments,
				ScanDetections: r.ScanDetections,
				ScanTypes:      r.ScanTypes,
			})
		}
	}

	bundleID := fmt.Sprintf("bundle_%s_%s", packID, time.Now().UTC().Format("20060102T150405"))

	return &compliance.Bundle{
		ID:              bundleID,
		PackID:          coverage.PackID,
		PackName:        coverage.PackName,
		Framework:       coverage.Framework,
		GeneratedAt:     time.Now().UTC(),
		GeneratedBy:     instanceID,
		Coverage:        *coverage,
		EvidenceSummary: summary,
		AuditRecords:    auditRecords,
		Disclaimer:      compliance.ComplianceDisclaimer,
	}, nil
}

// evaluateRequirement assesses a single requirement against available evidence.
func (s *ComplianceService) evaluateRequirement(
	req compliance.Requirement,
	stats *auditStats,
	sysCtx ComplianceContext,
) compliance.RequirementCoverage {
	checkResults := make([]compliance.CheckResult, 0, len(req.EvidenceChecks))
	passedCount := 0

	for _, check := range req.EvidenceChecks {
		result := s.evaluateCheck(check, stats, sysCtx)
		checkResults = append(checkResults, result)
		if result.Passed {
			passedCount++
		}
	}

	score := 0.0
	if len(checkResults) > 0 {
		score = float64(passedCount) / float64(len(checkResults))
	}

	var status compliance.CoverageStatus
	switch {
	case score >= 1.0:
		status = compliance.StatusCovered
	case score > 0:
		status = compliance.StatusPartial
	default:
		status = compliance.StatusGap
	}

	return compliance.RequirementCoverage{
		RequirementID: req.ID,
		Article:       req.Article,
		Title:         req.Title,
		Status:        status,
		Score:         score,
		CheckResults:  checkResults,
	}
}

// evaluateCheck performs a single evidence check.
func (s *ComplianceService) evaluateCheck(
	check compliance.EvidenceCheck,
	stats *auditStats,
	sysCtx ComplianceContext,
) compliance.CheckResult {
	result := compliance.CheckResult{
		CheckID:     check.ID,
		Description: check.Description,
		Source:      check.Source,
	}

	switch check.CheckType {
	case compliance.CheckAuditTrailExists:
		if stats != nil && stats.totalCalls > 0 {
			result.Passed = true
			result.Detail = fmt.Sprintf("%d audit records found in period", stats.totalCalls)
		} else {
			result.Detail = "No audit records found for the specified period"
		}

	case compliance.CheckDecisionLogged:
		if stats != nil && stats.byDecision != nil {
			total := int64(0)
			for _, count := range stats.byDecision {
				total += count
			}
			if total > 0 {
				result.Passed = true
				result.Detail = fmt.Sprintf("%d decisions logged (allow: %d, deny: %d)",
					total,
					stats.byDecision["allow"],
					stats.byDecision["deny"]+stats.byDecision["blocked"])
			} else {
				result.Detail = "No policy decisions found in audit trail"
			}
		} else {
			result.Detail = "No policy decisions found in audit trail"
		}

	case compliance.CheckEvidenceSigned:
		if sysCtx.EvidenceEnabled {
			result.Passed = true
			result.Detail = "Cryptographic evidence signing is enabled (ECDSA P-256)"
		} else {
			result.Detail = "Cryptographic evidence is not enabled. Enable in config: evidence.enabled: true"
		}

	case compliance.CheckContentScanEnabled:
		if sysCtx.ContentScanEnabled || sysCtx.InputScanEnabled {
			result.Passed = true
			parts := []string{}
			if sysCtx.ContentScanEnabled {
				parts = append(parts, "response scanning")
			}
			if sysCtx.InputScanEnabled {
				parts = append(parts, "input scanning")
			}
			result.Detail = fmt.Sprintf("Content scanning active: %s", joinStrings(parts, ", "))
		} else {
			result.Detail = "Content scanning is not enabled. Enable response and/or input scanning in Security settings"
		}

	case compliance.CheckToolIntegrityEnabled:
		if sysCtx.ToolIntegrityActive {
			result.Passed = true
			result.Detail = "Tool integrity baseline captured; drift detection active"
		} else {
			result.Detail = "No tool integrity baseline captured. Capture baseline in Security > Tool Security"
		}

	case compliance.CheckRateLimitEnabled:
		if sysCtx.RateLimitEnabled {
			result.Passed = true
			result.Detail = "Rate limiting is enabled and configured"
		} else {
			result.Detail = "Rate limiting is not enabled. Configure rate_limit.enabled in config"
		}

	case compliance.CheckIdentitiesConfigured:
		if sysCtx.IdentityCount > 0 && sysCtx.APIKeyCount > 0 {
			result.Passed = true
			result.Detail = fmt.Sprintf("%d identities configured, %d API keys active", sysCtx.IdentityCount, sysCtx.APIKeyCount)
		} else if sysCtx.IdentityCount > 0 {
			result.Detail = fmt.Sprintf("%d identities configured but no API keys active. Create API keys in Connections", sysCtx.IdentityCount)
		} else {
			result.Detail = "No identities configured. Add identities in Access management"
		}

	case compliance.CheckPoliciesConfigured:
		if sysCtx.PolicyCount > 0 && sysCtx.DenyRuleCount > 0 {
			result.Passed = true
			result.Detail = fmt.Sprintf("%d policies configured with %d restrictive rules", sysCtx.PolicyCount, sysCtx.DenyRuleCount)
		} else if sysCtx.PolicyCount > 0 {
			result.Detail = fmt.Sprintf("%d policies configured but no deny/block rules. Add restrictive rules in Tools & Rules", sysCtx.PolicyCount)
		} else {
			result.Detail = "No access control policies configured. Add policies in Tools & Rules"
		}

	case compliance.CheckHITLAvailable:
		if sysCtx.HITLAvailable {
			result.Passed = true
			result.Detail = "Human-in-the-loop approval mechanism is available"
		} else {
			result.Detail = "HITL approval not configured. Enable approval rules with action 'Ask' in Tools & Rules"
		}

	default:
		result.Detail = "Unknown check type: " + string(check.CheckType)
	}

	return result
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += sep + parts[i]
	}
	return result
}
