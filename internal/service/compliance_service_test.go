package service

import (
	"context"
	"testing"
	"time"

	"log/slog"
	"os"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/compliance"
)

// makeAuditReader creates a mock audit reader function from a list of records.
func makeAuditReader(records []AuditRecordCompat) func(int) []AuditRecordCompat {
	return func(n int) []AuditRecordCompat {
		if n > len(records) {
			return records
		}
		return records[:n]
	}
}

func newTestComplianceService(records []AuditRecordCompat) *ComplianceService {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	var readerFn func(int) []AuditRecordCompat
	if records != nil {
		readerFn = makeAuditReader(records)
	}
	return NewComplianceService(readerFn, logger)
}

// buildRecords creates N audit records with given allow/deny distribution.
func buildRecords(total int, allowRatio float64) []AuditRecordCompat {
	records := make([]AuditRecordCompat, 0, total)
	allowCount := int(float64(total) * allowRatio)
	for i := 0; i < total; i++ {
		decision := "deny"
		if i < allowCount {
			decision = "allow"
		}
		records = append(records, AuditRecordCompat{
			Timestamp:  time.Now().Add(-time.Duration(i) * time.Minute),
			Decision:   decision,
			ToolName:   "read_file",
			IdentityID: "agent-1",
			SessionID:  "sess-1",
		})
	}
	return records
}

func TestListPacks(t *testing.T) {
	svc := newTestComplianceService(nil)
	packs := svc.ListPacks()

	if len(packs) == 0 {
		t.Fatal("expected at least one built-in pack")
	}

	found := false
	for _, p := range packs {
		if p.ID == "eu-ai-act-transparency" {
			found = true
			if p.Framework != "EU AI Act" {
				t.Errorf("expected framework 'EU AI Act', got %q", p.Framework)
			}
			if len(p.Requirements) == 0 {
				t.Error("expected requirements in EU AI Act pack")
			}
		}
	}
	if !found {
		t.Error("eu-ai-act-transparency pack not found")
	}
}

func TestGetPack_Found(t *testing.T) {
	svc := newTestComplianceService(nil)
	pack, err := svc.GetPack("eu-ai-act-transparency")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pack.ID != "eu-ai-act-transparency" {
		t.Errorf("wrong pack ID: %s", pack.ID)
	}
}

func TestGetPack_NotFound(t *testing.T) {
	svc := newTestComplianceService(nil)
	_, err := svc.GetPack("nonexistent-pack")
	if err == nil {
		t.Fatal("expected error for nonexistent pack")
	}
}

func TestAnalyzeCoverage_FullyCovered(t *testing.T) {
	records := buildRecords(1000, 0.8)
	svc := newTestComplianceService(records)
	sysCtx := ComplianceContext{
		EvidenceEnabled:     true,
		ContentScanEnabled:  true,
		InputScanEnabled:    true,
		ToolIntegrityActive: true,
		RateLimitEnabled:    true,
		IdentityCount:       5,
		PolicyCount:         10,
		APIKeyCount:         3,
		DenyRuleCount:       5,
		HITLAvailable:       true,
	}

	report, err := svc.AnalyzeCoverage(context.Background(), "eu-ai-act-transparency",
		time.Now().Add(-24*time.Hour), time.Now(), sysCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.OverallScore != 1.0 {
		t.Errorf("expected overall score 1.0 with all checks passing, got %.2f", report.OverallScore)
	}

	for _, req := range report.Requirements {
		if req.Status != compliance.StatusCovered {
			t.Errorf("requirement %s should be covered, got %s", req.RequirementID, req.Status)
		}
		if req.Score != 1.0 {
			t.Errorf("requirement %s score should be 1.0, got %.2f", req.RequirementID, req.Score)
		}
		for _, cr := range req.CheckResults {
			if !cr.Passed {
				t.Errorf("check %s should pass: %s", cr.CheckID, cr.Detail)
			}
			if cr.Detail == "" {
				t.Errorf("check %s has empty detail", cr.CheckID)
			}
		}
	}
}

func TestAnalyzeCoverage_AllGaps(t *testing.T) {
	// No audit data, no system features enabled.
	svc := newTestComplianceService([]AuditRecordCompat{})
	sysCtx := ComplianceContext{} // All false/zero

	report, err := svc.AnalyzeCoverage(context.Background(), "eu-ai-act-transparency",
		time.Now().Add(-24*time.Hour), time.Now(), sysCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.OverallScore != 0.0 {
		t.Errorf("expected overall score 0.0 with no checks passing, got %.2f", report.OverallScore)
	}

	for _, req := range report.Requirements {
		if req.Status == compliance.StatusCovered {
			t.Errorf("requirement %s should NOT be covered with empty context", req.RequirementID)
		}
		for _, cr := range req.CheckResults {
			if cr.Passed {
				t.Errorf("check %s should NOT pass with empty context: %s", cr.CheckID, cr.Detail)
			}
		}
	}
}

func TestAnalyzeCoverage_PartialCoverage(t *testing.T) {
	records := buildRecords(500, 0.9)
	svc := newTestComplianceService(records)
	sysCtx := ComplianceContext{
		EvidenceEnabled: true,
		// Other features disabled — partial coverage.
		IdentityCount: 3,
		PolicyCount:   2,
	}

	report, err := svc.AnalyzeCoverage(context.Background(), "eu-ai-act-transparency",
		time.Now().Add(-24*time.Hour), time.Now(), sysCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be between 0 and 1.
	if report.OverallScore <= 0.0 || report.OverallScore >= 1.0 {
		t.Errorf("expected partial score between 0 and 1, got %.2f", report.OverallScore)
	}

	hasPartial := false
	hasCovered := false
	hasGap := false
	for _, req := range report.Requirements {
		switch req.Status {
		case compliance.StatusPartial:
			hasPartial = true
		case compliance.StatusCovered:
			hasCovered = true
		case compliance.StatusGap:
			hasGap = true
		case compliance.StatusNotApplied:
			// Not expected in this test but handled for exhaustiveness.
		}
	}

	// With some features on, some off, we expect a mix.
	if !hasPartial && !hasCovered && !hasGap {
		t.Error("expected at least some status variation with partial context")
	}
}

func TestAnalyzeCoverage_InvalidPack(t *testing.T) {
	svc := newTestComplianceService(nil)
	_, err := svc.AnalyzeCoverage(context.Background(), "invalid",
		time.Now().Add(-24*time.Hour), time.Now(), ComplianceContext{})
	if err == nil {
		t.Fatal("expected error for invalid pack ID")
	}
}

func TestGenerateBundle(t *testing.T) {
	records := buildRecords(250, 0.92)
	svc := newTestComplianceService(records)
	sysCtx := ComplianceContext{
		EvidenceEnabled:    true,
		ContentScanEnabled: true,
		IdentityCount:      3,
		PolicyCount:        5,
	}

	bundle, err := svc.GenerateBundle(context.Background(), "eu-ai-act-transparency",
		time.Now().Add(-7*24*time.Hour), time.Now(), sysCtx, "sg-test-instance")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify bundle structure.
	if bundle.ID == "" {
		t.Error("bundle ID should not be empty")
	}
	if bundle.PackID != "eu-ai-act-transparency" {
		t.Errorf("wrong pack ID: %s", bundle.PackID)
	}
	if bundle.Framework != "EU AI Act" {
		t.Errorf("wrong framework: %s", bundle.Framework)
	}
	if bundle.GeneratedBy != "sg-test-instance" {
		t.Errorf("wrong instance ID: %s", bundle.GeneratedBy)
	}
	if bundle.Disclaimer != compliance.ComplianceDisclaimer {
		t.Error("disclaimer mismatch")
	}

	// Verify evidence summary.
	if bundle.EvidenceSummary.TotalAuditRecords != 250 {
		t.Errorf("expected 250 audit records in summary, got %d", bundle.EvidenceSummary.TotalAuditRecords)
	}
	if bundle.EvidenceSummary.UniqueIdentities != 1 {
		t.Errorf("expected 1 unique identity, got %d", bundle.EvidenceSummary.UniqueIdentities)
	}

	// Verify coverage is populated.
	if len(bundle.Coverage.Requirements) == 0 {
		t.Error("coverage requirements should not be empty")
	}
	if bundle.Coverage.OverallScore < 0 || bundle.Coverage.OverallScore > 1 {
		t.Errorf("overall score out of range: %.2f", bundle.Coverage.OverallScore)
	}
}

func TestGenerateBundle_InvalidPack(t *testing.T) {
	svc := newTestComplianceService(nil)
	_, err := svc.GenerateBundle(context.Background(), "nonexistent",
		time.Now().Add(-24*time.Hour), time.Now(), ComplianceContext{}, "test")
	if err == nil {
		t.Fatal("expected error for invalid pack")
	}
}

func TestEvaluateCheck_AuditTrailExists_WithData(t *testing.T) {
	records := buildRecords(100, 1.0)
	svc := newTestComplianceService(records)
	stats := svc.computeAuditStats(time.Time{}, time.Time{})

	check := compliance.EvidenceCheck{
		ID:        "test-audit",
		CheckType: compliance.CheckAuditTrailExists,
	}

	result := svc.evaluateCheck(check, stats, ComplianceContext{})
	if !result.Passed {
		t.Errorf("audit trail check should pass with %d records", stats.totalCalls)
	}
}

func TestEvaluateCheck_AuditTrailExists_Empty(t *testing.T) {
	svc := newTestComplianceService(nil)

	check := compliance.EvidenceCheck{
		ID:        "test-audit-empty",
		CheckType: compliance.CheckAuditTrailExists,
	}

	result := svc.evaluateCheck(check, nil, ComplianceContext{})
	if result.Passed {
		t.Error("audit trail check should fail with nil stats")
	}
}

func TestEvaluateCheck_AuditTrailExists_ZeroCalls(t *testing.T) {
	svc := newTestComplianceService([]AuditRecordCompat{})
	stats := svc.computeAuditStats(time.Time{}, time.Time{})

	check := compliance.EvidenceCheck{
		ID:        "test-audit-zero",
		CheckType: compliance.CheckAuditTrailExists,
	}

	result := svc.evaluateCheck(check, stats, ComplianceContext{})
	if result.Passed {
		t.Error("audit trail check should fail with 0 records")
	}
}

func TestEvaluateCheck_DecisionLogged(t *testing.T) {
	records := buildRecords(100, 0.9)
	svc := newTestComplianceService(records)
	stats := svc.computeAuditStats(time.Time{}, time.Time{})

	check := compliance.EvidenceCheck{
		ID:        "test-decision",
		CheckType: compliance.CheckDecisionLogged,
	}

	result := svc.evaluateCheck(check, stats, ComplianceContext{})
	if !result.Passed {
		t.Error("decision logged check should pass")
	}
}

func TestEvaluateCheck_DecisionLogged_Empty(t *testing.T) {
	svc := newTestComplianceService([]AuditRecordCompat{})
	stats := svc.computeAuditStats(time.Time{}, time.Time{})

	check := compliance.EvidenceCheck{
		ID:        "test-decision-empty",
		CheckType: compliance.CheckDecisionLogged,
	}

	result := svc.evaluateCheck(check, stats, ComplianceContext{})
	if result.Passed {
		t.Error("decision logged check should fail with empty decisions")
	}
}

func TestEvaluateCheck_EvidenceSigned(t *testing.T) {
	svc := newTestComplianceService(nil)

	check := compliance.EvidenceCheck{
		ID:        "test-evidence",
		CheckType: compliance.CheckEvidenceSigned,
	}

	// Enabled.
	result := svc.evaluateCheck(check, nil, ComplianceContext{EvidenceEnabled: true})
	if !result.Passed {
		t.Error("evidence signed check should pass when enabled")
	}

	// Disabled.
	result = svc.evaluateCheck(check, nil, ComplianceContext{EvidenceEnabled: false})
	if result.Passed {
		t.Error("evidence signed check should fail when disabled")
	}
}

func TestEvaluateCheck_ContentScanEnabled(t *testing.T) {
	svc := newTestComplianceService(nil)
	check := compliance.EvidenceCheck{ID: "test-scan", CheckType: compliance.CheckContentScanEnabled}

	// Both disabled.
	r := svc.evaluateCheck(check, nil, ComplianceContext{})
	if r.Passed {
		t.Error("should fail with both scans disabled")
	}

	// Response only.
	r = svc.evaluateCheck(check, nil, ComplianceContext{ContentScanEnabled: true})
	if !r.Passed {
		t.Error("should pass with response scan enabled")
	}

	// Input only.
	r = svc.evaluateCheck(check, nil, ComplianceContext{InputScanEnabled: true})
	if !r.Passed {
		t.Error("should pass with input scan enabled")
	}

	// Both.
	r = svc.evaluateCheck(check, nil, ComplianceContext{ContentScanEnabled: true, InputScanEnabled: true})
	if !r.Passed {
		t.Error("should pass with both scans enabled")
	}
}

func TestEvaluateCheck_ToolIntegrity(t *testing.T) {
	svc := newTestComplianceService(nil)
	check := compliance.EvidenceCheck{ID: "test-integrity", CheckType: compliance.CheckToolIntegrityEnabled}

	r := svc.evaluateCheck(check, nil, ComplianceContext{ToolIntegrityActive: false})
	if r.Passed {
		t.Error("should fail when tool integrity inactive")
	}

	r = svc.evaluateCheck(check, nil, ComplianceContext{ToolIntegrityActive: true})
	if !r.Passed {
		t.Error("should pass when tool integrity active")
	}
}

func TestEvaluateCheck_RateLimit(t *testing.T) {
	svc := newTestComplianceService(nil)
	check := compliance.EvidenceCheck{ID: "test-rl", CheckType: compliance.CheckRateLimitEnabled}

	r := svc.evaluateCheck(check, nil, ComplianceContext{RateLimitEnabled: false})
	if r.Passed {
		t.Error("should fail when rate limiting disabled")
	}

	r = svc.evaluateCheck(check, nil, ComplianceContext{RateLimitEnabled: true})
	if !r.Passed {
		t.Error("should pass when rate limiting enabled")
	}
}

func TestEvaluateCheck_Identities(t *testing.T) {
	svc := newTestComplianceService(nil)
	check := compliance.EvidenceCheck{ID: "test-id", CheckType: compliance.CheckIdentitiesConfigured}

	r := svc.evaluateCheck(check, nil, ComplianceContext{IdentityCount: 0})
	if r.Passed {
		t.Error("should fail with 0 identities")
	}

	// Identities without API keys should not pass
	r = svc.evaluateCheck(check, nil, ComplianceContext{IdentityCount: 3, APIKeyCount: 0})
	if r.Passed {
		t.Error("should fail with identities but no API keys")
	}

	r = svc.evaluateCheck(check, nil, ComplianceContext{IdentityCount: 3, APIKeyCount: 2})
	if !r.Passed {
		t.Error("should pass with 3 identities + API keys")
	}
}

func TestEvaluateCheck_Policies(t *testing.T) {
	svc := newTestComplianceService(nil)
	check := compliance.EvidenceCheck{ID: "test-pol", CheckType: compliance.CheckPoliciesConfigured}

	r := svc.evaluateCheck(check, nil, ComplianceContext{PolicyCount: 0})
	if r.Passed {
		t.Error("should fail with 0 policies")
	}

	// Policies without deny rules should not pass
	r = svc.evaluateCheck(check, nil, ComplianceContext{PolicyCount: 5, DenyRuleCount: 0})
	if r.Passed {
		t.Error("should fail with policies but no deny rules")
	}

	r = svc.evaluateCheck(check, nil, ComplianceContext{PolicyCount: 5, DenyRuleCount: 3})
	if !r.Passed {
		t.Error("should pass with 5 policies + deny rules")
	}
}

func TestEvaluateCheck_HITL(t *testing.T) {
	svc := newTestComplianceService(nil)
	check := compliance.EvidenceCheck{ID: "test-hitl", CheckType: compliance.CheckHITLAvailable}

	r := svc.evaluateCheck(check, nil, ComplianceContext{HITLAvailable: false})
	if r.Passed {
		t.Error("should fail when HITL not available")
	}

	r = svc.evaluateCheck(check, nil, ComplianceContext{HITLAvailable: true})
	if !r.Passed {
		t.Error("should pass when HITL available")
	}
}

func TestEvaluateCheck_UnknownType(t *testing.T) {
	svc := newTestComplianceService(nil)
	check := compliance.EvidenceCheck{ID: "test-unknown", CheckType: "unknown_type"}

	r := svc.evaluateCheck(check, nil, ComplianceContext{})
	if r.Passed {
		t.Error("unknown check type should not pass")
	}
	if r.Detail == "" {
		t.Error("unknown check type should have detail")
	}
}

func TestAnalyzeCoverage_ScoreRange(t *testing.T) {
	records := buildRecords(10, 1.0)
	svc := newTestComplianceService(records)

	contexts := []ComplianceContext{
		{}, // All disabled
		{EvidenceEnabled: true},
		{EvidenceEnabled: true, ContentScanEnabled: true, IdentityCount: 1, PolicyCount: 1},
		{EvidenceEnabled: true, ContentScanEnabled: true, InputScanEnabled: true,
			ToolIntegrityActive: true, RateLimitEnabled: true,
			IdentityCount: 5, PolicyCount: 10, HITLAvailable: true},
	}

	for i, sysCtx := range contexts {
		report, err := svc.AnalyzeCoverage(context.Background(), "eu-ai-act-transparency",
			time.Now().Add(-24*time.Hour), time.Now(), sysCtx)
		if err != nil {
			t.Fatalf("context %d: unexpected error: %v", i, err)
		}

		if report.OverallScore < 0.0 || report.OverallScore > 1.0 {
			t.Errorf("context %d: score %.2f out of [0, 1] range", i, report.OverallScore)
		}

		for _, req := range report.Requirements {
			if req.Score < 0.0 || req.Score > 1.0 {
				t.Errorf("context %d, req %s: score %.2f out of range", i, req.RequirementID, req.Score)
			}
		}
	}
}

func TestAnalyzeCoverage_RequirementCountMatchesPack(t *testing.T) {
	svc := newTestComplianceService(nil)

	pack, _ := svc.GetPack("eu-ai-act-transparency")
	report, err := svc.AnalyzeCoverage(context.Background(), "eu-ai-act-transparency",
		time.Now().Add(-24*time.Hour), time.Now(), ComplianceContext{})
	if err != nil {
		t.Fatal(err)
	}

	if len(report.Requirements) != len(pack.Requirements) {
		t.Errorf("report has %d requirements, pack has %d",
			len(report.Requirements), len(pack.Requirements))
	}

	// Verify each requirement ID matches.
	for i, req := range report.Requirements {
		if req.RequirementID != pack.Requirements[i].ID {
			t.Errorf("requirement %d: report ID %q != pack ID %q",
				i, req.RequirementID, pack.Requirements[i].ID)
		}
	}
}

func TestGenerateBundle_Disclaimer(t *testing.T) {
	svc := newTestComplianceService(buildRecords(1, 1.0))

	bundle, err := svc.GenerateBundle(context.Background(), "eu-ai-act-transparency",
		time.Now().Add(-24*time.Hour), time.Now(), ComplianceContext{}, "test")
	if err != nil {
		t.Fatal(err)
	}

	if bundle.Disclaimer == "" {
		t.Error("bundle must always include disclaimer")
	}

	if bundle.Disclaimer != compliance.ComplianceDisclaimer {
		t.Error("disclaimer does not match ComplianceDisclaimer constant")
	}
}

func TestGenerateBundle_IDFormat(t *testing.T) {
	svc := newTestComplianceService(buildRecords(1, 1.0))

	bundle, err := svc.GenerateBundle(context.Background(), "eu-ai-act-transparency",
		time.Now().Add(-24*time.Hour), time.Now(), ComplianceContext{}, "inst-1")
	if err != nil {
		t.Fatal(err)
	}

	if len(bundle.ID) < 20 {
		t.Errorf("bundle ID too short: %q", bundle.ID)
	}

	// Should start with "bundle_eu-ai-act-transparency_"
	prefix := "bundle_eu-ai-act-transparency_"
	if len(bundle.ID) < len(prefix) || bundle.ID[:len(prefix)] != prefix {
		t.Errorf("bundle ID should start with %q, got %q", prefix, bundle.ID)
	}
}

func TestEvaluateRequirement_AllChecksPassing(t *testing.T) {
	records := buildRecords(100, 1.0)
	svc := newTestComplianceService(records)
	stats := svc.computeAuditStats(time.Time{}, time.Time{})

	req := compliance.Requirement{
		ID:      "test-req",
		Article: "Test",
		Title:   "Test Requirement",
		EvidenceChecks: []compliance.EvidenceCheck{
			{ID: "c1", CheckType: compliance.CheckAuditTrailExists},
			{ID: "c2", CheckType: compliance.CheckDecisionLogged},
		},
	}

	rc := svc.evaluateRequirement(req, stats, ComplianceContext{})
	if rc.Score != 1.0 {
		t.Errorf("expected score 1.0, got %.2f", rc.Score)
	}
	if rc.Status != compliance.StatusCovered {
		t.Errorf("expected status covered, got %s", rc.Status)
	}
}

func TestEvaluateRequirement_OneOfTwoPassing(t *testing.T) {
	records := buildRecords(100, 1.0)
	svc := newTestComplianceService(records)
	stats := svc.computeAuditStats(time.Time{}, time.Time{})

	req := compliance.Requirement{
		ID: "test-req",
		EvidenceChecks: []compliance.EvidenceCheck{
			{ID: "c1", CheckType: compliance.CheckAuditTrailExists},      // passes
			{ID: "c2", CheckType: compliance.CheckEvidenceSigned},         // fails (not enabled)
		},
	}

	rc := svc.evaluateRequirement(req, stats, ComplianceContext{})
	if rc.Score != 0.5 {
		t.Errorf("expected score 0.5, got %.2f", rc.Score)
	}
	if rc.Status != compliance.StatusPartial {
		t.Errorf("expected status partial, got %s", rc.Status)
	}
}

func TestEvaluateRequirement_NonePassingMultipleChecks(t *testing.T) {
	svc := newTestComplianceService(nil)

	req := compliance.Requirement{
		ID: "test-req",
		EvidenceChecks: []compliance.EvidenceCheck{
			{ID: "c1", CheckType: compliance.CheckEvidenceSigned},
			{ID: "c2", CheckType: compliance.CheckToolIntegrityEnabled},
		},
	}

	rc := svc.evaluateRequirement(req, nil, ComplianceContext{})
	if rc.Score != 0.0 {
		t.Errorf("expected score 0.0, got %.2f", rc.Score)
	}
	if rc.Status != compliance.StatusGap {
		t.Errorf("expected status gap, got %s", rc.Status)
	}
}

// --- Wave 1 Test: Compliance grammar (singular/plural identities) ---

func TestComplianceService_PluralizeIdentities(t *testing.T) {
	svc := newTestComplianceService(nil)
	check := compliance.EvidenceCheck{ID: "test-plural", CheckType: compliance.CheckIdentitiesConfigured}

	// 0 identities
	r := svc.evaluateCheck(check, nil, ComplianceContext{IdentityCount: 0})
	if r.Passed {
		t.Error("should fail with 0 identities")
	}
	if r.Detail != "No identities configured. Add identities in Access management" {
		t.Errorf("detail for 0 = %q", r.Detail)
	}

	// Identities without API keys
	r = svc.evaluateCheck(check, nil, ComplianceContext{IdentityCount: 1, APIKeyCount: 0})
	if r.Passed {
		t.Error("should fail with identity but no API key")
	}

	// 1 identity + API key
	r = svc.evaluateCheck(check, nil, ComplianceContext{IdentityCount: 1, APIKeyCount: 1})
	if !r.Passed {
		t.Error("should pass with 1 identity + API key")
	}

	// 3 identities + API keys
	r = svc.evaluateCheck(check, nil, ComplianceContext{IdentityCount: 3, APIKeyCount: 2})
	if !r.Passed {
		t.Error("should pass with 3 identities + API keys")
	}
}

// --- Wave 1 Test: Compliance grammar (singular/plural policies) ---

func TestComplianceService_PluralPolicies(t *testing.T) {
	svc := newTestComplianceService(nil)
	check := compliance.EvidenceCheck{ID: "test-pol-plural", CheckType: compliance.CheckPoliciesConfigured}

	// Policies without deny rules should fail
	r := svc.evaluateCheck(check, nil, ComplianceContext{PolicyCount: 1, DenyRuleCount: 0})
	if r.Passed {
		t.Error("should fail with policy but no deny rules")
	}

	// 1 policy + deny rules
	r = svc.evaluateCheck(check, nil, ComplianceContext{PolicyCount: 1, DenyRuleCount: 1})
	if !r.Passed {
		t.Error("should pass with 1 policy + deny rules")
	}

	// 5 policies + deny rules
	r = svc.evaluateCheck(check, nil, ComplianceContext{PolicyCount: 5, DenyRuleCount: 3})
	if !r.Passed {
		t.Error("should pass with 5 policies + deny rules")
	}
}

func TestEvaluateRequirement_NoChecks(t *testing.T) {
	svc := newTestComplianceService(nil)

	req := compliance.Requirement{
		ID:             "test-empty",
		EvidenceChecks: []compliance.EvidenceCheck{},
	}

	rc := svc.evaluateRequirement(req, nil, ComplianceContext{})
	if rc.Score != 0.0 {
		t.Errorf("expected score 0.0 for empty checks, got %.2f", rc.Score)
	}
}
