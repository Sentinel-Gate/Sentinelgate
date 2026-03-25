// Package compliance provides types for mapping audit evidence to regulatory requirements.
//
// SentinelGate produces technical evidence that supports compliance — it does not
// replace legal review. Every generated bundle includes a disclaimer.
package compliance

import "time"

// PolicyPack defines a compliance framework with its requirements.
type PolicyPack struct {
	// ID is the unique identifier (e.g., "eu-ai-act-transparency").
	ID string `json:"id"`
	// Name is the human-readable name (e.g., "EU AI Act — Transparency").
	Name string `json:"name"`
	// Description explains what this pack covers.
	Description string `json:"description"`
	// Framework is the regulatory framework (e.g., "EU AI Act", "SOC2").
	Framework string `json:"framework"`
	// Version is the pack version for tracking updates.
	Version string `json:"version"`
	// Requirements lists the individual regulatory requirements.
	Requirements []Requirement `json:"requirements"`
}

// Requirement is a single regulatory requirement within a pack.
type Requirement struct {
	// ID is a stable identifier (e.g., "art-13-1").
	ID string `json:"id"`
	// Article is the regulation article reference (e.g., "Art. 13(1)").
	Article string `json:"article"`
	// Title is a short name (e.g., "Transparency of AI Systems").
	Title string `json:"title"`
	// Description explains what the requirement mandates.
	Description string `json:"description"`
	// EvidenceChecks are the checks that determine coverage.
	EvidenceChecks []EvidenceCheck `json:"evidence_checks"`
}

// EvidenceCheck defines how to verify that a requirement is met.
type EvidenceCheck struct {
	// ID identifies this specific check (e.g., "art-13-1-audit-trail").
	ID string `json:"id"`
	// Description explains what this check verifies.
	Description string `json:"description"`
	// CheckType is the kind of evidence to look for.
	CheckType CheckType `json:"check_type"`
	// Source identifies where SG produces this evidence.
	Source string `json:"source"`
}

// CheckType determines what kind of evidence an EvidenceCheck looks for.
type CheckType string

const (
	// CheckAuditTrailExists verifies audit records exist for the time period.
	CheckAuditTrailExists CheckType = "audit_trail_exists"
	// CheckDecisionLogged verifies policy decisions are logged with reasons.
	CheckDecisionLogged CheckType = "decision_logged"
	// CheckEvidenceSigned verifies evidence records are cryptographically signed.
	CheckEvidenceSigned CheckType = "evidence_signed"
	// CheckContentScanEnabled verifies content scanning is active.
	CheckContentScanEnabled CheckType = "content_scan_enabled"
	// CheckToolIntegrityEnabled verifies tool integrity checking is active.
	CheckToolIntegrityEnabled CheckType = "tool_integrity_enabled"
	// CheckRateLimitEnabled verifies rate limiting is configured.
	CheckRateLimitEnabled CheckType = "rate_limit_enabled"
	// CheckIdentitiesConfigured verifies identities with roles exist.
	CheckIdentitiesConfigured CheckType = "identities_configured"
	// CheckPoliciesConfigured verifies access control policies exist.
	CheckPoliciesConfigured CheckType = "policies_configured"
	// CheckHITLAvailable verifies human-in-the-loop approval is available.
	CheckHITLAvailable CheckType = "hitl_available"
)

// CoverageStatus indicates how well a requirement is covered.
type CoverageStatus string

const (
	StatusCovered    CoverageStatus = "covered"     // Fully evidenced
	StatusPartial    CoverageStatus = "partial"     // Some evidence, gaps remain
	StatusGap        CoverageStatus = "gap"         // No evidence found
	StatusNotApplied CoverageStatus = "not_applied" // Requirement doesn't apply
)

// RequirementCoverage is the coverage analysis result for a single requirement.
type RequirementCoverage struct {
	RequirementID string         `json:"requirement_id"`
	Article       string         `json:"article"`
	Title         string         `json:"title"`
	Status        CoverageStatus `json:"status"`
	Score         float64        `json:"score"` // 0.0 to 1.0
	CheckResults  []CheckResult  `json:"check_results"`
}

// CheckResult is the outcome of evaluating a single evidence check.
type CheckResult struct {
	CheckID     string `json:"check_id"`
	Description string `json:"description"`
	Passed      bool   `json:"passed"`
	Detail      string `json:"detail"` // Human-readable explanation
	Source      string `json:"source"` // Where the evidence came from
}

// CoverageReport is the full coverage analysis for a policy pack.
type CoverageReport struct {
	PackID       string                `json:"pack_id"`
	PackName     string                `json:"pack_name"`
	Framework    string                `json:"framework"`
	Period       CoveragePeriod        `json:"period"`
	OverallScore float64               `json:"overall_score"` // 0.0 to 1.0
	Requirements []RequirementCoverage `json:"requirements"`
	GeneratedAt  time.Time             `json:"generated_at"`
}

// CoveragePeriod specifies the time range analyzed.
type CoveragePeriod struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Bundle is a complete compliance evidence package.
type Bundle struct {
	// Metadata
	ID          string    `json:"id"`
	PackID      string    `json:"pack_id"`
	PackName    string    `json:"pack_name"`
	Framework   string    `json:"framework"`
	GeneratedAt time.Time `json:"generated_at"`
	GeneratedBy string    `json:"generated_by"` // SentinelGate instance ID

	// Coverage analysis
	Coverage CoverageReport `json:"coverage"`

	// Evidence summary
	EvidenceSummary EvidenceSummary `json:"evidence_summary"`

	// AuditRecords contains a sample of actual audit records from the period.
	// Capped at MaxBundleAuditRecords to keep bundle size manageable.
	AuditRecords []AuditRecordSummary `json:"audit_records"`

	// Disclaimer (always present)
	Disclaimer string `json:"disclaimer"`
}

// MaxBundleAuditRecords is the maximum number of audit records included in a bundle.
const MaxBundleAuditRecords = 100

// AuditRecordSummary is a minimal audit record representation for inclusion in bundles.
type AuditRecordSummary struct {
	Timestamp      time.Time `json:"timestamp"`
	IdentityID     string    `json:"identity_id"`
	IdentityName   string    `json:"identity_name,omitempty"`
	SessionID      string    `json:"session_id"`
	ToolName       string    `json:"tool_name"`
	Decision       string    `json:"decision"`
	Reason         string    `json:"reason,omitempty"`
	RequestArgs    map[string]interface{} `json:"request_args,omitempty"`
	ScanDetections int                    `json:"scan_detections,omitempty"`
	ScanTypes      string                 `json:"scan_types,omitempty"`
}

// EvidenceSummary provides aggregate statistics about the evidence collected.
type EvidenceSummary struct {
	TotalAuditRecords int64            `json:"total_audit_records"`
	UniqueIdentities  int64            `json:"unique_identities"`
	UniqueSessions    int64            `json:"unique_sessions"`
	UniqueTools       int64            `json:"unique_tools"`
	DecisionBreakdown map[string]int64 `json:"decision_breakdown"` // allow/deny counts
	Period            CoveragePeriod   `json:"period"`
}

// ComplianceDisclaimer is the standard disclaimer included in every bundle.
const ComplianceDisclaimer = "This bundle contains technical evidence produced automatically " +
	"by SentinelGate. It does not constitute legal advice nor certification of compliance. " +
	"Compliance assessment requires independent legal analysis. The evidence documents " +
	"what occurred (who, what, when, with what authorization); the evaluation of " +
	"conformity remains the responsibility of the client and their legal counsel."
