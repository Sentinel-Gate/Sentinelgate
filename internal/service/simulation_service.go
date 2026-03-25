package service

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/cel-go/cel"

	celeval "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/cel"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// CandidateRule represents a rule being built that should be included in simulation.
type CandidateRule struct {
	ToolMatch string `json:"tool_match"`
	Action    string `json:"action"`
	Priority  int    `json:"priority"`
	Condition string `json:"condition,omitempty"`
}

// SimulationRequest defines the parameters for a policy simulation.
type SimulationRequest struct {
	// PolicyRules are the rules to simulate against (new or modified).
	PolicyRules []policy.Rule `json:"policy_rules"`
	// CandidateRules are rules being built that should be included in the simulation.
	// Their CEL conditions are compiled and evaluated against each audit record.
	CandidateRules []CandidateRule `json:"candidate_rules,omitempty"`
	// Period defines the audit time range to replay.
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	// MaxRecords limits how many audit records to process (default 1000).
	MaxRecords int `json:"max_records"`
	// ToolMatch filters impacted tools to those matching this glob pattern.
	ToolMatch string `json:"tool_match"`
}

// SimulationResult is the output of a policy simulation.
type SimulationResult struct {
	// TotalProcessed is the number of raw audit records before filtering.
	TotalProcessed int `json:"total_processed"`
	// TotalAnalyzed is the number of audit records processed.
	TotalAnalyzed int `json:"total_analyzed"`
	// Changed is the number of records whose decision would differ.
	Changed int `json:"changed"`
	// Unchanged is the number of records whose decision stays the same.
	Unchanged int `json:"unchanged"`
	// AllowToDeny is the count of calls that would be newly blocked.
	AllowToDeny int `json:"allow_to_deny"`
	// DenyToAllow is the count of calls that would be newly allowed.
	DenyToAllow int `json:"deny_to_allow"`
	// ImpactedAgents lists identities whose calls would change.
	ImpactedAgents []string `json:"impacted_agents"`
	// ImpactedTools lists tools whose calls would change.
	ImpactedTools []string `json:"impacted_tools"`
	// Details contains per-record simulation results (limited to changed records).
	Details []SimulationDetail `json:"details"`
	// Duration is how long the simulation took.
	DurationMs int64 `json:"duration_ms"`
}

// SimulationDetail describes a single record where the decision would change.
type SimulationDetail struct {
	Timestamp        string `json:"timestamp"`
	ToolName         string `json:"tool_name"`
	IdentityID       string `json:"identity_id"`
	IdentityName     string `json:"identity_name,omitempty"`
	OriginalDecision string `json:"original_decision"`
	NewDecision      string `json:"new_decision"`
	NewRuleID        string `json:"new_rule_id,omitempty"`
	NewRuleName      string `json:"new_rule_name,omitempty"`
	NewReason        string `json:"new_reason,omitempty"`
}

// SimulationService replays audit traffic against candidate policy rules.
type SimulationService struct {
	policyService *PolicyService
	auditReader   func(n int) []audit.AuditRecord
	logger        *slog.Logger
}

// NewSimulationService creates a new simulation service.
// auditReaderFn returns the N most recent audit records.
func NewSimulationService(policyService *PolicyService, auditReaderFn func(n int) []audit.AuditRecord, logger *slog.Logger) *SimulationService {
	return &SimulationService{
		policyService: policyService,
		auditReader:   auditReaderFn,
		logger:        logger,
	}
}

// Simulate re-evaluates historical audit records against candidate policy rules.
func (s *SimulationService) Simulate(ctx context.Context, req SimulationRequest) (*SimulationResult, error) {
	start := time.Now()

	maxRecords := req.MaxRecords
	if maxRecords <= 0 || maxRecords > 10000 {
		maxRecords = 1000
	}

	// Get audit records.
	var records []audit.AuditRecord
	if s.auditReader != nil {
		records = s.auditReader(maxRecords)
	}

	if len(records) == 0 {
		return &SimulationResult{DurationMs: time.Since(start).Milliseconds()}, nil
	}

	// Pre-compile candidate rules' CEL conditions for full evaluation.
	type compiledCandidate struct {
		ToolMatch string
		Action    string
		Priority  int
		Program   cel.Program // nil if condition is empty/true (matches all)
	}
	var candidates []compiledCandidate
	var celEvaluator *celeval.Evaluator
	if len(req.CandidateRules) > 0 {
		celEvaluator = s.policyService.CELEvaluator()
		for _, cr := range req.CandidateRules {
			cc := compiledCandidate{
				ToolMatch: cr.ToolMatch,
				Action:    strings.ToLower(cr.Action),
				Priority:  cr.Priority,
			}
			if cr.Condition != "" && cr.Condition != "true" {
				prg, err := celEvaluator.Compile(cr.Condition)
				if err != nil {
					s.logger.Warn("candidate rule CEL compile failed, skipping rule", "condition", cr.Condition, "error", err)
					continue // skip this candidate entirely — invalid CEL should not match anything
				}
				cc.Program = prg
			}
			candidates = append(candidates, cc)
		}
	}

	// Replay audit records against current rules + candidate rules.
	impactedAgentSet := make(map[string]bool)
	impactedToolSet := make(map[string]bool)
	var details []SimulationDetail
	changed := 0
	unchanged := 0
	allowToDeny := 0
	denyToAllow := 0

	for _, rec := range records {
		// Skip records without meaningful tool calls.
		if rec.ToolName == "" {
			continue
		}

		// Build evaluation context from the audit record.
		evalCtx := policy.EvaluationContext{
			ToolName:     rec.ToolName,
			IdentityID:   rec.IdentityID,
			IdentityName: rec.IdentityName,
			Protocol:     rec.Protocol,
			SessionID:    rec.SessionID,
			RequestTime:  rec.Timestamp,
			SkipCache:    true,
		}
		if rec.ToolArguments != nil {
			evalCtx.ToolArguments = rec.ToolArguments
		}

		// Evaluate against the current policy rules.
		newDecision, err := s.policyService.Evaluate(ctx, evalCtx)
		if err != nil {
			s.logger.Debug("simulation eval error", "tool", rec.ToolName, "error", err)
			continue
		}

		newDecisionStr := "allow"
		if newDecision.RequiresApproval {
			newDecisionStr = "approval_required"
		} else if !newDecision.Allowed {
			newDecisionStr = "deny"
		}
		newRuleID := newDecision.RuleID
		newRuleName := newDecision.RuleName
		newReason := newDecision.Reason

		// If candidate rules are provided, check if any would override the current decision.
		// Uses filepath.Match + CEL evaluation, matching production policy_service.go behavior.
		if len(candidates) > 0 {
			for _, cc := range candidates {
				// 1. Check tool_match glob (mirrors PolicyService.Evaluate logic)
				toolMatched := false
				if cc.ToolMatch == "*" || cc.ToolMatch == rec.ToolName {
					toolMatched = true
				} else if cc.ToolMatch != "" {
					if m, _ := filepath.Match(cc.ToolMatch, rec.ToolName); m {
						toolMatched = true
					}
					// Workaround: bare patterns like "read_*" should match namespaced "desktop/read_file"
					if !toolMatched && !strings.Contains(cc.ToolMatch, "/") {
						if slashIdx := strings.Index(rec.ToolName, "/"); slashIdx >= 0 {
							barePart := rec.ToolName[slashIdx+1:]
							toolMatched, _ = filepath.Match(cc.ToolMatch, barePart)
						}
					}
				}
				if !toolMatched {
					continue
				}
				// 2. Evaluate CEL condition (if present)
				if cc.Program != nil && celEvaluator != nil {
					condResult, err := celEvaluator.Evaluate(ctx, cc.Program, evalCtx)
					if err != nil {
						s.logger.Debug("candidate CEL eval error", "tool", rec.ToolName, "error", err)
						continue
					}
					if !condResult {
						continue // condition didn't match this record
					}
				}
				// 3. Candidate rule matches — check if it would override (same or higher priority wins)
				if cc.Priority >= newDecision.Priority {
					switch cc.Action {
					case "allow":
						newDecisionStr = "allow"
					case "approval_required":
						newDecisionStr = "approval_required"
					default:
						newDecisionStr = "deny"
					}
					newRuleID = ""
					newRuleName = "candidate rule"
					newReason = "matched candidate rule (" + cc.ToolMatch + ")"
				}
			}
		}

		// Normalize original decision: "blocked" (quota deny) → "deny", "warn" (quota pass) → "allow"
		originalDecision := rec.Decision
		switch originalDecision {
		case "blocked":
			originalDecision = "deny"
		case "warn":
			originalDecision = "allow"
		}

		if newDecisionStr == originalDecision {
			unchanged++
			continue
		}

		changed++
		impactedAgentSet[rec.IdentityID] = true
		impactedToolSet[rec.ToolName] = true

		originalBlocking := originalDecision == "deny" || originalDecision == "approval_required"
		newBlocking := newDecisionStr == "deny" || newDecisionStr == "approval_required"
		if !originalBlocking && newBlocking {
			allowToDeny++
		} else if originalBlocking && !newBlocking {
			denyToAllow++
		}

		// Only keep first 100 changed details to limit response size.
		if len(details) < 100 {
			details = append(details, SimulationDetail{
				Timestamp:        rec.Timestamp.Format(time.RFC3339),
				ToolName:         rec.ToolName,
				IdentityID:       rec.IdentityID,
				IdentityName:     rec.IdentityName,
				OriginalDecision: originalDecision,
				NewDecision:      newDecisionStr,
				NewRuleID:        newRuleID,
				NewRuleName:      newRuleName,
				NewReason:        newReason,
			})
		}
	}

	impactedAgents := make([]string, 0, len(impactedAgentSet))
	for agent := range impactedAgentSet {
		impactedAgents = append(impactedAgents, agent)
	}
	impactedTools := make([]string, 0, len(impactedToolSet))
	for tool := range impactedToolSet {
		// Filter by tool_match pattern if provided.
		if req.ToolMatch != "" && req.ToolMatch != "*" {
			if matched, _ := filepath.Match(req.ToolMatch, tool); !matched {
				continue
			}
		}
		impactedTools = append(impactedTools, tool)
	}

	return &SimulationResult{
		TotalProcessed: len(records),
		TotalAnalyzed:  changed + unchanged,
		Changed:        changed,
		Unchanged:      unchanged,
		AllowToDeny:    allowToDeny,
		DenyToAllow:    denyToAllow,
		ImpactedAgents: impactedAgents,
		ImpactedTools:  impactedTools,
		Details:        details,
		DurationMs:     time.Since(start).Milliseconds(),
	}, nil
}
