// Package service contains application services.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// PolicyEvaluateRequest represents a policy evaluation request from the API.
// It accepts a CanonicalAction representation and identity information.
type PolicyEvaluateRequest struct {
	ActionType    string                 `json:"action_type"`
	ActionName    string                 `json:"action_name"`
	Protocol      string                 `json:"protocol"`
	Framework     string                 `json:"framework,omitempty"`
	Gateway       string                 `json:"gateway,omitempty"`
	Arguments     map[string]interface{} `json:"arguments,omitempty"`
	IdentityName  string                 `json:"identity_name"`
	IdentityRoles []string               `json:"identity_roles"`
	Destination   *DestinationRequest    `json:"destination,omitempty"`
}

// DestinationRequest represents destination details for an evaluation request.
type DestinationRequest struct {
	URL     string `json:"url,omitempty"`
	Domain  string `json:"domain,omitempty"`
	IP      string `json:"ip,omitempty"`
	Port    int    `json:"port,omitempty"`
	Scheme  string `json:"scheme,omitempty"`
	Path    string `json:"path,omitempty"`
	Command string `json:"command,omitempty"`
}

// PolicyEvaluateResponse represents the structured result of a policy evaluation.
type PolicyEvaluateResponse struct {
	Decision  string `json:"decision"`
	RuleID    string `json:"rule_id,omitempty"`
	RuleName  string `json:"rule_name,omitempty"`
	Reason    string `json:"reason"`
	HelpURL   string `json:"help_url,omitempty"`
	HelpText  string `json:"help_text,omitempty"`
	RequestID string `json:"request_id"`
	LatencyMs int64  `json:"latency_ms"`
}

// PolicyEvaluation represents a stored evaluation record.
type PolicyEvaluation struct {
	RequestID  string    `json:"request_id"`
	ActionType string    `json:"action_type"`
	ActionName string    `json:"action_name"`
	Protocol   string    `json:"protocol"`
	Gateway    string    `json:"gateway"`
	Framework  string    `json:"framework,omitempty"`
	Decision   string    `json:"decision"`
	RuleID     string    `json:"rule_id,omitempty"`
	LatencyMs  int64     `json:"latency_ms"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// PolicyEvaluationService handles policy evaluation requests from the API.
// It wraps the core PolicyService, adds evaluation tracking (latency, protocol),
// and generates helpful deny messages.
type PolicyEvaluationService struct {
	policyEngine policy.PolicyEngine
	policyStore  policy.PolicyStore
	stateStore   *state.FileStateStore
	logger       *slog.Logger

	// In-memory evaluation store for status polling.
	mu          sync.RWMutex
	evaluations map[string]*PolicyEvaluation // keyed by request_id
	evalOrder   []string                     // FIFO order for eviction
	maxEvals    int
}

// NewPolicyEvaluationService creates a new PolicyEvaluationService.
func NewPolicyEvaluationService(
	engine policy.PolicyEngine,
	store policy.PolicyStore,
	stateStore *state.FileStateStore,
	logger *slog.Logger,
) *PolicyEvaluationService {
	return &PolicyEvaluationService{
		policyEngine: engine,
		policyStore:  store,
		stateStore:   stateStore,
		logger:       logger,
		evaluations:  make(map[string]*PolicyEvaluation),
		evalOrder:    make([]string, 0, 1000),
		maxEvals:     1000,
	}
}

// Evaluate processes a policy evaluation request.
// It converts the request to an EvaluationContext, evaluates it, and returns
// a structured response with helpful deny information.
func (s *PolicyEvaluationService) Evaluate(ctx context.Context, req PolicyEvaluateRequest) (*PolicyEvaluateResponse, error) {
	requestID := uuid.New().String()
	start := time.Now()

	// Convert request to EvaluationContext.
	evalCtx := s.buildEvalContext(req)

	// Evaluate against policy engine.
	decision, err := s.policyEngine.Evaluate(ctx, evalCtx)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	latencyMs := time.Since(start).Milliseconds()

	// Build response.
	resp := &PolicyEvaluateResponse{
		RequestID: requestID,
		RuleID:    decision.RuleID,
		RuleName:  decision.RuleName,
		Reason:    decision.Reason,
		LatencyMs: latencyMs,
	}

	// Determine decision string.
	switch {
	case decision.RequiresApproval:
		resp.Decision = "approval_required"
	case decision.Allowed:
		resp.Decision = "allow"
	default:
		resp.Decision = "deny"
	}

	// Generate helpful deny information.
	if resp.Decision == "deny" || resp.Decision == "approval_required" {
		resp.HelpURL = GenerateHelpURL(decision.RuleID)
		resp.HelpText = GenerateHelpText(decision)
	}

	// Store evaluation record (non-blocking).
	now := time.Now().UTC()
	eval := &PolicyEvaluation{
		RequestID:  requestID,
		ActionType: req.ActionType,
		ActionName: req.ActionName,
		Protocol:   req.Protocol,
		Gateway:    req.Gateway,
		Framework:  req.Framework,
		Decision:   resp.Decision,
		RuleID:     decision.RuleID,
		LatencyMs:  latencyMs,
		Status:     resp.Decision,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	s.storeEvaluation(eval)

	s.logger.Debug("policy evaluation completed",
		"request_id", requestID,
		"action_type", req.ActionType,
		"action_name", req.ActionName,
		"decision", resp.Decision,
		"latency_ms", latencyMs,
	)

	return resp, nil
}

// GetEvaluationStatus returns the status of a policy evaluation by request ID.
// Returns nil if the evaluation is not found.
func (s *PolicyEvaluationService) GetEvaluationStatus(requestID string) *PolicyEvaluation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.evaluations[requestID]
}

// ClearEvaluations removes all stored evaluation records.
// Used by factory reset to discard stale evaluation history.
func (s *PolicyEvaluationService) ClearEvaluations() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evaluations = make(map[string]*PolicyEvaluation)
	s.evalOrder = make([]string, 0, s.maxEvals)
}

// buildEvalContext converts a PolicyEvaluateRequest to a policy.EvaluationContext.
func (s *PolicyEvaluationService) buildEvalContext(req PolicyEvaluateRequest) policy.EvaluationContext {
	evalCtx := policy.EvaluationContext{
		ToolName:      req.ActionName,
		ToolArguments: req.Arguments,
		UserRoles:     req.IdentityRoles,
		IdentityName:  req.IdentityName,
		RequestTime:   time.Now(),
		ActionType:    req.ActionType,
		ActionName:    req.ActionName,
		Protocol:      req.Protocol,
		Gateway:       req.Gateway,
		Framework:     req.Framework,
	}

	if req.Destination != nil {
		evalCtx.DestURL = req.Destination.URL
		evalCtx.DestDomain = req.Destination.Domain
		evalCtx.DestIP = req.Destination.IP
		evalCtx.DestPort = req.Destination.Port
		evalCtx.DestScheme = req.Destination.Scheme
		evalCtx.DestPath = req.Destination.Path
		evalCtx.DestCommand = req.Destination.Command
	}

	return evalCtx
}

// storeEvaluation stores an evaluation record with bounded FIFO eviction,
// and persists pending approvals to state.json so they survive restarts (H-10).
func (s *PolicyEvaluationService) storeEvaluation(eval *PolicyEvaluation) {
	s.mu.Lock()

	// Evict oldest if at capacity.
	if len(s.evalOrder) >= s.maxEvals {
		oldID := s.evalOrder[0]
		newOrder := make([]string, len(s.evalOrder)-1)
		copy(newOrder, s.evalOrder[1:])
		s.evalOrder = newOrder
		delete(s.evaluations, oldID)
	}

	s.evaluations[eval.RequestID] = eval
	s.evalOrder = append(s.evalOrder, eval.RequestID)

	// Only persist to state.json when the evaluation requires it (pending or
	// approval_required). This avoids rewriting state.json on every allow/deny
	// evaluation, reducing I/O contention and disk writes under load.
	needsPersist := eval.Status == "pending" || eval.Status == "approval_required"
	var pending []state.PolicyEvaluationEntry
	if needsPersist {
		pending = s.pendingEvalsLocked()
	}
	s.mu.Unlock()

	if needsPersist && s.stateStore != nil {
		if err := s.persistEvaluations(pending); err != nil {
			s.logger.Error("failed to persist policy evaluations", "error", err)
		}
	}
}

// pendingEvalsLocked returns state entries for all pending evaluations.
// Caller must hold s.mu.
func (s *PolicyEvaluationService) pendingEvalsLocked() []state.PolicyEvaluationEntry {
	entries := make([]state.PolicyEvaluationEntry, 0, len(s.evalOrder))
	for _, id := range s.evalOrder {
		eval := s.evaluations[id]
		if eval == nil {
			continue
		}
		if eval.Status != "pending" && eval.Status != "approval_required" {
			continue
		}
		entries = append(entries, state.PolicyEvaluationEntry{
			RequestID:  eval.RequestID,
			ActionType: eval.ActionType,
			ActionName: eval.ActionName,
			Protocol:   eval.Protocol,
			Gateway:    eval.Gateway,
			Framework:  eval.Framework,
			Decision:   eval.Decision,
			RuleID:     eval.RuleID,
			LatencyMs:  eval.LatencyMs,
			Status:     eval.Status,
			CreatedAt:  eval.CreatedAt,
			UpdatedAt:  eval.UpdatedAt,
		})
	}
	return entries
}

// persistEvaluations writes pending evaluations to state.json via Mutate.
func (s *PolicyEvaluationService) persistEvaluations(entries []state.PolicyEvaluationEntry) error {
	return s.stateStore.Mutate(func(appState *state.AppState) error {
		appState.PolicyEvaluations = entries
		return nil
	})
}

// LoadFromState restores persisted evaluations from state.json at boot.
// Call this after creating the service to recover pending approvals.
func (s *PolicyEvaluationService) LoadFromState(appState *state.AppState) {
	if len(appState.PolicyEvaluations) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	loaded := 0
	for _, entry := range appState.PolicyEvaluations {
		if len(s.evalOrder) >= s.maxEvals {
			break
		}
		eval := &PolicyEvaluation{
			RequestID:  entry.RequestID,
			ActionType: entry.ActionType,
			ActionName: entry.ActionName,
			Protocol:   entry.Protocol,
			Gateway:    entry.Gateway,
			Framework:  entry.Framework,
			Decision:   entry.Decision,
			RuleID:     entry.RuleID,
			LatencyMs:  entry.LatencyMs,
			Status:     entry.Status,
			CreatedAt:  entry.CreatedAt,
			UpdatedAt:  entry.UpdatedAt,
		}
		s.evaluations[eval.RequestID] = eval
		s.evalOrder = append(s.evalOrder, eval.RequestID)
		loaded++
	}

	s.logger.Info("restored policy evaluations from state", "count", loaded)
}

// GenerateHelpText creates a human-readable help text from a policy decision.
func GenerateHelpText(decision policy.Decision) string {
	ruleName := decision.RuleName
	if ruleName == "" {
		ruleName = decision.RuleID
	}

	if decision.HelpText != "" {
		return decision.HelpText
	}

	if ruleName == "" {
		return "This action was denied by policy. Contact your administrator for access."
	}

	return fmt.Sprintf(
		"Action blocked by rule '%s'. Contact your admin or modify the rule at %s.",
		ruleName,
		GenerateHelpURL(decision.RuleID),
	)
}

// GenerateHelpURL creates a URL pointing to the rule in the Admin UI.
func GenerateHelpURL(ruleID string) string {
	if ruleID == "" {
		return "/admin/policies"
	}
	return fmt.Sprintf("/admin/policies#rule-%s", ruleID)
}
