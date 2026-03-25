package admin

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// policyRequest is the JSON request body for creating/updating a policy.
type policyRequest struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Priority    int           `json:"priority"`
	Enabled     bool          `json:"enabled"`
	Rules       []ruleRequest `json:"rules"`
	// Top-level rule fields: allow creating a single-rule policy
	// without wrapping in a rules[] array.
	ToolMatch string `json:"tool_match"`
	Condition string `json:"condition"`
	Action    string `json:"action"`
}

// ruleRequest is the JSON request body for a policy rule.
type ruleRequest struct {
	ID              string `json:"id,omitempty"`
	Name            string `json:"name"`
	Priority        int    `json:"priority"`
	ToolMatch       string `json:"tool_match"`
	Condition       string `json:"condition"`
	Action          string `json:"action"`
	ApprovalTimeout string `json:"approval_timeout,omitempty"`
	TimeoutAction   string `json:"timeout_action,omitempty"`
	Source          string `json:"source,omitempty"`
}

// policyResponse is the JSON response for a single policy.
type policyResponse struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Priority    int            `json:"priority"`
	Enabled     bool           `json:"enabled"`
	Rules       []ruleResponse `json:"rules"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// ruleResponse is the JSON response for a rule within a policy.
type ruleResponse struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Priority        int       `json:"priority"`
	ToolMatch       string    `json:"tool_match"`
	Condition       string    `json:"condition"`
	Action          string    `json:"action"`
	ApprovalTimeout string    `json:"approval_timeout,omitempty"`
	TimeoutAction   string    `json:"timeout_action,omitempty"`
	Source          string    `json:"source,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// toPolicyResponse converts a domain policy to an API response.
func toPolicyResponse(p *policy.Policy) policyResponse {
	rules := make([]ruleResponse, len(p.Rules))
	for i, r := range p.Rules {
		rules[i] = ruleResponse{
			ID:        r.ID,
			Name:      r.Name,
			Priority:  r.Priority,
			ToolMatch: r.ToolMatch,
			Condition: r.Condition,
			Action:    string(r.Action),
			Source:    r.Source,
			CreatedAt: r.CreatedAt,
		}
		if r.ApprovalTimeout > 0 {
			rules[i].ApprovalTimeout = r.ApprovalTimeout.String()
		}
		if r.TimeoutAction != "" {
			rules[i].TimeoutAction = string(r.TimeoutAction)
		}
	}
	return policyResponse{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Priority:    p.Priority,
		Enabled:     p.Enabled,
		Rules:       rules,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

// toDomainPolicy converts a request body to a domain policy.
// M-18: Returns error if any rule has an invalid approval_timeout.
func toDomainPolicy(req policyRequest) (*policy.Policy, error) {
	rules := make([]policy.Rule, len(req.Rules))
	for i, r := range req.Rules {
		cond := r.Condition
		if cond == "" {
			cond = "true" // default: match all calls
		}
		toolMatch := r.ToolMatch
		if toolMatch == "" {
			toolMatch = "*" // default: match all tools (consistent with top-level rule handling)
		}
		rules[i] = policy.Rule{
			ID:        r.ID,
			Name:      r.Name,
			Priority:  r.Priority,
			ToolMatch: toolMatch,
			Condition: cond,
			Action:    policy.Action(r.Action),
			Source:    r.Source,
		}
		if r.ApprovalTimeout != "" {
			d, parseErr := time.ParseDuration(r.ApprovalTimeout)
			if parseErr != nil {
				// M-18: Return validation error instead of silently ignoring.
				return nil, fmt.Errorf("rule %q: invalid approval_timeout %q: %w", r.Name, r.ApprovalTimeout, parseErr)
			}
			rules[i].ApprovalTimeout = d
		}
		if r.TimeoutAction != "" {
			rules[i].TimeoutAction = policy.Action(r.TimeoutAction)
		}
	}
	// If no rules were provided but top-level rule fields exist,
	// create a single rule from the top-level fields.
	// This handles the common case where users send rule data
	// as top-level fields instead of inside the rules array.
	if len(rules) == 0 && (req.ToolMatch != "" || req.Action != "") {
		rule := policy.Rule{
			Name:      req.Name,
			Priority:  req.Priority,
			ToolMatch: req.ToolMatch,
			Condition: req.Condition,
			Action:    policy.Action(req.Action),
		}
		if rule.ToolMatch == "" {
			rule.ToolMatch = "*"
		}
		if rule.Condition == "" {
			rule.Condition = "true"
		}
		rules = []policy.Rule{rule}
	}

	return &policy.Policy{
		Name:        req.Name,
		Description: req.Description,
		Priority:    req.Priority,
		Enabled:     req.Enabled,
		Rules:       rules,
	}, nil
}

// WithPolicyAdminService sets the policy admin service on the AdminAPIHandler.
func WithPolicyAdminService(s *service.PolicyAdminService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.policyAdminService = s }
}

// handleListPolicies returns all policies as a JSON array.
// GET /admin/api/policies
func (h *AdminAPIHandler) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	if h.policyAdminService == nil {
		h.respondError(w, http.StatusInternalServerError, "policy service not configured")
		return
	}

	policies, err := h.policyAdminService.List(r.Context())
	if err != nil {
		h.logger.Error("failed to list policies", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to list policies")
		return
	}

	// Convert to response format.
	result := make([]policyResponse, len(policies))
	for i := range policies {
		result[i] = toPolicyResponse(&policies[i])
	}

	h.respondJSON(w, http.StatusOK, result)
}

// handleCreatePolicy creates a new policy from the request body.
// POST /admin/api/policies
func (h *AdminAPIHandler) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	if h.policyAdminService == nil {
		h.respondError(w, http.StatusInternalServerError, "policy service not configured")
		return
	}

	var req policyRequest
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}

	if req.Name == "" {
		h.respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	// H-5: Validate approval_timeout durations before processing.
	for _, r := range req.Rules {
		if r.ApprovalTimeout != "" {
			if _, err := time.ParseDuration(r.ApprovalTimeout); err != nil {
				h.respondError(w, http.StatusBadRequest, "invalid approval_timeout: "+r.ApprovalTimeout)
				return
			}
		}
	}

	p, convErr := toDomainPolicy(req)
	if convErr != nil {
		h.respondError(w, http.StatusBadRequest, "invalid rule configuration") // L-18
		return
	}
	created, err := h.policyAdminService.Create(r.Context(), p)
	if err != nil {
		if errors.Is(err, service.ErrInvalidPolicy) {
			h.respondError(w, http.StatusBadRequest, "invalid policy configuration")
			return
		}
		h.logger.Error("failed to create policy", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}

	h.respondJSON(w, http.StatusCreated, toPolicyResponse(created))
}

// handleUpdatePolicy updates an existing policy.
// PUT /admin/api/policies/{id}
func (h *AdminAPIHandler) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	if h.policyAdminService == nil {
		h.respondError(w, http.StatusInternalServerError, "policy service not configured")
		return
	}

	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "policy ID is required")
		return
	}

	var req policyRequest
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}

	if req.Name == "" {
		h.respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	// H-5: Validate approval_timeout durations before processing.
	for _, r := range req.Rules {
		if r.ApprovalTimeout != "" {
			if _, err := time.ParseDuration(r.ApprovalTimeout); err != nil {
				h.respondError(w, http.StatusBadRequest, "invalid approval_timeout: "+r.ApprovalTimeout)
				return
			}
		}
	}

	p, convErr := toDomainPolicy(req)
	if convErr != nil {
		h.respondError(w, http.StatusBadRequest, "invalid rule configuration") // L-18
		return
	}
	updated, err := h.policyAdminService.Update(r.Context(), id, p)
	if err != nil {
		if errors.Is(err, service.ErrPolicyNotFound) {
			h.respondError(w, http.StatusNotFound, "policy not found")
			return
		}
		if errors.Is(err, service.ErrInvalidPolicy) {
			h.respondError(w, http.StatusBadRequest, "invalid policy configuration")
			return
		}
		h.logger.Error("failed to update policy", "error", err, "id", id)
		h.respondError(w, http.StatusInternalServerError, "failed to update policy")
		return
	}

	h.respondJSON(w, http.StatusOK, toPolicyResponse(updated))
}

// handleDeletePolicy removes a policy by ID.
// DELETE /admin/api/policies/{id}
func (h *AdminAPIHandler) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	if h.policyAdminService == nil {
		h.respondError(w, http.StatusInternalServerError, "policy service not configured")
		return
	}

	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "policy ID is required")
		return
	}

	err := h.policyAdminService.Delete(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrDefaultPolicyDelete) {
			h.respondError(w, http.StatusForbidden, "cannot delete the default policy")
			return
		}
		if errors.Is(err, service.ErrPolicyNotFound) {
			h.respondError(w, http.StatusNotFound, "policy not found")
			return
		}
		h.logger.Error("failed to delete policy", "error", err, "id", id)
		h.respondError(w, http.StatusInternalServerError, "failed to delete policy")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteRule removes a single rule from a policy.
// DELETE /admin/api/policies/{id}/rules/{ruleId}
func (h *AdminAPIHandler) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	if h.policyAdminService == nil {
		h.respondError(w, http.StatusInternalServerError, "policy service not configured")
		return
	}

	policyID := h.pathParam(r, "id")
	ruleID := h.pathParam(r, "ruleId")
	if policyID == "" || ruleID == "" {
		h.respondError(w, http.StatusBadRequest, "policy ID and rule ID are required")
		return
	}

	err := h.policyAdminService.DeleteRule(r.Context(), policyID, ruleID)
	if err != nil {
		if errors.Is(err, service.ErrDefaultPolicyDelete) {
			h.respondError(w, http.StatusForbidden, "cannot modify the default policy")
			return
		}
		if errors.Is(err, service.ErrPolicyNotFound) {
			h.respondError(w, http.StatusNotFound, "policy not found")
			return
		}
		h.logger.Error("failed to delete rule", "error", err, "policy_id", policyID, "rule_id", ruleID)
		h.respondError(w, http.StatusInternalServerError, "failed to delete rule")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
