package admin

import (
	"errors"
	"net/http"
	"strings"
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
func toDomainPolicy(req policyRequest) *policy.Policy {
	rules := make([]policy.Rule, len(req.Rules))
	for i, r := range req.Rules {
		rules[i] = policy.Rule{
			ID:        r.ID,
			Name:      r.Name,
			Priority:  r.Priority,
			ToolMatch: r.ToolMatch,
			Condition: r.Condition,
			Action:    policy.Action(r.Action),
		}
		if r.ApprovalTimeout != "" {
			if d, err := time.ParseDuration(r.ApprovalTimeout); err == nil {
				rules[i].ApprovalTimeout = d
			}
		}
		if r.TimeoutAction != "" {
			rules[i].TimeoutAction = policy.Action(r.TimeoutAction)
		}
	}
	return &policy.Policy{
		Name:        req.Name,
		Description: req.Description,
		Priority:    req.Priority,
		Enabled:     req.Enabled,
		Rules:       rules,
	}
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
		h.respondError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	if req.Name == "" {
		h.respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	p := toDomainPolicy(req)
	created, err := h.policyAdminService.Create(r.Context(), p)
	if err != nil {
		if strings.Contains(err.Error(), "invalid policy:") {
			h.respondError(w, http.StatusBadRequest, err.Error())
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
		h.respondError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	if req.Name == "" {
		h.respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	p := toDomainPolicy(req)
	updated, err := h.policyAdminService.Update(r.Context(), id, p)
	if err != nil {
		if errors.Is(err, service.ErrPolicyNotFound) {
			h.respondError(w, http.StatusNotFound, "policy not found")
			return
		}
		if strings.Contains(err.Error(), "invalid policy:") {
			h.respondError(w, http.StatusBadRequest, err.Error())
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
