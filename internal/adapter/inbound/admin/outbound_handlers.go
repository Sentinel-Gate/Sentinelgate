package admin

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// -- Request / Response types -------------------------------------------------

type outboundRuleRequest struct {
	Name       string                  `json:"name"`
	Mode       string                  `json:"mode"`
	Targets    []outboundTargetRequest `json:"targets"`
	Action     string                  `json:"action"`
	Scope      string                  `json:"scope"`
	Priority   int                     `json:"priority"`
	Enabled    *bool                   `json:"enabled"`
	Base64Scan bool                    `json:"base64_scan"`
	HelpText   string                  `json:"help_text"`
	HelpURL    string                  `json:"help_url"`
}

type outboundTargetRequest struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type outboundRuleResponse struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Mode       string                   `json:"mode"`
	Targets    []outboundTargetResponse `json:"targets"`
	Action     string                   `json:"action"`
	Scope      string                   `json:"scope"`
	Priority   int                      `json:"priority"`
	Enabled    bool                     `json:"enabled"`
	Base64Scan bool                     `json:"base64_scan"`
	HelpText   string                   `json:"help_text,omitempty"`
	HelpURL    string                   `json:"help_url,omitempty"`
	ReadOnly   bool                     `json:"read_only"`
	CreatedAt  time.Time                `json:"created_at"`
	UpdatedAt  time.Time                `json:"updated_at"`
}

type outboundTargetResponse struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type outboundTestRequest struct {
	Domain string `json:"domain"`
	IP     string `json:"ip"`
	Port   int    `json:"port"`
}

type outboundTestResponse struct {
	Blocked bool                  `json:"blocked"`
	Rule    *outboundRuleResponse `json:"rule,omitempty"`
	Message string                `json:"message"`
}

// -- Conversion helpers -------------------------------------------------------

// toOutboundRuleResponse converts a domain OutboundRule to an API response.
func toOutboundRuleResponse(rule *action.OutboundRule) outboundRuleResponse {
	targets := make([]outboundTargetResponse, len(rule.Targets))
	for i, t := range rule.Targets {
		targets[i] = outboundTargetResponse{
			Type:  string(t.Type),
			Value: t.Value,
		}
	}
	return outboundRuleResponse{
		ID:         rule.ID,
		Name:       rule.Name,
		Mode:       string(rule.Mode),
		Targets:    targets,
		Action:     string(rule.Action),
		Scope:      rule.Scope,
		Priority:   rule.Priority,
		Enabled:    rule.Enabled,
		Base64Scan: rule.Base64Scan,
		HelpText:   rule.HelpText,
		HelpURL:    rule.HelpURL,
		ReadOnly:   strings.HasPrefix(rule.ID, "default-blocklist-"),
		CreatedAt:  rule.CreatedAt,
		UpdatedAt:  rule.UpdatedAt,
	}
}

// toOutboundRule converts an API request to a domain OutboundRule.
func toOutboundRule(req outboundRuleRequest) *action.OutboundRule {
	targets := make([]action.OutboundTarget, len(req.Targets))
	for i, t := range req.Targets {
		targets[i] = action.OutboundTarget{
			Type:  action.TargetType(t.Type),
			Value: t.Value,
		}
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	return &action.OutboundRule{
		Name:       req.Name,
		Mode:       action.RuleMode(req.Mode),
		Targets:    targets,
		Action:     action.RuleAction(req.Action),
		Scope:      req.Scope,
		Priority:   req.Priority,
		Enabled:    enabled,
		Base64Scan: req.Base64Scan,
		HelpText:   req.HelpText,
		HelpURL:    req.HelpURL,
	}
}

// -- Handlers -----------------------------------------------------------------

// handleListOutboundRules returns all outbound rules as a JSON array.
// GET /admin/api/v1/security/outbound/rules
func (h *AdminAPIHandler) handleListOutboundRules(w http.ResponseWriter, r *http.Request) {
	if h.outboundAdminService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "outbound control not available")
		return
	}

	rules, err := h.outboundAdminService.List(r.Context())
	if err != nil {
		h.logger.Error("failed to list outbound rules", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to list outbound rules")
		return
	}

	// Already sorted by priority from store, but ensure consistent response.
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})

	result := make([]outboundRuleResponse, len(rules))
	for i := range rules {
		result[i] = toOutboundRuleResponse(&rules[i])
	}

	h.respondJSON(w, http.StatusOK, result)
}

// handleGetOutboundRule returns a single outbound rule by ID.
// GET /admin/api/v1/security/outbound/rules/{id}
func (h *AdminAPIHandler) handleGetOutboundRule(w http.ResponseWriter, r *http.Request) {
	if h.outboundAdminService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "outbound control not available")
		return
	}

	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "rule ID is required")
		return
	}

	rule, err := h.outboundAdminService.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, action.ErrOutboundRuleNotFound) {
			h.respondError(w, http.StatusNotFound, "outbound rule not found")
			return
		}
		h.logger.Error("failed to get outbound rule", "error", err, "id", id)
		h.respondError(w, http.StatusInternalServerError, "failed to get outbound rule")
		return
	}

	h.respondJSON(w, http.StatusOK, toOutboundRuleResponse(rule))
}

// handleCreateOutboundRule creates a new outbound rule.
// POST /admin/api/v1/security/outbound/rules
func (h *AdminAPIHandler) handleCreateOutboundRule(w http.ResponseWriter, r *http.Request) {
	if h.outboundAdminService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "outbound control not available")
		return
	}

	var req outboundRuleRequest
	if err := h.readJSON(r, &req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	// Basic validation at the API layer.
	if req.Name == "" {
		h.respondError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Mode != "blocklist" && req.Mode != "allowlist" {
		h.respondError(w, http.StatusBadRequest, "mode must be 'blocklist' or 'allowlist'")
		return
	}
	if len(req.Targets) == 0 {
		h.respondError(w, http.StatusBadRequest, "at least one target is required")
		return
	}

	// Set default action if not provided.
	if req.Action == "" {
		req.Action = "block"
	}

	rule := toOutboundRule(req)
	created, err := h.outboundAdminService.Create(r.Context(), rule)
	if err != nil {
		h.logger.Error("failed to create outbound rule", "error", err)
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusCreated, toOutboundRuleResponse(created))
}

// handleUpdateOutboundRule updates an existing outbound rule.
// PUT /admin/api/v1/security/outbound/rules/{id}
func (h *AdminAPIHandler) handleUpdateOutboundRule(w http.ResponseWriter, r *http.Request) {
	if h.outboundAdminService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "outbound control not available")
		return
	}

	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "rule ID is required")
		return
	}

	var req outboundRuleRequest
	if err := h.readJSON(r, &req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	// Basic validation at the API layer.
	if req.Name == "" {
		h.respondError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Mode != "blocklist" && req.Mode != "allowlist" {
		h.respondError(w, http.StatusBadRequest, "mode must be 'blocklist' or 'allowlist'")
		return
	}
	if len(req.Targets) == 0 {
		h.respondError(w, http.StatusBadRequest, "at least one target is required")
		return
	}

	if req.Action == "" {
		req.Action = "block"
	}

	rule := toOutboundRule(req)
	updated, err := h.outboundAdminService.Update(r.Context(), id, rule)
	if err != nil {
		if errors.Is(err, action.ErrOutboundRuleNotFound) {
			h.respondError(w, http.StatusNotFound, "outbound rule not found")
			return
		}
		if errors.Is(err, service.ErrDefaultRuleReadOnly) {
			h.respondError(w, http.StatusForbidden, "default blocklist rules cannot be modified")
			return
		}
		h.logger.Error("failed to update outbound rule", "error", err, "id", id)
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, toOutboundRuleResponse(updated))
}

// handleDeleteOutboundRule deletes an outbound rule by ID.
// DELETE /admin/api/v1/security/outbound/rules/{id}
func (h *AdminAPIHandler) handleDeleteOutboundRule(w http.ResponseWriter, r *http.Request) {
	if h.outboundAdminService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "outbound control not available")
		return
	}

	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "rule ID is required")
		return
	}

	err := h.outboundAdminService.Delete(r.Context(), id)
	if err != nil {
		if errors.Is(err, action.ErrOutboundRuleNotFound) {
			h.respondError(w, http.StatusNotFound, "outbound rule not found")
			return
		}
		if errors.Is(err, service.ErrDefaultRuleReadOnly) {
			h.respondError(w, http.StatusForbidden, "default blocklist rules cannot be deleted")
			return
		}
		h.logger.Error("failed to delete outbound rule", "error", err, "id", id)
		h.respondError(w, http.StatusInternalServerError, "failed to delete outbound rule")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleTestOutbound tests whether a destination would be blocked by current rules.
// POST /admin/api/v1/security/outbound/test
func (h *AdminAPIHandler) handleTestOutbound(w http.ResponseWriter, r *http.Request) {
	if h.outboundAdminService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "outbound control not available")
		return
	}

	var req outboundTestRequest
	if err := h.readJSON(r, &req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	if req.Domain == "" && req.IP == "" {
		h.respondError(w, http.StatusBadRequest, "domain or ip is required")
		return
	}

	// Test against ALL enabled rules by listing them and calling evaluateDestination.
	blocked, matchingRule := h.testDestinationAgainstRules(r.Context(), req.Domain, req.IP, req.Port)

	resp := outboundTestResponse{}
	if blocked && matchingRule != nil {
		ruleResp := toOutboundRuleResponse(matchingRule)
		resp.Blocked = true
		resp.Rule = &ruleResp
		resp.Message = "Destination would be blocked by rule: " + matchingRule.Name
	} else {
		resp.Blocked = false
		resp.Message = "Destination is allowed"
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// testDestinationAgainstRules lists all enabled rules and evaluates the destination
// using the same logic as the real outbound interceptor (respects allowlist/blocklist mode).
func (h *AdminAPIHandler) testDestinationAgainstRules(ctx context.Context, domain, ip string, port int) (bool, *action.OutboundRule) {
	rules, err := h.outboundAdminService.List(ctx)
	if err != nil {
		h.logger.Error("failed to list rules for test", "error", err)
		return false, nil
	}

	return action.EvaluateDestination(rules, domain, ip, port, h.logger)
}

// handleOutboundStats returns aggregate statistics about outbound rules.
// GET /admin/api/v1/security/outbound/stats
func (h *AdminAPIHandler) handleOutboundStats(w http.ResponseWriter, r *http.Request) {
	if h.outboundAdminService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "outbound control not available")
		return
	}

	stats, err := h.outboundAdminService.Stats(r.Context())
	if err != nil {
		h.logger.Error("failed to get outbound stats", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to get outbound stats")
		return
	}

	h.respondJSON(w, http.StatusOK, stats)
}
