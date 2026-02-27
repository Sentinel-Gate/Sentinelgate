package admin

import (
	"errors"
	"net/http"

	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// templateListItem is the JSON response for a template in the list endpoint.
type templateListItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Icon        string `json:"icon"`
	RuleCount   int    `json:"rule_count"`
}

// templateDetailResponse is the JSON response for a single template with full rule details.
type templateDetailResponse struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Icon        string                 `json:"icon"`
	RuleCount   int                    `json:"rule_count"`
	Rules       []templateRuleResponse `json:"rules"`
}

// templateRuleResponse is the JSON response for a rule within a template.
type templateRuleResponse struct {
	Name      string `json:"name"`
	ToolMatch string `json:"tool_match"`
	Condition string `json:"condition"`
	Action    string `json:"action"`
	Priority  int    `json:"priority"`
}

// handleListTemplates returns all built-in policy templates.
// GET /admin/api/v1/templates
func (h *AdminAPIHandler) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.respondError(w, http.StatusInternalServerError, "template service not configured")
		return
	}

	templates := h.templateService.List()
	items := make([]templateListItem, len(templates))
	for i, tmpl := range templates {
		items[i] = templateListItem{
			ID:          tmpl.ID,
			Name:        tmpl.Name,
			Description: tmpl.Description,
			Category:    tmpl.Category,
			Icon:        tmpl.Icon,
			RuleCount:   len(tmpl.Rules),
		}
	}

	h.respondJSON(w, http.StatusOK, items)
}

// handleGetTemplate returns a single template with full rule details.
// GET /admin/api/v1/templates/{id}
func (h *AdminAPIHandler) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.respondError(w, http.StatusInternalServerError, "template service not configured")
		return
	}

	id := h.pathParam(r, "id")
	tmpl, err := h.templateService.Get(id)
	if err != nil {
		if errors.Is(err, service.ErrTemplateNotFound) {
			h.respondError(w, http.StatusNotFound, "template not found")
			return
		}
		h.logger.Error("failed to get template", "error", err, "id", id)
		h.respondError(w, http.StatusInternalServerError, "failed to get template")
		return
	}

	rules := make([]templateRuleResponse, len(tmpl.Rules))
	for i, r := range tmpl.Rules {
		rules[i] = templateRuleResponse{
			Name:      r.Name,
			ToolMatch: r.ToolMatch,
			Condition: r.Condition,
			Action:    string(r.Action),
			Priority:  r.Priority,
		}
	}

	resp := templateDetailResponse{
		ID:          tmpl.ID,
		Name:        tmpl.Name,
		Description: tmpl.Description,
		Category:    tmpl.Category,
		Icon:        tmpl.Icon,
		RuleCount:   len(tmpl.Rules),
		Rules:       rules,
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// handleApplyTemplate instantiates a template as a real, editable policy.
// POST /admin/api/v1/templates/{id}/apply
func (h *AdminAPIHandler) handleApplyTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.respondError(w, http.StatusInternalServerError, "template service not configured")
		return
	}

	id := h.pathParam(r, "id")
	created, err := h.templateService.Apply(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrTemplateNotFound) {
			h.respondError(w, http.StatusNotFound, "template not found")
			return
		}
		h.logger.Error("failed to apply template", "error", err, "id", id)
		h.respondError(w, http.StatusInternalServerError, "failed to apply template")
		return
	}

	h.logger.Info("template applied", "template_id", id, "policy_id", created.ID)
	h.respondJSON(w, http.StatusCreated, toPolicyResponse(created))
}
