package admin

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// WithToolSecurityService sets the tool security service.
func WithToolSecurityService(s *service.ToolSecurityService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.toolSecurityService = s }
}

// SetToolSecurityService sets the tool security service after construction.
func (h *AdminAPIHandler) SetToolSecurityService(s *service.ToolSecurityService) {
	h.toolSecurityService = s
}

// handleCaptureBaseline captures the current tool set as the baseline.
// POST /admin/api/v1/tools/baseline
func (h *AdminAPIHandler) handleCaptureBaseline(w http.ResponseWriter, r *http.Request) {
	if h.toolSecurityService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "tool security service not available")
		return
	}

	count, err := h.toolSecurityService.CaptureBaseline(r.Context())
	if err != nil {
		h.internalError(w, "failed to capture baseline", err)
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"tools_captured": count,
		"captured_at":    time.Now().UTC(),
	})
}

// handleGetBaseline returns the current tool baseline.
// GET /admin/api/v1/tools/baseline
func (h *AdminAPIHandler) handleGetBaseline(w http.ResponseWriter, r *http.Request) {
	if h.toolSecurityService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "tool security service not available")
		return
	}

	baseline := h.toolSecurityService.GetBaseline()

	tools := make([]interface{}, 0, len(baseline))
	for _, entry := range baseline {
		tools = append(tools, entry)
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"tools": tools,
	})
}

// handleDetectDrift compares current tools against the baseline.
// GET /admin/api/v1/tools/drift
func (h *AdminAPIHandler) handleDetectDrift(w http.ResponseWriter, r *http.Request) {
	if h.toolSecurityService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "tool security service not available")
		return
	}

	drifts, err := h.toolSecurityService.DetectDrift(r.Context())
	if err != nil {
		if errors.Is(err, service.ErrNoBaseline) {
			// L-24: Use user-facing message instead of exposing internal method names.
			h.respondError(w, http.StatusConflict, "no baseline exists; please capture a baseline first")
		} else {
			h.internalError(w, "failed to detect drift", err)
		}
		return
	}

	baseline := h.toolSecurityService.GetBaseline()

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"drifts":         drifts,
		"baseline_tools": len(baseline),
	})
}

// handleQuarantineTool quarantines a tool by name.
// POST /admin/api/v1/tools/quarantine
func (h *AdminAPIHandler) handleQuarantineTool(w http.ResponseWriter, r *http.Request) {
	if h.toolSecurityService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "tool security service not available")
		return
	}

	var body struct {
		ToolName string `json:"tool_name"`
	}
	if err := h.readJSON(r, &body); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}
	if body.ToolName == "" {
		h.respondError(w, http.StatusBadRequest, "tool_name is required")
		return
	}

	if err := h.toolSecurityService.Quarantine(body.ToolName); err != nil {
		h.internalError(w, "failed to quarantine tool", err)
		return
	}

	// Emit event so NotificationService generates a user-facing notification.
	if h.eventBus != nil {
		h.eventBus.Publish(context.Background(), event.Event{
			Type:     "tool.quarantined",
			Source:   "tool-integrity",
			Severity: event.SeverityWarning,
			Payload: map[string]string{
				"tool_name": body.ToolName,
			},
		})
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"quarantined": body.ToolName,
	})
}

// handleUnquarantineTool removes quarantine from a tool.
// DELETE /admin/api/v1/tools/quarantine/{tool_name}
func (h *AdminAPIHandler) handleUnquarantineTool(w http.ResponseWriter, r *http.Request) {
	if h.toolSecurityService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "tool security service not available")
		return
	}

	toolName := h.pathParam(r, "tool_name")
	if toolName == "" {
		h.respondError(w, http.StatusBadRequest, "tool_name is required")
		return
	}

	if err := h.toolSecurityService.Unquarantine(toolName); err != nil {
		if errors.Is(err, service.ErrNotQuarantined) {
			h.respondError(w, http.StatusBadRequest, "tool is not quarantined")
		} else {
			h.internalError(w, "failed to unquarantine tool", err)
		}
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"unquarantined": toolName,
	})
}

// handleListQuarantined returns the list of quarantined tools.
// GET /admin/api/v1/tools/quarantine
func (h *AdminAPIHandler) handleListQuarantined(w http.ResponseWriter, r *http.Request) {
	if h.toolSecurityService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "tool security service not available")
		return
	}

	tools := h.toolSecurityService.GetQuarantinedTools()
	if tools == nil {
		tools = []string{}
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"quarantined_tools": tools,
	})
}

// handleAcceptToolChange updates the baseline for a specific tool to accept its current definition.
// POST /admin/api/v1/tools/accept-change
func (h *AdminAPIHandler) handleAcceptToolChange(w http.ResponseWriter, r *http.Request) {
	if h.toolSecurityService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "tool security service not available")
		return
	}

	var req struct {
		ToolName string `json:"tool_name"`
	}
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}
	if req.ToolName == "" {
		h.respondError(w, http.StatusBadRequest, "tool_name is required")
		return
	}

	if err := h.toolSecurityService.AcceptChange(r.Context(), req.ToolName); err != nil {
		h.internalError(w, "failed to accept tool change", err)
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{"status": "accepted", "tool": req.ToolName})
}
