package admin

import (
	"errors"
	"net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// SetPermissionHealthService sets the permission health service after construction.
func (h *AdminAPIHandler) SetPermissionHealthService(s *service.PermissionHealthService) {
	h.permissionHealthService = s
}

// handleGetAllPermissionHealth returns permission health reports for all identities.
// GET /admin/api/v1/permissions/health
func (h *AdminAPIHandler) handleGetAllPermissionHealth(w http.ResponseWriter, r *http.Request) {
	if h.permissionHealthService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "permission health service not available")
		return
	}

	reports, err := h.permissionHealthService.GetAllHealthReports(r.Context())
	if err != nil {
		h.internalError(w, "failed to get permission health reports", err)
		return
	}
	if reports == nil {
		reports = []service.PermissionHealthReport{}
	}
	h.respondJSON(w, http.StatusOK, reports)
}

// handleGetPermissionHealth returns permission health for a specific identity.
// GET /admin/api/v1/permissions/health/{identity_id}
func (h *AdminAPIHandler) handleGetPermissionHealth(w http.ResponseWriter, r *http.Request) {
	if h.permissionHealthService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "permission health service not available")
		return
	}

	identityID := h.pathParam(r, "identity_id")
	if identityID == "" {
		h.respondError(w, http.StatusBadRequest, "identity_id is required")
		return
	}

	report, err := h.permissionHealthService.ComputeHealthReport(r.Context(), identityID)
	if err != nil {
		if errors.Is(err, service.ErrIdentityNotFound) {
			// L-25: Use explicit client-facing message instead of err.Error().
			h.respondError(w, http.StatusNotFound, "identity not found")
		} else if errors.Is(err, service.ErrPermissionHealthDisabled) {
			// L-25: Use explicit client-facing message instead of err.Error().
			h.respondError(w, http.StatusServiceUnavailable, "permission health is disabled")
		} else {
			h.internalError(w, "failed to compute permission health report", err)
		}
		return
	}
	h.respondJSON(w, http.StatusOK, report)
}

// handleGetPermissionSuggestions returns auto-tighten suggestions for an identity.
// GET /admin/api/v1/permissions/suggestions/{identity_id}
func (h *AdminAPIHandler) handleGetPermissionSuggestions(w http.ResponseWriter, r *http.Request) {
	if h.permissionHealthService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "permission health service not available")
		return
	}

	identityID := h.pathParam(r, "identity_id")
	if identityID == "" {
		h.respondError(w, http.StatusBadRequest, "identity_id is required")
		return
	}

	report, err := h.permissionHealthService.ComputeHealthReport(r.Context(), identityID)
	if err != nil {
		if errors.Is(err, service.ErrIdentityNotFound) {
			// L-25: Use explicit client-facing message instead of err.Error().
			h.respondError(w, http.StatusNotFound, "identity not found")
		} else if errors.Is(err, service.ErrPermissionHealthDisabled) {
			// L-25: Use explicit client-facing message instead of err.Error().
			h.respondError(w, http.StatusServiceUnavailable, "permission health is disabled")
		} else {
			h.internalError(w, "failed to compute permission suggestions", err)
		}
		return
	}
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"identity_id": identityID,
		"suggestions": report.Suggestions,
	})
}

// handleApplySuggestions applies selected policy suggestions for an identity.
// POST /admin/api/v1/permissions/apply
func (h *AdminAPIHandler) handleApplySuggestions(w http.ResponseWriter, r *http.Request) {
	if h.permissionHealthService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "permission health service not available")
		return
	}

	var req struct {
		IdentityID    string   `json:"identity_id"`
		SuggestionIDs []string `json:"suggestion_ids"`
	}
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}
	if req.IdentityID == "" {
		h.respondError(w, http.StatusBadRequest, "identity_id is required")
		return
	}
	if len(req.SuggestionIDs) == 0 {
		h.respondError(w, http.StatusBadRequest, "suggestion_ids is required")
		return
	}

	applied, err := h.permissionHealthService.ApplySuggestions(r.Context(), req.IdentityID, req.SuggestionIDs)
	if err != nil {
		h.internalError(w, "failed to apply permission suggestions", err)
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"applied": applied,
	})
}

// handleGetPermissionHealthConfig returns the current shadow mode config.
// GET /admin/api/v1/permissions/config
func (h *AdminAPIHandler) handleGetPermissionHealthConfig(w http.ResponseWriter, r *http.Request) {
	if h.permissionHealthService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "permission health service not available")
		return
	}

	cfg := h.permissionHealthService.Config()
	h.respondJSON(w, http.StatusOK, cfg)
}

// handleUpdatePermissionHealthConfig updates the shadow mode config.
// PUT /admin/api/v1/permissions/config
func (h *AdminAPIHandler) handleUpdatePermissionHealthConfig(w http.ResponseWriter, r *http.Request) {
	if h.permissionHealthService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "permission health service not available")
		return
	}

	var cfg service.PermissionHealthConfig
	if err := h.readJSON(r, &cfg); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}

	// Validate mode
	switch cfg.Mode {
	case service.ShadowModeDisabled, service.ShadowModeShadow,
		service.ShadowModeSuggest, service.ShadowModeAuto:
		// valid
	default:
		h.respondError(w, http.StatusBadRequest, "invalid mode: must be disabled, shadow, suggest, or auto")
		return
	}

	if cfg.LearningDays <= 0 {
		cfg.LearningDays = 14
	}
	if cfg.GracePeriodDays <= 0 {
		cfg.GracePeriodDays = 7
	}

	// Persist to state.json FIRST — only mutate in-memory on success (H-7).
	if h.stateStore != nil {
		if err := h.stateStore.Mutate(func(appState *state.AppState) error {
			appState.PermissionHealthConfig = &state.PermissionHealthConfigEntry{
				Mode:            string(cfg.Mode),
				LearningDays:    cfg.LearningDays,
				GracePeriodDays: cfg.GracePeriodDays,
				WhitelistTools:  cfg.WhitelistTools,
				UpdatedAt:       time.Now().UTC(),
			}
			return nil
		}); err != nil {
			h.respondError(w, http.StatusInternalServerError, "failed to persist permission health config")
			return
		}
	}

	h.permissionHealthService.SetConfig(cfg)
	h.respondJSON(w, http.StatusOK, cfg)
}
