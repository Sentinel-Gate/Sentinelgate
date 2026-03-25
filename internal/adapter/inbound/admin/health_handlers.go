package admin

import (
	"math"
	"net/http"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// SetHealthService wires the Health service (called from bootComplianceAndSimulation).
func (h *AdminAPIHandler) SetHealthService(s *service.HealthService) {
	h.healthService = s
}

// handleGetAgentHealth returns health trend data for a single agent.
// GET /admin/api/v1/agents/{identity_id}/health
func (h *AdminAPIHandler) handleGetAgentHealth(w http.ResponseWriter, r *http.Request) {
	identityID := h.pathParam(r, "identity_id") // L-10
	if identityID == "" {
		h.respondError(w, http.StatusBadRequest, "identity_id is required")
		return
	}

	if h.healthService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "health service not available")
		return
	}

	report, err := h.healthService.GetHealthReport(r.Context(), identityID)
	if err != nil {
		h.internalError(w, "failed to get agent health report", err)
		return
	}

	h.respondJSON(w, http.StatusOK, report)
}

// handleGetHealthOverview returns cross-agent health overview.
// GET /admin/api/v1/health/overview
func (h *AdminAPIHandler) handleGetHealthOverview(w http.ResponseWriter, r *http.Request) {
	if h.healthService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "health service not available")
		return
	}

	entries, err := h.healthService.GetHealthOverview(r.Context())
	if err != nil {
		h.internalError(w, "failed to get health overview", err)
		return
	}

	h.respondJSON(w, http.StatusOK, entries)
}

// handleGetHealthConfig returns the health alerting configuration.
// GET /admin/api/v1/health/config
func (h *AdminAPIHandler) handleGetHealthConfig(w http.ResponseWriter, r *http.Request) {
	if h.healthService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "health service not available")
		return
	}
	h.respondJSON(w, http.StatusOK, h.healthService.Config())
}

// handlePutHealthConfig updates the health alerting configuration.
// PUT /admin/api/v1/health/config
func (h *AdminAPIHandler) handlePutHealthConfig(w http.ResponseWriter, r *http.Request) {
	if h.healthService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "health service not available")
		return
	}

	var cfg struct {
		DenyRateWarning    *float64 `json:"deny_rate_warning"`
		DenyRateCritical   *float64 `json:"deny_rate_critical"`
		DriftScoreWarning  *float64 `json:"drift_score_warning"`
		DriftScoreCritical *float64 `json:"drift_score_critical"`
		ErrorRateWarning   *float64 `json:"error_rate_warning"`
		ErrorRateCritical  *float64 `json:"error_rate_critical"`
	}
	if err := h.readJSON(r, &cfg); err != nil {
		h.logger.Error("invalid health config request", "error", err)
		h.handleReadJSONErr(w, err)
		return
	}

	// M-46: Build new config but persist BEFORE mutating in-memory
	current := h.healthService.Config()
	if cfg.DenyRateWarning != nil {
		current.DenyRateWarning = *cfg.DenyRateWarning
	}
	if cfg.DenyRateCritical != nil {
		current.DenyRateCritical = *cfg.DenyRateCritical
	}
	if cfg.DriftScoreWarning != nil {
		current.DriftScoreWarning = *cfg.DriftScoreWarning
	}
	if cfg.DriftScoreCritical != nil {
		current.DriftScoreCritical = *cfg.DriftScoreCritical
	}
	if cfg.ErrorRateWarning != nil {
		current.ErrorRateWarning = *cfg.ErrorRateWarning
	}
	if cfg.ErrorRateCritical != nil {
		current.ErrorRateCritical = *cfg.ErrorRateCritical
	}

	// Validate threshold values: must be in [0.0, 1.0], not NaN/Inf,
	// and warning must be less than critical when both are set.
	thresholds := []struct {
		name string
		val  float64
	}{
		{"deny_rate_warning", current.DenyRateWarning},
		{"deny_rate_critical", current.DenyRateCritical},
		{"drift_score_warning", current.DriftScoreWarning},
		{"drift_score_critical", current.DriftScoreCritical},
		{"error_rate_warning", current.ErrorRateWarning},
		{"error_rate_critical", current.ErrorRateCritical},
	}
	for _, t := range thresholds {
		if math.IsNaN(t.val) || math.IsInf(t.val, 0) || t.val < 0 || t.val > 1 {
			h.respondError(w, http.StatusBadRequest, t.name+" must be between 0.0 and 1.0")
			return
		}
	}
	pairs := []struct {
		warnName, critName string
		warn, crit         float64
	}{
		{"deny_rate_warning", "deny_rate_critical", current.DenyRateWarning, current.DenyRateCritical},
		{"drift_score_warning", "drift_score_critical", current.DriftScoreWarning, current.DriftScoreCritical},
		{"error_rate_warning", "error_rate_critical", current.ErrorRateWarning, current.ErrorRateCritical},
	}
	for _, p := range pairs {
		if p.warn > 0 && p.crit > 0 && p.warn >= p.crit {
			h.respondError(w, http.StatusBadRequest, p.warnName+" must be less than "+p.critName)
			return
		}
	}

	// Persist to state.json FIRST — only mutate in-memory on success
	if h.stateStore != nil {
		if err := h.stateStore.Mutate(func(appState *state.AppState) error {
			appState.HealthConfig = &state.HealthConfigEntry{
				DenyRateWarning:    current.DenyRateWarning,
				DenyRateCritical:   current.DenyRateCritical,
				DriftScoreWarning:  current.DriftScoreWarning,
				DriftScoreCritical: current.DriftScoreCritical,
				ErrorRateWarning:   current.ErrorRateWarning,
				ErrorRateCritical:  current.ErrorRateCritical,
			}
			return nil
		}); err != nil {
			h.respondError(w, http.StatusInternalServerError, "failed to persist health config")
			return
		}
	}

	h.healthService.SetConfig(current)

	h.respondJSON(w, http.StatusOK, current)
}
