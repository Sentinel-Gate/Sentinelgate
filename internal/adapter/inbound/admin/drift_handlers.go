package admin

import (
	"math"
	"net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// WithDriftService sets the drift detection service.
func WithDriftService(s *service.DriftService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.driftService = s }
}

// SetDriftService sets the drift detection service after construction.
func (h *AdminAPIHandler) SetDriftService(s *service.DriftService) {
	h.driftService = s
}

// handleListBehavioralDriftReports returns drift reports for all identities with recent activity.
// GET /admin/api/v1/drift/reports
func (h *AdminAPIHandler) handleListDriftReports(w http.ResponseWriter, r *http.Request) {
	if h.driftService == nil {
		h.respondJSON(w, http.StatusOK, []service.BehavioralDriftReport{})
		return
	}

	reports, err := h.driftService.DetectAll(r.Context())
	if err != nil {
		h.internalError(w, "failed to detect drift reports", err)
		return
	}
	if reports == nil {
		reports = []service.BehavioralDriftReport{}
	}

	h.respondJSON(w, http.StatusOK, reports)
}

// handleGetDriftProfile returns the drift report for a specific identity.
// GET /admin/api/v1/drift/profiles/{identity_id}
func (h *AdminAPIHandler) handleGetDriftProfile(w http.ResponseWriter, r *http.Request) {
	if h.driftService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "drift detection not configured")
		return
	}

	identityID := h.pathParam(r, "identity_id")
	if identityID == "" {
		h.respondError(w, http.StatusBadRequest, "identity_id is required")
		return
	}

	report, err := h.driftService.DetectDrift(r.Context(), identityID)
	if err != nil {
		h.internalError(w, "failed to detect drift for identity", err)
		return
	}

	h.respondJSON(w, http.StatusOK, report)
}

// handleResetDriftBaseline resets the behavioral baseline for an identity.
// POST /admin/api/v1/drift/profiles/{identity_id}/reset
func (h *AdminAPIHandler) handleResetDriftBaseline(w http.ResponseWriter, r *http.Request) {
	if h.driftService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "drift detection not configured")
		return
	}

	identityID := h.pathParam(r, "identity_id")
	if identityID == "" {
		h.respondError(w, http.StatusBadRequest, "identity_id is required")
		return
	}

	if err := h.driftService.ResetBaseline(r.Context(), identityID); err != nil {
		h.internalError(w, "failed to reset drift baseline", err)
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":      "reset",
		"identity_id": identityID,
		"message":     "baseline reset successfully",
	})
}

// driftConfigResponse wraps DriftConfig with a "configured" flag so the frontend
// can distinguish "drift is actively running" from "server returned defaults".
type driftConfigResponse struct {
	Configured bool               `json:"configured"`
	Config     service.DriftConfig `json:"config"`
}

// handleGetDriftConfig returns the current drift detection configuration.
// GET /admin/api/v1/drift/config
func (h *AdminAPIHandler) handleGetDriftConfig(w http.ResponseWriter, r *http.Request) {
	if h.driftService == nil {
		h.respondJSON(w, http.StatusOK, driftConfigResponse{
			Configured: false,
			Config:     service.DefaultDriftConfig(),
		})
		return
	}

	h.respondJSON(w, http.StatusOK, driftConfigResponse{
		Configured: true,
		Config:     h.driftService.Config(),
	})
}

// handlePutDriftConfig updates the drift detection configuration (H-8).
// PUT /admin/api/v1/drift/config
func (h *AdminAPIHandler) handlePutDriftConfig(w http.ResponseWriter, r *http.Request) {
	if h.driftService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "drift detection not configured")
		return
	}

	var req struct {
		BaselineWindowDays *int     `json:"baseline_window_days"`
		CurrentWindowDays  *int     `json:"current_window_days"`
		ToolShiftThreshold *float64 `json:"tool_shift_threshold"`
		DenyRateThreshold  *float64 `json:"deny_rate_threshold"`
		ErrorRateThreshold *float64 `json:"error_rate_threshold"`
		LatencyThreshold   *float64 `json:"latency_threshold"`
		TemporalThreshold  *float64 `json:"temporal_threshold"`
		ArgShiftThreshold  *float64 `json:"arg_shift_threshold"`
		MinCallsBaseline   *int     `json:"min_calls_baseline"`
	}
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}

	// Merge with current config (partial update).
	cfg := h.driftService.Config()
	if req.BaselineWindowDays != nil {
		cfg.BaselineWindowDays = *req.BaselineWindowDays
	}
	if req.CurrentWindowDays != nil {
		cfg.CurrentWindowDays = *req.CurrentWindowDays
	}
	if req.ToolShiftThreshold != nil {
		cfg.ToolShiftThreshold = *req.ToolShiftThreshold
	}
	if req.DenyRateThreshold != nil {
		cfg.DenyRateThreshold = *req.DenyRateThreshold
	}
	if req.ErrorRateThreshold != nil {
		cfg.ErrorRateThreshold = *req.ErrorRateThreshold
	}
	if req.LatencyThreshold != nil {
		cfg.LatencyThreshold = *req.LatencyThreshold
	}
	if req.TemporalThreshold != nil {
		cfg.TemporalThreshold = *req.TemporalThreshold
	}
	if req.ArgShiftThreshold != nil {
		cfg.ArgShiftThreshold = *req.ArgShiftThreshold
	}
	if req.MinCallsBaseline != nil {
		cfg.MinCallsBaseline = *req.MinCallsBaseline
	}

	// Basic validation.
	if cfg.BaselineWindowDays <= 0 {
		h.respondError(w, http.StatusBadRequest, "baseline_window_days must be > 0")
		return
	}
	if cfg.CurrentWindowDays <= 0 {
		h.respondError(w, http.StatusBadRequest, "current_window_days must be > 0")
		return
	}
	if cfg.MinCallsBaseline < 0 {
		h.respondError(w, http.StatusBadRequest, "min_calls_baseline must not be negative")
		return
	}

	// H-10: Validate float thresholds: reject NaN/Inf and negative values.
	floatThresholds := []struct {
		name string
		val  float64
	}{
		{"tool_shift_threshold", cfg.ToolShiftThreshold},
		{"deny_rate_threshold", cfg.DenyRateThreshold},
		{"error_rate_threshold", cfg.ErrorRateThreshold},
		{"latency_threshold", cfg.LatencyThreshold},
		{"temporal_threshold", cfg.TemporalThreshold},
		{"arg_shift_threshold", cfg.ArgShiftThreshold},
	}
	for _, t := range floatThresholds {
		if math.IsNaN(t.val) || math.IsInf(t.val, 0) {
			h.respondError(w, http.StatusBadRequest, t.name+" must be a finite number")
			return
		}
		if t.val < 0 {
			h.respondError(w, http.StatusBadRequest, t.name+" must not be negative")
			return
		}
	}

	// Persist to state.json FIRST — only mutate in-memory on success.
	if h.stateStore != nil {
		if err := h.stateStore.Mutate(func(appState *state.AppState) error {
			appState.DriftConfig = &state.DriftConfigEntry{
				BaselineWindowDays: cfg.BaselineWindowDays,
				CurrentWindowDays:  cfg.CurrentWindowDays,
				ToolShiftThreshold: cfg.ToolShiftThreshold,
				DenyRateThreshold:  cfg.DenyRateThreshold,
				ErrorRateThreshold: cfg.ErrorRateThreshold,
				LatencyThreshold:   cfg.LatencyThreshold,
				TemporalThreshold:  cfg.TemporalThreshold,
				ArgShiftThreshold:  cfg.ArgShiftThreshold,
				MinCallsBaseline:   cfg.MinCallsBaseline,
				UpdatedAt:          time.Now().UTC(),
			}
			return nil
		}); err != nil {
			h.respondError(w, http.StatusInternalServerError, "failed to persist drift config")
			return
		}
	}

	h.driftService.SetConfig(cfg)
	h.respondJSON(w, http.StatusOK, driftConfigResponse{
		Configured: true,
		Config:     cfg,
	})
}
