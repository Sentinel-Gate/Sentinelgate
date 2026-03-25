package admin

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// SetFinOpsService wires the FinOps service (called from bootComplianceAndSimulation).
func (h *AdminAPIHandler) SetFinOpsService(s *service.FinOpsService) {
	h.finopsService = s
}

// handleGetFinOpsCosts returns a cost report for a period.
func (h *AdminAPIHandler) handleGetFinOpsCosts(w http.ResponseWriter, r *http.Request) {
	if h.finopsService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "finops service not available")
		return
	}

	start, end, perr := parseCostPeriod(r)
	if perr != nil {
		h.respondError(w, http.StatusBadRequest, perr.Error())
		return
	}
	report, err := h.finopsService.GetCostReport(r.Context(), start, end)
	if err != nil {
		h.logger.Error("failed to get cost report", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to get cost report")
		return
	}

	h.respondJSON(w, http.StatusOK, report)
}

// handleGetFinOpsIdentityCost returns cost detail for one identity.
func (h *AdminAPIHandler) handleGetFinOpsIdentityCost(w http.ResponseWriter, r *http.Request) {
	if h.finopsService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "finops service not available")
		return
	}

	id := h.pathParam(r, "identity_id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "identity_id required")
		return
	}

	start, end, perr := parseCostPeriod(r)
	if perr != nil {
		h.respondError(w, http.StatusBadRequest, perr.Error())
		return
	}
	detail, err := h.finopsService.GetIdentityCost(r.Context(), id, start, end)
	if err != nil {
		h.logger.Error("failed to get identity cost", "identity_id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to get identity cost")
		return
	}

	h.respondJSON(w, http.StatusOK, detail)
}

// handleGetFinOpsBudgets returns budget statuses and triggers alert checks.
func (h *AdminAPIHandler) handleGetFinOpsBudgets(w http.ResponseWriter, r *http.Request) {
	if h.finopsService == nil {
		h.respondJSON(w, http.StatusOK, map[string]interface{}{"budgets": []interface{}{}})
		return
	}

	start, end, perr := parseCostPeriod(r)
	if perr != nil {
		h.respondError(w, http.StatusBadRequest, perr.Error())
		return
	}
	statuses := h.finopsService.CheckBudgets(r.Context(), start, end)
	if statuses == nil {
		statuses = []service.BudgetStatus{}
	}

	// BUG-10 FIX: Replace UUID identity_name with human-readable name.
	// When an identity has no audit records, computeBudgetStatus uses the
	// identity ID (UUID) as the name fallback. Look up real names here.
	if h.identityService != nil && len(statuses) > 0 {
		identities, err := h.identityService.ListIdentities(r.Context())
		if err == nil {
			nameMap := make(map[string]string, len(identities))
			for _, ident := range identities {
				nameMap[ident.ID] = ident.Name
			}
			for i := range statuses {
				if name, ok := nameMap[statuses[i].IdentityID]; ok && name != "" {
					statuses[i].IdentityName = name
				}
			}
		}
	}

	h.respondJSON(w, http.StatusOK, map[string]interface{}{"budgets": statuses})
}

// handleGetFinOpsConfig returns the current FinOps configuration.
func (h *AdminAPIHandler) handleGetFinOpsConfig(w http.ResponseWriter, r *http.Request) {
	if h.finopsService == nil {
		h.respondJSON(w, http.StatusOK, service.DefaultFinOpsConfig())
		return
	}

	h.respondJSON(w, http.StatusOK, h.finopsService.Config())
}

// handleUpdateFinOpsConfig updates the FinOps configuration.
func (h *AdminAPIHandler) handleUpdateFinOpsConfig(w http.ResponseWriter, r *http.Request) {
	if h.finopsService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "finops service not available")
		return
	}

	var cfg service.FinOpsConfig
	if err := h.readJSON(r, &cfg); err != nil {
		h.logger.Error("invalid finops config request", "error", err)
		h.handleReadJSONErr(w, err)
		return
	}

	if cfg.AlertThresholds == nil {
		cfg.AlertThresholds = []float64{0.70, 0.85, 1.0}
	}
	if cfg.ToolCosts == nil {
		cfg.ToolCosts = make(map[string]float64)
	}
	if cfg.Budgets == nil {
		cfg.Budgets = make(map[string]float64)
	}
	if cfg.BudgetActions == nil {
		cfg.BudgetActions = make(map[string]string)
	}

	// Sort AlertThresholds before validation so user-provided unordered
	// values are normalised, and dedup to prevent identical consecutive entries (M-36).
	sort.Float64s(cfg.AlertThresholds)
	cfg.AlertThresholds = dedupFloat64s(cfg.AlertThresholds)

	// Validate all float64 fields: reject NaN, Inf, negative values (M-34),
	// and ensure AlertThresholds are in [0.0, 1.0] and ascending (M-36).
	if err := service.ValidateFinOpsConfig(cfg); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Persist to state.json FIRST — only mutate in-memory on success.
	if h.stateStore != nil {
		if err := h.stateStore.Mutate(func(appState *state.AppState) error {
			appState.FinOpsConfig = toFinOpsStateConfig(cfg)
			return nil
		}); err != nil {
			h.logger.Error("failed to persist finops config", "error", err)
			h.respondError(w, http.StatusInternalServerError, "failed to persist finops config")
			return
		}
	}

	h.finopsService.SetConfig(cfg)

	h.respondJSON(w, http.StatusOK, cfg)
}

// toFinOpsStateConfig converts a service config to the state persistence format.
func toFinOpsStateConfig(cfg service.FinOpsConfig) *state.FinOpsConfigEntry {
	return &state.FinOpsConfigEntry{
		Enabled:            cfg.Enabled,
		DefaultCostPerCall: cfg.DefaultCostPerCall,
		ToolCosts:          cfg.ToolCosts,
		Budgets:            cfg.Budgets,
		BudgetActions:      cfg.BudgetActions,
		AlertThresholds:    cfg.AlertThresholds,
		UpdatedAt:          time.Now(),
	}
}

// dedupFloat64s removes consecutive duplicate values from a sorted slice (M-36).
func dedupFloat64s(s []float64) []float64 {
	if len(s) <= 1 {
		return s
	}
	out := s[:1]
	for i := 1; i < len(s); i++ {
		if s[i] != out[len(out)-1] {
			out = append(out, s[i])
		}
	}
	return out
}

// SanitizeFinOpsStateConfig validates and sanitises a FinOpsConfig loaded from
// state.json at boot time (L-45). Invalid float values are replaced with
// defaults so that corrupt persisted data does not propagate into runtime.
func SanitizeFinOpsStateConfig(cfg *service.FinOpsConfig, logger interface{ Warn(string, ...any) }) {
	defaults := service.DefaultFinOpsConfig()

	if err := service.ValidateFinOpsConfig(*cfg); err != nil {
		logger.Warn("finops config from state.json contains invalid values, resetting to defaults", "error", err)
		*cfg = defaults
	}
}

// parseCostPeriod extracts start/end from query params, defaulting to current month (UTC).
func parseCostPeriod(r *http.Request) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	var start, end time.Time

	if startStr != "" {
		parsed, err := time.Parse(time.RFC3339, startStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid 'start' parameter, expected RFC3339 format")
		}
		start = parsed
	}
	if start.IsZero() {
		start = time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	}

	if endStr != "" {
		parsed, err := time.Parse(time.RFC3339, endStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid 'end' parameter, expected RFC3339 format")
		}
		end = parsed
	}
	if end.IsZero() {
		end = start.AddDate(0, 1, 0)
	}

	// L-15: Reject invalid time ranges.
	if !start.Before(end) {
		return time.Time{}, time.Time{}, fmt.Errorf("'start' must be before 'end'")
	}
	return start, end, nil
}
