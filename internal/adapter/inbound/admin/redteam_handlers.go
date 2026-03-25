package admin

import (
	"errors"
	"net/http"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/redteam"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// SetRedTeamService wires the red team service (called from bootComplianceAndSimulation).
func (h *AdminAPIHandler) SetRedTeamService(s *service.RedTeamService) {
	h.redteamService = s
}

// handleRunRedTeam runs an attack suite (full or by category).
func (h *AdminAPIHandler) handleRunRedTeam(w http.ResponseWriter, r *http.Request) {
	if h.redteamService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "red team service not available")
		return
	}

	var req struct {
		TargetIdentity string   `json:"target_identity"`
		Roles          []string `json:"roles"`
		Category       string   `json:"category"`
	}
	if r.ContentLength != 0 { // L-19: r.Body is never nil in net/http
		if err := h.readJSON(r, &req); err != nil {
			h.handleReadJSONErr(w, err)
			return
		}
	}

	if req.TargetIdentity == "" {
		h.respondError(w, http.StatusBadRequest, "target_identity is required")
		return
	}

	// L-42: Validate category against known attack categories.
	if req.Category != "" {
		validCategories := map[redteam.AttackCategory]bool{
			redteam.CategoryToolMisuse:        true,
			redteam.CategoryArgManipulation:   true,
			redteam.CategoryPromptInjDirect:   true,
			redteam.CategoryPromptInjIndirect: true,
			redteam.CategoryPermEscalation:    true,
			redteam.CategoryMultiStep:         true,
		}
		if !validCategories[redteam.AttackCategory(req.Category)] {
			h.respondError(w, http.StatusBadRequest, "unknown attack category: "+req.Category)
			return
		}
	}

	var (
		report *redteam.Report
		err    error
	)

	if req.Category != "" {
		report, err = h.redteamService.RunCategory(r.Context(), redteam.AttackCategory(req.Category), req.TargetIdentity, req.Roles)
	} else {
		report, err = h.redteamService.RunSuite(r.Context(), req.TargetIdentity, req.Roles)
	}

	if err != nil {
		h.logger.Error("red team run failed", "error", err)
		h.respondError(w, http.StatusInternalServerError, "red team run failed")
		return
	}

	h.respondJSON(w, http.StatusOK, report)
}

// handleRunSingleRedTeam runs a single attack pattern.
func (h *AdminAPIHandler) handleRunSingleRedTeam(w http.ResponseWriter, r *http.Request) {
	if h.redteamService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "red team service not available")
		return
	}

	var req struct {
		PatternID      string   `json:"pattern_id"`
		TargetIdentity string   `json:"target_identity"`
		Roles          []string `json:"roles"`
	}
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}
	if req.PatternID == "" {
		h.respondError(w, http.StatusBadRequest, "pattern_id required")
		return
	}
	if req.TargetIdentity == "" { // L-20
		h.respondError(w, http.StatusBadRequest, "target_identity required")
		return
	}

	result, err := h.redteamService.RunSingle(r.Context(), req.PatternID, req.TargetIdentity, req.Roles)
	if err != nil {
		if errors.Is(err, service.ErrUnknownPattern) {
			h.respondError(w, http.StatusNotFound, "pattern not found")
		} else {
			h.logger.Error("red team single run failed", "pattern_id", req.PatternID, "error", err)
			h.respondError(w, http.StatusInternalServerError, "red team execution failed")
		}
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}

// handleGetRedTeamCorpus returns the available attack patterns.
func (h *AdminAPIHandler) handleGetRedTeamCorpus(w http.ResponseWriter, r *http.Request) {
	if h.redteamService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "red team service not available")
		return
	}

	corpus := h.redteamService.GetCorpus()
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"patterns": corpus,
		"total":    len(corpus),
	})
}

// handleGetRedTeamReports returns stored reports.
func (h *AdminAPIHandler) handleGetRedTeamReports(w http.ResponseWriter, r *http.Request) {
	if h.redteamService == nil {
		h.respondJSON(w, http.StatusOK, map[string]interface{}{"reports": []interface{}{}})
		return
	}

	reports := h.redteamService.GetReports()
	h.respondJSON(w, http.StatusOK, map[string]interface{}{"reports": reports})
}

// handleGetRedTeamReport returns a specific report by ID.
func (h *AdminAPIHandler) handleGetRedTeamReport(w http.ResponseWriter, r *http.Request) {
	if h.redteamService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "red team service not available")
		return
	}

	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "report ID required")
		return
	}

	report := h.redteamService.GetReport(id)
	if report == nil {
		h.respondError(w, http.StatusNotFound, "report not found")
		return
	}

	h.respondJSON(w, http.StatusOK, report)
}
