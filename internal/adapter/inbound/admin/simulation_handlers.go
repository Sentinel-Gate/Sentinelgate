package admin

import (
	"net/http"

	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// SetSimulationService sets the simulation service after construction.
func (h *AdminAPIHandler) SetSimulationService(s *service.SimulationService) {
	h.simulationService = s
}

// simulationRequest is the JSON body for POST /admin/api/v1/simulation/run.
type simulationRequest struct {
	MaxRecords     int                      `json:"max_records"`
	ToolMatch      string                   `json:"tool_match"`
	CandidateRules []service.CandidateRule   `json:"candidate_rules,omitempty"`
}

// handleRunSimulation runs a policy simulation against recent audit traffic.
// POST /admin/api/v1/simulation/run
func (h *AdminAPIHandler) handleRunSimulation(w http.ResponseWriter, r *http.Request) {
	if h.simulationService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "simulation service not available")
		return
	}

	var req simulationRequest
	if r.Body != nil && r.ContentLength != 0 {
		if !h.readJSONBody(w, r, &req) {
			return
		}
	}

	// L-12: Cap MaxRecords to prevent resource exhaustion.
	maxRecords := req.MaxRecords
	if maxRecords <= 0 || maxRecords > 10000 {
		maxRecords = 10000
	}
	simReq := service.SimulationRequest{
		MaxRecords:     maxRecords,
		ToolMatch:      req.ToolMatch,
		CandidateRules: req.CandidateRules,
	}

	result, err := h.simulationService.Simulate(r.Context(), simReq)
	if err != nil {
		h.logger.Error("simulation failed", "error", err)
		h.respondError(w, http.StatusInternalServerError, "simulation failed")
		return
	}

	h.respondJSON(w, http.StatusOK, result)
}
