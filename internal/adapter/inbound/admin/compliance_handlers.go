package admin

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// SetComplianceService sets the compliance service after construction.
func (h *AdminAPIHandler) SetComplianceService(s *service.ComplianceService) {
	h.complianceService = s
}

// SetComplianceContextProvider sets the function that builds ComplianceContext
// from current system state. Called at request time for fresh data.
func (h *AdminAPIHandler) SetComplianceContextProvider(fn func() service.ComplianceContext) {
	h.complianceCtxFn = fn
}

// handleListCompliancePacks returns available compliance policy packs.
// GET /admin/api/v1/compliance/packs
func (h *AdminAPIHandler) handleListCompliancePacks(w http.ResponseWriter, r *http.Request) {
	if h.complianceService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "compliance service not available")
		return
	}
	h.respondJSON(w, http.StatusOK, h.complianceService.ListPacks())
}

// handleGetCompliancePack returns a single pack by ID.
// GET /admin/api/v1/compliance/packs/{id}
func (h *AdminAPIHandler) handleGetCompliancePack(w http.ResponseWriter, r *http.Request) {
	if h.complianceService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "compliance service not available")
		return
	}
	id := h.pathParam(r, "id") // L-10
	pack, err := h.complianceService.GetPack(id)
	if err != nil {
		h.logger.Warn("compliance pack not found", "id", id, "error", err)
		h.respondError(w, http.StatusNotFound, "compliance pack not found") // L-17
		return
	}
	h.respondJSON(w, http.StatusOK, pack)
}

// coverageRequest is the JSON body for POST /admin/api/v1/compliance/packs/{id}/coverage.
type coverageRequest struct {
	StartTime string `json:"start_time"` // RFC3339 (optional, default: 7d ago)
	EndTime   string `json:"end_time"`   // RFC3339 (optional, default: now)
}

// handleGetComplianceCoverage analyzes coverage for a pack.
// POST /admin/api/v1/compliance/packs/{id}/coverage
func (h *AdminAPIHandler) handleGetComplianceCoverage(w http.ResponseWriter, r *http.Request) {
	if h.complianceService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "compliance service not available")
		return
	}

	packID := h.pathParam(r, "id") // L-10

	var req coverageRequest
	if r.Body != nil {
		if err := h.readJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
			h.handleReadJSONErr(w, err)
			return
		}
	}

	start, end, perr := parsePeriod(req.StartTime, req.EndTime)
	if perr != nil {
		h.respondError(w, http.StatusBadRequest, perr.Error())
		return
	}

	sysCtx := service.ComplianceContext{}
	if h.complianceCtxFn != nil {
		sysCtx = h.complianceCtxFn()
	}

	report, err := h.complianceService.AnalyzeCoverage(r.Context(), packID, start, end, sysCtx)
	if err != nil {
		h.logger.Error("compliance coverage analysis failed", "pack_id", packID, "error", err)
		h.respondError(w, http.StatusInternalServerError, "coverage analysis failed")
		return
	}

	h.respondJSON(w, http.StatusOK, report)
}

// bundleRequest is the JSON body for POST /admin/api/v1/compliance/bundles.
type bundleRequest struct {
	PackID    string `json:"pack_id"`
	StartTime string `json:"start_time"` // RFC3339 (optional, default: 7d ago)
	EndTime   string `json:"end_time"`   // RFC3339 (optional, default: now)
}

// handleGenerateBundle generates a compliance evidence bundle.
// POST /admin/api/v1/compliance/bundles
func (h *AdminAPIHandler) handleGenerateBundle(w http.ResponseWriter, r *http.Request) {
	if h.complianceService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "compliance service not available")
		return
	}

	var req bundleRequest
	if !h.readJSONBody(w, r, &req) {
		return
	}
	if req.PackID == "" {
		h.respondError(w, http.StatusBadRequest, "pack_id is required")
		return
	}

	start, end, perr := parsePeriod(req.StartTime, req.EndTime)
	if perr != nil {
		h.respondError(w, http.StatusBadRequest, perr.Error())
		return
	}

	sysCtx := service.ComplianceContext{}
	if h.complianceCtxFn != nil {
		sysCtx = h.complianceCtxFn()
	}

	instanceID := "sentinelgate"
	if h.buildInfo != nil && h.buildInfo.Version != "" {
		instanceID = "sentinelgate-" + h.buildInfo.Version
	}

	bundle, err := h.complianceService.GenerateBundle(r.Context(), req.PackID, start, end, sysCtx, instanceID)
	if err != nil {
		h.logger.Error("compliance bundle generation failed", "pack_id", req.PackID, "error", err)
		h.respondError(w, http.StatusInternalServerError, "bundle generation failed")
		return
	}

	h.respondJSON(w, http.StatusOK, bundle)
}

// evidenceConfigResponse is the API representation of evidence configuration.
type evidenceConfigResponse struct {
	Enabled   bool `json:"enabled"`
	RuntimeOn bool `json:"runtime_on"` // current runtime state (from ComplianceContext)
}

// evidenceConfigRequest is the JSON body for PUT /admin/api/v1/compliance/evidence.
type evidenceConfigRequest struct {
	Enabled bool `json:"enabled"`
}

// handleGetEvidenceConfig returns the evidence configuration.
// GET /admin/api/v1/compliance/evidence
func (h *AdminAPIHandler) handleGetEvidenceConfig(w http.ResponseWriter, r *http.Request) {
	// Runtime state from ComplianceContext (reflects config.yaml on boot).
	runtimeOn := false
	if h.complianceCtxFn != nil {
		runtimeOn = h.complianceCtxFn().EvidenceEnabled
	}

	// Saved state from state.json (user's desired state after next restart).
	savedEnabled := runtimeOn
	if h.stateStore != nil {
		if appState, err := h.stateStore.Load(); err != nil {
			h.logger.Warn("failed to load state for evidence config", "error", err)
		} else if appState.EvidenceConfig != nil {
			savedEnabled = appState.EvidenceConfig.Enabled
		}
	}

	h.respondJSON(w, http.StatusOK, evidenceConfigResponse{
		Enabled:   savedEnabled,
		RuntimeOn: runtimeOn,
	})
}

// handlePutEvidenceConfig persists the evidence toggle to state.json.
// PUT /admin/api/v1/compliance/evidence
func (h *AdminAPIHandler) handlePutEvidenceConfig(w http.ResponseWriter, r *http.Request) {
	var req evidenceConfigRequest
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}

	if h.stateStore == nil {
		h.respondError(w, http.StatusInternalServerError, "state store not available")
		return
	}

	if err := h.stateStore.Mutate(func(appState *state.AppState) error {
		appState.EvidenceConfig = &state.EvidenceConfigEntry{
			Enabled:   req.Enabled,
			UpdatedAt: time.Now().UTC(),
		}
		return nil
	}); err != nil {
		h.logger.Error("failed to persist evidence config", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to persist evidence config")
		return
	}

	runtimeOn := false
	if h.complianceCtxFn != nil {
		runtimeOn = h.complianceCtxFn().EvidenceEnabled
	}

	h.respondJSON(w, http.StatusOK, evidenceConfigResponse{
		Enabled:   req.Enabled,
		RuntimeOn: runtimeOn,
	})
}

// parsePeriod parses start/end times with defaults (7d ago to now).
// Returns an error if non-empty input fails to parse as RFC3339.
func parsePeriod(startStr, endStr string) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	start := now.Add(-7 * 24 * time.Hour)
	end := now

	if startStr != "" {
		t, err := time.Parse(time.RFC3339, startStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid start_time format, expected RFC3339")
		}
		start = t
	}
	if endStr != "" {
		t, err := time.Parse(time.RFC3339, endStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid end_time format, expected RFC3339")
		}
		end = t
	}

	return start, end, nil
}
