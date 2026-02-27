package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
)

// ResponseScanController allows the admin API to control response scanning.
// The ResponseScanInterceptor from the action package satisfies this interface.
type ResponseScanController interface {
	Mode() action.ScanMode
	Enabled() bool
	SetMode(mode action.ScanMode)
	SetEnabled(enabled bool)
}

// WithResponseScanController sets the response scan controller on the AdminAPIHandler.
func WithResponseScanController(ctrl ResponseScanController) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.responseScanCtrl = ctrl }
}

// SetResponseScanController sets the response scan controller after construction.
// This is needed when the interceptor is created after the AdminAPIHandler (due to
// boot sequence ordering where BOOT-07 builds the interceptor chain after services).
func (h *AdminAPIHandler) SetResponseScanController(ctrl ResponseScanController) {
	h.responseScanCtrl = ctrl
}

// AddResponseScanController registers an additional scan controller that will be
// updated whenever the content scanning config changes. This is used for the HTTP
// gateway's response scan interceptor, which is a separate instance from the MCP one.
func (h *AdminAPIHandler) AddResponseScanController(ctrl ResponseScanController) {
	h.additionalScanCtrls = append(h.additionalScanCtrls, ctrl)
}

// contentScanningResponse is the JSON response for GET/PUT content scanning config.
type contentScanningResponse struct {
	Mode    string `json:"mode"`
	Enabled bool   `json:"enabled"`
	Message string `json:"message,omitempty"`
}

// contentScanningRequest is the JSON request body for PUT content scanning config.
type contentScanningRequest struct {
	Mode    string `json:"mode"`
	Enabled *bool  `json:"enabled"`
}

// handleGetContentScanning returns the current content scanning configuration.
// GET /admin/api/v1/security/content-scanning
func (h *AdminAPIHandler) handleGetContentScanning(w http.ResponseWriter, r *http.Request) {
	if h.responseScanCtrl == nil {
		h.respondError(w, http.StatusServiceUnavailable, "content scanning not available")
		return
	}

	h.respondJSON(w, http.StatusOK, contentScanningResponse{
		Mode:    string(h.responseScanCtrl.Mode()),
		Enabled: h.responseScanCtrl.Enabled(),
	})
}

// handleUpdateContentScanning updates the content scanning configuration.
// PUT /admin/api/v1/security/content-scanning
func (h *AdminAPIHandler) handleUpdateContentScanning(w http.ResponseWriter, r *http.Request) {
	if h.responseScanCtrl == nil {
		h.respondError(w, http.StatusServiceUnavailable, "content scanning not available")
		return
	}

	var req contentScanningRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate mode.
	if req.Mode != string(action.ScanModeMonitor) && req.Mode != string(action.ScanModeEnforce) {
		h.respondError(w, http.StatusBadRequest, "invalid mode: must be \"monitor\" or \"enforce\"")
		return
	}

	// Apply changes to the interceptor (takes effect immediately via atomic swap).
	h.responseScanCtrl.SetMode(action.ScanMode(req.Mode))
	if req.Enabled != nil {
		h.responseScanCtrl.SetEnabled(*req.Enabled)
	}

	// Also update additional controllers (e.g., HTTP gateway's response scan interceptor).
	for _, ctrl := range h.additionalScanCtrls {
		ctrl.SetMode(action.ScanMode(req.Mode))
		if req.Enabled != nil {
			ctrl.SetEnabled(*req.Enabled)
		}
	}

	// Persist to state.json.
	if h.stateStore != nil {
		if err := h.persistContentScanningConfig(req); err != nil {
			h.logger.Error("failed to persist content scanning config", "error", err)
			// Still return success since the runtime config was updated.
		}
	}

	enabled := h.responseScanCtrl.Enabled()
	h.logger.Info("content scanning configuration updated",
		"mode", req.Mode,
		"enabled", enabled,
	)

	h.respondJSON(w, http.StatusOK, contentScanningResponse{
		Mode:    req.Mode,
		Enabled: enabled,
		Message: "Content scanning configuration updated",
	})
}

// persistContentScanningConfig saves the content scanning config to state.json.
func (h *AdminAPIHandler) persistContentScanningConfig(req contentScanningRequest) error {
	appState, err := h.stateStore.Load()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if appState.ContentScanningConfig == nil {
		appState.ContentScanningConfig = &state.ContentScanningConfig{}
	}

	appState.ContentScanningConfig.Mode = req.Mode
	if req.Enabled != nil {
		appState.ContentScanningConfig.Enabled = *req.Enabled
	}
	appState.ContentScanningConfig.UpdatedAt = now

	return h.stateStore.Save(appState)
}
