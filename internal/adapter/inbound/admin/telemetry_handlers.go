package admin

import (
	"net/http"
	"regexp"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// validServiceName matches alphanumeric chars, dots, dashes, and underscores (L-44).
var validServiceName = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// SetTelemetryService sets the telemetry service after construction.
func (h *AdminAPIHandler) SetTelemetryService(s *service.TelemetryService) {
	h.telemetryService = s
}

// handleGetTelemetryConfig returns the current telemetry configuration.
// GET /admin/api/v1/telemetry/config
func (h *AdminAPIHandler) handleGetTelemetryConfig(w http.ResponseWriter, r *http.Request) {
	if h.telemetryService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "telemetry service not available")
		return
	}
	cfg := h.telemetryService.Config()
	h.respondJSON(w, http.StatusOK, cfg)
}

// handlePutTelemetryConfig updates the telemetry configuration.
// PUT /admin/api/v1/telemetry/config
func (h *AdminAPIHandler) handlePutTelemetryConfig(w http.ResponseWriter, r *http.Request) {
	if h.telemetryService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "telemetry service not available")
		return
	}

	var req service.TelemetryConfig
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}

	// L-44: Validate ServiceName (alphanumeric, dots, dashes, underscores, max 128 chars).
	if req.ServiceName != "" {
		if len(req.ServiceName) > 128 {
			h.respondError(w, http.StatusBadRequest, "service_name must be at most 128 characters")
			return
		}
		if !validServiceName.MatchString(req.ServiceName) {
			h.respondError(w, http.StatusBadRequest, "service_name must contain only alphanumeric characters, dots, dashes, and underscores")
			return
		}
	}

	// Persist to state.json FIRST — only mutate in-memory on success.
	if h.stateStore != nil {
		if err := h.stateStore.Mutate(func(appState *state.AppState) error {
			appState.TelemetryConfig = &state.TelemetryConfigEntry{
				Enabled:     req.Enabled,
				ServiceName: req.ServiceName,
				UpdatedAt:   time.Now().UTC(),
			}
			return nil
		}); err != nil {
			h.logger.Error("failed to persist telemetry config", "error", err)
			h.respondError(w, http.StatusInternalServerError, "failed to persist telemetry config")
			return
		}
	}

	if err := h.telemetryService.SetConfig(req); err != nil {
		h.internalError(w, "failed to set telemetry config", err)
		return
	}

	cfg := h.telemetryService.Config()
	h.respondJSON(w, http.StatusOK, cfg)
}
