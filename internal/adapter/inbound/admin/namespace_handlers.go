package admin

import (
	"net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// SetNamespaceService sets the namespace service after construction.
func (h *AdminAPIHandler) SetNamespaceService(s *service.NamespaceService) {
	h.namespaceService = s
}

// handleGetNamespaceConfig returns the current namespace configuration.
// GET /admin/api/v1/namespaces/config
func (h *AdminAPIHandler) handleGetNamespaceConfig(w http.ResponseWriter, r *http.Request) {
	if h.namespaceService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "namespace service not available")
		return
	}
	h.respondJSON(w, http.StatusOK, h.namespaceService.Config())
}

// handlePutNamespaceConfig updates the namespace configuration.
// PUT /admin/api/v1/namespaces/config
func (h *AdminAPIHandler) handlePutNamespaceConfig(w http.ResponseWriter, r *http.Request) {
	if h.namespaceService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "namespace service not available")
		return
	}

	var cfg service.NamespaceConfig
	if err := h.readJSON(r, &cfg); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}

	// L-43: Reject rules that set both VisibleTools and HiddenTools simultaneously.
	for role, rule := range cfg.Rules {
		if rule != nil && len(rule.VisibleTools) > 0 && len(rule.HiddenTools) > 0 {
			h.respondError(w, http.StatusBadRequest,
				"namespace rule for role '"+role+"' cannot set both visible_tools and hidden_tools")
			return
		}
	}

	// Persist to state.json FIRST — only mutate in-memory on success.
	if h.stateStore != nil {
		if err := h.stateStore.Mutate(func(appState *state.AppState) error {
			entry := &state.NamespaceConfigEntry{
				Enabled:   cfg.Enabled,
				UpdatedAt: time.Now().UTC(),
			}
			entry.Rules = make(map[string]state.NamespaceRuleEntry)
			for role, rule := range cfg.Rules {
				entry.Rules[role] = state.NamespaceRuleEntry{
					VisibleTools: rule.VisibleTools,
					HiddenTools:  rule.HiddenTools,
				}
			}
			appState.NamespaceConfig = entry
			return nil
		}); err != nil {
			h.logger.Error("failed to persist namespace config", "error", err)
			h.respondError(w, http.StatusInternalServerError, "failed to persist namespace config")
			return
		}
	}

	h.namespaceService.SetConfig(cfg)

	h.respondJSON(w, http.StatusOK, h.namespaceService.Config())
}
