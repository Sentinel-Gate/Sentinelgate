package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/google/uuid"
)

// inputScanConfigResponse is the JSON response for GET /admin/api/v1/security/input-scanning.
type inputScanConfigResponse struct {
	Enabled        bool                                               `json:"enabled"`
	Whitelist      []action.WhitelistEntry                            `json:"whitelist"`
	PatternActions map[action.ContentPatternType]action.ContentPatternAction `json:"pattern_actions,omitempty"`
}

// handleGetInputScanning returns the current input content scanning configuration.
// GET /admin/api/v1/security/input-scanning
func (h *AdminAPIHandler) handleGetInputScanning(w http.ResponseWriter, r *http.Request) {
	if h.contentScanInterceptor == nil {
		h.respondError(w, http.StatusServiceUnavailable, "input content scanning not available")
		return
	}

	h.respondJSON(w, http.StatusOK, inputScanConfigResponse{
		Enabled:        h.contentScanInterceptor.Enabled(),
		Whitelist:      h.contentScanInterceptor.GetWhitelist(),
		PatternActions: h.contentScanInterceptor.GetPatternActions(),
	})
}

// inputScanConfigRequest is the JSON body for PUT /admin/api/v1/security/input-scanning.
type inputScanConfigRequest struct {
	Enabled        *bool                                                      `json:"enabled"`
	PatternActions map[action.ContentPatternType]action.ContentPatternAction `json:"pattern_actions,omitempty"`
}

// handleUpdateInputScanning updates the input content scanning configuration.
// PUT /admin/api/v1/security/input-scanning
func (h *AdminAPIHandler) handleUpdateInputScanning(w http.ResponseWriter, r *http.Request) {
	if h.contentScanInterceptor == nil {
		h.respondError(w, http.StatusServiceUnavailable, "input content scanning not available")
		return
	}

	var req inputScanConfigRequest
	if !h.readJSONBody(w, r, &req) {
		return
	}

	// Validate all pattern actions before applying any mutations.
	for pt, act := range req.PatternActions {
		// M-37: Validate pattern type keys against known ContentPatternType constants.
		if !isValidContentPatternType(pt) {
			h.respondError(w, http.StatusBadRequest, "unknown pattern type: "+string(pt))
			return
		}
		switch act {
		case "off", "alert", "mask", "block":
			// valid
		default:
			h.respondError(w, http.StatusBadRequest, "invalid action for pattern "+string(pt)+": "+string(act))
			return
		}
	}

	// Capture old state for rollback on persist failure.
	oldEnabled := h.contentScanInterceptor.Enabled()
	oldPatternActions := h.contentScanInterceptor.GetPatternActions()

	// Apply changes to interceptor.
	if req.Enabled != nil {
		h.contentScanInterceptor.SetEnabled(*req.Enabled)
	}
	for pt, act := range req.PatternActions {
		h.contentScanInterceptor.SetPatternAction(pt, act)
	}

	// Persist to state.json.
	if h.stateStore != nil {
		if err := h.persistInputScanConfig(); err != nil {
			// Rollback in-memory state.
			h.contentScanInterceptor.SetEnabled(oldEnabled)
			for pt := range req.PatternActions {
				if oldAct, ok := oldPatternActions[pt]; ok {
					h.contentScanInterceptor.SetPatternAction(pt, oldAct)
				}
			}
			h.logger.Error("failed to persist input scan config", "error", err)
			h.respondError(w, http.StatusInternalServerError, "failed to persist input scan config")
			return
		}
	}

	h.respondJSON(w, http.StatusOK, inputScanConfigResponse{
		Enabled:        h.contentScanInterceptor.Enabled(),
		Whitelist:      h.contentScanInterceptor.GetWhitelist(),
		PatternActions: h.contentScanInterceptor.GetPatternActions(),
	})
}

// whitelistRequest is the JSON body for POST /admin/api/v1/security/input-scanning/whitelist.
type whitelistRequest struct {
	PatternType string `json:"pattern_type"`
	Scope       string `json:"scope"`
	Value       string `json:"value"`
}

// handleAddWhitelist adds a new whitelist entry.
// POST /admin/api/v1/security/input-scanning/whitelist
func (h *AdminAPIHandler) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	if h.contentScanInterceptor == nil {
		h.respondError(w, http.StatusServiceUnavailable, "input content scanning not available")
		return
	}

	var req whitelistRequest
	if !h.readJSONBody(w, r, &req) {
		return
	}

	if req.PatternType == "" || req.Scope == "" || req.Value == "" {
		h.respondError(w, http.StatusBadRequest, "pattern_type, scope, and value are required")
		return
	}

	// M-35: Validate PatternType against known ContentPatternType constants.
	if !isValidContentPatternType(action.ContentPatternType(req.PatternType)) {
		h.respondError(w, http.StatusBadRequest, "unknown pattern type: "+req.PatternType)
		return
	}

	// Validate scope.
	switch action.WhitelistScope(req.Scope) {
	case action.WhitelistScopePath, action.WhitelistScopeAgent, action.WhitelistScopeTool:
	default:
		h.respondError(w, http.StatusBadRequest, "scope must be path, agent, or tool")
		return
	}

	entry := action.WhitelistEntry{
		ID:          "wl_" + uuid.New().String(),
		PatternType: action.ContentPatternType(req.PatternType),
		Scope:       action.WhitelistScope(req.Scope),
		Value:       req.Value,
	}
	h.contentScanInterceptor.AddWhitelistEntry(entry)

	// Persist.
	if h.stateStore != nil {
		if err := h.persistWhitelist(); err != nil {
			// Rollback: remove the entry we just added.
			h.contentScanInterceptor.RemoveWhitelistEntry(entry.ID)
			h.logger.Error("failed to persist whitelist", "error", err)
			h.respondError(w, http.StatusInternalServerError, "failed to persist whitelist")
			return
		}
	}

	// Emit event on the notification bus.
	if h.eventBus != nil {
		h.eventBus.Publish(context.Background(), event.Event{
			Type:     "content.whitelist_added",
			Source:   "content-scanning",
			Severity: event.SeverityInfo,
			Payload: map[string]string{
				"pattern_type": req.PatternType,
				"scope":        req.Scope,
				"value":        req.Value,
			},
		})
	}

	h.respondJSON(w, http.StatusCreated, entry)
}

// handleRemoveWhitelist removes a whitelist entry.
// DELETE /admin/api/v1/security/input-scanning/whitelist/{id}
func (h *AdminAPIHandler) handleRemoveWhitelist(w http.ResponseWriter, r *http.Request) {
	if h.contentScanInterceptor == nil {
		h.respondError(w, http.StatusServiceUnavailable, "input content scanning not available")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "id is required")
		return
	}

	// Capture entry details before removal for event payload.
	var removedEntry action.WhitelistEntry
	for _, e := range h.contentScanInterceptor.GetWhitelist() {
		if e.ID == id {
			removedEntry = e
			break
		}
	}

	if !h.contentScanInterceptor.RemoveWhitelistEntry(id) {
		h.respondError(w, http.StatusNotFound, "whitelist entry not found")
		return
	}

	// Persist.
	if h.stateStore != nil {
		if err := h.persistWhitelist(); err != nil {
			// Rollback: re-add the entry we just removed.
			h.contentScanInterceptor.AddWhitelistEntry(removedEntry)
			h.logger.Error("failed to persist whitelist removal", "error", err)
			h.respondError(w, http.StatusInternalServerError, "failed to persist whitelist removal")
			return
		}
	}

	// Emit event on the notification bus.
	if h.eventBus != nil {
		h.eventBus.Publish(context.Background(), event.Event{
			Type:     "content.whitelist_removed",
			Source:   "content-scanning",
			Severity: event.SeverityInfo,
			Payload: map[string]string{
				"pattern_type": string(removedEntry.PatternType),
				"scope":        string(removedEntry.Scope),
				"value":        removedEntry.Value,
			},
		})
	}

	h.respondJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// isValidContentPatternType checks whether the given pattern type is a known constant.
func isValidContentPatternType(pt action.ContentPatternType) bool {
	switch pt {
	case action.PatternEmail, action.PatternCCNumber, action.PatternSSN,
		action.PatternUKNI, action.PatternPhone, action.PatternAWSKey,
		action.PatternGCPKey, action.PatternAzureKey, action.PatternStripe,
		action.PatternGitHub, action.PatternGeneric:
		return true
	default:
		return false
	}
}

// persistInputScanConfig saves the input scan enabled state to state.json.
func (h *AdminAPIHandler) persistInputScanConfig() error {
	return h.stateStore.Mutate(func(appState *state.AppState) error {
		if appState.ContentScanningConfig == nil {
			appState.ContentScanningConfig = &state.ContentScanningConfig{}
		}
		appState.ContentScanningConfig.InputScanEnabled = h.contentScanInterceptor.Enabled()
		// Persist pattern action overrides
		pa := h.contentScanInterceptor.GetPatternActions()
		if len(pa) > 0 {
			m := make(map[string]string, len(pa))
			for k, v := range pa {
				m[string(k)] = string(v)
			}
			appState.ContentScanningConfig.PatternActions = m
		}
		appState.ContentScanningConfig.UpdatedAt = time.Now().UTC()
		return nil
	})
}

// persistWhitelist saves the current whitelist to state.json.
func (h *AdminAPIHandler) persistWhitelist() error {
	entries := h.contentScanInterceptor.GetWhitelist()
	stateEntries := make([]state.ContentWhitelistEntry, 0, len(entries))
	for _, e := range entries {
		stateEntries = append(stateEntries, state.ContentWhitelistEntry{
			ID:          e.ID,
			PatternType: string(e.PatternType),
			Scope:       string(e.Scope),
			Value:       e.Value,
			CreatedAt:   time.Now().UTC(),
		})
	}

	return h.stateStore.Mutate(func(appState *state.AppState) error {
		if appState.ContentScanningConfig == nil {
			appState.ContentScanningConfig = &state.ContentScanningConfig{}
		}
		appState.ContentScanningConfig.Whitelist = stateEntries
		appState.ContentScanningConfig.UpdatedAt = time.Now().UTC()
		return nil
	})
}
