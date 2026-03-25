package admin

import (
	"context"
	"errors"
	"net/http"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/quota"
)

// WithQuotaStore sets the quota configuration store.
func WithQuotaStore(s quota.QuotaStore) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.quotaStore = s }
}

// SetQuotaStore sets the quota store after construction.
// This is needed when the store is created after the AdminAPIHandler (due to
// boot sequence ordering where BOOT-07 builds the interceptor chain after services).
func (h *AdminAPIHandler) SetQuotaStore(s quota.QuotaStore) {
	h.quotaStore = s
}

// quotaRequest is the JSON body for create/update quota endpoints.
type quotaRequest struct {
	MaxCallsPerSession   int64            `json:"max_calls_per_session,omitempty"`
	MaxWritesPerSession  int64            `json:"max_writes_per_session,omitempty"`
	MaxDeletesPerSession int64            `json:"max_deletes_per_session,omitempty"`
	MaxCallsPerMinute    int64            `json:"max_calls_per_minute,omitempty"`
	MaxCallsPerDay       int64            `json:"max_calls_per_day,omitempty"`
	ToolLimits           map[string]int64 `json:"tool_limits,omitempty"`
	Action               string           `json:"action"`
	Enabled              bool             `json:"enabled"`
}

// quotaResponse is the JSON representation of a quota config returned by the API.
type quotaResponse struct {
	IdentityID           string           `json:"identity_id"`
	MaxCallsPerSession   int64            `json:"max_calls_per_session,omitempty"`
	MaxWritesPerSession  int64            `json:"max_writes_per_session,omitempty"`
	MaxDeletesPerSession int64            `json:"max_deletes_per_session,omitempty"`
	MaxCallsPerMinute    int64            `json:"max_calls_per_minute,omitempty"`
	MaxCallsPerDay       int64            `json:"max_calls_per_day,omitempty"`
	ToolLimits           map[string]int64 `json:"tool_limits,omitempty"`
	Action               string           `json:"action"`
	Enabled              bool             `json:"enabled"`
}

// handleListQuotas returns all configured quotas.
// GET /admin/api/v1/quotas
func (h *AdminAPIHandler) handleListQuotas(w http.ResponseWriter, r *http.Request) {
	if h.quotaStore == nil {
		h.respondError(w, http.StatusInternalServerError, "quota store not configured")
		return
	}

	configs, err := h.quotaStore.List(r.Context())
	if err != nil {
		h.logger.Error("failed to list quotas", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to list quotas")
		return
	}

	result := make([]quotaResponse, 0, len(configs))
	for _, c := range configs {
		result = append(result, toQuotaResponse(c))
	}

	h.respondJSON(w, http.StatusOK, result)
}

// handleGetQuota returns the quota config for a specific identity.
// GET /admin/api/v1/quotas/{identity_id}
func (h *AdminAPIHandler) handleGetQuota(w http.ResponseWriter, r *http.Request) {
	if h.quotaStore == nil {
		h.respondError(w, http.StatusInternalServerError, "quota store not configured")
		return
	}

	identityID := h.pathParam(r, "identity_id")

	cfg, err := h.quotaStore.Get(r.Context(), identityID)
	if err != nil {
		if errors.Is(err, quota.ErrQuotaNotFound) {
			h.respondError(w, http.StatusNotFound, "quota config not found")
			return
		}
		h.logger.Error("failed to get quota", "identity_id", identityID, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to get quota")
		return
	}

	h.respondJSON(w, http.StatusOK, toQuotaResponse(cfg))
}

// handlePutQuota creates or updates the quota config for an identity.
// PUT /admin/api/v1/quotas/{identity_id}
func (h *AdminAPIHandler) handlePutQuota(w http.ResponseWriter, r *http.Request) {
	if h.quotaStore == nil {
		h.respondError(w, http.StatusInternalServerError, "quota store not configured")
		return
	}

	identityID := h.pathParam(r, "identity_id")

	var req quotaRequest
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}

	// Validate action
	if req.Action != "deny" && req.Action != "warn" {
		h.respondError(w, http.StatusBadRequest, "action must be \"deny\" or \"warn\"")
		return
	}

	// Validate non-negative limits
	if req.MaxCallsPerSession < 0 || req.MaxWritesPerSession < 0 ||
		req.MaxDeletesPerSession < 0 || req.MaxCallsPerMinute < 0 ||
		req.MaxCallsPerDay < 0 {
		h.respondError(w, http.StatusBadRequest, "limits must be non-negative")
		return
	}
	for toolName, limit := range req.ToolLimits {
		if limit < 0 {
			h.respondError(w, http.StatusBadRequest, "tool limit for "+toolName+" must be non-negative")
			return
		}
	}

	cfg := &quota.QuotaConfig{
		IdentityID:           identityID,
		MaxCallsPerSession:   req.MaxCallsPerSession,
		MaxWritesPerSession:  req.MaxWritesPerSession,
		MaxDeletesPerSession: req.MaxDeletesPerSession,
		MaxCallsPerMinute:    req.MaxCallsPerMinute,
		MaxCallsPerDay:       req.MaxCallsPerDay,
		ToolLimits:           req.ToolLimits,
		Action:               quota.QuotaAction(req.Action),
		Enabled:              req.Enabled,
	}

	// Capture old config for rollback on persist failure.
	oldCfg, oldErr := h.quotaStore.Get(r.Context(), identityID)

	if err := h.quotaStore.Put(r.Context(), cfg); err != nil {
		h.logger.Error("failed to put quota", "identity_id", identityID, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to save quota")
		return
	}

	// Persist to state.json — return error if persist fails (M-12).
	if err := h.persistQuotas(r.Context()); err != nil {
		// Rollback in-memory state.
		if oldErr != nil {
			_ = h.quotaStore.Delete(r.Context(), identityID)
		} else {
			_ = h.quotaStore.Put(r.Context(), oldCfg)
		}
		h.logger.Error("failed to persist quotas to state", "error", err)
		h.respondError(w, http.StatusInternalServerError, "quota saved in memory but failed to persist to state")
		return
	}

	h.respondJSON(w, http.StatusOK, toQuotaResponse(cfg))
}

// handleDeleteQuota removes the quota config for an identity.
// DELETE /admin/api/v1/quotas/{identity_id}
func (h *AdminAPIHandler) handleDeleteQuota(w http.ResponseWriter, r *http.Request) {
	if h.quotaStore == nil {
		h.respondError(w, http.StatusInternalServerError, "quota store not configured")
		return
	}

	identityID := h.pathParam(r, "identity_id")

	// Capture existing config for rollback on persist failure.
	existing, err := h.quotaStore.Get(r.Context(), identityID)
	if err != nil {
		if errors.Is(err, quota.ErrQuotaNotFound) {
			h.respondError(w, http.StatusNotFound, "quota config not found")
			return
		}
		h.logger.Error("failed to get quota for delete", "identity_id", identityID, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to delete quota")
		return
	}

	if err := h.quotaStore.Delete(r.Context(), identityID); err != nil {
		h.logger.Error("failed to delete quota", "identity_id", identityID, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to delete quota")
		return
	}

	// Persist to state.json — return error if persist fails (M-12).
	if err := h.persistQuotas(r.Context()); err != nil {
		// Rollback: re-add deleted config.
		_ = h.quotaStore.Put(r.Context(), existing)
		h.logger.Error("failed to persist quotas to state", "error", err)
		h.respondError(w, http.StatusInternalServerError, "quota deleted in memory but failed to persist to state")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// persistQuotas rebuilds the Quotas slice in state.json from the quota store.
func (h *AdminAPIHandler) persistQuotas(ctx context.Context) error {
	configs, err := h.quotaStore.List(ctx)
	if err != nil {
		return err
	}
	entries := make([]state.QuotaConfigEntry, 0, len(configs))
	for _, c := range configs {
		entries = append(entries, state.QuotaConfigEntry{
			IdentityID:           c.IdentityID,
			MaxCallsPerSession:   c.MaxCallsPerSession,
			MaxWritesPerSession:  c.MaxWritesPerSession,
			MaxDeletesPerSession: c.MaxDeletesPerSession,
			MaxCallsPerMinute:    c.MaxCallsPerMinute,
			MaxCallsPerDay:       c.MaxCallsPerDay,
			ToolLimits:           c.ToolLimits,
			Action:               string(c.Action),
			Enabled:              c.Enabled,
		})
	}
	return h.stateStore.Mutate(func(appState *state.AppState) error {
		appState.Quotas = entries
		return nil
	})
}

// toQuotaResponse converts a QuotaConfig to the API response format.
func toQuotaResponse(c *quota.QuotaConfig) quotaResponse {
	return quotaResponse{
		IdentityID:           c.IdentityID,
		MaxCallsPerSession:   c.MaxCallsPerSession,
		MaxWritesPerSession:  c.MaxWritesPerSession,
		MaxDeletesPerSession: c.MaxDeletesPerSession,
		MaxCallsPerMinute:    c.MaxCallsPerMinute,
		MaxCallsPerDay:       c.MaxCallsPerDay,
		ToolLimits:           c.ToolLimits,
		Action:               string(c.Action),
		Enabled:              c.Enabled,
	}
}
