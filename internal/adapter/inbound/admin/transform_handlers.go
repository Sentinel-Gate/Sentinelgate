package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/transform"
	"github.com/google/uuid"
)

// WithTransformStore sets the transform rule store.
func WithTransformStore(s transform.TransformStore) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.transformStore = s }
}

// WithTransformExecutor sets the transform executor.
func WithTransformExecutor(e *transform.TransformExecutor) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.transformExecutor = e }
}

// SetTransformStore sets the transform store after construction.
// This is needed when the store is created after the AdminAPIHandler (due to
// boot sequence ordering where BOOT-07 builds the interceptor chain after services).
func (h *AdminAPIHandler) SetTransformStore(s transform.TransformStore) {
	h.transformStore = s
}

// SetTransformExecutor sets the transform executor after construction.
func (h *AdminAPIHandler) SetTransformExecutor(e *transform.TransformExecutor) {
	h.transformExecutor = e
}

// transformRequest is the JSON body for create/update transform rule endpoints.
type transformRequest struct {
	Name      string                  `json:"name"`
	Type      string                  `json:"type"`
	ToolMatch string                  `json:"tool_match"`
	Priority  int                     `json:"priority"`
	Enabled   bool                    `json:"enabled"`
	Config    transform.TransformConfig `json:"config"`
}

// transformResponse is the JSON representation of a transform rule returned by the API.
type transformResponse struct {
	ID        string                  `json:"id"`
	Name      string                  `json:"name"`
	Type      string                  `json:"type"`
	ToolMatch string                  `json:"tool_match"`
	Priority  int                     `json:"priority"`
	Enabled   bool                    `json:"enabled"`
	Config    transform.TransformConfig `json:"config"`
	CreatedAt time.Time               `json:"created_at"`
	UpdatedAt time.Time               `json:"updated_at"`
}

// transformTestRequest is the JSON body for the test transform endpoint.
type transformTestRequest struct {
	Text  string             `json:"text"`
	Rules []transformRequest `json:"rules"`
}

// transformTestResponse is the JSON response from the test transform endpoint.
type transformTestResponse struct {
	Output  string                    `json:"output"`
	Results []transform.TransformResult `json:"results"`
}

// handleListTransforms returns all configured transform rules.
// GET /admin/api/v1/transforms
func (h *AdminAPIHandler) handleListTransforms(w http.ResponseWriter, r *http.Request) {
	if h.transformStore == nil {
		h.respondError(w, http.StatusInternalServerError, "transform store not configured")
		return
	}

	rules, err := h.transformStore.List(r.Context())
	if err != nil {
		h.logger.Error("failed to list transforms", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to list transforms")
		return
	}

	result := make([]transformResponse, 0, len(rules))
	for _, r := range rules {
		result = append(result, toTransformResponse(r))
	}

	h.respondJSON(w, http.StatusOK, result)
}

// handleGetTransform returns a single transform rule by ID.
// GET /admin/api/v1/transforms/{id}
func (h *AdminAPIHandler) handleGetTransform(w http.ResponseWriter, r *http.Request) {
	if h.transformStore == nil {
		h.respondError(w, http.StatusInternalServerError, "transform store not configured")
		return
	}

	id := h.pathParam(r, "id")

	rule, err := h.transformStore.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, transform.ErrTransformNotFound) {
			h.respondError(w, http.StatusNotFound, "transform rule not found")
			return
		}
		h.logger.Error("failed to get transform", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to get transform")
		return
	}

	h.respondJSON(w, http.StatusOK, toTransformResponse(rule))
}

// handleCreateTransform creates a new transform rule.
// POST /admin/api/v1/transforms
func (h *AdminAPIHandler) handleCreateTransform(w http.ResponseWriter, r *http.Request) {
	if h.transformStore == nil {
		h.respondError(w, http.StatusInternalServerError, "transform store not configured")
		return
	}

	var req transformRequest
	if err := h.readJSON(r, &req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	now := time.Now().UTC()
	rule := &transform.TransformRule{
		ID:        uuid.New().String(),
		Name:      req.Name,
		Type:      transform.TransformType(req.Type),
		ToolMatch: req.ToolMatch,
		Priority:  req.Priority,
		Enabled:   req.Enabled,
		Config:    req.Config,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := rule.Validate(); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.transformStore.Put(r.Context(), rule); err != nil {
		h.logger.Error("failed to create transform", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to create transform")
		return
	}

	// Persist to state.json.
	if err := h.persistTransforms(r.Context()); err != nil {
		h.logger.Error("failed to persist transforms to state", "error", err)
	}

	h.respondJSON(w, http.StatusCreated, toTransformResponse(rule))
}

// handleUpdateTransform updates an existing transform rule.
// PUT /admin/api/v1/transforms/{id}
func (h *AdminAPIHandler) handleUpdateTransform(w http.ResponseWriter, r *http.Request) {
	if h.transformStore == nil {
		h.respondError(w, http.StatusInternalServerError, "transform store not configured")
		return
	}

	id := h.pathParam(r, "id")

	// Load existing rule to preserve ID and CreatedAt.
	existing, err := h.transformStore.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, transform.ErrTransformNotFound) {
			h.respondError(w, http.StatusNotFound, "transform rule not found")
			return
		}
		h.logger.Error("failed to get transform for update", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to get transform")
		return
	}

	var req transformRequest
	if err := h.readJSON(r, &req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Merge: preserve ID and CreatedAt, update everything else.
	existing.Name = req.Name
	existing.Type = transform.TransformType(req.Type)
	existing.ToolMatch = req.ToolMatch
	existing.Priority = req.Priority
	existing.Enabled = req.Enabled
	existing.Config = req.Config
	existing.UpdatedAt = time.Now().UTC()

	if err := existing.Validate(); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := h.transformStore.Put(r.Context(), existing); err != nil {
		h.logger.Error("failed to update transform", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to update transform")
		return
	}

	// Persist to state.json.
	if err := h.persistTransforms(r.Context()); err != nil {
		h.logger.Error("failed to persist transforms to state", "error", err)
	}

	h.respondJSON(w, http.StatusOK, toTransformResponse(existing))
}

// handleDeleteTransform removes a transform rule.
// DELETE /admin/api/v1/transforms/{id}
func (h *AdminAPIHandler) handleDeleteTransform(w http.ResponseWriter, r *http.Request) {
	if h.transformStore == nil {
		h.respondError(w, http.StatusInternalServerError, "transform store not configured")
		return
	}

	id := h.pathParam(r, "id")

	if err := h.transformStore.Delete(r.Context(), id); err != nil {
		h.logger.Error("failed to delete transform", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to delete transform")
		return
	}

	// Persist to state.json.
	if err := h.persistTransforms(r.Context()); err != nil {
		h.logger.Error("failed to persist transforms to state", "error", err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleTestTransform applies transforms to sample text and returns the result.
// POST /admin/api/v1/transforms/test
func (h *AdminAPIHandler) handleTestTransform(w http.ResponseWriter, r *http.Request) {
	if h.transformExecutor == nil {
		h.respondError(w, http.StatusInternalServerError, "transform executor not configured")
		return
	}

	var req transformTestRequest
	if err := h.readJSON(r, &req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Build TransformRule slice from request, validate each.
	rules := make([]transform.TransformRule, 0, len(req.Rules))
	for i, rr := range req.Rules {
		rule := transform.TransformRule{
			ID:        uuid.New().String(),
			Name:      rr.Name,
			Type:      transform.TransformType(rr.Type),
			ToolMatch: rr.ToolMatch,
			Priority:  rr.Priority,
			Enabled:   rr.Enabled,
			Config:    rr.Config,
		}
		if err := rule.Validate(); err != nil {
			h.respondError(w, http.StatusBadRequest, "rule["+strconv.Itoa(i)+"]: "+err.Error())
			return
		}
		rules = append(rules, rule)
	}

	output, results := h.transformExecutor.Apply(req.Text, rules)

	h.respondJSON(w, http.StatusOK, transformTestResponse{
		Output:  output,
		Results: results,
	})
}

// persistTransforms rebuilds the Transforms slice in state.json from the transform store.
func (h *AdminAPIHandler) persistTransforms(ctx context.Context) error {
	rules, err := h.transformStore.List(ctx)
	if err != nil {
		return err
	}
	appState, err := h.stateStore.Load()
	if err != nil {
		return err
	}
	appState.Transforms = make([]state.TransformRuleEntry, 0, len(rules))
	for _, r := range rules {
		var cfgMap map[string]interface{}
		if cfgBytes, err := json.Marshal(r.Config); err == nil {
			_ = json.Unmarshal(cfgBytes, &cfgMap)
		}
		appState.Transforms = append(appState.Transforms, state.TransformRuleEntry{
			ID:        r.ID,
			Name:      r.Name,
			Type:      string(r.Type),
			ToolMatch: r.ToolMatch,
			Priority:  r.Priority,
			Enabled:   r.Enabled,
			Config:    cfgMap,
			CreatedAt: r.CreatedAt,
			UpdatedAt: r.UpdatedAt,
		})
	}
	return h.stateStore.Save(appState)
}

// toTransformResponse converts a TransformRule to the API response format.
func toTransformResponse(r *transform.TransformRule) transformResponse {
	return transformResponse{
		ID:        r.ID,
		Name:      r.Name,
		Type:      string(r.Type),
		ToolMatch: r.ToolMatch,
		Priority:  r.Priority,
		Enabled:   r.Enabled,
		Config:    r.Config,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

