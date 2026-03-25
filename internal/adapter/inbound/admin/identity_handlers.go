package admin

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// identityRequest is the JSON body for create and update identity endpoints.
type identityRequest struct {
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

// identityResponse is the JSON representation of an identity returned by the API.
type identityResponse struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Roles     []string `json:"roles"`
	ReadOnly  bool     `json:"read_only"`
	CreatedAt string   `json:"created_at"`
}

// WithIdentityService sets the identity and API key management service.
func WithIdentityService(s *service.IdentityService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.identityService = s }
}

// handleListIdentities returns all identities.
// GET /admin/api/identities
func (h *AdminAPIHandler) handleListIdentities(w http.ResponseWriter, r *http.Request) {
	if h.identityService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "identity service not configured")
		return
	}
	ctx := r.Context()

	identities, err := h.identityService.ListIdentities(ctx)
	if err != nil {
		h.logger.Error("failed to list identities", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to list identities")
		return
	}

	result := make([]identityResponse, 0, len(identities))
	for _, identity := range identities {
		result = append(result, identityResponse{
			ID:        identity.ID,
			Name:      identity.Name,
			Roles:     identity.Roles,
			ReadOnly:  identity.ReadOnly,
			CreatedAt: identity.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	h.respondJSON(w, http.StatusOK, result)
}

// handleCreateIdentity creates a new identity.
// POST /admin/api/identities
func (h *AdminAPIHandler) handleCreateIdentity(w http.ResponseWriter, r *http.Request) {
	if h.identityService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "identity service not configured")
		return
	}
	ctx := r.Context()

	var req identityRequest
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}

	if req.Name == "" {
		h.respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	// H-14: Validate all roles to prevent arbitrary role injection.
	for _, role := range req.Roles {
		if !auth.Role(role).IsValid() {
			h.respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid role: %q", role))
			return
		}
	}

	input := service.CreateIdentityInput{
		Name:  req.Name,
		Roles: req.Roles,
	}

	identity, err := h.identityService.CreateIdentity(ctx, input)
	if err != nil {
		if errors.Is(err, service.ErrDuplicateName) {
			h.respondError(w, http.StatusConflict, "identity name already exists")
			return
		}
		h.internalError(w, "failed to create identity", err)
		return
	}

	// Auth store sync is handled centrally via IdentityService.PostMutationHook.
	// No manual sync needed here.

	h.respondJSON(w, http.StatusCreated, identityResponse{
		ID:        identity.ID,
		Name:      identity.Name,
		Roles:     identity.Roles,
		ReadOnly:  identity.ReadOnly,
		CreatedAt: identity.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// handleUpdateIdentity updates an existing identity.
// PUT /admin/api/identities/{id}
func (h *AdminAPIHandler) handleUpdateIdentity(w http.ResponseWriter, r *http.Request) {
	if h.identityService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "identity service not configured")
		return
	}
	ctx := r.Context()
	id := h.pathParam(r, "id")

	var req identityRequest
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}

	// H-14: Validate all roles to prevent arbitrary role injection.
	for _, role := range req.Roles {
		if !auth.Role(role).IsValid() {
			h.respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid role: %q", role))
			return
		}
	}

	input := service.UpdateIdentityInput{
		Roles: req.Roles,
	}
	if req.Name != "" {
		input.Name = &req.Name
	}

	identity, err := h.identityService.UpdateIdentity(ctx, id, input)
	if err != nil {
		if errors.Is(err, service.ErrIdentityNotFound) {
			h.respondError(w, http.StatusNotFound, "identity not found")
			return
		}
		if errors.Is(err, service.ErrDuplicateName) {
			h.respondError(w, http.StatusConflict, "identity name already exists")
			return
		}
		if errors.Is(err, service.ErrReadOnly) {
			h.respondError(w, http.StatusForbidden, "cannot modify read-only identity")
			return
		}
		h.internalError(w, "failed to update identity", err)
		return
	}

	h.respondJSON(w, http.StatusOK, identityResponse{
		ID:        identity.ID,
		Name:      identity.Name,
		Roles:     identity.Roles,
		ReadOnly:  identity.ReadOnly,
		CreatedAt: identity.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// handleDeleteIdentity deletes an identity and all its API keys.
// DELETE /admin/api/identities/{id}
// BUG-6 FIX: After deleting, invalidates all cached sessions for the identity
// so any connected agents are immediately disconnected.
func (h *AdminAPIHandler) handleDeleteIdentity(w http.ResponseWriter, r *http.Request) {
	if h.identityService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "identity service not configured")
		return
	}
	ctx := r.Context()
	id := h.pathParam(r, "id")

	_, err := h.identityService.DeleteIdentity(ctx, id)
	if err != nil {
		if errors.Is(err, service.ErrIdentityNotFound) {
			h.respondError(w, http.StatusNotFound, "identity not found")
			return
		}
		if errors.Is(err, service.ErrReadOnly) {
			h.respondError(w, http.StatusForbidden, "cannot delete read-only identity")
			return
		}
		h.logger.Error("failed to delete identity", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to delete identity")
		return
	}

	// Auth store sync is handled centrally via IdentityService.PostMutationHook.
	// No manual sync needed here.

	// BUG-6 FIX: Invalidate all cached sessions for this identity so any
	// connected agents are immediately disconnected.
	if h.sessionCacheInvalidator != nil {
		h.sessionCacheInvalidator.InvalidateByIdentity(id)
	}

	w.WriteHeader(http.StatusNoContent)
}
