package admin

import (
	"errors"
	"net/http"

	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// generateKeyRequest is the JSON body for the generate key endpoint.
type generateKeyRequest struct {
	IdentityID string `json:"identity_id"`
	Name       string `json:"name"`
}

// generateKeyResponse is the JSON response for key generation.
// The CleartextKey is returned exactly once and never stored.
type generateKeyResponse struct {
	ID           string `json:"id"`
	IdentityID   string `json:"identity_id"`
	Name         string `json:"name"`
	CleartextKey string `json:"cleartext_key"`
	CreatedAt    string `json:"created_at"`
}

// keyResponse is the JSON representation of an API key (without cleartext).
type keyResponse struct {
	ID         string `json:"id"`
	IdentityID string `json:"identity_id"`
	Name       string `json:"name"`
	Revoked    bool   `json:"revoked"`
	ReadOnly   bool   `json:"read_only"`
	CreatedAt  string `json:"created_at"`
}

// handleListKeys returns all API keys across all identities.
// GET /admin/api/keys
func (h *AdminAPIHandler) handleListKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	keys, err := h.identityService.ListAllKeys(ctx)
	if err != nil {
		h.logger.Error("failed to list keys", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to list keys")
		return
	}

	result := make([]keyResponse, 0, len(keys))
	for _, k := range keys {
		result = append(result, keyResponse{
			ID:         k.ID,
			IdentityID: k.IdentityID,
			Name:       k.Name,
			Revoked:    k.Revoked,
			ReadOnly:   k.ReadOnly,
			CreatedAt:  k.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	h.respondJSON(w, http.StatusOK, result)
}

// handleGenerateKey generates a new API key for an identity.
// POST /admin/api/keys
func (h *AdminAPIHandler) handleGenerateKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req generateKeyRequest
	if err := h.readJSON(r, &req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.IdentityID == "" {
		h.respondError(w, http.StatusBadRequest, "identity_id is required")
		return
	}
	if req.Name == "" {
		h.respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	input := service.GenerateKeyInput{
		IdentityID: req.IdentityID,
		Name:       req.Name,
	}

	result, err := h.identityService.GenerateKey(ctx, input)
	if err != nil {
		if errors.Is(err, service.ErrIdentityNotFound) {
			h.respondError(w, http.StatusNotFound, "identity not found")
			return
		}
		// SECU-06: Only log the error, never the cleartext key.
		h.logger.Error("failed to generate key", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to generate key")
		return
	}

	// Auth store sync is handled centrally via IdentityService.PostMutationHook.
	// No manual sync needed here.

	// SECU-06: Cleartext key is returned in response only, never logged.
	h.respondJSON(w, http.StatusCreated, generateKeyResponse{
		ID:           result.KeyEntry.ID,
		IdentityID:   result.KeyEntry.IdentityID,
		Name:         result.KeyEntry.Name,
		CleartextKey: result.CleartextKey,
		CreatedAt:    result.KeyEntry.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// handleRevokeKey revokes an API key.
// DELETE /admin/api/keys/{id}
func (h *AdminAPIHandler) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := h.pathParam(r, "id")

	_, err := h.identityService.RevokeKey(ctx, id)
	if err != nil {
		if errors.Is(err, service.ErrAPIKeyNotFound) {
			h.respondError(w, http.StatusNotFound, "api key not found")
			return
		}
		if errors.Is(err, service.ErrReadOnly) {
			h.respondError(w, http.StatusForbidden, "cannot revoke read-only key")
			return
		}
		h.logger.Error("failed to revoke key", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to revoke key")
		return
	}

	// Auth store sync is handled centrally via IdentityService.PostMutationHook.
	// No manual sync needed here.

	w.WriteHeader(http.StatusNoContent)
}
