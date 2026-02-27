package admin

import (
	"net/http"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
)

// WithApprovalStore sets the approval store on the AdminAPIHandler.
func WithApprovalStore(store *action.ApprovalStore) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.approvalStore = store }
}

// SetApprovalStore sets the approval store after construction.
// This is needed when the store is created after the AdminAPIHandler
// (due to boot sequence ordering where BOOT-07 builds the interceptor
// chain after the admin handler).
func (h *AdminAPIHandler) SetApprovalStore(store *action.ApprovalStore) {
	h.approvalStore = store
}

// approvalResponse is the JSON response for a single pending approval.
type approvalResponse struct {
	ID           string `json:"id"`
	ToolName     string `json:"tool_name"`
	IdentityName string `json:"identity_name"`
	IdentityID   string `json:"identity_id"`
	Status       string `json:"status"`
	CreatedAt    string `json:"created_at"`
}

// handleListApprovals returns all pending approvals as a JSON array.
// GET /admin/api/v1/approvals
func (h *AdminAPIHandler) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	if h.approvalStore == nil {
		h.respondJSON(w, http.StatusOK, []approvalResponse{})
		return
	}

	pending := h.approvalStore.List()
	result := make([]approvalResponse, len(pending))
	for i, p := range pending {
		result[i] = approvalResponse{
			ID:           p.ID,
			ToolName:     p.ToolName,
			IdentityName: p.IdentityName,
			IdentityID:   p.IdentityID,
			Status:       p.Status,
			CreatedAt:    p.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	h.respondJSON(w, http.StatusOK, result)
}

// handleApproveRequest approves a pending approval request.
// POST /admin/api/v1/approvals/{id}/approve
func (h *AdminAPIHandler) handleApproveRequest(w http.ResponseWriter, r *http.Request) {
	if h.approvalStore == nil {
		h.respondError(w, http.StatusNotFound, "approval store not configured")
		return
	}

	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "approval ID is required")
		return
	}

	if err := h.approvalStore.Approve(id); err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "approved",
		"id":      id,
		"message": "approval granted",
	})
}

// denyRequest is the JSON request body for denying an approval.
type denyRequest struct {
	Reason string `json:"reason"`
}

// handleDenyRequest denies a pending approval request.
// POST /admin/api/v1/approvals/{id}/deny
func (h *AdminAPIHandler) handleDenyRequest(w http.ResponseWriter, r *http.Request) {
	if h.approvalStore == nil {
		h.respondError(w, http.StatusNotFound, "approval store not configured")
		return
	}

	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "approval ID is required")
		return
	}

	// Read optional reason from body
	var req denyRequest
	_ = h.readJSON(r, &req) // Ignore errors -- reason is optional

	reason := req.Reason
	if reason == "" {
		reason = "denied by admin"
	}

	if err := h.approvalStore.Deny(id, reason); err != nil {
		h.respondError(w, http.StatusNotFound, err.Error())
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "denied",
		"id":      id,
		"message": reason,
	})
}
