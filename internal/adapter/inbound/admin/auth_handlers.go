package admin

import (
	"net/http"
)

// --- Request/response types ---

// authStatusResponse is the JSON response for GET /admin/api/auth/status.
type authStatusResponse struct {
	AuthRequired bool `json:"auth_required"`
	PasswordSet  bool `json:"password_set"`
	Localhost    bool `json:"localhost"`
}

// --- Auth handlers ---

// handleAuthStatus returns authentication status information.
// GET /admin/api/auth/status
//
// Response: {"auth_required": bool, "password_set": bool, "localhost": bool}
//   - auth_required: true if request is NOT from localhost (remote access needs SSH tunnel)
//   - password_set: always false in OSS (no remote auth)
//   - localhost: true if request originates from loopback address
func (h *AdminAPIHandler) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	h.respondJSON(w, http.StatusOK, authStatusResponse{
		AuthRequired: !isLocalhost(r),
		PasswordSet:  false, // No remote auth in OSS
		Localhost:    isLocalhost(r),
	})
}
