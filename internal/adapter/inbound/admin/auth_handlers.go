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
//
// L-37: This endpoint is intentionally exempt from rate limiting for localhost.
// The admin UI is localhost-only in OSS, so the auth status endpoint is only
// reachable by local users (or via SSH tunnel). Remote access is blocked by
// the admin auth middleware, and remote IPs are subject to the global API rate
// limiter (60 req/min/IP). There is no brute-force risk since no credentials
// are validated here — it only reports auth mode.
func (h *AdminAPIHandler) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	ip := h.clientIP(r)
	local := isLocalhostIP(ip)
	h.respondJSON(w, http.StatusOK, authStatusResponse{
		AuthRequired: !local,
		PasswordSet:  false, // No remote auth in OSS
		Localhost:    local,
	})
}
