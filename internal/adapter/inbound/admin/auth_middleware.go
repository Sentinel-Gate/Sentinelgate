package admin

import (
	"net"
	"net/http"
)

// isLocalhost checks if the request originates from a loopback address.
// It parses the host portion from r.RemoteAddr and checks for 127.0.0.1,
// ::1, or localhost. X-Forwarded-For is intentionally NOT trusted for
// security (an attacker could spoof it).
func isLocalhost(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr might not have a port (unlikely with net/http, but be safe).
		host = r.RemoteAddr
	}
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// adminAuthMiddleware wraps an http.Handler and enforces localhost-only access.
// Localhost requests (AUTH-01) bypass auth entirely. Remote requests are
// rejected with 403 — use SSH tunnel for remote access.
func (h *AdminAPIHandler) adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLocalhost(r) {
			next.ServeHTTP(w, r)
			return
		}
		h.respondError(w, http.StatusForbidden, "admin API requires localhost access")
	})
}
