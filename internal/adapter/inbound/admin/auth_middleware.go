package admin

import (
	"net"
	"net/http"
	"strings"
)

// isLocalhostIP reports whether the given IP string is a loopback address.
// Only matches actual IP addresses (127.0.0.1, ::1), not the literal "localhost".
func isLocalhostIP(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1"
}

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
	return isLocalhostIP(host)
}

// clientIP returns the effective client IP for auth decisions (HARD-11).
//
// Behaviour:
//   - If no trusted proxies are configured, returns the RemoteAddr host (backward-compatible).
//   - If the connecting IP is in a trusted proxy CIDR, walks X-Forwarded-For right-to-left
//     and returns the first IP not in a trusted proxy CIDR as the real client IP.
//   - If the connecting IP is NOT a trusted proxy, returns the RemoteAddr host directly
//     (XFF is ignored — untrusted source could forge it).
func (h *AdminAPIHandler) clientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	// No trusted proxies configured: use RemoteAddr directly (current behaviour).
	if len(h.trustedProxies) == 0 {
		return remoteHost
	}

	// Check whether the direct caller is a trusted proxy.
	remoteIP := net.ParseIP(remoteHost)
	if remoteIP == nil || !h.isTrustedProxy(remoteIP) {
		// Direct caller is not a trusted proxy — XFF is untrusted.
		return remoteHost
	}

	// Walk X-Forwarded-For right-to-left to find the rightmost non-proxy IP.
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remoteHost
	}

	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.TrimSpace(parts[i])
		ip := net.ParseIP(candidate)
		if ip == nil {
			continue
		}
		if !h.isTrustedProxy(ip) {
			return candidate
		}
	}

	// All XFF entries were trusted proxies — fall back to RemoteAddr.
	return remoteHost
}

// isTrustedProxy reports whether the given IP falls within any of the configured
// trusted proxy CIDRs.
func (h *AdminAPIHandler) isTrustedProxy(ip net.IP) bool {
	for _, network := range h.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// adminAuthMiddleware wraps an http.Handler and enforces localhost-only access.
// Localhost requests (AUTH-01) bypass auth entirely. Remote requests are
// rejected with 403 — use SSH tunnel for remote access.
//
// When trusted proxies are configured (HARD-11), the effective client IP is
// resolved via X-Forwarded-For before checking for loopback.
func (h *AdminAPIHandler) adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := h.clientIP(r)
		if isLocalhostIP(ip) {
			next.ServeHTTP(w, r)
			return
		}
		h.respondError(w, http.StatusForbidden, "admin API requires localhost access")
	})
}
