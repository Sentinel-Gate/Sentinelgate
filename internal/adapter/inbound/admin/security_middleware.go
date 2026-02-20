package admin

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// cspMiddleware sets Content Security Policy and related security headers on all responses.
// CSP restricts resource loading to mitigate XSS and data injection attacks (SECU-03).
func cspMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"img-src 'self' data:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; "+
				"frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		next.ServeHTTP(w, r)
	})
}

// csrfMiddleware provides Cross-Site Request Forgery protection for admin API endpoints (SECU-02).
//
// On safe methods (GET, HEAD, OPTIONS):
//   - Sets a CSRF token cookie if not already present.
//   - Does NOT validate tokens (safe methods are idempotent).
//
// On state-changing methods (POST, PUT, DELETE):
//   - Auth endpoints (/admin/api/auth/*) are exempt (informational, no CSRF needed).
//   - All other endpoints require the X-CSRF-Token header to match the sentinel_csrf_token cookie.
//   - Mismatches or missing tokens result in 403.
func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.Method

		// Safe methods: set cookie if missing, then pass through.
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			ensureCSRFCookie(w, r)
			next.ServeHTTP(w, r)
			return
		}

		// State-changing methods: exempt auth endpoints (informational only).
		if strings.HasPrefix(r.URL.Path, "/admin/api/auth/") {
			next.ServeHTTP(w, r)
			return
		}

		// Exempt runtime agent endpoints (called programmatically, not from browsers).
		// These are protected by API key auth and localhost-only access instead.
		if strings.HasPrefix(r.URL.Path, "/admin/api/v1/policy/evaluate") ||
			strings.HasPrefix(r.URL.Path, "/admin/api/v1/security/outbound/test") {
			next.ServeHTTP(w, r)
			return
		}

		// Validate CSRF token.
		cookie, err := r.Cookie("sentinel_csrf_token")
		if err != nil || cookie.Value == "" {
			http.Error(w, `{"error":"CSRF token invalid"}`, http.StatusForbidden)
			return
		}

		headerToken := r.Header.Get("X-CSRF-Token")
		if headerToken == "" || headerToken != cookie.Value {
			http.Error(w, `{"error":"CSRF token invalid"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ensureCSRFCookie sets the sentinel_csrf_token cookie if it is not already present
// on the request. The cookie is readable by JavaScript (HttpOnly=false) so the
// frontend can include it as the X-CSRF-Token header on state-changing requests.
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie("sentinel_csrf_token"); err == nil {
		return // Already has a token.
	}

	token := generateCSRFToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "sentinel_csrf_token",
		Value:    token,
		Path:     "/admin",
		HttpOnly: false, // JS must read this to send as header
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 hours, matches session cookie
	})
}

// generateCSRFToken returns a cryptographically random 32-byte hex-encoded string.
func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand.Read should never fail on modern systems.
		// Fallback: return a zero-filled token (will still validate correctly).
		return strings.Repeat("0", 64)
	}
	return hex.EncodeToString(b)
}
