package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// isTLSRequest returns true when the request arrived over TLS. It only trusts
// X-Forwarded-Proto when isTrustedProxy returns true for the direct peer IP.
// When isTrustedProxy is nil, X-Forwarded-Proto is never trusted (M-11).
func isTLSRequest(r *http.Request, isTrustedProxy func(net.IP) bool) bool {
	if r.TLS != nil {
		return true
	}
	if isTrustedProxy == nil {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if !isTrustedProxy(ip) {
		return false
	}
	return r.Header.Get("X-Forwarded-Proto") == "https"
}

// cspMiddleware sets Content Security Policy and related security headers on all responses.
// CSP restricts resource loading to mitigate XSS and data injection attacks (SECU-03).
func cspMiddleware(next http.Handler) http.Handler {
	return cspMiddlewareWithTLS(next, nil)
}

func cspMiddlewareWithTLS(next http.Handler, isTrustedProxy func(net.IP) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; font-src 'self'; connect-src 'self'; "+
				"frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		if isTLSRequest(r, isTrustedProxy) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

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
			if !ensureCSRFCookie(w, r) {
				return // 500 already sent
			}
			next.ServeHTTP(w, r)
			return
		}

		// State-changing methods: exempt auth endpoints (informational only).
		if strings.HasPrefix(r.URL.Path, "/admin/api/auth/") {
			next.ServeHTTP(w, r)
			return
		}

		// Validate CSRF token.
		// Runtime agent endpoints (/policy/evaluate, /outbound/test) are no longer
		// exempt — they must use the CSRF token or an API key auth header.
		cookie, err := r.Cookie("sentinel_csrf_token")
		if err != nil || cookie.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"CSRF token invalid"}`))
			return
		}

		headerToken := r.Header.Get("X-CSRF-Token")
		if headerToken == "" || subtle.ConstantTimeCompare([]byte(headerToken), []byte(cookie.Value)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"CSRF token invalid"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ensureCSRFCookie sets the sentinel_csrf_token cookie if it is not already present
// on the request. Returns true on success, false if it wrote a 500 error.
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) bool {
	return ensureCSRFCookieWithTLS(w, r, nil)
}

func ensureCSRFCookieWithTLS(w http.ResponseWriter, r *http.Request, isTrustedProxy func(net.IP) bool) bool {
	if _, err := r.Cookie("sentinel_csrf_token"); err == nil {
		return true // Already has a token.
	}

	token, err := generateCSRFToken()
	if err != nil {
		// Critical: crypto/rand failed. Return 500 rather than serving
		// with a predictable token (A7a: no panic outside main).
		slog.Error("CRITICAL: cannot generate CSRF token", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "sentinel_csrf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: false, // JS must read this to send as header
		Secure:   isTLSRequest(r, isTrustedProxy),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7200, // 2 hours (L-59: align closer to session lifetime)
	})
	return true
}

func (h *AdminAPIHandler) csrfMiddlewareWithProxyTrust(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := r.Method

		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			if !ensureCSRFCookieWithTLS(w, r, h.isTrustedProxy) {
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/admin/api/auth/") {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie("sentinel_csrf_token")
		if err != nil || cookie.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"CSRF token invalid"}`))
			return
		}

		headerToken := r.Header.Get("X-CSRF-Token")
		if headerToken == "" || subtle.ConstantTimeCompare([]byte(headerToken), []byte(cookie.Value)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"CSRF token invalid"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// generateCSRFToken returns a cryptographically random 32-byte hex-encoded string.
// On modern systems crypto/rand.Read never fails. If it does, returns an error
// instead of panicking (A7a: no panic outside main).
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}
