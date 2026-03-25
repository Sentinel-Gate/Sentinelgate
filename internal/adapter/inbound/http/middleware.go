// Package http provides the HTTP transport adapter for the proxy.
package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/Sentinel-Gate/Sentinelgate/internal/ctxkey"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/google/uuid"
)

// requestIDContextKey is the type for the request ID context key.
type requestIDContextKey struct{}

// RequestIDKey is the context key for the request ID.
var RequestIDKey = requestIDContextKey{}

// LoggerKey is the context key for the enriched logger.
// Uses shared key type from ctxkey package to allow cross-package access without import cycles.
var LoggerKey = ctxkey.LoggerKey{}

// RequestIDMiddleware extracts or generates a request ID and enriches the logger.
// The request ID is stored in context using RequestIDKey.
// An enriched logger with request_id field is stored using LoggerKey.
func RequestIDMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" || !isValidRequestID(requestID) {
				requestID = uuid.New().String()
			}

			// Enrich logger with request_id
			enrichedLogger := logger.With("request_id", requestID)

			// Store in context
			ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
			ctx = context.WithValue(ctx, LoggerKey, enrichedLogger)

			// Set response header for correlation
			w.Header().Set("X-Request-ID", requestID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// LoggerFromContext retrieves the enriched logger from context.
// Returns slog.Default() if no logger is in context.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(LoggerKey).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

// DNSRebindingProtection validates Origin and Host headers against allowlists.
// This prevents DNS rebinding attacks by ensuring requests come from allowed origins.
// If allowedOrigins is empty, all requests with an Origin header are blocked (local-only mode).
//
// When no Origin header is present, the Host header is validated against allowedHosts.
// If allowedHosts is empty, Host validation defaults to allowing only localhost variants.
// This closes the gap where requests without an Origin header could bypass DNS rebinding
// protection entirely.
func DNSRebindingProtection(allowedOrigins []string, allowedHosts ...string) func(http.Handler) http.Handler {
	// Build a set for O(1) lookup (L-70: store lowercase for case-insensitive matching).
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowed[strings.ToLower(origin)] = struct{}{}
	}

	// Build allowed hosts set. Default to localhost variants if none provided.
	hostSet := make(map[string]struct{}, len(allowedHosts))
	for _, h := range allowedHosts {
		hostSet[strings.ToLower(h)] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := strings.ToLower(r.Header.Get("Origin"))

			if origin != "" {
				// If Origin present, it must be in the allowlist (case-insensitive, L-70).
				if _, ok := allowed[origin]; !ok {
					// L-20: Return JSON response instead of text/plain for DNS rebinding rejections.
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "Forbidden: origin not allowed"})
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			// No Origin header: validate Host header to prevent DNS rebinding.
			host := r.Host
			if host == "" {
				host = r.Header.Get("Host")
			}
			// Strip port if present for comparison.
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			host = strings.ToLower(host)

			// If allowed hosts are configured, check against them.
			if len(hostSet) > 0 {
				if _, ok := hostSet[host]; !ok {
					// L-20: Return JSON response instead of text/plain for DNS rebinding rejections.
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "Forbidden: host not allowed"})
					return
				}
			} else {
				// Default: only allow localhost variants (safe default for local-only mode).
				// L-69: Also reject empty Host — no valid HTTP/1.1 client should send one.
			if host != "localhost" && host != "127.0.0.1" && host != "::1" {
					// L-20: Return JSON response instead of text/plain for DNS rebinding rejections.
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": "Forbidden: host not allowed"})
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// APIKeyMiddleware extracts API key from Authorization header.
// The API key is stored in context using proxy.APIKeyContextKey for downstream handlers.
// It also sets proxy.ConnectionIDKey based on the API key so that different clients
// get isolated session cache entries in the AuthInterceptor. Without this, all HTTP
// requests share connID="default" and the first authenticated client's session is
// reused for all subsequent requests regardless of their API key.
// If no Authorization header or invalid format, the request continues without an API key.
// AuthInterceptor will validate the API key later in the interceptor chain.
func APIKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		// Extract Bearer token if present
		if strings.HasPrefix(auth, "Bearer ") {
			apiKey := strings.TrimPrefix(auth, "Bearer ")
			ctx := context.WithValue(r.Context(), proxy.APIKeyContextKey, apiKey)
			// Use a hash of the API key as the connection ID so each client gets
			// its own session cache entry. This prevents session bleed between
			// different API keys sharing the HTTP transport's default connID.
			connID := apiKeyConnectionID(apiKey)
			ctx = context.WithValue(ctx, proxy.ConnectionIDKey, connID)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

// apiKeyConnectionID generates a deterministic connection ID from an API key.
// Uses a prefix of the SHA-256 hash to avoid storing the raw key in the cache map.
func apiKeyConnectionID(apiKey string) string {
	h := sha256.Sum256([]byte(apiKey))
	return "http-" + hex.EncodeToString(h[:8])
}

// RealIPMiddleware extracts the client's real IP address for rate limiting.
// It checks X-Forwarded-For and X-Real-IP headers (for reverse proxy support),
// falling back to r.RemoteAddr if no proxy headers are present.
// The rightmost IP in X-Forwarded-For is used because it is the one
// inserted by the trusted reverse proxy and cannot be spoofed by clients.
// The IP is stored in context using proxy.IPAddressKey.
func RealIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractRealIP(r)
		ctx := context.WithValue(r.Context(), proxy.IPAddressKey, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractRealIP extracts the client's real IP address from the request.
// X-Forwarded-For and X-Real-IP headers are only trusted when the direct
// connection comes from a loopback or private IP (RFC 1918 / RFC 4193).
// This prevents attackers on the public internet from spoofing their IP
// to bypass rate limiting or poison audit logs.
func extractRealIP(r *http.Request) string {
	// Extract the direct connection IP from RemoteAddr.
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	// Only trust proxy headers when the direct connection is from a
	// loopback or private network address (i.e. a trusted local proxy).
	if !isPrivateOrLoopback(remoteHost) {
		return remoteHost
	}

	// Check X-Forwarded-For (common reverse proxy header)
	// Format: X-Forwarded-For: client, proxy1, proxy2
	// Use the rightmost IP — it is set by the trusted proxy closest to us.
	// M-11: Validate with net.ParseIP before returning to prevent log injection
	// and rate-limiter key poisoning from malformed XFF values.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for i := len(ips) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(ips[i])
			if ip != "" && net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP (nginx-style header)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// Fall back to RemoteAddr
	return remoteHost
}

// isValidRequestID checks that a request ID is safe to log and reflect.
// Max 128 characters, alphanumeric plus dots, underscores, and hyphens only.
// Rejects control characters and other special chars to prevent log injection.
func isValidRequestID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// isPrivateOrLoopback reports whether the given IP string is a loopback
// or private network address (RFC 1918 IPv4, RFC 4193 IPv6).
func isPrivateOrLoopback(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}
