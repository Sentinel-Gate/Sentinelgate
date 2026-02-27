// Package http provides the HTTP transport adapter for the proxy.
package http

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
			if requestID == "" {
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

// DNSRebindingProtection validates Origin header against an allowlist.
// This prevents DNS rebinding attacks by ensuring requests come from allowed origins.
// If allowedOrigins is empty, all requests with an Origin header are blocked (local-only mode).
// Requests without an Origin header are allowed (same-origin or non-browser).
func DNSRebindingProtection(allowedOrigins []string) func(http.Handler) http.Handler {
	// Build a set for O(1) lookup
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowed[origin] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// If no Origin header, allow (same-origin or non-browser request)
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			// If Origin present, it must be in the allowlist
			if _, ok := allowed[origin]; !ok {
				http.Error(w, "Forbidden: origin not allowed", http.StatusForbidden)
				return
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
// Only the first IP in X-Forwarded-For is trusted to avoid spoofing.
// The IP is stored in context using proxy.IPAddressKey.
func RealIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractRealIP(r)
		ctx := context.WithValue(r.Context(), proxy.IPAddressKey, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractRealIP extracts the client's real IP address from the request.
func extractRealIP(r *http.Request) string {
	// Check X-Forwarded-For first (common reverse proxy header)
	// Format: X-Forwarded-For: client, proxy1, proxy2
	// Trust only the first IP (client IP from first proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Split by comma and take first entry
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := strings.TrimSpace(ips[0])
			if ip != "" {
				return ip
			}
		}
	}

	// Check X-Real-IP (nginx-style header)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	// RemoteAddr is in "host:port" format, extract host
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, use RemoteAddr as-is
		return r.RemoteAddr
	}
	return host
}
