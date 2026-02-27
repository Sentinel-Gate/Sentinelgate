package httpgw

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
)

// AuthConfig configures the HTTP Gateway authentication middleware.
type AuthConfig struct {
	// APIKeyService validates API keys against the auth store.
	APIKeyService *auth.APIKeyService
	// DevMode skips authentication when true (uses dev identity).
	DevMode bool
	// Logger for authentication events.
	Logger *slog.Logger
}

// NewAuthMiddleware creates an HTTP middleware that authenticates HTTP Gateway
// requests. It extracts an API key from one of three sources (in priority order):
//
//  1. Proxy-Authorization: Bearer <key> (standard forward proxy auth)
//  2. Authorization: Bearer <key> (standard HTTP auth fallback)
//  3. X-SentinelGate-Key: <key> (alternative for restricted clients)
//
// On success, the middleware stores the authenticated identity in the request
// context (ContextKeyIdentity) for the handler to read.
//
// On failure, it returns HTTP 407 Proxy Authentication Required.
//
// In dev mode, authentication is skipped and a dev identity is used.
func NewAuthMiddleware(cfg AuthConfig) func(http.Handler) http.Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Dev mode: skip auth, use dev identity
			if cfg.DevMode {
				identity := &action.ActionIdentity{
					ID:        "dev-user",
					Name:      "Development User",
					Roles:     []string{"admin", "user"},
					SessionID: uuid.New().String(),
				}
				ctx := context.WithValue(r.Context(), ContextKeyIdentity, identity)
				logger.Debug("dev mode: bypassing HTTP gateway auth")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Extract API key from request (priority: Proxy-Authorization > X-SentinelGate-Key > query param)
			apiKey := extractAPIKey(r)
			if apiKey == "" {
				logger.Debug("HTTP gateway auth: no credentials provided",
					"remote_addr", r.RemoteAddr,
				)
				w.Header().Set("Proxy-Authenticate", "Bearer")
				writeJSONError(w, http.StatusProxyAuthRequired, "proxy_auth_required", "", "authentication required", "", "")
				return
			}

			// Validate the API key
			authIdentity, err := cfg.APIKeyService.Validate(r.Context(), apiKey)
			if err != nil {
				logger.Debug("HTTP gateway auth: invalid API key",
					"remote_addr", r.RemoteAddr,
					"error", err,
				)
				w.Header().Set("Proxy-Authenticate", "Bearer")
				writeJSONError(w, http.StatusProxyAuthRequired, "proxy_auth_required", "", "invalid credentials", "", "")
				return
			}

			// Convert auth.Identity to ActionIdentity
			roles := make([]string, len(authIdentity.Roles))
			for i, role := range authIdentity.Roles {
				roles[i] = string(role)
			}
			identity := &action.ActionIdentity{
				ID:        authIdentity.ID,
				Name:      authIdentity.Name,
				Roles:     roles,
				SessionID: uuid.New().String(),
			}

			// Store identity and API key in context
			ctx := context.WithValue(r.Context(), ContextKeyIdentity, identity)
			ctx = context.WithValue(ctx, ContextKeyAPIKey, apiKey)

			logger.Debug("HTTP gateway auth: authenticated",
				"identity_id", authIdentity.ID,
				"identity_name", authIdentity.Name,
			)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractAPIKey extracts an API key from the request using three mechanisms
// in order of priority:
//  1. Proxy-Authorization: Bearer <key> (or Basic with password as key)
//  2. Authorization: Bearer <key>
//  3. X-SentinelGate-Key: <key>
//
// SECURITY: Query parameter auth (?sg_key=) was intentionally removed because
// query strings are logged by proxies, WAFs, and servers, and appear in
// browser history and Referer headers — exposing API keys.
func extractAPIKey(r *http.Request) string {
	// 1. Proxy-Authorization header (highest priority)
	if proxyAuth := r.Header.Get("Proxy-Authorization"); proxyAuth != "" {
		if strings.HasPrefix(proxyAuth, "Bearer ") {
			if key := strings.TrimPrefix(proxyAuth, "Bearer "); key != "" {
				return key
			}
		}
		// Support Basic auth: HTTP clients send this when the proxy URL
		// contains credentials (http://user:password@host:port).
		// The password field carries the API key.
		if strings.HasPrefix(proxyAuth, "Basic ") {
			if key := extractBasicPassword(proxyAuth); key != "" {
				return key
			}
		}
	}

	// 2. Authorization header (standard HTTP auth fallback)
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			if key := strings.TrimPrefix(auth, "Bearer "); key != "" {
				return key
			}
		}
	}

	// 3. X-SentinelGate-Key header
	if key := r.Header.Get("X-SentinelGate-Key"); key != "" {
		return key
	}

	return ""
}

// extractBasicPassword decodes a Basic auth header and returns the password.
// Format: "Basic base64(user:password)" → returns password.
// Used to extract the API key from proxy URL credentials (http://sg:<key>@host).
func extractBasicPassword(header string) string {
	encoded := strings.TrimPrefix(header, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}
