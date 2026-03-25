// Package http provides the HTTP transport adapter for the proxy.
package http

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/port/inbound"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// HTTPTransport is the inbound adapter that connects the proxy to HTTP clients.
// It implements the inbound.ProxyService interface, allowing MCP clients to
// connect via HTTP Streamable Transport instead of stdio.
type HTTPTransport struct {
	proxyService       *service.ProxyService
	server             *http.Server
	addr               string
	allowedOrigins     []string
	allowedHosts       []string       // Allowed Host header values for DNS rebinding protection
	metricsToken       string         // Bearer token for /metrics endpoint (empty = localhost only)
	certFile           string
	keyFile            string
	sessions           *sessionRegistry
	logger             *slog.Logger
	extraHandler       http.Handler   // Optional extra handler (e.g., admin UI)
	metrics            *Metrics       // Prometheus metrics
	healthChecker      *HealthChecker // Health check handler
}

// Option is a functional option for configuring HTTPTransport.
type Option func(*HTTPTransport)

// WithAddr sets the listen address for the HTTP server.
// Default is "127.0.0.1:8080" (localhost only).
func WithAddr(addr string) Option {
	return func(t *HTTPTransport) {
		t.addr = addr
	}
}

// WithTLS enables TLS with the provided certificate and key files.
// If not set, the server runs without TLS (plain HTTP).
func WithTLS(certFile, keyFile string) Option {
	return func(t *HTTPTransport) {
		t.certFile = certFile
		t.keyFile = keyFile
	}
}

// WithAllowedOrigins sets the allowed origins for DNS rebinding protection.
// If empty, all requests with an Origin header are blocked (local-only mode).
// Example: []string{"https://example.com", "http://localhost:3000"}
func WithAllowedOrigins(origins []string) Option {
	return func(t *HTTPTransport) {
		t.allowedOrigins = origins
	}
}

// WithAllowedHosts sets the allowed Host header values for DNS rebinding protection.
// Requests without an Origin header will have their Host header checked against this list.
// If empty, Host header validation is not enforced.
func WithAllowedHosts(hosts []string) Option {
	return func(t *HTTPTransport) {
		t.allowedHosts = hosts
	}
}

// WithMetricsToken sets the bearer token required to access the /metrics endpoint.
// If empty, /metrics is restricted to localhost-only access.
func WithMetricsToken(token string) Option {
	return func(t *HTTPTransport) {
		t.metricsToken = token
	}
}

// WithLogger sets the logger for the HTTP transport.
func WithLogger(logger *slog.Logger) Option {
	return func(t *HTTPTransport) {
		t.logger = logger
	}
}

// WithExtraHandler adds an extra HTTP handler that will be consulted
// for routes not handled by the MCP transport (e.g., admin UI).
func WithExtraHandler(h http.Handler) Option {
	return func(t *HTTPTransport) {
		t.extraHandler = h
	}
}

// WithHealthChecker sets the health checker for the /health endpoint.
func WithHealthChecker(hc *HealthChecker) Option {
	return func(t *HTTPTransport) {
		t.healthChecker = hc
	}
}

// WithSessionTerminateCallback sets a callback invoked when a session is terminated.
// Used to clean up per-session state in other components (e.g., framework tracking).
func WithSessionTerminateCallback(cb func(sessionID string)) Option {
	return func(t *HTTPTransport) {
		t.sessions.onTerminate = cb
	}
}

// NewHTTPTransport creates an HTTP transport adapter wrapping the given proxy service.
func NewHTTPTransport(proxyService *service.ProxyService, opts ...Option) *HTTPTransport {
	t := &HTTPTransport{
		proxyService:   proxyService,
		addr:           "127.0.0.1:8080",
		allowedOrigins: []string{},
		sessions:       newSessionRegistry(),
		logger:         slog.Default(),
	}

	for _, opt := range opts {
		opt(t)
	}

	// Start cleanup goroutine after all options are applied (including onTerminate callback).
	t.sessions.startCleanup()

	return t
}

// Start begins accepting HTTP connections and processing MCP messages.
// It blocks until the context is cancelled or an error occurs.
func (t *HTTPTransport) Start(ctx context.Context) error {
	// Create Prometheus registry and metrics
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	t.metrics = NewMetrics(reg)

	// Build middleware chain: Metrics -> RequestID -> RealIP -> DNSRebinding -> APIKey -> Handler
	// Middleware order (outermost first):
	// 1. MetricsMiddleware - Record duration and status (MUST be outermost to capture full duration)
	// 2. RequestID - Extract/generate request ID and enrich logger
	// 3. RealIP - Extract client IP from X-Forwarded-For
	// 4. DNSRebinding - Security check for Origin header
	// 5. APIKey - Extract API key and identity
	// 6. Handler - MCP request handling
	mcpHandler := mcpHandler(t.proxyService, t.sessions)
	mcpHandler = APIKeyMiddleware(mcpHandler)
	mcpHandler = DNSRebindingProtection(t.allowedOrigins, t.allowedHosts...)(mcpHandler)
	mcpHandler = RealIPMiddleware(mcpHandler)
	mcpHandler = RequestIDMiddleware(t.logger)(mcpHandler)
	mcpHandler = MetricsMiddleware(t.metrics)(mcpHandler)

	// Build mux with standard routes (always use mux for /metrics endpoint)
	mux := http.NewServeMux()
	// Admin routes take priority (if extra handler provided)
	if t.extraHandler != nil {
		mux.Handle("/admin/api/", t.extraHandler)
		mux.Handle("/admin/", t.extraHandler)
		mux.Handle("/admin", t.extraHandler)
	}
	if t.healthChecker != nil {
		mux.Handle("/health", t.healthChecker.Handler())
	} else {
		// Fallback to simple handler if no checker configured
		mux.Handle("/health", healthHandler())
	}
	mux.Handle("/metrics", t.metricsAuthHandler(promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		Registry: reg,
	})))
	// Favicon handler to prevent browser 500 errors
	mux.Handle("/favicon.ico", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	// MCP spec compliance: OAuth Protected Resource Metadata (RFC 9728).
	// Returns metadata indicating this server accepts Bearer token auth.
	// No authorization_servers field = no OAuth server, Bearer only.
	mux.Handle("/.well-known/oauth-protected-resource", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeJSONError(w, http.StatusMethodNotAllowed, "Method Not Allowed")
			return
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"resource":                 scheme + "://" + r.Host + "/mcp",
			"bearer_methods_supported": []string{"header"},
			"scopes_supported":         []string{},
			"resource_name":            "SentinelGate MCP Proxy",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	// All other .well-known paths return 404 (prevents catch-all from returning 400).
	mux.Handle("/.well-known/", http.NotFoundHandler())
	// MCP on explicit paths (takes priority over catch-all in Go's ServeMux)
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/mcp/", mcpHandler)
	// Catch-all: route everything to MCP handler
	mux.Handle("/", mcpHandler)
	// Recovery middleware is the outermost layer — catches panics from any
	// handler and returns 500 with a structured log entry (M-42).
	handler := recoveryMiddleware(mux)

	// Create HTTP server with timeouts to mitigate Slowloris DoS attacks (H-11).
	// WriteTimeout is intentionally omitted because SSE connections must remain open.
	t.server = &http.Server{
		Addr:              t.addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
	}

	// Configure TLS if certificates provided
	// L-9: Prefer AEAD cipher suites (GCM, ChaCha20) and exclude CBC mode ciphers.
	// Go 1.22+ defaults are already secure, but explicit preference improves defense in depth.
	if t.certFile != "" && t.keyFile != "" {
		t.server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		}
	}

	// Channel for server errors
	errCh := make(chan error, 1)

	// Start server in goroutine
	go func() {
		var err error
		if t.certFile != "" && t.keyFile != "" {
			t.logger.Info("starting HTTPS server", "addr", t.addr)
			err = t.server.ListenAndServeTLS(t.certFile, t.keyFile)
		} else {
			t.logger.Info("starting HTTP server", "addr", t.addr)
			err = t.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for context cancellation or server error.
	// On context cancel, return immediately — the lifecycle manager
	// will call Shutdown() at PhaseStopAccepting.
	select {
	case <-ctx.Done():
		t.logger.Info("context cancelled, HTTP server will be shut down by lifecycle")
		return nil
	case err := <-errCh:
		return err
	}
}

// metricsAuthHandler wraps the metrics handler with authentication.
// If a metricsToken is configured, requests must include a matching
// Authorization: Bearer <token> header. Otherwise, only localhost access
// is allowed (preventing exposure to the public internet).
func (t *HTTPTransport) metricsAuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If a token is configured, check for Bearer token match.
		if t.metricsToken != "" {
			auth := r.Header.Get("Authorization")
			expected := "Bearer " + t.metricsToken
			if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
				// L-26: Use writeJSONError for consistent JSON error responses.
				writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// No token configured: restrict to localhost only.
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			// L-26: Use writeJSONError for consistent JSON error responses.
			writeJSONError(w, http.StatusForbidden, "Forbidden: metrics requires localhost access or bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Shutdown performs graceful shutdown of the HTTP server.
// It is registered as a lifecycle hook at PhaseStopAccepting so that
// slow clients don't delay the rest of the shutdown sequence.
func (t *HTTPTransport) Shutdown(ctx context.Context) error {
	// Close all SSE channels first
	t.sessions.closeAll()

	if t.server == nil {
		return nil
	}

	// Shutdown server gracefully using the caller-provided context (lifecycle timeout)
	if err := t.server.Shutdown(ctx); err != nil {
		t.logger.Error("error during server shutdown", "error", err)
		return err
	}

	t.logger.Info("HTTP server shutdown complete")
	return nil
}

// Close gracefully shuts down the transport.
func (t *HTTPTransport) Close() error {
	if t.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return t.Shutdown(ctx)
}

// BroadcastNotification sends a JSON-RPC notification to all connected SSE clients.
// Used for server-initiated notifications like notifications/tools/list_changed.
// The optional params argument allows passing notification parameters (e.g., for
// notifications/progress or notifications/message). If nil, no "params" field is included.
func (t *HTTPTransport) BroadcastNotification(method string, params ...json.RawMessage) {
	notification := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if len(params) > 0 && params[0] != nil {
		notification["params"] = params[0]
	}
	data, err := json.Marshal(notification)
	if err != nil {
		t.logger.Error("failed to marshal notification", "method", method, "error", err)
		return
	}
	t.sessions.broadcast(data)
	t.logger.Debug("broadcast notification", "method", method)
}

// recoveryMiddleware catches panics and returns 500 instead of crashing the
// server. It logs the panic value and stack trace via slog.Error (M-42).
func recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic recovered", "panic", rec, "stack", string(debug.Stack()))
				// L-26: Use writeJSONError for consistent JSON error responses.
				writeJSONError(w, http.StatusInternalServerError, "Internal Server Error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Compile-time check that HTTPTransport implements ProxyService interface.
var _ inbound.ProxyService = (*HTTPTransport)(nil)
