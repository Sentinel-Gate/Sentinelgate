// Package http provides the HTTP transport adapter for the proxy.
package http

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
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
	certFile           string
	keyFile            string
	sessions           *sessionRegistry
	logger             *slog.Logger
	extraHandler       http.Handler   // Optional extra handler (e.g., admin UI)
	httpGatewayHandler http.Handler   // Optional HTTP Gateway handler for single-port routing
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

// WithHTTPGatewayHandler sets the HTTP Gateway handler for single-port routing.
// When set, non-MCP paths (except /admin/, /health, /metrics) route to this handler.
// When nil, MCP remains the catch-all handler (backward compatible).
func WithHTTPGatewayHandler(h http.Handler) Option {
	return func(t *HTTPTransport) {
		t.httpGatewayHandler = h
	}
}

// WithHealthChecker sets the health checker for the /health endpoint.
func WithHealthChecker(hc *HealthChecker) Option {
	return func(t *HTTPTransport) {
		t.healthChecker = hc
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
	mcpHandler = DNSRebindingProtection(t.allowedOrigins)(mcpHandler)
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
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		Registry: reg,
	}))
	// Favicon handler to prevent browser 500 errors
	mux.Handle("/favicon.ico", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	// MCP on explicit paths (takes priority over catch-all in Go's ServeMux)
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("/mcp/", mcpHandler)
	// Catch-all: HTTP Gateway if enabled, otherwise MCP (backward compatible)
	if t.httpGatewayHandler != nil {
		mux.Handle("/", t.httpGatewayHandler)
	} else {
		mux.Handle("/", mcpHandler)
	}
	var handler http.Handler = mux

	// Wrap with CONNECT handler: Go's ServeMux doesn't properly route CONNECT
	// requests (r.URL.Path is empty for CONNECT host:port) and may issue 301
	// redirects. When the HTTP gateway is configured, intercept CONNECT requests
	// before the mux and route them directly to the gateway handler (TLSInspector).
	if t.httpGatewayHandler != nil {
		inner := handler
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				t.httpGatewayHandler.ServeHTTP(w, r)
				return
			}
			inner.ServeHTTP(w, r)
		})
	}

	// Create HTTP server
	t.server = &http.Server{
		Addr:    t.addr,
		Handler: handler,
	}

	// Configure TLS if certificates provided
	if t.certFile != "" && t.keyFile != "" {
		t.server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
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

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		t.logger.Info("context cancelled, shutting down HTTP server")
		return t.shutdown()
	case err := <-errCh:
		return err
	}
}

// shutdown performs graceful shutdown of the HTTP server.
func (t *HTTPTransport) shutdown() error {
	// Create timeout context for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Close all SSE channels first
	t.sessions.closeAll()

	// Shutdown server gracefully
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
	return t.shutdown()
}

// Compile-time check that HTTPTransport implements ProxyService interface.
var _ inbound.ProxyService = (*HTTPTransport)(nil)
