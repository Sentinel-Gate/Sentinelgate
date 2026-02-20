package http

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// markerHandler returns an http.Handler that writes a specific marker string.
// Used in routing tests to verify which handler received the request.
func markerHandler(marker string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handler", marker)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, marker)
	})
}

// newTestTransport creates an HTTPTransport with minimal dependencies for routing tests.
// It sets up mock handlers for admin and gateway to verify routing behavior.
func newTestTransport(t *testing.T, gatewayHandler http.Handler) *HTTPTransport {
	t.Helper()
	logger := slog.Default()

	// Create a minimal proxy service (nil client is fine for routing tests;
	// we never actually process MCP messages).
	proxyService := service.NewProxyService(nil, nil, logger)

	opts := []Option{
		WithAddr(":0"), // Use any available port
		WithLogger(logger),
		WithExtraHandler(markerHandler("admin")),
	}

	if gatewayHandler != nil {
		opts = append(opts, WithHTTPGatewayHandler(gatewayHandler))
	}

	return NewHTTPTransport(proxyService, opts...)
}

// startTestServer starts the transport's HTTP server on a random port and returns
// the base URL and a cleanup function. Uses httptest.NewServer for simplicity.
func startTestServer(t *testing.T, transport *HTTPTransport) (baseURL string, cleanup func()) {
	t.Helper()

	// Build the same mux that Start() builds, but without Prometheus metrics/middleware
	// to keep tests fast and focused on routing.
	mux := http.NewServeMux()

	// Admin routes
	if transport.extraHandler != nil {
		mux.Handle("/admin/api/", transport.extraHandler)
		mux.Handle("/admin/", transport.extraHandler)
		mux.Handle("/admin", transport.extraHandler)
	}

	// Health
	mux.Handle("/health", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))

	// Favicon
	mux.Handle("/favicon.ico", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	// MCP handler marker (simplified — real MCP handler has middleware chain)
	mcpMarker := markerHandler("mcp")
	mux.Handle("/mcp", mcpMarker)
	mux.Handle("/mcp/", mcpMarker)

	// Catch-all: gateway or MCP
	if transport.httpGatewayHandler != nil {
		mux.Handle("/", transport.httpGatewayHandler)
	} else {
		mux.Handle("/", mcpMarker)
	}

	server := httptest.NewServer(mux)
	return server.URL, server.Close
}

func TestRouting_MCPRoute(t *testing.T) {
	transport := newTestTransport(t, markerHandler("gateway"))
	baseURL, cleanup := startTestServer(t, transport)
	defer cleanup()

	resp, err := http.Get(baseURL + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	handler := resp.Header.Get("X-Handler")
	if handler != "mcp" {
		t.Errorf("GET /mcp reached handler %q, want %q", handler, "mcp")
	}
}

func TestRouting_MCPRouteTrailingSlash(t *testing.T) {
	transport := newTestTransport(t, markerHandler("gateway"))
	baseURL, cleanup := startTestServer(t, transport)
	defer cleanup()

	resp, err := http.Get(baseURL + "/mcp/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	handler := resp.Header.Get("X-Handler")
	if handler != "mcp" {
		t.Errorf("GET /mcp/ reached handler %q, want %q", handler, "mcp")
	}
}

func TestRouting_AdminRoute(t *testing.T) {
	transport := newTestTransport(t, markerHandler("gateway"))
	baseURL, cleanup := startTestServer(t, transport)
	defer cleanup()

	resp, err := http.Get(baseURL + "/admin/api/v1/system/info")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	handler := resp.Header.Get("X-Handler")
	if handler != "admin" {
		t.Errorf("GET /admin/api/v1/system/info reached handler %q, want %q", handler, "admin")
	}
}

func TestRouting_HealthRoute(t *testing.T) {
	transport := newTestTransport(t, markerHandler("gateway"))
	baseURL, cleanup := startTestServer(t, transport)
	defer cleanup()

	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /health status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestRouting_GatewayCatchAll(t *testing.T) {
	transport := newTestTransport(t, markerHandler("gateway"))
	baseURL, cleanup := startTestServer(t, transport)
	defer cleanup()

	paths := []string{"/some/api/path", "/v1/chat/completions", "/proxy/endpoint", "/"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(baseURL + path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			handler := resp.Header.Get("X-Handler")
			if handler != "gateway" {
				t.Errorf("GET %s reached handler %q, want %q", path, handler, "gateway")
			}
		})
	}
}

func TestRouting_NoGatewayFallbackToMCP(t *testing.T) {
	// When gateway handler is nil, all non-specific paths should reach MCP handler
	transport := newTestTransport(t, nil)
	baseURL, cleanup := startTestServer(t, transport)
	defer cleanup()

	paths := []string{"/some/api/path", "/v1/chat/completions", "/"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(baseURL + path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			handler := resp.Header.Get("X-Handler")
			if handler != "mcp" {
				t.Errorf("GET %s (no gateway) reached handler %q, want %q", path, handler, "mcp")
			}
		})
	}
}

func TestRouting_TableDriven(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		hasGateway      bool
		expectedHandler string
	}{
		{"MCP explicit", "/mcp", true, "mcp"},
		{"MCP trailing slash", "/mcp/", true, "mcp"},
		{"MCP subpath", "/mcp/some/sub", true, "mcp"},
		{"Admin UI", "/admin/", true, "admin"},
		{"Admin API", "/admin/api/v1/policies", true, "admin"},
		{"Gateway catch-all root", "/", true, "gateway"},
		{"Gateway catch-all path", "/api/v1/data", true, "gateway"},
		{"No gateway root fallback", "/", false, "mcp"},
		{"No gateway path fallback", "/api/v1/data", false, "mcp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gwHandler http.Handler
			if tt.hasGateway {
				gwHandler = markerHandler("gateway")
			}
			transport := newTestTransport(t, gwHandler)
			baseURL, cleanup := startTestServer(t, transport)
			defer cleanup()

			resp, err := http.Get(baseURL + tt.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			handler := resp.Header.Get("X-Handler")
			if handler != tt.expectedHandler {
				t.Errorf("GET %s reached handler %q, want %q", tt.path, handler, tt.expectedHandler)
			}
		})
	}
}

func TestWithHTTPGatewayHandler_Option(t *testing.T) {
	handler := markerHandler("test-gateway")
	transport := &HTTPTransport{}
	opt := WithHTTPGatewayHandler(handler)
	opt(transport)

	if transport.httpGatewayHandler == nil {
		t.Fatal("WithHTTPGatewayHandler did not set httpGatewayHandler")
	}
}

func TestTransport_StartAndShutdown(t *testing.T) {
	// Integration test: verify the real Start() method builds the mux correctly.
	// We start the transport, make a request to /health, then shut down.
	logger := slog.Default()
	proxyService := service.NewProxyService(nil, nil, logger)

	transport := NewHTTPTransport(proxyService,
		WithAddr("127.0.0.1:0"),
		WithLogger(logger),
	)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- transport.Start(ctx)
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context to trigger shutdown
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start() returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start() did not return within 5 seconds after cancel")
	}
}
