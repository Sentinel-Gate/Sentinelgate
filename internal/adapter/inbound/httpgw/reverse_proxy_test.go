package httpgw

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
)

// === ReverseProxy.Match Tests ===

// TestReverseProxy_MatchLongestPrefix verifies that the most specific (longest)
// matching path prefix wins when multiple targets could match.
func TestReverseProxy_MatchLongestPrefix(t *testing.T) {
	rp := NewReverseProxy(testLogger())
	rp.SetTargets([]UpstreamTarget{
		{ID: "broad", PathPrefix: "/api/", Upstream: "http://broad.local", Enabled: true},
		{ID: "specific", PathPrefix: "/api/v2/", Upstream: "http://specific.local", Enabled: true},
	})

	target := rp.Match("/api/v2/foo")
	if target == nil {
		t.Fatal("expected a match")
	}
	if target.ID != "specific" {
		t.Errorf("expected 'specific' target, got %q", target.ID)
	}

	// /api/v1/bar should match the broad target
	target = rp.Match("/api/v1/bar")
	if target == nil {
		t.Fatal("expected a match for /api/v1/bar")
	}
	if target.ID != "broad" {
		t.Errorf("expected 'broad' target, got %q", target.ID)
	}
}

// TestReverseProxy_NoMatch verifies that nil is returned when no target matches.
func TestReverseProxy_NoMatch(t *testing.T) {
	rp := NewReverseProxy(testLogger())
	rp.SetTargets([]UpstreamTarget{
		{ID: "api", PathPrefix: "/api/", Upstream: "http://api.local", Enabled: true},
	})

	target := rp.Match("/other/path")
	if target != nil {
		t.Errorf("expected nil match, got %v", target)
	}
}

// TestReverseProxy_DisabledTargetSkipped verifies that disabled targets are skipped.
func TestReverseProxy_DisabledTargetSkipped(t *testing.T) {
	rp := NewReverseProxy(testLogger())
	rp.SetTargets([]UpstreamTarget{
		{ID: "disabled", PathPrefix: "/api/", Upstream: "http://disabled.local", Enabled: false},
	})

	target := rp.Match("/api/data")
	if target != nil {
		t.Errorf("expected nil match for disabled target, got %v", target)
	}
}

// === ReverseProxy.Forward Tests ===

// TestReverseProxy_ForwardStripPrefix verifies that StripPrefix=true strips
// the path prefix before forwarding to the upstream.
func TestReverseProxy_ForwardStripPrefix(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	rp := NewReverseProxy(testLogger())
	target := &UpstreamTarget{
		ID:          "test",
		Name:        "Test",
		PathPrefix:  "/api/openai/",
		Upstream:    upstream.URL,
		StripPrefix: true,
		Enabled:     true,
	}

	req := httptest.NewRequest("GET", "/api/openai/v1/chat", nil)
	rec := httptest.NewRecorder()

	rp.Forward(rec, req, target)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if receivedPath != "/v1/chat" {
		t.Errorf("expected path '/v1/chat', got %q", receivedPath)
	}
}

// TestReverseProxy_ForwardNoStripPrefix verifies that StripPrefix=false preserves
// the full path when forwarding.
func TestReverseProxy_ForwardNoStripPrefix(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()

	rp := NewReverseProxy(testLogger())
	target := &UpstreamTarget{
		ID:          "test",
		Name:        "Test",
		PathPrefix:  "/api/",
		Upstream:    upstream.URL,
		StripPrefix: false,
		Enabled:     true,
	}

	req := httptest.NewRequest("GET", "/api/data/items", nil)
	rec := httptest.NewRecorder()

	rp.Forward(rec, req, target)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if receivedPath != "/api/data/items" {
		t.Errorf("expected path '/api/data/items', got %q", receivedPath)
	}
}

// TestReverseProxy_HeaderInjection verifies that configured headers are injected
// into proxied requests, overwriting existing headers.
func TestReverseProxy_HeaderInjection(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp := NewReverseProxy(testLogger())
	target := &UpstreamTarget{
		ID:         "test",
		Name:       "Test",
		PathPrefix: "/api/",
		Upstream:   upstream.URL,
		Headers: map[string]string{
			"Authorization": "Bearer sk-secret",
			"X-Custom":      "injected",
		},
		Enabled: true,
	}

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("Authorization", "Bearer original")
	req.Header.Set("X-Existing", "preserved")
	rec := httptest.NewRecorder()

	rp.Forward(rec, req, target)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Injected headers should overwrite existing
	if receivedHeaders.Get("Authorization") != "Bearer sk-secret" {
		t.Errorf("expected injected Authorization, got %q", receivedHeaders.Get("Authorization"))
	}
	if receivedHeaders.Get("X-Custom") != "injected" {
		t.Errorf("expected X-Custom 'injected', got %q", receivedHeaders.Get("X-Custom"))
	}
	// Non-injected headers should be preserved
	if receivedHeaders.Get("X-Existing") != "preserved" {
		t.Errorf("expected X-Existing 'preserved', got %q", receivedHeaders.Get("X-Existing"))
	}
}

// TestReverseProxy_UpstreamError verifies that an unreachable upstream returns
// a 502 Bad Gateway response with a JSON error body.
func TestReverseProxy_UpstreamError(t *testing.T) {
	rp := NewReverseProxy(testLogger())
	target := &UpstreamTarget{
		ID:         "test",
		Name:       "Test",
		PathPrefix: "/api/",
		Upstream:   "http://127.0.0.1:1", // Port 1 is typically refused
		Enabled:    true,
	}

	req := httptest.NewRequest("GET", "/api/data", nil)
	rec := httptest.NewRecorder()

	rp.Forward(rec, req, target)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] != "gateway_error" {
		t.Errorf("expected error 'gateway_error', got %v", resp["error"])
	}
}

// TestReverseProxy_HopByHopHeadersRemoved verifies that hop-by-hop headers
// (Connection, Proxy-Authorization, etc.) are not forwarded to the upstream.
func TestReverseProxy_HopByHopHeadersRemoved(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp := NewReverseProxy(testLogger())
	target := &UpstreamTarget{
		ID:         "test",
		Name:       "Test",
		PathPrefix: "/api/",
		Upstream:   upstream.URL,
		Enabled:    true,
	}

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Proxy-Authorization", "Bearer secret")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("X-Custom", "should-remain")
	rec := httptest.NewRecorder()

	rp.Forward(rec, req, target)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	hopHeaders := []string{"Connection", "Proxy-Authorization", "Te", "Transfer-Encoding", "Upgrade"}
	for _, h := range hopHeaders {
		if receivedHeaders.Get(h) != "" {
			t.Errorf("hop-by-hop header %q should be removed, but found %q", h, receivedHeaders.Get(h))
		}
	}
	if receivedHeaders.Get("X-Custom") != "should-remain" {
		t.Errorf("X-Custom should be preserved, got %q", receivedHeaders.Get("X-Custom"))
	}
}

// TestReverseProxy_XForwardedHeaders verifies that X-Forwarded-For,
// X-Forwarded-Proto, and X-Forwarded-Host are added to proxied requests.
func TestReverseProxy_XForwardedHeaders(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp := NewReverseProxy(testLogger())
	target := &UpstreamTarget{
		ID:         "test",
		Name:       "Test",
		PathPrefix: "/api/",
		Upstream:   upstream.URL,
		Enabled:    true,
	}

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Host = "gateway.example.com"
	rec := httptest.NewRecorder()

	rp.Forward(rec, req, target)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	if xff := receivedHeaders.Get("X-Forwarded-For"); xff != "10.0.0.1" {
		t.Errorf("expected X-Forwarded-For '10.0.0.1', got %q", xff)
	}
	if xfp := receivedHeaders.Get("X-Forwarded-Proto"); xfp != "http" {
		t.Errorf("expected X-Forwarded-Proto 'http', got %q", xfp)
	}
	if xfh := receivedHeaders.Get("X-Forwarded-Host"); xfh != "gateway.example.com" {
		t.Errorf("expected X-Forwarded-Host 'gateway.example.com', got %q", xfh)
	}
}

// TestReverseProxy_XForwardedForAppend verifies that X-Forwarded-For appends
// to an existing value when the header is already present.
func TestReverseProxy_XForwardedForAppend(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp := NewReverseProxy(testLogger())
	target := &UpstreamTarget{
		ID:         "test",
		Name:       "Test",
		PathPrefix: "/api/",
		Upstream:   upstream.URL,
		Enabled:    true,
	}

	req := httptest.NewRequest("GET", "/api/data", nil)
	req.RemoteAddr = "10.0.0.2:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	rec := httptest.NewRecorder()

	rp.Forward(rec, req, target)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	expected := "10.0.0.1, 10.0.0.2"
	if xff := receivedHeaders.Get("X-Forwarded-For"); xff != expected {
		t.Errorf("expected X-Forwarded-For %q, got %q", expected, xff)
	}
}

// === Handler Integration Tests with Reverse Proxy ===

// TestReverseProxy_HandlerIntegration verifies the full flow: request ->
// normalize -> destination override -> chain -> reverse proxy forward.
func TestReverseProxy_HandlerIntegration(t *testing.T) {
	var receivedPath string
	var receivedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("X-Upstream", "reverse-proxy")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "proxied response")
	}))
	defer upstream.Close()

	// Track what destination the chain sees
	var chainDestURL string
	chain := &mockInterceptor{
		interceptFn: func(ctx context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			chainDestURL = a.Destination.URL
			return a, nil
		},
	}

	handler := NewHandler(chain, testLogger())

	// Set up reverse proxy
	rp := NewReverseProxy(testLogger())
	rp.SetTargets([]UpstreamTarget{
		{
			ID:          "test",
			Name:        "Test API",
			PathPrefix:  "/api/test/",
			Upstream:    upstream.URL,
			StripPrefix: true,
			Headers: map[string]string{
				"Authorization": "Bearer secret-key",
			},
			Enabled: true,
		},
	})
	handler.SetReverseProxy(rp)

	req := httptest.NewRequest("GET", "/api/test/v1/data?q=hello", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify the response came from upstream
	body := rec.Body.String()
	if body != "proxied response" {
		t.Errorf("expected 'proxied response', got %q", body)
	}
	if rec.Header().Get("X-Upstream") != "reverse-proxy" {
		t.Errorf("expected X-Upstream header from reverse proxy upstream")
	}

	// Verify path stripping worked
	if receivedPath != "/v1/data" {
		t.Errorf("expected upstream path '/v1/data', got %q", receivedPath)
	}

	// Verify header injection worked
	if receivedAuth != "Bearer secret-key" {
		t.Errorf("expected injected Authorization, got %q", receivedAuth)
	}

	// Verify the chain saw the real upstream URL (not the local path)
	if !strings.HasPrefix(chainDestURL, upstream.URL) {
		t.Errorf("expected chain Destination.URL to start with %q, got %q", upstream.URL, chainDestURL)
	}
}

// TestReverseProxy_HandlerFallbackForwardProxy verifies that requests not matching
// any reverse proxy target fall through to forward proxy mode.
func TestReverseProxy_HandlerFallbackForwardProxy(t *testing.T) {
	// Forward proxy upstream
	forwardUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "forward proxy response")
	}))
	defer forwardUpstream.Close()

	chain := &mockInterceptor{} // Allow all
	handler := newTestHandler(chain, testLogger())

	// Set up reverse proxy with a different prefix
	rp := NewReverseProxy(testLogger())
	rp.SetTargets([]UpstreamTarget{
		{
			ID:         "api",
			PathPrefix: "/api/special/",
			Upstream:   "http://special.local",
			Enabled:    true,
		},
	})
	handler.SetReverseProxy(rp)

	// Request to a non-matching path should go through forward proxy
	req := httptest.NewRequest("GET", forwardUpstream.URL+"/other/path", nil)
	req.Host = strings.TrimPrefix(forwardUpstream.URL, "http://")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 (forward proxy), got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if body != "forward proxy response" {
		t.Errorf("expected 'forward proxy response', got %q", body)
	}
}

// TestReverseProxy_HandlerDeniedByChain verifies that the chain can deny
// reverse proxy requests (returning 403).
func TestReverseProxy_HandlerDeniedByChain(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be called when chain denies request")
	}))
	defer upstream.Close()

	chain := &mockInterceptor{
		interceptFn: func(ctx context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			return nil, &action.OutboundDenyError{
				Domain:   "api.blocked.com",
				RuleName: "test-blocklist",
				Reason:   "domain blocked by outbound rule",
			}
		},
	}

	handler := NewHandler(chain, testLogger())

	rp := NewReverseProxy(testLogger())
	rp.SetTargets([]UpstreamTarget{
		{
			ID:         "blocked",
			PathPrefix: "/api/blocked/",
			Upstream:   upstream.URL,
			Enabled:    true,
		},
	})
	handler.SetReverseProxy(rp)

	req := httptest.NewRequest("GET", "/api/blocked/data", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"] != "outbound_blocked" {
		t.Errorf("expected error 'outbound_blocked', got %v", resp["error"])
	}
}

// TestReverseProxy_ForwardPOSTBody verifies that POST request bodies are
// correctly forwarded through the reverse proxy.
func TestReverseProxy_ForwardPOSTBody(t *testing.T) {
	var receivedBody string
	var receivedMethod string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, "created")
	}))
	defer upstream.Close()

	rp := NewReverseProxy(testLogger())
	target := &UpstreamTarget{
		ID:          "test",
		Name:        "Test",
		PathPrefix:  "/api/",
		Upstream:    upstream.URL,
		StripPrefix: true,
		Enabled:     true,
	}

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`
	req := httptest.NewRequest("POST", "/api/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	rp.Forward(rec, req, target)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if receivedMethod != "POST" {
		t.Errorf("expected POST method, got %s", receivedMethod)
	}
	if receivedBody != body {
		t.Errorf("expected body %q, got %q", body, receivedBody)
	}
}

// TestReverseProxy_QueryStringPreserved verifies that query strings are
// preserved when forwarding through the reverse proxy.
func TestReverseProxy_QueryStringPreserved(t *testing.T) {
	var receivedQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp := NewReverseProxy(testLogger())
	target := &UpstreamTarget{
		ID:          "test",
		Name:        "Test",
		PathPrefix:  "/api/",
		Upstream:    upstream.URL,
		StripPrefix: true,
		Enabled:     true,
	}

	req := httptest.NewRequest("GET", "/api/search?q=hello&limit=10", nil)
	rec := httptest.NewRecorder()

	rp.Forward(rec, req, target)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if receivedQuery != "q=hello&limit=10" {
		t.Errorf("expected query 'q=hello&limit=10', got %q", receivedQuery)
	}
}

// === Helper function tests ===

// TestBuildUpstreamURL verifies the upstream URL construction with and without
// prefix stripping.
func TestBuildUpstreamURL(t *testing.T) {
	tests := []struct {
		name     string
		target   UpstreamTarget
		path     string
		expected string
	}{
		{
			name: "strip prefix",
			target: UpstreamTarget{
				PathPrefix:  "/api/openai/",
				Upstream:    "https://api.openai.com",
				StripPrefix: true,
			},
			path:     "/api/openai/v1/chat",
			expected: "https://api.openai.com/v1/chat",
		},
		{
			name: "no strip prefix",
			target: UpstreamTarget{
				PathPrefix:  "/api/",
				Upstream:    "https://backend.local",
				StripPrefix: false,
			},
			path:     "/api/data/items",
			expected: "https://backend.local/api/data/items",
		},
		{
			name: "trailing slash on upstream",
			target: UpstreamTarget{
				PathPrefix:  "/api/",
				Upstream:    "https://backend.local/",
				StripPrefix: true,
			},
			path:     "/api/items",
			expected: "https://backend.local/items",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildUpstreamURL(&tt.target, tt.path)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestExtractDomain verifies domain extraction from URLs.
func TestExtractDomain(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://api.openai.com", "api.openai.com"},
		{"http://localhost:8080", "localhost"},
		{"https://example.com/path", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			result := extractDomain(tt.url)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestExtractPort verifies port extraction from URLs with defaults.
func TestExtractPort(t *testing.T) {
	tests := []struct {
		url      string
		expected int
	}{
		{"https://api.openai.com", 443},
		{"http://localhost:8080", 8080},
		{"http://example.com", 80},
		{"https://example.com:9443", 9443},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			result := extractPort(tt.url)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}
