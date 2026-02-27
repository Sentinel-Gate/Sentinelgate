package http

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
)

// --- RequestIDMiddleware tests ---

func TestRequestIDMiddleware_GeneratesID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mw := RequestIDMiddleware(logger)

	var capturedID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID, _ = r.Context().Value(RequestIDKey).(string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, req)

	if capturedID == "" {
		t.Error("RequestIDMiddleware should generate an ID when X-Request-ID is absent")
	}
	if rec.Header().Get("X-Request-ID") != capturedID {
		t.Errorf("response header X-Request-ID = %q, want %q", rec.Header().Get("X-Request-ID"), capturedID)
	}
}

func TestRequestIDMiddleware_PassthroughExisting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mw := RequestIDMiddleware(logger)

	const existingID = "my-custom-request-id-123"
	var capturedID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID, _ = r.Context().Value(RequestIDKey).(string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", existingID)
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, req)

	if capturedID != existingID {
		t.Errorf("context request ID = %q, want %q", capturedID, existingID)
	}
	if rec.Header().Get("X-Request-ID") != existingID {
		t.Errorf("response header X-Request-ID = %q, want %q", rec.Header().Get("X-Request-ID"), existingID)
	}
}

func TestRequestIDMiddleware_EnrichesLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mw := RequestIDMiddleware(logger)

	var capturedLogger *slog.Logger
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedLogger, _ = r.Context().Value(LoggerKey).(*slog.Logger)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, req)

	if capturedLogger == nil {
		t.Fatal("enriched logger should be stored in context")
	}
}

// --- LoggerFromContext tests ---

func TestLoggerFromContext_WithLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mw := RequestIDMiddleware(logger)

	var got *slog.Logger
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = LoggerFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, req)

	if got == nil {
		t.Fatal("LoggerFromContext should return non-nil logger when set")
	}
}

func TestLoggerFromContext_Fallback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	got := LoggerFromContext(req.Context())
	if got == nil {
		t.Fatal("LoggerFromContext should return slog.Default() when no logger in context")
	}
}

// --- DNSRebindingProtection tests ---

func TestDNSRebindingProtection_NoOrigin_Allowed(t *testing.T) {
	mw := DNSRebindingProtection([]string{"http://localhost:8080"})

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No Origin header
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, req)

	if !called {
		t.Error("request without Origin header should be allowed")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestDNSRebindingProtection_AllowedOrigin(t *testing.T) {
	mw := DNSRebindingProtection([]string{"http://localhost:8080", "https://example.com"})

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, req)

	if !called {
		t.Error("request with allowed Origin should be passed through")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestDNSRebindingProtection_BlockedOrigin(t *testing.T) {
	mw := DNSRebindingProtection([]string{"http://localhost:8080"})

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, req)

	if called {
		t.Error("request with blocked Origin should not reach handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestDNSRebindingProtection_EmptyAllowlist_BlocksAll(t *testing.T) {
	mw := DNSRebindingProtection(nil) // empty allowlist

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "http://anything.com")
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, req)

	if called {
		t.Error("with empty allowlist, any Origin header should be blocked")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// --- APIKeyMiddleware tests ---

func TestAPIKeyMiddleware_BearerToken(t *testing.T) {
	var capturedKey string
	var capturedConnID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedKey, _ = r.Context().Value(proxy.APIKeyContextKey).(string)
		capturedConnID, _ = r.Context().Value(proxy.ConnectionIDKey).(string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer my-secret-api-key")
	rec := httptest.NewRecorder()
	APIKeyMiddleware(inner).ServeHTTP(rec, req)

	if capturedKey != "my-secret-api-key" {
		t.Errorf("captured API key = %q, want %q", capturedKey, "my-secret-api-key")
	}
	if capturedConnID == "" {
		t.Error("connection ID should be set when API key is provided")
	}
	// Connection ID should be deterministic
	expected := apiKeyConnectionID("my-secret-api-key")
	if capturedConnID != expected {
		t.Errorf("connection ID = %q, want %q", capturedConnID, expected)
	}
}

func TestAPIKeyMiddleware_NoAuth(t *testing.T) {
	var capturedKey string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedKey, _ = r.Context().Value(proxy.APIKeyContextKey).(string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No Authorization header
	rec := httptest.NewRecorder()
	APIKeyMiddleware(inner).ServeHTTP(rec, req)

	if capturedKey != "" {
		t.Errorf("API key should be empty when no Authorization header, got %q", capturedKey)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d (should pass through without key)", rec.Code, http.StatusOK)
	}
}

func TestAPIKeyMiddleware_NonBearerAuth(t *testing.T) {
	var capturedKey string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedKey, _ = r.Context().Value(proxy.APIKeyContextKey).(string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // Basic auth, not Bearer
	rec := httptest.NewRecorder()
	APIKeyMiddleware(inner).ServeHTTP(rec, req)

	if capturedKey != "" {
		t.Errorf("API key should be empty for non-Bearer auth, got %q", capturedKey)
	}
}

// --- apiKeyConnectionID tests ---

func TestApiKeyConnectionID_Deterministic(t *testing.T) {
	id1 := apiKeyConnectionID("test-key")
	id2 := apiKeyConnectionID("test-key")
	if id1 != id2 {
		t.Errorf("same key should produce same ID: %q vs %q", id1, id2)
	}
}

func TestApiKeyConnectionID_DifferentKeys(t *testing.T) {
	id1 := apiKeyConnectionID("key-a")
	id2 := apiKeyConnectionID("key-b")
	if id1 == id2 {
		t.Errorf("different keys should produce different IDs: both %q", id1)
	}
}

func TestApiKeyConnectionID_HasPrefix(t *testing.T) {
	id := apiKeyConnectionID("test-key")
	if len(id) < 5 || id[:5] != "http-" {
		t.Errorf("connection ID should start with 'http-', got %q", id)
	}
}

// --- extractRealIP tests ---

func TestExtractRealIP_XForwardedFor_Single(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")

	ip := extractRealIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("extractRealIP = %q, want %q", ip, "10.0.0.1")
	}
}

func TestExtractRealIP_XForwardedFor_Multiple(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2, 10.0.0.3")

	ip := extractRealIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("extractRealIP = %q, want first IP %q", ip, "10.0.0.1")
	}
}

func TestExtractRealIP_XRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "172.16.0.1")

	ip := extractRealIP(req)
	if ip != "172.16.0.1" {
		t.Errorf("extractRealIP = %q, want %q", ip, "172.16.0.1")
	}
}

func TestExtractRealIP_XForwardedFor_TakesPrecedence(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("X-Real-IP", "172.16.0.1")

	ip := extractRealIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("X-Forwarded-For should take precedence: got %q, want %q", ip, "10.0.0.1")
	}
}

func TestExtractRealIP_FallbackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// httptest.NewRequest sets RemoteAddr to "192.0.2.1:1234"
	req.RemoteAddr = "192.168.1.100:54321"

	ip := extractRealIP(req)
	if ip != "192.168.1.100" {
		t.Errorf("extractRealIP = %q, want %q (from RemoteAddr)", ip, "192.168.1.100")
	}
}

func TestExtractRealIP_RemoteAddrWithoutPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100" // no port

	ip := extractRealIP(req)
	if ip != "192.168.1.100" {
		t.Errorf("extractRealIP = %q, want %q", ip, "192.168.1.100")
	}
}

func TestExtractRealIP_XForwardedFor_WithSpaces(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "  10.0.0.1  , 10.0.0.2 ")

	ip := extractRealIP(req)
	if ip != "10.0.0.1" {
		t.Errorf("extractRealIP = %q, want trimmed %q", ip, "10.0.0.1")
	}
}

// --- RealIPMiddleware tests ---

func TestRealIPMiddleware_SetsContext(t *testing.T) {
	var capturedIP string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedIP, _ = r.Context().Value(proxy.IPAddressKey).(string)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Real-IP", "10.20.30.40")
	rec := httptest.NewRecorder()
	RealIPMiddleware(inner).ServeHTTP(rec, req)

	if capturedIP != "10.20.30.40" {
		t.Errorf("captured IP = %q, want %q", capturedIP, "10.20.30.40")
	}
}
