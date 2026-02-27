package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- isLocalhost Tests ---

func TestIsLocalhost_IPv4Loopback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	if !isLocalhost(req) {
		t.Error("expected 127.0.0.1 to be localhost")
	}
}

func TestIsLocalhost_IPv6Loopback(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::1]:12345"
	if !isLocalhost(req) {
		t.Error("expected ::1 to be localhost")
	}
}

func TestIsLocalhost_RemoteIPv4(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	if isLocalhost(req) {
		t.Error("expected 192.168.1.1 to NOT be localhost")
	}
}

func TestIsLocalhost_RemoteIPv6(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[2001:db8::1]:12345"
	if isLocalhost(req) {
		t.Error("expected 2001:db8::1 to NOT be localhost")
	}
}

func TestIsLocalhost_NamedLocalhost(t *testing.T) {
	// EDGE-01: "localhost" literal is NOT an IP address, so isLocalhostIP rejects it.
	// Under standard net/http, RemoteAddr always includes a port with an actual IP.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "localhost:12345"
	if isLocalhost(req) {
		t.Error("expected 'localhost' literal to NOT be treated as localhost IP (EDGE-01)")
	}
}

// --- isLocalhostIP unit tests (EDGE-01) ---

func TestIsLocalhostIP_IPv4(t *testing.T) {
	if !isLocalhostIP("127.0.0.1") {
		t.Error("expected isLocalhostIP(127.0.0.1) to be true")
	}
}

func TestIsLocalhostIP_IPv6(t *testing.T) {
	if !isLocalhostIP("::1") {
		t.Error("expected isLocalhostIP(::1) to be true")
	}
}

func TestIsLocalhostIP_Localhost_Literal(t *testing.T) {
	if isLocalhostIP("localhost") {
		t.Error("expected isLocalhostIP(localhost) to be false (EDGE-01)")
	}
}

func TestIsLocalhostIP_RemoteIP(t *testing.T) {
	if isLocalhostIP("192.168.1.1") {
		t.Error("expected isLocalhostIP(192.168.1.1) to be false")
	}
}

// --- adminAuthMiddleware Tests ---

func TestAdminAuthMiddleware_LocalhostPassesThrough(t *testing.T) {
	h := NewAdminAPIHandler()

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := h.adminAuthMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/upstreams", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("middleware should pass through for localhost")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestAdminAuthMiddleware_Remote_403(t *testing.T) {
	h := NewAdminAPIHandler()

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	handler := h.adminAuthMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/upstreams", nil)
	req.RemoteAddr = "192.168.1.100:5555"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Error("middleware should NOT pass through for remote requests")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

// --- X-Forwarded-For / Trusted Proxy Tests (HARD-11) ---

// TestClientIP_NoTrustedProxies_XFFIgnored verifies that without trusted proxies
// configured, X-Forwarded-For is ignored even if it claims to be 127.0.0.1.
func TestClientIP_NoTrustedProxies_XFFIgnored(t *testing.T) {
	h := NewAdminAPIHandler() // no trusted proxies

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")

	got := h.clientIP(req)
	if got != "1.2.3.4" {
		t.Errorf("clientIP = %q, want 1.2.3.4 (XFF must be ignored without trusted proxies)", got)
	}
}

// TestClientIP_NoTrustedProxies_XFFIgnored_AuthRejects confirms that auth middleware
// rejects a request from 1.2.3.4 even if X-Forwarded-For claims 127.0.0.1.
func TestClientIP_NoTrustedProxies_XFFIgnored_AuthRejects(t *testing.T) {
	h := NewAdminAPIHandler()

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := h.adminAuthMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/upstreams", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Error("request should be rejected when XFF claims localhost but no trusted proxies are set")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

// TestClientIP_TrustedProxy_XFFLocalhost_Accepted verifies that when a request comes from
// a trusted proxy (10.0.0.1) and X-Forwarded-For is 127.0.0.1, access is granted.
func TestClientIP_TrustedProxy_XFFLocalhost_Accepted(t *testing.T) {
	h := NewAdminAPIHandler(WithTrustedProxies([]string{"10.0.0.0/8"}))

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := h.adminAuthMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/upstreams", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("request should be accepted when trusted proxy forwards 127.0.0.1")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// TestClientIP_TrustedProxy_XFFRemote_Rejected verifies that when a request comes from
// a trusted proxy (10.0.0.1) and X-Forwarded-For is a non-localhost IP (1.2.3.4),
// the request is rejected.
func TestClientIP_TrustedProxy_XFFRemote_Rejected(t *testing.T) {
	h := NewAdminAPIHandler(WithTrustedProxies([]string{"10.0.0.0/8"}))

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := h.adminAuthMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/upstreams", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Error("request should be rejected when trusted proxy forwards non-localhost IP")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

// TestClientIP_UntrustedSource_XFFLocalhost_Rejected verifies that when a request comes from
// a non-trusted IP (1.2.3.4) with X-Forwarded-For: 127.0.0.1, it is rejected.
// XFF must be ignored for untrusted sources.
func TestClientIP_UntrustedSource_XFFLocalhost_Rejected(t *testing.T) {
	h := NewAdminAPIHandler(WithTrustedProxies([]string{"10.0.0.0/8"}))

	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	handler := h.adminAuthMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/upstreams", nil)
	req.RemoteAddr = "1.2.3.4:1234" // NOT in 10.0.0.0/8
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Error("request from untrusted source with XFF localhost should be rejected")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}
