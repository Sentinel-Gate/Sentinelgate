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
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "localhost:12345"
	if !isLocalhost(req) {
		t.Error("expected 'localhost' to be localhost")
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
