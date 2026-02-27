package admin

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
)

// newTestLegacyHandler creates a legacy AdminHandler in production mode
// (no DevMode, no YAML API keys) for testing.
func newTestLegacyHandler(t *testing.T) *AdminHandler {
	t.Helper()
	cfg := &config.OSSConfig{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	h, err := NewAdminHandler(cfg, logger)
	if err != nil {
		t.Fatalf("NewAdminHandler: %v", err)
	}
	return h
}

// TestLegacyHandler_SPA_Localhost_NoAuth_Serves200 verifies that the SPA
// shell is served without authentication when the request originates from
// localhost. This is consistent with AdminAPIHandler's localhost bypass.
func TestLegacyHandler_SPA_Localhost_NoAuth_Serves200(t *testing.T) {
	h := newTestLegacyHandler(t)
	handler := h.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /admin from localhost: got %d, want 200 (localhost should bypass auth)", rec.Code)
	}
}

// TestLegacyHandler_SPA_Localhost_IPv6_Serves200 verifies localhost bypass
// also works with IPv6 loopback (::1).
func TestLegacyHandler_SPA_Localhost_IPv6_Serves200(t *testing.T) {
	h := newTestLegacyHandler(t)
	handler := h.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "[::1]:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("GET /admin from [::1]: got %d, want 200", rec.Code)
	}
}

// TestLegacyHandler_SPA_Remote_NoAuth_Returns403 verifies that remote
// requests are rejected with 403 (localhost-only in OSS).
func TestLegacyHandler_SPA_Remote_NoAuth_Returns403(t *testing.T) {
	h := newTestLegacyHandler(t)
	handler := h.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "192.168.1.100:5555"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /admin from remote: got %d, want 403 (localhost-only)", rec.Code)
	}
}

// TestLegacyHandler_StaticFiles_AlwaysServed verifies that static files
// are served without authentication from any source.
func TestLegacyHandler_StaticFiles_AlwaysServed(t *testing.T) {
	h := newTestLegacyHandler(t)
	handler := h.Handler()

	req := httptest.NewRequest(http.MethodGet, "/admin/static/css/variables.css", nil)
	req.RemoteAddr = "192.168.1.100:5555"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Errorf("GET /admin/static/... from remote: got %d, static files should not require auth", rec.Code)
	}
}
