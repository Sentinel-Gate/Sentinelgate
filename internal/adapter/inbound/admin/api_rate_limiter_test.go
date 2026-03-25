package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

func TestAPIRateLimit_UnderLimit_Succeeds(t *testing.T) {
	h := NewAdminAPIHandler()
	handler := h.apiRateLimitMiddleware(5, 1*time.Minute, okHandler())

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
		req.RemoteAddr = "192.168.1.100:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i+1, rec.Code)
		}
	}
}

func TestAPIRateLimit_OverLimit_Returns429(t *testing.T) {
	h := NewAdminAPIHandler()
	handler := h.apiRateLimitMiddleware(3, 1*time.Minute, okHandler())

	// Use up the limit.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
		req.RemoteAddr = "10.0.0.1:5678"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: want 200, got %d", i+1, rec.Code)
		}
	}

	// Next request should be rate-limited.
	req := httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
	req.RemoteAddr = "10.0.0.1:5678"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rec.Code)
	}

	// Verify Retry-After header is present.
	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("missing Retry-After header")
	}

	// Verify error response body.
	var errResp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if errResp["error"] != "rate limit exceeded" {
		t.Errorf("unexpected error message: %q", errResp["error"])
	}
}

// TestAPIRateLimit_LocalhostIsRateLimited verifies that localhost is subject to
// rate limiting like any other IP (M-15: localhost exemption removed).
func TestAPIRateLimit_LocalhostIsRateLimited(t *testing.T) {
	h := NewAdminAPIHandler()
	handler := h.apiRateLimitMiddleware(2, 1*time.Minute, okHandler())

	// First 2 requests from localhost should succeed.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("localhost request %d: want 200, got %d", i+1, rec.Code)
		}
	}

	// Third request should be rate-limited.
	req := httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("localhost over limit: want 429, got %d", rec.Code)
	}
}

func TestAPIRateLimit_DifferentIPs_IndependentLimits(t *testing.T) {
	h := NewAdminAPIHandler()
	handler := h.apiRateLimitMiddleware(2, 1*time.Minute, okHandler())

	// IP 1 uses its limit.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("IP1 request %d: want 200, got %d", i+1, rec.Code)
		}
	}

	// IP 1 is now rate-limited.
	req := httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("IP1 over limit: want 429, got %d", rec.Code)
	}

	// IP 2 should still be allowed.
	req = httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("IP2: want 200, got %d", rec.Code)
	}
}

func TestAPIRateLimit_ResetsAfterWindow(t *testing.T) {
	h := NewAdminAPIHandler()
	// Use a very short window for testing.
	handler := h.apiRateLimitMiddleware(1, 50*time.Millisecond, okHandler())

	// Use up the limit.
	req := httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: want 200, got %d", rec.Code)
	}

	// Should be rate-limited.
	req = httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over limit: want 429, got %d", rec.Code)
	}

	// Wait for window to expire.
	time.Sleep(60 * time.Millisecond)

	// Should be allowed again.
	req = httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("after reset: want 200, got %d", rec.Code)
	}
}

// TestAPIRateLimit_XFFAwareBucketing verifies that when trusted proxies are configured,
// the rate limiter uses the XFF-resolved client IP for bucket keying, not the proxy IP (EDGE-02).
func TestAPIRateLimit_XFFAwareBucketing(t *testing.T) {
	h := NewAdminAPIHandler(WithTrustedProxies([]string{"10.0.0.0/8"}))
	handler := h.apiRateLimitMiddleware(2, 1*time.Minute, okHandler())

	// Two requests from client 1.2.3.4 via trusted proxy 10.0.0.1.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("client1 request %d: want 200, got %d", i+1, rec.Code)
		}
	}

	// Client 1.2.3.4 is now rate-limited.
	req := httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("client1 over limit: want 429, got %d", rec.Code)
	}

	// Client 5.6.7.8 via the SAME proxy should still be allowed (different bucket).
	req = httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "5.6.7.8")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("client2 via same proxy: want 200, got %d", rec.Code)
	}
}

// TestAPIRateLimit_XFFLocalhostIsRateLimited verifies that XFF-resolved localhost
// is subject to rate limiting like any other IP (M-15: localhost exemption removed).
func TestAPIRateLimit_XFFLocalhostIsRateLimited(t *testing.T) {
	h := NewAdminAPIHandler(WithTrustedProxies([]string{"10.0.0.0/8"}))
	handler := h.apiRateLimitMiddleware(2, 1*time.Minute, okHandler())

	// First 2 requests from "localhost" via trusted proxy should succeed.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("XFF localhost request %d: want 200, got %d", i+1, rec.Code)
		}
	}

	// Third request should be rate-limited.
	req := httptest.NewRequest(http.MethodGet, "/admin/api/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("XFF localhost over limit: want 429, got %d", rec.Code)
	}
}
