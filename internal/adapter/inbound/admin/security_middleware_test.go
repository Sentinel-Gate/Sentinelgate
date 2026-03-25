package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mustCSRFToken is a test helper that generates a CSRF token or fails the test.
func mustCSRFToken(t *testing.T) string {
	t.Helper()
	token, err := generateCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// dummyHandler returns a 200 OK with a fixed body for middleware testing.
func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// --- CSP Middleware Tests ---

func TestCSP_SetsHeaders(t *testing.T) {
	handler := cspMiddleware(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header not set")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing default-src 'self': %s", csp)
	}
	if !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP missing script-src 'self': %s", csp)
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP missing frame-ancestors 'none': %s", csp)
	}
	// Fonts are self-hosted — CSP should NOT reference external font domains.
	if strings.Contains(csp, "fonts.googleapis.com") {
		t.Errorf("CSP should not reference fonts.googleapis.com (fonts are self-hosted): %s", csp)
	}
	if strings.Contains(csp, "fonts.gstatic.com") {
		t.Errorf("CSP should not reference fonts.gstatic.com (fonts are self-hosted): %s", csp)
	}

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", rec.Header().Get("X-Content-Type-Options"))
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", rec.Header().Get("X-Frame-Options"))
	}
	if rec.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy = %q, want strict-origin-when-cross-origin", rec.Header().Get("Referrer-Policy"))
	}
}

// --- CSRF Middleware Tests ---

func TestCSRF_SetsCookieOnGET(t *testing.T) {
	handler := csrfMiddleware(dummyHandler())

	req := httptest.NewRequest(http.MethodGet, "/admin/api/upstreams", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	cookies := rec.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "sentinel_csrf_token" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("expected sentinel_csrf_token cookie on GET")
	}
	if csrfCookie.HttpOnly {
		t.Error("CSRF cookie should NOT be HttpOnly (JS needs to read it)")
	}
	if csrfCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("CSRF cookie SameSite = %v, want Strict", csrfCookie.SameSite)
	}
	if len(csrfCookie.Value) != 64 { // 32 bytes hex-encoded = 64 chars
		t.Errorf("CSRF token length = %d, want 64", len(csrfCookie.Value))
	}
}

func TestCSRF_POSTWithoutToken_Returns403(t *testing.T) {
	handler := csrfMiddleware(dummyHandler())

	req := httptest.NewRequest(http.MethodPost, "/admin/api/upstreams", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF token: status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "CSRF token invalid") {
		t.Errorf("expected CSRF error message, got: %s", rec.Body.String())
	}
}

func TestCSRF_POSTWithValidToken_Succeeds(t *testing.T) {
	handler := csrfMiddleware(dummyHandler())

	token := mustCSRFToken(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/api/upstreams", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST with valid CSRF token: status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestCSRF_POSTWithMismatchedToken_Returns403(t *testing.T) {
	handler := csrfMiddleware(dummyHandler())

	req := httptest.NewRequest(http.MethodPost, "/admin/api/upstreams", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "wrong-token")
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: mustCSRFToken(t)})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST with mismatched CSRF token: status = %d, want 403", rec.Code)
	}
}

func TestCSRF_GETBypassesValidation(t *testing.T) {
	handler := csrfMiddleware(dummyHandler())

	// GET without any CSRF token should succeed.
	req := httptest.NewRequest(http.MethodGet, "/admin/api/upstreams", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET should bypass CSRF validation: status = %d, want 200", rec.Code)
	}
}

func TestCSRF_AuthEndpointsBypassValidation(t *testing.T) {
	handler := csrfMiddleware(dummyHandler())

	// POST to auth status endpoint without CSRF token should succeed (auth prefix bypass).
	req := httptest.NewRequest(http.MethodPost, "/admin/api/auth/status", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST to /admin/api/auth/status should bypass CSRF: status = %d, want 200", rec.Code)
	}
}

func TestCSRF_DELETEWithoutToken_Returns403(t *testing.T) {
	handler := csrfMiddleware(dummyHandler())

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/upstreams/abc123", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("DELETE without CSRF token: status = %d, want 403", rec.Code)
	}
}

func TestCSRF_PUTWithValidToken_Succeeds(t *testing.T) {
	handler := csrfMiddleware(dummyHandler())

	token := mustCSRFToken(t)

	req := httptest.NewRequest(http.MethodPut, "/admin/api/policies/abc123", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT with valid CSRF token: status = %d, want 200", rec.Code)
	}
}

func TestCSRF_ExistingCookieNotOverwritten(t *testing.T) {
	handler := csrfMiddleware(dummyHandler())

	existingToken := "existing-token-value-should-not-change"
	req := httptest.NewRequest(http.MethodGet, "/admin/api/upstreams", nil)
	req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: existingToken})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should NOT set a new cookie since one already exists.
	for _, c := range rec.Result().Cookies() {
		if c.Name == "sentinel_csrf_token" {
			t.Error("should not overwrite existing CSRF cookie")
		}
	}
}

func TestGenerateCSRFToken_Unique(t *testing.T) {
	token1 := mustCSRFToken(t)
	token2 := mustCSRFToken(t)

	if token1 == token2 {
		t.Error("two generated CSRF tokens should not be identical")
	}
	if len(token1) != 64 {
		t.Errorf("CSRF token length = %d, want 64", len(token1))
	}
}

// TestGenerateCSRFToken_Format verifies the token is a 64-character lowercase hex string
// (32 random bytes hex-encoded). This documents the expected format for the CSRF validation.
func TestGenerateCSRFToken_Format(t *testing.T) {
	token, err := generateCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 {
		t.Errorf("CSRF token length = %d, want 64 (32 bytes hex-encoded)", len(token))
	}
	for _, c := range token {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("CSRF token contains non-hex char %q: %s", c, token)
			break
		}
	}
}

// TestCSRF_ConstantTimeCompare verifies that the CSRF middleware uses constant-time
// comparison (HARD-10): a valid token is accepted and a mismatched token is rejected.
// The test also confirms that partial-match tokens are rejected (not a prefix leak).
func TestCSRF_ConstantTimeCompare(t *testing.T) {
	handler := csrfMiddleware(dummyHandler())
	token := mustCSRFToken(t)

	// Valid: header matches cookie — must be accepted.
	t.Run("valid_token_accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/api/upstreams", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", token)
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: token})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("valid CSRF token rejected: status = %d", rec.Code)
		}
	})

	// Invalid: header is a prefix of the cookie value — must be rejected.
	t.Run("prefix_token_rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/api/upstreams", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", token[:32]) // first half only
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: token})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("prefix CSRF token accepted: status = %d", rec.Code)
		}
	})

	// Invalid: header is a completely different token — must be rejected.
	t.Run("different_token_rejected", func(t *testing.T) {
		otherToken := mustCSRFToken(t)
		req := httptest.NewRequest(http.MethodPost, "/admin/api/upstreams", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", otherToken)
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: token})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("mismatched CSRF token accepted: status = %d", rec.Code)
		}
	})
}
