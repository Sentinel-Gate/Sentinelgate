package admin

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// ============================================================================
// 3E.1: TestAdminAPI_OversizedBody — EXPOSES BUG B8
// Verifies that the admin API rejects oversized request bodies.
// Without MaxBytesReader in readJSON, json.Decoder allocates the entire body
// in memory, allowing memory exhaustion attacks from localhost.
//
// After fix: should return 413 Request Entity Too Large.
// ============================================================================

func TestAdminAPI_OversizedBody(t *testing.T) {
	// Setup minimal admin handler — only needs readJSON path.
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	handler := NewAdminAPIHandler(
		WithStateStore(stateStore),
		WithAPILogger(logger),
	)

	mux := handler.Routes()

	t.Run("50MB_body_rejected", func(t *testing.T) {
		// Create a 50MB body. We don't need to allocate 50MB of real data —
		// we use a reader that produces 50MB of repeating data.
		// However, for simplicity in checking the behavior, we'll use a
		// large-enough body that exceeds any reasonable limit.
		// With MaxBytesReader set to 10MB, a body > 10MB should be rejected.
		const bodySize = 50 * 1024 * 1024 // 50MB
		body := make([]byte, bodySize)
		// Fill with valid-ish JSON opening to trigger the decoder path
		copy(body, []byte(`{"name":"`))
		for i := 9; i < bodySize-2; i++ {
			body[i] = 'A'
		}
		copy(body[bodySize-2:], []byte(`"}`))

		req := httptest.NewRequest(http.MethodPost, "/admin/api/upstreams", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:1234" // bypass auth middleware
		req.Header.Set("Content-Type", "application/json")
		// Include CSRF token
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: testCSRFToken})
		req.Header.Set("X-CSRF-Token", testCSRFToken)

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		resp := rec.Result()
		defer func() { _ = resp.Body.Close() }()

		// After the B8 fix, the handler should reject the oversized body.
		// Expected: 413 Request Entity Too Large (from MaxBytesReader).
		// Before fix: 400 Bad Request (json decode error) or 200/201 (if somehow parsed).
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			respBody, _ := io.ReadAll(resp.Body)
			t.Errorf("oversized body: status=%d (want 413), body=%s",
				resp.StatusCode, truncate(string(respBody), 200))
		}
	})

	t.Run("normal_body_accepted", func(t *testing.T) {
		// A normal-sized body should parse without error via readJSON.
		normalBody := `{"name":"test-upstream","type":"http","url":"http://localhost:9999","enabled":true}`

		req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(normalBody))
		var target map[string]interface{}
		err := handler.readJSON(req, &target)

		if err != nil {
			t.Errorf("readJSON should accept normal body, got error: %v", err)
		}
		if target["name"] != "test-upstream" {
			t.Errorf("parsed name = %v, want %q", target["name"], "test-upstream")
		}
	})

	t.Run("readJSON_direct_oversized", func(t *testing.T) {
		// Test readJSON directly with an oversized body to verify the
		// MaxBytesReader integration without going through the full route.
		const bodySize = 15 * 1024 * 1024 // 15MB — exceeds 10MB limit
		body := make([]byte, bodySize)
		copy(body, []byte(`{"key":"`))
		for i := 8; i < bodySize-2; i++ {
			body[i] = 'B'
		}
		copy(body[bodySize-2:], []byte(`"}`))

		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))

		var target map[string]interface{}
		err := handler.readJSON(req, &target)

		if err == nil {
			t.Error("readJSON should return error for oversized body, got nil")
		}
	})
}

// ============================================================================
// 3E.2: TestDeeplyNestedJSON
// Verifies that deeply nested JSON (10000 levels) doesn't crash the admin API.
// Go's encoding/json decoder has no built-in nesting depth limit, so extreme
// nesting could cause stack overflow or excessive memory use. The test confirms
// readJSON returns an error (or handles it gracefully) without panicking.
// ============================================================================

func TestDeeplyNestedJSON(t *testing.T) {
	handler := NewAdminAPIHandler()

	const depth = 10000

	// Build deeply nested JSON: {"a":{"a":{"a":...}}}
	var buf bytes.Buffer
	for i := 0; i < depth; i++ {
		buf.WriteString(`{"a":`)
	}
	buf.WriteString(`"leaf"`)
	for i := 0; i < depth; i++ {
		buf.WriteByte('}')
	}

	nestedJSON := buf.Bytes()

	// Use a deferred recover to catch any panic from the JSON decoder.
	// If readJSON panics on deeply nested input, the test fails explicitly.
	didPanic := false
	var readErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
				t.Errorf("readJSON panicked on deeply nested JSON: %v", r)
			}
		}()

		req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(nestedJSON))
		var target interface{}
		readErr = handler.readJSON(req, &target)
	}()

	if didPanic {
		return // already reported via t.Errorf
	}

	// Assert that readJSON handled deeply nested input gracefully:
	// it must either decode successfully or return a non-nil error.
	// A nil error with a nil target would indicate silent data loss.
	if readErr != nil {
		t.Logf("readJSON returned error for %d-level nesting (acceptable): %v", depth, readErr)
	} else {
		// If decoding succeeded, the target must have been populated.
		req2 := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(nestedJSON))
		var target2 interface{}
		_ = handler.readJSON(req2, &target2)
		if target2 == nil {
			t.Error("readJSON returned nil error but target is nil — silent data loss")
		}
	}
}

// ============================================================================
// 3E.3: TestSSE_HTMLEscaping
// Verifies that XSS payloads in audit entries are properly escaped in SSE output.
//
// The SSE audit stream (handleAuditStream) serializes records via json.Marshal,
// which escapes <, >, and & to their Unicode escape sequences (\u003c, \u003e,
// \u0026). This means raw <script> tags can never appear in the SSE output.
//
// This test documents and validates that JSON encoding is the safety net
// against XSS in the SSE audit stream.
// ============================================================================

func TestSSE_HTMLEscaping(t *testing.T) {
	xssPayload := "<script>alert('xss')</script>"

	// Create audit records with XSS payloads in various fields.
	records := []audit.AuditRecord{
		{
			Timestamp:  time.Now().UTC(),
			SessionID:  "sess-xss",
			IdentityID: "user-xss",
			ToolName:   xssPayload,
			Decision:   "allow",
			Reason:     "test " + xssPayload,
			RuleID:     "rule-xss",
			RequestID:  "req-xss",
			Protocol:   "mcp",
		},
	}

	reader := &mockAuditReader{records: records}
	h := NewAdminAPIHandler(WithAuditReader(reader))

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit/stream", nil)
	// Cancel context immediately so the SSE loop exits after the initial batch.
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.handleAuditStream(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body := rec.Body.String()

	// The SSE body must contain data lines (sanity check).
	if !strings.Contains(body, "data: ") {
		t.Fatal("SSE body should contain 'data: ' lines with audit records")
	}

	// Critical assertion: raw <script> tags must NOT appear in the SSE output.
	// Go's json.Marshal escapes < to \u003c and > to \u003e, so the raw
	// HTML tag should never be present.
	if strings.Contains(body, "<script>") {
		t.Errorf("SSE output contains raw <script> tag — XSS vulnerability!\nBody excerpt: %s",
			truncate(body, 500))
	}
	if strings.Contains(body, "</script>") {
		t.Errorf("SSE output contains raw </script> tag — XSS vulnerability!\nBody excerpt: %s",
			truncate(body, 500))
	}

	// Verify the escaped form IS present (confirming JSON encoding did its job).
	if !strings.Contains(body, `\u003cscript\u003e`) {
		t.Errorf("SSE output should contain JSON-escaped \\u003cscript\\u003e but doesn't.\nBody: %s",
			truncate(body, 500))
	}

	// Document the safety mechanism.
	t.Logf("SSE audit stream uses json.Marshal which escapes < and > to Unicode sequences.")
	t.Logf("This provides inherent XSS protection: raw HTML tags cannot appear in the SSE data.")
}

// truncate returns the first n characters of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ============================================================================
// 3D.5: TestAdminAPI_NotAccessibleRemotely
// Verifies that admin API endpoints reject requests from non-localhost
// addresses with HTTP 403 Forbidden. The admin auth middleware must enforce
// localhost-only access regardless of the HTTP method or endpoint path.
//
// This is a critical security boundary: the admin API controls policies,
// identities, API keys, and system configuration. Remote access without
// an SSH tunnel must be denied.
// ============================================================================

func TestAdminAPI_NotAccessibleRemotely(t *testing.T) {
	handler := NewAdminAPIHandler(WithAPILogger(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	))
	mux := handler.Routes()

	// Representative set of admin API endpoints covering different HTTP
	// methods and functional areas (CRUD, security, system info).
	endpoints := []struct {
		method string
		path   string
		desc   string
	}{
		{http.MethodGet, "/admin/api/policies", "list policies"},
		{http.MethodPost, "/admin/api/identities", "create identity"},
		{http.MethodGet, "/admin/api/upstreams", "list upstreams"},
		{http.MethodDelete, "/admin/api/policies/test-id", "delete policy"},
		{http.MethodGet, "/admin/api/tools", "list tools"},
		{http.MethodGet, "/admin/api/keys", "list API keys"},
		{http.MethodGet, "/admin/api/stats", "get stats"},
		{http.MethodGet, "/admin/api/system", "system info"},
		{http.MethodGet, "/admin/api/audit", "query audit logs"},
		{http.MethodGet, "/admin/api/v1/security/content-scanning", "content scanning config"},
		{http.MethodGet, "/admin/api/v1/approvals", "list approvals"},
		{http.MethodPost, "/admin/api/v1/redteam/run", "run red team"},
	}

	// Remote addresses that must be rejected.
	remoteAddrs := []struct {
		addr string
		desc string
	}{
		{"10.0.0.1:1234", "private network (10.x)"},
		{"192.168.1.100:5555", "private network (192.168.x)"},
		{"8.8.8.8:443", "public IP (Google DNS)"},
		{"172.16.0.1:8080", "private network (172.16.x)"},
		{"[2001:db8::1]:1234", "IPv6 non-loopback"},
		{"203.0.113.42:9999", "TEST-NET-3 (documentation IP)"},
	}

	for _, ep := range endpoints {
		for _, ra := range remoteAddrs {
			name := ep.method + "_" + ep.desc + "_from_" + ra.desc
			t.Run(name, func(t *testing.T) {
				req := httptest.NewRequest(ep.method, ep.path, nil)
				req.RemoteAddr = ra.addr

				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)

				if rec.Code != http.StatusForbidden {
					t.Errorf("%s %s from %s: got status %d, want %d (403 Forbidden)",
						ep.method, ep.path, ra.addr, rec.Code, http.StatusForbidden)
				}

				// Verify the error message does not leak internal details.
				body := rec.Body.String()
				if strings.Contains(body, "stack") || strings.Contains(body, "goroutine") ||
					strings.Contains(body, "panic") || strings.Contains(body, "runtime") {
					t.Errorf("403 response body contains internal details: %s", truncate(body, 200))
				}
			})
		}
	}

	// Verify that localhost requests ARE accepted (sanity check).
	t.Run("localhost_accepted_sanity_check", func(t *testing.T) {
		localAddrs := []string{"127.0.0.1:1234", "[::1]:1234"}
		for _, addr := range localAddrs {
			req := httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil)
			req.RemoteAddr = addr

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			// Any status other than 403 means the auth middleware passed.
			// The actual handler may return 200, 404, 500, etc. depending
			// on missing dependencies — that is fine; what matters is that
			// the auth middleware did not block it.
			if rec.Code == http.StatusForbidden {
				t.Errorf("localhost request from %s was rejected with 403 (should be allowed)", addr)
			}
		}
	})

	// Verify that X-Forwarded-For spoofing does NOT bypass the middleware
	// when no trusted proxies are configured.
	t.Run("xff_spoofing_rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/api/policies", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "127.0.0.1")

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("XFF spoofing bypass: got status %d, want 403", rec.Code)
		}
	})
}
