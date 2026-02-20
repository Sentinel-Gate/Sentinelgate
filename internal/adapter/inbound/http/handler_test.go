package http

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// parseJSONRPCError is a test helper that parses a JSON-RPC error response body
// and returns the error code and message. It fails the test if parsing fails.
func parseJSONRPCError(t *testing.T, body []byte) (code int, message string) {
	t.Helper()
	var resp jsonRPCError
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to parse JSON-RPC error response: %v\nbody: %s", err, body)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc=2.0, got %q", resp.JSONRPC)
	}
	return resp.Error.Code, resp.Error.Message
}

// TestHandlePost_InvalidContentType verifies that POST with wrong Content-Type
// returns JSON-RPC error -32700.
func TestHandlePost_InvalidContentType(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"test","id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()

	handlePost(rec, req, nil)

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d (JSON-RPC errors return 200)", rec.Code, http.StatusOK)
	}

	code, msg := parseJSONRPCError(t, rec.Body.Bytes())
	if code != -32700 {
		t.Errorf("error code = %d, want -32700", code)
	}
	if !strings.Contains(msg, "content type must be application/json") {
		t.Errorf("error message = %q, want it to contain 'content type must be application/json'", msg)
	}
}

// TestHandlePost_EmptyBody verifies that POST with empty body
// returns JSON-RPC error -32700.
func TestHandlePost_EmptyBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlePost(rec, req, nil)

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	code, msg := parseJSONRPCError(t, rec.Body.Bytes())
	if code != -32700 {
		t.Errorf("error code = %d, want -32700", code)
	}
	if !strings.Contains(msg, "empty request body") {
		t.Errorf("error message = %q, want it to contain 'empty request body'", msg)
	}
}

// TestHandlePost_InvalidJSON verifies that POST with invalid JSON
// returns JSON-RPC error -32700.
func TestHandlePost_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{not valid json}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlePost(rec, req, nil)

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	code, msg := parseJSONRPCError(t, rec.Body.Bytes())
	if code != -32700 {
		t.Errorf("error code = %d, want -32700", code)
	}
	if !strings.Contains(msg, "invalid JSON") {
		t.Errorf("error message = %q, want it to contain 'invalid JSON'", msg)
	}
}

// TestHandlePost_OversizedPayload verifies that POST with body > 1MB
// returns JSON-RPC error -32700 before reading full body.
func TestHandlePost_OversizedPayload(t *testing.T) {
	// Create a body that exceeds 1MB
	oversized := bytes.Repeat([]byte("a"), maxRequestBodySize+1)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlePost(rec, req, nil)

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	code, msg := parseJSONRPCError(t, rec.Body.Bytes())
	if code != -32700 {
		t.Errorf("error code = %d, want -32700", code)
	}
	if !strings.Contains(msg, "too large") {
		t.Errorf("error message = %q, want it to contain 'too large'", msg)
	}
}

// TestHandlePost_MissingJsonrpcVersion verifies that POST with missing jsonrpc field
// returns JSON-RPC error -32600 (Invalid Request).
func TestHandlePost_MissingJsonrpcVersion(t *testing.T) {
	body := `{"method":"test","id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlePost(rec, req, nil)

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	code, msg := parseJSONRPCError(t, rec.Body.Bytes())
	if code != -32600 {
		t.Errorf("error code = %d, want -32600", code)
	}
	if !strings.Contains(msg, "jsonrpc") {
		t.Errorf("error message = %q, want it to contain 'jsonrpc'", msg)
	}
}

// TestHandlePost_MissingMethod verifies that POST with missing method field
// returns JSON-RPC error -32600 (Invalid Request).
func TestHandlePost_MissingMethod(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlePost(rec, req, nil)

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	code, msg := parseJSONRPCError(t, rec.Body.Bytes())
	if code != -32600 {
		t.Errorf("error code = %d, want -32600", code)
	}
	if !strings.Contains(msg, "method") {
		t.Errorf("error message = %q, want it to contain 'method'", msg)
	}
}

// TestHandlePost_WrongJsonrpcVersion verifies that POST with wrong jsonrpc version
// returns JSON-RPC error -32600 (Invalid Request).
func TestHandlePost_WrongJsonrpcVersion(t *testing.T) {
	body := `{"jsonrpc":"1.0","method":"test","id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlePost(rec, req, nil)

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	code, msg := parseJSONRPCError(t, rec.Body.Bytes())
	if code != -32600 {
		t.Errorf("error code = %d, want -32600", code)
	}
	if !strings.Contains(msg, "jsonrpc") {
		t.Errorf("error message = %q, want it to contain 'jsonrpc'", msg)
	}
}

// TestHandlePost_NoContentType verifies that POST with no Content-Type header
// is accepted (for flexibility with MCP clients that may not set it).
func TestHandlePost_NoContentType(t *testing.T) {
	// This test only checks that the handler doesn't reject on Content-Type.
	// It will fail at proxyService.Run since we pass nil, but that's after
	// all our validation checks pass.
	body := `{"jsonrpc":"2.0","method":"test","id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	// No Content-Type header set
	rec := httptest.NewRecorder()

	// This will panic/nil-pointer at proxyService.Run since proxyService is nil,
	// but we need to verify that validation passes first.
	// Use a recover to catch the nil pointer dereference.
	func() {
		defer func() {
			_ = recover() // Expected: nil proxyService causes panic after validation passes.
		}()
		handlePost(rec, req, nil)
	}()

	// If we get a JSON-RPC error response, check it's NOT a content-type error
	if rec.Body.Len() > 0 {
		var resp jsonRPCError
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err == nil {
			if resp.Error.Code == -32700 && strings.Contains(resp.Error.Message, "content type") {
				t.Error("empty Content-Type should be accepted, but got content-type error")
			}
		}
	}
}

// TestHandleGet_MissingSessionID verifies that GET without Mcp-Session-Id header
// returns 400 Bad Request.
func TestHandleGet_MissingSessionID(t *testing.T) {
	registry := newSessionRegistry()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()

	handleGet(rec, req, registry)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	if !strings.Contains(rec.Body.String(), "Mcp-Session-Id") {
		t.Errorf("response body = %q, want it to mention Mcp-Session-Id", rec.Body.String())
	}
}

// TestHandleDelete_MissingSessionID verifies that DELETE without Mcp-Session-Id header
// returns 400 Bad Request.
func TestHandleDelete_MissingSessionID(t *testing.T) {
	registry := newSessionRegistry()
	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	rec := httptest.NewRecorder()

	handleDelete(rec, req, registry)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	if !strings.Contains(rec.Body.String(), "Mcp-Session-Id") {
		t.Errorf("response body = %q, want it to mention Mcp-Session-Id", rec.Body.String())
	}
}

// TestHandleDelete_UnknownSession verifies that DELETE with unknown session ID
// returns 404 Not Found.
func TestHandleDelete_UnknownSession(t *testing.T) {
	registry := newSessionRegistry()
	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set(MCPSessionIDHeader, "nonexistent-session-id")
	rec := httptest.NewRecorder()

	handleDelete(rec, req, registry)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// TestMCPHandler_UnsupportedMethod verifies that non-allowed HTTP methods
// return 405 Method Not Allowed.
func TestMCPHandler_UnsupportedMethod(t *testing.T) {
	methods := []string{http.MethodPatch, http.MethodPut, http.MethodHead}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			registry := newSessionRegistry()
			handler := mcpHandler(nil, registry)

			req := httptest.NewRequest(method, "/mcp", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: status code = %d, want %d", method, rec.Code, http.StatusMethodNotAllowed)
			}
		})
	}
}

// TestHandlePost_ValidJSONNotObject verifies that a valid JSON value that is not
// an object (e.g., array, string, number) still passes JSON validation but fails
// the JSON-RPC field check since it won't have jsonrpc/method fields.
func TestHandlePost_ValidJSONNotObject(t *testing.T) {
	testCases := []struct {
		name string
		body string
	}{
		{"array", `[1,2,3]`},
		{"string", `"hello"`},
		{"number", `42`},
		{"boolean", `true`},
		{"null", `null`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handlePost(rec, req, nil)

			code, _ := parseJSONRPCError(t, rec.Body.Bytes())
			// Should get -32600 (Invalid Request) since jsonrpc/method are missing
			if code != -32600 {
				t.Errorf("error code = %d, want -32600 for non-object JSON", code)
			}
		})
	}
}

// TestHandlePost_MultipleContentTypes verifies that various non-JSON content types
// are all properly rejected.
func TestHandlePost_MultipleContentTypes(t *testing.T) {
	contentTypes := []string{
		"text/plain",
		"text/html",
		"application/xml",
		"multipart/form-data",
		"application/x-www-form-urlencoded",
	}

	body := `{"jsonrpc":"2.0","method":"test","id":1}`

	for _, ct := range contentTypes {
		t.Run(ct, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
			req.Header.Set("Content-Type", ct)
			rec := httptest.NewRecorder()

			handlePost(rec, req, nil)

			code, msg := parseJSONRPCError(t, rec.Body.Bytes())
			if code != -32700 {
				t.Errorf("error code = %d, want -32700 for Content-Type %q", code, ct)
			}
			if !strings.Contains(msg, "content type") {
				t.Errorf("error message = %q, want it to contain 'content type'", msg)
			}
		})
	}
}

// TestWriteJSONRPCError verifies the writeJSONRPCError helper produces
// correct JSON-RPC 2.0 error response format.
func TestWriteJSONRPCError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSONRPCError(rec, 42, -32600, "Invalid Request")

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d (JSON-RPC errors use 200)", rec.Code, http.StatusOK)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp jsonRPCError
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want 2.0", resp.JSONRPC)
	}
	// ID should be the number 42
	idFloat, ok := resp.ID.(float64)
	if !ok {
		t.Errorf("id type = %T, want float64 (JSON number)", resp.ID)
	} else if idFloat != 42 {
		t.Errorf("id = %v, want 42", idFloat)
	}
	if resp.Error.Code != -32600 {
		t.Errorf("error.code = %d, want -32600", resp.Error.Code)
	}
	if resp.Error.Message != "Invalid Request" {
		t.Errorf("error.message = %q, want 'Invalid Request'", resp.Error.Message)
	}
}

// TestWriteJSONRPCError_NilID verifies that writeJSONRPCError with nil ID
// produces JSON-RPC error with null id.
func TestWriteJSONRPCError_NilID(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSONRPCError(rec, nil, -32700, "Parse error")

	var resp jsonRPCError
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp.ID != nil {
		t.Errorf("id = %v, want nil", resp.ID)
	}
}
