package http

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// --- handleOptions tests ---

func TestHandleOptions_CORSHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/mcp", nil)
	rec := httptest.NewRecorder()

	handleOptions(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Access-Control-Allow-Methods header should be set")
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Error("Access-Control-Allow-Headers header should be set")
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "86400" {
		t.Errorf("Access-Control-Max-Age = %q, want %q", got, "86400")
	}
}

// --- filterResponseByID tests ---

func TestFilterResponseByID_SingleMatch(t *testing.T) {
	buffer := []byte(`{"jsonrpc":"2.0","id":1,"result":"ok"}`)
	expectedID := []byte(`1`)

	result := filterResponseByID(buffer, expectedID)
	if !bytes.Equal(result, buffer) {
		t.Errorf("single matching object should return as-is: got %q, want %q", result, buffer)
	}
}

func TestFilterResponseByID_SingleNoMatch(t *testing.T) {
	buffer := []byte(`{"jsonrpc":"2.0","id":2,"result":"ok"}`)
	expectedID := []byte(`1`)

	result := filterResponseByID(buffer, expectedID)
	// Falls through to slow path, no match found, returns first non-empty line
	if len(result) == 0 {
		t.Error("should return something even if no ID match")
	}
}

func TestFilterResponseByID_MultipleLines_MatchSecond(t *testing.T) {
	line1 := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":50}}`
	line2 := `{"jsonrpc":"2.0","id":42,"result":"done"}`
	buffer := []byte(line1 + "\n" + line2)
	expectedID := []byte(`42`)

	result := filterResponseByID(buffer, expectedID)
	if string(result) != line2 {
		t.Errorf("should extract matching line: got %q, want %q", result, line2)
	}
}

func TestFilterResponseByID_EmptyBuffer(t *testing.T) {
	buffer := []byte("")
	expectedID := []byte(`1`)

	result := filterResponseByID(buffer, expectedID)
	if !bytes.Equal(result, buffer) {
		t.Errorf("empty buffer should return empty: got %q", result)
	}
}

func TestFilterResponseByID_FallbackFirstLine(t *testing.T) {
	line1 := `{"jsonrpc":"2.0","id":99,"result":"first"}`
	line2 := `{"jsonrpc":"2.0","id":100,"result":"second"}`
	buffer := []byte(line1 + "\n" + line2)
	expectedID := []byte(`999`) // no match

	result := filterResponseByID(buffer, expectedID)
	if string(result) != line1 {
		t.Errorf("should fall back to first non-empty line: got %q, want %q", result, line1)
	}
}

// --- sessionRegistry tests ---

func TestSessionRegistry_RegisterUnregister(t *testing.T) {
	registry := newSessionRegistry()
	ch1 := make(chan []byte, 1)
	ch2 := make(chan []byte, 1)

	registry.register("session-1", ch1)
	registry.register("session-1", ch2)

	// Both channels should be registered
	registry.mu.RLock()
	if len(registry.sessions["session-1"]) != 2 {
		t.Errorf("expected 2 channels, got %d", len(registry.sessions["session-1"]))
	}
	registry.mu.RUnlock()

	// Unregister ch1
	registry.unregister("session-1", ch1)

	registry.mu.RLock()
	if len(registry.sessions["session-1"]) != 1 {
		t.Errorf("expected 1 channel after unregister, got %d", len(registry.sessions["session-1"]))
	}
	registry.mu.RUnlock()

	// Unregister ch2 (last one should remove session entry)
	registry.unregister("session-1", ch2)

	registry.mu.RLock()
	if _, exists := registry.sessions["session-1"]; exists {
		t.Error("session entry should be deleted when last channel is unregistered")
	}
	registry.mu.RUnlock()
}

func TestSessionRegistry_CloseAll(t *testing.T) {
	registry := newSessionRegistry()
	ch1 := make(chan []byte, 1)
	ch2 := make(chan []byte, 1)

	registry.register("sess-a", ch1)
	registry.register("sess-b", ch2)

	registry.closeAll()

	// Channels should be closed
	select {
	case _, ok := <-ch1:
		if ok {
			t.Error("ch1 should be closed")
		}
	default:
		t.Error("ch1 should be readable (closed)")
	}

	select {
	case _, ok := <-ch2:
		if ok {
			t.Error("ch2 should be closed")
		}
	default:
		t.Error("ch2 should be readable (closed)")
	}

	registry.mu.RLock()
	if len(registry.sessions) != 0 {
		t.Errorf("sessions map should be empty after closeAll, got %d entries", len(registry.sessions))
	}
	registry.mu.RUnlock()
}

// --- mcpHandler routing tests ---

func TestMCPHandler_OptionsRoute(t *testing.T) {
	registry := newSessionRegistry()
	handler := mcpHandler(nil, registry)

	req := httptest.NewRequest(http.MethodOptions, "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("OPTIONS status code = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

// --- healthHandler test ---

func TestHealthHandler_ReturnsOK(t *testing.T) {
	handler := healthHandler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	if body := rec.Body.String(); body != `{"status":"ok"}` {
		t.Errorf("body = %q, want %q", body, `{"status":"ok"}`)
	}
}

// --- broadcast tests ---

func TestSessionRegistryBroadcast(t *testing.T) {
	reg := newSessionRegistry()

	// Register two sessions with one channel each
	ch1 := make(chan []byte, 10)
	ch2 := make(chan []byte, 10)
	reg.register("session-1", ch1)
	reg.register("session-2", ch2)

	// Broadcast a message
	msg := []byte(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`)
	reg.broadcast(msg)

	// Both channels should receive the message
	select {
	case got := <-ch1:
		if string(got) != string(msg) {
			t.Errorf("ch1: got %s, want %s", got, msg)
		}
	case <-time.After(time.Second):
		t.Error("ch1: timeout waiting for broadcast")
	}

	select {
	case got := <-ch2:
		if string(got) != string(msg) {
			t.Errorf("ch2: got %s, want %s", got, msg)
		}
	case <-time.After(time.Second):
		t.Error("ch2: timeout waiting for broadcast")
	}

	// Cleanup
	reg.unregister("session-1", ch1)
	reg.unregister("session-2", ch2)
}

func TestSessionRegistryBroadcastEmpty(t *testing.T) {
	reg := newSessionRegistry()
	// Should not panic with no sessions
	reg.broadcast([]byte(`{"test":"ok"}`))
}

func TestSessionRegistryBroadcastFullChannel(t *testing.T) {
	reg := newSessionRegistry()
	ch := make(chan []byte, 1)
	reg.register("session-1", ch)

	// Fill the channel
	ch <- []byte("filler")

	// Broadcast should not block even with full channel
	done := make(chan bool)
	go func() {
		reg.broadcast([]byte(`{"test":"ok"}`))
		done <- true
	}()

	select {
	case <-done:
		// OK - broadcast completed without blocking
	case <-time.After(time.Second):
		t.Error("broadcast blocked on full channel")
	}

	reg.unregister("session-1", ch)
}

func TestSessionRegistryBroadcastMultipleChannelsPerSession(t *testing.T) {
	reg := newSessionRegistry()
	ch1 := make(chan []byte, 10)
	ch2 := make(chan []byte, 10)
	// Both channels on the same session
	reg.register("session-1", ch1)
	reg.register("session-1", ch2)

	msg := []byte(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`)
	reg.broadcast(msg)

	// Both channels should receive the message
	select {
	case got := <-ch1:
		if string(got) != string(msg) {
			t.Errorf("ch1: got %s, want %s", got, msg)
		}
	case <-time.After(time.Second):
		t.Error("ch1: timeout waiting for broadcast")
	}

	select {
	case got := <-ch2:
		if string(got) != string(msg) {
			t.Errorf("ch2: got %s, want %s", got, msg)
		}
	case <-time.After(time.Second):
		t.Error("ch2: timeout waiting for broadcast")
	}

	reg.unregister("session-1", ch1)
	reg.unregister("session-1", ch2)
}

// --- handleGet SSE tests ---

func TestHandleGet_SSEHeaders(t *testing.T) {
	registry := newSessionRegistry()

	// Use a timeout context to stop the SSE handler's event loop.
	// WithTimeout ensures the test never hangs even if cancellation
	// doesn't propagate through httptest.ResponseRecorder.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req = req.WithContext(ctx)
	req.Header.Set(MCPSessionIDHeader, "test-sse-session")
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleGet(rec, req, registry)
	}()

	// Give the handler a moment to set headers and write the initial comment,
	// then cancel context to stop the event loop.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleGet did not exit after context cancellation")
	}

	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
	if conn := rec.Header().Get("Connection"); conn != "keep-alive" {
		t.Errorf("Connection = %q, want keep-alive", conn)
	}
	if sid := rec.Header().Get(MCPSessionIDHeader); sid != "test-sse-session" {
		t.Errorf("Mcp-Session-Id = %q, want test-sse-session", sid)
	}
}

// --- handleDelete tests ---

func TestHandleDelete_Success(t *testing.T) {
	registry := newSessionRegistry()
	ch := make(chan []byte, 1)
	registry.register("del-session", ch)

	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set(MCPSessionIDHeader, "del-session")
	rec := httptest.NewRecorder()

	handleDelete(rec, req, registry)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusNoContent)
	}

	// Channel should have been closed
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("channel should be closed after delete")
		}
	default:
		t.Error("channel should be readable (closed) after delete")
	}
}
