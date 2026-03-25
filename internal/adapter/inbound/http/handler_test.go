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
// returns HTTP 415 Unsupported Media Type with JSON-RPC error -32700.
func TestHandlePost_InvalidContentType(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"test","id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()

	handlePost(rec, req, nil, nil)

	// M-17: Content-Type errors now return HTTP 200 with JSON-RPC error for consistency
	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d (JSON-RPC error over HTTP 200)", rec.Code, http.StatusOK)
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

	handlePost(rec, req, nil, nil)

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

	handlePost(rec, req, nil, nil)

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

	handlePost(rec, req, nil, nil)

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

	handlePost(rec, req, nil, nil)

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

	handlePost(rec, req, nil, nil)

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

	handlePost(rec, req, nil, nil)

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
// returns HTTP 415 Unsupported Media Type (L-11).
func TestHandlePost_NoContentType(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"test","id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	// No Content-Type header set
	rec := httptest.NewRecorder()

	handlePost(rec, req, nil, nil)

	// M-17: Missing Content-Type now returns HTTP 200 with JSON-RPC error for consistency
	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d (JSON-RPC error over HTTP 200)", rec.Code, http.StatusOK)
	}

	code, msg := parseJSONRPCError(t, rec.Body.Bytes())
	if code != -32700 {
		t.Errorf("error code = %d, want -32700", code)
	}
	if !strings.Contains(msg, "Content-Type") {
		t.Errorf("error message = %q, want it to contain 'Content-Type'", msg)
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

	// M-27: handleDelete now returns JSON-RPC errors (HTTP 200) for MCP consistency
	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d (JSON-RPC error over HTTP 200)", rec.Code, http.StatusOK)
	}

	if !strings.Contains(rec.Body.String(), "Mcp-Session-Id") {
		t.Errorf("response body = %q, want it to mention Mcp-Session-Id", rec.Body.String())
	}
}

// TestHandleDelete_UnknownSession verifies that DELETE with unknown session ID
// returns HTTP 404 Not Found per MCP spec.
func TestHandleDelete_UnknownSession(t *testing.T) {
	registry := newSessionRegistry()
	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set(MCPSessionIDHeader, "nonexistent-session-id")
	rec := httptest.NewRecorder()

	handleDelete(rec, req, registry)

	// MCP spec: unknown session → HTTP 404
	if rec.Code != http.StatusNotFound {
		t.Errorf("status code = %d, want %d (HTTP 404 for unknown session)", rec.Code, http.StatusNotFound)
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

			handlePost(rec, req, nil, nil)

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

			handlePost(rec, req, nil, nil)

			// M-17: Content-Type errors now return HTTP 200 with JSON-RPC error
			if rec.Code != http.StatusOK {
				t.Errorf("status code = %d, want %d for Content-Type %q", rec.Code, http.StatusOK, ct)
			}
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

	registry.register("session-1", ch1, "")
	registry.register("session-1", ch2, "")

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

	registry.register("sess-a", ch1, "")
	registry.register("sess-b", ch2, "")

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
	reg.register("session-1", ch1, "")
	reg.register("session-2", ch2, "")

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
	reg.register("session-1", ch, "")

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
	reg.register("session-1", ch1, "")
	reg.register("session-1", ch2, "")

	msg := []byte(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`)
	reg.broadcast(msg)

	// MCP spec: "MUST send each JSON-RPC message on only one of the
	// connected streams" — exactly ONE channel should receive the message.
	received := 0
	select {
	case <-ch1:
		received++
	default:
	}
	select {
	case <-ch2:
		received++
	default:
	}

	if received != 1 {
		t.Errorf("broadcast delivered to %d channels, want exactly 1", received)
	}

	reg.unregister("session-1", ch1)
	reg.unregister("session-1", ch2)
}

// --- handleGet SSE tests ---

func TestHandleGet_SSEHeaders(t *testing.T) {
	registry := newSessionRegistry()
	registry.preRegisterOwner("test-sse-session", "") // unauthenticated mode

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
	registry.register("del-session", ch, "")

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

// --- Wave 1: Auth & Discovery tests ---

func TestIsAuthErrorResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantAuth bool
	}{
		{"auth required", `{"jsonrpc":"2.0","error":{"code":-32600,"message":"Authentication required"},"id":1}`, true},
		{"invalid key", `{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid API key"},"id":1}`, true},
		{"session expired", `{"jsonrpc":"2.0","error":{"code":-32600,"message":"Session expired"},"id":1}`, true},
		{"policy denied", `{"jsonrpc":"2.0","error":{"code":-32600,"message":"Access denied by policy"},"id":1}`, false},
		{"success response", `{"jsonrpc":"2.0","result":{},"id":1}`, false},
		{"empty", ``, false},
		{"invalid json", `not json`, false},
		{"null error", `{"jsonrpc":"2.0","error":null,"id":1}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAuthErrorResponse([]byte(tt.input))
			if got != tt.wantAuth {
				t.Errorf("isAuthErrorResponse(%q) = %v, want %v", tt.input, got, tt.wantAuth)
			}
		})
	}
}

func TestWellKnownProtectedResource(t *testing.T) {
	mux := http.NewServeMux()
	// Register the same handler that transport.go registers
	mux.Handle("/.well-known/oauth-protected-resource", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeJSONError(w, http.StatusMethodNotAllowed, "Method Not Allowed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]interface{}{
			"resource":                 "http://" + r.Host + "/mcp",
			"bearer_methods_supported": []string{"header"},
			"scopes_supported":         []string{},
			"resource_name":            "SentinelGate MCP Proxy",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	mux.Handle("/.well-known/", http.NotFoundHandler())

	t.Run("GET returns metadata", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		req.Host = "localhost:8080"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.Contains(ct, "application/json") {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		var meta map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if meta["resource"] != "http://localhost:8080/mcp" {
			t.Errorf("resource = %v, want http://localhost:8080/mcp", meta["resource"])
		}
		bearerMethods, ok := meta["bearer_methods_supported"].([]interface{})
		if !ok || len(bearerMethods) != 1 || bearerMethods[0] != "header" {
			t.Errorf("bearer_methods_supported = %v, want [header]", meta["bearer_methods_supported"])
		}
		if _, hasAuthServers := meta["authorization_servers"]; hasAuthServers {
			t.Error("authorization_servers should NOT be present (Bearer only)")
		}
	})

	t.Run("POST returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rec.Code)
		}
	})

	t.Run("other well-known returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rec.Code)
		}
	})
}

func TestHandlePost_AuthError_WithSSEAccept_Returns401NotSSE(t *testing.T) {
	// Verify that isAuthErrorResponse correctly detects auth errors
	// that would be promoted to HTTP 401 (not SSE)
	authErrorBody := `{"jsonrpc":"2.0","error":{"code":-32600,"message":"Authentication required"},"id":1}`
	response := []byte(authErrorBody)

	if !isAuthErrorResponse(response) {
		t.Fatal("precondition: isAuthErrorResponse should return true")
	}
	// The early-return in handlePost occurs BEFORE the Accept SSE check (line ~482),
	// so an auth error never enters the SSE branch.
}

// --- Wave 2: Session Management tests ---

func TestSessionExists(t *testing.T) {
	registry := newSessionRegistry()

	if registry.sessionExists("nonexistent") {
		t.Error("sessionExists should return false for unknown session")
	}

	ch := make(chan []byte, 10)
	registry.register("existing", ch, "owner")

	if !registry.sessionExists("existing") {
		t.Error("sessionExists should return true for registered session")
	}

	registry.terminate("existing")

	if registry.sessionExists("existing") {
		t.Error("sessionExists should return false after termination")
	}
}

func TestHandleGet_UnknownSession_Returns404(t *testing.T) {
	registry := newSessionRegistry()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set(MCPSessionIDHeader, "nonexistent-session-id")
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()

	handleGet(rec, req, registry)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for unknown session", rec.Code)
	}
}

func TestHandleDelete_UnknownSession_Returns404(t *testing.T) {
	registry := newSessionRegistry()
	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set(MCPSessionIDHeader, "nonexistent-session-id")
	rec := httptest.NewRecorder()

	handleDelete(rec, req, registry)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for unknown session", rec.Code)
	}
}

func TestHandleGet_WrongOwner_Returns403(t *testing.T) {
	registry := newSessionRegistry()
	// Register session with owner "hash-A"
	ch := make(chan []byte, 10)
	registry.register("my-session", ch, "hash-A")
	defer registry.unregister("my-session", ch)

	// Request from different owner (no Authorization → ownerHash "" ≠ "hash-A")
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set(MCPSessionIDHeader, "my-session")
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()

	handleGet(rec, req, registry)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for wrong owner", rec.Code)
	}
}

func TestHandleDelete_ThenGet_Returns404(t *testing.T) {
	registry := newSessionRegistry()
	ch := make(chan []byte, 10)
	registry.register("doomed-session", ch, "owner-hash")

	// Terminate the session
	registry.terminate("doomed-session")

	// Try GET on terminated session
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set(MCPSessionIDHeader, "doomed-session")
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()

	handleGet(rec, req, registry)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for terminated session", rec.Code)
	}
}

func TestHandleGet_WrongOwner_ExistingSession_Returns403Not404(t *testing.T) {
	registry := newSessionRegistry()
	ch := make(chan []byte, 10)
	registry.register("owned-session", ch, "correct-hash")
	defer registry.unregister("owned-session", ch)

	// Request with wrong owner hash
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set(MCPSessionIDHeader, "owned-session")
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()

	handleGet(rec, req, registry)

	// Session exists but wrong owner → 403, not 404
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (session exists, wrong owner)", rec.Code)
	}
}

// --- Wave 3: Protocol Compliance tests ---

func TestHandlePost_UnsupportedProtocolVersion_Returns400(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"initialize","id":1,"params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(MCPProtocolVersionHeader, "9999-01-01")
	rec := httptest.NewRecorder()

	handlePost(rec, req, nil, nil)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for unsupported protocol version", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Unsupported MCP protocol version") {
		t.Errorf("body = %q, want protocol version error", rec.Body.String())
	}
}

func TestHandlePost_SupportedProtocolVersion_Continues(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"ping","id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(MCPProtocolVersionHeader, MCPProtocolVersion)
	// Set unknown session ID so the request fails with 404 BEFORE reaching
	// proxyService.Run() (which would panic with nil proxyService).
	req.Header.Set(MCPSessionIDHeader, "nonexistent-session")
	rec := httptest.NewRecorder()
	registry := newSessionRegistry()

	handlePost(rec, req, nil, registry)

	// If version were rejected, we'd get 400. We expect 404 (unknown session)
	// which proves the version check passed.
	if rec.Code == http.StatusBadRequest {
		t.Errorf("supported version should not return 400, got %d", rec.Code)
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 (unknown session after version pass), got %d", rec.Code)
	}
}

func TestHandlePost_NoProtocolVersion_Continues(t *testing.T) {
	body := `{"jsonrpc":"2.0","method":"ping","id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// NO MCP-Protocol-Version header
	req.Header.Set(MCPSessionIDHeader, "nonexistent-session")
	rec := httptest.NewRecorder()
	registry := newSessionRegistry()

	handlePost(rec, req, nil, registry)

	if rec.Code == http.StatusBadRequest {
		t.Errorf("missing version should not return 400 (backward compat)")
	}
}

func TestHandleGet_UnsupportedProtocolVersion_Returns400(t *testing.T) {
	registry := newSessionRegistry()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set(MCPProtocolVersionHeader, "9999-01-01")
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()

	handleGet(rec, req, registry)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for unsupported protocol version in GET", rec.Code)
	}
}

func TestBroadcast_SendsToOneStreamPerSession(t *testing.T) {
	registry := newSessionRegistry()

	// Session with 3 SSE channels
	ch1 := make(chan []byte, 10)
	ch2 := make(chan []byte, 10)
	ch3 := make(chan []byte, 10)
	registry.register("session-A", ch1, "owner-hash-A")
	registry.register("session-A", ch2, "owner-hash-A")
	registry.register("session-A", ch3, "owner-hash-A")

	registry.broadcast([]byte(`{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`))

	// Exactly ONE channel should receive
	received := 0
	select {
	case <-ch1:
		received++
	default:
	}
	select {
	case <-ch2:
		received++
	default:
	}
	select {
	case <-ch3:
		received++
	default:
	}

	if received != 1 {
		t.Errorf("broadcast delivered to %d channels, want exactly 1", received)
	}

	registry.unregister("session-A", ch1)
	registry.unregister("session-A", ch2)
	registry.unregister("session-A", ch3)
}

func TestBroadcast_MultipleSessionsEachGetOne(t *testing.T) {
	registry := newSessionRegistry()

	chA := make(chan []byte, 10)
	chB := make(chan []byte, 10)
	registry.register("session-A", chA, "owner-A")
	registry.register("session-B", chB, "owner-B")

	registry.broadcast([]byte(`{"method":"notifications/tools/list_changed"}`))

	// Both sessions should receive (once each)
	select {
	case <-chA:
		// OK
	default:
		t.Error("session-A should have received the broadcast")
	}
	select {
	case <-chB:
		// OK
	default:
		t.Error("session-B should have received the broadcast")
	}

	registry.unregister("session-A", chA)
	registry.unregister("session-B", chB)
}
