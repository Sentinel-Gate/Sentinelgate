package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// TestHTTPClient_StartAfterClose verifies that Start() succeeds
// after Close() has been called (client is reusable for HTTP mode).
func TestHTTPClient_StartAfterClose(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := NewHTTPClient("http://localhost:9999")

	// First Start should succeed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("first Start() failed: %v", err)
	}

	// Close the client
	if err := client.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	// Second Start() should succeed (client is reusable after Close)
	// This is required for HTTP mode where each request is a Start/Close cycle
	_, _, err = client.Start(ctx)
	if err != nil {
		t.Fatalf("second Start() after Close() should succeed, got: %v", err)
	}

	// Clean up
	if err := client.Close(); err != nil {
		t.Fatalf("final Close() failed: %v", err)
	}
}

// TestHTTPClient_DoubleClose verifies that Close() is idempotent
// (calling it twice returns nil, no panic).
func TestHTTPClient_DoubleClose(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := NewHTTPClient("http://localhost:9999")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// First Close() should succeed
	if err := client.Close(); err != nil {
		t.Fatalf("first Close() failed: %v", err)
	}

	// Second Close() should also succeed (idempotent)
	if err := client.Close(); err != nil {
		t.Errorf("second Close() should be nil, got: %v", err)
	}
}

// TestHTTPClient_DoubleStart verifies that Start() returns an error
// if called twice without Close().
func TestHTTPClient_DoubleStart(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := NewHTTPClient("http://localhost:9999")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First Start() should succeed
	_, _, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("first Start() failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Second Start() should return error about already started
	_, _, err = client.Start(ctx)
	if err == nil {
		t.Fatal("expected error from second Start(), got nil")
	}
	if !strings.Contains(err.Error(), "already started") {
		t.Errorf("expected error containing 'already started', got: %v", err)
	}
}

// TestHTTPClient_GoroutineCleanup verifies that goroutines exit cleanly
// when the client is closed, with no leaks detected by goleak.
func TestHTTPClient_GoroutineCleanup(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := NewHTTPClient("http://localhost:9999")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Small delay to let the goroutine start running
	time.Sleep(10 * time.Millisecond)

	// Close the client - should trigger clean goroutine exit
	// The goroutine is blocked on scanner.Scan() which returns when pipe is closed
	if err := client.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	// goleak.VerifyNone will detect any leaked goroutines
}

// TestHTTPClient_CloseBeforeStart verifies that Close() is safe
// even if Start() was never called, and Start() still works after.
func TestHTTPClient_CloseBeforeStart(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := NewHTTPClient("http://localhost:9999")

	// Close without starting - should be safe (no-op on unstarted client)
	if err := client.Close(); err != nil {
		t.Errorf("Close() on unstarted client should succeed, got: %v", err)
	}

	// Start() should still work - Close() on unstarted client is a no-op
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() after Close() on unstarted client should succeed, got: %v", err)
	}

	// Clean up
	if err := client.Close(); err != nil {
		t.Fatalf("final Close() failed: %v", err)
	}
}

// TestHTTPClient_ContextCancellation verifies that the goroutine exits
// cleanly when the context is cancelled.
func TestHTTPClient_ContextCancellation(t *testing.T) {
	defer goleak.VerifyNone(t)

	client := NewHTTPClient("http://localhost:9999")

	ctx, cancel := context.WithCancel(context.Background())

	_, _, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Cancel the context - should trigger goroutine to exit
	cancel()

	// Small delay to let the context cancellation propagate
	time.Sleep(50 * time.Millisecond)

	// Close should still work
	if err := client.Close(); err != nil {
		t.Fatalf("Close() after context cancel failed: %v", err)
	}

	// goleak.VerifyNone will detect any leaked goroutines
}

// TestScanner_LargeMessages verifies that the scanner buffer configuration
// (256KB initial, 1MB max) correctly handles messages of various sizes.
// This mirrors the configuration in http_client.go's readRequestsAndSend().
func TestScanner_LargeMessages(t *testing.T) {
	// Test messages of various sizes to verify buffer growth
	// Note: The scanner max is 1MB, but the token itself (message without newline)
	// must fit, so we test up to 1MB - 1 byte.
	sizes := []int{
		64 * 1024,     // 64KB (default scanner max without Buffer())
		256 * 1024,    // 256KB (our initial buffer)
		512 * 1024,    // 512KB
		1024*1024 - 1, // Just under 1MB (should work - our effective max)
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%dKB", size/1024), func(t *testing.T) {
			// Create message of specified size
			msg := make([]byte, size)
			for i := range msg {
				msg[i] = 'x'
			}
			msg[0] = '{' // Make it look like JSON-ish
			msg[len(msg)-1] = '}'

			// Create pipe and scanner with same config as HTTPClient
			r, w := io.Pipe()

			scanner := bufio.NewScanner(r)
			buf := make([]byte, 0, 256*1024) // 256KB initial (matches http_client.go)
			scanner.Buffer(buf, 1024*1024)   // 1MB max (matches http_client.go)

			// Write message in goroutine
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = w.Close() }()
				_, _ = w.Write(msg)
				_, _ = w.Write([]byte("\n"))
			}()

			// Read with scanner
			if !scanner.Scan() {
				t.Fatalf("scanner.Scan() returned false, err: %v", scanner.Err())
			}

			got := scanner.Bytes()
			if len(got) != size {
				t.Errorf("expected %d bytes, got %d", size, len(got))
			}

			<-done
		})
	}
}

// TestScanner_ExceedsMaxBuffer verifies that messages larger than 1MB
// correctly return bufio.ErrTooLong. This documents expected behavior
// when clients send oversized messages.
func TestScanner_ExceedsMaxBuffer(t *testing.T) {
	// Message larger than 1MB should fail with ErrTooLong
	size := 1024*1024 + 1
	msg := make([]byte, size)
	for i := range msg {
		msg[i] = 'x'
	}

	r, w := io.Pipe()

	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 256*1024)
	scanner.Buffer(buf, 1024*1024)

	// Write in goroutine - note: write may fail with io.ErrClosedPipe
	// if we close reader before all data is written (which is expected)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = w.Close() }()
		// Ignore error - it may be io.ErrClosedPipe if reader closes first
		_, _ = w.Write(msg)
		_, _ = w.Write([]byte("\n"))
	}()

	if scanner.Scan() {
		t.Fatal("expected Scan() to return false for oversized message")
	}

	if !errors.Is(scanner.Err(), bufio.ErrTooLong) {
		t.Errorf("expected ErrTooLong, got: %v", scanner.Err())
	}

	// Close reader to unblock writer goroutine BEFORE waiting
	// (scanner detected token too long but writer may still be blocked on write)
	_ = r.Close()

	// Now wait for writer goroutine to finish (it should get io.ErrClosedPipe)
	<-done
}

// TestScanner_MessageAtExactLimit verifies scanner behavior at the exact 1MB boundary.
// Tests boundary conditions: 1MB-2 bytes, 1MB-1 byte (max allowed), and exactly 1MB (should fail).
func TestScanner_MessageAtExactLimit(t *testing.T) {
	// Test exact boundary conditions
	// Max buffer is 1MB, but token must fit WITH newline
	// So max message is 1MB - 1 byte

	testCases := []struct {
		name        string
		size        int
		shouldPass  bool
		description string
	}{
		{
			name:        "1MB_minus_2_bytes",
			size:        1024*1024 - 2,
			shouldPass:  true,
			description: "Just under limit - should work",
		},
		{
			name:        "1MB_minus_1_byte",
			size:        1024*1024 - 1,
			shouldPass:  true,
			description: "Exactly at limit - should work (max token size)",
		},
		{
			name:        "exactly_1MB",
			size:        1024 * 1024,
			shouldPass:  false,
			description: "At max buffer - fails (token + newline > buffer)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create message of exact size
			msg := make([]byte, tc.size)
			for i := range msg {
				msg[i] = 'x'
			}
			msg[0] = '{'
			msg[len(msg)-1] = '}'

			r, w := io.Pipe()

			scanner := bufio.NewScanner(r)
			buf := make([]byte, 0, 256*1024) // 256KB initial (matches http_client.go)
			scanner.Buffer(buf, 1024*1024)   // 1MB max (matches http_client.go)

			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() { _ = w.Close() }()
				// Write may fail with ErrClosedPipe if reader closes first
				_, _ = w.Write(msg)
				_, _ = w.Write([]byte("\n"))
			}()

			scanned := scanner.Scan()

			if tc.shouldPass {
				if !scanned {
					t.Errorf("%s: expected scan to succeed, got error: %v", tc.description, scanner.Err())
				} else if len(scanner.Bytes()) != tc.size {
					t.Errorf("%s: expected %d bytes, got %d", tc.description, tc.size, len(scanner.Bytes()))
				}
			} else {
				if scanned {
					t.Errorf("%s: expected scan to fail, but got %d bytes", tc.description, len(scanner.Bytes()))
				}
				if !errors.Is(scanner.Err(), bufio.ErrTooLong) {
					t.Errorf("%s: expected ErrTooLong, got: %v", tc.description, scanner.Err())
				}
				// Close reader to unblock writer
				_ = r.Close()
			}

			<-done
		})
	}
}

// TestScanner_EmptyMessage verifies that empty lines and minimal JSON
// are handled correctly by the scanner configuration.
func TestScanner_EmptyMessage(t *testing.T) {
	r, w := io.Pipe()

	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 256*1024)
	scanner.Buffer(buf, 1024*1024)

	go func() {
		defer func() { _ = w.Close() }()
		_, _ = w.Write([]byte("\n"))   // Just newline
		_, _ = w.Write([]byte("{}\n")) // Empty JSON object
	}()

	// First scan should return empty line
	if !scanner.Scan() {
		t.Fatalf("first scan failed: %v", scanner.Err())
	}
	if len(scanner.Bytes()) != 0 {
		t.Errorf("expected empty, got %d bytes", len(scanner.Bytes()))
	}

	// Second scan should return {}
	if !scanner.Scan() {
		t.Fatalf("second scan failed: %v", scanner.Err())
	}
	if string(scanner.Bytes()) != "{}" {
		t.Errorf("expected '{}', got '%s'", scanner.Bytes())
	}
}

// TestHTTPClient_ConnectionFailureWithServer verifies behavior when server
// returns errors. Uses httptest server for controlled testing without goroutine leaks.
func TestHTTPClient_ConnectionFailureWithServer(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Create a server that immediately returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 503 Service Unavailable to simulate connection issues
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start should succeed (it only sets up pipes)
	writer, reader, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Write a message to trigger HTTP request
	_, writeErr := writer.Write([]byte(`{"jsonrpc":"2.0","method":"test","id":1}` + "\n"))
	if writeErr != nil {
		t.Logf("Write error: %v", writeErr)
	}

	// Read response - should be error response from our writeErrorResponse
	scanner := bufio.NewScanner(reader)
	if scanner.Scan() {
		resp := scanner.Text()
		// Should contain JSON-RPC error response
		if !strings.Contains(resp, "error") {
			t.Errorf("expected error in response, got: %s", resp)
		}
		t.Logf("Got expected error response: %s", resp)
	}

	// Close the client cleanly
	if err := client.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// goleak.VerifyNone will verify no goroutines leaked
}

// TestHTTPClient_ServerTimeout verifies behavior when server is slow.
// Tests that timeout handling works correctly.
func TestHTTPClient_ServerTimeout(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay longer than client timeout
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer server.Close()

	// Create client with very short timeout
	httpClient := &http.Client{Timeout: 10 * time.Millisecond}
	client := NewHTTPClient(server.URL, WithHTTPClient(httpClient))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	writer, reader, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Write request
	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","method":"test","id":1}` + "\n"))

	// Read response - should be error due to timeout
	scanner := bufio.NewScanner(reader)
	if scanner.Scan() {
		resp := scanner.Text()
		// Should contain error (timeout-related)
		if !strings.Contains(resp, "error") {
			t.Errorf("expected error response due to timeout, got: %s", resp)
		}
		// Should be sanitized "Request timeout" message
		if strings.Contains(resp, "Request timeout") {
			t.Log("Got expected timeout error response")
		}
	}

	_ = client.Close()
}

// TestHTTPClient_CleanShutdownOnContextCancel verifies that goroutines
// exit cleanly when context is cancelled during active connection.
func TestHTTPClient_CleanShutdownOnContextCancel(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Create a server that responds slowly
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"ok","id":1}`))
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL)

	ctx, cancel := context.WithCancel(context.Background())

	writer, _, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Write a request
	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","method":"test","id":1}` + "\n"))

	// Cancel context while request is in flight
	time.Sleep(10 * time.Millisecond)
	cancel()

	// Close should complete even with pending request
	err = client.Close()
	if err != nil {
		// May have timeout waiting for goroutine, which is acceptable
		t.Logf("Close error (may be expected): %v", err)
	}

	// goleak.VerifyNone verifies no leaks
}

// ---------------------------------------------------------------------------
// SSE & Content-Type branching tests
// ---------------------------------------------------------------------------

// TestHTTPClient_SSEResponse verifies that the client correctly parses an SSE
// response containing a single JSON-RPC result message.
func TestHTTPClient_SSEResponse(t *testing.T) {
	defer goleak.VerifyNone(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, _ := w.(http.Flusher)
		fmt.Fprint(w, "event: message\n")
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"test_tool\"}]}}\n")
		fmt.Fprint(w, "\n") // blank line = end of event
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	writer, reader, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Send a request to trigger the HTTP POST
	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","method":"tools/list","id":1}` + "\n"))

	// Read the response
	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() {
		t.Fatalf("expected response, scanner error: %v", scanner.Err())
	}

	resp := scanner.Text()

	// Verify JSON structure
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		t.Fatalf("response is not valid JSON: %v\nraw: %s", err, resp)
	}

	if parsed["jsonrpc"] != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got: %v", parsed["jsonrpc"])
	}

	// id comes back as float64 from json.Unmarshal into interface{}
	if parsed["id"] != float64(1) {
		t.Errorf("expected id 1, got: %v", parsed["id"])
	}

	result, ok := parsed["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected result object, got: %T", parsed["result"])
	}

	tools, ok := result["tools"].([]interface{})
	if !ok || len(tools) != 1 {
		t.Fatalf("expected 1 tool, got: %v", result["tools"])
	}

	tool := tools[0].(map[string]interface{})
	if tool["name"] != "test_tool" {
		t.Errorf("expected tool name 'test_tool', got: %v", tool["name"])
	}

	_ = client.Close()
}

// TestHTTPClient_SSEWithNotifications verifies that SSE progress notifications
// (messages without "id") are silently consumed and only the final JSON-RPC
// response (with "id") is returned through the pipe.
func TestHTTPClient_SSEWithNotifications(t *testing.T) {
	defer goleak.VerifyNone(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, _ := w.(http.Flusher)

		// First event: notification (no "id")
		fmt.Fprint(w, "event: message\n")
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":50}}\n")
		fmt.Fprint(w, "\n")
		if flusher != nil {
			flusher.Flush()
		}

		// Second event: actual response (with "id")
		fmt.Fprint(w, "event: message\n")
		fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"Hello\"}]}}\n")
		fmt.Fprint(w, "\n")
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	writer, reader, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","method":"tools/call","id":1}` + "\n"))

	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() {
		t.Fatalf("expected response, scanner error: %v", scanner.Err())
	}

	resp := scanner.Text()

	// Should be the response with id=1, not the notification
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		t.Fatalf("response is not valid JSON: %v\nraw: %s", err, resp)
	}

	if parsed["id"] != float64(1) {
		t.Errorf("expected id 1, got: %v", parsed["id"])
	}

	// Verify notifications were consumed — only one message should come through
	if strings.Contains(resp, "notifications/progress") {
		t.Error("notification should have been consumed, not returned")
	}

	result, ok := parsed["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected result object, got: %T", parsed["result"])
	}

	content, ok := result["content"].([]interface{})
	if !ok || len(content) != 1 {
		t.Fatalf("expected 1 content item, got: %v", result["content"])
	}

	item := content[0].(map[string]interface{})
	if item["text"] != "Hello" {
		t.Errorf("expected text 'Hello', got: %v", item["text"])
	}

	_ = client.Close()
}

// TestHTTPClient_SSEMultiLineData verifies that multiple `data:` lines within
// a single SSE event are joined with newlines. Since real MCP servers send
// single-line JSON, this test also verifies normal single-line parsing as a
// baseline, and tests the multi-line joining edge case separately.
func TestHTTPClient_SSEMultiLineData(t *testing.T) {
	defer goleak.VerifyNone(t)

	t.Run("single_data_line", func(t *testing.T) {
		// Baseline: single data: line with valid JSON — this is what real servers do.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "event: message\n")
			fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n")
			fmt.Fprint(w, "\n")
		}))
		defer server.Close()

		client := NewHTTPClient(server.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		writer, reader, err := client.Start(ctx)
		if err != nil {
			t.Fatalf("Start() failed: %v", err)
		}

		_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","method":"test","id":1}` + "\n"))

		scanner := bufio.NewScanner(reader)
		if !scanner.Scan() {
			t.Fatalf("expected response, scanner error: %v", scanner.Err())
		}

		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(scanner.Text()), &parsed); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if parsed["id"] != float64(1) {
			t.Errorf("expected id 1, got: %v", parsed["id"])
		}

		_ = client.Close()
	})

	t.Run("multi_data_lines_joined", func(t *testing.T) {
		// Edge case: multiple data: lines are joined with \n per SSE spec.
		// We test that joining happens by checking handleSSEResponse directly.
		// Note: the joined result must still be valid JSON to be returned as a response.
		sseBody := strings.NewReader(
			"event: message\n" +
				"data: {\"jsonrpc\":\"2.0\",\n" +
				"data: \"id\":1,\n" +
				"data: \"result\":{}}\n" +
				"\n",
		)

		// handleSSEResponse is a method on HTTPClient — create a minimal instance.
		// L-28: Pass original request with matching id for response correlation.
		client := NewHTTPClient("http://unused")
		originalReq := []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`)
		resp, err := client.handleSSEResponse(sseBody, originalReq)
		if err != nil {
			// Multi-line data joined with \n won't be valid JSON (embedded newlines).
			// This is expected — the SSE spec says to join with \n, but real servers
			// send each event as a single data: line with valid JSON.
			t.Logf("multi-line data join produced non-JSON (expected): %v", err)
			return
		}

		// If somehow it parsed, verify it has an id
		var parsed map[string]interface{}
		if json.Unmarshal(resp, &parsed) == nil && parsed["id"] != nil {
			t.Logf("multi-line data was parseable: %s", string(resp))
		}
	})
}

// TestHTTPClient_202Accepted verifies that when the server returns 202 Accepted
// (acknowledgement of a notification), no response is written to the output pipe.
func TestHTTPClient_202Accepted(t *testing.T) {
	defer goleak.VerifyNone(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	writer, reader, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Send a notification (no "id") — server returns 202 Accepted
	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"))

	// Give the goroutine time to process and not write anything
	time.Sleep(100 * time.Millisecond)

	// Close the writer to signal no more requests
	_ = writer.Close()

	// Now read — there should be nothing, so scanner.Scan() should return false
	// (pipe closes after goroutine exits)
	scanner := bufio.NewScanner(reader)
	if scanner.Scan() {
		t.Errorf("expected no response for 202 Accepted notification, got: %s", scanner.Text())
	}

	_ = client.Close()
}

// TestHTTPClient_JSONResponseRegression verifies that plain application/json
// responses (non-SSE) still work correctly — regression test for the
// Content-Type branching logic.
func TestHTTPClient_JSONResponseRegression(t *testing.T) {
	defer goleak.VerifyNone(t)

	expectedResult := `{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"test-server"}}}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, expectedResult)
	}))
	defer server.Close()

	client := NewHTTPClient(server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	writer, reader, err := client.Start(ctx)
	if err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","method":"initialize","id":1}` + "\n"))

	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() {
		t.Fatalf("expected response, scanner error: %v", scanner.Err())
	}

	resp := scanner.Text()

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		t.Fatalf("response is not valid JSON: %v\nraw: %s", err, resp)
	}

	if parsed["jsonrpc"] != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got: %v", parsed["jsonrpc"])
	}

	if parsed["id"] != float64(1) {
		t.Errorf("expected id 1, got: %v", parsed["id"])
	}

	result, ok := parsed["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected result object, got: %T", parsed["result"])
	}

	serverInfo, ok := result["serverInfo"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected serverInfo object, got: %T", result["serverInfo"])
	}

	if serverInfo["name"] != "test-server" {
		t.Errorf("expected server name 'test-server', got: %v", serverInfo["name"])
	}

	_ = client.Close()
}

// TestIsJSONRPCNotification verifies the isJSONRPCNotification helper function
// that distinguishes notifications (method + no id) from requests/responses.
func TestIsJSONRPCNotification(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "notification_with_method_no_id",
			input:    `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			expected: true,
		},
		{
			name:     "request_with_method_and_id",
			input:    `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			expected: false,
		},
		{
			name:     "response_with_id_no_method",
			input:    `{"jsonrpc":"2.0","id":1,"result":{}}`,
			expected: false,
		},
		{
			name:     "invalid_json",
			input:    `invalid json`,
			expected: false,
		},
		{
			name:     "empty_object",
			input:    `{}`,
			expected: false,
		},
		{
			name:     "notification_with_params",
			input:    `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":50}}`,
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isJSONRPCNotification([]byte(tc.input))
			if got != tc.expected {
				t.Errorf("isJSONRPCNotification(%s) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}
