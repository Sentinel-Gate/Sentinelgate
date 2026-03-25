// Package mcp provides MCP client adapters for connecting to upstream servers.
package mcp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
)

// clientState represents the lifecycle state of an HTTPClient.
type clientState int

const (
	stateNew     clientState = iota // Initial state, not yet started
	stateStarted                    // Started and running
	stateClosed                     // Closed, terminal state
)

const (
	// scannerInitialBufSize is the initial buffer size for the message scanner.
	// MCP messages are typically small, but we start with a reasonable buffer
	// to minimize allocations for moderate-sized messages.
	scannerInitialBufSize = 256 * 1024 // 256KB

	// scannerMaxBufSize is the maximum buffer size for the message scanner.
	// Messages exceeding this size will cause bufio.ErrTooLong.
	// 1MB is sufficient for all practical MCP messages.
	scannerMaxBufSize = 1024 * 1024 // 1MB

	// maxResponseBodySize is the maximum response body size from upstream.
	// Prevents OOM from a malicious upstream sending unbounded responses.
	maxResponseBodySize = 10 * 1024 * 1024 // 10MB

	// defaultRequestTimeout is the per-request timeout for HTTP requests.
	// This replaces the global http.Client.Timeout, allowing SSE streams
	// enough time to deliver progress notifications + final response.
	defaultRequestTimeout = 120 * time.Second
)

// validUpstreamSessionIDPattern validates session IDs from upstream servers (M-7).
var validUpstreamSessionIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._\-]{1,128}$`)

// ssrfSafeDialer returns a net.Dialer with a Control function that rejects
// connections to private/link-local/loopback IPs at TCP connect time.
// H-1: Prevents DNS rebinding TOCTOU attacks where a hostname resolves to a
// safe IP at validation time but changes to a blocked IP (e.g. 169.254.169.254)
// before the actual TCP connection is established.
func ssrfSafeDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("SSRF protection: invalid address %q", address)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return nil // not an IP literal, should not happen at this stage
			}
			if ip.IsLoopback() {
				return fmt.Errorf("SSRF protection: loopback IP %s blocked", ip)
			}
			if ip.IsPrivate() {
				return fmt.Errorf("SSRF protection: private IP %s blocked", ip)
			}
			if ip.IsUnspecified() {
				return fmt.Errorf("SSRF protection: unspecified IP %s blocked", ip)
			}
			if ip.IsLinkLocalUnicast() {
				return fmt.Errorf("SSRF protection: link-local IP %s blocked (cloud metadata)", ip)
			}
			if ip.IsLinkLocalMulticast() {
				return fmt.Errorf("SSRF protection: link-local multicast IP %s blocked", ip)
			}
			return nil
		},
	}
}

// HTTPClient connects to an MCP server via HTTP (Streamable HTTP transport).
// It implements the outbound.MCPClient interface.
type HTTPClient struct {
	endpoint       string
	httpClient     *http.Client
	requestTimeout time.Duration // Per-request timeout (context-based, not http.Client.Timeout)

	mu        sync.Mutex
	sessionID string      // Mcp-Session-Id from server
	state     clientState // Lifecycle state (stateNew -> stateStarted -> stateClosed)
	wg        sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc

	sseRetryMs atomic.Int64 // M-41: server-suggested SSE reconnect delay in ms

	requestPipeReader  *io.PipeReader
	requestPipeWriter  *io.PipeWriter
	responsePipeReader *io.PipeReader
	responsePipeWriter *io.PipeWriter

	done chan struct{}
}

// ClientOption is a functional option for configuring HTTPClient.
type ClientOption func(*HTTPClient)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *HTTPClient) {
		c.httpClient = client
	}
}

// WithTimeout sets the per-request timeout for the HTTP client.
// Each HTTP POST uses context.WithTimeout with this duration.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *HTTPClient) {
		c.requestTimeout = d
	}
}

// WithSSRFProtection replaces the default transport's dialer with one that
// rejects connections to private/loopback/link-local IPs at TCP connect time.
// H-1: Prevents DNS rebinding TOCTOU where a hostname resolves to a safe IP
// at admin validation time but changes to a blocked IP before TCP connect.
func WithSSRFProtection() ClientOption {
	return func(c *HTTPClient) {
		if t, ok := c.httpClient.Transport.(*http.Transport); ok {
			t.DialContext = ssrfSafeDialer().DialContext
		}
	}
}

// NewHTTPClient creates a client for the given MCP server HTTP endpoint.
// The endpoint is the base URL of the remote MCP server.
func NewHTTPClient(endpoint string, opts ...ClientOption) *HTTPClient {
	c := &HTTPClient{
		endpoint: endpoint,
		httpClient: &http.Client{
			// No global timeout — per-request context timeout is used instead.
			// http.Client.Timeout kills connections hard, even while actively
			// reading SSE streams. Context-based timeouts are more graceful.
			Timeout: 0,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12, // SECU-01: TLS 1.2 minimum
				},
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		requestTimeout: defaultRequestTimeout,
		done:           make(chan struct{}),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Start establishes the connection to the remote MCP server.
// Returns io.WriteCloser for sending requests and io.ReadCloser for receiving responses.
// Uses pipe adapters to bridge HTTP request/response to stream interface.
func (c *HTTPClient) Start(ctx context.Context) (io.WriteCloser, io.ReadCloser, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.state {
	case stateStarted:
		return nil, nil, errors.New("client already started")
	case stateClosed:
		return nil, nil, errors.New("client is closed, create a new instance")
	case stateNew:
		// Proceed with start
	}

	c.state = stateStarted
	// Reset completion channel for this run
	c.done = make(chan struct{})

	// Create cancellable context for internal use
	c.ctx, c.cancel = context.WithCancel(ctx)

	// Create pipes for bidirectional communication
	// Request pipe: ProxyService writes -> HTTPClient reads
	c.requestPipeReader, c.requestPipeWriter = io.Pipe()
	// Response pipe: HTTPClient writes -> ProxyService reads
	c.responsePipeReader, c.responsePipeWriter = io.Pipe()

	// Start goroutine to read requests and send HTTP POSTs
	c.wg.Add(1)
	go c.readRequestsAndSend()

	return c.requestPipeWriter, c.responsePipeReader, nil
}

// readRequestsAndSend reads newline-delimited JSON messages from the request pipe
// and sends each as an HTTP POST to the endpoint.
//
// The scanner is configured with scannerInitialBufSize (256KB) initial buffer and
// scannerMaxBufSize (1MB) maximum. Messages exceeding 1MB will cause the scanner
// to return bufio.ErrTooLong and exit the loop. This is expected behavior - clients
// should not send messages larger than 1MB.
func (c *HTTPClient) readRequestsAndSend() {
	defer c.wg.Done()
	defer close(c.done)
	defer func() { _ = c.responsePipeWriter.Close() }()
	defer func() { _ = c.requestPipeReader.CloseWithError(errors.New("pipe goroutine exited")) }()

	scanner := bufio.NewScanner(c.requestPipeReader)
	buf := make([]byte, 0, scannerInitialBufSize)
	scanner.Buffer(buf, scannerMaxBufSize)

	for scanner.Scan() {
		// Check context before processing
		if c.ctx.Err() != nil {
			return
		}

		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}

		// Check if this is a JSON-RPC notification (no "id" field).
		// Notifications don't expect responses; suppress any server reply
		// to prevent out-of-order messages in the response pipe.
		isNotification := isJSONRPCNotification(raw)

		// Send HTTP POST with the message
		resp, err := c.sendRequest(raw)
		if err != nil {
			// Don't write error responses for notifications
			if !isNotification {
				c.writeErrorResponse(raw, err)
			}
			continue
		}

		// Skip writing if no response body (202 Accepted) or notification
		if resp == nil || isNotification {
			continue
		}

		// Strip trailing newlines from response before writing the pipe delimiter.
		// HTTP servers using json.Encoder.Encode() append a trailing newline to
		// the response body. If we don't strip it, the response pipe gets two
		// consecutive newlines (json\n\n), which causes the next bufio.Scanner
		// on the reader side to see an empty line and desync.
		for len(resp) > 0 && resp[len(resp)-1] == '\n' {
			resp = resp[:len(resp)-1]
		}

		// Write response + exactly one newline to response pipe
		if _, err := c.responsePipeWriter.Write(resp); err != nil {
			return // Pipe closed
		}
		if _, err := c.responsePipeWriter.Write([]byte("\n")); err != nil {
			return // Pipe closed
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("scanner error reading request pipe", "error", err)
	}
}

// sendRequest sends an HTTP POST request with the JSON-RPC message.
// Handles both JSON and SSE (text/event-stream) responses per MCP Streamable HTTP spec.
// Returns nil, nil for 202 Accepted (notification acknowledgement).
func (c *HTTPClient) sendRequest(body []byte) ([]byte, error) {
	// Per-request context timeout instead of global http.Client.Timeout.
	// This allows SSE streams to be read without being killed mid-stream.
	reqCtx, reqCancel := context.WithTimeout(c.ctx, c.requestTimeout)
	defer reqCancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Set body using a bytes.Reader to avoid import cycle
	req.Body = io.NopCloser(newBytesReader(body))
	req.ContentLength = int64(len(body))

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	// Add session ID if we have one
	c.mu.Lock()
	sessionID := c.sessionID
	c.mu.Unlock()
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Save session ID from response.
	// M-7: Validate session ID from upstream against safe pattern before storing.
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		if len(sid) <= 128 && validUpstreamSessionIDPattern.MatchString(sid) {
			c.mu.Lock()
			c.sessionID = sid
			c.mu.Unlock()
		}
	}

	// Handle 202 Accepted — server acknowledges notification, no body expected.
	if resp.StatusCode == http.StatusAccepted {
		return nil, nil
	}

	// Handle non-2xx status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
		return nil, fmt.Errorf("http status %d: %s", resp.StatusCode, string(errBody))
	}

	// Branch based on Content-Type: SSE vs JSON.
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		return c.handleSSEResponse(resp.Body, body)
	}

	// Default: JSON response (existing behavior).
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return respBody, nil
}

// handleSSEResponse parses a Server-Sent Events stream from the response body
// and returns the JSON-RPC response matching the original request's id.
// L-28: Matches response id against the original request id and distinguishes
// responses (with "result" or "error") from server-to-client requests (with "method").
// Notifications (messages without "id") are silently consumed.
//
// SSE format per spec:
//
//	event: message
//	data: {"jsonrpc":"2.0","id":1,"result":{...}}
//	<blank line>
//
// Multiple data: lines for the same event are joined with newlines.
func (c *HTTPClient) handleSSEResponse(body io.Reader, originalRequest []byte) ([]byte, error) {
	// L-28: Extract the request id to match against response id.
	var reqIDProbe struct {
		ID json.RawMessage `json:"id"`
	}
	var requestID string
	if json.Unmarshal(originalRequest, &reqIDProbe) == nil && len(reqIDProbe.ID) > 0 {
		requestID = string(reqIDProbe.ID)
	}

	scanner := bufio.NewScanner(body)
	// Use a generous buffer for SSE — events can contain large JSON payloads.
	scanner.Buffer(make([]byte, 0, 64*1024), maxResponseBodySize)

	var dataLines []string

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case line == "":
			// Blank line = end of event. Process accumulated data lines.
			if len(dataLines) > 0 {
				data := strings.Join(dataLines, "\n")
				dataLines = nil

				if matched, ok := c.matchSSEResponseMessage([]byte(data), requestID); ok {
					return matched, nil
				}
				// Not a matching response — consume and continue.
			}

		case strings.HasPrefix(line, "data:"):
			// Extract data payload, trimming optional leading space after "data:".
			payload := line[5:]
			if len(payload) > 0 && payload[0] == ' ' {
				payload = payload[1:]
			}
			dataLines = append(dataLines, payload)

		case strings.HasPrefix(line, "retry:"):
			// M-41: parse server-suggested reconnect delay
			retryStr := strings.TrimSpace(line[6:])
			if val, err := strconv.ParseInt(retryStr, 10, 64); err == nil && val >= 0 {
				c.sseRetryMs.Store(val)
			}

			// event:, id:, : (comment) lines are ignored per SSE spec.
		}
	}

	// Stream ended. Check for remaining buffered data (server may omit trailing blank line).
	if len(dataLines) > 0 {
		data := strings.Join(dataLines, "\n")
		if matched, ok := c.matchSSEResponseMessage([]byte(data), requestID); ok {
			return matched, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("SSE stream read: %w", err)
	}

	return nil, fmt.Errorf("SSE stream ended without JSON-RPC response")
}

// matchSSEResponseMessage checks if an SSE data message is a JSON-RPC response
// matching the original request id, or a server-to-client request that should
// be forwarded.
// H-11: Messages with both "method" AND "id" are server-to-client requests
// (e.g. sampling/createMessage, elicitation/create) and must be forwarded,
// not discarded. Only pure notifications (method present, no id) are skipped.
func (c *HTTPClient) matchSSEResponseMessage(data []byte, requestID string) ([]byte, bool) {
	var probe struct {
		ID     *json.RawMessage `json:"id"`
		Method *string          `json:"method"`
	}
	if json.Unmarshal(data, &probe) != nil || probe.ID == nil {
		return nil, false
	}

	// H-11: If this message has both method and id, it's a server-to-client request
	// (e.g. sampling/createMessage). Forward it to the caller so the proxy can
	// relay it downstream instead of silently discarding it.
	if probe.Method != nil {
		return data, true
	}

	// L-28: Pure response (id, no method). Match against the original request id.
	if requestID != "" && string(*probe.ID) != requestID {
		return nil, false
	}

	return data, true
}

// isJSONRPCNotification returns true if the raw message is a JSON-RPC notification.
// Per JSON-RPC 2.0 spec, a notification is a request object without an "id" member.
// L-12: "id":null is a valid request with a null id, NOT a notification.
// Only the complete absence of the "id" key qualifies as a notification.
func isJSONRPCNotification(raw []byte) bool {
	// First check that a "method" field exists.
	var methodProbe struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(raw, &methodProbe); err != nil {
		return false
	}
	if methodProbe.Method == "" {
		return false
	}
	// Check whether the "id" key is present at all using a map.
	// json.Unmarshal into map will include "id" key even if value is null,
	// but will omit "id" entirely if the key is absent from the JSON.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return false
	}
	_, hasID := fields["id"]
	return !hasID
}

// writeErrorResponse writes a JSON-RPC error response to the response pipe.
// SECURITY: Error messages are sanitized to prevent internal details from leaking to clients.
func (c *HTTPClient) writeErrorResponse(rawRequest []byte, err error) {
	// M-23: Use json.RawMessage for request ID to preserve exact numeric precision.
	var requestID json.RawMessage
	var req struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(rawRequest, &req) == nil && len(req.ID) > 0 && string(req.ID) != "null" {
		requestID = req.ID
	}

	// SECURITY: Sanitize error message for client response.
	// Internal error details should not be exposed.
	safeMessage := "Internal error"
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		safeMessage = "Request timeout"
	}

	// Create JSON-RPC error response.
	// Per JSON-RPC 2.0 spec: "If there was an error in detecting the id in
	// the Request object, it MUST be Null." Always include "id" so that
	// clients can correlate error responses. When requestID is nil, json.Marshal
	// produces "id": null as required by the spec.
	errResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      requestID, // nil → "id": null in JSON (spec-compliant)
		"error": map[string]interface{}{
			"code":    -32603, // Internal error
			"message": safeMessage,
		},
	}

	respBytes, marshalErr := json.Marshal(errResp)
	if marshalErr != nil {
		// M-17: Fallback to hardcoded JSON-RPC error on marshal failure.
		slog.Warn("failed to marshal error response, using fallback", "error", marshalErr)
		respBytes = []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}`)
	}
	if _, werr := c.responsePipeWriter.Write(respBytes); werr != nil {
		slog.Warn("failed to write error response to pipe", "error", werr)
		return
	}
	if _, werr := c.responsePipeWriter.Write([]byte("\n")); werr != nil {
		slog.Warn("failed to write newline to response pipe", "error", werr)
	}
}

// Wait blocks until the HTTP connection is closed.
// Returns nil (HTTP has no process exit like stdio).
func (c *HTTPClient) Wait() error {
	<-c.done
	return nil
}

// Close terminates the HTTP connection and cleans up resources.
// Close is idempotent: calling it multiple times is safe and returns nil.
// After Close(), the client can be restarted with Start() for a new request cycle.
// This is required for HTTP mode where each request is a separate Start/Close cycle.
func (c *HTTPClient) Close() error {
	c.mu.Lock()

	// L-6: Idempotent: already closed or never started, nothing to do.
	// Both stateNew and stateClosed are terminal/idle states where Close() is a no-op.
	if c.state == stateNew || c.state == stateClosed {
		c.mu.Unlock()
		return nil
	}

	var errs []error

	// Cancel context to stop goroutines
	if c.cancel != nil {
		c.cancel()
	}

	// Close request pipe (signals EOF to goroutine)
	if c.requestPipeWriter != nil {
		if err := c.requestPipeWriter.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close request pipe: %w", err))
		}
	}
	if c.requestPipeReader != nil {
		if err := c.requestPipeReader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close request pipe reader: %w", err))
		}
	}

	// Mark as closed temporarily while we wait for goroutines
	c.state = stateClosed
	c.mu.Unlock()

	// Wait for goroutine to finish (with timeout) outside of lock
	// Only wait if the client was started (goroutine was spawned)
	if c.done != nil {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-c.done:
			// Clean exit
		case <-timer.C:
			errs = append(errs, errors.New("timeout waiting for goroutine"))
		}
	}

	// Re-acquire lock to close response pipes and reset state
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close response pipe
	if c.responsePipeWriter != nil {
		// Already closed in goroutine, but safe to close again
		_ = c.responsePipeWriter.Close()
	}
	if c.responsePipeReader != nil {
		if err := c.responsePipeReader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close response pipe: %w", err))
		}
	}

	// Close idle connections from the HTTP transport pool.
	c.httpClient.CloseIdleConnections()

	// Reset state to allow reuse (required for HTTP mode)
	// Note: Don't nil out pipe references - the old goroutine may still
	// be draining. Start() will create fresh pipes that overwrite these.
	c.state = stateNew

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// bytesReader is a simple io.Reader that reads from a byte slice.
// This avoids importing bytes package just for bytes.NewReader.
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// Compile-time check that HTTPClient implements MCPClient interface.
var _ outbound.MCPClient = (*HTTPClient)(nil)
