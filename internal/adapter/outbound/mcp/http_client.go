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
	"net/http"
	"sync"
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
)

// HTTPClient connects to an MCP server via HTTP (Streamable HTTP transport).
// It implements the outbound.MCPClient interface.
type HTTPClient struct {
	endpoint   string
	httpClient *http.Client

	mu        sync.Mutex
	sessionID string      // Mcp-Session-Id from server
	state     clientState // Lifecycle state (stateNew -> stateStarted -> stateClosed)
	wg        sync.WaitGroup

	ctx    context.Context
	cancel context.CancelFunc

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

// WithTimeout sets the request timeout for the HTTP client.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *HTTPClient) {
		if c.httpClient != nil {
			c.httpClient.Timeout = d
		}
	}
}

// NewHTTPClient creates a client for the given MCP server HTTP endpoint.
// The endpoint is the base URL of the remote MCP server.
func NewHTTPClient(endpoint string, opts ...ClientOption) *HTTPClient {
	c := &HTTPClient{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12, // SECU-01: TLS 1.2 minimum
				},
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		done: make(chan struct{}),
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

		// Send HTTP POST with the message
		resp, err := c.sendRequest(raw)
		if err != nil {
			// Write JSON-RPC error response to pipe
			c.writeErrorResponse(raw, err)
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
}

// sendRequest sends an HTTP POST request with the JSON-RPC message.
func (c *HTTPClient) sendRequest(body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Set body using a bytes.Reader to avoid import cycle
	req.Body = io.NopCloser(newBytesReader(body))
	req.ContentLength = int64(len(body))

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

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

	// Save session ID from response
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.mu.Lock()
		c.sessionID = sid
		c.mu.Unlock()
	}

	// Read response body (limited to prevent OOM from malicious upstream)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Handle non-2xx status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http status %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// writeErrorResponse writes a JSON-RPC error response to the response pipe.
// SECURITY: Error messages are sanitized to prevent internal details from leaking to clients.
func (c *HTTPClient) writeErrorResponse(rawRequest []byte, err error) {
	// Try to extract request ID from the original request
	var requestID interface{}
	var req struct {
		ID interface{} `json:"id"`
	}
	if json.Unmarshal(rawRequest, &req) == nil && req.ID != nil {
		requestID = req.ID
	}

	// SECURITY: Sanitize error message for client response.
	// Internal error details should not be exposed.
	safeMessage := "Internal error"
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		safeMessage = "Request timeout"
	}

	// Create JSON-RPC error response
	errResp := map[string]interface{}{
		"jsonrpc": "2.0",
		"error": map[string]interface{}{
			"code":    -32603, // Internal error
			"message": safeMessage,
		},
	}
	if requestID != nil {
		errResp["id"] = requestID
	}

	respBytes, _ := json.Marshal(errResp)
	_, _ = c.responsePipeWriter.Write(respBytes)
	_, _ = c.responsePipeWriter.Write([]byte("\n"))
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

	// Idempotent: already in new state, nothing to do
	if c.state == stateNew {
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
		done := make(chan struct{})
		go func() {
			c.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
			// Clean exit
		case <-time.After(5 * time.Second):
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
