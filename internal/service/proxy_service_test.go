package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"go.uber.org/goleak"
)

// mockMCPClient implements outbound.MCPClient for testing proxy service goroutine cleanup.
type mockMCPClient struct {
	startFunc func(ctx context.Context) (io.WriteCloser, io.ReadCloser, error)
	closeFunc func() error
	waitFunc  func() error

	// Track state for assertions
	mu      sync.Mutex
	started bool
	closed  bool
}

func (m *mockMCPClient) Start(ctx context.Context) (io.WriteCloser, io.ReadCloser, error) {
	m.mu.Lock()
	m.started = true
	m.mu.Unlock()
	if m.startFunc != nil {
		return m.startFunc(ctx)
	}
	// Default: create pipes
	r, w := io.Pipe()
	return w, r, nil
}

func (m *mockMCPClient) Close() error {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

func (m *mockMCPClient) Wait() error {
	if m.waitFunc != nil {
		return m.waitFunc()
	}
	return nil
}

func (m *mockMCPClient) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// writerWithCloseSignal wraps an io.WriteCloser and signals a channel on close.
// This simulates how closing a process's stdin causes the process to exit
// (and thus close its stdout).
type writerWithCloseSignal struct {
	io.WriteCloser
	onClose func()
	once    sync.Once
}

func (w *writerWithCloseSignal) Close() error {
	err := w.WriteCloser.Close()
	w.once.Do(func() {
		if w.onClose != nil {
			w.onClose()
		}
	})
	return err
}

// TestProxyService_ContextCancellation verifies that ProxyService exits cleanly
// when the context is cancelled and pipes are closed, with no goroutine leaks.
//
// In production, context cancellation typically coincides with pipe closure
// (e.g., process termination closes both). This test simulates that by
// closing the client input pipe after context cancellation to unblock
// the scanner goroutines.
func TestProxyService_ContextCancellation(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Create pipes for server communication.
	// serverIn: proxy writes to serverInWriter, mock server reads from serverInReader
	// serverOut: mock server writes to serverOutWriter, proxy reads from serverOutReader
	serverInReader, serverInWriter := io.Pipe()
	serverOutReader, serverOutWriter := io.Pipe()

	// Wrap serverInWriter to signal when it's closed (simulating server stdin close).
	// When the proxy closes serverIn, we close serverOut to simulate server exit.
	wrappedServerIn := &writerWithCloseSignal{
		WriteCloser: serverInWriter,
		onClose: func() {
			// Simulate server process exit: when stdin closes, server exits and closes stdout
			_ = serverOutWriter.Close()
		},
	}

	mockClient := &mockMCPClient{
		startFunc: func(ctx context.Context) (io.WriteCloser, io.ReadCloser, error) {
			return wrappedServerIn, serverOutReader, nil
		},
		closeFunc: func() error {
			// Cleanup any remaining pipe ends
			_ = serverInWriter.Close()
			_ = serverOutReader.Close()
			_ = serverInReader.Close()
			_ = serverOutWriter.Close()
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxyService := NewProxyService(mockClient, proxy.NewPassthroughInterceptor(), logger)

	// Create client pipes
	clientInReader, clientInWriter := io.Pipe()
	clientOutReader, clientOutWriter := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())

	// Run proxy
	errCh := make(chan error, 1)
	go func() {
		errCh <- proxyService.Run(ctx, clientInReader, clientOutWriter)
	}()

	// Give proxy time to start its goroutines
	time.Sleep(50 * time.Millisecond)

	// Cancel context - this signals shutdown intent
	cancel()

	// Close client input to unblock the client->server scanner.
	// This triggers a cascade:
	// 1. client->server scanner gets EOF
	// 2. client->server goroutine exits, closing serverIn via defer
	// 3. wrappedServerIn.Close() triggers serverOutWriter.Close()
	// 4. server->client scanner gets EOF
	// 5. server->client goroutine exits
	// 6. proxy.Run() returns
	_ = clientInWriter.Close()

	// Wait for completion with timeout
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for proxy shutdown")
	}

	// Verify mock client was closed
	if !mockClient.isClosed() {
		t.Error("expected mock client to be closed")
	}

	// Cleanup any remaining pipes
	_ = clientInReader.Close()
	_ = clientOutReader.Close()
	_ = clientOutWriter.Close()
}

// TestProxyService_ClientDisconnect verifies that ProxyService handles
// client disconnect (EOF) gracefully with no goroutine leaks.
//
// When the client closes its input pipe (simulating process exit or connection close),
// the proxy should detect EOF, close the server connection, and exit cleanly.
func TestProxyService_ClientDisconnect(t *testing.T) {
	defer goleak.VerifyNone(t)

	serverInReader, serverInWriter := io.Pipe()
	serverOutReader, serverOutWriter := io.Pipe()

	// Simulate server behavior: when stdin closes, server exits and closes stdout
	wrappedServerIn := &writerWithCloseSignal{
		WriteCloser: serverInWriter,
		onClose: func() {
			_ = serverOutWriter.Close()
		},
	}

	mockClient := &mockMCPClient{
		startFunc: func(ctx context.Context) (io.WriteCloser, io.ReadCloser, error) {
			return wrappedServerIn, serverOutReader, nil
		},
		closeFunc: func() error {
			_ = serverInWriter.Close()
			_ = serverOutReader.Close()
			_ = serverInReader.Close()
			_ = serverOutWriter.Close()
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxyService := NewProxyService(mockClient, proxy.NewPassthroughInterceptor(), logger)

	clientInReader, clientInWriter := io.Pipe()
	clientOutReader, clientOutWriter := io.Pipe()

	ctx := context.Background()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxyService.Run(ctx, clientInReader, clientOutWriter)
	}()

	// Give proxy time to start
	time.Sleep(50 * time.Millisecond)

	// Simulate client disconnect by closing input.
	// Cascade: clientIn EOF -> serverIn closed -> serverOut closed -> proxy exits
	_ = clientInWriter.Close()

	// Wait for completion
	select {
	case <-errCh:
		// Expected - proxy should exit when client disconnects
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for proxy to handle client disconnect")
	}

	// Verify mock client was closed
	if !mockClient.isClosed() {
		t.Error("expected mock client to be closed")
	}

	// Cleanup remaining pipes
	_ = clientInReader.Close()
	_ = clientOutReader.Close()
	_ = clientOutWriter.Close()
}

// TestProxyService_ServerDisconnect verifies that ProxyService handles
// server disconnect (EOF) gracefully with no goroutine leaks.
//
// When the server closes its output pipe (simulating server exit or crash),
// the proxy should detect EOF on the server->client side and signal shutdown.
// Note: The current proxy implementation requires external pipe closure to
// fully unblock all goroutines - this is expected behavior as the proxy
// doesn't forcibly terminate blocked I/O operations.
func TestProxyService_ServerDisconnect(t *testing.T) {
	defer goleak.VerifyNone(t)

	serverInReader, serverInWriter := io.Pipe()
	serverOutReader, serverOutWriter := io.Pipe()

	mockClient := &mockMCPClient{
		startFunc: func(ctx context.Context) (io.WriteCloser, io.ReadCloser, error) {
			return serverInWriter, serverOutReader, nil
		},
		closeFunc: func() error {
			_ = serverInWriter.Close()
			_ = serverInReader.Close()
			_ = serverOutReader.Close()
			_ = serverOutWriter.Close()
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxyService := NewProxyService(mockClient, proxy.NewPassthroughInterceptor(), logger)

	clientInReader, clientInWriter := io.Pipe()
	clientOutReader, clientOutWriter := io.Pipe()

	ctx := context.Background()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxyService.Run(ctx, clientInReader, clientOutWriter)
	}()

	// Give proxy time to start
	time.Sleep(50 * time.Millisecond)

	// Simulate server disconnect by closing server output.
	// The server->client goroutine will detect EOF and call cancel().
	_ = serverOutWriter.Close()

	// The client->server goroutine is blocked on scanner.Scan() reading from
	// clientInReader. In production, the caller (HTTP handler or stdio handler)
	// would close clientIn when it detects the proxy context was cancelled.
	// Simulate this by closing clientInWriter after a short delay.
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = clientInWriter.Close()
	}()

	// Wait for completion
	select {
	case <-errCh:
		// Expected - proxy should exit after all goroutines complete
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for proxy to handle server disconnect")
	}

	// Verify mock client was closed
	if !mockClient.isClosed() {
		t.Error("expected mock client to be closed")
	}

	// Cleanup remaining pipes
	_ = clientInReader.Close()
	_ = clientOutReader.Close()
	_ = clientOutWriter.Close()
}

// TestProxyService_MessageRoundtrip verifies basic message flow through
// the proxy and clean shutdown with no goroutine leaks.
//
// This test sends a message through the proxy to an echo server and verifies
// the response, then performs a clean shutdown.
func TestProxyService_MessageRoundtrip(t *testing.T) {
	defer goleak.VerifyNone(t)

	serverInReader, serverInWriter := io.Pipe()
	serverOutReader, serverOutWriter := io.Pipe()

	// Echo server simulation: reads from serverIn, writes to serverOut.
	// When serverIn is closed (EOF), echo server exits and closes serverOut.
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		defer func() { _ = serverOutWriter.Close() }() // Simulate server exit closing stdout
		buf := make([]byte, 4096)
		for {
			n, err := serverInReader.Read(buf)
			if err != nil {
				return
			}
			if _, err := serverOutWriter.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	mockClient := &mockMCPClient{
		startFunc: func(ctx context.Context) (io.WriteCloser, io.ReadCloser, error) {
			return serverInWriter, serverOutReader, nil
		},
		closeFunc: func() error {
			_ = serverInWriter.Close()
			_ = serverInReader.Close()
			_ = serverOutReader.Close()
			_ = serverOutWriter.Close()
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxyService := NewProxyService(mockClient, proxy.NewPassthroughInterceptor(), logger)

	clientInReader, clientInWriter := io.Pipe()
	clientOutReader, clientOutWriter := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxyService.Run(ctx, clientInReader, clientOutWriter)
	}()

	// Send message from client
	testMsg := `{"jsonrpc":"2.0","method":"test","id":1}` + "\n"
	_, err := clientInWriter.Write([]byte(testMsg))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Read response using a bufio.Reader to get the full line including newline.
	// The proxy writes message then newline in separate Write() calls, so a single
	// Read() might not get both.
	responseCh := make(chan string, 1)
	go func() {
		buf := make([]byte, 0, 1024)
		tmp := make([]byte, 256)
		for {
			n, err := clientOutReader.Read(tmp)
			if err != nil {
				responseCh <- string(buf)
				return
			}
			buf = append(buf, tmp[:n]...)
			// Check if we got a complete line
			if len(buf) > 0 && buf[len(buf)-1] == '\n' {
				responseCh <- string(buf)
				return
			}
		}
	}()

	select {
	case response := <-responseCh:
		if response != testMsg {
			t.Errorf("expected %q, got %q", testMsg, response)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for response")
	}

	// Clean shutdown: close client input.
	// This triggers: clientIn EOF -> serverIn closed -> echo server exits ->
	// serverOut closed -> proxy exits
	_ = clientInWriter.Close()

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for shutdown")
	}

	// Wait for echo server to exit
	select {
	case <-echoDone:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for echo server to exit")
	}

	// Verify mock client was closed
	if !mockClient.isClosed() {
		t.Error("expected mock client to be closed")
	}

	// Cleanup remaining pipes
	_ = clientInReader.Close()
	_ = clientOutReader.Close()
	_ = clientOutWriter.Close()
}

// mockRejectingInterceptor implements proxy.MessageInterceptor that rejects
// messages with a specific method.
type mockRejectingInterceptor struct {
	rejectMethod string
}

func (m *mockRejectingInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	if msg.Decoded != nil {
		if req, ok := msg.Decoded.(*jsonrpc.Request); ok {
			if req.Method == m.rejectMethod {
				return nil, proxy.ErrPolicyDenied
			}
		}
	}
	return msg, nil
}

// TestProxyService_InterceptorRejection verifies that ProxyService handles
// interceptor rejection correctly by returning an error response to the client
// and cleaning up goroutines without leaks.
//
// When the interceptor rejects a message, the proxy should:
// 1. Send a JSON-RPC error response to the client
// 2. NOT forward the message to the server
// 3. Continue processing subsequent messages
// 4. Clean up properly on shutdown
func TestProxyService_InterceptorRejection(t *testing.T) {
	defer goleak.VerifyNone(t)

	serverInReader, serverInWriter := io.Pipe()
	serverOutReader, serverOutWriter := io.Pipe()

	// Track messages received by server
	serverReceived := make(chan string, 10)

	// Server simulation: reads messages and echoes them
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer func() { _ = serverOutWriter.Close() }()
		buf := make([]byte, 4096)
		for {
			n, err := serverInReader.Read(buf)
			if err != nil {
				return
			}
			// Record received message
			select {
			case serverReceived <- string(buf[:n]):
			default:
			}
			// Echo back
			if _, err := serverOutWriter.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	mockClient := &mockMCPClient{
		startFunc: func(ctx context.Context) (io.WriteCloser, io.ReadCloser, error) {
			return serverInWriter, serverOutReader, nil
		},
		closeFunc: func() error {
			_ = serverInWriter.Close()
			_ = serverInReader.Close()
			_ = serverOutReader.Close()
			_ = serverOutWriter.Close()
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use rejecting interceptor that blocks "tools/call" messages
	interceptor := &mockRejectingInterceptor{rejectMethod: "tools/call"}
	proxyService := NewProxyService(mockClient, interceptor, logger)

	clientInReader, clientInWriter := io.Pipe()
	clientOutReader, clientOutWriter := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxyService.Run(ctx, clientInReader, clientOutWriter)
	}()

	// Collect client responses - buffer until we get a complete line
	clientResponses := make(chan []byte, 10)
	go func() {
		accumulated := make([]byte, 0, 4096)
		buf := make([]byte, 4096)
		for {
			n, err := clientOutReader.Read(buf)
			if err != nil {
				return
			}
			accumulated = append(accumulated, buf[:n]...)
			// Check for complete lines and send them
			for {
				idx := bytes.IndexByte(accumulated, '\n')
				if idx == -1 {
					break
				}
				// Include the newline in the response
				line := make([]byte, idx+1)
				copy(line, accumulated[:idx+1])
				accumulated = accumulated[idx+1:]
				clientResponses <- line
			}
		}
	}()

	// Give proxy time to start
	time.Sleep(50 * time.Millisecond)

	// Send a message that should be REJECTED (tools/call)
	rejectedMsg := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"test"},"id":1}` + "\n"
	_, err := clientInWriter.Write([]byte(rejectedMsg))
	if err != nil {
		t.Fatalf("write rejected message failed: %v", err)
	}

	// Wait for error response from proxy
	var errorResponse []byte
	select {
	case resp := <-clientResponses:
		errorResponse = resp
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for error response")
	}

	// Verify error response is a JSON-RPC error
	var rpcResp struct {
		JSONRPC string `json:"jsonrpc"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		ID interface{} `json:"id"`
	}
	// Trim newline for parsing
	if err := json.Unmarshal(bytes.TrimSpace(errorResponse), &rpcResp); err != nil {
		t.Fatalf("failed to parse error response: %v, got: %s", err, errorResponse)
	}
	if rpcResp.Error == nil {
		t.Errorf("expected error response, got: %s", errorResponse)
	}
	if rpcResp.Error != nil && !strings.Contains(rpcResp.Error.Message, "denied") {
		t.Errorf("expected 'denied' in error message, got: %s", rpcResp.Error.Message)
	}

	// Verify server did NOT receive the rejected message
	select {
	case msg := <-serverReceived:
		t.Errorf("server should not have received rejected message, got: %s", msg)
	case <-time.After(100 * time.Millisecond):
		// Expected - server should not receive rejected message
	}

	// Send a message that should be ALLOWED (not tools/call)
	allowedMsg := `{"jsonrpc":"2.0","method":"test/allowed","id":2}` + "\n"
	_, err = clientInWriter.Write([]byte(allowedMsg))
	if err != nil {
		t.Fatalf("write allowed message failed: %v", err)
	}

	// Wait for server to receive and echo
	select {
	case msg := <-serverReceived:
		if !strings.Contains(msg, "test/allowed") {
			t.Errorf("expected server to receive allowed message, got: %s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server to receive allowed message")
	}

	// Wait for echoed response
	select {
	case resp := <-clientResponses:
		if !strings.Contains(string(resp), "test/allowed") {
			t.Errorf("expected echoed response, got: %s", resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for echoed response")
	}

	// Clean shutdown
	_ = clientInWriter.Close()

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for shutdown")
	}

	select {
	case <-serverDone:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for server to exit")
	}

	if !mockClient.isClosed() {
		t.Error("expected mock client to be closed")
	}

	// Cleanup
	_ = clientInReader.Close()
	_ = clientOutReader.Close()
	_ = clientOutWriter.Close()
}

// TestProxyService_SlowServer verifies that ProxyService handles
// slow server responses gracefully when context times out.
//
// When the context times out while waiting for server response,
// the proxy should exit cleanly with no goroutine leaks.
func TestProxyService_SlowServer(t *testing.T) {
	defer goleak.VerifyNone(t)

	serverInReader, serverInWriter := io.Pipe()
	serverOutReader, serverOutWriter := io.Pipe()

	// Slow server simulation: reads from serverIn but delays response significantly
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer func() { _ = serverOutWriter.Close() }()
		buf := make([]byte, 4096)
		for {
			n, err := serverInReader.Read(buf)
			if err != nil {
				return
			}
			// Simulate slow server - delay before response
			time.Sleep(500 * time.Millisecond)
			if _, err := serverOutWriter.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	mockClient := &mockMCPClient{
		startFunc: func(ctx context.Context) (io.WriteCloser, io.ReadCloser, error) {
			return serverInWriter, serverOutReader, nil
		},
		closeFunc: func() error {
			_ = serverInWriter.Close()
			_ = serverInReader.Close()
			_ = serverOutReader.Close()
			_ = serverOutWriter.Close()
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	proxyService := NewProxyService(mockClient, proxy.NewPassthroughInterceptor(), logger)

	clientInReader, clientInWriter := io.Pipe()
	clientOutReader, clientOutWriter := io.Pipe()

	// Use short timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxyService.Run(ctx, clientInReader, clientOutWriter)
	}()

	// Send a message that will trigger the slow response
	testMsg := `{"jsonrpc":"2.0","method":"slow/request","id":1}` + "\n"
	_, err := clientInWriter.Write([]byte(testMsg))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Context should timeout before server responds
	// After timeout, close client input to unblock client->server scanner
	go func() {
		time.Sleep(150 * time.Millisecond) // Wait for context to timeout
		_ = clientInWriter.Close()
	}()

	// Wait for proxy to exit
	select {
	case err := <-errCh:
		// May return context.DeadlineExceeded or nil depending on timing
		if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for proxy to handle slow server")
	}

	// Wait for slow server goroutine to exit
	select {
	case <-serverDone:
	case <-time.After(1 * time.Second):
		// Server may still be blocked on write, that's OK
	}

	if !mockClient.isClosed() {
		t.Error("expected mock client to be closed")
	}

	// Cleanup
	_ = clientInReader.Close()
	_ = clientOutReader.Close()
	_ = clientOutWriter.Close()
}

// TestProxyService_MalformedMessage verifies that ProxyService handles
// malformed JSON messages gracefully without crashing or leaking goroutines.
//
// The proxy should either:
// - Pass through malformed messages (if passthrough mode)
// - Log an error and continue processing
// - Clean up properly on shutdown
func TestProxyService_MalformedMessage(t *testing.T) {
	testCases := []struct {
		name    string
		message string
	}{
		{"empty", "\n"},
		{"invalid_json", "{invalid}\n"},
		{"not_jsonrpc", `{"foo":"bar"}` + "\n"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer goleak.VerifyNone(t)

			serverInReader, serverInWriter := io.Pipe()
			serverOutReader, serverOutWriter := io.Pipe()

			// Track messages received by server
			serverReceived := make(chan string, 10)

			// Server simulation: reads messages and echoes them
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				defer func() { _ = serverOutWriter.Close() }()
				buf := make([]byte, 4096)
				for {
					n, err := serverInReader.Read(buf)
					if err != nil {
						return
					}
					// Record received message
					select {
					case serverReceived <- string(buf[:n]):
					default:
					}
					// Echo back
					if _, err := serverOutWriter.Write(buf[:n]); err != nil {
						return
					}
				}
			}()

			mockClient := &mockMCPClient{
				startFunc: func(ctx context.Context) (io.WriteCloser, io.ReadCloser, error) {
					return serverInWriter, serverOutReader, nil
				},
				closeFunc: func() error {
					_ = serverInWriter.Close()
					_ = serverInReader.Close()
					_ = serverOutReader.Close()
					_ = serverOutWriter.Close()
					return nil
				},
			}

			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			proxyService := NewProxyService(mockClient, proxy.NewPassthroughInterceptor(), logger)

			clientInReader, clientInWriter := io.Pipe()
			clientOutReader, clientOutWriter := io.Pipe()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			errCh := make(chan error, 1)
			go func() {
				errCh <- proxyService.Run(ctx, clientInReader, clientOutWriter)
			}()

			// Drain client output to prevent blocking
			go func() {
				buf := make([]byte, 4096)
				for {
					_, err := clientOutReader.Read(buf)
					if err != nil {
						return
					}
				}
			}()

			// Give proxy time to start
			time.Sleep(50 * time.Millisecond)

			// Send malformed message
			_, err := clientInWriter.Write([]byte(tc.message))
			if err != nil {
				t.Fatalf("write malformed message failed: %v", err)
			}

			// For non-empty messages, proxy may forward them (passthrough behavior)
			// Wait a bit to see if proxy handles it
			time.Sleep(100 * time.Millisecond)

			// Verify proxy is still running by sending a valid message
			validMsg := `{"jsonrpc":"2.0","method":"test","id":99}` + "\n"
			_, err = clientInWriter.Write([]byte(validMsg))
			if err != nil {
				t.Fatalf("write valid message failed: %v", err)
			}

			// Wait for server to receive the valid message (proves proxy is still working)
			timeout := time.After(2 * time.Second)
			for {
				select {
				case msg := <-serverReceived:
					if strings.Contains(msg, `"id":99`) {
						// Success - proxy forwarded valid message after malformed one
						goto cleanup
					}
					// Continue draining other messages
				case <-timeout:
					t.Fatal("timeout waiting for valid message to reach server")
				}
			}

		cleanup:
			// Clean shutdown
			_ = clientInWriter.Close()

			select {
			case <-errCh:
			case <-time.After(2 * time.Second):
				t.Fatal("timeout waiting for shutdown")
			}

			select {
			case <-serverDone:
			case <-time.After(1 * time.Second):
				t.Fatal("timeout waiting for server to exit")
			}

			if !mockClient.isClosed() {
				t.Error("expected mock client to be closed")
			}

			// Cleanup
			_ = clientInReader.Close()
			_ = clientOutReader.Close()
			_ = clientOutWriter.Close()
		})
	}
}
