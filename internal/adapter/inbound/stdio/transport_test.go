package stdio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/inbound"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"go.uber.org/goleak"
)

// Compile-time interface compliance check (runtime assertion).
var _ inbound.ProxyService = (*StdioTransport)(nil)

// mockMCPClient implements outbound.MCPClient for testing.
type mockMCPClient struct {
	startFunc func(ctx context.Context) (io.WriteCloser, io.ReadCloser, error)
	closeFunc func() error
	waitFunc  func() error

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

// writerWithCloseSignal wraps an io.WriteCloser and signals on close.
// Simulates how closing a process's stdin causes the process to exit.
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

// TestNewStdioTransport verifies construction returns non-nil with proper initialization.
func TestNewStdioTransport(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockClient := &mockMCPClient{}
	proxyService := service.NewProxyService(mockClient, proxy.NewPassthroughInterceptor(), logger)

	transport := NewStdioTransport(proxyService)
	if transport == nil {
		t.Fatal("expected non-nil transport")
		return
	}
	if transport.proxyService != proxyService {
		t.Error("expected proxyService to be set")
	}
}

// TestStdioTransport_Close verifies Close returns nil (no resources to clean up).
func TestStdioTransport_Close(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockClient := &mockMCPClient{}
	proxyService := service.NewProxyService(mockClient, proxy.NewPassthroughInterceptor(), logger)

	transport := NewStdioTransport(proxyService)
	err := transport.Close()
	if err != nil {
		t.Errorf("expected Close() to return nil, got: %v", err)
	}
}

// TestStdioTransport_InterfaceCompliance verifies StdioTransport satisfies the inbound.ProxyService interface.
func TestStdioTransport_InterfaceCompliance(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mockClient := &mockMCPClient{}
	proxyService := service.NewProxyService(mockClient, proxy.NewPassthroughInterceptor(), logger)

	transport := NewStdioTransport(proxyService)

	// Runtime type assertion (complements compile-time check at package level)
	var _ inbound.ProxyService = transport
}

// TestStdioTransport_Start_ContextCancellation verifies that Start returns when context is cancelled.
func TestStdioTransport_Start_ContextCancellation(t *testing.T) {
	defer goleak.VerifyNone(t)

	serverInReader, serverInWriter := io.Pipe()
	serverOutReader, serverOutWriter := io.Pipe()

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
	proxyService := service.NewProxyService(mockClient, proxy.NewPassthroughInterceptor(), logger)
	transport := NewStdioTransport(proxyService)

	// Save and restore os.Stdin/os.Stdout
	origStdin, origStdout := os.Stdin, os.Stdout
	defer func() { os.Stdin, os.Stdout = origStdin, origStdout }()

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	os.Stdin = stdinR
	os.Stdout = stdoutW

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- transport.Start(ctx)
	}()

	// Give transport time to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context
	cancel()

	// Close stdin to unblock scanner (simulates process termination behavior)
	_ = stdinW.Close()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for transport to stop after context cancellation")
	}

	if !mockClient.isClosed() {
		t.Error("expected mock client to be closed")
	}

	// Cleanup remaining pipes
	_ = stdinR.Close()
	_ = stdoutR.Close()
	_ = stdoutW.Close()
}

// TestStdioTransport_Start_MessageRouting verifies that Start proxies stdin data to upstream
// and routes upstream responses back to stdout via an echo server mock.
func TestStdioTransport_Start_MessageRouting(t *testing.T) {
	defer goleak.VerifyNone(t)

	serverInReader, serverInWriter := io.Pipe()
	serverOutReader, serverOutWriter := io.Pipe()

	// Echo server: reads from serverIn, writes back to serverOut
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		defer func() { _ = serverOutWriter.Close() }()
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
	proxyService := service.NewProxyService(mockClient, proxy.NewPassthroughInterceptor(), logger)
	transport := NewStdioTransport(proxyService)

	// Save and restore os.Stdin/os.Stdout
	origStdin, origStdout := os.Stdin, os.Stdout
	defer func() { os.Stdin, os.Stdout = origStdin, origStdout }()

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	os.Stdin = stdinR
	os.Stdout = stdoutW

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- transport.Start(ctx)
	}()

	// Send a JSON-RPC message via stdin
	testMsg := `{"jsonrpc":"2.0","method":"test/echo","id":1}` + "\n"
	if _, err := stdinW.Write([]byte(testMsg)); err != nil {
		t.Fatalf("write to stdin failed: %v", err)
	}

	// Read response from stdout
	responseCh := make(chan string, 1)
	go func() {
		buf := make([]byte, 0, 1024)
		tmp := make([]byte, 256)
		for {
			n, err := stdoutR.Read(tmp)
			if err != nil {
				responseCh <- string(buf)
				return
			}
			buf = append(buf, tmp[:n]...)
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
		t.Fatal("timeout waiting for echoed response on stdout")
	}

	// Clean shutdown
	_ = stdinW.Close()

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for transport shutdown")
	}

	select {
	case <-echoDone:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for echo server to exit")
	}

	if !mockClient.isClosed() {
		t.Error("expected mock client to be closed")
	}

	// Cleanup remaining pipes
	_ = stdinR.Close()
	_ = stdoutR.Close()
	_ = stdoutW.Close()
}

// TestStdioTransport_Start_SetsLocalIP verifies that Start sets "local" as the
// IP address in the context via proxy.IPAddressKey.
func TestStdioTransport_Start_SetsLocalIP(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Channel to capture the IP from context
	capturedIP := make(chan string, 1)

	// Custom interceptor that captures the IP address from context
	ipCapture := &ipCaptureInterceptor{captured: capturedIP}

	serverInReader, serverInWriter := io.Pipe()
	serverOutReader, serverOutWriter := io.Pipe()

	// Echo server: reads from serverIn, writes to serverOut.
	// Needed so the proxy's client->server write doesn't block.
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		defer func() { _ = serverOutWriter.Close() }()
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
			_ = serverOutReader.Close()
			_ = serverInReader.Close()
			_ = serverOutWriter.Close()
			return nil
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use ipCapture interceptor to verify context propagation
	proxyService := service.NewProxyService(mockClient, ipCapture, logger)
	transport := NewStdioTransport(proxyService)

	// Save and restore os.Stdin/os.Stdout
	origStdin, origStdout := os.Stdin, os.Stdout
	defer func() { os.Stdin, os.Stdout = origStdin, origStdout }()

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	os.Stdin = stdinR
	os.Stdout = stdoutW

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- transport.Start(ctx)
	}()

	// Drain stdout to prevent blocking on echo responses
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := stdoutR.Read(buf); err != nil {
				return
			}
		}
	}()

	// Send a message to trigger the interceptor
	testMsg := `{"jsonrpc":"2.0","method":"test","id":1}` + "\n"
	if _, err := stdinW.Write([]byte(testMsg)); err != nil {
		t.Fatalf("write to stdin failed: %v", err)
	}

	// Wait for interceptor to capture the IP
	select {
	case ip := <-capturedIP:
		if ip != "local" {
			t.Errorf("expected IP address 'local', got %q", ip)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for interceptor to capture IP address")
	}

	// Clean shutdown: close stdin triggers cascade through echo server
	_ = stdinW.Close()

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for transport shutdown")
	}

	select {
	case <-echoDone:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for echo server to exit")
	}

	if !mockClient.isClosed() {
		t.Error("expected mock client to be closed")
	}

	// Cleanup remaining pipes
	_ = stdinR.Close()
	_ = stdoutR.Close()
	_ = stdoutW.Close()
}

// TestStdioTransport_Start_ErrorResponse verifies that policy rejections
// produce JSON-RPC error responses on stdout.
func TestStdioTransport_Start_ErrorResponse(t *testing.T) {
	defer goleak.VerifyNone(t)

	serverInReader, serverInWriter := io.Pipe()
	serverOutReader, serverOutWriter := io.Pipe()

	// Track messages reaching server
	serverReceived := make(chan string, 10)
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
			select {
			case serverReceived <- string(buf[:n]):
			default:
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
	// Use rejecting interceptor
	interceptor := &rejectingInterceptor{rejectMethod: "tools/call"}
	proxyService := service.NewProxyService(mockClient, interceptor, logger)
	transport := NewStdioTransport(proxyService)

	// Save and restore os.Stdin/os.Stdout
	origStdin, origStdout := os.Stdin, os.Stdout
	defer func() { os.Stdin, os.Stdout = origStdin, origStdout }()

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	os.Stdin = stdinR
	os.Stdout = stdoutW

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- transport.Start(ctx)
	}()

	// Collect responses from stdout
	clientResponses := make(chan []byte, 10)
	go func() {
		accumulated := make([]byte, 0, 4096)
		buf := make([]byte, 4096)
		for {
			n, err := stdoutR.Read(buf)
			if err != nil {
				return
			}
			accumulated = append(accumulated, buf[:n]...)
			for {
				idx := bytes.IndexByte(accumulated, '\n')
				if idx == -1 {
					break
				}
				line := make([]byte, idx+1)
				copy(line, accumulated[:idx+1])
				accumulated = accumulated[idx+1:]
				clientResponses <- line
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)

	// Send a message that should be rejected
	rejectedMsg := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"test"},"id":1}` + "\n"
	if _, err := stdinW.Write([]byte(rejectedMsg)); err != nil {
		t.Fatalf("write rejected message failed: %v", err)
	}

	// Read error response
	var errorResponse []byte
	select {
	case resp := <-clientResponses:
		errorResponse = resp
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for error response")
	}

	// Verify it's a JSON-RPC error
	var rpcResp struct {
		JSONRPC string `json:"jsonrpc"`
		Error   *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		ID interface{} `json:"id"`
	}
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
		// Expected
	}

	// Clean shutdown
	_ = stdinW.Close()

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for transport shutdown")
	}

	select {
	case <-serverDone:
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for server to exit")
	}

	if !mockClient.isClosed() {
		t.Error("expected mock client to be closed")
	}

	// Cleanup remaining pipes
	_ = stdinR.Close()
	_ = stdoutR.Close()
	_ = stdoutW.Close()
}

// --- Helper interceptors ---

// ipCaptureInterceptor captures the IP address from context and forwards the message.
type ipCaptureInterceptor struct {
	captured chan<- string
	once     sync.Once
}

func (i *ipCaptureInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	i.once.Do(func() {
		ip, _ := ctx.Value(proxy.IPAddressKey).(string)
		select {
		case i.captured <- ip:
		default:
		}
	})
	return msg, nil
}

// rejectingInterceptor rejects messages with a specific method.
type rejectingInterceptor struct {
	rejectMethod string
}

func (r *rejectingInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	if msg.Decoded != nil {
		if req, ok := msg.Decoded.(*jsonrpc.Request); ok {
			if req.Method == r.rejectMethod {
				return nil, proxy.ErrPolicyDenied
			}
		}
	}
	return msg, nil
}
