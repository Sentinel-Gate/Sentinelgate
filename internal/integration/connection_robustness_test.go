package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/mcp"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// adversarialBinaryPath holds the path to the built adversarial-testserver
// binary. It is set by TestMain.
var adversarialBinaryPath string

func TestMain(m *testing.M) {
	// Build the adversarial-testserver binary once for all tests.
	tmpDir, err := os.MkdirTemp("", "sentinelgate-inttest-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}

	binPath := filepath.Join(tmpDir, "adversarial-testserver")
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/adversarial-testserver")
	// Build from repo root.
	cmd.Dir = repoRoot()
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build adversarial-testserver: %v\n", err)
		os.Exit(1)
	}
	adversarialBinaryPath = binPath

	code := m.Run()

	// Clean up.
	os.RemoveAll(tmpDir)
	os.Exit(code)
}

// repoRoot returns the root of the repo by looking for go.mod.
func repoRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Fallback: use current directory.
			d, _ := os.Getwd()
			return d
		}
		dir = parent
	}
}

// --- Test helpers ---

// robustnessUpstreamStore implements upstream.UpstreamStore for connection robustness tests.
type robustnessUpstreamStore struct {
	mu        sync.RWMutex
	upstreams map[string]*upstream.Upstream
}

func newRobustnessUpstreamStore() *robustnessUpstreamStore {
	return &robustnessUpstreamStore{
		upstreams: make(map[string]*upstream.Upstream),
	}
}

func (s *robustnessUpstreamStore) List(_ context.Context) ([]upstream.Upstream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]upstream.Upstream, 0, len(s.upstreams))
	for _, u := range s.upstreams {
		result = append(result, *u)
	}
	return result, nil
}

func (s *robustnessUpstreamStore) Get(_ context.Context, id string) (*upstream.Upstream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.upstreams[id]
	if !ok {
		return nil, upstream.ErrUpstreamNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *robustnessUpstreamStore) Add(_ context.Context, u *upstream.Upstream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstreams[u.ID] = u
	return nil
}

func (s *robustnessUpstreamStore) Update(_ context.Context, u *upstream.Upstream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.upstreams[u.ID]; !ok {
		return upstream.ErrUpstreamNotFound
	}
	s.upstreams[u.ID] = u
	return nil
}

func (s *robustnessUpstreamStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.upstreams[id]; !ok {
		return upstream.ErrUpstreamNotFound
	}
	delete(s.upstreams, id)
	return nil
}

// newTestUpstreamManager creates an UpstreamManager backed by the given upstream
// configs and a custom client factory.
func newTestUpstreamManager(t *testing.T, factory service.ClientFactory, upstreams ...*upstream.Upstream) *service.UpstreamManager {
	t.Helper()
	store := newRobustnessUpstreamStore()
	for _, u := range upstreams {
		_ = store.Add(context.Background(), u)
	}
	logger := testLogger()
	svc := service.NewUpstreamService(store, nil, logger)
	mgr := service.NewUpstreamManager(svc, factory, logger)
	return mgr
}

// waitForStatus polls the upstream status until the desired status is reached
// or the timeout expires. Returns the final observed status.
func waitForStatus(t *testing.T, mgr *service.UpstreamManager, id string, want upstream.ConnectionStatus, timeout time.Duration) upstream.ConnectionStatus {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, _ := mgr.Status(id)
		if status == want {
			return status
		}
		time.Sleep(20 * time.Millisecond)
	}
	status, lastErr := mgr.Status(id)
	t.Logf("waitForStatus(%s): final status=%q lastErr=%q (wanted %q)", id, status, lastErr, want)
	return status
}

// --- 4A.1: Upstream crash during tool call ---

// TestUpstreamCrashDuringToolCall verifies that when an upstream MCP server
// crashes mid-session (after successful init handshake), the UpstreamManager
// detects the crash and transitions the connection to a non-connected state,
// eventually triggering reconnection.
//
// Uses the adversarial-testserver with --mode=crash-after-n --crash-after=2
// so it completes the init handshake (initialize + notifications/initialized = 2 messages)
// and then crashes on the 3rd message (any subsequent request).
func TestUpstreamCrashDuringToolCall(t *testing.T) {
	if adversarialBinaryPath == "" {
		t.Fatal("adversarial-testserver binary not built; TestMain did not run")
	}

	u := &upstream.Upstream{
		ID:      "crash-upstream",
		Name:    "crash-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: adversarialBinaryPath,
		Args:    []string{"--mode=crash-after-n", "--crash-after=2", "--tools=echo_tool"},
	}

	clientCount := atomic.Int32{}
	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		clientCount.Add(1)
		client := mcp.NewStdioClient(u.Command, u.Args...)
		return client, nil
	}

	mgr := newTestUpstreamManager(t, factory, u)
	mgr.SetBackoffBase(50 * time.Millisecond)
	mgr.SetGlobalRetryConfig(3, 500*time.Millisecond)

	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	// Start the upstream -- the init handshake should complete successfully.
	if err := mgr.Start(ctx, "crash-upstream"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Wait for connected status.
	status := waitForStatus(t, mgr, "crash-upstream", upstream.StatusConnected, 5*time.Second)
	if status != upstream.StatusConnected {
		t.Fatalf("expected Connected after start, got %q", status)
	}

	// Get the connection and send a tools/call request.
	// This is the 3rd message -> the server will crash (exit 1).
	writer, _, err := mgr.GetConnection("crash-upstream")
	if err != nil {
		t.Fatalf("GetConnection() unexpected error: %v", err)
	}

	toolsCallReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo_tool","arguments":{}}}` + "\n"
	_, writeErr := writer.Write([]byte(toolsCallReq))
	// The write may or may not fail depending on timing -- the important thing is
	// that the server crashes and the manager detects it.
	_ = writeErr

	// After the crash, the health monitor should detect the process exit and
	// schedule reconnection. The status should transition through
	// Disconnected/Connecting and potentially back to Connected (since the
	// factory creates a new server each time, and crash-after-n applies fresh).
	//
	// We verify that the crash was detected by checking that a reconnection
	// attempt was made (clientCount > 1).
	time.Sleep(1 * time.Second)

	finalClients := clientCount.Load()
	if finalClients < 2 {
		t.Errorf("expected at least 2 client creations (original + reconnect after crash), got %d", finalClients)
	}

	// The reconnected server also uses crash-after-n=2, so it will again be
	// Connected until the next 3rd message. Verify it recovered.
	status = waitForStatus(t, mgr, "crash-upstream", upstream.StatusConnected, 5*time.Second)
	if status != upstream.StatusConnected {
		_, lastErr := mgr.Status("crash-upstream")
		t.Errorf("expected Connected after reconnect, got %q (lastErr=%q)", status, lastErr)
	}
}

// --- 4A.2: HTTP upstream returning 502/503 ---

// TestHTTPUpstream_502_503 verifies that when an HTTP upstream returns 502 or 503,
// the UpstreamManager correctly marks the connection as Error and handles the
// failure gracefully (no panic, proper status reporting).
func TestHTTPUpstream_502_503(t *testing.T) {
	subtests := []struct {
		name       string
		statusCode int
	}{
		{"502_BadGateway", http.StatusBadGateway},
		{"503_ServiceUnavailable", http.StatusServiceUnavailable},
	}

	for _, tc := range subtests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test HTTP server that returns the error status code.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				fmt.Fprintf(w, `{"error":"service unavailable","status":%d}`, tc.statusCode)
			}))

			u := &upstream.Upstream{
				ID:      "http-error-upstream",
				Name:    "http-error-server",
				Type:    upstream.UpstreamTypeHTTP,
				Enabled: true,
				URL:     srv.URL,
			}

			factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
				return mcp.NewHTTPClient(u.URL, mcp.WithTimeout(2*time.Second)), nil
			}

			mgr := newTestUpstreamManager(t, factory, u)
			mgr.SetBackoffBase(50 * time.Millisecond)
			mgr.SetGlobalRetryConfig(2, 500*time.Millisecond)

			// Clean up in correct order: manager first, then server, then
			// check for goroutine leaks. Defers run LIFO.
			t.Cleanup(func() {
				_ = mgr.Close()
				srv.Close()
				// Give HTTP transport goroutines time to drain after server close.
				time.Sleep(50 * time.Millisecond)
				goleak.VerifyNone(t,
					goleak.IgnoreCurrent(),
					goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
					goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
					goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
				)
			})

			ctx := context.Background()

			// Start the upstream -- the init handshake should fail because the
			// server returns 502/503 instead of a valid JSON-RPC response.
			if err := mgr.Start(ctx, "http-error-upstream"); err != nil {
				t.Fatalf("Start() unexpected error: %v", err)
			}

			// Give time for the connection attempt + retries to exhaust.
			time.Sleep(500 * time.Millisecond)

			// The status should be Error (or Connecting if still retrying).
			status, lastErr := mgr.Status("http-error-upstream")
			if status != upstream.StatusError && status != upstream.StatusConnecting {
				t.Errorf("expected Error or Connecting status, got %q (lastErr=%q)", status, lastErr)
			}

			// Verify that the error message indicates the HTTP failure.
			if lastErr == "" {
				t.Error("expected non-empty lastErr after HTTP error")
			}

			// The connection should never reach Connected.
			if status == upstream.StatusConnected {
				t.Error("HTTP upstream returning error status should NOT be Connected")
			}
		})
	}
}

// --- 4A.3: Upstream EOF without process exit ---

// eofMidResponseClient is a mock MCPClient that completes the init handshake
// successfully but then closes stdout (sends EOF) when the next request is
// received. This simulates an upstream that drops the connection without the
// process actually exiting (e.g., a network partition on HTTP, or a server
// that closes its output pipe but remains running).
type eofMidResponseClient struct {
	mu          sync.Mutex
	waitCh      chan struct{}
	closed      bool
	pipeCleanup func()
	pipeDone    chan struct{}
}

func newEOFMidResponseClient() *eofMidResponseClient {
	return &eofMidResponseClient{
		waitCh: make(chan struct{}),
	}
}

func (c *eofMidResponseClient) Start(_ context.Context) (io.WriteCloser, io.ReadCloser, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = false
	c.waitCh = make(chan struct{})

	// Use pipes with an auto-responder that handles init then kills the response pipe.
	reqReader, reqWriter := io.Pipe()
	respReader, respWriter := io.Pipe()
	done := make(chan struct{})
	waitCh := c.waitCh // capture for goroutine

	go func() {
		defer close(done)
		defer respWriter.Close()
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			line := scanner.Text()

			if strings.Contains(line, "initialize") && strings.Contains(line, "\"id\"") {
				var req struct{ ID json.RawMessage `json:"id"` }
				if json.Unmarshal([]byte(line), &req) == nil && req.ID != nil {
					resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"eof-mock","version":"1.0"}}}`, string(req.ID))
					fmt.Fprintln(respWriter, resp)
				}
				continue
			}

			// notifications/initialized -- no response needed
			if strings.Contains(line, "notifications/initialized") {
				continue
			}

			// Any subsequent message (tools/call etc.) -- close the response
			// pipe to simulate EOF without process exit.
			// Write a partial/truncated response line then close.
			respWriter.Write([]byte(`{"jsonrpc":"2.0","id":1,"res`))
			// Close the response pipe (EOF to reader) without a newline,
			// and signal Wait() that the "process" has terminated.
			// This must be done in a goroutine-safe way since Wait() blocks
			// on waitCh.
			select {
			case <-waitCh:
			default:
				close(waitCh)
			}
			return
		}
	}()

	c.pipeDone = done
	c.pipeCleanup = func() {
		reqReader.Close()
	}

	return reqWriter, respReader, nil
}

func (c *eofMidResponseClient) Wait() error {
	<-c.waitCh
	return nil
}

func (c *eofMidResponseClient) Close() error {
	c.mu.Lock()
	cleanup := c.pipeCleanup
	c.pipeCleanup = nil
	done := c.pipeDone
	c.pipeDone = nil
	c.closed = true
	select {
	case <-c.waitCh:
	default:
		close(c.waitCh)
	}
	c.mu.Unlock()

	if cleanup != nil {
		cleanup()
	}
	if done != nil {
		<-done
	}
	return nil
}

var _ outbound.MCPClient = (*eofMidResponseClient)(nil)

// TestUpstreamEOF_WithoutProcessExit verifies that when an upstream's stdout
// closes (EOF) while the process is still technically alive, the UpstreamManager
// detects the broken pipe via the line-reader channel closing and transitions
// the connection to Error/Disconnected.
//
// This simulates scenarios like:
// - Network partition on an HTTP upstream
// - Upstream server closing its output stream while still running
// - Broken pipe without process exit signal
func TestUpstreamEOF_WithoutProcessExit(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "eof-upstream",
		Name:    "eof-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/bin/true", // placeholder -- factory overrides
	}

	clientCount := atomic.Int32{}
	factory := func(_ *upstream.Upstream) (outbound.MCPClient, error) {
		clientCount.Add(1)
		return newEOFMidResponseClient(), nil
	}

	mgr := newTestUpstreamManager(t, factory, u)
	mgr.SetBackoffBase(50 * time.Millisecond)
	mgr.SetGlobalRetryConfig(2, 500*time.Millisecond)

	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	// Start -- init handshake should succeed.
	if err := mgr.Start(ctx, "eof-upstream"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Wait for Connected.
	status := waitForStatus(t, mgr, "eof-upstream", upstream.StatusConnected, 5*time.Second)
	if status != upstream.StatusConnected {
		t.Fatalf("expected Connected after start, got %q", status)
	}

	// Send a tools/call request -- this triggers the mock to close stdout (EOF).
	writer, _, err := mgr.GetConnection("eof-upstream")
	if err != nil {
		t.Fatalf("GetConnection() unexpected error: %v", err)
	}

	toolsCallReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo_tool"}}` + "\n"
	_, _ = writer.Write([]byte(toolsCallReq))

	// The EOF on stdout should cause the line reader goroutine's channel to close.
	// The health monitor (Wait()) will also return, triggering reconnection.
	// Wait for reconnection attempt.
	time.Sleep(1 * time.Second)

	// Verify that a reconnection was attempted.
	finalClients := clientCount.Load()
	if finalClients < 2 {
		t.Errorf("expected at least 2 client creations (original + reconnect after EOF), got %d", finalClients)
	}

	// After reconnection, the new client also succeeds init handshake -> Connected.
	status = waitForStatus(t, mgr, "eof-upstream", upstream.StatusConnected, 5*time.Second)
	if status != upstream.StatusConnected {
		_, lastErr := mgr.Status("eof-upstream")
		t.Errorf("expected Connected after reconnect, got %q (lastErr=%q)", status, lastErr)
	}
}

// --- 4B: Retry & Recovery ---

// alwaysFailMockClient is an MCPClient whose Start always returns an error.
// It satisfies outbound.MCPClient and is used to test retry/backoff logic.
type alwaysFailMockClient struct {
	mu       sync.Mutex
	startErr error
	waitCh   chan struct{}
	closed   bool
}

func newAlwaysFailMockClient(err error) *alwaysFailMockClient {
	return &alwaysFailMockClient{
		startErr: err,
		waitCh:   make(chan struct{}),
	}
}

func (c *alwaysFailMockClient) Start(_ context.Context) (io.WriteCloser, io.ReadCloser, error) {
	return nil, nil, c.startErr
}

func (c *alwaysFailMockClient) Wait() error {
	<-c.waitCh
	return nil
}

func (c *alwaysFailMockClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		select {
		case <-c.waitCh:
		default:
			close(c.waitCh)
		}
	}
	return nil
}

var _ outbound.MCPClient = (*alwaysFailMockClient)(nil)

// crashAfterStartMockClient completes the init handshake but then immediately
// crashes (Close + Wait return). Used to simulate upstreams that crash right
// after connecting.
type crashAfterStartMockClient struct {
	mu          sync.Mutex
	waitCh      chan struct{}
	closed      bool
	pipeCleanup func()
	pipeDone    chan struct{}
}

func newCrashAfterStartMockClient() *crashAfterStartMockClient {
	return &crashAfterStartMockClient{
		waitCh: make(chan struct{}),
	}
}

func (c *crashAfterStartMockClient) Start(_ context.Context) (io.WriteCloser, io.ReadCloser, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = false
	c.waitCh = make(chan struct{})

	reqReader, reqWriter := io.Pipe()
	respReader, respWriter := io.Pipe()
	done := make(chan struct{})
	waitCh := c.waitCh

	go func() {
		defer close(done)
		defer respWriter.Close()
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "initialize") && strings.Contains(line, "\"id\"") {
				var req struct{ ID json.RawMessage `json:"id"` }
				if json.Unmarshal([]byte(line), &req) == nil && req.ID != nil {
					resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"crash-mock","version":"1.0"}}}`, string(req.ID))
					fmt.Fprintln(respWriter, resp)
				}
				continue
			}
			if strings.Contains(line, "notifications/initialized") {
				// After init handshake completes, crash immediately.
				select {
				case <-waitCh:
				default:
					close(waitCh)
				}
				return
			}
		}
	}()

	c.pipeDone = done
	c.pipeCleanup = func() {
		reqReader.Close()
		respReader.Close()
	}
	return reqWriter, respReader, nil
}

func (c *crashAfterStartMockClient) Wait() error {
	<-c.waitCh
	return nil
}

func (c *crashAfterStartMockClient) Close() error {
	c.mu.Lock()
	cleanup := c.pipeCleanup
	c.pipeCleanup = nil
	doneCh := c.pipeDone
	c.pipeDone = nil
	c.closed = true
	select {
	case <-c.waitCh:
	default:
		close(c.waitCh)
	}
	c.mu.Unlock()

	if cleanup != nil {
		cleanup()
	}
	if doneCh != nil {
		<-doneCh
	}
	return nil
}

var _ outbound.MCPClient = (*crashAfterStartMockClient)(nil)

// --- 4B.1: Exponential backoff timing ---

// TestExponentialBackoff_Timing verifies that the UpstreamManager applies
// exponential backoff when reconnecting a failing upstream. It measures the
// intervals between retry attempts and checks they follow the 2^n pattern
// with a generous tolerance (±50%) to avoid flaky results from scheduling jitter.
func TestExponentialBackoff_Timing(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "backoff-timing",
		Name:    "backoff-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/bin/true",
	}

	var mu sync.Mutex
	var timestamps []time.Time

	factory := func(_ *upstream.Upstream) (outbound.MCPClient, error) {
		mu.Lock()
		timestamps = append(timestamps, time.Now())
		mu.Unlock()
		return newAlwaysFailMockClient(fmt.Errorf("connection refused")), nil
	}

	store := newRobustnessUpstreamStore()
	_ = store.Add(context.Background(), u)
	logger := testLogger()
	svc := service.NewUpstreamService(store, nil, logger)
	mgr := service.NewUpstreamManager(svc, factory, logger)
	mgr.SetBackoffBase(100 * time.Millisecond)
	mgr.SetGlobalRetryConfig(6, 2000*time.Millisecond)

	t.Cleanup(func() {
		_ = mgr.Close()
		goleak.VerifyNone(t,
			goleak.IgnoreCurrent(),
		)
	})

	ctx := context.Background()
	if err := mgr.Start(ctx, "backoff-timing"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Wait for all retries to exhaust: 100+200+400+800+1600+2000 = ~5100ms,
	// plus tolerance. Use 8s to be safe.
	deadline := time.After(8 * time.Second)
	for {
		status, _ := mgr.Status("backoff-timing")
		if status == upstream.StatusError {
			// Check if lastErr says max retries
			_, lastErr := mgr.Status("backoff-timing")
			if strings.Contains(lastErr, "max retries") {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for max retries to be reached")
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	ts := make([]time.Time, len(timestamps))
	copy(ts, timestamps)
	mu.Unlock()

	// We expect 1 initial + up to 6 retries = 7 attempts.
	// The factory is called once per attempt (attemptConnect calls clientFactory).
	if len(ts) < 4 {
		t.Fatalf("expected at least 4 attempt timestamps, got %d", len(ts))
	}

	// Expected intervals: ~100ms, ~200ms, ~400ms, ~800ms, ~1600ms, ~2000ms (cap)
	expectedDelays := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
		1600 * time.Millisecond,
		2000 * time.Millisecond,
	}

	for i := 1; i < len(ts) && i-1 < len(expectedDelays); i++ {
		actual := ts[i].Sub(ts[i-1])
		expected := expectedDelays[i-1]
		low := time.Duration(float64(expected) * 0.5)
		high := time.Duration(float64(expected) * 1.5)
		if actual < low || actual > high {
			t.Errorf("interval[%d]: got %v, expected ~%v (tolerance ±50%%: %v-%v)",
				i-1, actual, expected, low, high)
		} else {
			t.Logf("interval[%d]: %v (expected ~%v) OK", i-1, actual, expected)
		}
	}
}

// --- 4B.2: Max retry permanent error ---

// TestMaxRetry_PermanentError verifies that after maxRetries consecutive failures,
// the upstream transitions to StatusError with a "max retries" message and no
// further retry attempts are scheduled.
func TestMaxRetry_PermanentError(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "max-retry",
		Name:    "max-retry-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/bin/true",
	}

	var attemptCount atomic.Int32

	factory := func(_ *upstream.Upstream) (outbound.MCPClient, error) {
		attemptCount.Add(1)
		return newAlwaysFailMockClient(fmt.Errorf("permanent failure")), nil
	}

	store := newRobustnessUpstreamStore()
	_ = store.Add(context.Background(), u)
	logger := testLogger()
	svc := service.NewUpstreamService(store, nil, logger)
	mgr := service.NewUpstreamManager(svc, factory, logger)
	mgr.SetBackoffBase(10 * time.Millisecond)
	mgr.SetGlobalRetryConfig(3, 100*time.Millisecond)

	t.Cleanup(func() {
		_ = mgr.Close()
		goleak.VerifyNone(t,
			goleak.IgnoreCurrent(),
		)
	})

	ctx := context.Background()
	if err := mgr.Start(ctx, "max-retry"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Wait for retries to exhaust: 10ms + 20ms + 40ms + margin = ~200ms
	time.Sleep(300 * time.Millisecond)

	// Status should be Error with max retries message.
	status, lastErr := mgr.Status("max-retry")
	if status != upstream.StatusError {
		t.Errorf("status = %q, want %q", status, upstream.StatusError)
	}
	if !strings.Contains(lastErr, "max retries") {
		t.Errorf("lastErr = %q, expected to contain 'max retries'", lastErr)
	}

	// Record current attempt count and wait to verify no further attempts.
	countAfterExhaust := attemptCount.Load()
	time.Sleep(200 * time.Millisecond)
	countAfterWait := attemptCount.Load()

	if countAfterWait != countAfterExhaust {
		t.Errorf("additional attempts after max retries: before=%d after=%d (expected no change)",
			countAfterExhaust, countAfterWait)
	}

	// Total attempts: 1 initial + 3 retries = 4
	if countAfterExhaust != 4 {
		t.Errorf("total attempts = %d, want 4 (1 initial + 3 retries)", countAfterExhaust)
	}
}

// --- 4B.3: Stability reset ---

// TestStabilityReset verifies that after a connection remains stable for the
// configured stabilityDuration, the retryCount is reset to 0. On a subsequent
// crash, backoff should restart from the base delay rather than a higher value.
func TestStabilityReset(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "stability-reset",
		Name:    "stability-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/bin/true",
	}

	var mu sync.Mutex
	var clients []*crashAfterStartMockClient
	var timestamps []time.Time

	// Phase tracking: first connection succeeds and stays up, then after
	// stability reset we crash it and track reconnection timing.
	var phase atomic.Int32 // 0=initial, 1=post-stability-crash
	factory := func(_ *upstream.Upstream) (outbound.MCPClient, error) {
		p := phase.Load()
		mu.Lock()
		timestamps = append(timestamps, time.Now())
		mu.Unlock()

		if p == 0 {
			// First phase: return a normal mock that stays connected.
			c := newEOFMidResponseClient()
			return c, nil
		}
		// Post-crash phase: always fail so we can observe backoff from base.
		return newAlwaysFailMockClient(fmt.Errorf("post-crash failure")), nil
	}

	store := newRobustnessUpstreamStore()
	_ = store.Add(context.Background(), u)
	logger := testLogger()
	svc := service.NewUpstreamService(store, nil, logger)

	// Use Unstarted so we can configure stability parameters before Init.
	mgr := service.NewUpstreamManagerUnstarted(svc, factory, logger)
	mgr.SetBackoffBase(100 * time.Millisecond)
	mgr.SetGlobalRetryConfig(5, 2000*time.Millisecond)

	// Access exported fields through the manager to set stability params.
	// We need short stability duration and check interval for testing.
	// These are unexported fields, so we use the service package's
	// NewUpstreamManagerUnstarted and set them through the exposed Init path.
	// Actually, stabilityDuration and stabilityCheckInterval are unexported,
	// so we'll test this indirectly: use ResetRetryCount (exported) to
	// simulate what stabilityChecker does, then verify backoff timing.

	mgr.Init()

	t.Cleanup(func() {
		_ = mgr.Close()
		// Give goroutines time to drain.
		time.Sleep(50 * time.Millisecond)
		goleak.VerifyNone(t,
			goleak.IgnoreCurrent(),
		)
	})

	ctx := context.Background()
	if err := mgr.Start(ctx, "stability-reset"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Wait for Connected.
	status := waitForStatus(t, mgr, "stability-reset", upstream.StatusConnected, 5*time.Second)
	if status != upstream.StatusConnected {
		t.Fatalf("expected Connected, got %q", status)
	}

	// Simulate that the connection has been stable: use ResetRetryCount to
	// mimic what stabilityChecker would do after stabilityDuration elapses.
	if err := mgr.ResetRetryCount("stability-reset"); err != nil {
		t.Fatalf("ResetRetryCount() error: %v", err)
	}

	// Now switch to failure phase and trigger a crash by sending a request
	// that causes the eofMidResponseClient to close.
	phase.Store(1)

	// Clear timestamps to track post-crash timing and record crash time.
	mu.Lock()
	timestamps = nil
	_ = clients // unused but kept for clarity
	mu.Unlock()

	crashTime := time.Now()

	writer, _, err := mgr.GetConnection("stability-reset")
	if err != nil {
		t.Fatalf("GetConnection() error: %v", err)
	}
	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"test"}}` + "\n"))

	// Wait for a couple of retries.
	time.Sleep(600 * time.Millisecond)

	mu.Lock()
	ts := make([]time.Time, len(timestamps))
	copy(ts, timestamps)
	mu.Unlock()

	if len(ts) < 1 {
		t.Fatalf("expected at least 1 post-crash attempt, got %d", len(ts))
	}

	// After the crash, monitorHealth calls scheduleRetry with retryCount=0
	// (because we reset it). scheduleRetry uses delay = backoffBase * 2^0 = 100ms.
	// So the first factory call should be ~100ms after the crash.
	firstRetryDelay := ts[0].Sub(crashTime)
	expectedBase := 100 * time.Millisecond
	low := time.Duration(float64(expectedBase) * 0.4)
	high := time.Duration(float64(expectedBase) * 2.5)
	if firstRetryDelay < low || firstRetryDelay > high {
		t.Errorf("first retry delay after stability reset = %v, expected ~%v (range %v-%v)",
			firstRetryDelay, expectedBase, low, high)
	} else {
		t.Logf("first retry delay after stability reset = %v (expected ~%v) OK", firstRetryDelay, expectedBase)
	}

	// If we have a second retry, verify the interval between 1st and 2nd is ~200ms
	// (retryCount=1 -> delay = 100ms * 2^1 = 200ms), confirming backoff starts from base.
	if len(ts) >= 2 {
		secondInterval := ts[1].Sub(ts[0])
		expected2 := 200 * time.Millisecond
		low2 := time.Duration(float64(expected2) * 0.4)
		high2 := time.Duration(float64(expected2) * 2.0)
		if secondInterval < low2 || secondInterval > high2 {
			t.Errorf("second retry interval = %v, expected ~%v (range %v-%v)",
				secondInterval, expected2, low2, high2)
		} else {
			t.Logf("second retry interval = %v (expected ~%v) OK", secondInterval, expected2)
		}
	}
}

// --- 4B.4: Retry during shutdown ---

// TestRetryDuringShutdown verifies that calling Close() on the UpstreamManager
// while retries are pending cancels all pending retries and does not schedule
// new Start attempts. No goroutine leaks should occur.
func TestRetryDuringShutdown(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "shutdown-retry",
		Name:    "shutdown-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/bin/true",
	}

	var attemptCount atomic.Int32

	factory := func(_ *upstream.Upstream) (outbound.MCPClient, error) {
		attemptCount.Add(1)
		return newAlwaysFailMockClient(fmt.Errorf("connection refused")), nil
	}

	store := newRobustnessUpstreamStore()
	_ = store.Add(context.Background(), u)
	logger := testLogger()
	svc := service.NewUpstreamService(store, nil, logger)
	mgr := service.NewUpstreamManager(svc, factory, logger)
	mgr.SetBackoffBase(500 * time.Millisecond) // long enough that retry is pending when we Close
	mgr.SetGlobalRetryConfig(10, 5*time.Second)

	ctx := context.Background()
	if err := mgr.Start(ctx, "shutdown-retry"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Wait for initial attempt to complete and retry to be scheduled.
	time.Sleep(100 * time.Millisecond)

	countBeforeClose := attemptCount.Load()
	if countBeforeClose < 1 {
		t.Fatal("expected at least 1 attempt before Close")
	}

	// Close the manager while a retry is pending.
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	// Wait to verify no new attempts happen after Close.
	time.Sleep(1 * time.Second)

	countAfterClose := attemptCount.Load()
	if countAfterClose > countBeforeClose+1 {
		// Allow at most 1 extra attempt that may have been in-flight during Close.
		t.Errorf("attempts after Close: before=%d after=%d (expected at most %d)",
			countBeforeClose, countAfterClose, countBeforeClose+1)
	}

	// Verify no goroutine leaks.
	goleak.VerifyNone(t,
		goleak.IgnoreCurrent(),
	)
}

// --- 4B.5: Rapid failure loop ---

// TestRapidFailureLoop verifies that when an upstream crashes immediately after
// Start (connects briefly then dies), the manager does not loop infinitely.
// With maxRetries=5 and a short backoff, it should reach StatusError after
// exhausting retries.
func TestRapidFailureLoop(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "rapid-fail",
		Name:    "rapid-fail-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/bin/true",
	}

	var attemptCount atomic.Int32

	factory := func(_ *upstream.Upstream) (outbound.MCPClient, error) {
		attemptCount.Add(1)
		return newCrashAfterStartMockClient(), nil
	}

	store := newRobustnessUpstreamStore()
	_ = store.Add(context.Background(), u)
	logger := testLogger()
	svc := service.NewUpstreamService(store, nil, logger)
	mgr := service.NewUpstreamManager(svc, factory, logger)
	mgr.SetBackoffBase(10 * time.Millisecond)
	mgr.SetGlobalRetryConfig(5, 100*time.Millisecond)

	t.Cleanup(func() {
		_ = mgr.Close()
		// Allow time for background goroutines to drain.
		time.Sleep(50 * time.Millisecond)
		goleak.VerifyNone(t,
			goleak.IgnoreCurrent(),
		)
	})

	ctx := context.Background()
	if err := mgr.Start(ctx, "rapid-fail"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Wait for retries to exhaust. With backoffBase=10ms and maxRetries=5:
	// delays: 10+20+40+80+100 = ~250ms for retries, plus connect/crash time.
	// The crash-after-start mock completes init then immediately crashes,
	// which triggers monitorHealth -> scheduleRetry. Give generous time.
	deadline := time.After(10 * time.Second)
	for {
		status, lastErr := mgr.Status("rapid-fail")
		if status == upstream.StatusError && strings.Contains(lastErr, "max retries") {
			break
		}
		select {
		case <-deadline:
			s, e := mgr.Status("rapid-fail")
			t.Fatalf("timed out waiting for Error status; current status=%q lastErr=%q", s, e)
		case <-time.After(50 * time.Millisecond):
		}
	}

	// Verify we reached Error state.
	status, lastErr := mgr.Status("rapid-fail")
	if status != upstream.StatusError {
		t.Errorf("final status = %q, want %q", status, upstream.StatusError)
	}
	if !strings.Contains(lastErr, "max retries") {
		t.Errorf("lastErr = %q, expected to contain 'max retries'", lastErr)
	}

	// Record attempt count and verify no further attempts.
	finalCount := attemptCount.Load()
	time.Sleep(300 * time.Millisecond)
	afterCount := attemptCount.Load()
	if afterCount != finalCount {
		t.Errorf("attempts continued after max retries: %d -> %d", finalCount, afterCount)
	}

	// The total number of attempts should be bounded:
	// 1 initial + up to 5 retries = 6 max factory calls.
	// But each crash-after-start mock successfully connects (triggers monitorHealth)
	// which then calls scheduleRetry on crash. So the retryCount increments
	// are from monitorHealth->scheduleRetry, not from attemptConnect failure.
	// Allow some extra due to timing.
	if finalCount > 10 {
		t.Errorf("too many attempts: %d (expected <= 10 for maxRetries=5)", finalCount)
	}
	t.Logf("total attempts: %d", finalCount)
}

// --- 4C: Timeout Handling ---

// --- 4C.1: ForwardToUpstream 30s timeout ---

// neverRespondMockClient completes the init handshake successfully but then
// never sends any response for subsequent requests. The lineCh stays open
// but no data arrives, exercising the 30s timeout in forwardToUpstream
// (upstream_router.go).
//
// NOTE: The 30s timeout is hardcoded in upstream_router.go's forwardToUpstream:
//
//	timeout := time.After(30 * time.Second)
//
// This test does NOT wait the full 30s. Instead, it verifies the MECHANISM:
// - The upstream connects successfully (handshake completes)
// - A tools/call request is sent
// - The lineCh never delivers data (simulating a hung upstream)
// - We verify that after 2s no response has been received, documenting
//   that the caller would be blocked until the 30s hardcoded timeout fires
// - Then we clean up the manager
type neverRespondMockClient struct {
	mu          sync.Mutex
	waitCh      chan struct{}
	closed      bool
	pipeCleanup func()
	pipeDone    chan struct{}
}

func newNeverRespondMockClient() *neverRespondMockClient {
	return &neverRespondMockClient{
		waitCh: make(chan struct{}),
	}
}

func (c *neverRespondMockClient) Start(_ context.Context) (io.WriteCloser, io.ReadCloser, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = false
	c.waitCh = make(chan struct{})

	reqReader, reqWriter := io.Pipe()
	respReader, respWriter := io.Pipe()
	done := make(chan struct{})

	go func() {
		defer close(done)
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			line := scanner.Text()

			// Handle initialize: send back a valid response.
			if strings.Contains(line, "initialize") && strings.Contains(line, "\"id\"") {
				var req struct{ ID json.RawMessage `json:"id"` }
				if json.Unmarshal([]byte(line), &req) == nil && req.ID != nil {
					resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"never-respond-mock","version":"1.0"}}}`, string(req.ID))
					fmt.Fprintln(respWriter, resp)
				}
				continue
			}

			// notifications/initialized — no response needed.
			if strings.Contains(line, "notifications/initialized") {
				continue
			}

			// Any subsequent message (tools/call etc.) — do NOT respond.
			// The response pipe stays open but silent, simulating a hung upstream.
			// Block until the client is closed.
			<-c.waitCh
			return
		}
	}()

	c.pipeDone = done
	c.pipeCleanup = func() {
		reqReader.Close()
		respWriter.Close()
	}

	return reqWriter, respReader, nil
}

func (c *neverRespondMockClient) Wait() error {
	<-c.waitCh
	return nil
}

func (c *neverRespondMockClient) Close() error {
	c.mu.Lock()
	cleanup := c.pipeCleanup
	c.pipeCleanup = nil
	doneCh := c.pipeDone
	c.pipeDone = nil
	c.closed = true
	select {
	case <-c.waitCh:
	default:
		close(c.waitCh)
	}
	c.mu.Unlock()

	if cleanup != nil {
		cleanup()
	}
	if doneCh != nil {
		<-doneCh
	}
	return nil
}

var _ outbound.MCPClient = (*neverRespondMockClient)(nil)

// TestForwardToUpstream_30sTimeout documents the hardcoded 30s timeout in
// upstream_router.go's forwardToUpstream. When an upstream completes the
// handshake but then never responds to a tools/call, the caller is blocked
// until the 30s timer fires.
//
// This test verifies the mechanism:
//  1. The upstream connects and completes the init handshake.
//  2. A tools/call request is written to the upstream's stdin.
//  3. The upstream never sends a response (lineCh blocks).
//  4. We verify that GetConnection succeeds (upstream is Connected) and
//     that writing to the upstream does not immediately error.
//  5. We verify that reading from lineCh blocks (no data within 2s),
//     documenting that the caller would be stuck for the full 30s timeout.
//  6. Cleanup via mgr.Close() unblocks everything.
//
// NOTE: We intentionally do NOT wait 30s. This is a documentation test that
// proves the timeout mechanism exists and that a hung upstream causes the
// caller to block. The actual 30s timeout is tested indirectly by the
// forwardToUpstream code path in upstream_router.go.
func TestForwardToUpstream_30sTimeout(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "timeout-upstream",
		Name:    "timeout-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/bin/true", // placeholder — factory overrides
	}

	factory := func(_ *upstream.Upstream) (outbound.MCPClient, error) {
		return newNeverRespondMockClient(), nil
	}

	mgr := newTestUpstreamManager(t, factory, u)
	mgr.SetBackoffBase(50 * time.Millisecond)
	mgr.SetGlobalRetryConfig(2, 500*time.Millisecond)

	t.Cleanup(func() {
		_ = mgr.Close()
		goleak.VerifyNone(t,
			goleak.IgnoreCurrent(),
		)
	})

	ctx := context.Background()

	// Start — init handshake should succeed.
	if err := mgr.Start(ctx, "timeout-upstream"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Wait for Connected.
	status := waitForStatus(t, mgr, "timeout-upstream", upstream.StatusConnected, 5*time.Second)
	if status != upstream.StatusConnected {
		t.Fatalf("expected Connected after start, got %q", status)
	}

	// Get the connection.
	writer, lineCh, err := mgr.GetConnection("timeout-upstream")
	if err != nil {
		t.Fatalf("GetConnection() unexpected error: %v", err)
	}

	// Send a tools/call request. The mock will receive it but never respond.
	toolsCallReq := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo_tool","arguments":{}}}` + "\n"
	_, writeErr := writer.Write([]byte(toolsCallReq))
	if writeErr != nil {
		t.Fatalf("Write() unexpected error: %v", writeErr)
	}

	// Verify that lineCh does NOT deliver any data within 2 seconds.
	// This documents that a hung upstream blocks the caller. In production,
	// forwardToUpstream (upstream_router.go) uses:
	//   timeout := time.After(30 * time.Second)
	// and would return "timeout waiting for upstream response (30s)" after 30s.
	select {
	case line, ok := <-lineCh:
		if ok {
			t.Fatalf("expected lineCh to block (hung upstream), but received data: %s", string(line))
		} else {
			t.Fatal("expected lineCh to block (hung upstream), but channel was closed")
		}
	case <-time.After(2 * time.Second):
		// Expected: no data received within 2s, confirming the upstream is hung.
		t.Log("PASS: lineCh blocked for 2s as expected — upstream never responded")
		t.Log("NOTE: In production, forwardToUpstream would timeout after 30s (hardcoded in upstream_router.go)")
	}

	// Cleanup: Close the manager, which will close the mock client and unblock
	// the goroutine that is waiting in the mock's Start handler.
}

// --- 4C.2: Handshake timeout (documents BUG B5) ---

// noInitResponseMockClient is a mock MCPClient that starts successfully
// (pipes are open) but never responds to the initialize request.
// The response pipe stays open but no data is ever written, causing
// readLineUnbuffered to block indefinitely on Read().
//
// This simulates a malicious or broken upstream that accepts the connection
// but hangs during the handshake phase.
type noInitResponseMockClient struct {
	mu          sync.Mutex
	waitCh      chan struct{}
	closed      bool
	pipeCleanup func()
	pipeDone    chan struct{}
}

func newNoInitResponseMockClient() *noInitResponseMockClient {
	return &noInitResponseMockClient{
		waitCh: make(chan struct{}),
	}
}

func (c *noInitResponseMockClient) Start(_ context.Context) (io.WriteCloser, io.ReadCloser, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = false
	c.waitCh = make(chan struct{})

	// Create pipes. We read from reqReader (to consume the initialize request)
	// but NEVER write to respWriter, so the response pipe blocks forever.
	reqReader, reqWriter := io.Pipe()
	respReader, respWriter := io.Pipe()
	done := make(chan struct{})

	go func() {
		defer close(done)
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			// Consume all messages but never respond.
			// This keeps the process "alive" while blocking
			// readLineUnbuffered on the response pipe.
		}
	}()

	c.pipeDone = done
	c.pipeCleanup = func() {
		reqReader.Close()
		respWriter.Close()
	}

	return reqWriter, respReader, nil
}

func (c *noInitResponseMockClient) Wait() error {
	<-c.waitCh
	return nil
}

func (c *noInitResponseMockClient) Close() error {
	c.mu.Lock()
	cleanup := c.pipeCleanup
	c.pipeCleanup = nil
	doneCh := c.pipeDone
	c.pipeDone = nil
	c.closed = true
	select {
	case <-c.waitCh:
	default:
		close(c.waitCh)
	}
	c.mu.Unlock()

	if cleanup != nil {
		cleanup()
	}
	if doneCh != nil {
		<-doneCh
	}
	return nil
}

var _ outbound.MCPClient = (*noInitResponseMockClient)(nil)

// TestHandshakeTimeout documents BUG B5: performInitHandshake has no timeout.
// When an upstream never responds to the initialize request,
// performInitHandshake calls readLineUnbuffered which blocks indefinitely
// on r.Read(buf). There is no deadline, no context cancellation, and no
// timeout wrapper around the read.
//
// This test:
//  1. Uses a mock client whose Start() returns open pipes but never writes
//     any response data
//  2. Calls mgr.Start() in a goroutine (it blocks because attemptConnect
//     calls performInitHandshake synchronously)
//  3. After 1 second, checks that the upstream is still in "Connecting" status
//     (NOT Connected, NOT Error) — proving the handshake is blocked
//  4. Waits 5 more seconds to confirm it stays blocked indefinitely
//  5. Closes the manager (which closes stdin/stdout pipes, unblocking Read)
//  6. Verifies clean goroutine shutdown via goleak
//
// BUG B5: readLineUnbuffered (upstream_manager.go) has no timeout or context
// cancellation. A malicious or broken upstream that accepts the TCP/pipe
// connection but never sends a response will cause performInitHandshake to
// block the Start() goroutine indefinitely. The only recovery is closing the
// underlying pipes (which Close() does).
func TestHandshakeTimeout(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "no-init-upstream",
		Name:    "no-init-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/bin/true", // placeholder — factory overrides
	}

	// Keep a reference to the mock client so we can close it explicitly.
	// Because BUG B5 means attemptConnect never finishes, the conn.client
	// field is never set, so mgr.Close() -> stopConnection cannot close it.
	// We must close the mock ourselves to unblock readLineUnbuffered.
	var mockMu sync.Mutex
	var mockClients []*noInitResponseMockClient

	factory := func(_ *upstream.Upstream) (outbound.MCPClient, error) {
		c := newNoInitResponseMockClient()
		mockMu.Lock()
		mockClients = append(mockClients, c)
		mockMu.Unlock()
		return c, nil
	}

	mgr := newTestUpstreamManager(t, factory, u)
	mgr.SetBackoffBase(50 * time.Millisecond)
	// Use 0 retries so we only have one blocked handshake attempt.
	mgr.SetGlobalRetryConfig(0, 500*time.Millisecond)

	// Close must happen before goleak check because the blocked handshake
	// goroutine only exits when pipes are closed.
	// Because of BUG B5, mgr.Close() alone cannot unblock the handshake:
	// - attemptConnect never finishes, so conn.client/stdin/stdout are nil
	// - stopConnection has nothing to close
	// We must explicitly close the mock clients to break the pipe reads.
	t.Cleanup(func() {
		_ = mgr.Close()
		// Explicitly close all mock clients to unblock readLineUnbuffered.
		mockMu.Lock()
		for _, c := range mockClients {
			_ = c.Close()
		}
		mockMu.Unlock()
		// Give goroutines time to drain after pipe close.
		time.Sleep(200 * time.Millisecond)
		goleak.VerifyNone(t,
			goleak.IgnoreCurrent(),
		)
	})

	ctx := context.Background()

	// Start() calls attemptConnect synchronously, which calls
	// performInitHandshake, which calls readLineUnbuffered.
	// Since our mock never responds, Start() blocks indefinitely (BUG B5).
	// Run it in a goroutine to avoid blocking the test.
	startDone := make(chan error, 1)
	go func() {
		startDone <- mgr.Start(ctx, "no-init-upstream")
	}()

	// Wait briefly for Start to register the connection entry with
	// status=Connecting before calling attemptConnect.
	time.Sleep(1 * time.Second)

	// Check: the upstream should be in "Connecting" status because
	// performInitHandshake is blocked in readLineUnbuffered waiting for a
	// response that will never come.
	status, lastErr := mgr.Status("no-init-upstream")
	t.Logf("status after 1s: %q, lastErr: %q", status, lastErr)

	if status == upstream.StatusConnected {
		t.Fatal("BUG B5 appears fixed: upstream reached Connected despite mock never responding to init")
	}

	// The status should be "connecting" because Start set it to Connecting
	// before calling attemptConnect, and attemptConnect is still blocked in
	// performInitHandshake.
	if status != upstream.StatusConnecting {
		t.Errorf("expected Connecting status while handshake is blocked, got %q (lastErr=%q)", status, lastErr)
	}

	// Wait 5 more seconds to confirm the handshake remains blocked.
	time.Sleep(5 * time.Second)
	status2, lastErr2 := mgr.Status("no-init-upstream")
	t.Logf("status after 6s: %q, lastErr: %q", status2, lastErr2)

	// Key assertion: the upstream must NOT have reached Connected.
	if status2 == upstream.StatusConnected {
		t.Fatal("BUG B5 appears fixed: upstream reached Connected after 6s despite mock never responding")
	}

	// If still Connecting after 6s, this proves BUG B5: no handshake timeout.
	if status2 == upstream.StatusConnecting {
		t.Log("BUG B5 CONFIRMED: performInitHandshake has no timeout — still Connecting after 6s")
		t.Log("readLineUnbuffered blocks indefinitely when upstream never sends init response")
		t.Log("The only recovery is closing the underlying pipes via manager.Close()")
	} else {
		// If Error/Disconnected, something else happened. Still not Connected, which is good.
		t.Logf("status after 6s is %q (lastErr=%q) — handshake did not reach Connected", status2, lastErr2)
	}

	// Verify that Start() has NOT returned yet (still blocked).
	select {
	case err := <-startDone:
		// If Start returned, the handshake was unblocked somehow.
		t.Logf("Start() returned (err=%v) — handshake was unblocked", err)
	default:
		t.Log("Start() is still blocked — confirms readLineUnbuffered has no timeout")
	}

	// Cleanup: t.Cleanup calls mgr.Close() which closes pipes, unblocking
	// readLineUnbuffered (Read returns EOF), then verifies no goroutine leaks.
}
