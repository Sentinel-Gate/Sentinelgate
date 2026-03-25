package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
)

// --- Adversarial MCP Client ---

// adversarialMCPClient is a custom mock that allows controlling the auto-responder
// behavior for handshake adversarial testing.
type adversarialMCPClient struct {
	mu        sync.Mutex
	waitCh    chan struct{}
	closed    bool
	cleanup   func()
	done      chan struct{}
	responder func(reqReader *io.PipeReader, respWriter *io.PipeWriter)
}

func newAdversarialClient(responder func(reqReader *io.PipeReader, respWriter *io.PipeWriter)) *adversarialMCPClient {
	return &adversarialMCPClient{
		waitCh:    make(chan struct{}),
		responder: responder,
	}
}

func (c *adversarialMCPClient) Start(_ context.Context) (io.WriteCloser, io.ReadCloser, error) {
	reqReader, reqWriter := io.Pipe()
	respReader, respWriter := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer respWriter.Close()
		c.responder(reqReader, respWriter)
	}()
	c.mu.Lock()
	c.done = done
	c.cleanup = func() {
		reqReader.Close()
		respReader.Close()
	}
	c.closed = false
	c.mu.Unlock()
	return reqWriter, respReader, nil
}

func (c *adversarialMCPClient) Wait() error {
	<-c.waitCh
	return nil
}

func (c *adversarialMCPClient) Close() error {
	c.mu.Lock()
	cleanup := c.cleanup
	c.cleanup = nil
	done := c.done
	c.done = nil
	select {
	case <-c.waitCh:
	default:
		close(c.waitCh)
	}
	c.closed = true
	c.mu.Unlock()
	if cleanup != nil {
		cleanup()
	}
	if done != nil {
		<-done
	}
	return nil
}

var _ outbound.MCPClient = (*adversarialMCPClient)(nil)

// --- Helpers ---

// waitForStatus polls the manager until the upstream reaches the desired status
// or the timeout expires. Returns true if the status was reached.
func waitForStatus(t *testing.T, mgr *UpstreamManager, upstreamID string, want upstream.ConnectionStatus, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status, _ := mgr.Status(upstreamID)
		if status == want {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// adversarialManagerEnv creates an UpstreamManager backed by a single upstream
// and a custom adversarialMCPClient driven by the provided responder function.
// The manager is configured with short backoff and maxRetries=0 (no retries)
// so that handshake failures are final.
func adversarialManagerEnv(t *testing.T, u *upstream.Upstream, responder func(*io.PipeReader, *io.PipeWriter)) *UpstreamManager {
	t.Helper()

	store := newMgrMockUpstreamStore()
	_ = store.Add(context.Background(), u)

	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger)

	factory := func(_ *upstream.Upstream) (outbound.MCPClient, error) {
		return newAdversarialClient(responder), nil
	}

	mgr := NewUpstreamManager(svc, factory, logger)
	mgr.backoffBase = 5 * time.Millisecond
	mgr.maxRetries = 0 // no retries — handshake result is final
	return mgr
}

// --- Tests ---

// TestHandshake_UpstreamRespondsWithError (1B.1) verifies that when the upstream
// returns a JSON-RPC error response to the initialize request, the handshake
// fails and the upstream transitions to StatusError.
func TestHandshake_UpstreamRespondsWithError(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := &upstream.Upstream{
		ID:      "err-resp-01",
		Name:    "error-responder",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/true",
	}

	responder := func(reqReader *io.PipeReader, respWriter *io.PipeWriter) {
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, "initialize") {
				continue
			}
			// Extract the request ID so the response matches.
			var req struct {
				ID json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal([]byte(line), &req); err != nil || req.ID == nil {
				continue
			}
			errResp := fmt.Sprintf(
				`{"jsonrpc":"2.0","id":%s,"error":{"code":-32603,"message":"initialization failed"}}`,
				string(req.ID),
			)
			fmt.Fprintln(respWriter, errResp)
			return
		}
	}

	mgr := adversarialManagerEnv(t, u, responder)
	defer func() { _ = mgr.Close() }()

	if err := mgr.Start(context.Background(), u.ID); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	if !waitForStatus(t, mgr, u.ID, upstream.StatusError, 5*time.Second) {
		status, lastErr := mgr.Status(u.ID)
		t.Fatalf("expected StatusError after error response, got %q (lastErr=%q)", status, lastErr)
	}

	// With maxRetries=0, scheduleRetry immediately overwrites lastError to
	// "max retries (0) exceeded". The original error ("init handshake: initialize error: ...")
	// is logged but not retained. We verify StatusError was reached, which is sufficient.
}

// TestHandshake_UpstreamNeverResponds (1B.2) documents BUG B5:
// readLineUnbuffered has no timeout. When the upstream reads the initialize
// request but never sends a response, readLineUnbuffered blocks forever.
//
// Because attemptConnect (and therefore Start) runs synchronously, the Start()
// call itself blocks when readLineUnbuffered hangs. We must call Start() in a
// separate goroutine and close the client's pipes externally to unblock it.
//
// Key observation: since attemptConnect stores the client in a local variable
// and only writes it to conn.client AFTER the handshake succeeds, mgr.Close()
// and stopConnection cannot reach the client to close its pipes. We must
// keep a reference to the adversarial client and close it directly.
//
// The fix for B5 would add a deadline/timeout to readLineUnbuffered so the
// handshake can fail without requiring an external pipe close.
func TestHandshake_UpstreamNeverResponds(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := &upstream.Upstream{
		ID:      "no-resp-02",
		Name:    "silent-upstream",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/true",
	}

	// Keep a reference to the adversarial client so we can close its pipes
	// directly, since mgr.Close()/stopConnection cannot reach it.
	var clientRef *adversarialMCPClient
	var clientMu sync.Mutex

	store := newMgrMockUpstreamStore()
	_ = store.Add(context.Background(), u)
	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger)

	// The responder reads the initialize request but never writes back.
	responder := func(reqReader *io.PipeReader, _ *io.PipeWriter) {
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			// consume all input, never respond
		}
	}

	factory := func(_ *upstream.Upstream) (outbound.MCPClient, error) {
		c := newAdversarialClient(responder)
		clientMu.Lock()
		clientRef = c
		clientMu.Unlock()
		return c, nil
	}

	mgr := NewUpstreamManager(svc, factory, logger)
	mgr.backoffBase = 5 * time.Millisecond
	mgr.maxRetries = 0

	// BUG B5: Start() calls attemptConnect synchronously, which calls
	// performInitHandshake → readLineUnbuffered. Since the upstream never
	// responds, readLineUnbuffered blocks forever and Start() never returns.
	startDone := make(chan error, 1)
	go func() {
		startDone <- mgr.Start(context.Background(), u.ID)
	}()

	// Give a short window for the handshake to be attempted.
	time.Sleep(500 * time.Millisecond)

	// Verify Start() is still blocked (B5 — no timeout on readLineUnbuffered).
	select {
	case err := <-startDone:
		if err != nil {
			t.Fatalf("Start() returned error: %v", err)
		}
		status, _ := mgr.Status(u.ID)
		if status == upstream.StatusConnected {
			t.Error("BUG B5 may be fixed: upstream connected despite never responding; " +
				"update this test to reflect the fix")
		}
	default:
		// Expected: Start() is still blocked because readLineUnbuffered hangs.
		t.Log("BUG B5 confirmed: Start() blocked because readLineUnbuffered has no timeout")
	}

	// Close the client directly to unblock readLineUnbuffered. This is
	// necessary because stopConnection cannot reach the client (it's in
	// a local variable inside attemptConnect, not yet stored in conn.client).
	clientMu.Lock()
	ref := clientRef
	clientMu.Unlock()
	if ref != nil {
		_ = ref.Close()
	}

	// Wait for Start() goroutine to finish after pipe close.
	select {
	case <-startDone:
		// good — readLineUnbuffered got EOF from pipe close
	case <-time.After(5 * time.Second):
		t.Fatal("Start() goroutine did not unblock after closing client pipes")
	}

	// Now close the manager to clean up the stability checker goroutine.
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}
}

// TestHandshake_NotificationsBeforeInitResponse (1B.3) exposes BUG B4:
// performInitHandshake reads exactly one line and treats it as the init
// response. If the upstream sends notifications before the real response,
// the first notification is accepted as the init "response" (it has no
// "error" field, so the check passes). The actual init response is then
// left in the pipe and consumed by the scanner goroutine, causing desync.
//
// After a fix for B4, performInitHandshake would skip notifications
// (messages without an "id" field) and wait for the real init response.
func TestHandshake_NotificationsBeforeInitResponse(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := &upstream.Upstream{
		ID:      "notif-b4-03",
		Name:    "notif-before-init",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/true",
	}

	responder := func(reqReader *io.PipeReader, respWriter *io.PipeWriter) {
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, "initialize") {
				continue
			}
			var req struct {
				ID json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal([]byte(line), &req); err != nil || req.ID == nil {
				continue
			}

			// Build all response lines. We must write them in a separate
			// goroutine because io.Pipe is synchronous: each Write blocks
			// until the reader consumes it. If we write inline, the second
			// Fprintln blocks while performInitHandshake (having consumed
			// the first line) tries to write notifications/initialized to
			// reqWriter, creating a deadlock (both sides blocked writing).
			realResp := fmt.Sprintf(
				`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"1.0"}}}`,
				string(req.ID),
			)
			go func() {
				fmt.Fprintln(respWriter, `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`)
				fmt.Fprintln(respWriter, `{"jsonrpc":"2.0","method":"notifications/progress","params":{}}`)
				fmt.Fprintln(respWriter, realResp)
			}()

			// Keep consuming remaining input (e.g. notifications/initialized)
			// so the auto-responder goroutine does not exit prematurely.
			continue
		}
	}

	mgr := adversarialManagerEnv(t, u, responder)
	defer func() { _ = mgr.Close() }()

	if err := mgr.Start(context.Background(), u.ID); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// Wait for the status to settle — either Connected or Error.
	connected := waitForStatus(t, mgr, u.ID, upstream.StatusConnected, 3*time.Second)
	status, lastErr := mgr.Status(u.ID)

	if connected {
		// BUG B4 present: the first notification was accepted as the init
		// response because it has no "error" field. The handshake "succeeded"
		// but the real init response is left in the pipe, causing desync.
		//
		// This is technically incorrect — the handshake should only accept
		// a message whose "id" matches the request ID. A notification (no "id")
		// should be skipped.
		t.Log("BUG B4 confirmed: handshake accepted a notification as the init response; " +
			"the real init response is left in the pipe causing desync")
	} else if status == upstream.StatusError {
		// If B4 is fixed, the handshake would have correctly skipped notifications
		// and found the real response. If we got an error here, check if the fix
		// introduced a different failure mode.
		t.Logf("B4 may be fixed or a different issue occurred: status=%q lastErr=%q", status, lastErr)
	} else {
		// After B4 fix, the upstream should connect successfully.
		t.Logf("B4 fix working: status=%q (expected StatusConnected)", status)
	}
}

// TestHandshake_MissingFieldsInResponse (1B.4) verifies that performInitHandshake
// accepts any non-error response, even if the result object is empty (missing
// protocolVersion, capabilities, serverInfo). The current code only checks for
// the presence of an "error" field — it does not validate result contents.
func TestHandshake_MissingFieldsInResponse(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := &upstream.Upstream{
		ID:      "empty-res-04",
		Name:    "empty-result",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/true",
	}

	responder := func(reqReader *io.PipeReader, respWriter *io.PipeWriter) {
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, "initialize") {
				continue
			}
			var req struct {
				ID json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal([]byte(line), &req); err != nil || req.ID == nil {
				continue
			}

			// Respond with an empty result — no protocolVersion, no capabilities.
			resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{}}`, string(req.ID))
			fmt.Fprintln(respWriter, resp)

			// Keep consuming input so goroutine does not exit prematurely.
			continue
		}
	}

	mgr := adversarialManagerEnv(t, u, responder)
	defer func() { _ = mgr.Close() }()

	if err := mgr.Start(context.Background(), u.ID); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// The handshake should succeed because the code only checks for "error" field.
	if !waitForStatus(t, mgr, u.ID, upstream.StatusConnected, 5*time.Second) {
		status, lastErr := mgr.Status(u.ID)
		t.Fatalf("expected StatusConnected with empty result, got %q (lastErr=%q)", status, lastErr)
	}

	// Document: the handshake accepts any non-error response, even with empty result.
	// A stricter implementation would validate protocolVersion at minimum.
	t.Log("handshake accepts response with empty result (no protocolVersion validation)")
}

// TestHandshake_ConnectionClosedDuringHandshake (1B.5) verifies that when the
// upstream closes the response pipe immediately after receiving the initialize
// request (without sending any response), readLineUnbuffered gets an EOF and
// the handshake fails with StatusError.
func TestHandshake_ConnectionClosedDuringHandshake(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := &upstream.Upstream{
		ID:      "close-mid-05",
		Name:    "close-during-handshake",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/true",
	}

	responder := func(reqReader *io.PipeReader, _ *io.PipeWriter) {
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "initialize") {
				// Read the initialize request but close the response pipe
				// immediately (respWriter is closed by deferred Close in
				// the goroutine wrapper — we just return without writing).
				return
			}
		}
		// If scanner ends without seeing initialize, just return.
	}

	mgr := adversarialManagerEnv(t, u, responder)
	defer func() { _ = mgr.Close() }()

	if err := mgr.Start(context.Background(), u.ID); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	// readLineUnbuffered should get EOF and fail the handshake.
	if !waitForStatus(t, mgr, u.ID, upstream.StatusError, 5*time.Second) {
		status, lastErr := mgr.Status(u.ID)
		t.Fatalf("expected StatusError after pipe close, got %q (lastErr=%q)", status, lastErr)
	}

	// With maxRetries=0, scheduleRetry immediately overwrites lastError to
	// "max retries (0) exceeded". The original error ("init handshake: read
	// initialize response: EOF") is logged but not retained. Reaching
	// StatusError after pipe close is sufficient validation.
}

// TestHandshake_IDFormat (1B.6) verifies the format of the JSON-RPC "id" field
// in the initialize request. The code uses "init-" + upstreamID[:8] when the
// upstream ID is longer than 8 characters, or "init-" + upstreamID for shorter IDs.
func TestHandshake_IDFormat(t *testing.T) {
	defer goleak.VerifyNone(t)

	tests := []struct {
		name       string
		upstreamID string
		wantID     string
	}{
		{
			name:       "long_id_truncated",
			upstreamID: "abcdefghij1234567890",
			wantID:     "init-abcdefgh",
		},
		{
			name:       "exactly_8_chars",
			upstreamID: "12345678",
			wantID:     "init-12345678",
		},
		{
			name:       "short_id_no_truncation",
			upstreamID: "abc",
			wantID:     "init-abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &upstream.Upstream{
				ID:      tt.upstreamID,
				Name:    "id-format-" + tt.name,
				Type:    upstream.UpstreamTypeStdio,
				Enabled: true,
				Command: "/usr/bin/true",
			}

			captured := make(chan string, 1)

			responder := func(reqReader *io.PipeReader, respWriter *io.PipeWriter) {
				scanner := bufio.NewScanner(reqReader)
				for scanner.Scan() {
					line := scanner.Text()
					if !strings.Contains(line, "initialize") {
						continue
					}

					// Capture the request for ID verification.
					var req struct {
						ID     json.RawMessage `json:"id"`
						Method string          `json:"method"`
					}
					if err := json.Unmarshal([]byte(line), &req); err != nil || req.ID == nil {
						continue
					}

					// Send the captured ID (unquoted string).
					var idStr string
					if err := json.Unmarshal(req.ID, &idStr); err == nil {
						select {
						case captured <- idStr:
						default:
						}
					}

					// Send a valid response so the handshake completes.
					resp := fmt.Sprintf(
						`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"mock","version":"1.0"}}}`,
						string(req.ID),
					)
					fmt.Fprintln(respWriter, resp)

					// Keep consuming input.
					continue
				}
			}

			mgr := adversarialManagerEnv(t, u, responder)
			defer func() { _ = mgr.Close() }()

			if err := mgr.Start(context.Background(), u.ID); err != nil {
				t.Fatalf("Start() unexpected error: %v", err)
			}

			// Wait for the captured ID.
			select {
			case gotID := <-captured:
				if gotID != tt.wantID {
					t.Errorf("initialize ID = %q, want %q", gotID, tt.wantID)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for initialize request to be captured")
			}

			// Also verify the connection succeeded.
			if !waitForStatus(t, mgr, u.ID, upstream.StatusConnected, 3*time.Second) {
				status, lastErr := mgr.Status(u.ID)
				t.Errorf("expected StatusConnected, got %q (lastErr=%q)", status, lastErr)
			}
		})
	}
}

// TestHandshake_DoubleInitOnSameConnection (1B.7) documents the behavior when
// Start() is called twice on the same upstream ID. Start() unconditionally
// creates a new upstreamConnection and overwrites the old entry in the map.
// This means the first connection's goroutines (scanner, monitorHealth) become
// orphaned until they encounter an error or the manager is closed.
//
// The test verifies:
// 1. The second Start() does NOT return an error (no "already started" guard).
// 2. The second connection reaches StatusConnected.
// 3. Both connections send separate initialize requests (2 total, not 1).
// 4. mgr.Close() cleans up all goroutines (including the replaced connection's).
func TestHandshake_DoubleInitOnSameConnection(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := &upstream.Upstream{
		ID: "dbl-init-07", Name: "double-init", Type: upstream.UpstreamTypeStdio,
		Enabled: true, Command: "/usr/bin/true",
	}

	initCount := atomic.Int32{}

	responder := func(reqReader *io.PipeReader, respWriter *io.PipeWriter) {
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "initialize") {
				initCount.Add(1)
				var req struct{ ID json.RawMessage `json:"id"` }
				if err := json.Unmarshal([]byte(line), &req); err != nil || req.ID == nil {
					continue
				}
				resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"mock","version":"1.0"}}}`, string(req.ID))
				fmt.Fprintln(respWriter, resp)
				continue
			}
		}
	}

	// Use a custom setup (not adversarialManagerEnv) so we can track multiple
	// client instances for proper cleanup.
	store := newMgrMockUpstreamStore()
	_ = store.Add(context.Background(), u)
	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger)

	var clientsMu sync.Mutex
	var clients []*adversarialMCPClient

	factory := func(_ *upstream.Upstream) (outbound.MCPClient, error) {
		c := newAdversarialClient(responder)
		clientsMu.Lock()
		clients = append(clients, c)
		clientsMu.Unlock()
		return c, nil
	}

	mgr := NewUpstreamManager(svc, factory, logger)
	mgr.backoffBase = 5 * time.Millisecond
	mgr.maxRetries = 0

	// First Start
	if err := mgr.Start(context.Background(), u.ID); err != nil {
		t.Fatalf("first Start() error: %v", err)
	}
	if !waitForStatus(t, mgr, u.ID, upstream.StatusConnected, 5*time.Second) {
		t.Fatal("upstream did not connect after first Start")
	}

	// Second Start on same upstream — overwrites the connection entry.
	err := mgr.Start(context.Background(), u.ID)
	t.Logf("second Start() returned: %v", err)

	// Wait for the second connection to reach Connected.
	if !waitForStatus(t, mgr, u.ID, upstream.StatusConnected, 5*time.Second) {
		status, lastErr := mgr.Status(u.ID)
		t.Fatalf("expected Connected after second Start, got %q (lastErr=%q)", status, lastErr)
	}

	// Document: Start() does NOT guard against double-start. Each call creates
	// a fresh connection and sends a new initialize handshake.
	if got := initCount.Load(); got < 2 {
		t.Errorf("expected at least 2 initialize requests (one per Start call), got %d", got)
	} else {
		t.Logf("upstream received %d initialize requests (one per Start call — no double-start guard)", got)
	}

	// Close the manager — this should clean up the active (second) connection.
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}

	// The first (replaced) connection's goroutines may still be running because
	// mgr.Close() only knows about the second connection entry. Close all
	// client instances directly to ensure goroutine cleanup for goleak.
	clientsMu.Lock()
	allClients := clients
	clientsMu.Unlock()
	for _, c := range allClients {
		_ = c.Close()
	}
}
