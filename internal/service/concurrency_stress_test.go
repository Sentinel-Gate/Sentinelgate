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

// waitStatus polls the manager for an upstream's status until it matches the
// desired value or the timeout expires. Returns true if the status matched.
// Named waitStatus (not waitForStatus) to avoid collisions with other test files.
func waitStatus(t *testing.T, mgr *UpstreamManager, upstreamID string, want upstream.ConnectionStatus, timeout time.Duration) bool {
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

// trackingFactory wraps the client factory to track all mock clients created
// during the test. This allows cleanup of orphaned mocks whose connections
// were replaced by concurrent Start() calls (the old mock's goroutines would
// otherwise leak).
type trackingFactory struct {
	mu      sync.Mutex
	clients []*mgrMockMCPClient
}

func (tf *trackingFactory) create(u *upstream.Upstream) (outbound.MCPClient, error) {
	mc := newMgrMockMCPClient()
	mc.simulateHTTP = (u.Type == upstream.UpstreamTypeHTTP)
	tf.mu.Lock()
	tf.clients = append(tf.clients, mc)
	tf.mu.Unlock()
	return mc, nil
}

// closeAll closes all tracked mock clients, cleaning up any orphaned
// auto-responder and reader goroutines.
func (tf *trackingFactory) closeAll() {
	tf.mu.Lock()
	defer tf.mu.Unlock()
	for _, mc := range tf.clients {
		_ = mc.Close()
	}
}

// testManagerEnvTracked creates a manager that tracks all mock clients ever
// created. Use tf.closeAll() in t.Cleanup to prevent goroutine leaks from
// orphaned connections.
func testManagerEnvTracked(t *testing.T, upstreams ...*upstream.Upstream) (*UpstreamManager, *trackingFactory) {
	t.Helper()

	store := newMgrMockUpstreamStore()
	for _, u := range upstreams {
		_ = store.Add(context.Background(), u)
	}

	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger)

	tf := &trackingFactory{}
	mgr := NewUpstreamManager(svc, tf.create, logger)

	return mgr, tf
}

// =============================================================================
// 2A — Race Conditions (all with -race)
// =============================================================================

// TestConcurrentStartStop exercises the manager's mu (RWMutex) and per-connection
// conn.mu by having 5 goroutines rapidly calling Start and Stop on the same
// upstream in parallel. The race detector must not fire, no panic may occur, and
// the final state after Close() must be coherent.
func TestConcurrentStartStop(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "race-ss-1",
		Name:    "race-start-stop",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	mgr, tf := testManagerEnvTracked(t, u)
	defer goleak.VerifyNone(t)
	// Clean up orphaned mocks first (LIFO: closeAll runs before VerifyNone).
	defer tf.closeAll()
	defer func() { _ = mgr.Close() }()

	// Reduce backoff so retries spawned during the test resolve quickly.
	mgr.backoffBase = 5 * time.Millisecond

	const goroutines = 5
	const iterations = 10
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Track panics across goroutines.
	var panicCount atomic.Int32

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicCount.Add(1)
					t.Errorf("goroutine panicked: %v", r)
				}
			}()
			for i := 0; i < iterations; i++ {
				_ = mgr.Start(ctx, "race-ss-1")
				_ = mgr.Stop("race-ss-1")
			}
		}()
	}

	// Use a timeout to detect deadlocks.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines completed.
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock detected: goroutines did not complete within 10s")
	}

	if panicCount.Load() > 0 {
		t.Fatalf("detected %d panics during concurrent Start/Stop", panicCount.Load())
	}

	// Final state: the upstream is either disconnected (last op was Stop) or
	// connected (last op was Start). Either is fine — we just verify coherence.
	status, _ := mgr.Status("race-ss-1")
	switch status {
	case upstream.StatusConnected, upstream.StatusDisconnected, upstream.StatusConnecting, upstream.StatusError:
		// All valid terminal states.
	default:
		t.Errorf("unexpected final status %q", status)
	}
}

// TestConcurrentToolCacheAccess verifies that ToolCache handles concurrent reads
// and writes without races. Multiple writer goroutines replace tool sets for
// different upstreams while reader goroutines query tools by name and list all.
func TestConcurrentToolCacheAccess(t *testing.T) {
	t.Parallel()

	cache := upstream.NewToolCache()

	const writers = 4
	const readers = 4
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(writers + readers)

	// Writers: each owns a unique upstream ID and replaces tools repeatedly.
	for w := 0; w < writers; w++ {
		upstreamID := fmt.Sprintf("upstream-%d", w)
		go func(uid string) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				tools := make([]*upstream.DiscoveredTool, 0, 5)
				for j := 0; j < 5; j++ {
					tools = append(tools, &upstream.DiscoveredTool{
						Name:        fmt.Sprintf("%s-tool-%d-%d", uid, i, j),
						Description: "stress test tool",
						UpstreamID:  uid,
					})
				}
				cache.SetToolsForUpstream(uid, tools)

				// Also exercise conflict recording.
				cache.RecordConflict(upstream.ToolConflict{ //nolint:staticcheck // testing deprecated API
					ToolName:          fmt.Sprintf("conflict-%s-%d", uid, i),
					SkippedUpstreamID: uid,
					WinnerUpstreamID:  "other",
				})
			}
		}(upstreamID)
	}

	// Readers: continuously read while writers mutate.
	for r := 0; r < readers; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				_ = cache.GetAllTools()
				_, _ = cache.GetTool(fmt.Sprintf("upstream-0-tool-%d-0", i))
				_ = cache.GetToolsByUpstream("upstream-0")
				_, _ = cache.HasConflict(fmt.Sprintf("upstream-1-tool-%d-0", i), "upstream-2")
				_ = cache.GetConflicts()
				_ = cache.Count()
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success: no race detected.
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock detected: concurrent ToolCache access did not complete within 10s")
	}

	// Sanity: cache should have some tools.
	if cache.Count() == 0 {
		t.Error("expected ToolCache to contain tools after concurrent writes")
	}

	// Exercise removal under no contention to verify cleanup works.
	for w := 0; w < writers; w++ {
		cache.RemoveUpstream(fmt.Sprintf("upstream-%d", w))
	}
	if cache.Count() != 0 {
		t.Errorf("expected ToolCache to be empty after RemoveUpstream, got %d", cache.Count())
	}
}

// =============================================================================
// 2B — Goroutine Lifecycle
// =============================================================================

// TestCrashUpstream_GoroutineCleanup verifies that after an upstream crashes
// (simulateCrash), all associated goroutines (reader goroutine, health monitor)
// exit cleanly. The reader goroutine sees scanner EOF and closes lineCh;
// stopConnection drains lineCh. goleak.VerifyNone must pass.
func TestCrashUpstream_GoroutineCleanup(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "crash-gc-1",
		Name:    "crash-cleanup",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	mgr, tf := testManagerEnvTracked(t, u)
	// Disable retries so the crash does not trigger a reconnect loop
	// that would leave goroutines alive.
	mgr.maxRetries = 0
	mgr.backoffBase = 1 * time.Millisecond

	defer goleak.VerifyNone(t)
	defer tf.closeAll()
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()
	if err := mgr.Start(ctx, "crash-gc-1"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	if !waitStatus(t, mgr, "crash-gc-1", upstream.StatusConnected, 2*time.Second) {
		t.Fatal("upstream did not reach Connected status within 2s")
	}

	// Simulate upstream crash.
	tf.mu.Lock()
	if len(tf.clients) == 0 {
		tf.mu.Unlock()
		t.Fatal("mock client not found")
	}
	mc := tf.clients[len(tf.clients)-1]
	tf.mu.Unlock()

	mc.simulateCrash()

	// Give health monitor and reconnect logic time to process the crash.
	// With maxRetries=0, scheduleRetry will set status to Error and return.
	time.Sleep(300 * time.Millisecond)

	// Status should be Error or Disconnected (crash detected, no retries).
	status, _ := mgr.Status("crash-gc-1")
	if status != upstream.StatusError && status != upstream.StatusDisconnected {
		t.Errorf("expected Error or Disconnected after crash, got %q", status)
	}
}

// TestRapidReconnectCycles loops through Start/Stop cycles to verify that each
// cycle properly tears down the old reader goroutine and creates a new one.
// After all cycles, goleak.VerifyNone ensures no goroutines leaked.
func TestRapidReconnectCycles(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "rapid-rc-1",
		Name:    "rapid-reconnect",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	mgr, tf := testManagerEnvTracked(t, u)
	mgr.backoffBase = 5 * time.Millisecond

	defer goleak.VerifyNone(t)
	defer tf.closeAll()
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	const cycles = 10

	for i := 0; i < cycles; i++ {
		if err := mgr.Start(ctx, "rapid-rc-1"); err != nil {
			t.Fatalf("cycle %d: Start() error: %v", i, err)
		}

		if !waitStatus(t, mgr, "rapid-rc-1", upstream.StatusConnected, 2*time.Second) {
			t.Fatalf("cycle %d: upstream did not reach Connected within 2s", i)
		}

		if err := mgr.Stop("rapid-rc-1"); err != nil {
			t.Fatalf("cycle %d: Stop() error: %v", i, err)
		}

		if !waitStatus(t, mgr, "rapid-rc-1", upstream.StatusDisconnected, 2*time.Second) {
			t.Fatalf("cycle %d: upstream did not reach Disconnected within 2s", i)
		}
	}
}

// TestShutdownWithPendingConnections verifies that Close() cleanly tears down
// multiple active connections. Three upstreams are started and connected; then
// Close() is called. All reader goroutines, health monitors, and retry timers
// must exit. goleak.VerifyNone validates no leaks.
func TestShutdownWithPendingConnections(t *testing.T) {
	us := make([]*upstream.Upstream, 3)
	for i := 0; i < 3; i++ {
		us[i] = &upstream.Upstream{
			ID:      fmt.Sprintf("shutdown-pc-%d", i),
			Name:    fmt.Sprintf("shutdown-pending-%d", i),
			Type:    upstream.UpstreamTypeStdio,
			Enabled: true,
			Command: "/usr/bin/echo",
		}
	}

	mgr, tf := testManagerEnvTracked(t, us...)
	defer goleak.VerifyNone(t)
	defer tf.closeAll()

	ctx := context.Background()

	// Start all three upstreams.
	for _, u := range us {
		if err := mgr.Start(ctx, u.ID); err != nil {
			t.Fatalf("Start(%s) error: %v", u.ID, err)
		}
	}

	// Wait for all to be connected.
	for _, u := range us {
		if !waitStatus(t, mgr, u.ID, upstream.StatusConnected, 2*time.Second) {
			t.Fatalf("upstream %s did not reach Connected within 2s", u.ID)
		}
	}

	// Close the manager — this must clean up all goroutines.
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}

	// After Close(), all upstreams should be disconnected.
	for _, u := range us {
		status, _ := mgr.Status(u.ID)
		if status != upstream.StatusDisconnected {
			t.Errorf("upstream %s status after Close() = %q, want %q", u.ID, status, upstream.StatusDisconnected)
		}
	}
}

// =============================================================================
// 2C — Deadlock Scenarios
// =============================================================================

// TestLineCh_Full_WriterBlocked verifies that stopping a connection with a
// potentially full lineCh (capacity 8) does not deadlock. When stopConnection
// closes the client and pipes, the reader goroutine exits (scanner EOF), closes
// lineCh, and stopConnection drains any remaining items.
func TestLineCh_Full_WriterBlocked(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "linech-full-1",
		Name:    "linech-blocked",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	mgr, tf := testManagerEnvTracked(t, u)
	defer goleak.VerifyNone(t)
	defer tf.closeAll()
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()
	if err := mgr.Start(ctx, "linech-full-1"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	if !waitStatus(t, mgr, "linech-full-1", upstream.StatusConnected, 2*time.Second) {
		t.Fatal("upstream did not reach Connected within 2s")
	}

	// Stop closes pipes -> scanner exits -> goroutine closes lineCh ->
	// stopConnection drains lineCh. This must not deadlock.
	stopDone := make(chan error, 1)
	go func() {
		stopDone <- mgr.Stop("linech-full-1")
	}()

	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop() unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: Stop() did not complete within 5s")
	}

	status, _ := mgr.Status("linech-full-1")
	if status != upstream.StatusDisconnected {
		t.Errorf("status after Stop() = %q, want %q", status, upstream.StatusDisconnected)
	}
}

// TestConcurrentStatusDuringStartStop verifies that calling Status() from
// multiple goroutines while Start/Stop is in progress does not deadlock or
// panic. Status() takes a RLock on mu and then locks conn.mu — this must not
// conflict with Start/Stop which take a write lock on mu.
func TestConcurrentStatusDuringStartStop(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "status-race-1",
		Name:    "status-during-startstop",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	mgr, tf := testManagerEnvTracked(t, u)
	mgr.backoffBase = 5 * time.Millisecond

	defer goleak.VerifyNone(t)
	defer tf.closeAll()
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 3 goroutines continuously polling Status.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = mgr.Status("status-race-1")
					_ = mgr.StatusAll()
					_ = mgr.AllConnected()
				}
			}
		}()
	}

	// 2 goroutines doing Start/Stop cycles.
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				select {
				case <-stop:
					return
				default:
				}
				_ = mgr.Start(ctx, "status-race-1")
				time.Sleep(10 * time.Millisecond)
				_ = mgr.Stop("status-race-1")
			}
		}()
	}

	// Let it run for a bounded time.
	time.Sleep(500 * time.Millisecond)
	close(stop)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines exited cleanly.
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: goroutines did not exit within 5s")
	}
}

// TestCloseIdempotent verifies that calling Close() multiple times from
// concurrent goroutines does not panic or deadlock. The closed flag inside
// Close() must be properly guarded by the mutex.
func TestCloseIdempotent(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "close-idem-1",
		Name:    "close-idempotent",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	mgr, tf := testManagerEnvTracked(t, u)
	defer goleak.VerifyNone(t)
	defer tf.closeAll()

	ctx := context.Background()
	if err := mgr.Start(ctx, "close-idem-1"); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	if !waitStatus(t, mgr, "close-idem-1", upstream.StatusConnected, 2*time.Second) {
		t.Fatal("upstream did not reach Connected within 2s")
	}

	const closers = 5
	var wg sync.WaitGroup
	wg.Add(closers)

	errs := make([]error, closers)
	for i := 0; i < closers; i++ {
		i := i
		go func() {
			defer wg.Done()
			errs[i] = mgr.Close()
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// No deadlock.
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: concurrent Close() calls did not complete within 5s")
	}

	// All calls must succeed (Close is idempotent).
	for i, err := range errs {
		if err != nil {
			t.Errorf("Close() call %d returned unexpected error: %v", i, err)
		}
	}
}

// =============================================================================
// 2A.3 — Reconnect During In-Flight Call
// =============================================================================

// TestReconnectDuringInFlightCall verifies that stopping a manager while a
// goroutine is blocked reading from lineCh (simulating an in-flight tool call)
// does not deadlock. Stop closes the pipes, which causes the reader goroutine
// to exit and close lineCh. The blocked reader receives a channel-close signal.
func TestReconnectDuringInFlightCall(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := &upstream.Upstream{
		ID:      "inflight-2a3",
		Name:    "inflight-call",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/true",
	}

	// Responder: completes initialize normally, then never responds to tool calls.
	// The scanner loop keeps reading but never writes a response, simulating a
	// slow upstream. When Stop() closes the pipes, the scanner exits.
	responder := func(reqReader *io.PipeReader, respWriter *io.PipeWriter) {
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			line := scanner.Text()

			if strings.Contains(line, "initialize") {
				var req struct {
					ID json.RawMessage `json:"id"`
				}
				if err := json.Unmarshal([]byte(line), &req); err != nil || req.ID == nil {
					continue
				}
				resp := fmt.Sprintf(
					`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"1.0"}}}`,
					string(req.ID),
				)
				fmt.Fprintln(respWriter, resp)
				continue
			}
			// Tool calls: read but never respond. The scanner loop continues
			// until the pipe is closed by Stop().
		}
	}

	mgr := adversarialManagerEnv(t, u, responder)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()
	if err := mgr.Start(ctx, u.ID); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	if !waitForStatus(t, mgr, u.ID, upstream.StatusConnected, 3*time.Second) {
		status, lastErr := mgr.Status(u.ID)
		t.Fatalf("expected StatusConnected, got %q (lastErr=%q)", status, lastErr)
	}

	// Get the connection's stdin and lineCh.
	stdin, lineCh, err := mgr.GetConnection(u.ID)
	if err != nil {
		t.Fatalf("GetConnection() unexpected error: %v", err)
	}

	// In a goroutine, simulate an in-flight tool call:
	// write a request to stdin and block reading from lineCh.
	type readResult struct {
		data    []byte
		closed  bool
		readErr bool
	}
	resultCh := make(chan readResult, 1)

	go func() {
		toolReq := `{"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":{"name":"test-tool","arguments":{}}}` + "\n"
		_, writeErr := stdin.Write([]byte(toolReq))
		if writeErr != nil {
			// Pipe may already be closed by Stop; that's fine.
			resultCh <- readResult{readErr: true}
			return
		}

		// Block reading from lineCh — this simulates forwardToUpstream.
		data, ok := <-lineCh
		resultCh <- readResult{data: data, closed: !ok}
	}()

	// After 200ms, stop the manager to close the pipes.
	time.Sleep(200 * time.Millisecond)
	if err := mgr.Stop(u.ID); err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}

	// The reading goroutine should unblock because lineCh gets closed.
	select {
	case res := <-resultCh:
		if !res.closed && !res.readErr {
			t.Log("reader goroutine received data before close (possible but unlikely)")
		}
		// Either channel was closed or write failed — both are acceptable.
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: reader goroutine did not unblock within 5s after Stop()")
	}
}

// =============================================================================
// 2B.2 — Stop During Handshake
// =============================================================================

// TestStopDuringHandshake verifies that when an upstream never responds to the
// initialize request (so Start blocks in readLineUnbuffered), externally closing
// the client's pipes unblocks Start. This is the same pattern as
// TestHandshake_UpstreamNeverResponds but focused on goroutine cleanup.
func TestStopDuringHandshake(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := &upstream.Upstream{
		ID:      "stop-hs-2b2",
		Name:    "stop-during-handshake",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/true",
	}

	// Keep a reference to the adversarial client so we can close its pipes
	// directly — same pattern as TestHandshake_UpstreamNeverResponds.
	var clientRef *adversarialMCPClient
	var clientMu sync.Mutex

	store := newMgrMockUpstreamStore()
	_ = store.Add(context.Background(), u)
	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger)

	// Responder reads the initialize request but never writes back.
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
	defer func() { _ = mgr.Close() }()

	// Start blocks because readLineUnbuffered hangs (BUG B5).
	startDone := make(chan error, 1)
	go func() {
		startDone <- mgr.Start(context.Background(), u.ID)
	}()

	// Give time for the handshake to be attempted.
	time.Sleep(500 * time.Millisecond)

	// Verify Start() is still blocked.
	select {
	case <-startDone:
		// If Start returned, B5 may be fixed. Proceed with cleanup.
		t.Log("Start() returned (B5 may be fixed); proceeding with cleanup")
	default:
		// Expected: Start() is blocked.
	}

	// Close the client directly to unblock readLineUnbuffered.
	clientMu.Lock()
	ref := clientRef
	clientMu.Unlock()
	if ref != nil {
		_ = ref.Close()
	}

	// Wait for Start() goroutine to finish after pipe close.
	select {
	case <-startDone:
		// Good — readLineUnbuffered got EOF from pipe close.
	case <-time.After(5 * time.Second):
		t.Fatal("Start() goroutine did not unblock after closing client pipes")
	}
}

// =============================================================================
// 2B.3 — Context Cancellation Does Not Unblock forwardToUpstream
// =============================================================================

// TestContextCancellation_ForwardToUpstream documents that forwardToUpstream
// does NOT use context for timeout — it uses time.After(30s) internally.
// When a tool call is in-flight and the context is cancelled, forwardToUpstream
// remains blocked on lineCh/timer until the pipes are closed or the timer fires.
// We use a short test timeout to avoid waiting the full 30s.
func TestContextCancellation_ForwardToUpstream(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := &upstream.Upstream{
		ID:      "ctx-cancel-2b3",
		Name:    "ctx-cancel-forward",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/true",
	}

	// Responder: completes initialize, but never responds to tool calls.
	responder := func(reqReader *io.PipeReader, respWriter *io.PipeWriter) {
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			line := scanner.Text()

			if strings.Contains(line, "initialize") {
				var req struct {
					ID json.RawMessage `json:"id"`
				}
				if err := json.Unmarshal([]byte(line), &req); err != nil || req.ID == nil {
					continue
				}
				resp := fmt.Sprintf(
					`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"1.0"}}}`,
					string(req.ID),
				)
				fmt.Fprintln(respWriter, resp)
				continue
			}
			// Tool calls: read but never respond.
		}
	}

	mgr := adversarialManagerEnv(t, u, responder)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()
	if err := mgr.Start(ctx, u.ID); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	if !waitForStatus(t, mgr, u.ID, upstream.StatusConnected, 3*time.Second) {
		status, lastErr := mgr.Status(u.ID)
		t.Fatalf("expected StatusConnected, got %q (lastErr=%q)", status, lastErr)
	}

	stdin, lineCh, err := mgr.GetConnection(u.ID)
	if err != nil {
		t.Fatalf("GetConnection() unexpected error: %v", err)
	}

	// Write a tool call request.
	toolReq := `{"jsonrpc":"2.0","id":"call-ctx","method":"tools/call","params":{"name":"test-tool","arguments":{}}}` + "\n"
	if _, err := stdin.Write([]byte(toolReq)); err != nil {
		t.Fatalf("write tool call: %v", err)
	}

	// Create a cancellable context and cancel it after 200ms.
	cancelCtx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)

	// Try reading from lineCh with context cancellation.
	// Document: context cancellation does NOT unblock lineCh reads.
	readDone := make(chan bool, 1)
	go func() {
		select {
		case <-cancelCtx.Done():
			// Context was cancelled, but lineCh is still blocking.
			readDone <- false
		case _, ok := <-lineCh:
			readDone <- ok
		}
	}()

	// Wait for the context cancellation to fire (200ms + margin).
	select {
	case gotData := <-readDone:
		if !gotData {
			// Expected: context cancellation fired, lineCh was not unblocked by it.
			t.Log("documented: context cancellation does not unblock lineCh read (forwardToUpstream uses time.After, not ctx)")
		} else {
			t.Log("unexpected: lineCh received data despite upstream never responding")
		}
	case <-time.After(2 * time.Second):
		// Both lineCh and context are stuck — this should not happen because
		// we cancel the context after 200ms.
		t.Fatal("deadlock: neither context cancellation nor lineCh read completed within 2s")
	}

	// Clean up: close the manager to unblock the lineCh reader goroutine.
	// This is necessary because the upstream never responds and we need the
	// channel reader goroutine to exit for goleak to pass.
}

// =============================================================================
// 2C.2 — Per-Upstream Mutex / Concurrent LineCh Access
// =============================================================================

// TestPerUpstreamMutex_ConcurrentLineCh verifies that two concurrent goroutines
// writing to stdin and reading from the same lineCh (for the same upstream) do
// not panic under the race detector. At the manager level, lineCh is shared for
// all callers to the same upstream. This test verifies no data race occurs.
func TestPerUpstreamMutex_ConcurrentLineCh(t *testing.T) {
	defer goleak.VerifyNone(t)

	u := &upstream.Upstream{
		ID:      "mutex-2c2",
		Name:    "concurrent-linech",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/true",
	}

	// Responder: completes initialize, then responds to each tool call in order.
	var msgCount atomic.Int32
	responder := func(reqReader *io.PipeReader, respWriter *io.PipeWriter) {
		scanner := bufio.NewScanner(reqReader)
		for scanner.Scan() {
			line := scanner.Text()

			if strings.Contains(line, "initialize") {
				var req struct {
					ID json.RawMessage `json:"id"`
				}
				if err := json.Unmarshal([]byte(line), &req); err != nil || req.ID == nil {
					continue
				}
				resp := fmt.Sprintf(
					`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"mock","version":"1.0"}}}`,
					string(req.ID),
				)
				fmt.Fprintln(respWriter, resp)
				continue
			}

			// For tool calls, respond immediately with the same ID.
			if strings.Contains(line, "tools/call") {
				var req struct {
					ID json.RawMessage `json:"id"`
				}
				if err := json.Unmarshal([]byte(line), &req); err != nil || req.ID == nil {
					continue
				}
				n := msgCount.Add(1)
				resp := fmt.Sprintf(
					`{"jsonrpc":"2.0","id":%s,"result":{"content":[{"text":"response-%d"}]}}`,
					string(req.ID), n,
				)
				fmt.Fprintln(respWriter, resp)
			}
		}
	}

	mgr := adversarialManagerEnv(t, u, responder)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()
	if err := mgr.Start(ctx, u.ID); err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	if !waitForStatus(t, mgr, u.ID, upstream.StatusConnected, 3*time.Second) {
		status, lastErr := mgr.Status(u.ID)
		t.Fatalf("expected StatusConnected, got %q (lastErr=%q)", status, lastErr)
	}

	stdin, lineCh, err := mgr.GetConnection(u.ID)
	if err != nil {
		t.Fatalf("GetConnection() unexpected error: %v", err)
	}

	// Two goroutines concurrently write to stdin and read from lineCh.
	const goroutines = 2
	var wg sync.WaitGroup
	wg.Add(goroutines)

	var responses atomic.Int32
	var panicCount atomic.Int32

	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panicCount.Add(1)
					t.Errorf("goroutine %d panicked: %v", g, r)
				}
			}()

			toolReq := fmt.Sprintf(
				`{"jsonrpc":"2.0","id":"call-%d","method":"tools/call","params":{"name":"test-tool","arguments":{}}}`,
				g,
			)
			if _, err := fmt.Fprintln(stdin, toolReq); err != nil {
				// Pipe may be closed; that's acceptable.
				return
			}

			// Read from lineCh — whichever goroutine gets it first wins.
			select {
			case data, ok := <-lineCh:
				if ok && len(data) > 0 {
					responses.Add(1)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("goroutine %d: timed out reading from lineCh", g)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines completed.
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock detected: goroutines did not complete within 10s")
	}

	if panicCount.Load() > 0 {
		t.Fatalf("detected %d panics during concurrent lineCh access", panicCount.Load())
	}

	// Both goroutines wrote requests, and the upstream responded to both.
	// However, since lineCh is shared and reads are competitive, each goroutine
	// may get the other's response. We only verify at least one was received.
	if responses.Load() == 0 {
		t.Error("expected at least one response from concurrent lineCh reads")
	}
}

// =============================================================================
// 2C.3 — ToolCache Lock During Reconnect
// =============================================================================

// TestToolCacheLock_DuringReconnect verifies that the ToolCache RWMutex does not
// cause deadlocks when a reconnect (write-heavy SetToolsForUpstream) races with
// client requests (read-heavy GetAllTools, GetTool). This simulates the pattern
// where an upstream reconnects and refreshes its tool list while clients are
// actively routing requests through the cache.
func TestToolCacheLock_DuringReconnect(t *testing.T) {
	t.Parallel()

	cache := upstream.NewToolCache()
	const upstreamID = "reconnect-upstream"

	// Pre-populate with initial tools.
	initialTools := make([]*upstream.DiscoveredTool, 5)
	for i := 0; i < 5; i++ {
		initialTools[i] = &upstream.DiscoveredTool{
			Name:        fmt.Sprintf("tool-%d", i),
			Description: "initial tool",
			UpstreamID:  upstreamID,
		}
	}
	cache.SetToolsForUpstream(upstreamID, initialTools)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Goroutine 1: simulates reconnect — replaces tools in a tight loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		gen := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			gen++
			newTools := make([]*upstream.DiscoveredTool, 3+gen%5)
			for i := range newTools {
				newTools[i] = &upstream.DiscoveredTool{
					Name:        fmt.Sprintf("tool-gen%d-%d", gen, i),
					Description: fmt.Sprintf("generation %d", gen),
					UpstreamID:  upstreamID,
				}
			}
			cache.SetToolsForUpstream(upstreamID, newTools)
		}
	}()

	// Goroutine 2: simulates client requests — reads from cache in a tight loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = cache.GetAllTools()
			_, _ = cache.GetTool("tool-0")
			_, _ = cache.GetTool("tool-gen1-0")
			_ = cache.GetToolsByUpstream(upstreamID)
			_ = cache.Count()
		}
	}()

	// Let the concurrent phase run for 500ms.
	time.Sleep(500 * time.Millisecond)
	close(stop)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// No deadlock.
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: concurrent ToolCache reconnect access did not complete within 5s")
	}

	// Verify cache consistency: tools should belong to our upstream only.
	tools := cache.GetToolsByUpstream(upstreamID)
	allTools := cache.GetAllTools()

	if len(tools) == 0 {
		t.Error("expected ToolCache to have tools for upstream after concurrent writes")
	}

	// All tools in the cache should belong to our upstream.
	for _, tool := range allTools {
		if tool.UpstreamID != upstreamID {
			t.Errorf("found tool %q from unexpected upstream %q", tool.Name, tool.UpstreamID)
		}
	}

	// Count should be consistent.
	if cache.Count() != len(allTools) {
		t.Errorf("Count() = %d but GetAllTools() returned %d", cache.Count(), len(allTools))
	}
}

// =============================================================================
// 2A.5 — Tool Discovery During Routing
// =============================================================================

// TestToolDiscoveryDuringRouting verifies that SetToolsForUpstream racing with
// GetAllTools, GetTool, and GetToolsByUpstream is race-detector clean. This is
// similar to 2C.3 but uses multiple reader goroutines with varied access
// patterns to increase contention.
func TestToolDiscoveryDuringRouting(t *testing.T) {
	t.Parallel()

	cache := upstream.NewToolCache()
	const numUpstreams = 3

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Goroutine 1: writer — continuously updates tool sets for multiple upstreams.
	wg.Add(1)
	go func() {
		defer wg.Done()
		gen := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			gen++
			for uid := 0; uid < numUpstreams; uid++ {
				upstreamID := fmt.Sprintf("upstream-%d", uid)
				toolCount := 2 + gen%4
				tools := make([]*upstream.DiscoveredTool, toolCount)
				for i := range tools {
					tools[i] = &upstream.DiscoveredTool{
						Name:        fmt.Sprintf("u%d-tool-%d", uid, i),
						Description: fmt.Sprintf("gen %d", gen),
						UpstreamID:  upstreamID,
					}
				}
				cache.SetToolsForUpstream(upstreamID, tools)
			}
		}
	}()

	// Goroutines 2-4: readers — varied access patterns.
	// Reader A: GetAllTools
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			tools := cache.GetAllTools()
			// Just access the slice to exercise memory.
			for _, t := range tools {
				_ = t.Name
			}
		}
	}()

	// Reader B: GetTool (lookup by name)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for uid := 0; uid < numUpstreams; uid++ {
				for i := 0; i < 5; i++ {
					name := fmt.Sprintf("u%d-tool-%d", uid, i)
					_, _ = cache.GetTool(name)
				}
			}
		}
	}()

	// Reader C: GetToolsByUpstream
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for uid := 0; uid < numUpstreams; uid++ {
				upstreamID := fmt.Sprintf("upstream-%d", uid)
				tools := cache.GetToolsByUpstream(upstreamID)
				for _, t := range tools {
					_ = t.Description
				}
			}
		}
	}()

	// Let the concurrent phase run for 500ms.
	time.Sleep(500 * time.Millisecond)
	close(stop)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Race detector clean, no panic.
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: concurrent tool discovery/routing did not complete within 5s")
	}

	// Verify eventual consistency: after all writes have stopped, the cache
	// should be in a consistent state.
	allTools := cache.GetAllTools()
	count := cache.Count()
	if count != len(allTools) {
		t.Errorf("Count() = %d but GetAllTools() returned %d items", count, len(allTools))
	}

	// Each upstream should have some tools.
	for uid := 0; uid < numUpstreams; uid++ {
		upstreamID := fmt.Sprintf("upstream-%d", uid)
		tools := cache.GetToolsByUpstream(upstreamID)
		if len(tools) == 0 {
			t.Errorf("expected tools for %s after concurrent writes", upstreamID)
		}
	}
}
