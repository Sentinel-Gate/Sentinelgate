package service

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
)

// ClientFactory creates an MCPClient from an upstream configuration.
// The default factory creates StdioClient for stdio type and HTTPClient for http type.
type ClientFactory func(u *upstream.Upstream) (outbound.MCPClient, error)

// upstreamConnection holds the runtime state for a single upstream connection.
type upstreamConnection struct {
	client         outbound.MCPClient
	upstream       *upstream.Upstream
	status         upstream.ConnectionStatus
	lastError      string
	stdin          io.WriteCloser
	stdout         io.ReadCloser
	stdoutScanner  *bufio.Scanner
	lineCh         chan []byte
	retryCount     int
	connectedSince time.Time
	cancelRetry    context.CancelFunc // cancels pending retry goroutine
	mu             sync.Mutex
}

// UpstreamManager handles lifecycle management of multiple MCP server connections.
// It provides start, stop, restart, health monitoring, and exponential backoff retry.
type UpstreamManager struct {
	upstreamService *UpstreamService
	clientFactory   ClientFactory
	connections     map[string]*upstreamConnection
	mu              sync.RWMutex
	logger          *slog.Logger
	ctx             context.Context
	cancel          context.CancelFunc
	closed          bool
	wg              sync.WaitGroup // tracks stabilityChecker and monitorHealth goroutines

	// Configurable parameters (exported for testing).
	backoffBase            time.Duration
	backoffCap             time.Duration
	maxRetries             int
	stabilityDuration      time.Duration
	stabilityCheckInterval time.Duration

	// onStopCallback is called with the upstream ID after Stop() removes a connection.
	// Used to clean up external resources (e.g., per-upstream I/O mutexes in the router).
	onStopCallback func(upstreamID string)

	// ready is closed after construction to signal goroutines they can read config.
	ready chan struct{}
}

// SetOnStopCallback registers a function to be called with the upstream ID
// whenever an upstream is stopped and removed from management. This allows
// external cleanup of per-upstream resources (e.g., sync.Map entries).
func (m *UpstreamManager) SetOnStopCallback(fn func(upstreamID string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onStopCallback = fn
}

// NewUpstreamManager creates a new UpstreamManager.
func NewUpstreamManager(upstreamService *UpstreamService, clientFactory ClientFactory, logger *slog.Logger) *UpstreamManager {
	ctx, cancel := context.WithCancel(context.Background())
	mgr := &UpstreamManager{
		upstreamService:        upstreamService,
		clientFactory:          clientFactory,
		connections:            make(map[string]*upstreamConnection),
		logger:                 logger,
		ctx:                    ctx,
		cancel:                 cancel,
		backoffBase:            1 * time.Second,
		backoffCap:             60 * time.Second,
		maxRetries:             10,
		stabilityDuration:      5 * time.Minute,
		stabilityCheckInterval: 1 * time.Minute,
		ready:                  make(chan struct{}),
	}

	// Start stability reset checker.
	mgr.wg.Add(1)
	go mgr.stabilityChecker()

	// Signal that configuration is set and background goroutines may read it.
	// Tests that need to override config should call Init() manually instead.
	close(mgr.ready)

	return mgr
}

// Init signals background goroutines that configuration is ready to be read.
// This is called automatically by NewUpstreamManager. Tests that need to override
// configuration fields (e.g. stabilityCheckInterval) should use NewUpstreamManagerUnstarted
// to create the manager, set fields, then call Init().
func (m *UpstreamManager) Init() {
	select {
	case <-m.ready:
		// already initialized
	default:
		close(m.ready)
	}
}

// NewUpstreamManagerUnstarted creates a new UpstreamManager without signaling
// background goroutines to start. The caller MUST call Init() after configuring
// fields. This is intended for tests that need to override timing parameters.
func NewUpstreamManagerUnstarted(upstreamService *UpstreamService, clientFactory ClientFactory, logger *slog.Logger) *UpstreamManager {
	ctx, cancel := context.WithCancel(context.Background())
	mgr := &UpstreamManager{
		upstreamService:        upstreamService,
		clientFactory:          clientFactory,
		connections:            make(map[string]*upstreamConnection),
		logger:                 logger,
		ctx:                    ctx,
		cancel:                 cancel,
		backoffBase:            1 * time.Second,
		backoffCap:             60 * time.Second,
		maxRetries:             10,
		stabilityDuration:      5 * time.Minute,
		stabilityCheckInterval: 1 * time.Minute,
		ready:                  make(chan struct{}),
	}

	// Start stability reset checker (will block on ready channel).
	mgr.wg.Add(1)
	go mgr.stabilityChecker()

	return mgr
}

// StartAll starts all enabled upstreams from the upstream service.
func (m *UpstreamManager) StartAll(ctx context.Context) error {
	upstreams, err := m.upstreamService.List(ctx)
	if err != nil {
		return fmt.Errorf("list upstreams: %w", err)
	}

	// Create a context with timeout so goroutines unblock on timeout.
	startCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error
	for i := range upstreams {
		u := upstreams[i]
		if !u.Enabled {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Start(startCtx, u.ID); err != nil {
				m.logger.Error("failed to start upstream", "id", u.ID, "name", u.Name, "error", err)
				mu.Lock()
				errs = append(errs, fmt.Errorf("upstream %s (%s): %w", u.ID, u.Name, err))
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	if startCtx.Err() != nil {
		return fmt.Errorf("timeout waiting for all upstreams to start: %w", startCtx.Err())
	}
	return errors.Join(errs...)
}

// Start starts an individual upstream by ID.
// If the connection fails, it schedules a retry with exponential backoff.
func (m *UpstreamManager) Start(ctx context.Context, upstreamID string) error {
	// Get upstream config.
	u, err := m.upstreamService.Get(ctx, upstreamID)
	if err != nil {
		return fmt.Errorf("get upstream %s: %w", upstreamID, err)
	}

	// Create connection entry.
	conn := &upstreamConnection{
		upstream: u,
		status:   upstream.StatusConnecting,
	}

	m.mu.Lock()
	m.connections[upstreamID] = conn
	m.mu.Unlock()

	// Attempt connection.
	m.attemptConnect(conn)

	return nil
}

// attemptConnect tries to connect to an upstream and handles success/failure.
func (m *UpstreamManager) attemptConnect(conn *upstreamConnection) {
	conn.mu.Lock()
	u := conn.upstream
	conn.mu.Unlock()

	// Create client via factory.
	client, err := m.clientFactory(u)
	if err != nil {
		conn.mu.Lock()
		conn.status = upstream.StatusError
		conn.lastError = fmt.Sprintf("create client: %v", err)
		conn.mu.Unlock()
		m.logger.Error("failed to create client", "id", u.ID, "error", err)
		m.scheduleRetry(conn)
		return
	}

	// Start the client.
	stdin, stdout, err := client.Start(m.ctx)
	if err != nil {
		conn.mu.Lock()
		conn.status = upstream.StatusError
		conn.lastError = fmt.Sprintf("start client: %v", err)
		conn.mu.Unlock()
		m.logger.Error("failed to start upstream", "id", u.ID, "error", err)
		m.scheduleRetry(conn)
		return
	}

	if err := m.performInitHandshake(m.ctx, stdin, stdout, u.ID); err != nil {
		m.logger.Error("MCP init handshake failed", "id", u.ID, "error", err)
		_ = client.Close()
		conn.mu.Lock()
		conn.status = upstream.StatusError
		conn.lastError = fmt.Sprintf("init handshake: %v", err)
		conn.mu.Unlock()
		m.scheduleRetry(conn)
		return
	}

	// Start single reader goroutine for the lifetime of this connection.
	// Lines are read into a channel so forwardToUpstream can read with timeout.
	//
	// We use json.Decoder instead of bufio.Scanner because upstream MCP servers
	// may emit literal newline bytes (0x0A) inside JSON string values. A line-based
	// scanner would split the message at those embedded newlines, producing
	// truncated/corrupt JSON fragments. json.Decoder correctly parses the JSON
	// structure and returns complete objects regardless of embedded whitespace.
	lineCh := make(chan []byte, 8)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer close(lineCh)
		dec := json.NewDecoder(stdout)
		for {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
					m.logger.Error("JSON decode error reading upstream stdout", "id", u.ID, "error", err)
				}
				return
			}
			select {
			case lineCh <- []byte(raw):
			case <-m.ctx.Done():
				return
			}
		}
	}()

	// Success — do NOT reset retryCount here; the stabilityChecker will
	// reset it once the connection has been stable long enough.  This
	// prevents infinite reconnect loops for upstreams that connect briefly
	// then crash again.
	conn.mu.Lock()
	conn.client = client
	conn.stdin = stdin
	conn.stdout = stdout
	conn.stdoutScanner = nil // no longer using bufio.Scanner
	conn.lineCh = lineCh
	conn.status = upstream.StatusConnected
	conn.lastError = ""
	conn.connectedSince = time.Now()
	conn.mu.Unlock()

	m.logger.Info("upstream connected", "id", u.ID, "name", u.Name)

	// Start health monitor goroutine.
	m.wg.Add(1)
	go m.monitorHealth(conn)
}

// Stop stops an individual upstream by ID.
func (m *UpstreamManager) Stop(upstreamID string) error {
	m.mu.Lock()
	conn, ok := m.connections[upstreamID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("upstream %s not managed", upstreamID)
	}
	delete(m.connections, upstreamID)
	cb := m.onStopCallback
	m.mu.Unlock()

	m.stopConnection(conn)

	// Notify external cleanup (e.g., remove per-upstream I/O mutex entries).
	if cb != nil {
		cb(upstreamID)
	}
	return nil
}

// stopConnection shuts down a connection, cancels retries, and closes the client.
func (m *UpstreamManager) stopConnection(conn *upstreamConnection) {
	conn.mu.Lock()

	// Cancel any pending retry.
	if conn.cancelRetry != nil {
		conn.cancelRetry()
		conn.cancelRetry = nil
	}

	// Close client first — this triggers mock/real process cleanup
	// which closes the write end of pipes, sending EOF to readers.
	if conn.client != nil {
		if err := conn.client.Close(); err != nil {
			m.logger.Error("failed to close client", "id", conn.upstream.ID, "error", err)
		}
		conn.client = nil
	}

	// Close stdin to signal EOF to upstream.
	if conn.stdin != nil {
		_ = conn.stdin.Close()
		conn.stdin = nil
	}

	// Close stdout to unblock the scanner goroutine in attemptConnect.
	if conn.stdout != nil {
		_ = conn.stdout.Close()
		conn.stdout = nil
	}

	// Snapshot and nil-out lineCh before releasing the lock so the drain
	// loop runs without holding conn.mu (avoids blocking other callers
	// for up to 5 seconds).
	lineCh := conn.lineCh
	conn.lineCh = nil
	conn.mu.Unlock()

	// Wait for the channel reader goroutine to exit by draining lineCh.
	// The goroutine closes lineCh when the scanner stops (after pipe close).
	if lineCh != nil {
		drainTimer := time.NewTimer(5 * time.Second)
		defer drainTimer.Stop()
	drain:
		for {
			select {
			case _, ok := <-lineCh:
				if !ok {
					break drain
				}
			case <-drainTimer.C:
				m.logger.Warn("lineCh drain timeout, forcing close", "id", conn.upstream.ID)
				break drain
			}
		}
	}

	conn.mu.Lock()
	conn.status = upstream.StatusDisconnected
	conn.mu.Unlock()
}

// Restart stops and then starts an upstream.
func (m *UpstreamManager) Restart(ctx context.Context, upstreamID string) error {
	// Stop (ignore error if not managed - we'll start fresh).
	_ = m.Stop(upstreamID)

	return m.Start(ctx, upstreamID)
}

// GetConnection returns the stdin/stdout for a connected upstream.
func (m *UpstreamManager) GetConnection(upstreamID string) (io.WriteCloser, <-chan []byte, error) {
	m.mu.RLock()
	conn, ok := m.connections[upstreamID]
	m.mu.RUnlock()

	if !ok {
		return nil, nil, fmt.Errorf("upstream %s not connected", upstreamID)
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.status != upstream.StatusConnected {
		return nil, nil, fmt.Errorf("upstream %s status is %s, not connected", upstreamID, conn.status)
	}

	return conn.stdin, conn.lineCh, nil
}

// Status returns the current status and last error for an upstream.
func (m *UpstreamManager) Status(upstreamID string) (upstream.ConnectionStatus, string) {
	m.mu.RLock()
	conn, ok := m.connections[upstreamID]
	m.mu.RUnlock()

	if !ok {
		return upstream.StatusDisconnected, ""
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.status, conn.lastError
}

// AllConnected returns true if at least one upstream is connected.
// Despite its name, this checks for "any connected" — used for availability
// gating (503 status check). Renamed semantics: returns true when at least one
// upstream is reachable, false only when all are disconnected.
func (m *UpstreamManager) AllConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, conn := range m.connections {
		conn.mu.Lock()
		status := conn.status
		conn.mu.Unlock()
		if status == upstream.StatusConnected {
			return true
		}
	}
	return false
}

// StatusAll returns the status of all managed upstreams.
func (m *UpstreamManager) StatusAll() map[string]upstream.ConnectionStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]upstream.ConnectionStatus, len(m.connections))
	for id, conn := range m.connections {
		conn.mu.Lock()
		result[id] = conn.status
		conn.mu.Unlock()
	}
	return result
}

// Close stops all upstreams and cancels the manager context.
func (m *UpstreamManager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true

	// Collect connections to stop.
	conns := make([]*upstreamConnection, 0, len(m.connections))
	for _, conn := range m.connections {
		conns = append(conns, conn)
	}
	m.connections = make(map[string]*upstreamConnection)
	m.mu.Unlock()

	// Cancel the manager context first to signal background goroutines to exit.
	if m.cancel != nil {
		m.cancel()
	}

	// Stop all connections (kills processes, which unblocks monitorHealth).
	for _, conn := range conns {
		m.stopConnection(conn)
	}

	// Wait for background goroutines (monitorHealth, stabilityChecker) to exit.
	// Use timeout to avoid deadlock if a goroutine is stuck in blocking I/O.
	// The helper goroutine exits when m.wg.Wait() returns (it will eventually
	// unblock because the context is cancelled and pipes are closed above).
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-waitCtx.Done():
		m.logger.Warn("timeout waiting for background goroutines to exit")
	}

	return nil
}

// SetBackoffBase sets the base backoff duration (exported for integration tests).
func (m *UpstreamManager) SetBackoffBase(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.backoffBase = d
}

// SetGlobalRetryConfig updates the manager-level retry limits that apply to all
// upstreams. Changes take effect on the next retry attempt.
// maxRetries is the maximum number of reconnection attempts before giving up;
// backoffCap is the maximum delay between retries.
func (m *UpstreamManager) SetGlobalRetryConfig(maxRetries int, backoffCap time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxRetries = maxRetries
	m.backoffCap = backoffCap
}

// ResetRetryCount resets the retry counter for a specific upstream to zero.
// This is useful after manual intervention that resolves the underlying issue,
// allowing the manager to attempt reconnection as if the upstream was fresh.
// Returns an error if the upstream is not currently managed.
func (m *UpstreamManager) ResetRetryCount(upstreamID string) error {
	m.mu.RLock()
	conn, ok := m.connections[upstreamID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("upstream %s not managed", upstreamID)
	}

	conn.mu.Lock()
	conn.retryCount = 0
	conn.mu.Unlock()

	return nil
}

// --- Backoff retry logic ---

// calcBackoffDelay calculates the delay for a given retry count.
// Formula: min(base * 2^retryCount, cap)
// The caller must pass snapshotted config values to avoid lock ordering issues.
func calcBackoffDelay(retryCount int, base, cap time.Duration) time.Duration {
	delay := base
	for i := 0; i < retryCount; i++ {
		delay *= 2
		if delay > cap {
			return cap
		}
	}
	if delay > cap {
		return cap
	}
	return delay
}

// scheduleRetry schedules a reconnection attempt with exponential backoff.
func (m *UpstreamManager) scheduleRetry(conn *upstreamConnection) {
	// Snapshot manager-level config before acquiring conn.mu to preserve
	// the established lock ordering (m.mu -> conn.mu).
	m.mu.RLock()
	maxRetries := m.maxRetries
	backoffBase := m.backoffBase
	backoffCap := m.backoffCap
	m.mu.RUnlock()

	conn.mu.Lock()

	if conn.retryCount >= maxRetries {
		conn.status = upstream.StatusError
		conn.lastError = fmt.Sprintf("max retries (%d) exceeded", maxRetries)
		conn.mu.Unlock()
		m.logger.Error("max retries exceeded", "id", conn.upstream.ID, "retries", maxRetries)
		return
	}

	delay := calcBackoffDelay(conn.retryCount, backoffBase, backoffCap)
	conn.retryCount++
	attempt := conn.retryCount
	conn.status = upstream.StatusConnecting

	// Create a cancellable context for this retry.
	retryCtx, retryCancel := context.WithCancel(m.ctx)
	conn.cancelRetry = retryCancel
	upstreamID := conn.upstream.ID
	conn.mu.Unlock()

	m.logger.Info("scheduling retry", "id", upstreamID, "attempt", attempt, "delay", delay)

	// M-2: Track retry goroutine in WaitGroup to prevent it from surviving Close().
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		retryTimer := time.NewTimer(delay)
		defer retryTimer.Stop()
		select {
		case <-retryTimer.C:
			// Proceed with reconnect.
		case <-retryCtx.Done():
			// Retry was cancelled (Stop was called, or manager shut down).
			return
		}

		// M-2: Check if manager is closed before attempting reconnect.
		m.mu.RLock()
		closed := m.closed
		currentConn, ok := m.connections[upstreamID]
		m.mu.RUnlock()

		if closed || !ok || currentConn != conn {
			return
		}

		m.attemptConnect(conn)
	}()
}

// --- Health monitoring ---

// monitorHealth blocks until the upstream client terminates, then triggers reconnection.
func (m *UpstreamManager) monitorHealth(conn *upstreamConnection) {
	defer m.wg.Done()
	conn.mu.Lock()
	client := conn.client
	upstreamID := conn.upstream.ID
	conn.mu.Unlock()

	if client == nil {
		return
	}

	// Wait blocks until the process exits or connection drops.
	if waitErr := client.Wait(); waitErr != nil {
		m.logger.Debug("upstream client.Wait returned error", "id", upstreamID, "error", waitErr)
	}

	// Check if we're still managing this connection.
	m.mu.RLock()
	currentConn, ok := m.connections[upstreamID]
	m.mu.RUnlock()

	if !ok || currentConn != conn {
		// Connection was stopped or replaced; don't reconnect.
		return
	}

	// Check manager context.
	if m.ctx.Err() != nil {
		return
	}

	conn.mu.Lock()
	conn.status = upstream.StatusDisconnected
	conn.client = nil
	// Close stdout to unblock the scanner goroutine, which will in turn
	// close lineCh. This ensures pending readers on lineCh are unblocked
	// promptly rather than waiting for an indeterminate delay.
	if conn.stdout != nil {
		_ = conn.stdout.Close()
		conn.stdout = nil
	}
	conn.stdin = nil
	conn.lineCh = nil // Prevent stale channel reads after disconnect.
	conn.mu.Unlock()

	m.logger.Warn("upstream disconnected, scheduling reconnect", "id", upstreamID)
	m.scheduleRetry(conn)
}

// --- Stability reset ---

// stabilityChecker periodically checks connected upstreams and resets their
// retry count if they've been stable for the configured duration.
func (m *UpstreamManager) stabilityChecker() {
	defer m.wg.Done()
	// Wait for the constructor to finish so configuration fields are safe to read.
	select {
	case <-m.ready:
	case <-m.ctx.Done():
		return
	}

	ticker := time.NewTicker(m.stabilityCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.checkStability()
		case <-m.ctx.Done():
			return
		}
	}
}

// checkStability resets retry count for upstreams that have been connected
// longer than the stability duration.
func (m *UpstreamManager) checkStability() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	for _, conn := range m.connections {
		conn.mu.Lock()
		if conn.status == upstream.StatusConnected &&
			conn.retryCount > 0 &&
			!conn.connectedSince.IsZero() &&
			now.Sub(conn.connectedSince) >= m.stabilityDuration {
			m.logger.Info("resetting retry count after stable connection",
				"id", conn.upstream.ID,
				"stable_since", conn.connectedSince,
				"previous_retries", conn.retryCount)
			conn.retryCount = 0
		}
		conn.mu.Unlock()
	}
}

// performInitHandshake sends MCP initialize + notifications/initialized through
// the given pipes. This is required for HTTP Streamable transports where the
// upstream server creates a session on initialize and requires subsequent
// requests to carry the Mcp-Session-Id header. The HTTPClient captures the
// session ID from the response headers automatically.
func (m *UpstreamManager) performInitHandshake(ctx context.Context, stdin io.WriteCloser, stdout io.ReadCloser, upstreamID string) error {
	// Apply handshake timeout to prevent leaked goroutines on unresponsive upstreams
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Send initialize
	idSuffix := upstreamID
	if len(idSuffix) > 8 {
		idSuffix = idSuffix[:8]
	}
	initReq := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":"init-%s","method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"sentinel-gate","version":"1.1.0"}}}`,
		idSuffix,
	)
	if _, err := fmt.Fprintln(stdin, initReq); err != nil {
		return fmt.Errorf("write initialize: %w", err)
	}

	// Read response using unbuffered read to avoid stealing bytes from the pipe.
	// Skip any notifications the upstream sends before the init response (B4 fix).
	//
	// CRITICAL: Each read uses a one-shot goroutine that we ALWAYS wait for
	// before returning. This guarantees no goroutine is left reading from stdout
	// when the main reader (json.Decoder) starts. A lingering goroutine calling
	// Read() on the same pipe would race with the decoder and corrupt data.
	const maxInitSkip = 10
	type readResult struct {
		line []byte
		err  error
	}

	var (
		line []byte
		err  error
	)
	for i := 0; i < maxInitSkip; i++ {
		ch := make(chan readResult, 1)
		go func() {
			l, e := readLineUnbuffered(stdout)
			ch <- readResult{l, e}
		}()

		select {
		case res := <-ch:
			// Goroutine completed and exited — pipe is clean.
			line, err = res.line, res.err
		case <-ctx.Done():
			// Timeout. The goroutine is stuck in Read(). The caller will
			// close the pipe (client.Close), which unblocks Read() with EOF.
			// We don't wait here because that would block indefinitely.
			return fmt.Errorf("init handshake timeout: %w", ctx.Err())
		}
		if err != nil {
			return fmt.Errorf("read initialize response: %w", err)
		}
		var peek struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(line, &peek) == nil && peek.ID == nil && peek.Method != "" {
			m.logger.Debug("skipping notification during init handshake", "method", peek.Method)
			continue
		}
		break
	}
	// At this point, every read goroutine has completed (sent to ch and exited).
	// The stdout pipe has no competing readers — safe for json.Decoder.

	// Validate response is not an error
	var envelope struct {
		Error *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(line, &envelope); err == nil && envelope.Error != nil {
		return fmt.Errorf("initialize error: %s", string(*envelope.Error))
	}

	// Send notifications/initialized (no response expected for notifications)
	notifReq := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	if _, err := fmt.Fprintln(stdin, notifReq); err != nil {
		return fmt.Errorf("write notifications/initialized: %w", err)
	}

	m.logger.Debug("init handshake complete", "upstream", upstreamID)
	return nil
}

// readLineUnbuffered reads a single newline-terminated line from r without
// buffering extra bytes. This is critical for stdio pipes where a buffered
// reader (bufio.Scanner) would consume bytes that belong to subsequent
// messages, causing the channel-based reader goroutine to miss them.
const maxLineLength = 1024 * 1024 // 1MB, same as scanner buffer

func readLineUnbuffered(r io.Reader) ([]byte, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return line, nil
			}
			line = append(line, buf[0])
			if len(line) > maxLineLength {
				return nil, fmt.Errorf("line exceeds maximum length (%d bytes)", maxLineLength)
			}
		}
		if err != nil {
			if len(line) > 0 {
				return line, nil
			}
			return nil, err
		}
	}
}
