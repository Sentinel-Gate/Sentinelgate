package service

import (
	"context"
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

	// Configurable parameters (exported for testing).
	backoffBase            time.Duration
	backoffCap             time.Duration
	maxRetries             int
	stabilityDuration      time.Duration
	stabilityCheckInterval time.Duration

	// ready is closed after construction to signal goroutines they can read config.
	ready chan struct{}
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
	go mgr.stabilityChecker()

	return mgr
}

// StartAll starts all enabled upstreams from the upstream service.
func (m *UpstreamManager) StartAll(ctx context.Context) error {
	upstreams, err := m.upstreamService.List(ctx)
	if err != nil {
		return fmt.Errorf("list upstreams: %w", err)
	}

	var wg sync.WaitGroup
	for i := range upstreams {
		u := upstreams[i]
		if !u.Enabled {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Start(ctx, u.ID); err != nil {
				m.logger.Error("failed to start upstream", "id", u.ID, "name", u.Name, "error", err)
			}
		}()
	}

	// Wait with timeout for all starts to attempt.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-time.After(30 * time.Second):
		return errors.New("timeout waiting for all upstreams to start")
	}
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

	// Success.
	conn.mu.Lock()
	conn.client = client
	conn.stdin = stdin
	conn.stdout = stdout
	conn.status = upstream.StatusConnected
	conn.lastError = ""
	conn.retryCount = 0
	conn.connectedSince = time.Now()
	conn.mu.Unlock()

	m.logger.Info("upstream connected", "id", u.ID, "name", u.Name)

	// Start health monitor goroutine.
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
	m.mu.Unlock()

	m.stopConnection(conn)
	return nil
}

// stopConnection shuts down a connection, cancels retries, and closes the client.
func (m *UpstreamManager) stopConnection(conn *upstreamConnection) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Cancel any pending retry.
	if conn.cancelRetry != nil {
		conn.cancelRetry()
		conn.cancelRetry = nil
	}

	// Close client if exists.
	if conn.client != nil {
		if err := conn.client.Close(); err != nil {
			m.logger.Error("failed to close client", "id", conn.upstream.ID, "error", err)
		}
		conn.client = nil
	}

	conn.status = upstream.StatusDisconnected
	conn.stdin = nil
	conn.stdout = nil
}

// Restart stops and then starts an upstream.
func (m *UpstreamManager) Restart(ctx context.Context, upstreamID string) error {
	// Stop (ignore error if not managed - we'll start fresh).
	_ = m.Stop(upstreamID)

	return m.Start(ctx, upstreamID)
}

// GetConnection returns the stdin/stdout for a connected upstream.
func (m *UpstreamManager) GetConnection(upstreamID string) (io.WriteCloser, io.ReadCloser, error) {
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

	return conn.stdin, conn.stdout, nil
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
// Returns false when all upstreams are disconnected (for 503 status check).
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

	// Stop all connections.
	for _, conn := range conns {
		m.stopConnection(conn)
	}

	// Cancel the manager context to stop background goroutines.
	if m.cancel != nil {
		m.cancel()
	}

	return nil
}

// SetBackoffBase sets the base backoff duration (exported for integration tests).
func (m *UpstreamManager) SetBackoffBase(d time.Duration) {
	m.backoffBase = d
}

// --- Backoff retry logic ---

// calcBackoffDelay calculates the delay for a given retry count.
// Formula: min(base * 2^retryCount, cap)
func (m *UpstreamManager) calcBackoffDelay(retryCount int) time.Duration {
	delay := m.backoffBase
	for i := 0; i < retryCount; i++ {
		delay *= 2
		if delay > m.backoffCap {
			return m.backoffCap
		}
	}
	if delay > m.backoffCap {
		return m.backoffCap
	}
	return delay
}

// scheduleRetry schedules a reconnection attempt with exponential backoff.
func (m *UpstreamManager) scheduleRetry(conn *upstreamConnection) {
	conn.mu.Lock()

	if conn.retryCount >= m.maxRetries {
		conn.status = upstream.StatusError
		conn.lastError = fmt.Sprintf("max retries (%d) exceeded", m.maxRetries)
		conn.mu.Unlock()
		m.logger.Error("max retries exceeded", "id", conn.upstream.ID, "retries", m.maxRetries)
		return
	}

	delay := m.calcBackoffDelay(conn.retryCount)
	conn.retryCount++
	attempt := conn.retryCount
	conn.status = upstream.StatusConnecting

	// Create a cancellable context for this retry.
	retryCtx, retryCancel := context.WithCancel(m.ctx)
	conn.cancelRetry = retryCancel
	upstreamID := conn.upstream.ID
	conn.mu.Unlock()

	m.logger.Info("scheduling retry", "id", upstreamID, "attempt", attempt, "delay", delay)

	go func() {
		select {
		case <-time.After(delay):
			// Proceed with reconnect.
		case <-retryCtx.Done():
			// Retry was cancelled (Stop was called, or manager shut down).
			return
		}

		// Check if connection is still managed.
		m.mu.RLock()
		currentConn, ok := m.connections[upstreamID]
		m.mu.RUnlock()

		if !ok || currentConn != conn {
			// Connection was removed or replaced.
			return
		}

		m.attemptConnect(conn)
	}()
}

// --- Health monitoring ---

// monitorHealth blocks until the upstream client terminates, then triggers reconnection.
func (m *UpstreamManager) monitorHealth(conn *upstreamConnection) {
	conn.mu.Lock()
	client := conn.client
	upstreamID := conn.upstream.ID
	conn.mu.Unlock()

	if client == nil {
		return
	}

	// Wait blocks until the process exits or connection drops.
	_ = client.Wait()

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
	conn.stdin = nil
	conn.stdout = nil
	conn.mu.Unlock()

	m.logger.Warn("upstream disconnected, scheduling reconnect", "id", upstreamID)
	m.scheduleRetry(conn)
}

// --- Stability reset ---

// stabilityChecker periodically checks connected upstreams and resets their
// retry count if they've been stable for the configured duration.
func (m *UpstreamManager) stabilityChecker() {
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
