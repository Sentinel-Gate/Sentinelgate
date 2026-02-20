package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
)

// --- Mock MCPClient for Manager tests ---

// mgrMockMCPClient implements outbound.MCPClient for testing the UpstreamManager.
type mgrMockMCPClient struct {
	mu         sync.Mutex
	startErr   error
	closeErr   error
	waitErr    error
	waitCh     chan struct{} // blocks Wait() until closed
	started    bool
	closed     bool
	startCount int
	closeCount int
}

func newMgrMockMCPClient() *mgrMockMCPClient {
	return &mgrMockMCPClient{
		waitCh: make(chan struct{}),
	}
}

func (m *mgrMockMCPClient) Start(ctx context.Context) (io.WriteCloser, io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCount++
	if m.startErr != nil {
		return nil, nil, m.startErr
	}
	m.started = true
	m.closed = false
	// Reset wait channel for new connection
	m.waitCh = make(chan struct{})
	return &mgrNopWriteCloser{}, &mgrNopReadCloser{}, nil
}

func (m *mgrMockMCPClient) Wait() error {
	<-m.waitCh
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.waitErr
}

func (m *mgrMockMCPClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCount++
	m.closed = true
	m.started = false
	// Signal wait to return
	select {
	case <-m.waitCh:
		// already closed
	default:
		close(m.waitCh)
	}
	return m.closeErr
}

func (m *mgrMockMCPClient) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// simulateCrash simulates the upstream process exiting unexpectedly.
func (m *mgrMockMCPClient) simulateCrash() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started = false
	select {
	case <-m.waitCh:
		// already closed
	default:
		close(m.waitCh)
	}
}

// Compile-time check.
var _ outbound.MCPClient = (*mgrMockMCPClient)(nil)

// mgrNopWriteCloser implements io.WriteCloser with no-ops.
type mgrNopWriteCloser struct{}

func (n *mgrNopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (n *mgrNopWriteCloser) Close() error                { return nil }

// mgrNopReadCloser implements io.ReadCloser with no-ops.
type mgrNopReadCloser struct{}

func (n *mgrNopReadCloser) Read(p []byte) (int, error) { return 0, io.EOF }
func (n *mgrNopReadCloser) Close() error               { return nil }

// --- Test Helpers ---

func testManagerLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// mgrMockUpstreamStore implements upstream.UpstreamStore for manager tests.
type mgrMockUpstreamStore struct {
	mu        sync.RWMutex
	upstreams map[string]*upstream.Upstream
}

func newMgrMockUpstreamStore() *mgrMockUpstreamStore {
	return &mgrMockUpstreamStore{
		upstreams: make(map[string]*upstream.Upstream),
	}
}

func (s *mgrMockUpstreamStore) List(_ context.Context) ([]upstream.Upstream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]upstream.Upstream, 0, len(s.upstreams))
	for _, u := range s.upstreams {
		result = append(result, *u)
	}
	return result, nil
}

func (s *mgrMockUpstreamStore) Get(_ context.Context, id string) (*upstream.Upstream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.upstreams[id]
	if !ok {
		return nil, upstream.ErrUpstreamNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *mgrMockUpstreamStore) Add(_ context.Context, u *upstream.Upstream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstreams[u.ID] = u
	return nil
}

func (s *mgrMockUpstreamStore) Update(_ context.Context, u *upstream.Upstream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.upstreams[u.ID]; !ok {
		return upstream.ErrUpstreamNotFound
	}
	s.upstreams[u.ID] = u
	return nil
}

func (s *mgrMockUpstreamStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.upstreams[id]; !ok {
		return upstream.ErrUpstreamNotFound
	}
	delete(s.upstreams, id)
	return nil
}

// testManagerEnv creates a manager with mocked dependencies.
// Returns the manager and a map of upstream IDs to their mock clients.
// Caller is responsible for calling mgr.Close() to prevent goroutine leaks.
func testManagerEnv(t *testing.T, upstreams ...*upstream.Upstream) (*UpstreamManager, map[string]*mgrMockMCPClient) {
	t.Helper()

	store := newMgrMockUpstreamStore()
	for _, u := range upstreams {
		_ = store.Add(context.Background(), u)
	}

	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger) // stateStore nil: we don't persist in manager tests

	mockClients := make(map[string]*mgrMockMCPClient)
	var clientsMu sync.Mutex

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		clientsMu.Lock()
		defer clientsMu.Unlock()
		// Return existing mock if already created (for reconnect scenarios)
		if mc, ok := mockClients[u.ID]; ok {
			return mc, nil
		}
		mc := newMgrMockMCPClient()
		mockClients[u.ID] = mc
		return mc, nil
	}

	mgr := NewUpstreamManager(svc, factory, logger)

	return mgr, mockClients
}

// --- StartAll Tests ---

func TestUpstreamManager_StartAll_StartsEnabledUpstreams(t *testing.T) {
	u1 := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}
	u2 := &upstream.Upstream{
		ID:      "up-2",
		Name:    "server-2",
		Type:    upstream.UpstreamTypeHTTP,
		Enabled: true,
		URL:     "http://localhost:8080/mcp",
	}
	u3 := &upstream.Upstream{
		ID:      "up-3",
		Name:    "disabled-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: false,
		Command: "/usr/bin/echo",
	}

	mgr, clients := testManagerEnv(t, u1, u2, u3)
	// Close BEFORE goleak checks (LIFO order of defers)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	err := mgr.StartAll(ctx)
	if err != nil {
		t.Fatalf("StartAll() unexpected error: %v", err)
	}

	// Wait a moment for goroutines to complete start
	time.Sleep(100 * time.Millisecond)

	// Enabled upstreams should be connected
	s1, _ := mgr.Status("up-1")
	if s1 != upstream.StatusConnected {
		t.Errorf("upstream up-1 status = %q, want %q", s1, upstream.StatusConnected)
	}
	s2, _ := mgr.Status("up-2")
	if s2 != upstream.StatusConnected {
		t.Errorf("upstream up-2 status = %q, want %q", s2, upstream.StatusConnected)
	}

	// Disabled upstream should NOT have been started (no client created)
	if _, ok := clients["up-3"]; ok {
		t.Error("disabled upstream up-3 should not have been started")
	}
}

func TestUpstreamManager_StartAll_EmptyUpstreams(t *testing.T) {
	mgr, _ := testManagerEnv(t)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	err := mgr.StartAll(ctx)
	if err != nil {
		t.Fatalf("StartAll() with no upstreams should not error: %v", err)
	}
}

// --- Start Tests ---

func TestUpstreamManager_Start_Success(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	mgr, _ := testManagerEnv(t, u)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	err := mgr.Start(ctx, "up-1")
	if err != nil {
		t.Fatalf("Start() unexpected error: %v", err)
	}

	status, lastErr := mgr.Status("up-1")
	if status != upstream.StatusConnected {
		t.Errorf("Status() = %q, want %q", status, upstream.StatusConnected)
	}
	if lastErr != "" {
		t.Errorf("Status() lastErr = %q, want empty", lastErr)
	}
}

func TestUpstreamManager_Start_NotFound(t *testing.T) {
	mgr, _ := testManagerEnv(t)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	err := mgr.Start(ctx, "nonexistent")
	if err == nil {
		t.Fatal("Start() nonexistent should return error")
	}
}

func TestUpstreamManager_Start_FailTriggersRetry(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	store := newMgrMockUpstreamStore()
	_ = store.Add(context.Background(), u)

	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger)

	failCount := atomic.Int32{}
	failUntil := int32(2) // fail first 2 attempts, succeed on 3rd

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		mc := newMgrMockMCPClient()
		if failCount.Add(1) <= failUntil {
			mc.startErr = errors.New("connection refused")
		}
		return mc, nil
	}

	mgr := NewUpstreamManager(svc, factory, logger)
	mgr.backoffBase = 10 * time.Millisecond
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()
	err := mgr.Start(ctx, "up-1")
	// Start should not return error even on failure; it schedules retry
	if err != nil {
		t.Fatalf("Start() should not return error on connection failure: %v", err)
	}

	// Status should be Connecting or Error initially
	status, _ := mgr.Status("up-1")
	if status != upstream.StatusConnecting && status != upstream.StatusError {
		t.Errorf("Status() after failed start = %q, want Connecting or Error", status)
	}

	// Wait for retries to complete (base=10ms, delay=10ms, 20ms -> should reconnect within 200ms)
	time.Sleep(200 * time.Millisecond)

	status, _ = mgr.Status("up-1")
	if status != upstream.StatusConnected {
		t.Errorf("Status() after retries = %q, want %q", status, upstream.StatusConnected)
	}
}

// --- Stop Tests ---

func TestUpstreamManager_Stop_Connected(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	mgr, clients := testManagerEnv(t, u)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	if err := mgr.Start(ctx, "up-1"); err != nil {
		t.Fatalf("Start(): %v", err)
	}

	// Wait for client to be created
	time.Sleep(50 * time.Millisecond)

	err := mgr.Stop("up-1")
	if err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}

	status, _ := mgr.Status("up-1")
	if status != upstream.StatusDisconnected {
		t.Errorf("Status() after Stop() = %q, want %q", status, upstream.StatusDisconnected)
	}

	mc := clients["up-1"]
	if mc != nil && !mc.isClosed() {
		t.Error("Stop() should have closed the client")
	}
}

func TestUpstreamManager_Stop_NotManaged(t *testing.T) {
	mgr, _ := testManagerEnv(t)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	err := mgr.Stop("nonexistent")
	if err == nil {
		t.Fatal("Stop() unmanaged upstream should return error")
	}
}

func TestUpstreamManager_Stop_CancelsPendingRetry(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	store := newMgrMockUpstreamStore()
	_ = store.Add(context.Background(), u)

	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger)

	// Always fail so retries are pending
	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		mc := newMgrMockMCPClient()
		mc.startErr = errors.New("connection refused")
		return mc, nil
	}

	mgr := NewUpstreamManager(svc, factory, logger)
	mgr.backoffBase = 1 * time.Second // long backoff so retry is pending
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()
	_ = mgr.Start(ctx, "up-1")

	// Wait for initial attempt
	time.Sleep(50 * time.Millisecond)

	// Stop should cancel pending retry
	err := mgr.Stop("up-1")
	if err != nil {
		t.Fatalf("Stop() unexpected error: %v", err)
	}

	status, _ := mgr.Status("up-1")
	if status != upstream.StatusDisconnected {
		t.Errorf("Status() after Stop() with pending retry = %q, want %q", status, upstream.StatusDisconnected)
	}
}

// --- Restart Tests ---

func TestUpstreamManager_Restart_ReconnectsSuccessfully(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	store := newMgrMockUpstreamStore()
	_ = store.Add(context.Background(), u)

	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger)

	clientCount := atomic.Int32{}
	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		clientCount.Add(1)
		return newMgrMockMCPClient(), nil
	}

	mgr := NewUpstreamManager(svc, factory, logger)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	if err := mgr.Start(ctx, "up-1"); err != nil {
		t.Fatalf("Start(): %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if err := mgr.Restart(ctx, "up-1"); err != nil {
		t.Fatalf("Restart() unexpected error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	status, _ := mgr.Status("up-1")
	if status != upstream.StatusConnected {
		t.Errorf("Status() after Restart() = %q, want %q", status, upstream.StatusConnected)
	}

	// Should have created at least 2 clients (original + restart)
	if clientCount.Load() < 2 {
		t.Errorf("client creation count = %d, want >= 2", clientCount.Load())
	}
}

// --- GetConnection Tests ---

func TestUpstreamManager_GetConnection_Connected(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	mgr, _ := testManagerEnv(t, u)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	if err := mgr.Start(ctx, "up-1"); err != nil {
		t.Fatalf("Start(): %v", err)
	}

	stdin, stdout, err := mgr.GetConnection("up-1")
	if err != nil {
		t.Fatalf("GetConnection() unexpected error: %v", err)
	}
	if stdin == nil {
		t.Error("GetConnection() stdin is nil")
	}
	if stdout == nil {
		t.Error("GetConnection() stdout is nil")
	}
}

func TestUpstreamManager_GetConnection_NotConnected(t *testing.T) {
	mgr, _ := testManagerEnv(t)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	_, _, err := mgr.GetConnection("nonexistent")
	if err == nil {
		t.Fatal("GetConnection() not connected should return error")
	}
}

// --- Status Tests ---

func TestUpstreamManager_Status_NotManaged(t *testing.T) {
	mgr, _ := testManagerEnv(t)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	status, _ := mgr.Status("nonexistent")
	if status != upstream.StatusDisconnected {
		t.Errorf("Status() unmanaged = %q, want %q", status, upstream.StatusDisconnected)
	}
}

// --- AllConnected Tests ---

func TestUpstreamManager_AllConnected_SomeConnected(t *testing.T) {
	u1 := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	mgr, _ := testManagerEnv(t, u1)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	if err := mgr.Start(ctx, "up-1"); err != nil {
		t.Fatalf("Start(): %v", err)
	}

	if !mgr.AllConnected() {
		t.Error("AllConnected() = false, want true (at least one connected)")
	}
}

func TestUpstreamManager_AllConnected_NoneConnected(t *testing.T) {
	mgr, _ := testManagerEnv(t)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	if mgr.AllConnected() {
		t.Error("AllConnected() = true, want false (no connections)")
	}
}

// --- StatusAll Tests ---

func TestUpstreamManager_StatusAll(t *testing.T) {
	u1 := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}
	u2 := &upstream.Upstream{
		ID:      "up-2",
		Name:    "server-2",
		Type:    upstream.UpstreamTypeHTTP,
		Enabled: true,
		URL:     "http://localhost:8080/mcp",
	}

	mgr, _ := testManagerEnv(t, u1, u2)
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()

	if err := mgr.Start(ctx, "up-1"); err != nil {
		t.Fatalf("Start(): %v", err)
	}

	statuses := mgr.StatusAll()
	if len(statuses) < 1 {
		t.Fatalf("StatusAll() returned %d entries, want >= 1", len(statuses))
	}
	if statuses["up-1"] != upstream.StatusConnected {
		t.Errorf("StatusAll()[up-1] = %q, want %q", statuses["up-1"], upstream.StatusConnected)
	}

	// up-2 was not started, so it should not appear in StatusAll
	_ = ctx
}

// --- Backoff Tests ---

func TestUpstreamManager_BackoffExponential(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	store := newMgrMockUpstreamStore()
	_ = store.Add(context.Background(), u)

	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger)

	attemptCount := atomic.Int32{}

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		mc := newMgrMockMCPClient()
		mc.startErr = errors.New("connection refused")
		attemptCount.Add(1)
		return mc, nil
	}

	mgr := NewUpstreamManager(svc, factory, logger)
	mgr.backoffBase = 5 * time.Millisecond
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()
	_ = mgr.Start(ctx, "up-1")

	// Wait for several retry attempts
	time.Sleep(500 * time.Millisecond)

	attempts := attemptCount.Load()
	// With 5ms base and exponential backoff (5ms, 10ms, 20ms, 40ms, 80ms, 160ms, ...),
	// within 500ms we should get multiple attempts but not exceed max retries
	if attempts < 3 {
		t.Errorf("expected at least 3 retry attempts, got %d", attempts)
	}
}

func TestUpstreamManager_BackoffMaxRetries(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	store := newMgrMockUpstreamStore()
	_ = store.Add(context.Background(), u)

	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger)

	attemptCount := atomic.Int32{}

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		mc := newMgrMockMCPClient()
		mc.startErr = errors.New("connection refused")
		attemptCount.Add(1)
		return mc, nil
	}

	mgr := NewUpstreamManager(svc, factory, logger)
	mgr.backoffBase = 1 * time.Millisecond
	mgr.backoffCap = 2 * time.Millisecond
	mgr.maxRetries = 10
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()
	_ = mgr.Start(ctx, "up-1")

	// Wait long enough for all retries to exhaust
	time.Sleep(200 * time.Millisecond)

	attempts := attemptCount.Load()
	// Should stop at max retries (10) + 1 initial attempt = 11 total
	if attempts > 12 {
		t.Errorf("expected max ~11 attempts (1 initial + 10 retries), got %d", attempts)
	}

	// Status should be Error after max retries
	status, lastErr := mgr.Status("up-1")
	if status != upstream.StatusError {
		t.Errorf("Status() after max retries = %q, want %q", status, upstream.StatusError)
	}
	if lastErr == "" {
		t.Error("Status() lastErr should not be empty after max retries")
	}
}

func TestUpstreamManager_BackoffCapAt60s(t *testing.T) {
	// Test that the backoff delay is capped at 60s (using the formula)
	// delay = min(base * 2^retryCount, cap)
	// With base=1s: retry 0=1s, 1=2s, 2=4s, 3=8s, 4=16s, 5=32s, 6=64s->60s cap
	mgr := &UpstreamManager{
		backoffBase: 1 * time.Second,
		backoffCap:  60 * time.Second,
	}

	delay := mgr.calcBackoffDelay(0)
	if delay != 1*time.Second {
		t.Errorf("backoff delay at retry 0 = %v, want 1s", delay)
	}

	delay = mgr.calcBackoffDelay(1)
	if delay != 2*time.Second {
		t.Errorf("backoff delay at retry 1 = %v, want 2s", delay)
	}

	delay = mgr.calcBackoffDelay(5)
	if delay != 32*time.Second {
		t.Errorf("backoff delay at retry 5 = %v, want 32s", delay)
	}

	delay = mgr.calcBackoffDelay(6)
	if delay != 60*time.Second {
		t.Errorf("backoff delay at retry 6 = %v, want 60s (capped)", delay)
	}

	delay = mgr.calcBackoffDelay(10)
	if delay != 60*time.Second {
		t.Errorf("backoff delay at retry 10 = %v, want 60s (capped)", delay)
	}
}

// --- Health Monitor / Process Exit Tests ---

func TestUpstreamManager_ProcessExit_TriggersReconnect(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	store := newMgrMockUpstreamStore()
	_ = store.Add(context.Background(), u)

	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger)

	var clientsMu sync.Mutex
	var clients []*mgrMockMCPClient

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		mc := newMgrMockMCPClient()
		clientsMu.Lock()
		clients = append(clients, mc)
		clientsMu.Unlock()
		return mc, nil
	}

	mgr := NewUpstreamManager(svc, factory, logger)
	mgr.backoffBase = 10 * time.Millisecond
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()
	if err := mgr.Start(ctx, "up-1"); err != nil {
		t.Fatalf("Start(): %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	// Simulate process crash
	clientsMu.Lock()
	if len(clients) < 1 {
		t.Fatal("no clients created")
	}
	clients[0].simulateCrash()
	clientsMu.Unlock()

	// Wait for reconnect
	time.Sleep(200 * time.Millisecond)

	status, _ := mgr.Status("up-1")
	if status != upstream.StatusConnected {
		t.Errorf("Status() after crash and reconnect = %q, want %q", status, upstream.StatusConnected)
	}

	clientsMu.Lock()
	clientCount := len(clients)
	clientsMu.Unlock()
	if clientCount < 2 {
		t.Errorf("expected at least 2 clients (original + reconnect), got %d", clientCount)
	}
}

// --- Stability Reset Tests ---

func TestUpstreamManager_StabilityReset(t *testing.T) {
	u := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}

	store := newMgrMockUpstreamStore()
	_ = store.Add(context.Background(), u)

	logger := testManagerLogger()
	svc := NewUpstreamService(store, nil, logger)

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return newMgrMockMCPClient(), nil
	}

	mgr := NewUpstreamManagerUnstarted(svc, factory, logger)
	mgr.stabilityDuration = 50 * time.Millisecond // short for testing
	mgr.stabilityCheckInterval = 10 * time.Millisecond
	mgr.Init() // Signal goroutines to start with updated config
	defer goleak.VerifyNone(t)
	defer func() { _ = mgr.Close() }()

	ctx := context.Background()
	if err := mgr.Start(ctx, "up-1"); err != nil {
		t.Fatalf("Start(): %v", err)
	}

	// Manually set a retry count to verify it gets reset
	mgr.mu.RLock()
	conn := mgr.connections["up-1"]
	mgr.mu.RUnlock()

	conn.mu.Lock()
	conn.retryCount = 5
	conn.mu.Unlock()

	// Wait for stability check to reset
	time.Sleep(100 * time.Millisecond)

	conn.mu.Lock()
	rc := conn.retryCount
	conn.mu.Unlock()

	if rc != 0 {
		t.Errorf("retryCount after stability reset = %d, want 0", rc)
	}
}

// --- Close Tests ---

func TestUpstreamManager_Close_StopsAllUpstreams(t *testing.T) {
	u1 := &upstream.Upstream{
		ID:      "up-1",
		Name:    "server-1",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/echo",
	}
	u2 := &upstream.Upstream{
		ID:      "up-2",
		Name:    "server-2",
		Type:    upstream.UpstreamTypeHTTP,
		Enabled: true,
		URL:     "http://localhost:8080/mcp",
	}

	mgr, clients := testManagerEnv(t, u1, u2)
	defer goleak.VerifyNone(t)

	ctx := context.Background()

	if err := mgr.StartAll(ctx); err != nil {
		t.Fatalf("StartAll(): %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Close should stop everything
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close() unexpected error: %v", err)
	}

	// All clients should be closed
	for id, mc := range clients {
		if mc != nil && !mc.isClosed() {
			t.Errorf("client for %s should be closed after Close()", id)
		}
	}
}
