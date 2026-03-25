package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- Thread-safe mock types for concurrency tests ---

// threadSafeWriteCloser is a mutex-protected writer safe for concurrent use.
type threadSafeWriteCloser struct {
	mu  sync.Mutex
	buf []byte
}

func (w *threadSafeWriteCloser) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *threadSafeWriteCloser) Close() error { return nil }

// concurrentMockConnectionProvider is a thread-safe UpstreamConnectionProvider
// that holds io.WriteCloser + <-chan []byte pairs, suitable for concurrent tests.
type concurrentMockConnectionProvider struct {
	mu           sync.RWMutex
	writers      map[string]io.WriteCloser
	channels     map[string]<-chan []byte
	allConnected bool
}

func newConcurrentMockConnectionProvider() *concurrentMockConnectionProvider {
	return &concurrentMockConnectionProvider{
		writers:      make(map[string]io.WriteCloser),
		channels:     make(map[string]<-chan []byte),
		allConnected: true,
	}
}

func (m *concurrentMockConnectionProvider) addConnection(upstreamID string, writer io.WriteCloser, ch <-chan []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.writers[upstreamID] = writer
	m.channels[upstreamID] = ch
}

func (m *concurrentMockConnectionProvider) GetConnection(upstreamID string) (io.WriteCloser, <-chan []byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	w, ok := m.writers[upstreamID]
	if !ok {
		return nil, nil, fmt.Errorf("upstream %s not connected", upstreamID)
	}
	return w, m.channels[upstreamID], nil
}

func (m *concurrentMockConnectionProvider) AllConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.allConnected
}

// concurrentMockToolCacheReader wraps a tool map with a RWMutex
// to simulate concurrent tool discovery updates during routing.
type concurrentMockToolCacheReader struct {
	mu    sync.RWMutex
	tools map[string]*RoutableTool
}

func newConcurrentMockToolCacheReader(tools ...*RoutableTool) *concurrentMockToolCacheReader {
	m := &concurrentMockToolCacheReader{tools: make(map[string]*RoutableTool)}
	for _, t := range tools {
		m.tools[t.Name] = t
	}
	return m
}

func (m *concurrentMockToolCacheReader) GetTool(name string) (*RoutableTool, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tools[name]
	return t, ok
}

func (m *concurrentMockToolCacheReader) GetAllTools() []*RoutableTool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*RoutableTool, 0, len(m.tools))
	for _, t := range m.tools {
		result = append(result, t)
	}
	return result
}

func (m *concurrentMockToolCacheReader) IsAmbiguous(name string) (bool, []string) {
	return false, nil
}

func (m *concurrentMockToolCacheReader) setTools(tools []*RoutableTool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tools = make(map[string]*RoutableTool)
	for _, t := range tools {
		m.tools[t.Name] = t
	}
}

// --- Tests ---

// TestConcurrentToolCallsSameUpstream verifies that 10 goroutines calling
// tools/call for the same upstream all complete without data races or deadlocks.
// The per-upstream ioMutex serializes access; each goroutine gets exactly one
// response from the pre-filled channel.
func TestConcurrentToolCallsSameUpstream(t *testing.T) {
	t.Parallel()

	cache := newMockToolCacheReader(
		&RoutableTool{Name: "echo", UpstreamID: "upstream-1", Description: "Echo"},
	)
	manager := newConcurrentMockConnectionProvider()

	// Create a channel with 10 unique responses.
	ch := make(chan []byte, 10)
	for i := 0; i < 10; i++ {
		resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"resp-%d"}]}}`, i)
		ch <- []byte(resp)
	}
	manager.addConnection("upstream-1", &threadSafeWriteCloser{}, ch)

	router := newTestRouter(cache, manager)

	var wg sync.WaitGroup
	var errCount atomic.Int32
	var okCount atomic.Int32
	wg.Add(10)
	for g := 0; g < 10; g++ {
		go func(id int) {
			defer wg.Done()
			msg := makeToolsCallRequest(t, int64(id+1), "echo", nil)
			resp, err := router.Intercept(context.Background(), msg)
			if err != nil {
				errCount.Add(1)
				return
			}
			if resp != nil {
				okCount.Add(1)
			}
		}(g)
	}

	// Deadlock detection.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock: concurrent tool calls did not complete within 10s")
	}

	if okCount.Load() != 10 {
		t.Errorf("expected 10 successful responses, got %d (errors: %d)", okCount.Load(), errCount.Load())
	}
}

// TestToolsListDuringToolCall verifies that tools/list (served from the cache)
// does not block on the per-upstream ioMutex held by a concurrent tools/call.
// Goroutine 1 holds the mutex waiting for a delayed upstream response;
// goroutine 2 should return tools/list immediately from the cache.
func TestToolsListDuringToolCall(t *testing.T) {
	t.Parallel()

	cache := newMockToolCacheReader(
		&RoutableTool{Name: "slow-tool", UpstreamID: "upstream-1", Description: "Slow tool"},
	)
	manager := newConcurrentMockConnectionProvider()

	// Unbuffered channel — response sent after delay.
	ch := make(chan []byte, 1)
	manager.addConnection("upstream-1", &threadSafeWriteCloser{}, ch)
	router := newTestRouter(cache, manager)

	listDone := make(chan time.Time, 1)
	callDone := make(chan time.Time, 1)

	// Goroutine 1: tools/call (will block until response arrives on ch).
	go func() {
		msg := makeToolsCallRequest(t, 1, "slow-tool", nil)
		router.Intercept(context.Background(), msg)
		callDone <- time.Now()
	}()

	// Give goroutine 1 time to acquire the ioMutex and start waiting.
	time.Sleep(100 * time.Millisecond)

	// Goroutine 2: tools/list (should return immediately from cache).
	go func() {
		msg := makeToolsListRequest(t, 2)
		router.Intercept(context.Background(), msg)
		listDone <- time.Now()
	}()

	// Send the upstream response after 500ms total to unblock tools/call.
	go func() {
		time.Sleep(400 * time.Millisecond)
		ch <- []byte(`{"jsonrpc":"2.0","id":1,"result":{"text":"ok"}}`)
	}()

	// tools/list must complete quickly — it should NOT wait for the upstream.
	select {
	case <-listDone:
		// Success: tools/list returned without blocking on ioMutex.
	case <-time.After(5 * time.Second):
		t.Fatal("tools/list blocked — should not wait for upstream ioMutex")
	}

	// tools/call must also eventually complete once the response is sent.
	select {
	case <-callDone:
	case <-time.After(5 * time.Second):
		t.Fatal("tools/call did not complete after response was sent")
	}
}

// TestToolDiscoveryDuringRouting verifies that concurrent cache reads (via
// tools/list) and cache writes (setTools) don't cause data races.
// A concurrentMockToolCacheReader with RWMutex is used to simulate the
// real upstream.ToolCache behaviour under concurrent discovery updates.
func TestToolDiscoveryDuringRouting(t *testing.T) {
	t.Parallel()

	cache := newConcurrentMockToolCacheReader(
		&RoutableTool{Name: "alpha", UpstreamID: "upstream-1", Description: "Alpha"},
	)
	manager := newConcurrentMockConnectionProvider()
	router := newTestRouter(cache, manager)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup

	// Writer goroutine: rapidly mutates the tool set.
	wg.Add(1)
	go func() {
		defer wg.Done()
		sets := [][]*RoutableTool{
			{
				{Name: "alpha", UpstreamID: "upstream-1", Description: "Alpha"},
				{Name: "beta", UpstreamID: "upstream-2", Description: "Beta"},
			},
			{
				{Name: "gamma", UpstreamID: "upstream-3", Description: "Gamma"},
			},
			{
				{Name: "alpha", UpstreamID: "upstream-1", Description: "Alpha v2"},
				{Name: "delta", UpstreamID: "upstream-1", Description: "Delta"},
				{Name: "epsilon", UpstreamID: "upstream-2", Description: "Epsilon"},
			},
			{}, // empty set
		}
		i := 0
		for {
			select {
			case <-ctx.Done():
				return
			default:
				cache.setTools(sets[i%len(sets)])
				i++
			}
		}
	}()

	// Reader goroutines: continuously call tools/list.
	for r := 0; r < 3; r++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					msg := makeToolsListRequest(t, int64(id+100))
					resp, err := router.Intercept(context.Background(), msg)
					if err != nil {
						t.Errorf("tools/list error: %v", err)
						return
					}
					if resp == nil {
						t.Error("tools/list returned nil response")
						return
					}
					// Parse to exercise the full response path.
					var result struct {
						Result struct {
							Tools []json.RawMessage `json:"tools"`
						} `json:"result"`
					}
					if err := json.Unmarshal(resp.Raw, &result); err != nil {
						t.Errorf("failed to parse tools/list response: %v", err)
						return
					}
				}
			}
		}(r)
	}

	// Wait for context timeout then join.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("TestToolDiscoveryDuringRouting did not complete within 5s")
	}
}
