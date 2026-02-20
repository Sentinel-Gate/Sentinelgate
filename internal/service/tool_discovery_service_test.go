package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
)

// --- ToolCache unit tests ---

func TestToolCache_NewToolCache(t *testing.T) {
	cache := upstream.NewToolCache()
	if cache == nil {
		t.Fatal("NewToolCache returned nil")
	}
	if cache.Count() != 0 {
		t.Errorf("Count() = %d, want 0", cache.Count())
	}
}

func TestToolCache_SetAndGetTool(t *testing.T) {
	cache := upstream.NewToolCache()
	tools := []*upstream.DiscoveredTool{
		{
			Name:         "read_file",
			Description:  "Read a file from disk",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
			UpstreamID:   "upstream-1",
			UpstreamName: "filesystem",
			DiscoveredAt: time.Now(),
		},
		{
			Name:         "write_file",
			Description:  "Write a file to disk",
			InputSchema:  json.RawMessage(`{"type":"object"}`),
			UpstreamID:   "upstream-1",
			UpstreamName: "filesystem",
			DiscoveredAt: time.Now(),
		},
	}

	cache.SetToolsForUpstream("upstream-1", tools)

	// Verify count.
	if cache.Count() != 2 {
		t.Errorf("Count() = %d, want 2", cache.Count())
	}

	// Get by name.
	tool, ok := cache.GetTool("read_file")
	if !ok {
		t.Fatal("GetTool(read_file) returned false")
	}
	if tool.Name != "read_file" {
		t.Errorf("tool.Name = %q, want %q", tool.Name, "read_file")
	}
	if tool.UpstreamID != "upstream-1" {
		t.Errorf("tool.UpstreamID = %q, want %q", tool.UpstreamID, "upstream-1")
	}

	// Get non-existent tool.
	_, ok = cache.GetTool("nonexistent")
	if ok {
		t.Error("GetTool(nonexistent) should return false")
	}
}

func TestToolCache_GetAllTools(t *testing.T) {
	cache := upstream.NewToolCache()

	tools1 := []*upstream.DiscoveredTool{
		{Name: "tool_a", UpstreamID: "upstream-1", UpstreamName: "server1"},
		{Name: "tool_b", UpstreamID: "upstream-1", UpstreamName: "server1"},
	}
	tools2 := []*upstream.DiscoveredTool{
		{Name: "tool_c", UpstreamID: "upstream-2", UpstreamName: "server2"},
	}

	cache.SetToolsForUpstream("upstream-1", tools1)
	cache.SetToolsForUpstream("upstream-2", tools2)

	all := cache.GetAllTools()
	if len(all) != 3 {
		t.Errorf("GetAllTools() returned %d tools, want 3", len(all))
	}

	// Check all names present.
	names := make(map[string]bool)
	for _, tool := range all {
		names[tool.Name] = true
	}
	for _, expected := range []string{"tool_a", "tool_b", "tool_c"} {
		if !names[expected] {
			t.Errorf("GetAllTools() missing tool %q", expected)
		}
	}
}

func TestToolCache_GetToolsByUpstream(t *testing.T) {
	cache := upstream.NewToolCache()

	tools1 := []*upstream.DiscoveredTool{
		{Name: "tool_a", UpstreamID: "upstream-1", UpstreamName: "server1"},
		{Name: "tool_b", UpstreamID: "upstream-1", UpstreamName: "server1"},
	}
	tools2 := []*upstream.DiscoveredTool{
		{Name: "tool_c", UpstreamID: "upstream-2", UpstreamName: "server2"},
	}

	cache.SetToolsForUpstream("upstream-1", tools1)
	cache.SetToolsForUpstream("upstream-2", tools2)

	got := cache.GetToolsByUpstream("upstream-1")
	if len(got) != 2 {
		t.Errorf("GetToolsByUpstream(upstream-1) = %d tools, want 2", len(got))
	}

	got = cache.GetToolsByUpstream("upstream-2")
	if len(got) != 1 {
		t.Errorf("GetToolsByUpstream(upstream-2) = %d tools, want 1", len(got))
	}

	got = cache.GetToolsByUpstream("nonexistent")
	if len(got) != 0 {
		t.Errorf("GetToolsByUpstream(nonexistent) = %d tools, want 0", len(got))
	}
}

func TestToolCache_SetToolsForUpstream_ReplacesOld(t *testing.T) {
	cache := upstream.NewToolCache()

	// Set initial tools.
	initial := []*upstream.DiscoveredTool{
		{Name: "old_tool", UpstreamID: "upstream-1", UpstreamName: "server1"},
	}
	cache.SetToolsForUpstream("upstream-1", initial)

	if cache.Count() != 1 {
		t.Fatalf("Count() = %d after initial set, want 1", cache.Count())
	}

	// Replace with new tools.
	replacement := []*upstream.DiscoveredTool{
		{Name: "new_tool_a", UpstreamID: "upstream-1", UpstreamName: "server1"},
		{Name: "new_tool_b", UpstreamID: "upstream-1", UpstreamName: "server1"},
	}
	cache.SetToolsForUpstream("upstream-1", replacement)

	// Old tool should be gone.
	_, ok := cache.GetTool("old_tool")
	if ok {
		t.Error("old_tool should have been removed after replacement")
	}

	// New tools should be present.
	if cache.Count() != 2 {
		t.Errorf("Count() = %d after replacement, want 2", cache.Count())
	}

	_, ok = cache.GetTool("new_tool_a")
	if !ok {
		t.Error("new_tool_a should be present after replacement")
	}
}

func TestToolCache_RemoveUpstream(t *testing.T) {
	cache := upstream.NewToolCache()

	tools := []*upstream.DiscoveredTool{
		{Name: "tool_a", UpstreamID: "upstream-1", UpstreamName: "server1"},
		{Name: "tool_b", UpstreamID: "upstream-1", UpstreamName: "server1"},
	}
	cache.SetToolsForUpstream("upstream-1", tools)

	if cache.Count() != 2 {
		t.Fatalf("Count() = %d, want 2", cache.Count())
	}

	cache.RemoveUpstream("upstream-1")

	if cache.Count() != 0 {
		t.Errorf("Count() = %d after remove, want 0", cache.Count())
	}

	_, ok := cache.GetTool("tool_a")
	if ok {
		t.Error("tool_a should be gone after RemoveUpstream")
	}

	got := cache.GetToolsByUpstream("upstream-1")
	if len(got) != 0 {
		t.Errorf("GetToolsByUpstream after remove = %d, want 0", len(got))
	}
}

func TestToolCache_HasConflict(t *testing.T) {
	cache := upstream.NewToolCache()

	tools1 := []*upstream.DiscoveredTool{
		{Name: "shared_tool", UpstreamID: "upstream-1", UpstreamName: "server1"},
	}
	cache.SetToolsForUpstream("upstream-1", tools1)

	// Conflict: same name from different upstream.
	conflict, existingID := cache.HasConflict("shared_tool", "upstream-2")
	if !conflict {
		t.Error("HasConflict should return true for same tool from different upstream")
	}
	if existingID != "upstream-1" {
		t.Errorf("existingID = %q, want %q", existingID, "upstream-1")
	}

	// No conflict: same name from same upstream.
	conflict, _ = cache.HasConflict("shared_tool", "upstream-1")
	if conflict {
		t.Error("HasConflict should return false when excludeUpstreamID matches")
	}

	// No conflict: different name.
	conflict, _ = cache.HasConflict("unique_tool", "upstream-2")
	if conflict {
		t.Error("HasConflict should return false for non-existent tool name")
	}
}

func TestToolCache_ConcurrentAccess(t *testing.T) {
	cache := upstream.NewToolCache()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			upstreamID := fmt.Sprintf("upstream-%d", id)
			tools := []*upstream.DiscoveredTool{
				{Name: fmt.Sprintf("tool_%d", id), UpstreamID: upstreamID, UpstreamName: fmt.Sprintf("server-%d", id)},
			}
			cache.SetToolsForUpstream(upstreamID, tools)

			// Read operations.
			cache.GetAllTools()
			cache.GetTool(fmt.Sprintf("tool_%d", id))
			cache.Count()
			cache.HasConflict(fmt.Sprintf("tool_%d", id), "other")
		}(i)
	}
	wg.Wait()

	// After all goroutines, cache should have 10 tools.
	if cache.Count() != 10 {
		t.Errorf("Count() = %d after concurrent writes, want 10", cache.Count())
	}
}

// --- Mock types for ToolDiscoveryService tests ---

// discoveryMockUpstreamLister implements UpstreamLister for testing.
type discoveryMockUpstreamLister struct {
	upstreams []upstream.Upstream
	err       error
}

func (m *discoveryMockUpstreamLister) List(ctx context.Context) ([]upstream.Upstream, error) {
	if m.err != nil {
		return nil, m.err
	}
	result := make([]upstream.Upstream, len(m.upstreams))
	copy(result, m.upstreams)
	return result, nil
}

func (m *discoveryMockUpstreamLister) Get(ctx context.Context, id string) (*upstream.Upstream, error) {
	for i := range m.upstreams {
		if m.upstreams[i].ID == id {
			u := m.upstreams[i]
			return &u, nil
		}
	}
	return nil, upstream.ErrUpstreamNotFound
}

// discoveryMockClient implements outbound.MCPClient for testing tool discovery.
// It responds to tools/list requests on its stdin/stdout pipes.
type discoveryMockClient struct {
	tools       []discoveryMockTool
	startErr    error
	closeErr    error
	delay       time.Duration // simulate slow response
	stdinRead   *io.PipeReader
	stdinWrite  *io.PipeWriter
	stdoutRead  *io.PipeReader
	stdoutWrite *io.PipeWriter
	waitCh      chan struct{}
	closed      bool
	mu          sync.Mutex
}

type discoveryMockTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

func newDiscoveryMockClient(tools []discoveryMockTool) *discoveryMockClient {
	return &discoveryMockClient{
		tools:  tools,
		waitCh: make(chan struct{}),
	}
}

func (m *discoveryMockClient) Start(ctx context.Context) (io.WriteCloser, io.ReadCloser, error) {
	if m.startErr != nil {
		return nil, nil, m.startErr
	}

	// Create pipes: client writes to stdinWrite, mock reads from stdinRead.
	m.stdinRead, m.stdinWrite = io.Pipe()
	// Mock writes to stdoutWrite, client reads from stdoutRead.
	m.stdoutRead, m.stdoutWrite = io.Pipe()

	// Start goroutine to handle incoming requests.
	go m.handleRequests()

	return m.stdinWrite, m.stdoutRead, nil
}

func (m *discoveryMockClient) handleRequests() {
	scanner := bufio.NewScanner(m.stdinRead)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse request to get ID.
		var req struct {
			JSONRPC string `json:"jsonrpc"`
			ID      string `json:"id"`
			Method  string `json:"method"`
		}
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}

		if m.delay > 0 {
			// Use a select to make the delay cancellable via Close().
			select {
			case <-time.After(m.delay):
				// Delay complete.
			case <-m.waitCh:
				// Client closed during delay.
				return
			}
		}

		m.mu.Lock()
		closed := m.closed
		m.mu.Unlock()
		if closed {
			return
		}

		// Build response.
		toolsJSON, _ := json.Marshal(m.tools)
		resp := fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"result":{"tools":%s}}`, req.ID, string(toolsJSON))

		_, _ = m.stdoutWrite.Write([]byte(resp + "\n"))
	}
}

func (m *discoveryMockClient) Wait() error {
	<-m.waitCh
	return nil
}

func (m *discoveryMockClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	close(m.waitCh)

	if m.stdinRead != nil {
		_ = m.stdinRead.Close()
	}
	if m.stdinWrite != nil {
		_ = m.stdinWrite.Close()
	}
	if m.stdoutRead != nil {
		_ = m.stdoutRead.Close()
	}
	if m.stdoutWrite != nil {
		_ = m.stdoutWrite.Close()
	}

	return m.closeErr
}

// --- ToolDiscoveryService tests ---

func TestToolDiscoveryService_NewToolDiscoveryService(t *testing.T) {
	cache := upstream.NewToolCache()
	lister := &discoveryMockUpstreamLister{}
	logger := slog.Default()
	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return newDiscoveryMockClient(nil), nil
	}

	svc := NewToolDiscoveryService(lister, cache, factory, logger)
	if svc == nil {
		t.Fatal("NewToolDiscoveryService returned nil")
	}
	defer svc.Stop()

	if svc.Cache() == nil {
		t.Error("Cache() returned nil")
	}
	if svc.Cache() != cache {
		t.Error("Cache() should return the same cache passed to constructor")
	}
}

func TestToolDiscoveryService_DiscoverFromUpstream(t *testing.T) {
	cache := upstream.NewToolCache()
	lister := &discoveryMockUpstreamLister{
		upstreams: []upstream.Upstream{
			{
				ID:      "upstream-1",
				Name:    "filesystem",
				Type:    upstream.UpstreamTypeStdio,
				Enabled: true,
				Command: "/usr/bin/echo",
				Status:  upstream.StatusConnected,
			},
		},
	}

	mockTools := []discoveryMockTool{
		{Name: "read_file", Description: "Read a file"},
		{Name: "write_file", Description: "Write a file"},
	}

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return newDiscoveryMockClient(mockTools), nil
	}

	logger := slog.Default()
	svc := NewToolDiscoveryService(lister, cache, factory, logger)
	defer svc.Stop()

	count, err := svc.DiscoverFromUpstream(context.Background(), "upstream-1")
	if err != nil {
		t.Fatalf("DiscoverFromUpstream error: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}

	// Verify tools are in cache.
	tool, ok := cache.GetTool("read_file")
	if !ok {
		t.Fatal("read_file not found in cache")
	}
	if tool.UpstreamID != "upstream-1" {
		t.Errorf("tool.UpstreamID = %q, want %q", tool.UpstreamID, "upstream-1")
	}
	if tool.UpstreamName != "filesystem" {
		t.Errorf("tool.UpstreamName = %q, want %q", tool.UpstreamName, "filesystem")
	}
}

func TestToolDiscoveryService_DiscoverAll(t *testing.T) {
	cache := upstream.NewToolCache()
	lister := &discoveryMockUpstreamLister{
		upstreams: []upstream.Upstream{
			{
				ID:      "upstream-1",
				Name:    "filesystem",
				Type:    upstream.UpstreamTypeStdio,
				Enabled: true,
				Command: "/usr/bin/echo",
				Status:  upstream.StatusConnected,
			},
			{
				ID:      "upstream-2",
				Name:    "database",
				Type:    upstream.UpstreamTypeStdio,
				Enabled: true,
				Command: "/usr/bin/echo",
				Status:  upstream.StatusConnected,
			},
			{
				ID:      "upstream-3",
				Name:    "disabled-server",
				Type:    upstream.UpstreamTypeStdio,
				Enabled: false,
				Command: "/usr/bin/echo",
			},
		},
	}

	var clientMu sync.Mutex
	clientNum := 0
	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		clientMu.Lock()
		defer clientMu.Unlock()
		clientNum++
		tools := []discoveryMockTool{
			{Name: fmt.Sprintf("tool_from_%s", u.Name), Description: "A tool"},
		}
		return newDiscoveryMockClient(tools), nil
	}

	logger := slog.Default()
	svc := NewToolDiscoveryService(lister, cache, factory, logger)
	defer svc.Stop()

	err := svc.DiscoverAll(context.Background())
	if err != nil {
		t.Fatalf("DiscoverAll error: %v", err)
	}

	// Should discover from upstream-1 and upstream-2 (enabled + connected).
	// upstream-3 is disabled, should be skipped.
	if cache.Count() < 2 {
		t.Errorf("cache.Count() = %d, want at least 2", cache.Count())
	}

	// Verify tools from enabled upstreams.
	_, ok := cache.GetTool("tool_from_filesystem")
	if !ok {
		t.Error("tool_from_filesystem not found in cache")
	}

	_, ok = cache.GetTool("tool_from_database")
	if !ok {
		t.Error("tool_from_database not found in cache")
	}

	// Disabled upstream should not have tools.
	_, ok = cache.GetTool("tool_from_disabled-server")
	if ok {
		t.Error("tool_from_disabled-server should not be in cache (disabled upstream)")
	}
}

func TestToolDiscoveryService_DiscoverFromUpstream_NotFound(t *testing.T) {
	cache := upstream.NewToolCache()
	lister := &discoveryMockUpstreamLister{upstreams: nil}
	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return newDiscoveryMockClient(nil), nil
	}

	logger := slog.Default()
	svc := NewToolDiscoveryService(lister, cache, factory, logger)
	defer svc.Stop()

	_, err := svc.DiscoverFromUpstream(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent upstream")
	}
}

func TestToolDiscoveryService_DiscoverFromUpstream_EmptyTools(t *testing.T) {
	cache := upstream.NewToolCache()
	lister := &discoveryMockUpstreamLister{
		upstreams: []upstream.Upstream{
			{
				ID:      "upstream-1",
				Name:    "empty-server",
				Type:    upstream.UpstreamTypeStdio,
				Enabled: true,
				Command: "/usr/bin/echo",
				Status:  upstream.StatusConnected,
			},
		},
	}

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return newDiscoveryMockClient(nil), nil // No tools
	}

	logger := slog.Default()
	svc := NewToolDiscoveryService(lister, cache, factory, logger)
	defer svc.Stop()

	count, err := svc.DiscoverFromUpstream(context.Background(), "upstream-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestToolDiscoveryService_DiscoverFromUpstream_ClientFactoryError(t *testing.T) {
	cache := upstream.NewToolCache()
	lister := &discoveryMockUpstreamLister{
		upstreams: []upstream.Upstream{
			{
				ID:      "upstream-1",
				Name:    "server",
				Type:    upstream.UpstreamTypeStdio,
				Enabled: true,
				Command: "/usr/bin/echo",
			},
		},
	}

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return nil, fmt.Errorf("factory error")
	}

	logger := slog.Default()
	svc := NewToolDiscoveryService(lister, cache, factory, logger)
	defer svc.Stop()

	_, err := svc.DiscoverFromUpstream(context.Background(), "upstream-1")
	if err == nil {
		t.Fatal("expected error from client factory")
	}
	if !strings.Contains(err.Error(), "factory error") {
		t.Errorf("error = %q, want to contain %q", err.Error(), "factory error")
	}
}

func TestToolDiscoveryService_RefreshUpstream(t *testing.T) {
	cache := upstream.NewToolCache()
	lister := &discoveryMockUpstreamLister{
		upstreams: []upstream.Upstream{
			{
				ID:      "upstream-1",
				Name:    "server",
				Type:    upstream.UpstreamTypeStdio,
				Enabled: true,
				Command: "/usr/bin/echo",
				Status:  upstream.StatusConnected,
			},
		},
	}

	callCount := 0
	var factoryMu sync.Mutex
	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		factoryMu.Lock()
		callCount++
		n := callCount
		factoryMu.Unlock()
		if n == 1 {
			return newDiscoveryMockClient([]discoveryMockTool{
				{Name: "old_tool", Description: "Old version"},
			}), nil
		}
		return newDiscoveryMockClient([]discoveryMockTool{
			{Name: "new_tool", Description: "New version"},
		}), nil
	}

	logger := slog.Default()
	svc := NewToolDiscoveryService(lister, cache, factory, logger)
	defer svc.Stop()

	// Initial discovery.
	count, err := svc.DiscoverFromUpstream(context.Background(), "upstream-1")
	if err != nil {
		t.Fatalf("initial discover error: %v", err)
	}
	if count != 1 {
		t.Errorf("initial count = %d, want 1", count)
	}

	_, ok := cache.GetTool("old_tool")
	if !ok {
		t.Fatal("old_tool should be in cache after initial discovery")
	}

	// Refresh.
	count, err = svc.RefreshUpstream(context.Background(), "upstream-1")
	if err != nil {
		t.Fatalf("refresh error: %v", err)
	}
	if count != 1 {
		t.Errorf("refresh count = %d, want 1", count)
	}

	// Old tool should be gone, new tool should be present.
	_, ok = cache.GetTool("old_tool")
	if ok {
		t.Error("old_tool should be gone after refresh")
	}
	_, ok = cache.GetTool("new_tool")
	if !ok {
		t.Error("new_tool should be present after refresh")
	}
}

func TestToolDiscoveryService_ConflictDetection(t *testing.T) {
	cache := upstream.NewToolCache()

	// Pre-populate cache with a tool from upstream-1.
	cache.SetToolsForUpstream("upstream-1", []*upstream.DiscoveredTool{
		{Name: "shared_tool", UpstreamID: "upstream-1", UpstreamName: "server1"},
	})

	lister := &discoveryMockUpstreamLister{
		upstreams: []upstream.Upstream{
			{
				ID:      "upstream-2",
				Name:    "server2",
				Type:    upstream.UpstreamTypeStdio,
				Enabled: true,
				Command: "/usr/bin/echo",
				Status:  upstream.StatusConnected,
			},
		},
	}

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return newDiscoveryMockClient([]discoveryMockTool{
			{Name: "shared_tool", Description: "Conflicting tool"},
			{Name: "unique_tool", Description: "Unique tool"},
		}), nil
	}

	logger := slog.Default()
	svc := NewToolDiscoveryService(lister, cache, factory, logger)
	defer svc.Stop()

	count, err := svc.DiscoverFromUpstream(context.Background(), "upstream-2")
	if err != nil {
		t.Fatalf("discover error: %v", err)
	}

	// The conflicting tool should be skipped; only unique_tool stored.
	// Original shared_tool from upstream-1 should remain.
	tool, ok := cache.GetTool("shared_tool")
	if !ok {
		t.Fatal("shared_tool should still be in cache")
	}
	if tool.UpstreamID != "upstream-1" {
		t.Errorf("shared_tool.UpstreamID = %q, want %q (first upstream wins)", tool.UpstreamID, "upstream-1")
	}

	_, ok = cache.GetTool("unique_tool")
	if !ok {
		t.Error("unique_tool should be in cache")
	}

	// count should reflect non-conflicting tools only.
	if count != 1 {
		t.Errorf("count = %d, want 1 (shared_tool skipped due to conflict)", count)
	}
}

func TestToolDiscoveryService_PeriodicRetry(t *testing.T) {
	cache := upstream.NewToolCache()

	lister := &discoveryMockUpstreamLister{
		upstreams: []upstream.Upstream{
			{
				ID:      "upstream-1",
				Name:    "server1",
				Type:    upstream.UpstreamTypeStdio,
				Enabled: true,
				Command: "/usr/bin/echo",
				Status:  upstream.StatusConnected,
			},
		},
	}

	callCount := 0
	var factoryMu sync.Mutex
	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		factoryMu.Lock()
		callCount++
		n := callCount
		factoryMu.Unlock()

		if n == 1 {
			// First call: return empty (will trigger retry).
			return newDiscoveryMockClient(nil), nil
		}
		// Subsequent calls: return a tool.
		return newDiscoveryMockClient([]discoveryMockTool{
			{Name: "retried_tool", Description: "Found on retry"},
		}), nil
	}

	logger := slog.Default()
	svc := NewToolDiscoveryService(lister, cache, factory, logger)
	// Override retry interval to be fast for testing.
	svc.retryInterval = 50 * time.Millisecond
	defer svc.Stop()

	// Initial discovery returns 0 tools.
	count, err := svc.DiscoverFromUpstream(context.Background(), "upstream-1")
	if err != nil {
		t.Fatalf("initial discover error: %v", err)
	}
	if count != 0 {
		t.Errorf("initial count = %d, want 0", count)
	}

	// Start periodic retry.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartPeriodicRetry(ctx)

	// Wait for retry to fire.
	time.Sleep(200 * time.Millisecond)

	// Should now have a tool from the retry.
	_, ok := cache.GetTool("retried_tool")
	if !ok {
		t.Error("retried_tool should be in cache after periodic retry")
	}
}

func TestToolDiscoveryService_Stop(t *testing.T) {
	cache := upstream.NewToolCache()
	lister := &discoveryMockUpstreamLister{}
	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		return newDiscoveryMockClient(nil), nil
	}

	logger := slog.Default()
	svc := NewToolDiscoveryService(lister, cache, factory, logger)

	// Start periodic retry.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartPeriodicRetry(ctx)

	// Stop should not panic or hang.
	svc.Stop()

	// Double stop should be safe.
	svc.Stop()
}

func TestToolDiscoveryService_DiscoverFromUpstream_Timeout(t *testing.T) {
	cache := upstream.NewToolCache()
	lister := &discoveryMockUpstreamLister{
		upstreams: []upstream.Upstream{
			{
				ID:      "upstream-1",
				Name:    "slow-server",
				Type:    upstream.UpstreamTypeStdio,
				Enabled: true,
				Command: "/usr/bin/echo",
				Status:  upstream.StatusConnected,
			},
		},
	}

	factory := func(u *upstream.Upstream) (outbound.MCPClient, error) {
		mc := newDiscoveryMockClient([]discoveryMockTool{{Name: "tool"}})
		mc.delay = 30 * time.Second // Very slow response.
		return mc, nil
	}

	logger := slog.Default()
	svc := NewToolDiscoveryService(lister, cache, factory, logger)
	defer svc.Stop()

	// Use a short context timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := svc.DiscoverFromUpstream(ctx, "upstream-1")
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
