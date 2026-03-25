package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// UpstreamLister provides a list of configured upstreams for discovery.
type UpstreamLister interface {
	List(ctx context.Context) ([]upstream.Upstream, error)
	Get(ctx context.Context, id string) (*upstream.Upstream, error)
}

// ToolDiscoveryService discovers tools from connected upstream MCP servers
// and maintains a shared ToolCache for routing and tools/list aggregation.
type ToolDiscoveryService struct {
	upstreamService        UpstreamLister
	cache                  *upstream.ToolCache
	clientFactory          ClientFactory
	logger                 *slog.Logger
	retryInterval          time.Duration
	fullRediscoveryInterval time.Duration
	ctx                    context.Context
	cancel                 context.CancelFunc
	stopped                bool
	mu                     sync.Mutex
	wg                     sync.WaitGroup
	notifier               ToolChangeNotifier
	toolSecurityService    *ToolSecurityService
}

// NewToolDiscoveryService creates a new ToolDiscoveryService.
func NewToolDiscoveryService(
	upstreamService UpstreamLister,
	cache *upstream.ToolCache,
	clientFactory ClientFactory,
	logger *slog.Logger,
) *ToolDiscoveryService {
	ctx, cancel := context.WithCancel(context.Background())
	return &ToolDiscoveryService{
		upstreamService:        upstreamService,
		cache:                  cache,
		clientFactory:          clientFactory,
		logger:                 logger,
		retryInterval:          60 * time.Second,
		fullRediscoveryInterval: 5 * time.Minute,
		ctx:                    ctx,
		cancel:                 cancel,
	}
}

// DiscoverAll discovers tools from all enabled upstreams.
func (s *ToolDiscoveryService) DiscoverAll(ctx context.Context) error {
	upstreams, err := s.upstreamService.List(ctx)
	if err != nil {
		return fmt.Errorf("list upstreams: %w", err)
	}

	var totalTools int
	var discoveredUpstreams int

	for i := range upstreams {
		u := &upstreams[i]

		// Skip disabled upstreams.
		if !u.Enabled {
			s.logger.Debug("skipping disabled upstream", "id", u.ID, "name", u.Name)
			continue
		}

		count, err := s.DiscoverFromUpstream(ctx, u.ID)
		if err != nil {
			s.logger.Error("discovery failed for upstream",
				"id", u.ID, "name", u.Name, "error", err)
			continue
		}

		totalTools += count
		discoveredUpstreams++
	}

	s.logger.Info("discovery complete",
		"total_tools", totalTools,
		"upstreams_discovered", discoveredUpstreams)

	// Notify connected clients about tool list change.
	s.notifyToolsChanged()

	// Tool integrity check (Upgrade 4): compare against baseline and emit events.
	s.mu.Lock()
	tss := s.toolSecurityService
	s.mu.Unlock()
	if tss != nil {
		tss.CheckIntegrityAndEmit(ctx)
	}

	return nil
}

// DiscoverFromUpstream discovers tools from a single upstream by ID.
// It creates a temporary MCP client, performs the full MCP handshake
// (initialize → notifications/initialized → tools/list), parses the response,
// and stores all tools in the cache. The ToolCache handles namespacing
// automatically when tool names conflict across upstreams.
// Returns the number of tools stored.
func (s *ToolDiscoveryService) DiscoverFromUpstream(ctx context.Context, upstreamID string) (int, error) {
	// Get upstream config.
	u, err := s.upstreamService.Get(ctx, upstreamID)
	if err != nil {
		return 0, fmt.Errorf("get upstream %s: %w", upstreamID, err)
	}

	// Create temporary client for discovery.
	client, err := s.clientFactory(u)
	if err != nil {
		return 0, fmt.Errorf("create client for %s: %w", upstreamID, err)
	}
	// Start the client.
	stdin, stdout, err := client.Start(ctx)
	if err != nil {
		_ = client.Close()
		return 0, fmt.Errorf("start client for %s: %w", upstreamID, err)
	}

	// Start a reader goroutine that reads lines from stdout.
	// This single goroutine handles all responses for the handshake sequence.
	// M-38: Track the goroutine so we can wait for it before returning.
	type readResult struct {
		line string
		err  error
	}
	resultCh := make(chan readResult, 2)
	doneCh := make(chan struct{})
	var readerWg sync.WaitGroup
	readerWg.Add(1)
	go func() {
		defer readerWg.Done()
		defer close(resultCh)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case resultCh <- readResult{line: scanner.Text()}:
			case <-doneCh:
				return
			}
		}
		if err := scanner.Err(); err != nil {
			select {
			case resultCh <- readResult{err: err}:
			case <-doneCh:
			}
		}
	}()
	// M-38: Close client FIRST (closes stdout, unblocks scanner.Scan),
	// then signal doneCh and wait for goroutine to exit.
	// Order matters: readerWg.Wait() must come after client.Close().
	defer func() {
		close(doneCh)
		_ = client.Close()
		readerWg.Wait()
	}()

	// readResponse reads lines from the response channel, skipping any
	// server-to-client notifications (messages without "id" that have "method").
	// This is necessary because MCP servers may send notifications like
	// notifications/tools/list_changed between request and response.
	readResponse := func(step string) (string, error) {
		const maxSkip = 10
		for i := 0; i < maxSkip; i++ {
			select {
			case result, ok := <-resultCh:
				if !ok {
					return "", fmt.Errorf("EOF reading %s response from %s", step, upstreamID)
				}
				if result.err != nil {
					return "", fmt.Errorf("read %s from %s: %w", step, upstreamID, result.err)
				}
				// Skip notifications (no "id", has "method")
				var peek struct {
					ID     json.RawMessage `json:"id"`
					Method string          `json:"method"`
				}
				if json.Unmarshal([]byte(result.line), &peek) == nil && peek.ID == nil && peek.Method != "" {
					continue // skip notification
				}
				return result.line, nil
			case <-ctx.Done():
				return "", fmt.Errorf("timeout reading %s from %s: %w", step, upstreamID, ctx.Err())
			}
		}
		return "", fmt.Errorf("too many notifications while reading %s from %s", step, upstreamID)
	}

	// --- Step 1: MCP initialize handshake ---
	initID := fmt.Sprintf("init-%s", upstreamID)
	initReq := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":%q,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"sentinel-gate","version":"1.1.0"}}}`,
		initID,
	)
	if _, err := fmt.Fprintln(stdin, initReq); err != nil {
		return 0, fmt.Errorf("write initialize to %s: %w", upstreamID, err)
	}

	initLine, err := readResponse("initialize")
	if err != nil {
		return 0, err
	}

	// Validate initialize response (check for errors and ID match).
	var initResp struct {
		ID    string `json:"id"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(initLine), &initResp); err != nil {
		return 0, fmt.Errorf("parse initialize response from %s: %w", upstreamID, err)
	}
	if initResp.ID != initID {
		return 0, fmt.Errorf("initialize response ID mismatch from %s: got %q, want %q", upstreamID, initResp.ID, initID)
	}
	if initResp.Error != nil {
		return 0, fmt.Errorf("initialize error from %s: %s (code %d)",
			upstreamID, initResp.Error.Message, initResp.Error.Code)
	}

	// --- Step 2: Send notifications/initialized (no response expected) ---
	notifReq := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	if _, err := fmt.Fprintln(stdin, notifReq); err != nil {
		return 0, fmt.Errorf("write notifications/initialized to %s: %w", upstreamID, err)
	}

	// --- Step 3: Send tools/list ---
	reqID := fmt.Sprintf("discovery-%s", upstreamID)
	toolsReq := fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":"tools/list"}`, reqID)
	if _, err := fmt.Fprintln(stdin, toolsReq); err != nil {
		return 0, fmt.Errorf("write tools/list to %s: %w", upstreamID, err)
	}

	responseLine, err := readResponse("tools/list")
	if err != nil {
		return 0, err
	}

	// Parse JSON-RPC response.
	var resp struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Result  struct {
			Tools []struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				InputSchema json.RawMessage `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal([]byte(responseLine), &resp); err != nil {
		return 0, fmt.Errorf("parse response from %s: %w", upstreamID, err)
	}

	if resp.ID != reqID {
		return 0, fmt.Errorf("tools/list response ID mismatch from %s: got %q, want %q", upstreamID, resp.ID, reqID)
	}

	if resp.Error != nil {
		return 0, fmt.Errorf("tools/list error from %s: %s (code %d)",
			upstreamID, resp.Error.Message, resp.Error.Code)
	}

	// Build DiscoveredTool entries. With namespacing, all tools are stored
	// regardless of name conflicts — the ToolCache auto-namespaces when
	// multiple upstreams share the same tool name.
	now := time.Now()
	var allTools []*upstream.DiscoveredTool

	for _, t := range resp.Result.Tools {
		allTools = append(allTools, &upstream.DiscoveredTool{
			Name:         t.Name,
			Description:  t.Description,
			InputSchema:  t.InputSchema,
			UpstreamID:   upstreamID,
			UpstreamName: u.Name,
			DiscoveredAt: now,
		})
	}

	s.cache.SetToolsForUpstream(upstreamID, allTools)

	count := len(allTools)
	s.logger.Info("discovered tools",
		"upstream_id", upstreamID,
		"upstream_name", u.Name,
		"tools", count)

	// Notify connected clients about tool list change.
	s.notifyToolsChanged()

	return count, nil
}

// RefreshUpstream re-discovers tools from an upstream, replacing the cached tools.
// This is the same as DiscoverFromUpstream but logs as a refresh operation.
func (s *ToolDiscoveryService) RefreshUpstream(ctx context.Context, upstreamID string) (int, error) {
	s.logger.Info("refreshing tools for upstream", "upstream_id", upstreamID)
	count, err := s.DiscoverFromUpstream(ctx, upstreamID)
	if err != nil {
		return 0, fmt.Errorf("refresh upstream %s: %w", upstreamID, err)
	}
	s.logger.Info("refresh complete", "upstream_id", upstreamID, "tools", count)
	return count, nil
}

// StartPeriodicRetry starts a background goroutine that periodically retries
// discovery for upstreams with 0 cached tools.
func (s *ToolDiscoveryService) StartPeriodicRetry(ctx context.Context) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.retryInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.retryEmptyUpstreams(ctx)
			case <-ctx.Done():
				return
			case <-s.ctx.Done():
				return
			}
		}
	}()
}

// StartPeriodicFullRediscovery starts a background goroutine that periodically
// re-discovers tools from ALL active upstreams (not just empty ones).
// This closes the security gap where a compromised upstream could change tools
// at runtime without detection until the next restart.
func (s *ToolDiscoveryService) StartPeriodicFullRediscovery(ctx context.Context) {
	s.mu.Lock()
	interval := s.fullRediscoveryInterval
	s.mu.Unlock()

	if interval <= 0 {
		return
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.logger.Debug("running periodic full re-discovery")
				if err := s.DiscoverAll(ctx); err != nil {
					s.logger.Error("periodic full re-discovery failed", "error", err)
				}
			case <-ctx.Done():
				return
			case <-s.ctx.Done():
				return
			}
		}
	}()

	s.logger.Info("periodic full re-discovery started", "interval", interval)
}

// SetFullRediscoveryInterval sets the interval for periodic full re-discovery.
func (s *ToolDiscoveryService) SetFullRediscoveryInterval(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fullRediscoveryInterval = d
}

// retryEmptyUpstreams retries discovery for upstreams that have 0 tools cached.
func (s *ToolDiscoveryService) retryEmptyUpstreams(ctx context.Context) {
	upstreams, err := s.upstreamService.List(ctx)
	if err != nil {
		s.logger.Error("failed to list upstreams for retry", "error", err)
		return
	}

	for i := range upstreams {
		u := &upstreams[i]
		if !u.Enabled {
			continue
		}

		// Only retry upstreams with 0 tools.
		tools := s.cache.GetToolsByUpstream(u.ID)
		if len(tools) > 0 {
			continue
		}

		s.logger.Info("retrying discovery for upstream with 0 tools",
			"upstream_id", u.ID, "upstream_name", u.Name)

		count, err := s.DiscoverFromUpstream(ctx, u.ID)
		if err != nil {
			s.logger.Error("retry discovery failed",
				"upstream_id", u.ID, "error", err)
			continue
		}

		if count > 0 {
			s.logger.Info("retry discovered tools",
				"upstream_id", u.ID, "tools", count)
		}
	}
}

// Stop cancels the discovery service context, stops periodic retry, and waits
// for background goroutines to finish. Safe to call multiple times.
func (s *ToolDiscoveryService) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()

	// Wait for background goroutines (e.g., StartPeriodicRetry) to exit.
	s.wg.Wait()
}

// SetRetryInterval sets the retry interval for periodic discovery.
// It acquires the mutex so callers (including tests) do not need direct field access.
func (s *ToolDiscoveryService) SetRetryInterval(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retryInterval = d
}

// SetNotifier sets the tool change notifier for broadcasting list_changed notifications.
func (s *ToolDiscoveryService) SetNotifier(n ToolChangeNotifier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifier = n
}

// SetToolSecurityService sets the tool security service for integrity checks after discovery.
func (s *ToolDiscoveryService) SetToolSecurityService(svc *ToolSecurityService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.toolSecurityService = svc
}

// notifyToolsChanged sends a tools/list_changed notification if a notifier is set.
func (s *ToolDiscoveryService) notifyToolsChanged() {
	s.mu.Lock()
	n := s.notifier
	s.mu.Unlock()

	if n != nil {
		n.NotifyToolsChanged()
	}
}

// Cache returns the shared tool cache.
func (s *ToolDiscoveryService) Cache() *upstream.ToolCache {
	return s.cache
}
