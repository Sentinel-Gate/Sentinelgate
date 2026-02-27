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
	upstreamService UpstreamLister
	cache           *upstream.ToolCache
	clientFactory   ClientFactory
	logger          *slog.Logger
	retryInterval   time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
	stopped         bool
	mu              sync.Mutex
	notifier        ToolChangeNotifier
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
		upstreamService: upstreamService,
		cache:           cache,
		clientFactory:   clientFactory,
		logger:          logger,
		retryInterval:   60 * time.Second,
		ctx:             ctx,
		cancel:          cancel,
	}
}

// DiscoverAll discovers tools from all enabled upstreams.
func (s *ToolDiscoveryService) DiscoverAll(ctx context.Context) error {
	// Clear previous conflict records before re-discovery.
	s.cache.ClearConflicts()

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

	return nil
}

// DiscoverFromUpstream discovers tools from a single upstream by ID.
// It creates a temporary MCP client, performs the full MCP handshake
// (initialize → notifications/initialized → tools/list), parses the response,
// checks for conflicts, and stores non-conflicting tools in the cache.
// Returns the number of non-conflicting tools stored.
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
	defer func() { _ = client.Close() }()

	// Start the client.
	stdin, stdout, err := client.Start(ctx)
	if err != nil {
		return 0, fmt.Errorf("start client for %s: %w", upstreamID, err)
	}

	// Start a reader goroutine that reads lines from stdout.
	// This single goroutine handles all responses for the handshake sequence.
	type readResult struct {
		line string
		err  error
	}
	resultCh := make(chan readResult, 2)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			resultCh <- readResult{line: scanner.Text()}
		}
		if err := scanner.Err(); err != nil {
			resultCh <- readResult{err: err}
		}
		close(resultCh)
	}()

	// readResponse reads a single line from the response channel with timeout.
	readResponse := func(step string) (string, error) {
		select {
		case result, ok := <-resultCh:
			if !ok {
				return "", fmt.Errorf("EOF reading %s response from %s", step, upstreamID)
			}
			if result.err != nil {
				return "", fmt.Errorf("read %s from %s: %w", step, upstreamID, result.err)
			}
			return result.line, nil
		case <-ctx.Done():
			return "", fmt.Errorf("timeout reading %s from %s: %w", step, upstreamID, ctx.Err())
		}
	}

	// --- Step 1: MCP initialize handshake ---
	initID := fmt.Sprintf("init-%s", upstreamID)
	initReq := fmt.Sprintf(
		`{"jsonrpc":"2.0","id":%q,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"sentinel-gate","version":"1.1.0"}}}`,
		initID,
	)
	if _, err := fmt.Fprintln(stdin, initReq); err != nil {
		return 0, fmt.Errorf("write initialize to %s: %w", upstreamID, err)
	}

	initLine, err := readResponse("initialize")
	if err != nil {
		return 0, err
	}

	// Validate initialize response (check for errors).
	var initResp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(initLine), &initResp); err != nil {
		return 0, fmt.Errorf("parse initialize response from %s: %w", upstreamID, err)
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

	if resp.Error != nil {
		return 0, fmt.Errorf("tools/list error from %s: %s (code %d)",
			upstreamID, resp.Error.Message, resp.Error.Code)
	}

	// Build DiscoveredTool entries, checking for conflicts.
	now := time.Now()
	var nonConflicting []*upstream.DiscoveredTool
	var conflictCount int

	for _, t := range resp.Result.Tools {
		// Check for conflict with existing tools from other upstreams.
		if conflict, existingID := s.cache.HasConflict(t.Name, upstreamID); conflict {
			// Look up the winner upstream name from cache.
			winnerName := existingID
			if winner, ok := s.cache.GetTool(t.Name); ok {
				winnerName = winner.UpstreamName
			}
			s.cache.RecordConflict(upstream.ToolConflict{
				ToolName:            t.Name,
				SkippedUpstreamID:   upstreamID,
				SkippedUpstreamName: u.Name,
				WinnerUpstreamID:    existingID,
				WinnerUpstreamName:  winnerName,
			})
			s.logger.Warn("tool name conflict, skipping",
				"tool", t.Name,
				"upstream", upstreamID,
				"upstream_name", u.Name,
				"existing_upstream", existingID)
			conflictCount++
			continue
		}

		nonConflicting = append(nonConflicting, &upstream.DiscoveredTool{
			Name:         t.Name,
			Description:  t.Description,
			InputSchema:  t.InputSchema,
			UpstreamID:   upstreamID,
			UpstreamName: u.Name,
			DiscoveredAt: now,
		})
	}

	// Store non-conflicting tools in cache.
	s.cache.SetToolsForUpstream(upstreamID, nonConflicting)

	count := len(nonConflicting)
	s.logger.Info("discovered tools",
		"upstream_id", upstreamID,
		"upstream_name", u.Name,
		"tools", count,
		"conflicts", conflictCount)

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
	go func() {
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

// Stop cancels the discovery service context and stops periodic retry.
// Safe to call multiple times.
func (s *ToolDiscoveryService) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return
	}
	s.stopped = true

	if s.cancel != nil {
		s.cancel()
	}
}

// SetNotifier sets the tool change notifier for broadcasting list_changed notifications.
func (s *ToolDiscoveryService) SetNotifier(n ToolChangeNotifier) {
	s.notifier = n
}

// notifyToolsChanged sends a tools/list_changed notification if a notifier is set.
func (s *ToolDiscoveryService) notifyToolsChanged() {
	if s.notifier != nil {
		s.notifier.NotifyToolsChanged()
	}
}

// Cache returns the shared tool cache.
func (s *ToolDiscoveryService) Cache() *upstream.ToolCache {
	return s.cache
}
