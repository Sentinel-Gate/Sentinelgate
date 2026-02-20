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

	return nil
}

// DiscoverFromUpstream discovers tools from a single upstream by ID.
// It creates a temporary MCP client, sends a tools/list request, parses the response,
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

	// Build and send JSON-RPC tools/list request.
	reqID := fmt.Sprintf("discovery-%s", upstreamID)
	request := fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":"tools/list"}`, reqID)

	// Write request with newline delimiter.
	if _, err := fmt.Fprintln(stdin, request); err != nil {
		return 0, fmt.Errorf("write tools/list to %s: %w", upstreamID, err)
	}

	// Read response with context-based timeout.
	type readResult struct {
		line string
		err  error
	}

	resultCh := make(chan readResult, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			resultCh <- readResult{line: scanner.Text()}
		} else {
			if err := scanner.Err(); err != nil {
				resultCh <- readResult{err: err}
			} else {
				resultCh <- readResult{err: fmt.Errorf("EOF reading response from %s", upstreamID)}
			}
		}
	}()

	var responseLine string
	select {
	case result := <-resultCh:
		if result.err != nil {
			return 0, fmt.Errorf("read response from %s: %w", upstreamID, result.err)
		}
		responseLine = result.line
	case <-ctx.Done():
		return 0, fmt.Errorf("timeout reading response from %s: %w", upstreamID, ctx.Err())
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

// Cache returns the shared tool cache.
func (s *ToolDiscoveryService) Cache() *upstream.ToolCache {
	return s.cache
}
