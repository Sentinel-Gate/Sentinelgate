// Package proxy contains the core domain logic for the MCP proxy.
package proxy

import (
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// ToolCacheAdapter wraps an upstream.ToolCache to satisfy the ToolCacheReader
// interface. It converts *upstream.DiscoveredTool to *RoutableTool.
type ToolCacheAdapter struct {
	cache *upstream.ToolCache
}

// NewToolCacheAdapter creates a new ToolCacheAdapter wrapping the given ToolCache.
func NewToolCacheAdapter(cache *upstream.ToolCache) *ToolCacheAdapter {
	return &ToolCacheAdapter{cache: cache}
}

// GetTool looks up a tool by name and converts to RoutableTool.
func (a *ToolCacheAdapter) GetTool(name string) (*RoutableTool, bool) {
	dt, ok := a.cache.GetTool(name)
	if !ok {
		return nil, false
	}
	return toRoutableTool(dt), true
}

// GetAllTools returns all discovered tools as RoutableTools.
func (a *ToolCacheAdapter) GetAllTools() []*RoutableTool {
	allTools := a.cache.GetAllTools()
	result := make([]*RoutableTool, len(allTools))
	for i, dt := range allTools {
		result[i] = toRoutableTool(dt)
	}
	return result
}

// toRoutableTool converts a DiscoveredTool to a RoutableTool.
func toRoutableTool(dt *upstream.DiscoveredTool) *RoutableTool {
	return &RoutableTool{
		Name:        dt.Name,
		UpstreamID:  dt.UpstreamID,
		Description: dt.Description,
		InputSchema: dt.InputSchema,
	}
}

// Compile-time check that ToolCacheAdapter implements ToolCacheReader.
var _ ToolCacheReader = (*ToolCacheAdapter)(nil)
