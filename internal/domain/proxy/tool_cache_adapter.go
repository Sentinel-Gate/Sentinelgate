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

// GetTool looks up a tool by resolved name and converts to RoutableTool.
func (a *ToolCacheAdapter) GetTool(name string) (*RoutableTool, bool) {
	dt, ok := a.cache.GetTool(name)
	if !ok {
		return nil, false
	}
	return toRoutableTool(dt, name), true
}

// GetAllTools returns all discovered tools as RoutableTools with resolved names.
func (a *ToolCacheAdapter) GetAllTools() []*RoutableTool {
	allTools := a.cache.GetAllTools()
	result := make([]*RoutableTool, len(allTools))
	for i, dt := range allTools {
		result[i] = toRoutableTool(dt, dt.Name)
	}
	return result
}

// IsAmbiguous checks if a bare tool name is shared across multiple upstreams.
func (a *ToolCacheAdapter) IsAmbiguous(name string) (bool, []string) {
	return a.cache.IsAmbiguous(name)
}

// toRoutableTool converts a DiscoveredTool to a RoutableTool.
// resolvedName is the name as it appears in the resolved map (may include namespace prefix).
func toRoutableTool(dt *upstream.DiscoveredTool, resolvedName string) *RoutableTool {
	return &RoutableTool{
		Name:         resolvedName,
		OriginalName: dt.BareName,
		UpstreamID:   dt.UpstreamID,
		UpstreamName: dt.UpstreamName,
		Description:  dt.Description,
		InputSchema:  dt.InputSchema,
	}
}

// Compile-time check that ToolCacheAdapter implements ToolCacheReader.
var _ ToolCacheReader = (*ToolCacheAdapter)(nil)
