// Package upstream contains domain types for MCP upstream server configuration.
package upstream

import (
	"encoding/json"
	"sync"
	"time"
)

// DiscoveredTool represents a tool discovered from an upstream MCP server.
type DiscoveredTool struct {
	// Name is the tool's unique identifier.
	Name string
	// Description is the human-readable tool description.
	Description string
	// InputSchema is the JSON Schema for the tool's parameters.
	InputSchema json.RawMessage
	// UpstreamID identifies which upstream this tool was discovered from.
	UpstreamID string
	// UpstreamName is the human-readable name of the upstream.
	UpstreamName string
	// DiscoveredAt records when this tool was discovered.
	DiscoveredAt time.Time
}

// ToolConflict records a tool name conflict where a tool was skipped because
// another upstream already registered a tool with the same name.
type ToolConflict struct {
	// ToolName is the conflicting tool name.
	ToolName string
	// SkippedUpstreamID is the ID of the upstream whose tool was skipped.
	SkippedUpstreamID string
	// SkippedUpstreamName is the human-readable name of the skipped upstream.
	SkippedUpstreamName string
	// WinnerUpstreamID is the ID of the upstream that owns the winning tool.
	WinnerUpstreamID string
	// WinnerUpstreamName is the human-readable name of the winning upstream.
	WinnerUpstreamName string
}

const (
	// MaxToolsPerUpstream is the maximum number of tools a single upstream can register.
	// Prevents memory DoS from a malicious upstream advertising excessive tool counts.
	MaxToolsPerUpstream = 1000

	// MaxTotalTools is the maximum total tools across all upstreams.
	MaxTotalTools = 10000
)

// ToolCache provides thread-safe storage for discovered tools.
// It maintains two indexes: by tool name (for routing) and by upstream ID (for refresh/removal).
type ToolCache struct {
	tools      map[string]*DiscoveredTool
	byUpstream map[string][]*DiscoveredTool
	conflicts  []ToolConflict
	mu         sync.RWMutex
}

// NewToolCache creates a new empty ToolCache.
func NewToolCache() *ToolCache {
	return &ToolCache{
		tools:      make(map[string]*DiscoveredTool),
		byUpstream: make(map[string][]*DiscoveredTool),
	}
}

// SetToolsForUpstream replaces all tools for the given upstream.
// It first removes old entries from the tools map for this upstream,
// then adds the new tools to both maps.
// Tools are truncated to MaxToolsPerUpstream per upstream and MaxTotalTools globally.
func (c *ToolCache) SetToolsForUpstream(upstreamID string, tools []*DiscoveredTool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Enforce per-upstream limit.
	if len(tools) > MaxToolsPerUpstream {
		tools = tools[:MaxToolsPerUpstream]
	}

	// Remove old entries from the name index for this upstream.
	if oldTools, ok := c.byUpstream[upstreamID]; ok {
		for _, t := range oldTools {
			delete(c.tools, t.Name)
		}
	}

	// Store new tools in both indexes, respecting global limit.
	c.byUpstream[upstreamID] = tools
	for _, t := range tools {
		if len(c.tools) >= MaxTotalTools {
			break
		}
		c.tools[t.Name] = t
	}
}

// GetTool looks up a tool by name.
func (c *ToolCache) GetTool(name string) (*DiscoveredTool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	t, ok := c.tools[name]
	return t, ok
}

// GetAllTools returns all cached tools.
func (c *ToolCache) GetAllTools() []*DiscoveredTool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*DiscoveredTool, 0, len(c.tools))
	for _, t := range c.tools {
		result = append(result, t)
	}
	return result
}

// GetToolsByUpstream returns all tools for a specific upstream.
func (c *ToolCache) GetToolsByUpstream(upstreamID string) []*DiscoveredTool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tools := c.byUpstream[upstreamID]
	if tools == nil {
		return nil
	}
	// Return a copy to avoid race conditions.
	result := make([]*DiscoveredTool, len(tools))
	copy(result, tools)
	return result
}

// RemoveUpstream removes all tools for an upstream from the cache.
func (c *ToolCache) RemoveUpstream(upstreamID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove from name index.
	if tools, ok := c.byUpstream[upstreamID]; ok {
		for _, t := range tools {
			delete(c.tools, t.Name)
		}
	}

	// Remove from upstream index.
	delete(c.byUpstream, upstreamID)
}

// HasConflict checks if a tool name exists from a different upstream.
// Returns (conflict exists, existing upstream ID).
func (c *ToolCache) HasConflict(name string, excludeUpstreamID string) (bool, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	existing, ok := c.tools[name]
	if !ok {
		return false, ""
	}

	if existing.UpstreamID == excludeUpstreamID {
		return false, ""
	}

	return true, existing.UpstreamID
}

// RecordConflict records a tool name conflict.
func (c *ToolCache) RecordConflict(conflict ToolConflict) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.conflicts = append(c.conflicts, conflict)
}

// GetConflicts returns all recorded tool name conflicts.
func (c *ToolCache) GetConflicts() []ToolConflict {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.conflicts) == 0 {
		return nil
	}
	result := make([]ToolConflict, len(c.conflicts))
	copy(result, c.conflicts)
	return result
}

// ClearConflicts removes all recorded conflicts.
func (c *ToolCache) ClearConflicts() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.conflicts = nil
}

// Count returns the total number of cached tools.
func (c *ToolCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.tools)
}
