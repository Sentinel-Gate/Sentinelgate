// Package upstream contains domain types for MCP upstream server configuration.
package upstream

import (
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// DiscoveredTool represents a tool discovered from an upstream MCP server.
type DiscoveredTool struct {
	// Name is the tool's resolved name (may include namespace prefix in copies from GetTool/GetAllTools).
	Name string
	// BareName is the original tool name as registered by the upstream (without namespace prefix).
	// Populated by GetTool/GetAllTools when the Name is set to the resolved name.
	BareName string
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

// ToolConflict records a tool name that is shared across multiple upstreams.
// With namespacing, both tools coexist as upstream_name/tool_name.
type ToolConflict struct {
	// ToolName is the shared bare tool name.
	ToolName string
	// SkippedUpstreamID is kept for backward compat but no longer means "skipped".
	SkippedUpstreamID string
	// SkippedUpstreamName is kept for backward compat.
	SkippedUpstreamName string
	// WinnerUpstreamID is kept for backward compat but no longer means "winner".
	WinnerUpstreamID string
	// WinnerUpstreamName is kept for backward compat.
	WinnerUpstreamName string
}

const (
	// MaxToolsPerUpstream is the maximum number of tools a single upstream can register.
	// Prevents memory DoS from a malicious upstream advertising excessive tool counts.
	MaxToolsPerUpstream = 1000

	// MaxTotalTools is the maximum total tools across all upstreams.
	MaxTotalTools = 10000
)

// ToolCache provides thread-safe storage for discovered tools with automatic namespacing.
//
// When two or more upstreams register tools with the same bare name, the ToolCache
// automatically exposes them with namespace prefixes: "upstream_name/bare_name".
// Tools with unique names across all upstreams are exposed without any prefix.
// This behavior is transparent to callers: GetAllTools() returns resolved names,
// and GetTool() looks up by resolved name.
type ToolCache struct {
	// tools maps bare name → list of tools (one per upstream that has it)
	tools map[string][]*DiscoveredTool
	// byUpstream maps upstream ID → tools from that upstream (with bare names)
	byUpstream map[string][]*DiscoveredTool
	// resolved maps resolved name → tool (derived, rebuilt on mutation)
	// For unique names: "read_file" → tool
	// For conflicting names: "desktop/read_file" → tool, "train/read_file" → tool
	resolved map[string]*DiscoveredTool
	// ambiguous tracks bare names that have tools from multiple upstreams
	ambiguous map[string]bool
	conflicts []ToolConflict
	logger    *slog.Logger
	mu        sync.RWMutex
}

// NewToolCache creates a new empty ToolCache.
func NewToolCache() *ToolCache {
	return &ToolCache{
		tools:      make(map[string][]*DiscoveredTool),
		byUpstream: make(map[string][]*DiscoveredTool),
		resolved:   make(map[string]*DiscoveredTool),
		ambiguous:  make(map[string]bool),
		logger:     slog.Default(),
	}
}

// NewToolCacheWithLogger creates a new empty ToolCache with a custom logger.
func NewToolCacheWithLogger(logger *slog.Logger) *ToolCache {
	return &ToolCache{
		tools:      make(map[string][]*DiscoveredTool),
		byUpstream: make(map[string][]*DiscoveredTool),
		resolved:   make(map[string]*DiscoveredTool),
		ambiguous:  make(map[string]bool),
		logger:     logger,
	}
}

// SetToolsForUpstream replaces all tools for the given upstream.
// It removes old entries, stores the new tools, and rebuilds the resolved map
// which applies automatic namespacing when tool names conflict across upstreams.
// Tools are truncated to MaxToolsPerUpstream per upstream and MaxTotalTools globally.
func (c *ToolCache) SetToolsForUpstream(upstreamID string, tools []*DiscoveredTool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Enforce per-upstream limit.
	if len(tools) > MaxToolsPerUpstream {
		tools = tools[:MaxToolsPerUpstream]
	}

	// Remove old entries for this upstream from the tools list-map.
	if oldTools, ok := c.byUpstream[upstreamID]; ok {
		for _, t := range oldTools {
			c.removeToolEntry(t.Name, upstreamID)
		}
	}

	// Enforce global limit based on remaining capacity.
	remaining := MaxTotalTools - c.countToolEntries()
	if remaining < 0 {
		remaining = 0
	}
	if len(tools) > remaining {
		tools = tools[:remaining]
	}

	// Store a defensive copy in byUpstream index to prevent caller mutation.
	stored := make([]*DiscoveredTool, len(tools))
	copy(stored, tools)
	c.byUpstream[upstreamID] = stored

	// Add each tool to the tools list-map.
	for _, t := range tools {
		c.tools[t.Name] = append(c.tools[t.Name], t)
	}

	// Record conflicts for tools shared across upstreams.
	c.rebuildConflicts()

	// Rebuild the resolved name map.
	c.rebuildResolved()
}

// GetTool looks up a tool by its resolved name.
// Returns a copy with Name set to the resolved name.
// Returns (nil, false) if the name is not found in the resolved map.
func (c *ToolCache) GetTool(name string) (*DiscoveredTool, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	t, ok := c.resolved[name]
	if !ok {
		return nil, false
	}
	cp := *t
	cp.BareName = t.Name // preserve original bare name before overwrite
	cp.Name = name       // expose the resolved name (may include namespace prefix)
	return &cp, true
}

// GetAllTools returns all tools with resolved names.
// When tools have name conflicts, they are returned with namespace prefixes.
// Returns shallow copies to prevent callers from mutating the cache.
func (c *ToolCache) GetAllTools() []*DiscoveredTool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]*DiscoveredTool, 0, len(c.resolved))
	for resolvedName, t := range c.resolved {
		cp := *t
		cp.BareName = t.Name // preserve original bare name
		cp.Name = resolvedName
		result = append(result, &cp)
	}
	return result
}

// GetToolsByUpstream returns all tools for a specific upstream with their original bare names.
// Returns deep copies (like GetTool/GetAllTools) to prevent callers from mutating the cache.
func (c *ToolCache) GetToolsByUpstream(upstreamID string) []*DiscoveredTool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tools := c.byUpstream[upstreamID]
	if tools == nil {
		return nil
	}
	result := make([]*DiscoveredTool, len(tools))
	for i, t := range tools {
		cp := *t
		result[i] = &cp
	}
	return result
}

// RemoveUpstream removes all tools for an upstream from the cache.
func (c *ToolCache) RemoveUpstream(upstreamID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if tools, ok := c.byUpstream[upstreamID]; ok {
		for _, t := range tools {
			c.removeToolEntry(t.Name, upstreamID)
		}
	}
	delete(c.byUpstream, upstreamID)

	c.rebuildConflicts()
	c.rebuildResolved()
}

// IsAmbiguous checks if a bare tool name is shared across multiple upstreams.
// Returns the list of resolved (namespaced) names as suggestions, matching
// the exact keys used in the resolved map. When multiple upstreams share the
// same UpstreamName, those specific upstreams get a _ID suffix to disambiguate
// (e.g. "desktop_a1/read_file"); upstreams with unique names keep the plain format.
func (c *ToolCache) IsAmbiguous(name string) (bool, []string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.ambiguous[name] {
		return false, nil
	}

	// Scan resolved map for all keys whose underlying tool has this bare name.
	// This is authoritative — uses the exact keys stored in resolved, avoiding
	// re-derivation of the nameCount logic from rebuildResolved.
	// O(resolved) but resolved is bounded at MaxTotalTools and this is called
	// only on error paths (tool not found).
	suggestions := make([]string, 0, 4)
	for resolvedKey, t := range c.resolved {
		// t.Name is the original bare name (stored before any overwrite by GetTool/GetAllTools).
		// resolvedKey != name filters out non-ambiguous entries (bare name keys are for unique tools).
		if t.Name == name && resolvedKey != name {
			suggestions = append(suggestions, resolvedKey)
		}
	}
	if len(suggestions) == 0 {
		return false, nil
	}
	return true, suggestions
}

// OriginalName returns the bare tool name (without namespace prefix) for a resolved name.
// If the name has no "/" prefix, it is returned as-is.
func OriginalName(resolvedName string) string {
	if idx := strings.Index(resolvedName, "/"); idx >= 0 {
		return resolvedName[idx+1:]
	}
	return resolvedName
}

// HasConflict checks if a tool name exists from a different upstream.
// Returns (conflict exists, existing upstream ID).
func (c *ToolCache) HasConflict(name string, excludeUpstreamID string) (bool, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tools := c.tools[name]
	for _, t := range tools {
		if t.UpstreamID != excludeUpstreamID {
			return true, t.UpstreamID
		}
	}
	return false, ""
}

// maxConflicts is the upper bound on recorded conflicts to prevent unbounded growth.
const maxConflicts = 100

// addConflictDedup appends a conflict only if a matching entry does not already exist.
// Must be called with c.mu held.
func (c *ToolCache) addConflictDedup(conflict ToolConflict) {
	if len(c.conflicts) >= maxConflicts {
		return
	}
	for _, existing := range c.conflicts {
		if existing.ToolName == conflict.ToolName &&
			existing.SkippedUpstreamID == conflict.SkippedUpstreamID &&
			existing.WinnerUpstreamID == conflict.WinnerUpstreamID {
			return
		}
	}
	c.conflicts = append(c.conflicts, conflict)
}

// RecordConflict records a tool name conflict.
//
// Deprecated: With auto-namespacing, conflicts are rebuilt automatically by
// SetToolsForUpstream. Externally recorded conflicts will be overwritten on next rebuild.
func (c *ToolCache) RecordConflict(conflict ToolConflict) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.addConflictDedup(conflict)
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

// Count returns the total number of resolved tools (including namespaced variants).
func (c *ToolCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.resolved)
}

// rebuildResolved recomputes the resolved name map from the tools list-map.
// Must be called with c.mu held (write lock).
func (c *ToolCache) rebuildResolved() {
	c.resolved = make(map[string]*DiscoveredTool, c.countToolEntries())
	c.ambiguous = make(map[string]bool)

	for bareName, tools := range c.tools {
		if len(tools) == 1 {
			// Unique name across all upstreams — no namespace needed.
			c.resolved[bareName] = tools[0]
		} else if len(tools) > 1 {
			// Multiple upstreams share this name — namespace all of them.
			c.ambiguous[bareName] = true
			// Check if any UpstreamNames collide — if so, ALL tools with that name
			// get the _ID suffix for deterministic and symmetric disambiguation.
			nameCount := make(map[string]int, len(tools))
			for _, t := range tools {
				nameCount[t.UpstreamName]++
			}
			for _, t := range tools {
				nsName := t.UpstreamName + "/" + bareName
				if nameCount[t.UpstreamName] > 1 {
					nsName = t.UpstreamName + "_" + t.UpstreamID + "/" + bareName
				}
				c.resolved[nsName] = t
			}
		}
	}
}

// rebuildConflicts regenerates the conflict list from current tool state.
// Must be called with c.mu held (write lock).
func (c *ToolCache) rebuildConflicts() {
	c.conflicts = nil
	for bareName, tools := range c.tools {
		if len(tools) <= 1 {
			continue
		}
		// Record conflicts between all pairs (first upstream listed as "winner" for compat).
		first := tools[0]
		for i := 1; i < len(tools); i++ {
			c.addConflictDedup(ToolConflict{
				ToolName:            bareName,
				SkippedUpstreamID:   tools[i].UpstreamID,
				SkippedUpstreamName: tools[i].UpstreamName,
				WinnerUpstreamID:    first.UpstreamID,
				WinnerUpstreamName:  first.UpstreamName,
			})
		}
	}
}

// removeToolEntry removes a specific upstream's entry from the tools list for a bare name.
// Must be called with c.mu held (write lock).
func (c *ToolCache) removeToolEntry(bareName, upstreamID string) {
	list := c.tools[bareName]
	filtered := list[:0:0] // zero cap forces fresh allocation, avoids backing array aliasing
	for _, t := range list {
		if t.UpstreamID != upstreamID {
			filtered = append(filtered, t)
		}
	}
	if len(filtered) == 0 {
		delete(c.tools, bareName)
	} else {
		c.tools[bareName] = filtered
	}
}

// countToolEntries returns the total number of individual tool entries across all bare names.
// Must be called with c.mu held.
func (c *ToolCache) countToolEntries() int {
	count := 0
	for _, list := range c.tools {
		count += len(list)
	}
	return count
}
