package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// toolResponse is the JSON representation of a discovered tool.
type toolResponse struct {
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	InputSchema   json.RawMessage    `json:"input_schema"`
	UpstreamID    string             `json:"upstream_id"`
	UpstreamName  string             `json:"upstream_name"`
	DiscoveredAt  time.Time          `json:"discovered_at"`
	PolicyStatus  string             `json:"policy_status"`
	MatchingRules []matchingRuleInfo `json:"matching_rules,omitempty"`
}

// matchingRuleInfo is the JSON-safe representation of a rule matching a tool.
type matchingRuleInfo struct {
	Name      string `json:"name"`
	Action    string `json:"action"`
	Priority  int    `json:"priority"`
	Condition string `json:"condition"`
	ToolMatch string `json:"tool_match"`
}

// toolListResponse wraps the tool list with conflict metadata.
type toolListResponse struct {
	Tools     []toolResponse `json:"tools"`
	Conflicts []toolConflict `json:"conflicts"`
}

// toolConflict represents a tool name conflict between upstreams.
type toolConflict struct {
	ToolName    string   `json:"tool_name"`
	Upstreams   []string `json:"upstreams"`
	UpstreamIDs []string `json:"upstream_ids"`
}

// refreshResponse is the JSON response for the tool refresh endpoint.
type refreshResponse struct {
	Message    string `json:"message"`
	TotalTools int    `json:"total_tools"`
}

// handleListTools returns all discovered tools with upstream info and policy status.
// GET /admin/api/tools
func (h *AdminAPIHandler) handleListTools(w http.ResponseWriter, r *http.Request) {
	if h.toolCache == nil {
		h.respondJSON(w, http.StatusOK, toolListResponse{
			Tools:     []toolResponse{},
			Conflicts: []toolConflict{},
		})
		return
	}

	tools := h.toolCache.GetAllTools()

	// Build response with policy status for each tool.
	responses := make([]toolResponse, 0, len(tools))
	for _, t := range tools {
		policyStatus, matchingRules := h.evaluateToolPolicy(r.Context(), t.Name)

		resp := toolResponse{
			Name:          t.Name,
			Description:   t.Description,
			InputSchema:   t.InputSchema,
			UpstreamID:    t.UpstreamID,
			UpstreamName:  t.UpstreamName,
			DiscoveredAt:  t.DiscoveredAt,
			PolicyStatus:  policyStatus,
			MatchingRules: matchingRules,
		}
		responses = append(responses, resp)
	}

	// Sort by upstream_name then by name for stable ordering.
	sort.Slice(responses, func(i, j int) bool {
		if responses[i].UpstreamName != responses[j].UpstreamName {
			return responses[i].UpstreamName < responses[j].UpstreamName
		}
		return responses[i].Name < responses[j].Name
	})

	// Build conflict list from cache.
	conflicts := h.buildConflictList()

	h.respondJSON(w, http.StatusOK, toolListResponse{
		Tools:     responses,
		Conflicts: conflicts,
	})
}

// buildConflictList aggregates raw ToolConflict records into grouped conflict entries.
// Multiple conflicts for the same tool name are merged into a single entry listing all upstreams.
func (h *AdminAPIHandler) buildConflictList() []toolConflict {
	rawConflicts := h.toolCache.GetConflicts()
	if len(rawConflicts) == 0 {
		return []toolConflict{}
	}

	// Group by tool name: collect all unique upstream names and IDs involved.
	type conflictInfo struct {
		upstreamNames map[string]bool
		upstreamIDs   map[string]bool
	}
	grouped := make(map[string]*conflictInfo)
	var order []string

	for _, rc := range rawConflicts {
		ci, ok := grouped[rc.ToolName]
		if !ok {
			ci = &conflictInfo{
				upstreamNames: make(map[string]bool),
				upstreamIDs:   make(map[string]bool),
			}
			grouped[rc.ToolName] = ci
			order = append(order, rc.ToolName)
		}
		ci.upstreamNames[rc.WinnerUpstreamName] = true
		ci.upstreamNames[rc.SkippedUpstreamName] = true
		ci.upstreamIDs[rc.WinnerUpstreamID] = true
		ci.upstreamIDs[rc.SkippedUpstreamID] = true
	}

	// Sort tool names for stable output.
	sort.Strings(order)

	result := make([]toolConflict, 0, len(order))
	for _, name := range order {
		ci := grouped[name]
		var names, ids []string
		for n := range ci.upstreamNames {
			names = append(names, n)
		}
		for id := range ci.upstreamIDs {
			ids = append(ids, id)
		}
		sort.Strings(names)
		sort.Strings(ids)
		result = append(result, toolConflict{
			ToolName:    name,
			Upstreams:   names,
			UpstreamIDs: ids,
		})
	}

	return result
}

// handleRefreshTools triggers re-discovery for all upstreams and returns updated tool count.
// POST /admin/api/tools/refresh
func (h *AdminAPIHandler) handleRefreshTools(w http.ResponseWriter, r *http.Request) {
	if h.discoveryService == nil {
		h.respondError(w, http.StatusNotImplemented, "discovery service not available")
		return
	}

	if err := h.discoveryService.DiscoverAll(r.Context()); err != nil {
		h.logger.Error("tool refresh failed", "error", err)
		h.respondError(w, http.StatusInternalServerError, "tool discovery failed")
		return
	}

	totalTools := 0
	if h.toolCache != nil {
		totalTools = h.toolCache.Count()
	}

	h.respondJSON(w, http.StatusOK, refreshResponse{
		Message:    "discovery complete",
		TotalTools: totalTools,
	})
}

// evaluateToolPolicy determines the policy status of a tool by examining
// all rules whose tool_match pattern matches, without evaluating CEL conditions.
// Returns status ("allow", "deny", "conditional", "no_rule", "unknown") and
// matching rules (only when conditional).
func (h *AdminAPIHandler) evaluateToolPolicy(_ context.Context, toolName string) (string, []matchingRuleInfo) {
	if h.policyService == nil {
		return "unknown", nil
	}

	rules := h.policyService.GetMatchingRules(toolName)
	if len(rules) == 0 {
		return "no_rule", nil
	}

	// Check if all rules have the same action
	actions := make(map[policy.Action]bool)
	for _, r := range rules {
		actions[r.Action] = true
	}

	if len(actions) == 1 {
		for a := range actions {
			return string(a), nil
		}
	}

	// Mixed actions → conditional; include rule details for the frontend
	ruleInfos := make([]matchingRuleInfo, 0, len(rules))
	for _, r := range rules {
		ruleInfos = append(ruleInfos, matchingRuleInfo{
			Name:      r.Name,
			Action:    string(r.Action),
			Priority:  r.Priority,
			Condition: r.Condition,
			ToolMatch: r.ToolMatch,
		})
	}

	return "conditional", ruleInfos
}
