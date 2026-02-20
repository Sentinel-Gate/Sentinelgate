package admin

import (
	"context"
	"net/http"
)

// StatsResponse is the JSON response for GET /admin/api/stats.
type StatsResponse struct {
	Upstreams       int              `json:"upstreams"`
	Tools           int              `json:"tools"`
	Policies        int              `json:"policies"`
	Allowed         int64            `json:"allowed"`
	Denied          int64            `json:"denied"`
	RateLimited     int64            `json:"rate_limited"`
	Errors          int64            `json:"errors"`
	ProtocolCounts  map[string]int64 `json:"protocol_counts"`
	FrameworkCounts map[string]int64 `json:"framework_counts"`
}

// handleGetStats returns dashboard statistics including upstream count,
// tool count, policy count, and decision counters.
func (h *AdminAPIHandler) handleGetStats(w http.ResponseWriter, r *http.Request) {
	resp := StatsResponse{}

	if h.upstreamService != nil {
		upstreams, err := h.upstreamService.List(context.Background())
		if err == nil {
			resp.Upstreams = len(upstreams)
		}
	}

	if h.toolCache != nil {
		resp.Tools = h.toolCache.Count()
	}

	if h.policyStore != nil {
		policies, err := h.policyStore.GetAllPolicies(context.Background())
		if err == nil {
			resp.Policies = len(policies)
		}
	}

	if h.statsService != nil {
		stats := h.statsService.GetStats()
		resp.Allowed = stats.Allowed
		resp.Denied = stats.Denied
		resp.RateLimited = stats.RateLimited
		resp.Errors = stats.Errors
		resp.ProtocolCounts = stats.ProtocolCounts
		resp.FrameworkCounts = stats.FrameworkCounts
	}

	// Ensure maps are never null in JSON output.
	if resp.ProtocolCounts == nil {
		resp.ProtocolCounts = make(map[string]int64)
	}
	if resp.FrameworkCounts == nil {
		resp.FrameworkCounts = make(map[string]int64)
	}

	h.respondJSON(w, http.StatusOK, resp)
}
