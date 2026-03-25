package admin

import (
	"net/http"
	"sort"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// agentSummaryResponse is the JSON response for GET /admin/api/v1/agents/{identity_id}/summary.
type agentSummaryResponse struct {
	Identity       agentIdentityInfo   `json:"identity"`
	Session        *agentSessionInfo   `json:"session,omitempty"`
	Stats          agentStatsInfo      `json:"stats"`
	ToolUsage      []agentToolUsage    `json:"tool_usage"`
	Timeline       []agentTimelineItem `json:"timeline"`
	DataIncomplete bool                `json:"data_incomplete,omitempty"`
}

type agentIdentityInfo struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

type agentSessionInfo struct {
	SessionID  string `json:"session_id"`
	StartedAt  string `json:"started_at"`
	LastCallAt string `json:"last_call_at"`
	Status     string `json:"status"` // connected, idle, stale
}

type agentStatsInfo struct {
	TotalCalls     int64   `json:"total_calls"`
	AllowedCalls   int64   `json:"allowed_calls"`
	DeniedCalls    int64   `json:"denied_calls"`
	ErrorCalls     int64   `json:"error_calls"`
	ScanDetections int64   `json:"scan_detections"`
	ScanBlocked    int64   `json:"scan_blocked"`
	DriftScore     float64 `json:"drift_score"`
	AnomalyCount   int     `json:"anomaly_count"`
	DenyRate       float64 `json:"deny_rate"`
	ErrorRate      float64 `json:"error_rate"`
	ViolationCount int64   `json:"violation_count"`
	HealthStatus   string  `json:"health_status"` // healthy, attention, critical
}

type agentToolUsage struct {
	ToolName string  `json:"tool_name"`
	Count    int64   `json:"count"`
	Percent  float64 `json:"percent"`
}

type agentTimelineItem struct {
	Timestamp string `json:"timestamp"`
	ToolName  string `json:"tool_name"`
	Decision  string `json:"decision"`
	RuleID    string `json:"rule_id,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
}

// handleGetAgentSummary returns aggregated data for a single agent.
// GET /admin/api/v1/agents/{identity_id}/summary
func (h *AdminAPIHandler) handleGetAgentSummary(w http.ResponseWriter, r *http.Request) {
	identityID := h.pathParam(r, "identity_id") // L-10
	if identityID == "" {
		h.respondError(w, http.StatusBadRequest, "identity_id is required")
		return
	}

	// Get identity info.
	var idInfo agentIdentityInfo
	var dataIncomplete bool
	if h.identityService != nil {
		identities, err := h.identityService.ListIdentities(r.Context())
		if err != nil {
			h.logger.Error("agent summary: failed to list identities", "identity_id", identityID, "error", err)
			dataIncomplete = true
		}
		for _, id := range identities {
			if id.ID == identityID {
				idInfo = agentIdentityInfo{
					ID:    id.ID,
					Name:  id.Name,
					Roles: id.Roles,
				}
				break
			}
		}
	}
	if idInfo.ID == "" {
		idInfo = agentIdentityInfo{ID: identityID, Name: identityID}
	}

	// Get active session info.
	var sessionInfo *agentSessionInfo
	if h.sessionTracker != nil {
		sessions := h.sessionTracker.ActiveSessions()
		for _, sess := range sessions {
			if sess.IdentityID == identityID {
				status := "connected"
				if !sess.Usage.LastCallAt.IsZero() {
					idleMinutes := time.Since(sess.Usage.LastCallAt).Minutes()
					if idleMinutes > 15 {
						status = "stale"
					} else if idleMinutes > 5 {
						status = "idle"
					}
				}
				lastCall := ""
				if !sess.Usage.LastCallAt.IsZero() {
					lastCall = sess.Usage.LastCallAt.Format(time.RFC3339)
				}
				sessionInfo = &agentSessionInfo{
					SessionID:  sess.SessionID,
					StartedAt:  sess.Usage.StartedAt.Format(time.RFC3339),
					LastCallAt: lastCall,
					Status:     status,
				}
				break
			}
		}
	}

	// Get audit records for this agent (last 24h, up to 500).
	var stats agentStatsInfo
	var toolCounts map[string]int64
	var timelineItems []agentTimelineItem

	if h.auditReader != nil {
		now := time.Now()
		start := now.Add(-24 * time.Hour)
		filter := audit.AuditFilter{
			UserID:    identityID,
			StartTime: start,
			EndTime:   now,
			Limit:     500,
		}
		records, _, err := h.auditReader.Query(r.Context(), filter)
		if err != nil {
			h.logger.Error("agent summary: failed to query audit records", "identity_id", identityID, "error", err)
			dataIncomplete = true
		}

		toolCounts = make(map[string]int64)
		for _, rec := range records {
			stats.TotalCalls++
			switch rec.Decision {
			case "allow":
				stats.AllowedCalls++
			case "deny", "blocked":
				stats.DeniedCalls++
			default:
				stats.ErrorCalls++
			}

			if rec.ScanDetections > 0 {
				stats.ScanDetections += int64(rec.ScanDetections)
				if rec.ScanAction == "block" || rec.ScanAction == "blocked" {
					stats.ScanBlocked++
				}
			}

			if rec.ToolName != "" {
				toolCounts[rec.ToolName]++
			}

			timelineItems = append(timelineItems, agentTimelineItem{
				Timestamp: rec.Timestamp.Format(time.RFC3339),
				ToolName:  rec.ToolName,
				Decision:  rec.Decision,
				RuleID:    rec.RuleID,
				Reason:    rec.Reason,
				Protocol:  rec.Protocol,
			})
		}
	}

	// Build tool usage breakdown sorted by count descending.
	toolUsage := make([]agentToolUsage, 0, len(toolCounts))
	for name, count := range toolCounts {
		pct := 0.0
		if stats.TotalCalls > 0 {
			pct = float64(count) / float64(stats.TotalCalls) * 100
		}
		toolUsage = append(toolUsage, agentToolUsage{
			ToolName: name,
			Count:    count,
			Percent:  pct,
		})
	}
	sort.Slice(toolUsage, func(i, j int) bool {
		return toolUsage[i].Count > toolUsage[j].Count
	})

	// Limit timeline to last 100 items (most recent first — records are already sorted).
	if len(timelineItems) > 100 {
		timelineItems = timelineItems[:100]
	}

	// Drift score (Upgrade 5)
	if h.driftService != nil {
		report, driftErr := h.driftService.DetectDrift(r.Context(), identityID)
		if driftErr == nil && report != nil {
			stats.DriftScore = report.DriftScore
			stats.AnomalyCount = len(report.Anomalies)
		}
	}

	// Health metrics (Upgrade 11)
	if stats.TotalCalls > 0 {
		stats.DenyRate = float64(stats.DeniedCalls) / float64(stats.TotalCalls)
		stats.ErrorRate = float64(stats.ErrorCalls) / float64(stats.TotalCalls)
		stats.ViolationCount = stats.DeniedCalls + stats.ScanBlocked
	}
	if h.healthService != nil {
		hm := &service.HealthMetrics{
			DenyRate:   stats.DenyRate,
			DriftScore: stats.DriftScore,
			ErrorRate:  stats.ErrorRate,
		}
		stats.HealthStatus = h.healthService.ClassifyStatus(hm)
	}
	if stats.HealthStatus == "" {
		stats.HealthStatus = "healthy"
	}

	h.respondJSON(w, http.StatusOK, agentSummaryResponse{
		Identity:       idInfo,
		Session:        sessionInfo,
		Stats:          stats,
		ToolUsage:      toolUsage,
		Timeline:       timelineItems,
		DataIncomplete: dataIncomplete,
	})
}

// handleAcknowledgeAgentAlert acknowledges a health alert for an agent.
// POST /admin/api/v1/agents/{identity_id}/acknowledge
func (h *AdminAPIHandler) handleAcknowledgeAgentAlert(w http.ResponseWriter, r *http.Request) {
	identityID := h.pathParam(r, "identity_id")
	if identityID == "" {
		h.respondError(w, http.StatusBadRequest, "identity_id is required")
		return
	}

	var payload struct {
		AcknowledgedStatus string `json:"acknowledged_status"`
	}
	if !h.readJSONBody(w, r, &payload) {
		return
	}

	if payload.AcknowledgedStatus != "critical" && payload.AcknowledgedStatus != "attention" {
		h.respondError(w, http.StatusBadRequest, "acknowledged_status must be 'critical' or 'attention'")
		return
	}

	if h.healthService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "health service not available")
		return
	}

	h.healthService.AcknowledgeAlert(identityID, payload.AcknowledgedStatus)

	h.respondJSON(w, http.StatusOK, map[string]string{
		"identity_id": identityID,
		"status":      "acknowledged",
	})
}
