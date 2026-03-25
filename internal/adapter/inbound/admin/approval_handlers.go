package admin

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// WithApprovalStore sets the approval store on the AdminAPIHandler.
func WithApprovalStore(store *action.ApprovalStore) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.approvalStore = store }
}

// SetApprovalStore sets the approval store after construction.
// This is needed when the store is created after the AdminAPIHandler
// (due to boot sequence ordering where BOOT-07 builds the interceptor
// chain after the admin handler).
func (h *AdminAPIHandler) SetApprovalStore(store *action.ApprovalStore) {
	h.approvalStore = store
}

// approvalResponse is the JSON response for a single pending approval.
type approvalResponse struct {
	ID           string `json:"id"`
	ToolName     string `json:"tool_name"`
	IdentityName string `json:"identity_name"`
	IdentityID   string `json:"identity_id"`
	SessionID    string `json:"session_id,omitempty"`
	RuleID       string `json:"rule_id,omitempty"`
	RuleName     string `json:"rule_name,omitempty"`
	Condition    string `json:"condition,omitempty"`
	Status       string `json:"status"`
	CreatedAt    string `json:"created_at"`
	TimeoutSecs  int    `json:"timeout_secs"`
	AuditNote    string `json:"audit_note,omitempty"`
}

// handleListApprovals returns all pending approvals as a JSON array.
// GET /admin/api/v1/approvals
func (h *AdminAPIHandler) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	if h.approvalStore == nil {
		h.respondError(w, http.StatusServiceUnavailable, "approval store not configured")
		return
	}

	pending := h.approvalStore.List()
	result := make([]approvalResponse, len(pending))
	for i, p := range pending {
		result[i] = approvalResponse{
			ID:           p.ID,
			ToolName:     p.ToolName,
			IdentityName: p.IdentityName,
			IdentityID:   p.IdentityID,
			SessionID:    p.SessionID,
			RuleID:       p.RuleID,
			RuleName:     p.RuleName,
			Condition:    p.Condition,
			Status:       p.Status,
			CreatedAt:    p.CreatedAt.Format("2006-01-02T15:04:05Z"),
			TimeoutSecs:  int(p.Timeout.Seconds()),
		}
	}

	h.respondJSON(w, http.StatusOK, result)
}

// approveRequest is the JSON request body for approving an approval.
type approveRequest struct {
	Note string `json:"note"`
}

// handleApproveRequest approves a pending approval request.
// POST /admin/api/v1/approvals/{id}/approve
func (h *AdminAPIHandler) handleApproveRequest(w http.ResponseWriter, r *http.Request) {
	if h.approvalStore == nil {
		h.respondError(w, http.StatusServiceUnavailable, "approval store not configured")
		return
	}

	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "approval ID is required")
		return
	}

	var req approveRequest
	if err := h.readJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if err := h.approvalStore.Approve(id, req.Note); err != nil {
		if errors.Is(err, action.ErrAlreadyResolved) {
			h.respondError(w, http.StatusConflict, "approval already resolved")
		} else if errors.Is(err, action.ErrApprovalNotFound) {
			h.respondError(w, http.StatusNotFound, "approval not found")
		} else {
			h.internalError(w, "failed to approve request", err)
		}
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "approved",
		"id":      id,
		"message": "approval granted",
	})
}

// denyRequest is the JSON request body for denying an approval.
type denyRequest struct {
	Reason string `json:"reason"`
	Note   string `json:"note"`
}

// handleDenyRequest denies a pending approval request.
// POST /admin/api/v1/approvals/{id}/deny
func (h *AdminAPIHandler) handleDenyRequest(w http.ResponseWriter, r *http.Request) {
	if h.approvalStore == nil {
		h.respondError(w, http.StatusServiceUnavailable, "approval store not configured")
		return
	}

	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "approval ID is required")
		return
	}

	// Read optional reason and note from body (M-47: check errors, allow empty body)
	var req denyRequest
	if err := h.readJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "denied by admin"
	}

	if err := h.approvalStore.Deny(id, reason, req.Note); err != nil {
		if errors.Is(err, action.ErrAlreadyResolved) {
			h.respondError(w, http.StatusConflict, "approval already resolved")
		} else if errors.Is(err, action.ErrApprovalNotFound) {
			h.respondError(w, http.StatusNotFound, "approval not found")
		} else {
			h.internalError(w, "failed to deny request", err)
		}
		return
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":  "denied",
		"id":      id,
		"message": reason,
	})
}

// --- Decision Context (Delta 2.3) ---

// approvalContextResponse provides rich decision context for an approval request.
type approvalContextResponse struct {
	Request        approvalContextRequest  `json:"request"`
	SessionTrail   []approvalSessionAction `json:"session_trail"`
	AgentHistory   approvalAgentHistory    `json:"agent_history"`
	Assessment     []string                `json:"assessment"`
	DataIncomplete bool                    `json:"data_incomplete,omitempty"`
}

type approvalContextRequest struct {
	ID           string                 `json:"id"`
	ToolName     string                 `json:"tool_name"`
	Arguments    map[string]interface{} `json:"arguments,omitempty"`
	IdentityName string                 `json:"identity_name"`
	IdentityID   string                 `json:"identity_id"`
	RuleID       string                 `json:"rule_id,omitempty"`
	RuleName     string                 `json:"rule_name,omitempty"`
	Condition    string                 `json:"condition,omitempty"`
	CreatedAt    string                 `json:"created_at"`
	TimeoutSecs  int                    `json:"timeout_secs"`
}

type approvalSessionAction struct {
	Timestamp string `json:"timestamp"`
	ToolName  string `json:"tool_name"`
	Decision  string `json:"decision"`
	Status    string `json:"status,omitempty"` // "hold" for current request
}

type approvalAgentHistory struct {
	ToolUseCount    int                  `json:"tool_use_count"`
	LastUsed        string               `json:"last_used,omitempty"`
	SimilarToolUses []approvalSimilarUse `json:"similar_tool_uses,omitempty"`
}

type approvalSimilarUse struct {
	ToolName  string `json:"tool_name"`
	Decision  string `json:"decision"`
	Timestamp string `json:"timestamp"`
}

// handleGetApprovalContext returns rich decision context for a pending approval.
// GET /admin/api/v1/approvals/{id}/context
func (h *AdminAPIHandler) handleGetApprovalContext(w http.ResponseWriter, r *http.Request) {
	if h.approvalStore == nil {
		h.respondError(w, http.StatusServiceUnavailable, "approval store not configured")
		return
	}

	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "approval ID is required")
		return
	}

	p := h.approvalStore.Get(id)
	if p == nil {
		h.respondError(w, http.StatusNotFound, "approval not found")
		return
	}

	ctx := approvalContextRequest{
		ID:           p.ID,
		ToolName:     p.ToolName,
		Arguments:    p.Arguments,
		IdentityName: p.IdentityName,
		IdentityID:   p.IdentityID,
		RuleID:       p.RuleID,
		RuleName:     p.RuleName,
		Condition:    p.Condition,
		CreatedAt:    p.CreatedAt.Format(time.RFC3339),
		TimeoutSecs:  int(p.Timeout.Seconds()),
	}

	// Session trail: recent actions from same session/identity
	var sessionTrail []approvalSessionAction
	var history approvalAgentHistory
	var dataIncomplete bool

	if h.auditReader != nil {
		now := time.Now()
		// Get session actions (last hour from same identity)
		filter := audit.AuditFilter{
			UserID:    p.IdentityID,
			StartTime: now.Add(-1 * time.Hour),
			EndTime:   now,
			Limit:     20,
		}
		records, _, err := h.auditReader.Query(r.Context(), filter)
		if err != nil {
			h.logger.Error("approval context: failed to query session trail", "id", id, "error", err)
			dataIncomplete = true
		}

		for _, rec := range records {
			sessionTrail = append(sessionTrail, approvalSessionAction{
				Timestamp: rec.Timestamp.Format(time.RFC3339),
				ToolName:  rec.ToolName,
				Decision:  rec.Decision,
			})
		}
		// Append the current hold request
		sessionTrail = append(sessionTrail, approvalSessionAction{
			Timestamp: p.CreatedAt.Format(time.RFC3339),
			ToolName:  p.ToolName,
			Decision:  "hold",
			Status:    "hold",
		})

		// Agent history: how many times this agent used this specific tool (last 30 days)
		toolFilter := audit.AuditFilter{
			UserID:    p.IdentityID,
			ToolName:  p.ToolName,
			StartTime: now.Add(-30 * 24 * time.Hour),
			EndTime:   now,
			Limit:     100,
		}
		toolRecords, _, err := h.auditReader.Query(r.Context(), toolFilter)
		if err != nil {
			h.logger.Error("approval context: failed to query tool history", "id", id, "error", err)
			dataIncomplete = true
		}
		history.ToolUseCount = len(toolRecords)
		if len(toolRecords) > 0 {
			history.LastUsed = toolRecords[0].Timestamp.Format(time.RFC3339)
		}

		// Similar tools: find uses of tools with same prefix (e.g., delete_*)
		toolPrefix := extractToolPrefix(p.ToolName)
		if toolPrefix != "" {
			similarFilter := audit.AuditFilter{
				UserID:    p.IdentityID,
				StartTime: now.Add(-30 * 24 * time.Hour),
				EndTime:   now,
				Limit:     100,
			}
			similarRecords, _, err := h.auditReader.Query(r.Context(), similarFilter)
			if err != nil {
				h.logger.Error("approval context: failed to query similar tools", "id", id, "error", err)
				dataIncomplete = true
			}
			for _, rec := range similarRecords {
				if rec.ToolName != p.ToolName && strings.HasPrefix(rec.ToolName, toolPrefix) {
					history.SimilarToolUses = append(history.SimilarToolUses, approvalSimilarUse{
						ToolName:  rec.ToolName,
						Decision:  rec.Decision,
						Timestamp: rec.Timestamp.Format(time.RFC3339),
					})
				}
			}
			// Limit similar uses to 10 most recent
			if len(history.SimilarToolUses) > 10 {
				history.SimilarToolUses = history.SimilarToolUses[:10]
			}
		}
	}

	// Contextual assessment: deterministic rules
	assessment := buildContextualAssessment(p, sessionTrail, history)

	h.respondJSON(w, http.StatusOK, approvalContextResponse{
		Request:        ctx,
		SessionTrail:   sessionTrail,
		AgentHistory:   history,
		Assessment:     assessment,
		DataIncomplete: dataIncomplete,
	})
}

// extractToolPrefix returns the prefix before the last underscore (e.g., "delete" from "delete_database").
func extractToolPrefix(toolName string) string {
	idx := strings.LastIndex(toolName, "_")
	if idx <= 0 {
		return ""
	}
	return toolName[:idx+1] // include trailing underscore for prefix matching
}

// buildContextualAssessment generates deterministic assessment points.
func buildContextualAssessment(p *action.PendingApproval, trail []approvalSessionAction, history approvalAgentHistory) []string {
	var notes []string

	// Check if target looks like non-production
	if p.Arguments != nil {
		for _, v := range p.Arguments {
			if s, ok := v.(string); ok {
				lower := strings.ToLower(s)
				for _, env := range []string{"staging", "test", "dev", "sandbox", "demo"} {
					if strings.Contains(lower, env) {
						notes = append(notes, fmt.Sprintf("Target contains '%s' (non-production)", env))
						break
					}
				}
			}
		}
	}

	// Check session trail for context clues
	readDocs := false
	for _, a := range trail {
		if a.Status == "hold" {
			continue
		}
		if strings.Contains(a.ToolName, "read") || strings.Contains(a.ToolName, "search") {
			readDocs = true
		}
	}
	if readDocs {
		notes = append(notes, "Agent consulted documentation/search before this request")
	}

	// Check if trail actions are coherent (query → read → action pattern)
	if len(trail) >= 3 {
		notes = append(notes, fmt.Sprintf("Session has %d preceding actions", len(trail)-1))
	}

	// Agent history with this tool
	if history.ToolUseCount == 0 {
		notes = append(notes, fmt.Sprintf("Agent has never used %s before", p.ToolName))
	} else {
		notes = append(notes, fmt.Sprintf("Agent has used %s %d times in last 30 days", p.ToolName, history.ToolUseCount))
	}

	// Similar tool usage
	if len(history.SimilarToolUses) > 0 {
		notes = append(notes, fmt.Sprintf("Agent has used %d similar tools in last 30 days", len(history.SimilarToolUses)))
	}

	return notes
}
