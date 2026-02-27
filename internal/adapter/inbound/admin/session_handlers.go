package admin

import (
	"net/http"
	"sort"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
)

// WithSessionTracker sets the session tracker for active session monitoring.
func WithSessionTracker(t *session.SessionTracker) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.sessionTracker = t }
}

// SetSessionTracker sets the session tracker after construction.
// This is needed when the tracker is created after the AdminAPIHandler (due to
// boot sequence ordering where BOOT-07 builds the interceptor chain after services).
func (h *AdminAPIHandler) SetSessionTracker(t *session.SessionTracker) {
	h.sessionTracker = t
}

// activeSessionResponse is the JSON representation of an active session.
type activeSessionResponse struct {
	SessionID    string `json:"session_id"`
	IdentityID   string `json:"identity_id"`
	IdentityName string `json:"identity_name"`
	TotalCalls   int64  `json:"total_calls"`
	ReadCalls    int64  `json:"read_calls"`
	WriteCalls   int64  `json:"write_calls"`
	DeleteCalls  int64  `json:"delete_calls"`
	WindowCalls  int64  `json:"window_calls"`
	StartedAt    string `json:"started_at"`
	LastCallAt   string `json:"last_call_at,omitempty"`
}

// handleListActiveSessions returns all active sessions with usage data.
// GET /admin/api/v1/sessions/active
func (h *AdminAPIHandler) handleListActiveSessions(w http.ResponseWriter, r *http.Request) {
	if h.sessionTracker == nil {
		h.respondError(w, http.StatusInternalServerError, "session tracker not configured")
		return
	}

	sessions := h.sessionTracker.ActiveSessions()

	// Sort by LastCallAt descending (most recent first).
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].Usage.LastCallAt.After(sessions[j].Usage.LastCallAt)
	})

	result := make([]activeSessionResponse, 0, len(sessions))
	for _, s := range sessions {
		resp := activeSessionResponse{
			SessionID:    s.SessionID,
			IdentityID:   s.IdentityID,
			IdentityName: s.IdentityName,
			TotalCalls:   s.Usage.TotalCalls,
			ReadCalls:    s.Usage.ReadCalls,
			WriteCalls:   s.Usage.WriteCalls,
			DeleteCalls:  s.Usage.DeleteCalls,
			WindowCalls:  s.Usage.WindowCalls,
			StartedAt:    s.Usage.StartedAt.UTC().Format("2006-01-02T15:04:05Z"),
		}
		if !s.Usage.LastCallAt.IsZero() {
			resp.LastCallAt = s.Usage.LastCallAt.UTC().Format("2006-01-02T15:04:05Z")
		}
		result = append(result, resp)
	}

	h.respondJSON(w, http.StatusOK, result)
}
