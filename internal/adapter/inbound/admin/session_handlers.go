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

// SetSessionCacheInvalidator sets the auth interceptor cache invalidator.
// BUG-6 FIX: Enables Terminate/Revoke/Delete to flush cached sessions immediately.
func (h *AdminAPIHandler) SetSessionCacheInvalidator(inv SessionCacheInvalidator) {
	h.sessionCacheInvalidator = inv
}

// SetSessionService sets the session service for session lifecycle management.
// BUG-6 FIX: Enables Terminate to also delete the session from the session store.
func (h *AdminAPIHandler) SetSessionService(s *session.SessionService) {
	h.sessionService = s
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

// handleTerminateSession removes an active session.
// DELETE /admin/api/v1/sessions/{id}
// BUG-6 FIX: Also invalidates the auth interceptor cache and deletes the
// session from the session store, ensuring the agent cannot continue using
// the cached session without re-authenticating.
func (h *AdminAPIHandler) handleTerminateSession(w http.ResponseWriter, r *http.Request) {
	if h.sessionTracker == nil {
		h.respondError(w, http.StatusInternalServerError, "session tracker not configured")
		return
	}

	sessionID := h.pathParam(r, "id")
	if sessionID == "" {
		h.respondError(w, http.StatusBadRequest, "session ID required")
		return
	}

	if _, exists := h.sessionTracker.GetUsage(sessionID); !exists {
		h.respondError(w, http.StatusNotFound, "session not found")
		return
	}

	// 1. Remove from usage tracker (UI display).
	h.sessionTracker.RemoveSession(sessionID)

	// 2. BUG-6 FIX: Flush from auth interceptor cache so the agent must
	// re-authenticate on the next request (key will be re-validated).
	if h.sessionCacheInvalidator != nil {
		h.sessionCacheInvalidator.InvalidateBySessionID(sessionID)
	}

	// 3. BUG-6 FIX: Delete from session store so even if the cache entry
	// wasn't found (race), Get() will fail on next request.
	if h.sessionService != nil {
		if err := h.sessionService.Delete(r.Context(), sessionID); err != nil {
			h.logger.Debug("session delete from store failed (may already be expired)", "session_id", sessionID, "error", err)
		}
	}

	h.logger.Info("session terminated via admin API", "session_id", sessionID)
	h.respondJSON(w, http.StatusOK, map[string]interface{}{
		"terminated": true,
		"message":    "Session terminated. To permanently block this agent, revoke its API key.",
	})
}
