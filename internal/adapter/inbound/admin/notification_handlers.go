package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// sseNormalizeAdmin sanitizes SSE data to prevent newline injection in admin SSE streams.
// Replaces CRLF, bare CR, and bare LF with spaces to prevent SSE frame injection.
func sseNormalizeAdmin(data []byte) []byte {
	s := string(data)
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return []byte(s)
}

// WithNotificationService sets the notification service on the AdminAPIHandler.
func WithNotificationService(s *service.NotificationService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.notificationService = s }
}

// handleListNotifications returns active notifications.
// GET /admin/api/v1/notifications
func (h *AdminAPIHandler) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	if h.notificationService == nil {
		h.respondJSON(w, http.StatusOK, []any{})
		return
	}
	notifs := h.notificationService.List(true)
	h.respondJSON(w, http.StatusOK, notifs)
}

// handleNotificationCount returns the count of active and action-required notifications.
// GET /admin/api/v1/notifications/count
func (h *AdminAPIHandler) handleNotificationCount(w http.ResponseWriter, r *http.Request) {
	if h.notificationService == nil {
		h.respondJSON(w, http.StatusOK, map[string]int{"total": 0, "actions": 0})
		return
	}
	h.respondJSON(w, http.StatusOK, map[string]int{
		"total":   h.notificationService.TotalActiveCount(),
		"actions": h.notificationService.PendingActionCount(),
	})
}

// handleDismissNotification marks a single notification as dismissed.
// POST /admin/api/v1/notifications/{id}/dismiss
func (h *AdminAPIHandler) handleDismissNotification(w http.ResponseWriter, r *http.Request) {
	if h.notificationService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "notification service not available")
		return
	}
	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "notification ID required")
		return
	}
	if h.notificationService.Dismiss(id) {
		w.WriteHeader(http.StatusNoContent)
	} else {
		h.respondError(w, http.StatusNotFound, "notification not found")
	}
}

// handleDismissAllNotifications marks all notifications as dismissed.
// POST /admin/api/v1/notifications/dismiss-all
func (h *AdminAPIHandler) handleDismissAllNotifications(w http.ResponseWriter, r *http.Request) {
	if h.notificationService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "notification service not available")
		return
	}
	h.notificationService.DismissAll()
	w.WriteHeader(http.StatusNoContent)
}

// handleNotificationStream sends notifications via Server-Sent Events.
// GET /admin/api/v1/notifications/stream
func (h *AdminAPIHandler) handleNotificationStream(w http.ResponseWriter, r *http.Request) {
	if h.notificationService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "notification service not available")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		h.respondError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Send current active notifications first.
	active := h.notificationService.List(true)
	for _, n := range active {
		data, err := json.Marshal(n)
		if err != nil {
			h.logger.Warn("notification SSE: failed to marshal notification", "error", err)
			continue
		}
		// L-36: Check the error from the first SSE write. If the client is already
		// disconnected, return early before subscribing.
		if _, err := fmt.Fprintf(w, "data: %s\n\n", sseNormalizeAdmin(data)); err != nil {
			h.logger.Warn("notification SSE: initial write failed, client likely disconnected", "error", err)
			return
		}
	}
	flusher.Flush()

	// Subscribe for new notifications.
	ch, unsub := h.notificationService.SubscribeSSE()
	defer unsub()

	ctx := r.Context()
	keepalive := time.NewTimer(30 * time.Second)
	defer keepalive.Stop()
	maxDuration := time.NewTimer(30 * time.Minute)
	defer maxDuration.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-maxDuration.C:
			// Prevent permanently occupied resources from forgotten browser tabs.
			return
		case notif, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(notif)
			if err != nil {
				h.logger.Warn("notification SSE: failed to marshal notification", "error", err)
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", sseNormalizeAdmin(data)); err != nil {
				h.logger.Warn("notification SSE: write failed, client likely disconnected", "error", err)
				return
			}
			flusher.Flush()
			if !keepalive.Stop() {
				select {
				case <-keepalive.C:
				default:
				}
			}
			keepalive.Reset(30 * time.Second)
		case <-keepalive.C:
			// Keep-alive comment.
			if _, err := fmt.Fprintf(w, ": keepalive\n\n"); err != nil {
				h.logger.Warn("notification SSE: keepalive write failed, client likely disconnected", "error", err)
				return
			}
			flusher.Flush()
			keepalive.Reset(30 * time.Second)
		}
	}
}
