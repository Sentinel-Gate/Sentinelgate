package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

type notificationTestEnv struct {
	handler             *AdminAPIHandler
	notificationService *service.NotificationService
	mux                 http.Handler
}

func setupNotificationTestEnv(t *testing.T) *notificationTestEnv {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	notifSvc := service.NewNotificationService(100)
	handler := NewAdminAPIHandler(
		WithNotificationService(notifSvc),
		WithAPILogger(logger),
	)
	return &notificationTestEnv{
		handler:             handler,
		notificationService: notifSvc,
		mux:                 handler.Routes(),
	}
}

func setupNotificationTestEnvNilService(t *testing.T) *notificationTestEnv {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	handler := NewAdminAPIHandler(
		WithAPILogger(logger),
	)
	return &notificationTestEnv{
		handler: handler,
		mux:     handler.Routes(),
	}
}

// notifCSRFToken is a fixed CSRF token used across notification handler tests.
const notifCSRFToken = "test-csrf-token-for-notification-tests"

func (e *notificationTestEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.RemoteAddr = "127.0.0.1:1234" // bypass auth middleware in tests
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Include CSRF token on state-changing requests.
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete {
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: notifCSRFToken})
		req.Header.Set("X-CSRF-Token", notifCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeNotificationJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

// --- List Notifications ---

func TestHandleListNotifications_Empty(t *testing.T) {
	env := setupNotificationTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/notifications", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/notifications status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result []service.Notification
	decodeNotificationJSON(t, rec, &result)
	if len(result) != 0 {
		t.Errorf("response count = %d, want 0", len(result))
	}
}

func TestHandleListNotifications_WithData(t *testing.T) {
	env := setupNotificationTestEnv(t)

	env.notificationService.Add(service.Notification{
		ID:       "n1",
		Type:     "tool.changed",
		Title:    "Tool Changed",
		Message:  "Tool X was modified",
		Severity: "warning",
	})
	env.notificationService.Add(service.Notification{
		ID:       "n2",
		Type:     "tool.new",
		Title:    "New Tool",
		Message:  "Tool Y was discovered",
		Severity: "info",
	})

	rec := env.doRequest(t, "GET", "/admin/api/v1/notifications", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/notifications status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result []service.Notification
	decodeNotificationJSON(t, rec, &result)
	if len(result) != 2 {
		t.Errorf("response count = %d, want 2", len(result))
	}
}

// --- Notification Count ---

func TestHandleNotificationCount_Empty(t *testing.T) {
	env := setupNotificationTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/notifications/count", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/notifications/count status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result map[string]int
	decodeNotificationJSON(t, rec, &result)
	if result["total"] != 0 {
		t.Errorf("total = %d, want 0", result["total"])
	}
	if result["actions"] != 0 {
		t.Errorf("actions = %d, want 0", result["actions"])
	}
}

func TestHandleNotificationCount_WithData(t *testing.T) {
	env := setupNotificationTestEnv(t)

	env.notificationService.Add(service.Notification{
		ID:             "n1",
		Type:           "tool.changed",
		Title:          "Tool Changed",
		Message:        "Tool X was modified",
		Severity:       "warning",
		RequiresAction: true,
		Timestamp:      time.Now(),
	})
	env.notificationService.Add(service.Notification{
		ID:             "n2",
		Type:           "tool.new",
		Title:          "New Tool",
		Message:        "Tool Y was discovered",
		Severity:       "info",
		RequiresAction: false,
		Timestamp:      time.Now(),
	})
	env.notificationService.Add(service.Notification{
		ID:             "n3",
		Type:           "approval.hold",
		Title:          "Approval Required",
		Message:        "Agent wants to use tool Z",
		Severity:       "critical",
		RequiresAction: true,
		Timestamp:      time.Now(),
	})

	rec := env.doRequest(t, "GET", "/admin/api/v1/notifications/count", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/notifications/count status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result map[string]int
	decodeNotificationJSON(t, rec, &result)
	if result["total"] != 3 {
		t.Errorf("total = %d, want 3", result["total"])
	}
	if result["actions"] != 2 {
		t.Errorf("actions = %d, want 2", result["actions"])
	}
}

// --- Dismiss Notification ---

func TestHandleDismissNotification(t *testing.T) {
	env := setupNotificationTestEnv(t)

	env.notificationService.Add(service.Notification{
		ID:       "dismiss-me",
		Type:     "tool.changed",
		Title:    "Tool Changed",
		Message:  "Tool X was modified",
		Severity: "warning",
	})

	rec := env.doRequest(t, "POST", "/admin/api/v1/notifications/dismiss-me/dismiss", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST dismiss status = %d, want %d (body=%s)", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Verify the notification is no longer in active list.
	listRec := env.doRequest(t, "GET", "/admin/api/v1/notifications", nil)
	var result []service.Notification
	decodeNotificationJSON(t, listRec, &result)
	if len(result) != 0 {
		t.Errorf("active notifications after dismiss = %d, want 0", len(result))
	}
}

func TestHandleDismissNotification_NotFound(t *testing.T) {
	env := setupNotificationTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/notifications/nonexistent/dismiss", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST dismiss nonexistent status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// --- Dismiss All Notifications ---

func TestHandleDismissAllNotifications(t *testing.T) {
	env := setupNotificationTestEnv(t)

	env.notificationService.Add(service.Notification{
		ID:       "n1",
		Type:     "tool.changed",
		Title:    "Tool Changed",
		Message:  "Tool X was modified",
		Severity: "warning",
	})
	env.notificationService.Add(service.Notification{
		ID:       "n2",
		Type:     "tool.new",
		Title:    "New Tool",
		Message:  "Tool Y was discovered",
		Severity: "info",
	})

	rec := env.doRequest(t, "POST", "/admin/api/v1/notifications/dismiss-all", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST dismiss-all status = %d, want %d (body=%s)", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	// Verify all notifications are dismissed (active list is empty).
	listRec := env.doRequest(t, "GET", "/admin/api/v1/notifications", nil)
	var result []service.Notification
	decodeNotificationJSON(t, listRec, &result)
	if len(result) != 0 {
		t.Errorf("active notifications after dismiss-all = %d, want 0", len(result))
	}
}

// --- Nil Service ---

func TestHandleListNotifications_NilService(t *testing.T) {
	env := setupNotificationTestEnvNilService(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/notifications", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/notifications nil service status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result []interface{}
	decodeNotificationJSON(t, rec, &result)
	if len(result) != 0 {
		t.Errorf("response count = %d, want 0", len(result))
	}
}

func TestHandleNotificationCount_NilService(t *testing.T) {
	env := setupNotificationTestEnvNilService(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/notifications/count", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/notifications/count nil service status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result map[string]int
	decodeNotificationJSON(t, rec, &result)
	if result["total"] != 0 {
		t.Errorf("total = %d, want 0", result["total"])
	}
	if result["actions"] != 0 {
		t.Errorf("actions = %d, want 0", result["actions"])
	}
}
