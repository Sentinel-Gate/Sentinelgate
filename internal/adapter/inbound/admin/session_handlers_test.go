package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
)

func TestHandleListActiveSessions_Empty(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker := session.NewSessionTracker(1*time.Minute, session.DefaultClassifier())

	h := NewAdminAPIHandler(
		WithSessionTracker(tracker),
		WithAPILogger(logger),
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/sessions/active", nil)
	w := httptest.NewRecorder()

	h.handleListActiveSessions(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var items []activeSessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if len(items) != 0 {
		t.Fatalf("session count = %d, want 0", len(items))
	}
}

func TestHandleListActiveSessions_WithData(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	tracker := session.NewSessionTracker(1*time.Minute, session.DefaultClassifier())

	// Record calls for two sessions.
	tracker.RecordCall("session-1", "read_file", "identity-1", "Alice", nil)
	tracker.RecordCall("session-1", "write_file", "identity-1", "Alice", nil)
	tracker.RecordCall("session-2", "list_directory", "identity-2", "Bob", nil)

	h := NewAdminAPIHandler(
		WithSessionTracker(tracker),
		WithAPILogger(logger),
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/sessions/active", nil)
	w := httptest.NewRecorder()

	h.handleListActiveSessions(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var items []activeSessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if len(items) != 2 {
		t.Fatalf("session count = %d, want 2", len(items))
	}

	// Find session-1 and verify its counts.
	var s1 *activeSessionResponse
	for i := range items {
		if items[i].SessionID == "session-1" {
			s1 = &items[i]
			break
		}
	}
	if s1 == nil {
		t.Fatal("session-1 not found in results")
	}

	if s1.IdentityID != "identity-1" {
		t.Errorf("IdentityID = %q, want %q", s1.IdentityID, "identity-1")
	}
	if s1.IdentityName != "Alice" {
		t.Errorf("IdentityName = %q, want %q", s1.IdentityName, "Alice")
	}
	if s1.TotalCalls != 2 {
		t.Errorf("TotalCalls = %d, want 2", s1.TotalCalls)
	}
	if s1.ReadCalls != 1 {
		t.Errorf("ReadCalls = %d, want 1", s1.ReadCalls)
	}
	if s1.WriteCalls != 1 {
		t.Errorf("WriteCalls = %d, want 1", s1.WriteCalls)
	}
	if s1.StartedAt == "" {
		t.Error("StartedAt is empty")
	}
	if s1.LastCallAt == "" {
		t.Error("LastCallAt is empty")
	}
}
