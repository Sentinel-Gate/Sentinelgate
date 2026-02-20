package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

func TestHandleSystemInfo_Fields(t *testing.T) {
	startTime := time.Now().UTC().Add(-5 * time.Second)
	h := NewAdminAPIHandler(
		WithStartTime(startTime),
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/system", nil)
	rec := httptest.NewRecorder()

	h.handleSystemInfo(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp SystemInfoResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Default version when no BuildInfo is set.
	if resp.Version != "dev" {
		t.Errorf("Version = %q, want 'dev'", resp.Version)
	}
	if resp.Commit != "none" {
		t.Errorf("Commit = %q, want 'none'", resp.Commit)
	}
	if resp.BuildDate != "unknown" {
		t.Errorf("BuildDate = %q, want 'unknown'", resp.BuildDate)
	}

	if resp.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %q, want %q", resp.GoVersion, runtime.Version())
	}
	if resp.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", resp.OS, runtime.GOOS)
	}
	if resp.Arch != runtime.GOARCH {
		t.Errorf("Arch = %q, want %q", resp.Arch, runtime.GOARCH)
	}

	// Uptime should be at least 4 seconds (we set start 5s ago).
	if resp.UptimeSec < 4 {
		t.Errorf("UptimeSec = %d, want >= 4", resp.UptimeSec)
	}
	if resp.Uptime == "" {
		t.Error("Uptime string should not be empty")
	}
}

func TestHandleSystemInfo_WithBuildInfo(t *testing.T) {
	h := NewAdminAPIHandler(
		WithBuildInfo(&BuildInfo{
			Version:   "1.2.3",
			Commit:    "abc123",
			BuildDate: "2026-01-15",
		}),
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/system", nil)
	rec := httptest.NewRecorder()

	h.handleSystemInfo(rec, req)

	var resp SystemInfoResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Version != "1.2.3" {
		t.Errorf("Version = %q, want '1.2.3'", resp.Version)
	}
	if resp.Commit != "abc123" {
		t.Errorf("Commit = %q, want 'abc123'", resp.Commit)
	}
	if resp.BuildDate != "2026-01-15" {
		t.Errorf("BuildDate = %q, want '2026-01-15'", resp.BuildDate)
	}
}

func TestHandleSystemInfo_ContentType(t *testing.T) {
	h := NewAdminAPIHandler()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/system", nil)
	rec := httptest.NewRecorder()
	h.handleSystemInfo(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}
