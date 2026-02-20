package http

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// discardLogger returns a logger that discards all output (for tests)
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHealthChecker_Healthy(t *testing.T) {
	// Create real components
	sessionStore := memory.NewSessionStore()
	rateLimiter := memory.NewRateLimiter()

	// Create audit service with small channel
	auditStore := memory.NewAuditStore()
	auditService := service.NewAuditService(auditStore, discardLogger(),
		service.WithChannelSize(100),
	)

	hc := NewHealthChecker(sessionStore, rateLimiter, auditService, "test-version")

	// Check health
	health := hc.Check()

	if health.Status != "healthy" {
		t.Errorf("Status = %q, want healthy", health.Status)
	}
	if health.Version != "test-version" {
		t.Errorf("Version = %q, want test-version", health.Version)
	}
	if health.Checks["session_store"] != "ok" {
		t.Errorf("session_store check = %q, want ok", health.Checks["session_store"])
	}
	if health.Checks["rate_limiter"] != "ok" {
		t.Errorf("rate_limiter check = %q, want ok", health.Checks["rate_limiter"])
	}
}

func TestHealthChecker_NilComponents(t *testing.T) {
	hc := NewHealthChecker(nil, nil, nil, "")
	health := hc.Check()

	// Should still be healthy with nil components
	if health.Status != "healthy" {
		t.Errorf("Status = %q, want healthy", health.Status)
	}
	if health.Checks["session_store"] != "not configured" {
		t.Errorf("session_store = %q, want 'not configured'", health.Checks["session_store"])
	}
	if health.Checks["rate_limiter"] != "not configured" {
		t.Errorf("rate_limiter = %q, want 'not configured'", health.Checks["rate_limiter"])
	}
	if health.Checks["audit"] != "not configured" {
		t.Errorf("audit = %q, want 'not configured'", health.Checks["audit"])
	}
}

func TestHealthChecker_Handler_HTTP(t *testing.T) {
	sessionStore := memory.NewSessionStore()
	hc := NewHealthChecker(sessionStore, nil, nil, "1.0.0")

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	hc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status code = %d, want %d", rec.Code, http.StatusOK)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	var resp HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Status != "healthy" {
		t.Errorf("Response status = %q, want healthy", resp.Status)
	}
	if resp.Version != "1.0.0" {
		t.Errorf("Response version = %q, want 1.0.0", resp.Version)
	}
}

func TestHealthChecker_Unhealthy_AuditFull(t *testing.T) {
	// Create audit service with tiny channel and no timeout (drop immediately)
	auditStore := memory.NewAuditStore()
	auditService := service.NewAuditService(auditStore, discardLogger(),
		service.WithChannelSize(10),
		service.WithSendTimeout(0), // Drop immediately when full
	)

	// Fill the channel > 90% (need 10 records for a size-10 channel)
	// Since there's no worker consuming, records will fill the channel
	for i := 0; i < 10; i++ {
		auditService.Record(audit.AuditRecord{ToolName: "test"})
	}

	hc := NewHealthChecker(nil, nil, auditService, "")
	health := hc.Check()

	if health.Status != "unhealthy" {
		t.Errorf("Status = %q, want unhealthy (audit channel >90%% full)", health.Status)
	}
}

func TestHealthChecker_Handler_Unhealthy_503(t *testing.T) {
	// Create audit service with tiny channel and no timeout (drop immediately)
	auditStore := memory.NewAuditStore()
	auditService := service.NewAuditService(auditStore, discardLogger(),
		service.WithChannelSize(10),
		service.WithSendTimeout(0), // Drop immediately when full
	)

	// Fill the channel completely
	for i := 0; i < 10; i++ {
		auditService.Record(audit.AuditRecord{ToolName: "test"})
	}

	hc := NewHealthChecker(nil, nil, auditService, "")

	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()

	hc.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("Status code = %d, want %d (503 Service Unavailable)", rec.Code, http.StatusServiceUnavailable)
	}

	var resp HealthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Status != "unhealthy" {
		t.Errorf("Response status = %q, want unhealthy", resp.Status)
	}
}

func TestHealthChecker_GoroutineCount(t *testing.T) {
	hc := NewHealthChecker(nil, nil, nil, "")
	health := hc.Check()

	// Goroutines should be a positive number string
	if health.Checks["goroutines"] == "" {
		t.Error("goroutines check should be present")
	}
	if health.Checks["goroutines"] == "0" {
		t.Error("goroutines count should be > 0")
	}
}
