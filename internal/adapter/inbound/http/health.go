package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// HealthResponse is the JSON response from the /health endpoint.
type HealthResponse struct {
	Status  string            `json:"status"`            // "healthy" or "unhealthy"
	Checks  map[string]string `json:"checks"`            // Component check results
	Version string            `json:"version,omitempty"` // Optional version info
}

// HealthChecker verifies component health.
type HealthChecker struct {
	sessionStore *memory.MemorySessionStore
	rateLimiter  *memory.MemoryRateLimiter
	auditService *service.AuditService
	version      string
}

// NewHealthChecker creates a HealthChecker with optional components.
// Pass nil for components that aren't available.
func NewHealthChecker(
	sessionStore *memory.MemorySessionStore,
	rateLimiter *memory.MemoryRateLimiter,
	auditService *service.AuditService,
	version string,
) *HealthChecker {
	return &HealthChecker{
		sessionStore: sessionStore,
		rateLimiter:  rateLimiter,
		auditService: auditService,
		version:      version,
	}
}

// Check performs health checks on all components.
func (h *HealthChecker) Check() HealthResponse {
	checks := make(map[string]string)
	healthy := true

	// Check session store accessibility
	if h.sessionStore != nil {
		// Size() acquires lock - if this hangs, we have a problem
		_ = h.sessionStore.Size()
		checks["session_store"] = "ok"
	} else {
		checks["session_store"] = "not configured"
	}

	// Check rate limiter accessibility
	if h.rateLimiter != nil {
		_ = h.rateLimiter.Size()
		checks["rate_limiter"] = "ok"
	} else {
		checks["rate_limiter"] = "not configured"
	}

	// Check audit service channel depth
	if h.auditService != nil {
		depth := h.auditService.ChannelDepth()
		capacity := h.auditService.ChannelCapacity()
		percentFull := 0
		if capacity > 0 {
			percentFull = depth * 100 / capacity
		}

		if percentFull > 90 {
			// >90% full is unhealthy - system is under backpressure
			checks["audit"] = fmt.Sprintf("degraded: %d/%d (%d%%)", depth, capacity, percentFull)
			healthy = false
		} else {
			checks["audit"] = fmt.Sprintf("ok: %d/%d (%d%%)", depth, capacity, percentFull)
		}

		// Also check dropped records (warning indicator)
		drops := h.auditService.DroppedRecords()
		if drops > 0 {
			checks["audit_drops"] = fmt.Sprintf("%d dropped", drops)
		}
	} else {
		checks["audit"] = "not configured"
	}

	// Add Go runtime info
	checks["goroutines"] = fmt.Sprintf("%d", runtime.NumGoroutine())

	status := "healthy"
	if !healthy {
		status = "unhealthy"
	}

	return HealthResponse{
		Status:  status,
		Checks:  checks,
		Version: h.version,
	}
}

// Handler returns an HTTP handler for the health endpoint.
func (h *HealthChecker) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		health := h.Check()

		w.Header().Set("Content-Type", "application/json")
		if health.Status != "healthy" {
			w.WriteHeader(http.StatusServiceUnavailable) // 503
		} else {
			w.WriteHeader(http.StatusOK) // 200
		}

		_ = json.NewEncoder(w).Encode(health)
	})
}
