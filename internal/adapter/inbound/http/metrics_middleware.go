// Package http provides the HTTP transport adapter for the proxy.
package http

import (
	"net/http"
	"time"
)

// MetricsMiddleware wraps an HTTP handler to record Prometheus metrics.
// It records:
// - request_duration_seconds histogram (by method)
// - requests_total counter (by method and status)
func MetricsMiddleware(metrics *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip metrics for /metrics and /health endpoints
			if r.URL.Path == "/metrics" || r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()

			// Wrap ResponseWriter to capture status code
			wrapped := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			// Record metrics
			duration := time.Since(start).Seconds()
			method := r.Method
			status := statusToLabel(wrapped.status)

			metrics.RequestDuration.WithLabelValues(method).Observe(duration)
			metrics.RequestsTotal.WithLabelValues(method, status).Inc()
		})
	}
}

// statusRecorder wraps http.ResponseWriter to capture status code
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush delegates to the underlying ResponseWriter if it supports http.Flusher.
// This is required for SSE (Server-Sent Events) connections to work through the metrics middleware.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// statusToLabel converts HTTP status code to label value
func statusToLabel(code int) string {
	if code >= 200 && code < 400 {
		return "ok"
	}
	return "error"
}
