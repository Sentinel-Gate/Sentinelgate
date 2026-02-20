// Package http provides the HTTP transport adapter for the proxy.
package http

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for Sentinelgate.
// Pass to components that need to record metrics.
type Metrics struct {
	RequestsTotal     *prometheus.CounterVec
	RequestDuration   *prometheus.HistogramVec
	ActiveSessions    prometheus.Gauge
	PolicyEvaluations *prometheus.CounterVec
	AuditDropsTotal   prometheus.Counter
	RateLimitKeys     prometheus.Gauge
}

// NewMetrics creates and registers all metrics with the given registry.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	return &Metrics{
		RequestsTotal: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sentinelgate",
				Name:      "requests_total",
				Help:      "Total number of MCP requests processed",
			},
			[]string{"method", "status"}, // method=POST, status=ok/error
		),
		RequestDuration: promauto.With(reg).NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sentinelgate",
				Name:      "request_duration_seconds",
				Help:      "Request duration in seconds",
				Buckets:   prometheus.DefBuckets, // 5ms to 10s
			},
			[]string{"method"},
		),
		ActiveSessions: promauto.With(reg).NewGauge(
			prometheus.GaugeOpts{
				Namespace: "sentinelgate",
				Name:      "active_sessions",
				Help:      "Number of active sessions",
			},
		),
		PolicyEvaluations: promauto.With(reg).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sentinelgate",
				Name:      "policy_evaluations_total",
				Help:      "Total policy evaluations",
			},
			[]string{"result"}, // result=allow/deny
		),
		AuditDropsTotal: promauto.With(reg).NewCounter(
			prometheus.CounterOpts{
				Namespace: "sentinelgate",
				Name:      "audit_drops_total",
				Help:      "Total audit records dropped due to backpressure",
			},
		),
		RateLimitKeys: promauto.With(reg).NewGauge(
			prometheus.GaugeOpts{
				Namespace: "sentinelgate",
				Name:      "rate_limit_keys",
				Help:      "Number of active rate limit keys",
			},
		),
	}
}
