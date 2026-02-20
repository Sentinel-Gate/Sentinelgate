package http

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	// Verify all metrics are registered
	if m.RequestsTotal == nil {
		t.Error("RequestsTotal not initialized")
	}
	if m.RequestDuration == nil {
		t.Error("RequestDuration not initialized")
	}
	if m.ActiveSessions == nil {
		t.Error("ActiveSessions not initialized")
	}
	if m.PolicyEvaluations == nil {
		t.Error("PolicyEvaluations not initialized")
	}
	if m.AuditDropsTotal == nil {
		t.Error("AuditDropsTotal not initialized")
	}
	if m.RateLimitKeys == nil {
		t.Error("RateLimitKeys not initialized")
	}
}

func TestMetricsRecording(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	// Test counter increment
	m.RequestsTotal.WithLabelValues("POST", "ok").Inc()

	count := testutil.ToFloat64(m.RequestsTotal.WithLabelValues("POST", "ok"))
	if count != 1 {
		t.Errorf("RequestsTotal = %v, want 1", count)
	}

	// Test gauge set
	m.ActiveSessions.Set(5)
	sessions := testutil.ToFloat64(m.ActiveSessions)
	if sessions != 5 {
		t.Errorf("ActiveSessions = %v, want 5", sessions)
	}

	// Test histogram observation
	m.RequestDuration.WithLabelValues("POST").Observe(0.1)
	// Verify histogram was recorded (check it doesn't error)
	gathered, err := reg.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	found := false
	for _, mf := range gathered {
		if strings.Contains(mf.GetName(), "request_duration") {
			found = true
			break
		}
	}
	if !found {
		t.Error("request_duration histogram not found in gathered metrics")
	}
}
