package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestMetricsMiddleware_RecordsDuration(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	handler := MetricsMiddleware(metrics)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify histogram has observation
	metricFamilies, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, mf := range metricFamilies {
		if mf.GetName() == "sentinelgate_request_duration_seconds" {
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "method" && lp.GetValue() == "POST" {
						if m.GetHistogram().GetSampleCount() != 1 {
							t.Errorf("expected 1 observation, got %d", m.GetHistogram().GetSampleCount())
						}
						found = true
					}
				}
			}
		}
	}
	if !found {
		t.Error("expected to find request_duration_seconds metric with method=POST")
	}
}

func TestMetricsMiddleware_RecordsRequestCount(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	handler := MetricsMiddleware(metrics)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify counter incremented
	var m dto.Metric
	if err := metrics.RequestsTotal.WithLabelValues("POST", "ok").Write(&m); err != nil {
		t.Fatal(err)
	}
	if m.Counter.GetValue() != 1 {
		t.Errorf("expected count 1, got %f", m.Counter.GetValue())
	}
}

func TestMetricsMiddleware_ErrorStatus(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	handler := MetricsMiddleware(metrics)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify error counter incremented
	var m dto.Metric
	if err := metrics.RequestsTotal.WithLabelValues("POST", "error").Write(&m); err != nil {
		t.Fatal(err)
	}
	if m.Counter.GetValue() != 1 {
		t.Errorf("expected count 1, got %f", m.Counter.GetValue())
	}
}

func TestMetricsMiddleware_SkipsMetricsEndpoint(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	handler := MetricsMiddleware(metrics)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify no metrics recorded by checking the gathered metrics
	metricFamilies, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	for _, mf := range metricFamilies {
		if mf.GetName() == "sentinelgate_request_duration_seconds" {
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "method" && lp.GetValue() == "GET" {
						if m.GetHistogram().GetSampleCount() != 0 {
							t.Errorf("expected 0 observations for /metrics, got %d", m.GetHistogram().GetSampleCount())
						}
					}
				}
			}
		}
	}
}

func TestMetricsMiddleware_SkipsHealthEndpoint(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics := NewMetrics(reg)

	handler := MetricsMiddleware(metrics)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify no metrics recorded for health endpoint by checking gathered metrics
	metricFamilies, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}

	for _, mf := range metricFamilies {
		if mf.GetName() == "sentinelgate_request_duration_seconds" {
			for _, m := range mf.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "method" && lp.GetValue() == "GET" {
						if m.GetHistogram().GetSampleCount() != 0 {
							t.Errorf("expected 0 observations for /health, got %d", m.GetHistogram().GetSampleCount())
						}
					}
				}
			}
		}
	}
}
