package service

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// mockHealthReader implements HealthAuditReader for testing.
type mockHealthReader struct {
	records []audit.AuditRecord
}

func (m *mockHealthReader) Query(_ context.Context, filter audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	var result []audit.AuditRecord
	for _, r := range m.records {
		if filter.UserID != "" && r.IdentityID != filter.UserID {
			continue
		}
		if !filter.StartTime.IsZero() && r.Timestamp.Before(filter.StartTime) {
			continue
		}
		if !filter.EndTime.IsZero() && r.Timestamp.After(filter.EndTime) {
			continue
		}
		result = append(result, r)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result, "", nil
}

func TestHealthService_ComputeMetrics(t *testing.T) {
	now := time.Now()
	reader := &mockHealthReader{
		records: []audit.AuditRecord{
			{IdentityID: "agent-1", Decision: "allow", Timestamp: now.Add(-1 * time.Hour), ToolName: "read_file"},
			{IdentityID: "agent-1", Decision: "allow", Timestamp: now.Add(-2 * time.Hour), ToolName: "read_file"},
			{IdentityID: "agent-1", Decision: "deny", Timestamp: now.Add(-3 * time.Hour), ToolName: "write_file"},
			{IdentityID: "agent-1", Decision: "deny", Timestamp: now.Add(-4 * time.Hour), ToolName: "delete_file"},
			{IdentityID: "agent-1", Decision: "error", Timestamp: now.Add(-5 * time.Hour), ToolName: "bad_tool"},
			{IdentityID: "agent-1", Decision: "allow", Timestamp: now.Add(-6 * time.Hour), ToolName: "read_file", ScanAction: "blocked"},
		},
	}

	svc := NewHealthService(reader, slog.Default())
	metrics, err := svc.ComputeMetrics(context.Background(), "agent-1", 24*time.Hour)
	if err != nil {
		t.Fatalf("ComputeMetrics failed: %v", err)
	}

	if metrics.TotalCalls != 6 {
		t.Errorf("TotalCalls = %d, want 6", metrics.TotalCalls)
	}
	if metrics.DeniedCalls != 2 {
		t.Errorf("DeniedCalls = %d, want 2", metrics.DeniedCalls)
	}
	if metrics.ErrorCalls != 1 {
		t.Errorf("ErrorCalls = %d, want 1", metrics.ErrorCalls)
	}
	// ViolationCount = 2 denials + 1 scan_blocked = 3
	if metrics.ViolationCount != 3 {
		t.Errorf("ViolationCount = %d, want 3", metrics.ViolationCount)
	}

	expectedDenyRate := 2.0 / 6.0
	if diff := metrics.DenyRate - expectedDenyRate; diff > 0.001 || diff < -0.001 {
		t.Errorf("DenyRate = %f, want %f", metrics.DenyRate, expectedDenyRate)
	}
	expectedErrorRate := 1.0 / 6.0
	if diff := metrics.ErrorRate - expectedErrorRate; diff > 0.001 || diff < -0.001 {
		t.Errorf("ErrorRate = %f, want %f", metrics.ErrorRate, expectedErrorRate)
	}
}

func TestHealthService_ComputeMetrics_Empty(t *testing.T) {
	reader := &mockHealthReader{records: nil}
	svc := NewHealthService(reader, slog.Default())
	metrics, err := svc.ComputeMetrics(context.Background(), "agent-x", 24*time.Hour)
	if err != nil {
		t.Fatalf("ComputeMetrics failed: %v", err)
	}
	if metrics.TotalCalls != 0 {
		t.Errorf("TotalCalls = %d, want 0", metrics.TotalCalls)
	}
	if metrics.DenyRate != 0 {
		t.Errorf("DenyRate = %f, want 0", metrics.DenyRate)
	}
}

func TestHealthService_ClassifyStatus(t *testing.T) {
	svc := NewHealthService(&mockHealthReader{}, slog.Default())

	tests := []struct {
		name     string
		metrics  *HealthMetrics
		expected string
	}{
		{
			name:     "healthy agent",
			metrics:  &HealthMetrics{DenyRate: 0.05, DriftScore: 0.1, ErrorRate: 0.02},
			expected: "healthy",
		},
		{
			name:     "attention - deny rate",
			metrics:  &HealthMetrics{DenyRate: 0.15, DriftScore: 0.1, ErrorRate: 0.02},
			expected: "attention",
		},
		{
			name:     "attention - drift score",
			metrics:  &HealthMetrics{DenyRate: 0.05, DriftScore: 0.35, ErrorRate: 0.02},
			expected: "attention",
		},
		{
			name:     "critical - deny rate",
			metrics:  &HealthMetrics{DenyRate: 0.30, DriftScore: 0.1, ErrorRate: 0.02},
			expected: "critical",
		},
		{
			name:     "critical - drift score",
			metrics:  &HealthMetrics{DenyRate: 0.05, DriftScore: 0.65, ErrorRate: 0.02},
			expected: "critical",
		},
		{
			name:     "critical - error rate",
			metrics:  &HealthMetrics{DenyRate: 0.05, DriftScore: 0.1, ErrorRate: 0.20},
			expected: "critical",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := svc.ClassifyStatus(tt.metrics)
			if status != tt.expected {
				t.Errorf("ClassifyStatus = %q, want %q", status, tt.expected)
			}
		})
	}
}

func TestHealthService_GetHealthOverview(t *testing.T) {
	now := time.Now()
	reader := &mockHealthReader{
		records: []audit.AuditRecord{
			{IdentityID: "agent-1", Decision: "allow", Timestamp: now.Add(-1 * time.Hour), ToolName: "read"},
			{IdentityID: "agent-1", Decision: "deny", Timestamp: now.Add(-2 * time.Hour), ToolName: "write"},
			{IdentityID: "agent-2", Decision: "allow", Timestamp: now.Add(-1 * time.Hour), ToolName: "read"},
			{IdentityID: "agent-2", Decision: "allow", Timestamp: now.Add(-2 * time.Hour), ToolName: "list"},
			{IdentityID: "agent-2", Decision: "allow", Timestamp: now.Add(-3 * time.Hour), ToolName: "read"},
		},
	}

	svc := NewHealthService(reader, slog.Default())
	entries, err := svc.GetHealthOverview(context.Background())
	if err != nil {
		t.Fatalf("GetHealthOverview failed: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// agent-1 has deny rate 50%, should be listed first (critical)
	if entries[0].IdentityID != "agent-1" {
		t.Errorf("expected agent-1 first (higher deny rate), got %s", entries[0].IdentityID)
	}
	if entries[0].DenyRate != 0.5 {
		t.Errorf("agent-1 deny rate = %f, want 0.5", entries[0].DenyRate)
	}
}

func TestHealthService_GetHealthReport(t *testing.T) {
	now := time.Now()
	var records []audit.AuditRecord
	// Generate 30 days of records for trend
	for d := 0; d < 30; d++ {
		ts := now.Add(-time.Duration(d) * 24 * time.Hour)
		records = append(records, audit.AuditRecord{
			IdentityID: "agent-1", Decision: "allow", Timestamp: ts, ToolName: "read",
		})
		if d%5 == 0 {
			records = append(records, audit.AuditRecord{
				IdentityID: "agent-1", Decision: "deny", Timestamp: ts.Add(-1 * time.Hour), ToolName: "write",
			})
		}
	}

	reader := &mockHealthReader{records: records}
	svc := NewHealthService(reader, slog.Default())

	report, err := svc.GetHealthReport(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("GetHealthReport failed: %v", err)
	}

	if report.Status == "" {
		t.Error("Status should not be empty")
	}
	if len(report.Trend) != 30 {
		t.Errorf("expected 30 trend points, got %d", len(report.Trend))
	}
	if len(report.Comparisons) == 0 {
		t.Error("expected baseline comparisons")
	}
}

func TestHealthService_Config(t *testing.T) {
	svc := NewHealthService(&mockHealthReader{}, slog.Default())

	cfg := svc.Config()
	if cfg.DenyRateWarning != 0.10 {
		t.Errorf("default DenyRateWarning = %f, want 0.10", cfg.DenyRateWarning)
	}

	svc.SetConfig(HealthConfig{
		DenyRateWarning:    0.20,
		DenyRateCritical:   0.40,
		DriftScoreWarning:  0.35,
		DriftScoreCritical: 0.70,
		ErrorRateWarning:   0.08,
		ErrorRateCritical:  0.20,
	})

	cfg = svc.Config()
	if cfg.DenyRateWarning != 0.20 {
		t.Errorf("updated DenyRateWarning = %f, want 0.20", cfg.DenyRateWarning)
	}

	// Verify classification uses new thresholds
	status := svc.ClassifyStatus(&HealthMetrics{DenyRate: 0.15, DriftScore: 0.1, ErrorRate: 0.02})
	if status != "healthy" { // 0.15 < 0.20 warning
		t.Errorf("expected healthy with updated threshold, got %s", status)
	}
}

func TestHealthService_GetMetricsForCEL_Caching(t *testing.T) {
	now := time.Now()
	reader := &mockHealthReader{
		records: []audit.AuditRecord{
			{IdentityID: "agent-1", Decision: "allow", Timestamp: now.Add(-1 * time.Hour)},
			{IdentityID: "agent-1", Decision: "deny", Timestamp: now.Add(-2 * time.Hour)},
		},
	}

	svc := NewHealthService(reader, slog.Default())

	m1 := svc.GetMetricsForCEL(context.Background(), "agent-1")
	if m1.TotalCalls != 2 {
		t.Errorf("first call: TotalCalls = %d, want 2", m1.TotalCalls)
	}

	// Second call should return cached value
	m2 := svc.GetMetricsForCEL(context.Background(), "agent-1")
	if m2.TotalCalls != 2 {
		t.Errorf("cached call: TotalCalls = %d, want 2", m2.TotalCalls)
	}
}

func TestCompareStatus(t *testing.T) {
	tests := []struct {
		name          string
		baseline      float64
		current       float64
		lowerIsBetter bool
		expected      string
	}{
		{"both zero", 0, 0, true, "stable"},
		{"no change", 0.5, 0.5, true, "stable"},
		{"small increase lower-better", 0.10, 0.105, true, "stable"},
		{"big increase lower-better", 0.10, 0.20, true, "degraded"},
		{"decrease lower-better", 0.20, 0.10, true, "improved"},
		{"baseline zero current positive", 0, 0.1, true, "degraded"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := compareStatus(tt.baseline, tt.current, tt.lowerIsBetter)
			if status != tt.expected {
				t.Errorf("compareStatus(%f, %f, %v) = %q, want %q",
					tt.baseline, tt.current, tt.lowerIsBetter, status, tt.expected)
			}
		})
	}
}
