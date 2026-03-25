package service

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
)

// mockDriftAuditReader stores audit records for testing.
type mockDriftAuditReader struct {
	mu      sync.Mutex
	records []audit.AuditRecord
}

func (m *mockDriftAuditReader) Query(_ context.Context, filter audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []audit.AuditRecord
	for _, r := range m.records {
		if filter.UserID != "" && r.IdentityID != filter.UserID {
			continue
		}
		if filter.ToolName != "" && r.ToolName != filter.ToolName {
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

// mockDriftEventBus captures events.
type mockDriftEventBus struct {
	mu     sync.Mutex
	events []event.Event
}

func (b *mockDriftEventBus) Publish(_ context.Context, evt event.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, evt)
}
func (b *mockDriftEventBus) Subscribe(_ string, _ event.Subscriber) func() { return func() {} }
func (b *mockDriftEventBus) SubscribeAll(_ event.Subscriber) func()        { return func() {} }
func (b *mockDriftEventBus) DroppedCount() uint64                           { return 0 }

func (b *mockDriftEventBus) EventsByType(t string) []event.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	var result []event.Event
	for _, e := range b.events {
		if e.Type == t {
			result = append(result, e)
		}
	}
	return result
}

func makeRecords(identityID string, count int, tool string, decision string, baseTime time.Time) []audit.AuditRecord {
	records := make([]audit.AuditRecord, count)
	for i := 0; i < count; i++ {
		records[i] = audit.AuditRecord{
			Timestamp:     baseTime.Add(time.Duration(i) * time.Minute),
			IdentityID:    identityID,
			ToolName:      tool,
			Decision:      decision,
			LatencyMicros: 100,
		}
	}
	return records
}

func TestBuildProfile_EmptyRecords(t *testing.T) {
	svc := NewDriftService(nil, nil, slog.Default())
	defer svc.Stop()
	profile := svc.BuildProfile("test-agent", nil)

	if profile.IdentityID != "test-agent" {
		t.Errorf("expected identity test-agent, got %s", profile.IdentityID)
	}
	if profile.TotalCalls != 0 {
		t.Errorf("expected 0 total calls, got %d", profile.TotalCalls)
	}
}

func TestBuildProfile_Basic(t *testing.T) {
	svc := NewDriftService(nil, nil, slog.Default())
	defer svc.Stop()
	now := time.Now()

	var records []audit.AuditRecord
	records = append(records, makeRecords("agent-1", 60, "read_file", "allow", now)...)
	records = append(records, makeRecords("agent-1", 30, "search", "allow", now)...)
	records = append(records, makeRecords("agent-1", 10, "bash", "deny", now)...)

	profile := svc.BuildProfile("agent-1", records)

	if profile.TotalCalls != 100 {
		t.Errorf("expected 100 total calls, got %d", profile.TotalCalls)
	}

	// read_file should be 60%
	readPct := profile.ToolDistribution["read_file"]
	if readPct < 0.59 || readPct > 0.61 {
		t.Errorf("expected read_file ~60%%, got %.2f%%", readPct*100)
	}

	// deny rate should be 10%
	if profile.DenyRate < 0.09 || profile.DenyRate > 0.11 {
		t.Errorf("expected deny rate ~10%%, got %.2f%%", profile.DenyRate*100)
	}
}

func TestBuildProfile_ToolDistribution(t *testing.T) {
	svc := NewDriftService(nil, nil, slog.Default())
	defer svc.Stop()
	now := time.Now()

	records := []audit.AuditRecord{
		{Timestamp: now, IdentityID: "a", ToolName: "t1", Decision: "allow"},
		{Timestamp: now, IdentityID: "a", ToolName: "t1", Decision: "allow"},
		{Timestamp: now, IdentityID: "a", ToolName: "t2", Decision: "allow"},
		{Timestamp: now, IdentityID: "a", ToolName: "t3", Decision: "allow"},
	}

	profile := svc.BuildProfile("a", records)
	if profile.ToolDistribution["t1"] != 0.5 {
		t.Errorf("expected t1 at 50%%, got %.0f%%", profile.ToolDistribution["t1"]*100)
	}
	if profile.ToolDistribution["t2"] != 0.25 {
		t.Errorf("expected t2 at 25%%, got %.0f%%", profile.ToolDistribution["t2"]*100)
	}
}

func TestDetectDrift_NoBaseline(t *testing.T) {
	reader := &mockDriftAuditReader{}
	svc := NewDriftService(reader, nil, slog.Default())
	defer svc.Stop()

	report, err := svc.DetectDrift(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
	if len(report.Anomalies) != 0 {
		t.Errorf("expected no anomalies with empty baseline, got %d", len(report.Anomalies))
	}
}

func TestDetectDrift_ToolShift(t *testing.T) {
	now := time.Now()
	cfg := DefaultDriftConfig()

	// Baseline: 14 days ago, 80% read_file + 20% search
	baselineStart := now.Add(-time.Duration(cfg.CurrentWindowDays+cfg.BaselineWindowDays) * 24 * time.Hour)
	var records []audit.AuditRecord
	records = append(records, makeRecords("agent-1", 80, "read_file", "allow", baselineStart)...)
	records = append(records, makeRecords("agent-1", 20, "search", "allow", baselineStart)...)

	// Current: last day, 30% read_file + 60% bash + 10% search
	currentStart := now.Add(-time.Duration(cfg.CurrentWindowDays) * 24 * time.Hour)
	records = append(records, makeRecords("agent-1", 30, "read_file", "allow", currentStart)...)
	records = append(records, makeRecords("agent-1", 60, "bash", "allow", currentStart)...)
	records = append(records, makeRecords("agent-1", 10, "search", "allow", currentStart)...)

	reader := &mockDriftAuditReader{records: records}
	svc := NewDriftService(reader, nil, slog.Default())
	defer svc.Stop()

	report, err := svc.DetectDrift(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Anomalies) == 0 {
		t.Fatal("expected tool shift anomalies")
	}

	// Should detect bash emergence and read_file decline
	var hasBash, hasReadFile bool
	for _, a := range report.Anomalies {
		if a.Type == "tool_shift" && a.ToolName == "bash" {
			hasBash = true
		}
		if a.Type == "tool_shift" && a.ToolName == "read_file" {
			hasReadFile = true
		}
	}
	if !hasBash {
		t.Error("expected tool_shift anomaly for bash")
	}
	if !hasReadFile {
		t.Error("expected tool_shift anomaly for read_file")
	}

	if report.DriftScore <= 0 {
		t.Error("expected positive drift score")
	}
}

func TestDetectDrift_DenyRateIncrease(t *testing.T) {
	now := time.Now()
	cfg := DefaultDriftConfig()

	baselineStart := now.Add(-time.Duration(cfg.CurrentWindowDays+cfg.BaselineWindowDays) * 24 * time.Hour)
	var records []audit.AuditRecord
	// Baseline: 5% deny rate
	records = append(records, makeRecords("agent-1", 95, "read_file", "allow", baselineStart)...)
	records = append(records, makeRecords("agent-1", 5, "read_file", "deny", baselineStart)...)

	// Current: 30% deny rate
	currentStart := now.Add(-time.Duration(cfg.CurrentWindowDays) * 24 * time.Hour)
	records = append(records, makeRecords("agent-1", 70, "read_file", "allow", currentStart)...)
	records = append(records, makeRecords("agent-1", 30, "read_file", "deny", currentStart)...)

	reader := &mockDriftAuditReader{records: records}
	svc := NewDriftService(reader, nil, slog.Default())
	defer svc.Stop()

	report, err := svc.DetectDrift(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hasDenyRate bool
	for _, a := range report.Anomalies {
		if a.Type == "deny_rate" {
			hasDenyRate = true
			if a.Deviation <= 0 {
				t.Error("expected positive deviation for deny rate increase")
			}
		}
	}
	if !hasDenyRate {
		t.Error("expected deny_rate anomaly")
	}
}

func TestDetectDrift_BelowMinCalls(t *testing.T) {
	now := time.Now()
	cfg := DefaultDriftConfig()

	baselineStart := now.Add(-time.Duration(cfg.CurrentWindowDays+cfg.BaselineWindowDays) * 24 * time.Hour)
	// Only 5 baseline calls (below MinCallsBaseline=10)
	records := makeRecords("agent-1", 5, "read_file", "allow", baselineStart)

	currentStart := now.Add(-time.Duration(cfg.CurrentWindowDays) * 24 * time.Hour)
	records = append(records, makeRecords("agent-1", 50, "bash", "allow", currentStart)...)

	reader := &mockDriftAuditReader{records: records}
	svc := NewDriftService(reader, nil, slog.Default())
	defer svc.Stop()

	report, err := svc.DetectDrift(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Anomalies) != 0 {
		t.Errorf("expected no anomalies below min calls, got %d", len(report.Anomalies))
	}
}

func TestDetectDrift_EventEmission(t *testing.T) {
	now := time.Now()
	cfg := DefaultDriftConfig()

	baselineStart := now.Add(-time.Duration(cfg.CurrentWindowDays+cfg.BaselineWindowDays) * 24 * time.Hour)
	var records []audit.AuditRecord
	records = append(records, makeRecords("agent-1", 90, "read_file", "allow", baselineStart)...)
	records = append(records, makeRecords("agent-1", 10, "search", "allow", baselineStart)...)

	currentStart := now.Add(-time.Duration(cfg.CurrentWindowDays) * 24 * time.Hour)
	records = append(records, makeRecords("agent-1", 10, "read_file", "allow", currentStart)...)
	records = append(records, makeRecords("agent-1", 90, "bash", "allow", currentStart)...)

	reader := &mockDriftAuditReader{records: records}
	bus := &mockDriftEventBus{}
	svc := NewDriftService(reader, nil, slog.Default())
	defer svc.Stop()
	svc.SetEventBus(bus)

	_, err := svc.DetectDrift(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	events := bus.EventsByType("drift.anomaly")
	if len(events) != 1 {
		t.Fatalf("expected 1 drift.anomaly event, got %d", len(events))
	}

	evt := events[0]
	if evt.Source != "drift-detector" {
		t.Errorf("expected source drift-detector, got %s", evt.Source)
	}
	if !evt.RequiresAction {
		t.Error("drift anomaly should require action")
	}
}

func TestDetectAll(t *testing.T) {
	now := time.Now()
	cfg := DefaultDriftConfig()

	baselineStart := now.Add(-time.Duration(cfg.CurrentWindowDays+cfg.BaselineWindowDays) * 24 * time.Hour)
	var records []audit.AuditRecord
	// Two agents in baseline
	records = append(records, makeRecords("agent-1", 50, "read_file", "allow", baselineStart)...)
	records = append(records, makeRecords("agent-2", 50, "search", "allow", baselineStart)...)

	// Current activity
	currentStart := now.Add(-time.Duration(cfg.CurrentWindowDays) * 24 * time.Hour)
	records = append(records, makeRecords("agent-1", 10, "read_file", "allow", currentStart)...)
	records = append(records, makeRecords("agent-2", 10, "search", "allow", currentStart)...)

	reader := &mockDriftAuditReader{records: records}
	svc := NewDriftService(reader, nil, slog.Default())
	defer svc.Stop()

	reports, err := svc.DetectAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(reports) < 2 {
		t.Errorf("expected at least 2 reports, got %d", len(reports))
	}
}

func TestKLDivergence_Identical(t *testing.T) {
	p := []float64{0.5, 0.3, 0.2}
	kl := klDivergence(p, p)
	if kl > 0.01 {
		t.Errorf("expected ~0 KL for identical distributions, got %f", kl)
	}
}

func TestKLDivergence_Different(t *testing.T) {
	p := []float64{0.9, 0.1, 0.0}
	q := []float64{0.1, 0.1, 0.8}
	kl := klDivergence(p, q)
	if kl <= 0.1 {
		t.Errorf("expected positive KL for different distributions, got %f", kl)
	}
}

func TestKLDivergence_Empty(t *testing.T) {
	kl := klDivergence(nil, nil)
	if kl != 0 {
		t.Errorf("expected 0 for empty distributions, got %f", kl)
	}
}

func TestComputeDriftScore_NoAnomalies(t *testing.T) {
	score := computeDriftScore(nil)
	if score != 0 {
		t.Errorf("expected 0, got %f", score)
	}
}

func TestComputeDriftScore_Cap(t *testing.T) {
	anomalies := []DriftAnomaly{
		{Severity: "high"},
		{Severity: "high"},
		{Severity: "high"},
		{Severity: "medium"},
	}
	score := computeDriftScore(anomalies)
	if score != 1.0 {
		t.Errorf("expected score capped at 1.0, got %f", score)
	}
}

func TestDefaultDriftConfig(t *testing.T) {
	cfg := DefaultDriftConfig()
	if cfg.BaselineWindowDays != 14 {
		t.Errorf("expected 14 day baseline window, got %d", cfg.BaselineWindowDays)
	}
	if cfg.MinCallsBaseline != 10 {
		t.Errorf("expected 10 min calls, got %d", cfg.MinCallsBaseline)
	}
}

func TestSetConfig(t *testing.T) {
	svc := NewDriftService(nil, nil, slog.Default())
	defer svc.Stop()
	cfg := DefaultDriftConfig()
	cfg.BaselineWindowDays = 7
	svc.SetConfig(cfg)

	got := svc.Config()
	if got.BaselineWindowDays != 7 {
		t.Errorf("expected 7, got %d", got.BaselineWindowDays)
	}
}

func TestBuildProfile_HourlyPattern(t *testing.T) {
	svc := NewDriftService(nil, nil, slog.Default())
	defer svc.Stop()
	base := time.Date(2026, 3, 5, 14, 0, 0, 0, time.UTC)

	records := []audit.AuditRecord{
		{Timestamp: base, IdentityID: "a", ToolName: "t", Decision: "allow"},
		{Timestamp: base.Add(time.Hour), IdentityID: "a", ToolName: "t", Decision: "allow"},
		{Timestamp: base.Add(time.Hour), IdentityID: "a", ToolName: "t", Decision: "allow"},
	}

	profile := svc.BuildProfile("a", records)
	// Hour 14 should be 1/3 of max, hour 15 should be 2/3 (normalized to max=1.0)
	if profile.HourlyPattern[14] != 0.5 { // 1 call / 2 max calls = 0.5
		t.Errorf("expected hour 14 pattern 0.5, got %f", profile.HourlyPattern[14])
	}
	if profile.HourlyPattern[15] != 1.0 { // 2 calls / 2 max calls = 1.0
		t.Errorf("expected hour 15 pattern 1.0, got %f", profile.HourlyPattern[15])
	}
}

func TestDetectDrift_ArgShift(t *testing.T) {
	now := time.Now()
	cfg := DefaultDriftConfig()

	baselineStart := now.Add(-time.Duration(cfg.CurrentWindowDays+cfg.BaselineWindowDays) * 24 * time.Hour)
	var records []audit.AuditRecord

	// Baseline: read_file always with "path" arg
	for i := 0; i < 50; i++ {
		records = append(records, audit.AuditRecord{
			Timestamp:     baselineStart.Add(time.Duration(i) * time.Minute),
			IdentityID:    "agent-1",
			ToolName:      "read_file",
			Decision:      "allow",
			ToolArguments: map[string]interface{}{"path": "/docs/file.txt"},
		})
	}

	// Current: read_file with completely different args (url, headers, body)
	// Offset by 1h to avoid boundary bleed between baseline/current windows
	currentStart := now.Add(-time.Duration(cfg.CurrentWindowDays)*24*time.Hour + time.Hour)
	for i := 0; i < 50; i++ {
		records = append(records, audit.AuditRecord{
			Timestamp:     currentStart.Add(time.Duration(i) * time.Minute),
			IdentityID:    "agent-1",
			ToolName:      "read_file",
			Decision:      "allow",
			ToolArguments: map[string]interface{}{"url": "http://evil.com", "headers": "auth", "body": "data"},
		})
	}

	reader := &mockDriftAuditReader{records: records}
	svc := NewDriftService(reader, nil, slog.Default())
	defer svc.Stop()

	report, err := svc.DetectDrift(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hasArgShift bool
	for _, a := range report.Anomalies {
		if a.Type == "arg_shift" {
			hasArgShift = true
			if a.ToolName != "read_file" {
				t.Errorf("expected tool_name read_file, got %s", a.ToolName)
			}
		}
	}
	if !hasArgShift {
		t.Error("expected arg_shift anomaly when argument keys change completely")
	}
}

func TestDetectDrift_ArgShift_NoChange(t *testing.T) {
	now := time.Now()
	cfg := DefaultDriftConfig()

	baselineStart := now.Add(-time.Duration(cfg.CurrentWindowDays+cfg.BaselineWindowDays) * 24 * time.Hour)
	var records []audit.AuditRecord

	// Baseline and current: same args
	for i := 0; i < 50; i++ {
		records = append(records, audit.AuditRecord{
			Timestamp:     baselineStart.Add(time.Duration(i) * time.Minute),
			IdentityID:    "agent-1",
			ToolName:      "search",
			Decision:      "allow",
			ToolArguments: map[string]interface{}{"query": "test", "limit": 10},
		})
	}
	currentStart := now.Add(-time.Duration(cfg.CurrentWindowDays) * 24 * time.Hour)
	for i := 0; i < 50; i++ {
		records = append(records, audit.AuditRecord{
			Timestamp:     currentStart.Add(time.Duration(i) * time.Minute),
			IdentityID:    "agent-1",
			ToolName:      "search",
			Decision:      "allow",
			ToolArguments: map[string]interface{}{"query": "other", "limit": 20},
		})
	}

	reader := &mockDriftAuditReader{records: records}
	svc := NewDriftService(reader, nil, slog.Default())
	defer svc.Stop()

	report, err := svc.DetectDrift(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, a := range report.Anomalies {
		if a.Type == "arg_shift" {
			t.Error("should not detect arg_shift when keys are identical")
		}
	}
}

func TestBuildProfile_ArgKeys(t *testing.T) {
	svc := NewDriftService(nil, nil, slog.Default())
	defer svc.Stop()
	now := time.Now()

	records := []audit.AuditRecord{
		{Timestamp: now, IdentityID: "a", ToolName: "t1", Decision: "allow", ToolArguments: map[string]interface{}{"path": "/a"}},
		{Timestamp: now, IdentityID: "a", ToolName: "t1", Decision: "allow", ToolArguments: map[string]interface{}{"path": "/b", "recursive": true}},
		{Timestamp: now, IdentityID: "a", ToolName: "t2", Decision: "allow", ToolArguments: map[string]interface{}{"query": "x"}},
	}

	profile := svc.BuildProfile("a", records)

	t1Keys := profile.ArgKeysByTool["t1"]
	if t1Keys == nil {
		t.Fatal("expected arg keys for t1")
	}
	// "path" should appear in 2/2 calls = 1.0
	if t1Keys["path"] != 1.0 {
		t.Errorf("expected path freq 1.0, got %f", t1Keys["path"])
	}
	// "recursive" should appear in 1/2 calls = 0.5
	if t1Keys["recursive"] != 0.5 {
		t.Errorf("expected recursive freq 0.5, got %f", t1Keys["recursive"])
	}
}

func TestDetectDrift_LatencyChange(t *testing.T) {
	now := time.Now()
	cfg := DefaultDriftConfig()

	baselineStart := now.Add(-time.Duration(cfg.CurrentWindowDays+cfg.BaselineWindowDays) * 24 * time.Hour)
	var records []audit.AuditRecord

	// Baseline: 100µs avg
	for i := 0; i < 50; i++ {
		records = append(records, audit.AuditRecord{
			Timestamp:     baselineStart.Add(time.Duration(i) * time.Minute),
			IdentityID:    "agent-1",
			ToolName:      "read_file",
			Decision:      "allow",
			LatencyMicros: 100,
		})
	}

	// Current: 500µs avg (5x increase)
	currentStart := now.Add(-time.Duration(cfg.CurrentWindowDays) * 24 * time.Hour)
	for i := 0; i < 50; i++ {
		records = append(records, audit.AuditRecord{
			Timestamp:     currentStart.Add(time.Duration(i) * time.Minute),
			IdentityID:    "agent-1",
			ToolName:      "read_file",
			Decision:      "allow",
			LatencyMicros: 500,
		})
	}

	reader := &mockDriftAuditReader{records: records}
	svc := NewDriftService(reader, nil, slog.Default())
	defer svc.Stop()

	report, err := svc.DetectDrift(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hasLatency bool
	for _, a := range report.Anomalies {
		if a.Type == "latency" {
			hasLatency = true
		}
	}
	if !hasLatency {
		t.Error("expected latency anomaly for 5x increase")
	}
}
