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

type mockFinOpsAuditReader struct {
	records []audit.AuditRecord
}

func (m *mockFinOpsAuditReader) Query(_ context.Context, _ audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	return m.records, "", nil
}

func makeAuditRecords(identities, tools []string, count int) []audit.AuditRecord {
	var records []audit.AuditRecord
	now := time.Now()
	for i := 0; i < count; i++ {
		records = append(records, audit.AuditRecord{
			Timestamp:  now.Add(-time.Duration(i) * time.Minute),
			IdentityID: identities[i%len(identities)],
			ToolName:   tools[i%len(tools)],
			Decision:   "allow",
		})
	}
	return records
}

func TestFinOpsService_Disabled(t *testing.T) {
	reader := &mockFinOpsAuditReader{records: makeAuditRecords([]string{"a"}, []string{"t"}, 10)}
	svc := NewFinOpsService(reader, slog.Default())
	// Default config is disabled

	report, err := svc.GetCostReport(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.TotalCost != 0 {
		t.Errorf("disabled service should return 0 cost, got %f", report.TotalCost)
	}
}

func TestFinOpsService_BasicCostReport(t *testing.T) {
	records := makeAuditRecords([]string{"agent-a", "agent-b"}, []string{"read_file", "write_file"}, 20)
	reader := &mockFinOpsAuditReader{records: records}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetConfig(FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 0.01,
		ToolCosts:          map[string]float64{},
		Budgets:            map[string]float64{},
		AlertThresholds:    []float64{0.7, 0.85, 1.0},
	})

	report, err := svc.GetCostReport(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.TotalCalls != 20 {
		t.Errorf("expected 20 calls, got %d", report.TotalCalls)
	}
	if report.TotalCost <= 0 {
		t.Error("expected positive total cost")
	}
	if len(report.ByIdentity) != 2 {
		t.Errorf("expected 2 identities, got %d", len(report.ByIdentity))
	}
	if len(report.ByTool) != 2 {
		t.Errorf("expected 2 tools, got %d", len(report.ByTool))
	}
}

func TestFinOpsService_PerToolCost(t *testing.T) {
	records := []audit.AuditRecord{
		{IdentityID: "a", ToolName: "expensive_tool", Decision: "allow"},
		{IdentityID: "a", ToolName: "cheap_tool", Decision: "allow"},
	}
	reader := &mockFinOpsAuditReader{records: records}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetConfig(FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 0.01,
		ToolCosts: map[string]float64{
			"expensive_tool": 1.00,
			"cheap_tool":     0.001,
		},
		Budgets:         map[string]float64{},
		AlertThresholds: []float64{0.7, 0.85, 1.0},
	})

	report, err := svc.GetCostReport(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.TotalCost < 1.0 {
		t.Errorf("expected at least $1.00, got %f", report.TotalCost)
	}

	// Check expensive_tool is first (sorted by cost)
	if len(report.ByTool) < 2 {
		t.Fatalf("expected 2 tools, got %d", len(report.ByTool))
	}
	if report.ByTool[0].ToolName != "expensive_tool" {
		t.Errorf("expected expensive_tool first, got %s", report.ByTool[0].ToolName)
	}
}

func TestFinOpsService_DeniedCallsIgnored(t *testing.T) {
	records := []audit.AuditRecord{
		{IdentityID: "a", ToolName: "tool", Decision: "allow"},
		{IdentityID: "a", ToolName: "tool", Decision: "deny"},
		{IdentityID: "a", ToolName: "tool", Decision: "deny"},
	}
	reader := &mockFinOpsAuditReader{records: records}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetConfig(FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 1.00,
		ToolCosts:          map[string]float64{},
		Budgets:            map[string]float64{},
		AlertThresholds:    []float64{},
	})

	report, _ := svc.GetCostReport(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
	if report.TotalCalls != 1 {
		t.Errorf("expected 1 allowed call, got %d", report.TotalCalls)
	}
	if report.TotalCost != 1.0 {
		t.Errorf("expected $1.00, got %f", report.TotalCost)
	}
}

func TestFinOpsService_BudgetStatus(t *testing.T) {
	records := makeAuditRecords([]string{"agent-a"}, []string{"tool"}, 100)
	reader := &mockFinOpsAuditReader{records: records}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetConfig(FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 0.01,
		ToolCosts:          map[string]float64{},
		Budgets: map[string]float64{
			"agent-a": 5.00,
		},
		AlertThresholds: []float64{0.7, 0.85, 1.0},
	})

	report, _ := svc.GetCostReport(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
	if len(report.BudgetStatus) != 1 {
		t.Fatalf("expected 1 budget status, got %d", len(report.BudgetStatus))
	}

	bs := report.BudgetStatus[0]
	if bs.IdentityID != "agent-a" {
		t.Errorf("expected agent-a, got %s", bs.IdentityID)
	}
	if bs.Budget != 5.00 {
		t.Errorf("expected budget 5.00, got %f", bs.Budget)
	}
	if bs.Spent <= 0 {
		t.Error("expected positive spent")
	}
	if bs.Percentage <= 0 {
		t.Error("expected positive percentage")
	}
}

func TestFinOpsService_EstimateCost(t *testing.T) {
	svc := NewFinOpsService(nil, slog.Default())
	svc.SetConfig(FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 0.01,
		ToolCosts: map[string]float64{
			"expensive": 5.0,
		},
	})

	// Known tool
	cost := svc.EstimateCost("expensive", 100)
	if cost != 5.0 {
		t.Errorf("expected 5.0, got %f", cost)
	}

	// Default tool, small args
	cost = svc.EstimateCost("unknown", 100)
	if cost != 0.01 {
		t.Errorf("expected 0.01, got %f", cost)
	}

	// Default tool, large args
	cost = svc.EstimateCost("unknown", 5000)
	if cost <= 0.01 {
		t.Errorf("expected > 0.01 for large args, got %f", cost)
	}
}

func TestFinOpsService_GetIdentityCost(t *testing.T) {
	records := makeAuditRecords([]string{"agent-a", "agent-b"}, []string{"tool"}, 10)
	reader := &mockFinOpsAuditReader{records: records}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetConfig(FinOpsConfig{Enabled: true, DefaultCostPerCall: 0.01})

	detail, err := svc.GetIdentityCost(context.Background(), "agent-a", time.Now().Add(-24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detail.IdentityID != "agent-a" {
		t.Errorf("expected agent-a, got %s", detail.IdentityID)
	}
	if detail.CallCount == 0 {
		t.Error("expected calls for agent-a")
	}

	// Unknown identity
	detail2, _ := svc.GetIdentityCost(context.Background(), "unknown", time.Now().Add(-24*time.Hour), time.Now())
	if detail2.IdentityID != "unknown" {
		t.Errorf("expected unknown, got %s", detail2.IdentityID)
	}
	if detail2.CallCount != 0 {
		t.Errorf("expected 0 calls, got %d", detail2.CallCount)
	}
}

func TestFinOpsService_BudgetAlertEmission(t *testing.T) {
	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()

	var received []event.Event
	var mu sync.Mutex
	bus.Subscribe("finops.budget_exceeded", func(_ context.Context, e event.Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	records := makeAuditRecords([]string{"agent-a"}, []string{"tool"}, 200)
	reader := &mockFinOpsAuditReader{records: records}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetEventBus(bus)
	svc.SetConfig(FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 0.10,
		Budgets:            map[string]float64{"agent-a": 1.00}, // 200 * 0.10 = $20 >> $1 budget
		AlertThresholds:    []float64{1.0},
	})

	svc.CheckBudgets(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
	bus.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Error("expected budget_exceeded event")
	}
}

func TestFinOpsService_BudgetAlertNoDuplicate(t *testing.T) {
	bus := event.NewBus(100)
	bus.Start()

	var received []event.Event
	var mu sync.Mutex
	bus.Subscribe("finops.budget_exceeded", func(_ context.Context, e event.Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	records := makeAuditRecords([]string{"agent-a"}, []string{"tool"}, 200)
	reader := &mockFinOpsAuditReader{records: records}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetEventBus(bus)
	svc.SetConfig(FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 0.10,
		Budgets:            map[string]float64{"agent-a": 1.00},
		AlertThresholds:    []float64{1.0},
	})

	// Check twice
	svc.CheckBudgets(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
	svc.CheckBudgets(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
	bus.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Errorf("expected exactly 1 event (no duplicates), got %d", len(received))
	}
}

func TestFinOpsService_ConfigResetAlerts(t *testing.T) {
	svc := NewFinOpsService(nil, slog.Default())
	// NOTE: Intentionally accessing unexported field svc.alertsSent to set up
	// pre-existing alert state — this is an internal (same-package) test.
	svc.alertsSent["agent-a"] = map[float64]bool{1.0: true}

	svc.SetConfig(FinOpsConfig{Enabled: true})
	if len(svc.alertsSent) != 0 {
		t.Error("SetConfig should reset alert state")
	}
}

func TestFinOpsService_EmptyRecords(t *testing.T) {
	reader := &mockFinOpsAuditReader{records: nil}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetConfig(FinOpsConfig{Enabled: true, DefaultCostPerCall: 0.01})

	report, err := svc.GetCostReport(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.TotalCost != 0 {
		t.Errorf("expected 0 cost, got %f", report.TotalCost)
	}
	if report.TotalCalls != 0 {
		t.Errorf("expected 0 calls, got %d", report.TotalCalls)
	}
}

func TestFinOpsService_Projection(t *testing.T) {
	records := makeAuditRecords([]string{"a"}, []string{"t"}, 10)
	reader := &mockFinOpsAuditReader{records: records}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetConfig(FinOpsConfig{Enabled: true, DefaultCostPerCall: 0.01})

	// Period: last 24h, project to 48h
	start := time.Now().Add(-24 * time.Hour)
	end := time.Now().Add(24 * time.Hour)
	report, _ := svc.GetCostReport(context.Background(), start, end)

	// Projection should be roughly 2x the current cost (half the period elapsed)
	if report.Projection <= report.TotalCost {
		t.Errorf("projection (%f) should be greater than current cost (%f)", report.Projection, report.TotalCost)
	}
}

// --- Wave 5 Tests: Per-identity budget ---

func TestFinOpsService_BudgetPerIdentity(t *testing.T) {
	// identity-1: 60 calls, identity-2: 40 calls
	records := makeAuditRecords([]string{"identity-1", "identity-2"}, []string{"tool"}, 100)
	reader := &mockFinOpsAuditReader{records: records}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetConfig(FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 0.01,
		ToolCosts:          make(map[string]float64),
		Budgets: map[string]float64{
			"identity-1": 50.0,
			"identity-2": 100.0,
		},
		BudgetActions:   make(map[string]string),
		AlertThresholds: []float64{0.7, 0.85, 1.0},
	})

	report, err := svc.GetCostReport(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With 100 calls at $0.01 each split across 2 identities (50 each),
	// both should have spent $0.50, well under their budgets.
	if len(report.BudgetStatus) != 2 {
		t.Fatalf("expected 2 budget statuses, got %d", len(report.BudgetStatus))
	}

	for _, bs := range report.BudgetStatus {
		if bs.Spent <= 0 {
			t.Errorf("identity %s spent should be > 0", bs.IdentityID)
		}
		if bs.Percentage <= 0 {
			t.Errorf("identity %s percentage should be > 0", bs.IdentityID)
		}
	}
}

func TestFinOpsService_BudgetExceeded(t *testing.T) {
	bus := event.NewBus(100)
	bus.Start()

	var received []event.Event
	var mu sync.Mutex
	bus.Subscribe("finops.budget_exceeded", func(_ context.Context, e event.Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	// 10 calls at $0.01 each = $0.10, budget $0.05
	records := makeAuditRecords([]string{"identity-1"}, []string{"tool"}, 10)
	reader := &mockFinOpsAuditReader{records: records}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetEventBus(bus)
	svc.SetConfig(FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 0.01,
		ToolCosts:          make(map[string]float64),
		Budgets:            map[string]float64{"identity-1": 0.05},
		BudgetActions:      make(map[string]string),
		AlertThresholds:    []float64{1.0},
	})

	svc.CheckBudgets(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
	bus.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Error("expected finops.budget_exceeded event when identity exceeds budget")
	}
	if len(received) > 0 {
		payload, ok := received[0].Payload.(map[string]interface{})
		if !ok {
			t.Fatal("expected map payload")
		}
		if payload["identity_id"] != "identity-1" {
			t.Errorf("expected identity_id=identity-1, got %v", payload["identity_id"])
		}
	}
}

func TestFinOpsService_Concurrent(t *testing.T) {
	records := makeAuditRecords([]string{"a"}, []string{"t"}, 10)
	reader := &mockFinOpsAuditReader{records: records}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetConfig(FinOpsConfig{Enabled: true, DefaultCostPerCall: 0.01})

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.GetCostReport(context.Background(), time.Now().Add(-24*time.Hour), time.Now())
		}()
	}
	wg.Wait()
}

func TestFinOpsService_BudgetActionsBlockPreserved(t *testing.T) {
	reader := &mockFinOpsAuditReader{records: nil}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetConfig(FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 0.01,
		ToolCosts:          make(map[string]float64),
		Budgets:            map[string]float64{"agent-a": 100.0},
		BudgetActions:      map[string]string{"agent-a": "block"},
		AlertThresholds:    []float64{0.7, 0.85, 1.0},
	})

	cfg := svc.Config()
	if cfg.BudgetActions["agent-a"] != "block" {
		t.Errorf("expected BudgetActions[agent-a] = 'block', got %q", cfg.BudgetActions["agent-a"])
	}
	if cfg.Budgets["agent-a"] != 100.0 {
		t.Errorf("expected Budgets[agent-a] = 100.0, got %f", cfg.Budgets["agent-a"])
	}
}
