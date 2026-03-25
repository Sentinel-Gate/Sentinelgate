package service

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// passthrough interceptor that records whether it was called.
type passthroughInterceptor struct {
	called bool
}

func (p *passthroughInterceptor) Intercept(_ context.Context, act *action.CanonicalAction) (*action.CanonicalAction, error) {
	p.called = true
	return act, nil
}

// makeToolCallAction creates a CanonicalAction for a tool call by the given identity.
func makeToolCallAction(identityID, toolName string) *action.CanonicalAction {
	return &action.CanonicalAction{
		Type: action.ActionToolCall,
		Name: toolName,
		Identity: action.ActionIdentity{
			ID:        identityID,
			Name:      identityID,
			Roles:     []string{"user"},
			SessionID: "session-1",
		},
		RequestTime: time.Now(),
	}
}

// newBudgetTestFinOps creates a FinOpsService with the given records and config.
func newBudgetTestFinOps(records []audit.AuditRecord, cfg FinOpsConfig) *FinOpsService {
	reader := &mockFinOpsAuditReader{records: records}
	svc := NewFinOpsService(reader, slog.Default())
	svc.SetConfig(cfg)
	return svc
}

func TestBudgetBlock_DeniesCallsWhenExceeded(t *testing.T) {
	// 200 calls at $0.01 each = $2.00 spent for identity-x
	records := makeAuditRecords([]string{"identity-x"}, []string{"read_file"}, 200)
	finops := newBudgetTestFinOps(records, FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 0.01,
		ToolCosts:          map[string]float64{},
		Budgets:            map[string]float64{"identity-x": 1.00},
		BudgetActions:      map[string]string{"identity-x": "block"},
		AlertThresholds:    []float64{0.7, 0.85, 1.0},
	})

	next := &passthroughInterceptor{}
	interceptor := NewBudgetBlockInterceptor(finops, next, slog.Default())

	act := makeToolCallAction("identity-x", "write_file")
	_, err := interceptor.Intercept(context.Background(), act)

	if err == nil {
		t.Fatal("expected budget exceeded error, got nil")
	}
	if !strings.Contains(err.Error(), "monthly budget exceeded") {
		t.Errorf("expected 'monthly budget exceeded' in error, got: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "$2.00") {
		t.Errorf("expected spent amount in error message, got: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "$1.00") {
		t.Errorf("expected budget limit in error message, got: %s", err.Error())
	}
	if next.called {
		t.Error("next interceptor should NOT have been called when budget exceeded")
	}
}

func TestBudgetBlock_AllowsWhenActionIsNotify(t *testing.T) {
	records := makeAuditRecords([]string{"identity-x"}, []string{"read_file"}, 200)
	finops := newBudgetTestFinOps(records, FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 0.01,
		ToolCosts:          map[string]float64{},
		Budgets:            map[string]float64{"identity-x": 1.00},
		BudgetActions:      map[string]string{"identity-x": "notify"},
		AlertThresholds:    []float64{0.7, 0.85, 1.0},
	})

	next := &passthroughInterceptor{}
	interceptor := NewBudgetBlockInterceptor(finops, next, slog.Default())

	act := makeToolCallAction("identity-x", "write_file")
	_, err := interceptor.Intercept(context.Background(), act)

	if err != nil {
		t.Fatalf("expected no error for notify action, got: %v", err)
	}
	if !next.called {
		t.Error("next interceptor should have been called for notify action")
	}
}

func TestBudgetBlock_AllowsWhenFinopsDisabled(t *testing.T) {
	records := makeAuditRecords([]string{"identity-x"}, []string{"read_file"}, 200)
	finops := newBudgetTestFinOps(records, FinOpsConfig{
		Enabled:            false,
		DefaultCostPerCall: 0.01,
		Budgets:            map[string]float64{"identity-x": 1.00},
		BudgetActions:      map[string]string{"identity-x": "block"},
	})

	next := &passthroughInterceptor{}
	interceptor := NewBudgetBlockInterceptor(finops, next, slog.Default())

	act := makeToolCallAction("identity-x", "write_file")
	_, err := interceptor.Intercept(context.Background(), act)

	if err != nil {
		t.Fatalf("expected no error when finops disabled, got: %v", err)
	}
	if !next.called {
		t.Error("next interceptor should have been called when finops disabled")
	}
}

func TestBudgetBlock_AllowsWhenNoBudgetConfigured(t *testing.T) {
	records := makeAuditRecords([]string{"identity-x"}, []string{"read_file"}, 200)
	finops := newBudgetTestFinOps(records, FinOpsConfig{
		Enabled:            true,
		DefaultCostPerCall: 0.01,
		ToolCosts:          map[string]float64{},
		Budgets:            map[string]float64{},
		BudgetActions:      map[string]string{},
		AlertThresholds:    []float64{0.7, 0.85, 1.0},
	})

	next := &passthroughInterceptor{}
	interceptor := NewBudgetBlockInterceptor(finops, next, slog.Default())

	act := makeToolCallAction("identity-x", "write_file")
	_, err := interceptor.Intercept(context.Background(), act)

	if err != nil {
		t.Fatalf("expected no error when no budget configured, got: %v", err)
	}
	if !next.called {
		t.Error("next interceptor should have been called when no budget configured")
	}
}
