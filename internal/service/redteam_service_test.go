package service

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/redteam"
)

// mockRedTeamEvaluator is a configurable policy evaluator for testing.
type mockRedTeamEvaluator struct {
	allowAll  bool
	denyTools map[string]bool
}

func (m *mockRedTeamEvaluator) Evaluate(_ context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
	if m.denyTools != nil && m.denyTools[evalCtx.ToolName] {
		return policy.Decision{
			Allowed:  false,
			RuleID:   "test-deny-rule",
			RuleName: "test-deny",
			Reason:   "denied by test policy",
		}, nil
	}
	if m.allowAll {
		return policy.Decision{Allowed: true}, nil
	}
	return policy.Decision{Allowed: true}, nil
}

func TestRedTeamService_RunSuite_AllAllowed(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{allowAll: true}, slog.Default())

	report, err := svc.RunSuite(context.Background(), "test-agent", []string{"user"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.CorpusSize != 30 {
		t.Errorf("expected 30 patterns, got %d", report.CorpusSize)
	}
	if report.TotalPassed != 30 {
		t.Errorf("expected 30 vulnerabilities (all allowed), got %d", report.TotalPassed)
	}
	if report.TotalBlocked != 0 {
		t.Errorf("expected 0 blocked, got %d", report.TotalBlocked)
	}
	if report.BlockRate != 0 {
		t.Errorf("expected 0%% block rate, got %.1f%%", report.BlockRate)
	}
	if len(report.Vulnerabilities) != 30 {
		t.Errorf("expected 30 vulnerabilities, got %d", len(report.Vulnerabilities))
	}
	if report.ID == "" {
		t.Error("report ID should not be empty")
	}
}

func TestRedTeamService_RunSuite_SomeDenied(t *testing.T) {
	eval := &mockRedTeamEvaluator{
		denyTools: map[string]bool{
			"execute_command":  true,
			"delete_file":     true,
			"admin_reset_config": true,
		},
	}
	svc := NewRedTeamService(eval, slog.Default())

	report, err := svc.RunSuite(context.Background(), "", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.TotalBlocked == 0 {
		t.Error("expected some patterns blocked")
	}
	if report.TotalBlocked+report.TotalPassed != report.CorpusSize {
		t.Errorf("blocked (%d) + passed (%d) should equal corpus size (%d)",
			report.TotalBlocked, report.TotalPassed, report.CorpusSize)
	}

	// Verify blocked ones have rule info
	for _, r := range report.AllResults {
		if r.Blocked && r.Method == "policy" {
			if r.RuleID == "" {
				t.Errorf("blocked result %s should have RuleID", r.PatternID)
			}
		}
	}
}

func TestRedTeamService_RunCategory(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{allowAll: true}, slog.Default())

	report, err := svc.RunCategory(context.Background(), redteam.CategoryToolMisuse, "test", []string{"user"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if report.CorpusSize != 7 {
		t.Errorf("expected 7 tool_misuse patterns, got %d", report.CorpusSize)
	}

	for _, r := range report.AllResults {
		if r.Category != redteam.CategoryToolMisuse {
			t.Errorf("expected tool_misuse category, got %s", r.Category)
		}
	}
}

func TestRedTeamService_RunCategory_Unknown(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{}, slog.Default())

	_, err := svc.RunCategory(context.Background(), "nonexistent", "", nil)
	if err == nil {
		t.Error("expected error for unknown category")
	}
}

func TestRedTeamService_RunSingle(t *testing.T) {
	eval := &mockRedTeamEvaluator{
		denyTools: map[string]bool{"execute_command": true},
	}
	svc := NewRedTeamService(eval, slog.Default())

	result, err := svc.RunSingle(context.Background(), "TM-001", "agent", []string{"reader"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PatternID != "TM-001" {
		t.Errorf("expected TM-001, got %s", result.PatternID)
	}
	if !result.Blocked {
		t.Error("TM-001 calls execute_command which should be denied")
	}
	if result.Method != "policy" {
		t.Errorf("expected policy method, got %s", result.Method)
	}
}

func TestRedTeamService_RunSingle_Unknown(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{}, slog.Default())

	_, err := svc.RunSingle(context.Background(), "NONEXISTENT", "", nil)
	if err == nil {
		t.Error("expected error for unknown pattern")
	}
}

func TestRedTeamService_ContentScanBlocks(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{allowAll: true}, slog.Default())
	svc.SetContentScanFn(func(args map[string]interface{}) (detected, blocked bool) {
		return true, true
	})

	report, err := svc.RunSuite(context.Background(), "test", []string{"user"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All patterns with arguments should be blocked by content scan
	// Verify content scan blocked some patterns (checked below via TotalBlocked).
	if report.TotalBlocked == 0 {
		t.Error("content scan should have blocked some patterns")
	}
}

func TestRedTeamService_ContentScanDetectOnly(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{allowAll: true}, slog.Default())
	svc.SetContentScanFn(func(args map[string]interface{}) (detected, blocked bool) {
		return true, false // detect but don't block
	})

	report, err := svc.RunSuite(context.Background(), "test", []string{"user"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should all pass through to policy (which allows all)
	if report.TotalBlocked != 0 {
		t.Errorf("detect-only scan shouldn't block, got %d blocked", report.TotalBlocked)
	}
}

func TestRedTeamService_VulnerabilityHasRemediation(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{allowAll: true}, slog.Default())

	report, err := svc.RunSuite(context.Background(), "test", []string{"user"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, v := range report.Vulnerabilities {
		if v.Remediation == nil {
			t.Errorf("vulnerability %s should have remediation", v.PatternID)
		}
		if v.Explanation == "" {
			t.Errorf("vulnerability %s should have explanation", v.PatternID)
		}
	}
}

func TestRedTeamService_ReportStorage(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{allowAll: true}, slog.Default())

	// Run multiple times
	for i := 0; i < 3; i++ {
		_, err := svc.RunSuite(context.Background(), "test", nil)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}

	reports := svc.GetReports()
	if len(reports) != 3 {
		t.Errorf("expected 3 stored reports, got %d", len(reports))
	}

	// Most recent first
	if reports[0].Timestamp.Before(reports[2].Timestamp) {
		t.Error("reports should be most recent first")
	}
}

func TestRedTeamService_ReportStorageLimit(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{allowAll: true}, slog.Default())

	for i := 0; i < maxReports+5; i++ {
		_, _ = svc.RunSuite(context.Background(), "test", nil)
	}

	reports := svc.GetReports()
	if len(reports) != maxReports {
		t.Errorf("expected max %d reports, got %d", maxReports, len(reports))
	}
}

func TestRedTeamService_GetReport(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{allowAll: true}, slog.Default())

	report, _ := svc.RunSuite(context.Background(), "test", nil)

	found := svc.GetReport(report.ID)
	if found == nil {
		t.Fatal("should find report by ID")
	}
	if found.ID != report.ID {
		t.Errorf("expected %s, got %s", report.ID, found.ID)
	}

	notFound := svc.GetReport("nonexistent")
	if notFound != nil {
		t.Error("should return nil for unknown ID")
	}
}

func TestRedTeamService_EventBusEmission(t *testing.T) {
	// Manual scans (all current scans) should NOT emit events — results are
	// shown inline and notifications are suppressed per #57.
	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()

	var received []event.Event
	var mu sync.Mutex
	bus.Subscribe("redteam.scan_complete", func(_ context.Context, e event.Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	svc := NewRedTeamService(&mockRedTeamEvaluator{allowAll: true}, slog.Default())
	svc.SetEventBus(bus)

	_, _ = svc.RunSuite(context.Background(), "test", nil)

	// Give event bus time to deliver
	bus.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 0 {
		t.Fatalf("expected 0 events for manual scans (#57 suppression), got %d", len(received))
	}
}

func TestRedTeamService_EventBusNoVulns(t *testing.T) {
	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()

	var received []event.Event
	var mu sync.Mutex
	bus.Subscribe("redteam.scan_complete", func(_ context.Context, e event.Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	// Deny everything
	denyAll := make(map[string]bool)
	for _, p := range redteam.Corpus() {
		denyAll[p.ToolName] = true
	}
	svc := NewRedTeamService(&mockRedTeamEvaluator{denyTools: denyAll}, slog.Default())
	svc.SetEventBus(bus)

	_, _ = svc.RunSuite(context.Background(), "test", nil)
	bus.Stop()

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 0 {
		t.Fatalf("expected 0 events when no vulnerabilities, got %d", len(received))
	}
}

func TestRedTeamService_CategoryScores(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{allowAll: true}, slog.Default())

	report, _ := svc.RunSuite(context.Background(), "test", nil)

	if len(report.Scores) == 0 {
		t.Fatal("expected category scores")
	}

	totalFromScores := 0
	for _, cs := range report.Scores {
		totalFromScores += cs.Total
		if cs.Total != cs.Blocked+cs.Passed {
			t.Errorf("category %s: total (%d) != blocked (%d) + passed (%d)",
				cs.Category, cs.Total, cs.Blocked, cs.Passed)
		}
	}

	if totalFromScores != report.CorpusSize {
		t.Errorf("sum of category totals (%d) should equal corpus size (%d)",
			totalFromScores, report.CorpusSize)
	}
}

func TestRedTeamService_DefaultIdentity(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{allowAll: true}, slog.Default())

	result, _ := svc.RunSingle(context.Background(), "TM-001", "", nil)
	if result == nil {
		t.Fatal("expected result")
	}
	// Should not panic with empty identity/roles
}

func TestRedTeamService_ApprovalRequired(t *testing.T) {
	eval := &mockApprovalEvaluator{}
	svc := NewRedTeamService(eval, slog.Default())

	result, err := svc.RunSingle(context.Background(), "TM-001", "test", []string{"user"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Blocked {
		t.Error("approval_required should count as blocked")
	}
	if result.Method != "approval_required" {
		t.Errorf("expected approval_required method, got %s", result.Method)
	}
}

type mockApprovalEvaluator struct{}

func (m *mockApprovalEvaluator) Evaluate(_ context.Context, _ policy.EvaluationContext) (policy.Decision, error) {
	return policy.Decision{
		Allowed:          false,
		RequiresApproval: true,
		RuleID:           "hitl-rule",
		RuleName:         "human-approval",
	}, nil
}

func TestRedTeamService_Concurrent(t *testing.T) {
	svc := NewRedTeamService(&mockRedTeamEvaluator{allowAll: true}, slog.Default())

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.RunSuite(context.Background(), "test", nil)
		}()
	}
	wg.Wait()

	reports := svc.GetReports()
	if len(reports) != 5 {
		t.Errorf("expected 5 reports from concurrent runs, got %d", len(reports))
	}
}

func TestRedTeamService_CorpusSize(t *testing.T) {
	corpus := redteam.Corpus()
	if len(corpus) != 30 {
		t.Errorf("expected 30 patterns in OSS corpus, got %d", len(corpus))
	}

	// Verify IDs are unique
	ids := make(map[string]bool)
	for _, p := range corpus {
		if ids[p.ID] {
			t.Errorf("duplicate pattern ID: %s", p.ID)
		}
		ids[p.ID] = true
	}

	// Verify all have required fields
	for _, p := range corpus {
		if p.Name == "" {
			t.Errorf("pattern %s missing name", p.ID)
		}
		if p.Category == "" {
			t.Errorf("pattern %s missing category", p.ID)
		}
		if p.Severity == "" {
			t.Errorf("pattern %s missing severity", p.ID)
		}
		if p.ActionType == "" {
			t.Errorf("pattern %s missing action_type", p.ID)
		}
		if !p.ExpectBlock {
			t.Errorf("pattern %s: all attack patterns should expect to be blocked", p.ID)
		}
		if p.Remediation == nil {
			t.Errorf("pattern %s missing remediation", p.ID)
		}
	}
}

func TestRedTeamService_CategoryDistribution(t *testing.T) {
	corpus := redteam.Corpus()
	counts := make(map[redteam.AttackCategory]int)
	for _, p := range corpus {
		counts[p.Category]++
	}

	expected := map[redteam.AttackCategory]int{
		redteam.CategoryToolMisuse:        7,
		redteam.CategoryArgManipulation:   7,
		redteam.CategoryPromptInjDirect:   5,
		redteam.CategoryPromptInjIndirect: 5,
		redteam.CategoryPermEscalation:    4,
		redteam.CategoryMultiStep:         2,
	}

	for cat, exp := range expected {
		if counts[cat] != exp {
			t.Errorf("category %s: expected %d patterns, got %d", cat, exp, counts[cat])
		}
	}
}
