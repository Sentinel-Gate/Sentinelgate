package service

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// --- test helpers ---

type mockPHAuditReader struct {
	mu      sync.Mutex
	records []audit.AuditRecord
}

func (m *mockPHAuditReader) Query(_ context.Context, filter audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
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

type mockToolLister struct {
	tools []string
}

func (m *mockToolLister) GetAllToolNames() []string {
	return m.tools
}

type mockIdentityLister struct {
	identities []IdentityInfo
}

func (m *mockIdentityLister) GetAllIdentities() []IdentityInfo {
	return m.identities
}

type mockPolicyEvaluator struct {
	// allowedTools per identity — if identity not in map, all tools allowed
	allowedTools map[string]map[string]bool
}

func (m *mockPolicyEvaluator) Evaluate(_ context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
	if m.allowedTools == nil {
		return policy.Decision{Allowed: true, Reason: "default allow"}, nil
	}
	tools, ok := m.allowedTools[evalCtx.IdentityID]
	if !ok {
		return policy.Decision{Allowed: true, Reason: "default allow"}, nil
	}
	if tools[evalCtx.ToolName] {
		return policy.Decision{Allowed: true, Reason: "allowed"}, nil
	}
	return policy.Decision{Allowed: false, Reason: "denied"}, nil
}

func newTestPHService(reader *mockPHAuditReader, tools []string, identities []IdentityInfo, evaluator *mockPolicyEvaluator) *PermissionHealthService {
	return NewPermissionHealthService(
		reader,
		&mockToolLister{tools: tools},
		&mockIdentityLister{identities: identities},
		evaluator,
		slog.Default(),
	)
}

// --- tests ---

func TestBuildUsageProfile_Empty(t *testing.T) {
	svc := newTestPHService(
		&mockPHAuditReader{},
		[]string{"read_file", "write_file"},
		[]IdentityInfo{{ID: "agent-1", Name: "Agent 1", Roles: []string{"user"}}},
		&mockPolicyEvaluator{},
	)

	profile, err := svc.BuildUsageProfile(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile.TotalCalls != 0 {
		t.Errorf("expected 0 calls, got %d", profile.TotalCalls)
	}
	if len(profile.ToolUsage) != 0 {
		t.Errorf("expected empty tool usage, got %d", len(profile.ToolUsage))
	}
}

func TestBuildUsageProfile_Basic(t *testing.T) {
	now := time.Now()
	reader := &mockPHAuditReader{
		records: []audit.AuditRecord{
			{IdentityID: "agent-1", ToolName: "read_file", Timestamp: now.Add(-1 * time.Hour), ToolArguments: map[string]interface{}{"path": "/tmp"}},
			{IdentityID: "agent-1", ToolName: "read_file", Timestamp: now.Add(-2 * time.Hour), ToolArguments: map[string]interface{}{"path": "/etc"}},
			{IdentityID: "agent-1", ToolName: "write_file", Timestamp: now.Add(-3 * time.Hour), ToolArguments: map[string]interface{}{"path": "/tmp", "content": "x"}},
		},
	}
	svc := newTestPHService(reader, nil, nil, &mockPolicyEvaluator{})

	profile, err := svc.BuildUsageProfile(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if profile.TotalCalls != 3 {
		t.Errorf("expected 3 calls, got %d", profile.TotalCalls)
	}
	if profile.ToolUsage["read_file"].CallCount != 2 {
		t.Errorf("expected read_file=2, got %d", profile.ToolUsage["read_file"].CallCount)
	}
	if profile.ToolUsage["write_file"].CallCount != 1 {
		t.Errorf("expected write_file=1, got %d", profile.ToolUsage["write_file"].CallCount)
	}
}

func TestBuildUsageProfile_ArgKeys(t *testing.T) {
	now := time.Now()
	reader := &mockPHAuditReader{
		records: []audit.AuditRecord{
			{IdentityID: "a1", ToolName: "query_db", Timestamp: now, ToolArguments: map[string]interface{}{"sql": "select", "db": "main"}},
			{IdentityID: "a1", ToolName: "query_db", Timestamp: now, ToolArguments: map[string]interface{}{"sql": "insert"}},
		},
	}
	svc := newTestPHService(reader, nil, nil, &mockPolicyEvaluator{})
	profile, err := svc.BuildUsageProfile(context.Background(), "a1")
	if err != nil {
		t.Fatal(err)
	}
	info := profile.ToolUsage["query_db"]
	if info.ArgKeys["sql"] != 2 {
		t.Errorf("expected sql=2, got %d", info.ArgKeys["sql"])
	}
	if info.ArgKeys["db"] != 1 {
		t.Errorf("expected db=1, got %d", info.ArgKeys["db"])
	}
}

func TestGetPermittedTools(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		allowedTools: map[string]map[string]bool{
			"agent-1": {"read_file": true, "write_file": true, "delete_file": false},
		},
	}
	svc := newTestPHService(nil, []string{"read_file", "write_file", "delete_file"}, nil, evaluator)

	permitted, err := svc.GetPermittedTools(context.Background(), "agent-1", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	if len(permitted) != 2 {
		t.Errorf("expected 2 permitted, got %d", len(permitted))
	}
	if !permitted["read_file"] || !permitted["write_file"] {
		t.Errorf("expected read_file and write_file to be permitted")
	}
}

func TestAnalyzePermissionGaps_NeverUsed(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		allowedTools: map[string]map[string]bool{
			"agent-1": {"read_file": true, "write_file": true, "exec_cmd": true},
		},
	}
	svc := newTestPHService(nil, []string{"read_file", "write_file", "exec_cmd"}, nil, evaluator)

	usageProfile := &UsageProfile{
		IdentityID: "agent-1",
		ToolUsage: map[string]*ToolUsageInfo{
			"read_file": {CallCount: 10},
		},
	}

	gaps, err := svc.AnalyzePermissionGaps(context.Background(), "agent-1", []string{"user"}, usageProfile)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 2 {
		t.Fatalf("expected 2 gaps, got %d", len(gaps))
	}
	// Should be sorted: never_used first
	for _, g := range gaps {
		if g.GapType != GapNeverUsed {
			t.Errorf("expected never_used, got %s for %s", g.GapType, g.ToolName)
		}
	}
}

func TestAnalyzePermissionGaps_RarelyUsed(t *testing.T) {
	now := time.Now()
	evaluator := &mockPolicyEvaluator{
		allowedTools: map[string]map[string]bool{
			"agent-1": {"read_file": true, "write_file": true},
		},
	}
	svc := newTestPHService(nil, []string{"read_file", "write_file"}, nil, evaluator)

	usageProfile := &UsageProfile{
		IdentityID: "agent-1",
		ToolUsage: map[string]*ToolUsageInfo{
			"read_file":  {CallCount: 50, LastUsed: now},
			"write_file": {CallCount: 1, LastUsed: now.Add(-10 * 24 * time.Hour)},
		},
	}

	gaps, err := svc.AnalyzePermissionGaps(context.Background(), "agent-1", []string{"user"}, usageProfile)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(gaps))
	}
	if gaps[0].GapType != GapRarelyUsed {
		t.Errorf("expected rarely_used, got %s", gaps[0].GapType)
	}
	if gaps[0].ToolName != "write_file" {
		t.Errorf("expected write_file, got %s", gaps[0].ToolName)
	}
}

func TestAnalyzePermissionGaps_Whitelist(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		allowedTools: map[string]map[string]bool{
			"agent-1": {"read_file": true, "health_check": true},
		},
	}
	svc := newTestPHService(nil, []string{"read_file", "health_check"}, nil, evaluator)
	svc.SetConfig(PermissionHealthConfig{
		Mode:           ShadowModeShadow,
		LearningDays:   14,
		WhitelistTools: []string{"health_check"},
	})

	usageProfile := &UsageProfile{
		IdentityID: "agent-1",
		ToolUsage:  map[string]*ToolUsageInfo{},
	}

	gaps, err := svc.AnalyzePermissionGaps(context.Background(), "agent-1", []string{"user"}, usageProfile)
	if err != nil {
		t.Fatal(err)
	}
	// health_check should be excluded by whitelist
	if len(gaps) != 1 {
		t.Fatalf("expected 1 gap (health_check whitelisted), got %d", len(gaps))
	}
	if gaps[0].ToolName == "health_check" {
		t.Error("health_check should be whitelisted")
	}
}

func TestAnalyzePermissionGaps_TemporalExcess(t *testing.T) {
	evaluator := &mockPolicyEvaluator{
		allowedTools: map[string]map[string]bool{
			"agent-1": {"deploy": true},
		},
	}
	svc := newTestPHService(nil, []string{"deploy"}, nil, evaluator)

	// deploy used 10 times but only during hour 10 and 11
	hourly := [24]int{}
	hourly[10] = 5
	hourly[11] = 5
	usageProfile := &UsageProfile{
		IdentityID: "agent-1",
		ToolUsage: map[string]*ToolUsageInfo{
			"deploy": {CallCount: 10, LastUsed: time.Now(), HourlyUsage: hourly},
		},
	}

	gaps, err := svc.AnalyzePermissionGaps(context.Background(), "agent-1", []string{"user"}, usageProfile)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(gaps))
	}
	if gaps[0].GapType != GapTemporalExcess {
		t.Errorf("expected temporal_excess, got %s", gaps[0].GapType)
	}
}

func TestGenerateSuggestions_NeverUsed(t *testing.T) {
	svc := newTestPHService(nil, nil, nil, &mockPolicyEvaluator{})

	gaps := []PermissionGap{
		{ToolName: "exec_cmd", GapType: GapNeverUsed, DaysUnused: 14},
	}
	suggestions := svc.GenerateSuggestions("agent-1", "test-agent", gaps)
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
	if suggestions[0].Action != "deny" {
		t.Errorf("expected deny, got %s", suggestions[0].Action)
	}
	if suggestions[0].ToolPattern != "exec_cmd" {
		t.Errorf("expected exec_cmd pattern, got %s", suggestions[0].ToolPattern)
	}
	// Verify suggestion uses identity_name, not UUID
	if suggestions[0].Condition != `identity_name == "test-agent"` {
		t.Errorf("expected identity_name condition, got %s", suggestions[0].Condition)
	}
	// Verify RuleName uses the identity name
	expectedRuleName := "auto-tighten-test-agent-exec_cmd"
	if suggestions[0].RuleName != expectedRuleName {
		t.Errorf("expected RuleName %q, got %q", expectedRuleName, suggestions[0].RuleName)
	}
}

func TestGenerateSuggestions_TemporalRestriction(t *testing.T) {
	svc := newTestPHService(nil, nil, nil, &mockPolicyEvaluator{})

	gaps := []PermissionGap{
		{ToolName: "deploy", GapType: GapTemporalExcess, CallCount: 10},
	}
	suggestions := svc.GenerateSuggestions("agent-1", "test-agent", gaps)
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
	// Verify exact condition with identity_name and temporal restriction
	expectedCond := `identity_name == "test-agent" && !(request_hour >= 9 && request_hour <= 17)`
	if suggestions[0].Condition != expectedCond {
		t.Errorf("expected condition %q, got %q", expectedCond, suggestions[0].Condition)
	}
	expectedRuleName := "temporal-restrict-test-agent-deploy"
	if suggestions[0].RuleName != expectedRuleName {
		t.Errorf("expected RuleName %q, got %q", expectedRuleName, suggestions[0].RuleName)
	}
}

func TestGenerateSuggestions_EmptyNameFallback(t *testing.T) {
	svc := newTestPHService(nil, nil, nil, &mockPolicyEvaluator{})

	gaps := []PermissionGap{
		{ToolName: "exec_cmd", GapType: GapNeverUsed, DaysUnused: 14},
	}
	// Empty identityName — should fall back to identity_id in both Condition and RuleName
	suggestions := svc.GenerateSuggestions("abc-123-uuid", "", gaps)
	if len(suggestions) != 1 {
		t.Fatalf("expected 1 suggestion, got %d", len(suggestions))
	}
	expectedCond := `identity_id == "abc-123-uuid"`
	if suggestions[0].Condition != expectedCond {
		t.Errorf("expected fallback condition %q, got %q", expectedCond, suggestions[0].Condition)
	}
	expectedRuleName := "auto-tighten-abc-123-uuid-exec_cmd"
	if suggestions[0].RuleName != expectedRuleName {
		t.Errorf("expected fallback RuleName %q, got %q", expectedRuleName, suggestions[0].RuleName)
	}
}

func TestComputeHealthReport_Disabled(t *testing.T) {
	svc := newTestPHService(nil, nil, nil, &mockPolicyEvaluator{})
	svc.SetConfig(PermissionHealthConfig{Mode: ShadowModeDisabled})

	_, err := svc.ComputeHealthReport(context.Background(), "agent-1")
	if err == nil {
		t.Error("expected error when disabled")
	}
}

func TestComputeHealthReport_Full(t *testing.T) {
	now := time.Now()
	// read_file: 10 calls (active), search: 5 calls (active)
	// write_file: 0 calls, exec_cmd: 0 calls → 2 never_used gaps
	var records []audit.AuditRecord
	for i := 0; i < 10; i++ {
		records = append(records, audit.AuditRecord{
			IdentityID: "agent-1", ToolName: "read_file",
			Timestamp: now.Add(-time.Duration(i) * time.Hour), Decision: "allow",
		})
	}
	for i := 0; i < 5; i++ {
		records = append(records, audit.AuditRecord{
			IdentityID: "agent-1", ToolName: "search",
			Timestamp: now.Add(-time.Duration(i) * time.Hour), Decision: "allow",
		})
	}
	reader := &mockPHAuditReader{records: records}
	evaluator := &mockPolicyEvaluator{
		allowedTools: map[string]map[string]bool{
			"agent-1": {"read_file": true, "search": true, "write_file": true, "exec_cmd": true},
		},
	}
	identities := []IdentityInfo{{ID: "agent-1", Name: "Agent 1", Roles: []string{"user"}}}
	svc := newTestPHService(reader, []string{"read_file", "search", "write_file", "exec_cmd"}, identities, evaluator)

	report, err := svc.ComputeHealthReport(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.PermittedTools != 4 {
		t.Errorf("expected 4 permitted, got %d", report.PermittedTools)
	}
	if report.UsedTools != 2 {
		t.Errorf("expected 2 used, got %d", report.UsedTools)
	}
	// Score = 2/4 * 100 = 50
	if report.LeastPrivScore != 50 {
		t.Errorf("expected score 50, got %.1f", report.LeastPrivScore)
	}
	if len(report.Gaps) != 2 {
		t.Errorf("expected 2 gaps (never_used), got %d", len(report.Gaps))
	}
}

func TestComputeHealthReport_Cache(t *testing.T) {
	now := time.Now()
	reader := &mockPHAuditReader{
		records: []audit.AuditRecord{
			{IdentityID: "agent-1", ToolName: "read_file", Timestamp: now, Decision: "allow"},
		},
	}
	evaluator := &mockPolicyEvaluator{}
	identities := []IdentityInfo{{ID: "agent-1", Name: "Agent 1", Roles: []string{"user"}}}
	svc := newTestPHService(reader, []string{"read_file"}, identities, evaluator)

	r1, err := svc.ComputeHealthReport(context.Background(), "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := svc.ComputeHealthReport(context.Background(), "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	// Should be same cached instance
	if r1 != r2 {
		t.Error("expected cached report to be returned")
	}
}

func TestComputeHealthReport_IdentityNotFound(t *testing.T) {
	svc := newTestPHService(
		&mockPHAuditReader{},
		nil,
		[]IdentityInfo{}, // no identities
		&mockPolicyEvaluator{},
	)
	_, err := svc.ComputeHealthReport(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for missing identity")
	}
}

func TestGetAllHealthReports(t *testing.T) {
	now := time.Now()
	reader := &mockPHAuditReader{
		records: []audit.AuditRecord{
			{IdentityID: "a1", ToolName: "read_file", Timestamp: now, Decision: "allow"},
			{IdentityID: "a2", ToolName: "search", Timestamp: now, Decision: "allow"},
		},
	}
	evaluator := &mockPolicyEvaluator{}
	identities := []IdentityInfo{
		{ID: "a1", Name: "Agent 1", Roles: []string{"user"}},
		{ID: "a2", Name: "Agent 2", Roles: []string{"admin"}},
	}
	svc := newTestPHService(reader, []string{"read_file", "search"}, identities, evaluator)

	reports, err := svc.GetAllHealthReports(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(reports))
	}
}

func TestApplySuggestions_Disabled(t *testing.T) {
	svc := newTestPHService(nil, nil, nil, &mockPolicyEvaluator{})
	svc.SetConfig(PermissionHealthConfig{Mode: ShadowModeDisabled})

	_, err := svc.ApplySuggestions(context.Background(), "agent-1", []string{"s1"})
	if err == nil {
		t.Error("expected error when disabled")
	}
}

func TestApplySuggestions_EmitsEvent(t *testing.T) {
	now := time.Now()
	reader := &mockPHAuditReader{
		records: []audit.AuditRecord{
			{IdentityID: "agent-1", ToolName: "read_file", Timestamp: now, Decision: "allow"},
		},
	}
	evaluator := &mockPolicyEvaluator{
		allowedTools: map[string]map[string]bool{
			"agent-1": {"read_file": true, "exec_cmd": true},
		},
	}
	identities := []IdentityInfo{{ID: "agent-1", Name: "Agent 1", Roles: []string{"user"}}}
	svc := newTestPHService(reader, []string{"read_file", "exec_cmd"}, identities, evaluator)

	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()
	svc.SetEventBus(bus)

	// First compute report to get suggestions
	report, err := svc.ComputeHealthReport(context.Background(), "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Suggestions) == 0 {
		t.Fatal("expected at least 1 suggestion")
	}

	var mu sync.Mutex
	var received []event.Event
	bus.Subscribe("permissions.auto_tighten_applied", func(_ context.Context, e event.Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	applied, err := svc.ApplySuggestions(context.Background(), "agent-1", []string{report.Suggestions[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Errorf("expected 1 applied, got %d", applied)
	}

	// Wait briefly for async event dispatch
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Error("expected auto_tighten_applied event")
	}
}

func TestConfigSetGet(t *testing.T) {
	svc := newTestPHService(nil, nil, nil, &mockPolicyEvaluator{})

	defaultCfg := svc.Config()
	if defaultCfg.Mode != ShadowModeShadow {
		t.Errorf("expected default mode shadow, got %s", defaultCfg.Mode)
	}

	svc.SetConfig(PermissionHealthConfig{
		Mode:           ShadowModeAuto,
		LearningDays:   7,
		GracePeriodDays: 3,
		WhitelistTools: []string{"auth_check"},
	})

	newCfg := svc.Config()
	if newCfg.Mode != ShadowModeAuto {
		t.Errorf("expected auto, got %s", newCfg.Mode)
	}
	if newCfg.LearningDays != 7 {
		t.Errorf("expected 7, got %d", newCfg.LearningDays)
	}
}

func TestLeastPrivilegeScore_AllUsed(t *testing.T) {
	now := time.Now()
	// Both tools used 5+ times → no gaps
	var records []audit.AuditRecord
	for i := 0; i < 5; i++ {
		records = append(records,
			audit.AuditRecord{IdentityID: "a1", ToolName: "read_file", Timestamp: now.Add(-time.Duration(i) * time.Hour), Decision: "allow"},
			audit.AuditRecord{IdentityID: "a1", ToolName: "write_file", Timestamp: now.Add(-time.Duration(i) * time.Hour), Decision: "allow"},
		)
	}
	reader := &mockPHAuditReader{records: records}
	evaluator := &mockPolicyEvaluator{
		allowedTools: map[string]map[string]bool{
			"a1": {"read_file": true, "write_file": true},
		},
	}
	identities := []IdentityInfo{{ID: "a1", Name: "A1", Roles: []string{"user"}}}
	svc := newTestPHService(reader, []string{"read_file", "write_file"}, identities, evaluator)

	report, err := svc.ComputeHealthReport(context.Background(), "a1")
	if err != nil {
		t.Fatal(err)
	}
	if report.LeastPrivScore != 100 {
		t.Errorf("expected 100 (all used), got %.1f", report.LeastPrivScore)
	}
	if len(report.Gaps) != 0 {
		t.Errorf("expected 0 gaps, got %d", len(report.Gaps))
	}
}

// TestLeastPrivilegeScore_LessThan100WithGaps verifies that the score drops
// below 100 when there are permission gaps (permitted but never used tools).
func TestLeastPrivilegeScore_LessThan100WithGaps(t *testing.T) {
	now := time.Now()
	// Only read_file used, write_file never used → 1 gap out of 2 permitted
	var records []audit.AuditRecord
	for i := 0; i < 5; i++ {
		records = append(records,
			audit.AuditRecord{IdentityID: "a1", ToolName: "read_file", Timestamp: now.Add(-time.Duration(i) * time.Hour), Decision: "allow"},
		)
	}
	reader := &mockPHAuditReader{records: records}
	evaluator := &mockPolicyEvaluator{
		allowedTools: map[string]map[string]bool{
			"a1": {"read_file": true, "write_file": true},
		},
	}
	identities := []IdentityInfo{{ID: "a1", Name: "A1", Roles: []string{"user"}}}
	svc := newTestPHService(reader, []string{"read_file", "write_file"}, identities, evaluator)

	report, err := svc.ComputeHealthReport(context.Background(), "a1")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Gaps) == 0 {
		t.Fatal("expected at least 1 gap (write_file never used)")
	}
	if report.LeastPrivScore >= 100 {
		t.Errorf("expected score < 100 when gaps exist, got %.1f", report.LeastPrivScore)
	}
	// Score should be 50%: 1 used out of 2 permitted = (2-1)/2 * 100 = 50
	if report.LeastPrivScore != 50 {
		t.Errorf("expected score 50 (1 gap out of 2 permitted), got %.1f", report.LeastPrivScore)
	}
}

func TestGapEventEmission_SuggestMode(t *testing.T) {
	now := time.Now()
	reader := &mockPHAuditReader{
		records: []audit.AuditRecord{
			{IdentityID: "a1", ToolName: "read_file", Timestamp: now, Decision: "allow"},
		},
	}
	evaluator := &mockPolicyEvaluator{
		allowedTools: map[string]map[string]bool{
			"a1": {"read_file": true, "exec_cmd": true, "delete_db": true},
		},
	}
	identities := []IdentityInfo{{ID: "a1", Name: "A1", Roles: []string{"user"}}}
	svc := newTestPHService(reader, []string{"read_file", "exec_cmd", "delete_db"}, identities, evaluator)
	svc.SetConfig(PermissionHealthConfig{
		Mode:         ShadowModeSuggest,
		LearningDays: 14,
	})

	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()
	svc.SetEventBus(bus)

	var mu sync.Mutex
	var received []event.Event
	bus.Subscribe("permissions.gap_detected", func(_ context.Context, e event.Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	_, err := svc.ComputeHealthReport(context.Background(), "a1")
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Error("expected gap_detected event in suggest mode")
	}
	p, ok := received[0].Payload.(map[string]interface{})
	if !ok {
		t.Fatal("expected map payload")
	}
	if p["identity_id"] != "a1" {
		t.Errorf("expected identity_id a1, got %v", p["identity_id"])
	}
}

func TestShadowMode_NoEventInShadowMode(t *testing.T) {
	now := time.Now()
	reader := &mockPHAuditReader{
		records: []audit.AuditRecord{
			{IdentityID: "a1", ToolName: "read_file", Timestamp: now, Decision: "allow"},
		},
	}
	evaluator := &mockPolicyEvaluator{
		allowedTools: map[string]map[string]bool{
			"a1": {"read_file": true, "exec_cmd": true},
		},
	}
	identities := []IdentityInfo{{ID: "a1", Name: "A1", Roles: []string{"user"}}}
	svc := newTestPHService(reader, []string{"read_file", "exec_cmd"}, identities, evaluator)
	svc.SetConfig(PermissionHealthConfig{
		Mode:         ShadowModeShadow,
		LearningDays: 14,
	})

	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()
	svc.SetEventBus(bus)

	var mu sync.Mutex
	var received []event.Event
	bus.Subscribe("permissions.gap_detected", func(_ context.Context, e event.Event) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
	})

	_, err := svc.ComputeHealthReport(context.Background(), "a1")
	if err != nil {
		t.Fatal(err)
	}

	// Shadow mode should NOT emit gap_detected events
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(received) > 0 {
		t.Error("should NOT emit gap_detected in shadow mode")
	}
}

func TestConcurrentHealthReports(t *testing.T) {
	now := time.Now()
	reader := &mockPHAuditReader{
		records: []audit.AuditRecord{
			{IdentityID: "a1", ToolName: "read_file", Timestamp: now, Decision: "allow"},
		},
	}
	evaluator := &mockPolicyEvaluator{}
	identities := []IdentityInfo{{ID: "a1", Name: "A1", Roles: []string{"user"}}}
	svc := newTestPHService(reader, []string{"read_file"}, identities, evaluator)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.ComputeHealthReport(context.Background(), "a1")
		}()
	}
	wg.Wait()
}
