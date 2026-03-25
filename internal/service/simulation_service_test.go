package service

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

func newSimulationTestService(t *testing.T, rules []policy.Rule, records []audit.AuditRecord) *SimulationService {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create policy store with a single policy containing all rules.
	store := memory.NewPolicyStore()
	if len(rules) > 0 {
		p := &policy.Policy{
			ID:      "sim-test-policy",
			Name:    "Simulation Test",
			Enabled: true,
			Rules:   rules,
		}
		_ = store.SavePolicy(context.Background(), p)
	}

	policySvc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("failed to create policy service: %v", err)
	}

	readerFn := func(n int) []audit.AuditRecord {
		if n > len(records) {
			return records
		}
		return records[:n]
	}

	return NewSimulationService(policySvc, readerFn, logger)
}

func TestSimulate_NoRecords(t *testing.T) {
	svc := newSimulationTestService(t, nil, nil)

	result, err := svc.Simulate(context.Background(), SimulationRequest{
		StartTime:  time.Now().Add(-24 * time.Hour),
		EndTime:    time.Now(),
		MaxRecords: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalAnalyzed != 0 {
		t.Errorf("expected 0 analyzed, got %d", result.TotalAnalyzed)
	}
	if result.Changed != 0 {
		t.Errorf("expected 0 changed, got %d", result.Changed)
	}
}

func TestSimulate_NoChanges(t *testing.T) {
	// Policy: allow all. Audit records: all allowed. No change expected.
	rules := []policy.Rule{
		{ID: "allow-all", Name: "Allow All", Priority: 100, ToolMatch: "*",
			Condition: "true", Action: policy.ActionAllow},
	}
	records := []audit.AuditRecord{
		{Timestamp: time.Now().Add(-1 * time.Hour), ToolName: "read_file", Decision: "allow", IdentityID: "agent-1"},
		{Timestamp: time.Now().Add(-30 * time.Minute), ToolName: "write_file", Decision: "allow", IdentityID: "agent-1"},
	}

	svc := newSimulationTestService(t, rules, records)
	result, err := svc.Simulate(context.Background(), SimulationRequest{MaxRecords: 100})
	if err != nil {
		t.Fatal(err)
	}
	if result.TotalAnalyzed != 2 {
		t.Errorf("expected 2 analyzed, got %d", result.TotalAnalyzed)
	}
	if result.Changed != 0 {
		t.Errorf("expected 0 changed, got %d", result.Changed)
	}
	if result.Unchanged != 2 {
		t.Errorf("expected 2 unchanged, got %d", result.Unchanged)
	}
}

func TestSimulate_AllowToDeny(t *testing.T) {
	// Policy: deny write_file. Original audit: write_file was allowed.
	// Higher Priority number = evaluated first in SG's sort order.
	rules := []policy.Rule{
		{ID: "deny-write", Name: "Deny Write", Priority: 100, ToolMatch: "write_file",
			Condition: "true", Action: policy.ActionDeny},
		{ID: "allow-all", Name: "Allow All", Priority: 1, ToolMatch: "*",
			Condition: "true", Action: policy.ActionAllow},
	}
	records := []audit.AuditRecord{
		{Timestamp: time.Now().Add(-1 * time.Hour), ToolName: "read_file", Decision: "allow", IdentityID: "agent-1"},
		{Timestamp: time.Now().Add(-30 * time.Minute), ToolName: "write_file", Decision: "allow", IdentityID: "agent-2"},
		{Timestamp: time.Now().Add(-10 * time.Minute), ToolName: "write_file", Decision: "allow", IdentityID: "agent-1"},
	}

	svc := newSimulationTestService(t, rules, records)
	result, err := svc.Simulate(context.Background(), SimulationRequest{MaxRecords: 100})
	if err != nil {
		t.Fatal(err)
	}

	if result.TotalAnalyzed != 3 {
		t.Errorf("expected 3 analyzed, got %d", result.TotalAnalyzed)
	}
	if result.Changed != 2 {
		t.Errorf("expected 2 changed (write_file calls), got %d", result.Changed)
	}
	if result.AllowToDeny != 2 {
		t.Errorf("expected 2 allow->deny, got %d", result.AllowToDeny)
	}
	if result.DenyToAllow != 0 {
		t.Errorf("expected 0 deny->allow, got %d", result.DenyToAllow)
	}
	if result.Unchanged != 1 {
		t.Errorf("expected 1 unchanged (read_file), got %d", result.Unchanged)
	}

	// Check impacted agents.
	if len(result.ImpactedAgents) != 2 {
		t.Errorf("expected 2 impacted agents, got %d", len(result.ImpactedAgents))
	}
	// Check impacted tools.
	if len(result.ImpactedTools) != 1 || result.ImpactedTools[0] != "write_file" {
		t.Errorf("expected [write_file] impacted tool, got %v", result.ImpactedTools)
	}
}

func TestSimulate_DenyToAllow(t *testing.T) {
	// Policy: allow all. Original audit: write_file was denied.
	rules := []policy.Rule{
		{ID: "allow-all", Name: "Allow All", Priority: 100, ToolMatch: "*",
			Condition: "true", Action: policy.ActionAllow},
	}
	records := []audit.AuditRecord{
		{Timestamp: time.Now().Add(-1 * time.Hour), ToolName: "write_file", Decision: "deny", IdentityID: "agent-1"},
	}

	svc := newSimulationTestService(t, rules, records)
	result, err := svc.Simulate(context.Background(), SimulationRequest{MaxRecords: 100})
	if err != nil {
		t.Fatal(err)
	}

	if result.Changed != 1 {
		t.Errorf("expected 1 changed, got %d", result.Changed)
	}
	if result.DenyToAllow != 1 {
		t.Errorf("expected 1 deny->allow, got %d", result.DenyToAllow)
	}
	if result.AllowToDeny != 0 {
		t.Errorf("expected 0 allow->deny, got %d", result.AllowToDeny)
	}
}

func TestSimulate_Details(t *testing.T) {
	rules := []policy.Rule{
		{ID: "deny-bash", Name: "Deny Bash", Priority: 100, ToolMatch: "bash",
			Condition: "true", Action: policy.ActionDeny},
		{ID: "allow-all", Name: "Allow All", Priority: 1, ToolMatch: "*",
			Condition: "true", Action: policy.ActionAllow},
	}
	records := []audit.AuditRecord{
		{Timestamp: time.Now(), ToolName: "bash", Decision: "allow", IdentityID: "test-agent"},
	}

	svc := newSimulationTestService(t, rules, records)
	result, err := svc.Simulate(context.Background(), SimulationRequest{MaxRecords: 100})
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Details) != 1 {
		t.Fatalf("expected 1 detail, got %d", len(result.Details))
	}

	d := result.Details[0]
	if d.ToolName != "bash" {
		t.Errorf("expected tool bash, got %s", d.ToolName)
	}
	if d.OriginalDecision != "allow" {
		t.Errorf("expected original decision allow, got %s", d.OriginalDecision)
	}
	if d.NewDecision != "deny" {
		t.Errorf("expected new decision deny, got %s", d.NewDecision)
	}
	if d.NewRuleID != "deny-bash" {
		t.Errorf("expected new rule deny-bash, got %s", d.NewRuleID)
	}
	if d.IdentityID != "test-agent" {
		t.Errorf("expected identity test-agent, got %s", d.IdentityID)
	}
}

func TestSimulate_MaxRecordsDefault(t *testing.T) {
	rules := []policy.Rule{
		{ID: "allow-all", Name: "Allow All", Priority: 100, ToolMatch: "*",
			Condition: "true", Action: policy.ActionAllow},
	}

	// Create 2000 records.
	records := make([]audit.AuditRecord, 2000)
	for i := range records {
		records[i] = audit.AuditRecord{
			Timestamp:  time.Now().Add(-time.Duration(i) * time.Minute),
			ToolName:   "read_file",
			Decision:   "allow",
			IdentityID: "agent-1",
		}
	}

	svc := newSimulationTestService(t, rules, records)
	result, err := svc.Simulate(context.Background(), SimulationRequest{})
	if err != nil {
		t.Fatal(err)
	}

	// Default limit is 1000.
	if result.TotalAnalyzed != 1000 {
		t.Errorf("expected 1000 analyzed (default limit), got %d", result.TotalAnalyzed)
	}
}

func TestSimulate_SkipsEmptyToolName(t *testing.T) {
	rules := []policy.Rule{
		{ID: "allow-all", Name: "Allow All", Priority: 100, ToolMatch: "*",
			Condition: "true", Action: policy.ActionAllow},
	}
	records := []audit.AuditRecord{
		{Timestamp: time.Now(), ToolName: "", Decision: "allow", IdentityID: "agent-1"},
		{Timestamp: time.Now(), ToolName: "read_file", Decision: "allow", IdentityID: "agent-1"},
	}

	svc := newSimulationTestService(t, rules, records)
	result, err := svc.Simulate(context.Background(), SimulationRequest{MaxRecords: 100})
	if err != nil {
		t.Fatal(err)
	}

	if result.TotalAnalyzed != 1 {
		t.Errorf("expected 1 analyzed (skipping empty tool), got %d", result.TotalAnalyzed)
	}
}

func TestSimulate_DetailsLimitedTo100(t *testing.T) {
	rules := []policy.Rule{
		{ID: "deny-all", Name: "Deny All", Priority: 1, ToolMatch: "*",
			Condition: "true", Action: policy.ActionDeny},
	}

	// 200 records all originally allowed -> all will change to deny.
	records := make([]audit.AuditRecord, 200)
	for i := range records {
		records[i] = audit.AuditRecord{
			Timestamp:  time.Now().Add(-time.Duration(i) * time.Minute),
			ToolName:   "read_file",
			Decision:   "allow",
			IdentityID: "agent-1",
		}
	}

	svc := newSimulationTestService(t, rules, records)
	result, err := svc.Simulate(context.Background(), SimulationRequest{MaxRecords: 200})
	if err != nil {
		t.Fatal(err)
	}

	if result.Changed != 200 {
		t.Errorf("expected 200 changed, got %d", result.Changed)
	}
	if len(result.Details) != 100 {
		t.Errorf("expected details limited to 100, got %d", len(result.Details))
	}
}

func TestSimulate_DurationReported(t *testing.T) {
	svc := newSimulationTestService(t, nil, nil)
	result, err := svc.Simulate(context.Background(), SimulationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if result.DurationMs < 0 {
		t.Errorf("duration should not be negative: %d", result.DurationMs)
	}
}

func TestSimulate_MixedChanges(t *testing.T) {
	// Policy: deny write, allow read. Mix of changes.
	rules := []policy.Rule{
		{ID: "deny-write", Name: "Deny Write", Priority: 100, ToolMatch: "write_file",
			Condition: "true", Action: policy.ActionDeny},
		{ID: "allow-all", Name: "Allow All", Priority: 1, ToolMatch: "*",
			Condition: "true", Action: policy.ActionAllow},
	}
	records := []audit.AuditRecord{
		{Timestamp: time.Now(), ToolName: "read_file", Decision: "allow", IdentityID: "a1"},   // unchanged
		{Timestamp: time.Now(), ToolName: "write_file", Decision: "allow", IdentityID: "a2"},  // allow->deny
		{Timestamp: time.Now(), ToolName: "read_file", Decision: "deny", IdentityID: "a1"},    // deny->allow
		{Timestamp: time.Now(), ToolName: "write_file", Decision: "deny", IdentityID: "a3"},   // unchanged (still deny)
	}

	svc := newSimulationTestService(t, rules, records)
	result, err := svc.Simulate(context.Background(), SimulationRequest{MaxRecords: 100})
	if err != nil {
		t.Fatal(err)
	}

	if result.TotalAnalyzed != 4 {
		t.Errorf("expected 4 analyzed, got %d", result.TotalAnalyzed)
	}
	if result.Changed != 2 {
		t.Errorf("expected 2 changed, got %d", result.Changed)
	}
	if result.AllowToDeny != 1 {
		t.Errorf("expected 1 allow->deny, got %d", result.AllowToDeny)
	}
	if result.DenyToAllow != 1 {
		t.Errorf("expected 1 deny->allow, got %d", result.DenyToAllow)
	}
	if result.Unchanged != 2 {
		t.Errorf("expected 2 unchanged, got %d", result.Unchanged)
	}
}
