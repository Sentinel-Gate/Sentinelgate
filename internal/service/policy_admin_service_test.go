package service

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// testPolicyAdminEnv sets up a fresh PolicyAdminService with in-memory store,
// a temporary state file, and a real PolicyService for each test.
func testPolicyAdminEnv(t *testing.T) (*PolicyAdminService, *PolicyService, *mockPolicyStore, string) {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)

	// Initialize the state file with defaults so Save/Load work.
	defaultState := stateStore.DefaultState()
	if err := stateStore.Save(defaultState); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	// Create a store with a default policy already seeded.
	defaultPolicy := DefaultPolicy()
	defaultPolicy.ID = "default-policy-id"
	for i := range defaultPolicy.Rules {
		defaultPolicy.Rules[i].ID = defaultPolicy.Rules[i].Name
	}
	store := newMockPolicyStore(*defaultPolicy)

	// Create the real PolicyService (needed for Reload).
	policySvc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService: %v", err)
	}

	adminSvc := NewPolicyAdminService(store, stateStore, policySvc, logger)
	return adminSvc, policySvc, store, statePath
}

// --- Create Tests ---

func TestPolicyAdminService_Create(t *testing.T) {
	svc, _, _, _ := testPolicyAdminEnv(t)
	ctx := context.Background()

	p := &policy.Policy{
		Name:        "Custom Policy",
		Description: "Test policy for custom rules",
		Priority:    10,
		Rules: []policy.Rule{
			{
				Name:      "allow-read",
				Priority:  100,
				ToolMatch: "read_*",
				Condition: "true",
				Action:    policy.ActionAllow,
			},
		},
	}

	created, err := svc.Create(ctx, p)
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	// Must have generated a UUID.
	if created.ID == "" {
		t.Error("Create() did not generate an ID")
	}

	// Must have set Enabled to true.
	if !created.Enabled {
		t.Error("Create() should default to Enabled=true")
	}

	// Must have set timestamps.
	if created.CreatedAt.IsZero() {
		t.Error("Create() did not set CreatedAt")
	}
	if created.UpdatedAt.IsZero() {
		t.Error("Create() did not set UpdatedAt")
	}

	// Must have generated IDs for rules.
	if len(created.Rules) != 1 {
		t.Fatalf("Create() rules count = %d, want 1", len(created.Rules))
	}
	if created.Rules[0].ID == "" {
		t.Error("Create() did not generate rule ID")
	}

	// Must preserve fields.
	if created.Name != "Custom Policy" {
		t.Errorf("Create() Name = %q, want %q", created.Name, "Custom Policy")
	}
	if created.Description != "Test policy for custom rules" {
		t.Errorf("Create() Description = %q, want %q", created.Description, "Test policy for custom rules")
	}
}

func TestPolicyAdminService_Create_EmptyName(t *testing.T) {
	svc, _, _, _ := testPolicyAdminEnv(t)
	ctx := context.Background()

	p := &policy.Policy{
		Name: "",
	}

	_, err := svc.Create(ctx, p)
	if err == nil {
		t.Fatal("Create() empty name should return error")
	}
}

func TestPolicyAdminService_Create_WithMultipleRules(t *testing.T) {
	svc, _, _, _ := testPolicyAdminEnv(t)
	ctx := context.Background()

	p := &policy.Policy{
		Name: "Multi-rule Policy",
		Rules: []policy.Rule{
			{Name: "rule-1", Priority: 100, ToolMatch: "read_*", Condition: "true", Action: policy.ActionAllow},
			{Name: "rule-2", Priority: 50, ToolMatch: "write_*", Condition: "true", Action: policy.ActionDeny},
		},
	}

	created, err := svc.Create(ctx, p)
	if err != nil {
		t.Fatalf("Create() unexpected error: %v", err)
	}

	if len(created.Rules) != 2 {
		t.Fatalf("Create() rules count = %d, want 2", len(created.Rules))
	}

	// Both rules must have IDs.
	for i, r := range created.Rules {
		if r.ID == "" {
			t.Errorf("Create() rule %d did not get an ID", i)
		}
	}
}

// --- Update Tests ---

func TestPolicyAdminService_Update(t *testing.T) {
	svc, _, _, _ := testPolicyAdminEnv(t)
	ctx := context.Background()

	// Create a policy first.
	p := &policy.Policy{
		Name:    "Original",
		Enabled: true,
		Rules: []policy.Rule{
			{Name: "rule-1", Priority: 100, ToolMatch: "*", Condition: "true", Action: policy.ActionAllow},
		},
	}
	created, err := svc.Create(ctx, p)
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}

	// Update the policy.
	update := &policy.Policy{
		Name:        "Updated",
		Description: "Updated description",
		Enabled:     true,
		Rules: []policy.Rule{
			{Name: "new-rule", Priority: 200, ToolMatch: "read_*", Condition: "true", Action: policy.ActionAllow},
		},
	}

	updated, err := svc.Update(ctx, created.ID, update)
	if err != nil {
		t.Fatalf("Update() unexpected error: %v", err)
	}

	if updated.Name != "Updated" {
		t.Errorf("Update() Name = %q, want %q", updated.Name, "Updated")
	}
	if updated.Description != "Updated description" {
		t.Errorf("Update() Description = %q, want %q", updated.Description, "Updated description")
	}

	// CreatedAt must be preserved.
	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Error("Update() changed CreatedAt (should be immutable)")
	}

	// UpdatedAt must advance.
	if !updated.UpdatedAt.After(created.UpdatedAt) && !updated.UpdatedAt.Equal(created.UpdatedAt) {
		t.Error("Update() should advance UpdatedAt")
	}
}

func TestPolicyAdminService_Update_NotFound(t *testing.T) {
	svc, _, _, _ := testPolicyAdminEnv(t)
	ctx := context.Background()

	update := &policy.Policy{Name: "Ghost"}
	_, err := svc.Update(ctx, "nonexistent-id", update)
	if err == nil {
		t.Fatal("Update() nonexistent should return error")
	}
}

// --- Delete Tests ---

func TestPolicyAdminService_Delete(t *testing.T) {
	svc, _, _, _ := testPolicyAdminEnv(t)
	ctx := context.Background()

	// Create a non-default policy.
	p := &policy.Policy{
		Name:    "Deletable",
		Enabled: true,
		Rules: []policy.Rule{
			{Name: "rule-1", Priority: 100, ToolMatch: "*", Condition: "true", Action: policy.ActionAllow},
		},
	}
	created, err := svc.Create(ctx, p)
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}

	// Delete should succeed.
	if err := svc.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}

	// Should be gone.
	_, err = svc.Get(ctx, created.ID)
	if err == nil {
		t.Error("Get() after Delete() should return error")
	}
}

func TestPolicyAdminService_Delete_DefaultPolicy(t *testing.T) {
	svc, _, _, _ := testPolicyAdminEnv(t)
	ctx := context.Background()

	// Try to delete the default policy (seeded in testPolicyAdminEnv).
	err := svc.Delete(ctx, "default-policy-id")
	if err == nil {
		t.Fatal("Delete() default policy should return error")
	}
	if err != ErrDefaultPolicyDelete {
		t.Errorf("Delete() error = %v, want %v", err, ErrDefaultPolicyDelete)
	}
}

func TestPolicyAdminService_Delete_DevDefaultPolicy(t *testing.T) {
	// Simulate dev mode where the default policy is named "dev-allow-all".
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	devPolicy := policy.Policy{
		ID:      "dev-allow-all",
		Name:    DevDefaultPolicyName, // "dev-allow-all"
		Enabled: true,
		Rules: []policy.Rule{
			{ID: "allow-all", Name: "allow-all", Priority: 100, ToolMatch: "*", Condition: "true", Action: policy.ActionAllow},
		},
	}
	store := newMockPolicyStore(devPolicy)
	policySvc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService: %v", err)
	}
	svc := NewPolicyAdminService(store, stateStore, policySvc, logger)

	// Try to delete the dev default policy.
	err = svc.Delete(context.Background(), "dev-allow-all")
	if err == nil {
		t.Fatal("Delete() dev default policy should return error")
	}
	if err != ErrDefaultPolicyDelete {
		t.Errorf("Delete() error = %v, want %v", err, ErrDefaultPolicyDelete)
	}
}

func TestPolicyAdminService_Delete_LastNonDefault(t *testing.T) {
	// Regression test: a single non-default policy must be deletable.
	// Before the fix, the count-based guard blocked deletion of ANY last policy.
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	customPolicy := policy.Policy{
		ID:      "custom-only-policy",
		Name:    "Custom Policy",
		Enabled: true,
		Rules: []policy.Rule{
			{ID: "rule-1", Name: "allow-all", Priority: 100, ToolMatch: "*", Condition: "true", Action: policy.ActionAllow},
		},
	}
	store := newMockPolicyStore(customPolicy)
	policySvc, err := NewPolicyService(context.Background(), store, logger)
	if err != nil {
		t.Fatalf("NewPolicyService: %v", err)
	}
	svc := NewPolicyAdminService(store, stateStore, policySvc, logger)

	// Delete should succeed -- "Custom Policy" is not a default name.
	if err := svc.Delete(context.Background(), "custom-only-policy"); err != nil {
		t.Fatalf("Delete() last non-default policy should succeed, got: %v", err)
	}

	// Verify it is gone.
	_, err = svc.Get(context.Background(), "custom-only-policy")
	if err != ErrPolicyNotFound {
		t.Errorf("Get() after Delete() should return ErrPolicyNotFound, got: %v", err)
	}
}

func TestPolicyAdminService_Delete_NotFound(t *testing.T) {
	svc, _, _, _ := testPolicyAdminEnv(t)
	ctx := context.Background()

	err := svc.Delete(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("Delete() nonexistent should return error")
	}
}

// --- persistState Tests ---

func TestPolicyAdminService_PersistState(t *testing.T) {
	svc, _, _, statePath := testPolicyAdminEnv(t)
	ctx := context.Background()

	// Create a policy (which triggers persistState).
	p := &policy.Policy{
		Name:    "Persist Test",
		Enabled: true,
		Rules: []policy.Rule{
			{Name: "rule-1", Priority: 100, ToolMatch: "read_*", Condition: "true", Action: policy.ActionAllow},
		},
	}
	if _, err := svc.Create(ctx, p); err != nil {
		t.Fatalf("Create(): %v", err)
	}

	// Verify state.json was updated.
	stateStore := state.NewFileStateStore(statePath, slog.Default())
	appState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load state: %v", err)
	}

	// Should have policies from both the default and the new one.
	if len(appState.Policies) == 0 {
		t.Fatal("Persisted policies count = 0, want > 0")
	}
}

// --- List Tests ---

func TestPolicyAdminService_List(t *testing.T) {
	svc, _, _, _ := testPolicyAdminEnv(t)
	ctx := context.Background()

	// Default policy is already seeded.
	policies, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}

	if len(policies) == 0 {
		t.Error("List() should return at least the default policy")
	}
}

// --- Get Tests ---

func TestPolicyAdminService_Get(t *testing.T) {
	svc, _, _, _ := testPolicyAdminEnv(t)
	ctx := context.Background()

	// Create a policy.
	p := &policy.Policy{
		Name:    "Get Test",
		Enabled: true,
		Rules: []policy.Rule{
			{Name: "rule-1", Priority: 100, ToolMatch: "*", Condition: "true", Action: policy.ActionAllow},
		},
	}
	created, err := svc.Create(ctx, p)
	if err != nil {
		t.Fatalf("Create(): %v", err)
	}

	// Get should return it.
	got, err := svc.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get() unexpected error: %v", err)
	}
	if got.Name != "Get Test" {
		t.Errorf("Get() Name = %q, want %q", got.Name, "Get Test")
	}
}

func TestPolicyAdminService_Get_NotFound(t *testing.T) {
	svc, _, _, _ := testPolicyAdminEnv(t)
	ctx := context.Background()

	_, err := svc.Get(ctx, "nonexistent")
	if err == nil {
		t.Fatal("Get() nonexistent should return error")
	}
}

// --- Reload Tests ---

func TestPolicyAdminService_Create_TriggersReload(t *testing.T) {
	svc, policySvc, _, _ := testPolicyAdminEnv(t)
	ctx := context.Background()

	// Initial evaluation with default policy - should be denied (default deny).
	evalCtx := policy.EvaluationContext{
		ToolName:      "custom_tool",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"tester"},
		SessionID:     "test-session",
		IdentityID:    "test-identity",
	}

	// Evaluate before creating custom policy.
	decision, err := policySvc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Initial Evaluate: %v", err)
	}
	if decision.Allowed {
		t.Log("Note: initial evaluation allowed (admin bypass rule)")
	}

	// Create a high-priority allow policy for the custom tool.
	p := &policy.Policy{
		Name:    "Custom Allow",
		Enabled: true,
		Rules: []policy.Rule{
			{
				Name:      "allow-custom",
				Priority:  2000, // Higher than admin bypass
				ToolMatch: "custom_tool",
				Condition: "true",
				Action:    policy.ActionAllow,
			},
		},
	}
	if _, err := svc.Create(ctx, p); err != nil {
		t.Fatalf("Create(): %v", err)
	}

	// Evaluate after creating custom policy - should be allowed.
	decision, err = policySvc.Evaluate(ctx, evalCtx)
	if err != nil {
		t.Fatalf("Post-create Evaluate: %v", err)
	}
	if !decision.Allowed {
		t.Error("Expected evaluation to be allowed after creating high-priority allow rule")
	}
}
