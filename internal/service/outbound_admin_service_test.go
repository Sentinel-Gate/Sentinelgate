package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
)

// testOutboundSetup creates a test OutboundAdminService with all dependencies.
func testOutboundSetup(t *testing.T) (*OutboundAdminService, *action.OutboundInterceptor) {
	t.Helper()
	logger := slog.Default()

	// Create temp state store.
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	stateStore := state.NewFileStateStore(statePath, logger)
	appState := stateStore.DefaultState()
	if err := stateStore.Save(appState); err != nil {
		t.Fatalf("failed to save initial state: %v", err)
	}

	// Create store and interceptor.
	store := action.NewMemoryOutboundStore()

	// Use a mock next interceptor for the outbound interceptor.
	next := &mockActionInterceptor{}
	resolver := action.NewDNSResolver(logger, action.WithLookupFunc(func(host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}))
	interceptor := action.NewOutboundInterceptor(nil, resolver, next, logger)

	svc := NewOutboundAdminService(store, stateStore, logger, interceptor)
	return svc, interceptor
}

// mockActionInterceptor is a simple passthrough for testing.
type mockActionInterceptor struct{}

func (m *mockActionInterceptor) Intercept(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
	return a, nil
}

func validTestRule() *action.OutboundRule {
	return &action.OutboundRule{
		Name:    "Test Block Rule",
		Mode:    action.RuleModeBlocklist,
		Action:  action.RuleActionBlock,
		Enabled: true,
		Targets: []action.OutboundTarget{
			{Type: action.TargetDomain, Value: "evil.com"},
		},
		Priority: 100,
	}
}

func TestOutboundAdminCreateValid(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	rule := validTestRule()
	created, err := svc.Create(ctx, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected generated ID")
	}
	if created.Name != "Test Block Rule" {
		t.Errorf("expected name 'Test Block Rule', got %q", created.Name)
	}
	if created.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
}

func TestOutboundAdminCreateMissingName(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	rule := validTestRule()
	rule.Name = ""
	_, err := svc.Create(ctx, rule)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestOutboundAdminCreateInvalidMode(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	rule := validTestRule()
	rule.Mode = "invalid"
	_, err := svc.Create(ctx, rule)
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestOutboundAdminCreateEmptyTargets(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	rule := validTestRule()
	rule.Targets = nil
	_, err := svc.Create(ctx, rule)
	if err == nil {
		t.Fatal("expected error for empty targets")
	}
}

func TestOutboundAdminCreateInvalidTargetType(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	rule := validTestRule()
	rule.Targets = []action.OutboundTarget{
		{Type: "invalid_type", Value: "foo"},
	}
	_, err := svc.Create(ctx, rule)
	if err == nil {
		t.Fatal("expected error for invalid target type")
	}
}

func TestOutboundAdminUpdateExisting(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	// Create a rule first.
	rule := validTestRule()
	created, err := svc.Create(ctx, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Update it.
	updated := validTestRule()
	updated.Name = "Updated Rule"
	result, err := svc.Update(ctx, created.ID, updated)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Name != "Updated Rule" {
		t.Errorf("expected name 'Updated Rule', got %q", result.Name)
	}
	if result.ID != created.ID {
		t.Errorf("expected ID preserved, got %q", result.ID)
	}
	if result.CreatedAt != created.CreatedAt {
		t.Error("expected CreatedAt to be preserved")
	}
}

func TestOutboundAdminUpdateNonExistent(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	rule := validTestRule()
	_, err := svc.Update(ctx, "does-not-exist", rule)
	if !errors.Is(err, action.ErrOutboundRuleNotFound) {
		t.Fatalf("expected ErrOutboundRuleNotFound, got: %v", err)
	}
}

func TestOutboundAdminUpdateDefaultRule_ToggleEnabled(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	// Load defaults to get a default rule in the store.
	appState := &state.AppState{}
	if err := svc.LoadFromState(ctx, appState); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Default rules should allow toggling enabled/disabled.
	rule := validTestRule()
	rule.Enabled = false
	updated, err := svc.Update(ctx, "default-blocklist-1", rule)
	if err != nil {
		t.Fatalf("expected toggle to succeed, got: %v", err)
	}
	if updated.Enabled {
		t.Error("expected default rule to be disabled after toggle")
	}
	// Name and other fields should remain unchanged (not overwritten by the update payload).
	if updated.Name == rule.Name {
		t.Error("expected default rule name to be preserved, but it was overwritten")
	}
}

func TestOutboundAdminDeleteExisting(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	rule := validTestRule()
	created, err := svc.Create(ctx, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = svc.Delete(ctx, created.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = svc.Get(ctx, created.ID)
	if !errors.Is(err, action.ErrOutboundRuleNotFound) {
		t.Fatalf("expected rule to be deleted, got: %v", err)
	}
}

func TestOutboundAdminDeleteNonExistent(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	err := svc.Delete(ctx, "does-not-exist")
	if !errors.Is(err, action.ErrOutboundRuleNotFound) {
		t.Fatalf("expected ErrOutboundRuleNotFound, got: %v", err)
	}
}

func TestOutboundAdminDeleteDefaultRule(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	// Load defaults.
	appState := &state.AppState{}
	if err := svc.LoadFromState(ctx, appState); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := svc.Delete(ctx, "default-blocklist-1")
	if !errors.Is(err, ErrDefaultRuleReadOnly) {
		t.Fatalf("expected ErrDefaultRuleReadOnly, got: %v", err)
	}
}

func TestOutboundAdminList(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	// Create two rules.
	for i := 0; i < 2; i++ {
		rule := validTestRule()
		rule.Name = "Rule " + string(rune('A'+i))
		rule.Priority = (i + 1) * 100
		if _, err := svc.Create(ctx, rule); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	rules, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
}

func TestOutboundAdminTestRuleMatching(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	_ = svc // not strictly needed for TestRule but keeps setup consistent

	rule := action.OutboundRule{
		ID:      "test-1",
		Name:    "Block Evil",
		Mode:    action.RuleModeBlocklist,
		Action:  action.RuleActionBlock,
		Enabled: true,
		Targets: []action.OutboundTarget{
			{Type: action.TargetDomain, Value: "evil.com"},
		},
	}

	blocked, matchedRule := svc.TestRule(context.Background(), rule, "evil.com", "1.2.3.4", 443)
	if !blocked {
		t.Fatal("expected domain to be matched")
	}
	if matchedRule == nil {
		t.Fatal("expected matching rule")
	}
}

func TestOutboundAdminTestRuleNonMatching(t *testing.T) {
	svc, _ := testOutboundSetup(t)

	rule := action.OutboundRule{
		ID:      "test-1",
		Name:    "Block Evil",
		Mode:    action.RuleModeBlocklist,
		Action:  action.RuleActionBlock,
		Enabled: true,
		Targets: []action.OutboundTarget{
			{Type: action.TargetDomain, Value: "evil.com"},
		},
	}

	blocked, matchedRule := svc.TestRule(context.Background(), rule, "good.com", "5.6.7.8", 443)
	if blocked {
		t.Fatal("expected domain NOT to be matched")
	}
	if matchedRule != nil {
		t.Fatal("expected nil matching rule")
	}
}

func TestOutboundAdminStats(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	// Load defaults (2 default rules).
	appState := &state.AppState{}
	if err := svc.LoadFromState(ctx, appState); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Create 1 custom rule.
	rule := validTestRule()
	if _, err := svc.Create(ctx, rule); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stats, err := svc.Stats(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.TotalRules != 3 {
		t.Errorf("expected 3 total rules, got %d", stats.TotalRules)
	}
	if stats.DefaultRules != 2 {
		t.Errorf("expected 2 default rules, got %d", stats.DefaultRules)
	}
	if stats.CustomRules != 1 {
		t.Errorf("expected 1 custom rule, got %d", stats.CustomRules)
	}
	if stats.BlocklistRules != 3 {
		t.Errorf("expected 3 blocklist rules, got %d", stats.BlocklistRules)
	}
}

func TestOutboundAdminLoadFromStatePersisted(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	// Simulate persisted rules in state.
	now := time.Now().UTC()
	appState := &state.AppState{
		OutboundRules: []state.OutboundRuleEntry{
			{
				ID:       "persisted-1",
				Name:     "Persisted Rule",
				Mode:     "blocklist",
				Action:   "block",
				Enabled:  true,
				Priority: 100,
				Targets: []state.OutboundTargetEntry{
					{Type: "domain", Value: "bad.com"},
				},
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
	}

	if err := svc.LoadFromState(ctx, appState); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rules, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "Persisted Rule" {
		t.Errorf("expected 'Persisted Rule', got %q", rules[0].Name)
	}
}

func TestOutboundAdminLoadFromStateEmpty(t *testing.T) {
	svc, _ := testOutboundSetup(t)
	ctx := context.Background()

	// Empty state -> should load defaults.
	appState := &state.AppState{}
	if err := svc.LoadFromState(ctx, appState); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rules, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	defaults := action.DefaultBlocklistRules()
	if len(rules) != len(defaults) {
		t.Fatalf("expected %d default rules, got %d", len(defaults), len(rules))
	}
	// Verify first default rule.
	if rules[0].Name != defaults[0].Name {
		t.Errorf("expected first rule '%s', got %q", defaults[0].Name, rules[0].Name)
	}
	if !rules[0].ReadOnly {
		t.Error("expected default rules to be ReadOnly")
	}
}

func TestOutboundAdminReloadInterceptor(t *testing.T) {
	logger := slog.Default()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	stateStore := state.NewFileStateStore(statePath, logger)
	appState := stateStore.DefaultState()
	_ = stateStore.Save(appState)

	store := action.NewMemoryOutboundStore()
	next := &mockActionInterceptor{}
	resolver := action.NewDNSResolver(logger, action.WithLookupFunc(func(host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}))
	interceptor := action.NewOutboundInterceptor(nil, resolver, next, logger)

	svc := NewOutboundAdminService(store, stateStore, logger, interceptor)
	ctx := context.Background()

	// Initially no rules -- everything passes through.
	a := &action.CanonicalAction{
		RequestID: "reload-test-1",
		Arguments: map[string]interface{}{"url": "https://evil.com/data"},
	}
	_, err := interceptor.Intercept(ctx, a)
	if err != nil {
		t.Fatalf("expected passthrough with empty rules: %v", err)
	}

	// Create a blocking rule via admin service.
	rule := &action.OutboundRule{
		Name:     "Block evil.com",
		Mode:     action.RuleModeBlocklist,
		Action:   action.RuleActionBlock,
		Enabled:  true,
		Priority: 100,
		Targets: []action.OutboundTarget{
			{Type: action.TargetDomain, Value: "evil.com"},
		},
	}
	if _, err := svc.Create(ctx, rule); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Now the interceptor should block evil.com.
	a2 := &action.CanonicalAction{
		RequestID: "reload-test-2",
		Arguments: map[string]interface{}{"url": "https://evil.com/data"},
	}
	_, err = interceptor.Intercept(ctx, a2)
	if err == nil {
		t.Fatal("expected block after create, got passthrough")
	}
	var denyErr *action.OutboundDenyError
	if !errors.As(err, &denyErr) {
		t.Fatalf("expected OutboundDenyError, got %T: %v", err, err)
	}
}

func TestOutboundAdminPersistenceRoundTrip(t *testing.T) {
	logger := slog.Default()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	stateStore := state.NewFileStateStore(statePath, logger)
	appState := stateStore.DefaultState()
	_ = stateStore.Save(appState)

	store := action.NewMemoryOutboundStore()
	next := &mockActionInterceptor{}
	resolver := action.NewDNSResolver(logger, action.WithLookupFunc(func(host string) ([]string, error) {
		return []string{"1.2.3.4"}, nil
	}))
	interceptor := action.NewOutboundInterceptor(nil, resolver, next, logger)
	svc := NewOutboundAdminService(store, stateStore, logger, interceptor)
	ctx := context.Background()

	// Create a rule.
	rule := validTestRule()
	created, err := svc.Create(ctx, rule)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read state.json back and verify OutboundRules is populated.
	savedState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("unexpected error loading state: %v", err)
	}
	if len(savedState.OutboundRules) != 1 {
		t.Fatalf("expected 1 outbound rule in state, got %d", len(savedState.OutboundRules))
	}
	if savedState.OutboundRules[0].ID != created.ID {
		t.Errorf("expected rule ID %q in state, got %q", created.ID, savedState.OutboundRules[0].ID)
	}

	// Clean up stderr noise.
	_ = os.Stderr
}
