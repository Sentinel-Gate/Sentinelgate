package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
)

// ErrDefaultRuleReadOnly is returned when attempting to modify or delete a default blocklist rule.
var ErrDefaultRuleReadOnly = errors.New("default blocklist rules cannot be modified")

// OutboundStats provides aggregate statistics about outbound rules.
type OutboundStats struct {
	TotalRules     int `json:"total_rules"`
	EnabledRules   int `json:"enabled_rules"`
	BlocklistRules int `json:"blocklist_rules"`
	AllowlistRules int `json:"allowlist_rules"`
	DefaultRules   int `json:"default_rules"`
	CustomRules    int `json:"custom_rules"`
}

// validTargetTypes is the set of recognized outbound target types.
var validTargetTypes = map[action.TargetType]bool{
	action.TargetDomain:     true,
	action.TargetIP:         true,
	action.TargetCIDR:       true,
	action.TargetDomainGlob: true,
	action.TargetPortRange:  true,
}

// OutboundAdminService provides CRUD operations on outbound rules
// with validation, default rule protection, state.json persistence,
// and live interceptor reload across all registered interceptors.
type OutboundAdminService struct {
	store        action.OutboundRuleStore
	stateStore   *state.FileStateStore
	interceptors []*action.OutboundInterceptor
	logger       *slog.Logger
	mu           sync.Mutex // serializes state writes
}

// NewOutboundAdminService creates a new OutboundAdminService.
// It accepts zero or more OutboundInterceptor instances that will all
// receive rule reload notifications when rules are created/updated/deleted.
func NewOutboundAdminService(
	store action.OutboundRuleStore,
	stateStore *state.FileStateStore,
	logger *slog.Logger,
	interceptors ...*action.OutboundInterceptor,
) *OutboundAdminService {
	return &OutboundAdminService{
		store:        store,
		stateStore:   stateStore,
		interceptors: interceptors,
		logger:       logger,
	}
}

// AddInterceptor registers an additional interceptor for rule reload notifications.
// This is used when an interceptor is created after the OutboundAdminService
// (e.g., the HTTP gateway outbound interceptor created inside a conditional block).
func (s *OutboundAdminService) AddInterceptor(interceptor *action.OutboundInterceptor) {
	s.interceptors = append(s.interceptors, interceptor)
}

// ReloadRules triggers an explicit rule reload across all registered interceptors.
// Used when a new interceptor is registered after initial boot.
func (s *OutboundAdminService) ReloadRules(ctx context.Context) {
	s.reloadInterceptor(ctx)
}

// List returns all outbound rules from the store.
func (s *OutboundAdminService) List(ctx context.Context) ([]action.OutboundRule, error) {
	return s.store.List(ctx)
}

// Get returns a single outbound rule by ID.
// Returns action.ErrOutboundRuleNotFound if not found.
func (s *OutboundAdminService) Get(ctx context.Context, id string) (*action.OutboundRule, error) {
	return s.store.Get(ctx, id)
}

// Create validates, generates an ID, persists, and live-reloads a new outbound rule.
func (s *OutboundAdminService) Create(ctx context.Context, rule *action.OutboundRule) (*action.OutboundRule, error) {
	if err := validateOutboundRule(rule); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	rule.ID = uuid.New().String()
	rule.CreatedAt = now
	rule.UpdatedAt = now

	if err := s.store.Save(ctx, rule); err != nil {
		return nil, fmt.Errorf("save outbound rule: %w", err)
	}

	if err := s.persistState(ctx); err != nil {
		s.logger.Error("failed to persist state after create", "rule_id", rule.ID, "error", err)
		return nil, fmt.Errorf("persist state: %w", err)
	}

	s.reloadInterceptor(ctx)

	s.logger.Info("outbound rule created", "id", rule.ID, "name", rule.Name)
	return s.store.Get(ctx, rule.ID)
}

// Update validates and updates an existing outbound rule.
// Default blocklist rules only allow toggling the Enabled field.
func (s *OutboundAdminService) Update(ctx context.Context, id string, rule *action.OutboundRule) (*action.OutboundRule, error) {
	existing, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	if isDefaultRule(existing.ID) {
		// Default rules: only allow toggling enabled/disabled.
		existing.Enabled = rule.Enabled
		existing.UpdatedAt = time.Now().UTC()
		if err := s.store.Save(ctx, existing); err != nil {
			return nil, fmt.Errorf("save outbound rule: %w", err)
		}
		if err := s.persistState(ctx); err != nil {
			s.logger.Error("failed to persist state after update", "rule_id", id, "error", err)
			return nil, fmt.Errorf("persist state: %w", err)
		}
		s.reloadInterceptor(ctx)
		s.logger.Info("outbound default rule toggled", "id", id, "enabled", existing.Enabled)
		return s.store.Get(ctx, id)
	}

	if err := validateOutboundRule(rule); err != nil {
		return nil, err
	}

	// Preserve immutable fields.
	rule.ID = id
	rule.CreatedAt = existing.CreatedAt
	rule.UpdatedAt = time.Now().UTC()

	if err := s.store.Save(ctx, rule); err != nil {
		return nil, fmt.Errorf("save outbound rule: %w", err)
	}

	if err := s.persistState(ctx); err != nil {
		s.logger.Error("failed to persist state after update", "rule_id", id, "error", err)
		return nil, fmt.Errorf("persist state: %w", err)
	}

	s.reloadInterceptor(ctx)

	s.logger.Info("outbound rule updated", "id", id, "name", rule.Name)
	return s.store.Get(ctx, id)
}

// Delete removes an outbound rule by ID.
// Default blocklist rules cannot be deleted.
func (s *OutboundAdminService) Delete(ctx context.Context, id string) error {
	existing, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}

	if isDefaultRule(existing.ID) {
		return ErrDefaultRuleReadOnly
	}

	if err := s.store.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete outbound rule: %w", err)
	}

	if err := s.persistState(ctx); err != nil {
		s.logger.Error("failed to persist state after delete", "rule_id", id, "error", err)
		return fmt.Errorf("persist state: %w", err)
	}

	s.reloadInterceptor(ctx)

	s.logger.Info("outbound rule deleted", "id", id)
	return nil
}

// TestRule evaluates whether the given destination would be matched by the given rule.
// Returns (true, rule) if the destination matches, (false, nil) otherwise.
func (s *OutboundAdminService) TestRule(_ context.Context, rule action.OutboundRule, testDomain string, testIP string, testPort int) (bool, *action.OutboundRule) {
	if action.MatchRule(rule, testDomain, testIP, testPort) {
		return true, &rule
	}
	return false, nil
}

// Stats returns aggregate statistics about outbound rules.
func (s *OutboundAdminService) Stats(ctx context.Context) (*OutboundStats, error) {
	rules, err := s.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list rules for stats: %w", err)
	}

	stats := &OutboundStats{
		TotalRules: len(rules),
	}

	for _, r := range rules {
		if r.Enabled {
			stats.EnabledRules++
		}
		switch r.Mode {
		case action.RuleModeBlocklist:
			stats.BlocklistRules++
		case action.RuleModeAllowlist:
			stats.AllowlistRules++
		}
		if isDefaultRule(r.ID) {
			stats.DefaultRules++
		} else {
			stats.CustomRules++
		}
	}

	return stats, nil
}

// LoadFromState loads persisted outbound rules from AppState into the in-memory store.
// If no persisted rules exist, loads the default blocklist rules with ReadOnly flag.
// After loading, it reloads the interceptor with the loaded rules.
func (s *OutboundAdminService) LoadFromState(ctx context.Context, appState *state.AppState) error {
	if len(appState.OutboundRules) == 0 {
		// No persisted rules: load default blocklist as read-only.
		defaults := action.DefaultBlocklistRules()
		for i := range defaults {
			defaults[i].ReadOnly = true
			defaults[i].CreatedAt = time.Now().UTC()
			defaults[i].UpdatedAt = defaults[i].CreatedAt
			if err := s.store.Save(ctx, &defaults[i]); err != nil {
				s.logger.Error("failed to save default rule", "id", defaults[i].ID, "error", err)
			}
		}
		s.logger.Info("loaded default outbound blocklist", "rules", len(defaults))
		s.reloadInterceptor(ctx)
		return nil
	}

	// Load persisted rules from state.json.
	for _, entry := range appState.OutboundRules {
		rule := entryToRule(entry)
		if err := s.store.Save(ctx, &rule); err != nil {
			s.logger.Error("failed to load outbound rule from state", "id", entry.ID, "error", err)
			continue
		}
	}

	s.logger.Info("loaded outbound rules from state", "rules", len(appState.OutboundRules))
	s.reloadInterceptor(ctx)
	return nil
}

// reloadInterceptor lists all enabled rules and atomically replaces the
// rule set on ALL registered interceptors (MCP chain + HTTP gateway).
func (s *OutboundAdminService) reloadInterceptor(ctx context.Context) {
	rules, err := s.store.List(ctx)
	if err != nil {
		s.logger.Error("failed to list rules for interceptor reload", "error", err)
		return
	}

	// Only pass enabled rules to the interceptors.
	enabled := make([]action.OutboundRule, 0, len(rules))
	for _, r := range rules {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}

	for _, interceptor := range s.interceptors {
		interceptor.SetRules(enabled)
	}
}

// persistState writes all outbound rules to state.json.
func (s *OutboundAdminService) persistState(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rules, err := s.store.List(ctx)
	if err != nil {
		return fmt.Errorf("list rules for persistence: %w", err)
	}

	entries := make([]state.OutboundRuleEntry, 0, len(rules))
	for _, r := range rules {
		entries = append(entries, ruleToEntry(r))
	}

	appState, err := s.stateStore.Load()
	if err != nil {
		return fmt.Errorf("load state for persistence: %w", err)
	}

	appState.OutboundRules = entries

	if err := s.stateStore.Save(appState); err != nil {
		return fmt.Errorf("save state: %w", err)
	}

	return nil
}

// validateOutboundRule validates required fields for an outbound rule.
func validateOutboundRule(rule *action.OutboundRule) error {
	if rule.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if rule.Mode != action.RuleModeBlocklist && rule.Mode != action.RuleModeAllowlist {
		return fmt.Errorf("rule mode must be 'blocklist' or 'allowlist'")
	}
	if rule.Action != action.RuleActionBlock && rule.Action != action.RuleActionAlert && rule.Action != action.RuleActionLog {
		return fmt.Errorf("rule action must be 'block', 'alert', or 'log'")
	}
	if len(rule.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}
	for _, t := range rule.Targets {
		if !validTargetTypes[t.Type] {
			return fmt.Errorf("invalid target type: %q", t.Type)
		}
	}
	return nil
}

// isDefaultRule returns true if the rule ID indicates a default blocklist rule.
func isDefaultRule(id string) bool {
	return strings.HasPrefix(id, "default-blocklist-")
}

// ruleToEntry converts a domain OutboundRule to a state.json OutboundRuleEntry.
func ruleToEntry(r action.OutboundRule) state.OutboundRuleEntry {
	targets := make([]state.OutboundTargetEntry, len(r.Targets))
	for i, t := range r.Targets {
		targets[i] = state.OutboundTargetEntry{
			Type:  string(t.Type),
			Value: t.Value,
		}
	}
	return state.OutboundRuleEntry{
		ID:         r.ID,
		Name:       r.Name,
		Mode:       string(r.Mode),
		Targets:    targets,
		Action:     string(r.Action),
		Scope:      r.Scope,
		Priority:   r.Priority,
		Enabled:    r.Enabled,
		Base64Scan: r.Base64Scan,
		HelpText:   r.HelpText,
		HelpURL:    r.HelpURL,
		ReadOnly:   r.ReadOnly,
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
	}
}

// entryToRule converts a state.json OutboundRuleEntry to a domain OutboundRule.
func entryToRule(e state.OutboundRuleEntry) action.OutboundRule {
	targets := make([]action.OutboundTarget, len(e.Targets))
	for i, t := range e.Targets {
		targets[i] = action.OutboundTarget{
			Type:  action.TargetType(t.Type),
			Value: t.Value,
		}
	}
	return action.OutboundRule{
		ID:         e.ID,
		Name:       e.Name,
		Mode:       action.RuleMode(e.Mode),
		Targets:    targets,
		Action:     action.RuleAction(e.Action),
		Scope:      e.Scope,
		Priority:   e.Priority,
		Enabled:    e.Enabled,
		Base64Scan: e.Base64Scan,
		HelpText:   e.HelpText,
		HelpURL:    e.HelpURL,
		ReadOnly:   e.ReadOnly,
		CreatedAt:  e.CreatedAt,
		UpdatedAt:  e.UpdatedAt,
	}
}
