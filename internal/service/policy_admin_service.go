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

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// ErrDefaultPolicyDelete is returned when attempting to delete the default policy.
var ErrDefaultPolicyDelete = errors.New("cannot delete the default policy")

// ErrPolicyNotFound is returned when a policy is not found.
var ErrPolicyNotFound = errors.New("policy not found")

// ErrInvalidPolicy is returned when a policy has invalid configuration (e.g. bad CEL expression).
var ErrInvalidPolicy = errors.New("invalid policy")

// DefaultPolicyName is the name used to identify the default policy.
const DefaultPolicyName = "Default RBAC Policy"

// DevDefaultPolicyName is the name used by the dev-mode default policy.
const DevDefaultPolicyName = "dev-allow-all"

// PolicyAdminService provides CRUD operations on policies
// with validation, default policy protection, and persistence to state.json.
// After every mutation it calls PolicyService.Reload() to hot-reload CEL rules.
type PolicyAdminService struct {
	store         policy.PolicyStore
	stateStore    *state.FileStateStore
	policyService *PolicyService
	logger        *slog.Logger
	mu            sync.Mutex // serializes state writes
}

// NewPolicyAdminService creates a new PolicyAdminService.
func NewPolicyAdminService(
	store policy.PolicyStore,
	stateStore *state.FileStateStore,
	policyService *PolicyService,
	logger *slog.Logger,
) *PolicyAdminService {
	return &PolicyAdminService{
		store:         store,
		stateStore:    stateStore,
		policyService: policyService,
		logger:        logger,
	}
}

// List returns all policies from the store.
func (s *PolicyAdminService) List(ctx context.Context) ([]policy.Policy, error) {
	return s.store.GetAllPolicies(ctx)
}

// Get returns a single policy by ID with its rules.
// Returns ErrPolicyNotFound if the policy does not exist.
func (s *PolicyAdminService) Get(ctx context.Context, id string) (*policy.Policy, error) {
	p, err := s.store.GetPolicyWithRules(ctx, id)
	if err != nil {
		if errors.Is(err, memory.ErrPolicyNotFound) {
			return nil, ErrPolicyNotFound
		}
		return nil, fmt.Errorf("get policy: %w", err)
	}
	if p == nil {
		return nil, ErrPolicyNotFound
	}
	return p, nil
}

// Create creates a new policy with the given configuration.
// Generates UUID for the policy and each rule, sets timestamps,
// persists to state.json, and triggers a hot-reload.
func (s *PolicyAdminService) Create(ctx context.Context, p *policy.Policy) (*policy.Policy, error) {
	// Validate basic fields.
	if p.Name == "" {
		return nil, fmt.Errorf("policy name is required")
	}

	// Generate ID and set timestamps.
	now := time.Now().UTC()
	p.ID = uuid.New().String()
	p.CreatedAt = now
	p.UpdatedAt = now

	// M-8: Respect the caller's Enabled value (allows draft mode).
	// The handler layer can default to true if needed for UX.

	// Generate IDs for rules.
	for i := range p.Rules {
		if p.Rules[i].ID == "" {
			p.Rules[i].ID = uuid.New().String()
		}
		if p.Rules[i].CreatedAt.IsZero() {
			p.Rules[i].CreatedAt = now
		}
	}

	// Validate CEL expressions before persisting to prevent invalid policies
	// from poisoning the store (invalid CEL would break all subsequent reloads).
	if err := s.policyService.ValidateRules(p.Rules); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}

	// Serialize mutation + persist to prevent concurrent CRUDs from
	// creating inconsistent state on partial persist failure (M-18).
	s.mu.Lock()
	if err := s.store.SavePolicy(ctx, p); err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("save policy: %w", err)
	}
	if err := s.persistStateLocked(ctx); err != nil {
		s.logger.Error("policy persistence failed, rolling back in-memory create", "policy_id", p.ID, "error", err)
		if rbErr := s.store.DeletePolicy(ctx, p.ID); rbErr != nil {
			s.logger.Error("CRITICAL: rollback failed after persist error, in-memory state may be inconsistent", "policy_id", p.ID, "rollback_error", rbErr)
		}
		s.mu.Unlock()
		return nil, fmt.Errorf("persist policy: %w", err)
	}
	s.mu.Unlock()

	// ALWAYS trigger hot-reload so the CEL engine compiles the new rules.
	if err := s.policyService.Reload(ctx); err != nil {
		s.logger.Error("failed to reload policies after create", "policy_id", p.ID, "error", err)
		return nil, fmt.Errorf("reload policies: %w", err)
	}

	s.logger.Info("policy created", "id", p.ID, "name", p.Name, "rules", len(p.Rules))

	// Return the policy as stored.
	return s.store.GetPolicyWithRules(ctx, p.ID)
}

// Update updates an existing policy. Preserves immutable fields (ID, CreatedAt),
// updates timestamp, persists, and triggers reload.
// Returns ErrPolicyNotFound if the policy does not exist.
func (s *PolicyAdminService) Update(ctx context.Context, id string, p *policy.Policy) (*policy.Policy, error) {
	// Verify existing policy exists.
	existing, err := s.store.GetPolicyWithRules(ctx, id)
	if err != nil {
		if errors.Is(err, memory.ErrPolicyNotFound) {
			return nil, ErrPolicyNotFound
		}
		return nil, fmt.Errorf("get existing policy: %w", err)
	}
	if existing == nil {
		return nil, ErrPolicyNotFound
	}

	// Validate basic fields.
	if p.Name == "" {
		return nil, fmt.Errorf("policy name is required")
	}

	// Preserve immutable fields and update timestamps.
	p.ID = id
	p.CreatedAt = existing.CreatedAt
	p.UpdatedAt = time.Now().UTC()

	// Generate IDs for any new rules that lack an ID.
	for i := range p.Rules {
		if p.Rules[i].ID == "" {
			p.Rules[i].ID = uuid.New().String()
		}
		if p.Rules[i].CreatedAt.IsZero() {
			p.Rules[i].CreatedAt = p.UpdatedAt
		}
	}

	// Validate CEL expressions before persisting.
	if err := s.policyService.ValidateRules(p.Rules); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}

	// Serialize mutation + persist (M-18).
	s.mu.Lock()
	if err := s.store.SavePolicy(ctx, p); err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("save policy: %w", err)
	}
	if err := s.persistStateLocked(ctx); err != nil {
		s.logger.Error("policy persistence failed, rolling back in-memory update", "policy_id", id, "error", err)
		if rbErr := s.store.SavePolicy(ctx, existing); rbErr != nil {
			s.logger.Error("CRITICAL: rollback failed after persist error, in-memory state may be inconsistent", "policy_id", id, "rollback_error", rbErr)
		}
		s.mu.Unlock()
		return nil, fmt.Errorf("persist policy: %w", err)
	}
	s.mu.Unlock()

	// ALWAYS trigger hot-reload.
	if err := s.policyService.Reload(ctx); err != nil {
		s.logger.Error("failed to reload policies after update", "policy_id", id, "error", err)
		return nil, fmt.Errorf("reload policies: %w", err)
	}

	s.logger.Info("policy updated", "id", id, "name", p.Name)

	return s.store.GetPolicyWithRules(ctx, id)
}

// Delete removes a policy by ID. The default policy cannot be deleted.
// Returns ErrDefaultPolicyDelete if attempting to delete the default policy.
// Returns ErrPolicyNotFound if the policy does not exist.
func (s *PolicyAdminService) Delete(ctx context.Context, id string) error {
	// Verify policy exists and check if it's the default.
	// Use GetPolicyWithRules to capture the full state for potential rollback.
	existing, err := s.store.GetPolicyWithRules(ctx, id)
	if err != nil {
		if errors.Is(err, memory.ErrPolicyNotFound) {
			return ErrPolicyNotFound
		}
		return fmt.Errorf("get policy: %w", err)
	}
	if existing == nil {
		return ErrPolicyNotFound
	}

	// Protect the default policy from deletion (both production and dev-mode names).
	if existing.Name == DefaultPolicyName || existing.Name == DevDefaultPolicyName {
		return ErrDefaultPolicyDelete
	}

	// Serialize mutation + persist (M-18).
	s.mu.Lock()
	if err := s.store.DeletePolicy(ctx, id); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("delete policy: %w", err)
	}
	if err := s.persistStateLocked(ctx); err != nil {
		s.logger.Error("policy persistence failed, rolling back in-memory delete", "policy_id", id, "error", err)
		if rbErr := s.store.SavePolicy(ctx, existing); rbErr != nil {
			s.logger.Error("CRITICAL: rollback failed after persist error, in-memory state may be inconsistent", "policy_id", id, "rollback_error", rbErr)
		}
		s.mu.Unlock()
		return fmt.Errorf("persist policy: %w", err)
	}
	s.mu.Unlock()

	// ALWAYS trigger hot-reload.
	if err := s.policyService.Reload(ctx); err != nil {
		s.logger.Error("failed to reload policies after delete", "policy_id", id, "error", err)
		return fmt.Errorf("reload policies: %w", err)
	}

	s.logger.Info("policy deleted", "id", id)
	return nil
}

// DeleteRule removes a single rule from a policy.
// If the policy has only one rule left, the entire policy is deleted.
// Returns ErrPolicyNotFound if the policy does not exist.
func (s *PolicyAdminService) DeleteRule(ctx context.Context, policyID, ruleID string) error {
	// Verify policy exists.
	existing, err := s.store.GetPolicyWithRules(ctx, policyID)
	if err != nil {
		if errors.Is(err, memory.ErrPolicyNotFound) {
			return ErrPolicyNotFound
		}
		return fmt.Errorf("get policy: %w", err)
	}
	if existing == nil {
		return ErrPolicyNotFound
	}

	// Protect the default policy from rule deletion.
	if existing.Name == DefaultPolicyName || existing.Name == DevDefaultPolicyName {
		return ErrDefaultPolicyDelete
	}

	// If only one rule left, delete the entire policy instead of leaving an empty shell.
	if len(existing.Rules) <= 1 {
		return s.Delete(ctx, policyID)
	}

	// Serialize mutation + persist (M-18).
	s.mu.Lock()
	if err := s.store.DeleteRule(ctx, policyID, ruleID); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("delete rule: %w", err)
	}
	if err := s.persistStateLocked(ctx); err != nil {
		s.logger.Error("rule persistence failed, rolling back in-memory delete", "policy_id", policyID, "rule_id", ruleID, "error", err)
		if rbErr := s.store.SavePolicy(ctx, existing); rbErr != nil {
			s.logger.Error("CRITICAL: rollback failed after persist error, in-memory state may be inconsistent", "policy_id", policyID, "rule_id", ruleID, "rollback_error", rbErr)
		}
		s.mu.Unlock()
		return fmt.Errorf("persist rule deletion: %w", err)
	}
	s.mu.Unlock()

	// ALWAYS trigger hot-reload.
	if err := s.policyService.Reload(ctx); err != nil {
		s.logger.Error("failed to reload policies after delete rule", "policy_id", policyID, "rule_id", ruleID, "error", err)
		return fmt.Errorf("reload policies: %w", err)
	}

	s.logger.Info("rule deleted", "policy_id", policyID, "rule_id", ruleID)
	return nil
}

// LoadPoliciesFromState loads policy entries from state.json into the in-memory
// policy store. Entries are grouped by policy name (extracted from the
// "PolicyName: RuleName" format). Policies already present in the store
// (e.g. seeded from YAML config) are skipped to avoid duplicates.
// After loading, it triggers a PolicyService.Reload() to compile the rules.
func (s *PolicyAdminService) LoadPoliciesFromState(ctx context.Context, appState *state.AppState) error {
	if len(appState.Policies) == 0 {
		return nil
	}

	// Get existing policy names to avoid duplicates with YAML-seeded policies.
	existing, err := s.store.GetAllPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to get existing policies: %w", err)
	}
	existingNames := make(map[string]bool, len(existing))
	for _, p := range existing {
		existingNames[p.Name] = true
	}

	// Group flat PolicyEntry records by policy name.
	// The entry Name format is "PolicyName: RuleName".
	type policyGroup struct {
		name    string
		entries []state.PolicyEntry
	}
	groups := make(map[string]*policyGroup)
	var order []string

	for _, entry := range appState.Policies {
		policyName := entry.Name
		ruleName := ""
		if idx := strings.Index(entry.Name, ": "); idx > 0 {
			policyName = entry.Name[:idx]
			ruleName = entry.Name[idx+2:]
		}

		// Skip if this policy is already seeded (e.g. dev-allow-all from YAML).
		if existingNames[policyName] {
			continue
		}

		g, ok := groups[policyName]
		if !ok {
			g = &policyGroup{name: policyName}
			groups[policyName] = g
			order = append(order, policyName)
		}
		// Override name with just the rule name for the entry.
		entry.Name = ruleName
		g.entries = append(g.entries, entry)
	}

	// Convert each group into a domain Policy and add to store.
	for _, policyName := range order {
		g := groups[policyName]

		rules := make([]policy.Rule, 0, len(g.entries))
		for _, e := range g.entries {
			condition := e.Condition
			if condition == "" {
				condition = "true"
			}
			r := policy.Rule{
				ID:        e.ID,
				Name:      e.Name,
				Priority:  e.Priority,
				ToolMatch: e.ToolPattern,
				Condition: condition,
				Action:    policy.Action(e.Action),
				HelpText:  e.HelpText,
				Source:    e.Source,
				CreatedAt: e.CreatedAt,
			}
			if e.ApprovalTimeout != "" {
				if d, parseErr := time.ParseDuration(e.ApprovalTimeout); parseErr == nil {
					r.ApprovalTimeout = d
				}
			}
			if e.TimeoutAction != "" {
				r.TimeoutAction = policy.Action(e.TimeoutAction)
			}
			rules = append(rules, r)
		}

		var createdAt, updatedAt time.Time
		var description string
		var policyPriority int
		var persistedPolicyID string
		enabled := true
		if len(g.entries) > 0 {
			createdAt = g.entries[0].CreatedAt
			updatedAt = g.entries[0].UpdatedAt
			description = g.entries[0].Description
			enabled = g.entries[0].Enabled
			policyPriority = g.entries[0].PolicyPriority
			persistedPolicyID = g.entries[0].PolicyID // L-14: restore persisted policy ID
		}

		// L-14: Reuse the persisted policy UUID instead of generating a new one on every restart.
		policyID := persistedPolicyID
		if policyID == "" {
			policyID = uuid.New().String()
		}

		p := &policy.Policy{
			ID:          policyID,
			Name:        policyName,
			Description: description,
			Priority:    policyPriority,
			Enabled:     enabled,
			Rules:       rules,
			CreatedAt:   createdAt,
			UpdatedAt:   updatedAt,
		}

		if err := s.store.SavePolicy(ctx, p); err != nil {
			s.logger.Error("failed to load policy from state", "name", policyName, "error", err)
			continue
		}
		s.logger.Info("loaded policy from state", "name", policyName, "rules", len(rules))
	}

	// Reload compiled rules to include the newly loaded policies.
	if err := s.policyService.Reload(ctx); err != nil {
		return fmt.Errorf("reload after loading state policies: %w", err)
	}

	return nil
}

// allPolicyLister is implemented by stores that can return all policies including disabled ones.
type allPolicyLister interface {
	GetAllPoliciesIncludingDisabled(ctx context.Context) ([]policy.Policy, error)
}

// persistStateLocked reads all policies from memory, converts them to PolicyEntry
// format, loads the full AppState, updates the Policies field, and saves.
// Caller must hold s.mu.
func (s *PolicyAdminService) persistStateLocked(ctx context.Context) error {
	// Read ALL policies from memory store, including disabled ones.
	var policies []policy.Policy
	var err error
	if lister, ok := s.store.(allPolicyLister); ok {
		policies, err = lister.GetAllPoliciesIncludingDisabled(ctx)
	} else {
		// M-24: Warn that disabled policies may be lost on persist
		// because the store doesn't support GetAllPoliciesIncludingDisabled.
		slog.Warn("policy store does not support disabled policy listing; disabled policies may be lost on persist")
		policies, err = s.store.GetAllPolicies(ctx)
	}
	if err != nil {
		return fmt.Errorf("list policies for persistence: %w", err)
	}

	// Convert to state entries.
	entries := make([]state.PolicyEntry, 0, len(policies))
	for _, p := range policies {
		for _, r := range p.Rules {
			entry := state.PolicyEntry{
				ID:             r.ID,
				PolicyID:       p.ID, // L-14: persist parent policy UUID to survive restarts
				Name:           fmt.Sprintf("%s: %s", p.Name, r.Name),
				Description:    p.Description,
				PolicyPriority: p.Priority,
				Priority:       r.Priority,
				ToolPattern:    r.ToolMatch,
				Condition:      r.Condition,
				Action:         string(r.Action),
				Enabled:        p.Enabled,
				HelpText:       r.HelpText,
				Source:         r.Source,
				CreatedAt:      r.CreatedAt,
				UpdatedAt:      p.UpdatedAt,
			}
			if r.ApprovalTimeout > 0 {
				entry.ApprovalTimeout = r.ApprovalTimeout.String()
			}
			if r.TimeoutAction != "" {
				entry.TimeoutAction = string(r.TimeoutAction)
			}
			entries = append(entries, entry)
		}
	}

	return s.stateStore.Mutate(func(appState *state.AppState) error {
		appState.Policies = entries
		return nil
	})
}
