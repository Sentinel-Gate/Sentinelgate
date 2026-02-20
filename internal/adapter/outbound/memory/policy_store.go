package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// Error types for policy store operations.
var (
	ErrPolicyNotFound = errors.New("policy not found")
)

// MemoryPolicyStore implements policy.PolicyStore with in-memory map.
// Thread-safe for concurrent access. For development/testing only.
type MemoryPolicyStore struct {
	policies map[string]*policy.Policy // ID -> Policy
	mu       sync.RWMutex
}

// NewPolicyStore creates a new in-memory policy store.
func NewPolicyStore() *MemoryPolicyStore {
	return &MemoryPolicyStore{
		policies: make(map[string]*policy.Policy),
	}
}

// GetAllPolicies returns all enabled policies.
func (s *MemoryPolicyStore) GetAllPolicies(ctx context.Context) ([]policy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []policy.Policy
	for _, p := range s.policies {
		if p.Enabled {
			// Return a copy to prevent mutation
			policyCopy := copyPolicy(p)
			result = append(result, *policyCopy)
		}
	}
	return result, nil
}

// GetPolicy returns a policy by ID.
// Returns ErrPolicyNotFound if policy doesn't exist.
func (s *MemoryPolicyStore) GetPolicy(ctx context.Context, id string) (*policy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.policies[id]
	if !ok {
		return nil, ErrPolicyNotFound
	}

	// Return a copy to prevent mutation
	return copyPolicy(p), nil
}

// SavePolicy creates or updates a policy.
func (s *MemoryPolicyStore) SavePolicy(ctx context.Context, p *policy.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy to prevent external mutation
	s.policies[p.ID] = copyPolicy(p)
	return nil
}

// AddPolicy adds a policy (for testing/seeding).
func (s *MemoryPolicyStore) AddPolicy(p *policy.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy to prevent external mutation
	s.policies[p.ID] = copyPolicy(p)
}

// DeletePolicy removes a policy by ID.
// Returns ErrPolicyNotFound if policy doesn't exist.
func (s *MemoryPolicyStore) DeletePolicy(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.policies[id]; !ok {
		return ErrPolicyNotFound
	}
	delete(s.policies, id)
	return nil
}

// GetPolicyWithRules returns a policy with all its rules loaded.
// For memory store, this is the same as GetPolicy since rules are always loaded.
func (s *MemoryPolicyStore) GetPolicyWithRules(ctx context.Context, id string) (*policy.Policy, error) {
	return s.GetPolicy(ctx, id)
}

// SaveRule creates or updates a rule within a policy.
func (s *MemoryPolicyStore) SaveRule(ctx context.Context, policyID string, r *policy.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.policies[policyID]
	if !ok {
		return ErrPolicyNotFound
	}

	// If rule has an ID, try to find and update it
	if r.ID != "" {
		for i, rule := range p.Rules {
			if rule.ID == r.ID {
				p.Rules[i] = *r
				return nil
			}
		}
		// Rule not found, return error
		return errors.New("rule not found")
	}

	// Generate a new ID for new rules
	r.ID = generateID()
	p.Rules = append(p.Rules, *r)
	return nil
}

// DeleteRule removes a rule by ID.
func (s *MemoryPolicyStore) DeleteRule(ctx context.Context, policyID, ruleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.policies[policyID]
	if !ok {
		return ErrPolicyNotFound
	}

	for i, rule := range p.Rules {
		if rule.ID == ruleID {
			p.Rules = append(p.Rules[:i], p.Rules[i+1:]...)
			return nil
		}
	}

	return errors.New("rule not found")
}

// generateID generates a simple ID for memory store.
func generateID() string {
	return "mem-" + randomString(8)
}

// randomString generates a random string of given length.
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[i%len(letters)]
	}
	return string(b)
}

// copyPolicy creates a deep copy of a policy.
func copyPolicy(p *policy.Policy) *policy.Policy {
	policyCopy := &policy.Policy{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Priority:    p.Priority,
		Enabled:     p.Enabled,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
		Rules:       make([]policy.Rule, len(p.Rules)),
	}
	copy(policyCopy.Rules, p.Rules)
	return policyCopy
}

// Compile-time interface verification.
var _ policy.PolicyStore = (*MemoryPolicyStore)(nil)
