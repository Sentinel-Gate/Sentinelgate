package action

import (
	"context"
	"errors"
	"sort"
	"sync"
)

// ErrOutboundRuleNotFound is returned when a requested outbound rule does not exist.
var ErrOutboundRuleNotFound = errors.New("outbound rule not found")

// OutboundRuleStore defines CRUD operations for outbound rules.
type OutboundRuleStore interface {
	// List returns all rules sorted by Priority ascending.
	List(ctx context.Context) ([]OutboundRule, error)
	// Get returns a single rule by ID. Returns ErrOutboundRuleNotFound if not found.
	Get(ctx context.Context, id string) (*OutboundRule, error)
	// Save creates or updates a rule in the store.
	Save(ctx context.Context, rule *OutboundRule) error
	// Delete removes a rule by ID. Returns ErrOutboundRuleNotFound if not found.
	Delete(ctx context.Context, id string) error
}

// MemoryOutboundStore implements OutboundRuleStore with thread-safe in-memory storage.
type MemoryOutboundStore struct {
	rules map[string]*OutboundRule
	mu    sync.RWMutex
}

// NewMemoryOutboundStore creates a new empty MemoryOutboundStore.
func NewMemoryOutboundStore() *MemoryOutboundStore {
	return &MemoryOutboundStore{
		rules: make(map[string]*OutboundRule),
	}
}

// List returns all rules as copies, sorted by Priority ascending.
// Both enabled and disabled rules are returned.
func (s *MemoryOutboundStore) List(_ context.Context) ([]OutboundRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]OutboundRule, 0, len(s.rules))
	for _, r := range s.rules {
		result = append(result, copyRule(r))
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Priority < result[j].Priority
	})

	return result, nil
}

// Get returns a copy of the rule with the given ID.
// Returns ErrOutboundRuleNotFound if the rule does not exist.
func (s *MemoryOutboundStore) Get(_ context.Context, id string) (*OutboundRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.rules[id]
	if !ok {
		return nil, ErrOutboundRuleNotFound
	}

	copied := copyRule(r)
	return &copied, nil
}

// Save creates or updates a rule. Stores a deep copy so external modifications
// do not affect stored data.
func (s *MemoryOutboundStore) Save(_ context.Context, rule *OutboundRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	copied := copyRule(rule)
	s.rules[rule.ID] = &copied
	return nil
}

// Delete removes a rule by ID. Returns ErrOutboundRuleNotFound if not found.
func (s *MemoryOutboundStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.rules[id]; !ok {
		return ErrOutboundRuleNotFound
	}

	delete(s.rules, id)
	return nil
}

// copyRule creates a deep copy of an OutboundRule, including its Targets slice.
func copyRule(r *OutboundRule) OutboundRule {
	copied := *r
	if r.Targets != nil {
		copied.Targets = make([]OutboundTarget, len(r.Targets))
		copy(copied.Targets, r.Targets)
	}
	return copied
}
