package transform

import (
	"context"
	"sync"
)

// Compile-time check that MemoryTransformStore implements TransformStore.
var _ TransformStore = (*MemoryTransformStore)(nil)

// MemoryTransformStore is a thread-safe in-memory implementation of TransformStore.
type MemoryTransformStore struct {
	mu    sync.RWMutex
	rules map[string]*TransformRule
}

// NewMemoryTransformStore creates a new empty MemoryTransformStore.
func NewMemoryTransformStore() *MemoryTransformStore {
	return &MemoryTransformStore{
		rules: make(map[string]*TransformRule),
	}
}

// List returns all transform rules as a slice of deep copies.
func (s *MemoryTransformStore) List(_ context.Context) ([]*TransformRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*TransformRule, 0, len(s.rules))
	for _, r := range s.rules {
		result = append(result, copyRule(r))
	}
	return result, nil
}

// Get returns a deep copy of the transform rule with the given ID.
// Returns ErrTransformNotFound if not found.
func (s *MemoryTransformStore) Get(_ context.Context, id string) (*TransformRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.rules[id]
	if !ok {
		return nil, ErrTransformNotFound
	}
	return copyRule(r), nil
}

// Put creates or updates a transform rule (upsert). Validates before storing.
func (s *MemoryTransformStore) Put(_ context.Context, rule *TransformRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.rules[rule.ID] = copyRule(rule)
	return nil
}

// Delete removes a transform rule by ID. No error if not found.
func (s *MemoryTransformStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.rules, id)
	return nil
}

// copyRule creates a deep copy of a TransformRule to prevent external mutation.
func copyRule(r *TransformRule) *TransformRule {
	cp := *r

	// Deep copy slices in Config
	if len(r.Config.Patterns) > 0 {
		cp.Config.Patterns = make([]string, len(r.Config.Patterns))
		copy(cp.Config.Patterns, r.Config.Patterns)
	}
	if len(r.Config.MaskPatterns) > 0 {
		cp.Config.MaskPatterns = make([]string, len(r.Config.MaskPatterns))
		copy(cp.Config.MaskPatterns, r.Config.MaskPatterns)
	}

	return &cp
}
