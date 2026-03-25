package quota

import (
	"context"
	"sync"
)

// MemoryQuotaStore is a thread-safe in-memory implementation of QuotaStore.
type MemoryQuotaStore struct {
	mu      sync.RWMutex
	configs map[string]*QuotaConfig
}

// Compile-time interface check.
var _ QuotaStore = (*MemoryQuotaStore)(nil)

// NewMemoryQuotaStore creates a new MemoryQuotaStore.
func NewMemoryQuotaStore() *MemoryQuotaStore {
	return &MemoryQuotaStore{
		configs: make(map[string]*QuotaConfig),
	}
}

// Get returns a copy of the quota config for the given identity.
// Returns ErrQuotaNotFound if no config exists.
func (s *MemoryQuotaStore) Get(_ context.Context, identityID string) (*QuotaConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cfg, ok := s.configs[identityID]
	if !ok {
		return nil, ErrQuotaNotFound
	}

	// Return a copy to prevent external mutation.
	cp := *cfg
	if cfg.ToolLimits != nil {
		cp.ToolLimits = make(map[string]int64, len(cfg.ToolLimits))
		for k, v := range cfg.ToolLimits {
			cp.ToolLimits[k] = v
		}
	}
	return &cp, nil
}

// Put upserts a quota config (create or update).
func (s *MemoryQuotaStore) Put(_ context.Context, config *QuotaConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy to prevent external mutation.
	cp := *config
	if config.ToolLimits != nil {
		cp.ToolLimits = make(map[string]int64, len(config.ToolLimits))
		for k, v := range config.ToolLimits {
			cp.ToolLimits[k] = v
		}
	}
	s.configs[config.IdentityID] = &cp
	return nil
}

// Delete removes the quota config for the given identity.
// No error is returned if the config does not exist.
func (s *MemoryQuotaStore) Delete(_ context.Context, identityID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.configs, identityID)
	return nil
}

// List returns all quota configs as a slice.
func (s *MemoryQuotaStore) List(_ context.Context) ([]*QuotaConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*QuotaConfig, 0, len(s.configs))
	for _, cfg := range s.configs {
		cp := *cfg
		if cfg.ToolLimits != nil {
			cp.ToolLimits = make(map[string]int64, len(cfg.ToolLimits))
			for k, v := range cfg.ToolLimits {
				cp.ToolLimits[k] = v
			}
		}
		result = append(result, &cp)
	}
	return result, nil
}
