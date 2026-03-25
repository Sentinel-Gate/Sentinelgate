package memory

import (
	"context"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// MemoryUpstreamStore implements upstream.UpstreamStore with an in-memory map.
// Thread-safe for concurrent access via sync.RWMutex.
// Returns deep copies to prevent external mutation of stored data.
type MemoryUpstreamStore struct {
	upstreams map[string]*upstream.Upstream
	mu        sync.RWMutex
}

// NewUpstreamStore creates a new in-memory upstream store.
func NewUpstreamStore() *MemoryUpstreamStore {
	return &MemoryUpstreamStore{
		upstreams: make(map[string]*upstream.Upstream),
	}
}

// List returns all configured upstreams as deep copies.
func (s *MemoryUpstreamStore) List(ctx context.Context) ([]upstream.Upstream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]upstream.Upstream, 0, len(s.upstreams))
	for _, u := range s.upstreams {
		result = append(result, *copyUpstream(u))
	}
	return result, nil
}

// Get returns a single upstream by ID as a deep copy.
// Returns ErrUpstreamNotFound if the upstream does not exist.
func (s *MemoryUpstreamStore) Get(ctx context.Context, id string) (*upstream.Upstream, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.upstreams[id]
	if !ok {
		return nil, upstream.ErrUpstreamNotFound
	}
	return copyUpstream(u), nil
}

// Add stores a new upstream. Stores a deep copy to prevent external mutation.
func (s *MemoryUpstreamStore) Add(ctx context.Context, u *upstream.Upstream) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.upstreams[u.ID] = copyUpstream(u)
	return nil
}

// Update replaces an existing upstream with a deep copy.
// Returns ErrUpstreamNotFound if the upstream does not exist.
func (s *MemoryUpstreamStore) Update(ctx context.Context, u *upstream.Upstream) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.upstreams[u.ID]; !ok {
		return upstream.ErrUpstreamNotFound
	}
	s.upstreams[u.ID] = copyUpstream(u)
	return nil
}

// Delete removes an upstream by ID.
// Returns ErrUpstreamNotFound if the upstream does not exist.
func (s *MemoryUpstreamStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.upstreams[id]; !ok {
		return upstream.ErrUpstreamNotFound
	}
	delete(s.upstreams, id)
	return nil
}

// copyUpstream creates a deep copy of an Upstream to prevent mutation.
func copyUpstream(u *upstream.Upstream) *upstream.Upstream {
	c := &upstream.Upstream{
		ID:        u.ID,
		Name:      u.Name,
		Type:      u.Type,
		Enabled:   u.Enabled,
		Command:   u.Command,
		URL:       u.URL,
		Status:    u.Status,
		LastError: u.LastError,
		ToolCount: u.ToolCount,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}

	// Deep copy slices and maps.
	if u.Args != nil {
		c.Args = make([]string, len(u.Args))
		copy(c.Args, u.Args)
	}
	if u.Env != nil {
		c.Env = make(map[string]string, len(u.Env))
		for k, v := range u.Env {
			c.Env[k] = v
		}
	}

	return c
}

// Compile-time interface verification.
var _ upstream.UpstreamStore = (*MemoryUpstreamStore)(nil)
