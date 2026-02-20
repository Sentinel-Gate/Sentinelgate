package upstream

import (
	"context"
	"errors"
)

// Sentinel errors for upstream store operations.
var (
	// ErrUpstreamNotFound is returned when an upstream with the given ID does not exist.
	ErrUpstreamNotFound = errors.New("upstream not found")
	// ErrDuplicateUpstreamName is returned when an upstream name already exists.
	ErrDuplicateUpstreamName = errors.New("duplicate upstream name")
)

// UpstreamStore provides CRUD operations for upstream configuration.
// This is a port (interface) in the hexagonal architecture.
// Implementations: in-memory (memory package).
type UpstreamStore interface {
	// List returns all configured upstreams.
	List(ctx context.Context) ([]Upstream, error)
	// Get returns a single upstream by ID.
	// Returns ErrUpstreamNotFound if the upstream does not exist.
	Get(ctx context.Context, id string) (*Upstream, error)
	// Add stores a new upstream.
	Add(ctx context.Context, upstream *Upstream) error
	// Update replaces an existing upstream.
	// Returns ErrUpstreamNotFound if the upstream does not exist.
	Update(ctx context.Context, upstream *Upstream) error
	// Delete removes an upstream by ID.
	// Returns ErrUpstreamNotFound if the upstream does not exist.
	Delete(ctx context.Context, id string) error
}
