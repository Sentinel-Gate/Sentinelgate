package transform

import (
	"context"
	"errors"
)

// ErrTransformNotFound is returned when a transform rule is not found by ID.
var ErrTransformNotFound = errors.New("transform rule not found")

// TransformStore defines the persistence interface for transform rules.
type TransformStore interface {
	// List returns all transform rules.
	List(ctx context.Context) ([]*TransformRule, error)
	// Get returns a transform rule by ID.
	Get(ctx context.Context, id string) (*TransformRule, error)
	// Put creates or updates a transform rule (upsert).
	Put(ctx context.Context, rule *TransformRule) error
	// Delete removes a transform rule by ID. No error if not found.
	Delete(ctx context.Context, id string) error
}
