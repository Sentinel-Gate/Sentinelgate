// Package storage defines domain interfaces for structured data persistence.
// These replace ad-hoc file-based storage with typed abstractions:
//   - TimeSeriesStore: for drift profiles, cost data, usage analytics
//   - VersionedStore: for tool baselines, evidence chains, compliance bundles
package storage

import (
	"context"
	"encoding/json"
	"time"
)

// DataPoint represents a single time-series observation.
type DataPoint struct {
	Timestamp time.Time         `json:"timestamp"`
	Value     float64           `json:"value"`
	Tags      map[string]string `json:"tags,omitempty"`
	Payload   json.RawMessage   `json:"payload,omitempty"`
}

// AggFunc defines an aggregation function for time-series queries.
type AggFunc string

const (
	AggSum   AggFunc = "sum"
	AggAvg   AggFunc = "avg"
	AggMin   AggFunc = "min"
	AggMax   AggFunc = "max"
	AggCount AggFunc = "count"
)

// TimeSeriesStore persists and queries time-indexed data points.
// Used by: Drift Detection (Upgrade 5), Shadow Mode (Upgrade 6), FinOps (Upgrade 12).
type TimeSeriesStore interface {
	// Append adds a data point to a named series.
	Append(ctx context.Context, series string, point DataPoint) error

	// Query returns data points in a time range, ordered by timestamp ascending.
	Query(ctx context.Context, series string, from, to time.Time) ([]DataPoint, error)

	// Aggregate computes a scalar aggregate over a time range.
	Aggregate(ctx context.Context, series string, from, to time.Time, fn AggFunc) (float64, error)

	// Prune removes data points older than the given duration. Returns count removed.
	Prune(ctx context.Context, olderThan time.Duration) (int, error)

	// DeleteSeries removes all data points for a named series. Returns count removed.
	DeleteSeries(ctx context.Context, series string) (int, error)

	// Close releases resources.
	Close() error
}

// Value represents a stored value with metadata.
type Value struct {
	Data      json.RawMessage `json:"data"`
	Version   int64           `json:"version"`
	UpdatedAt time.Time       `json:"updated_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// VersionedValue is a historical value with its version number.
type VersionedValue struct {
	Value
	CreatedAt time.Time `json:"created_at"`
}

// ErrNotFound is returned when a key does not exist.
type ErrNotFound struct {
	Key string
}

func (e *ErrNotFound) Error() string { return "key not found: " + e.Key }

// VersionedStore persists key-value data with version history.
// Used by: Evidence Chain (Upgrade 1), Tool Baselines (Upgrade 4), Compliance (Upgrade 2).
type VersionedStore interface {
	// Get returns the latest value for a key.
	Get(ctx context.Context, key string) (Value, error)

	// Put stores a value, creating a new version. Returns the assigned version number.
	Put(ctx context.Context, key string, value Value) error

	// History returns the N most recent versions of a key, newest first.
	History(ctx context.Context, key string, limit int) ([]VersionedValue, error)

	// Delete removes a key and all its versions.
	Delete(ctx context.Context, key string) error

	// List returns all keys matching the given prefix.
	List(ctx context.Context, prefix string) ([]string, error)

	// Close releases resources.
	Close() error
}
