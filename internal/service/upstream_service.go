package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// UpstreamService provides CRUD operations on upstream configurations
// with validation and persistence to state.json.
type UpstreamService struct {
	store      upstream.UpstreamStore
	stateStore *state.FileStateStore
	logger     *slog.Logger
	mu         sync.Mutex // serializes state writes
}

// NewUpstreamService creates a new UpstreamService.
func NewUpstreamService(store upstream.UpstreamStore, stateStore *state.FileStateStore, logger *slog.Logger) *UpstreamService {
	return &UpstreamService{
		store:      store,
		stateStore: stateStore,
		logger:     logger,
	}
}

// List returns all configured upstreams from the in-memory store.
func (s *UpstreamService) List(ctx context.Context) ([]upstream.Upstream, error) {
	return s.store.List(ctx)
}

// Get returns a single upstream by ID.
// Returns upstream.ErrUpstreamNotFound if the upstream does not exist.
func (s *UpstreamService) Get(ctx context.Context, id string) (*upstream.Upstream, error) {
	return s.store.Get(ctx, id)
}

// Add validates and creates a new upstream, persisting the change to state.json.
// Generates a UUID, sets timestamps, checks name uniqueness, and validates configuration.
func (s *UpstreamService) Add(ctx context.Context, u *upstream.Upstream) (*upstream.Upstream, error) {
	// Validate the upstream configuration.
	if err := u.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Check name uniqueness.
	if err := s.checkNameUnique(ctx, u.Name, ""); err != nil {
		return nil, err
	}

	// Generate ID and set timestamps.
	now := time.Now().UTC()
	u.ID = uuid.New().String()
	u.CreatedAt = now
	u.UpdatedAt = now

	// Add to in-memory store.
	if err := s.store.Add(ctx, u); err != nil {
		return nil, fmt.Errorf("add upstream to store: %w", err)
	}

	// Persist to state.json.
	if err := s.persistState(ctx); err != nil {
		s.logger.Error("failed to persist state after add", "upstream_id", u.ID, "error", err)
		return nil, fmt.Errorf("persist state: %w", err)
	}

	s.logger.Info("upstream added", "id", u.ID, "name", u.Name, "type", u.Type)

	// Return the upstream as stored (via Get for a clean copy).
	return s.store.Get(ctx, u.ID)
}

// Update validates and updates an existing upstream, persisting the change.
// Checks name uniqueness excluding the upstream being updated.
func (s *UpstreamService) Update(ctx context.Context, id string, u *upstream.Upstream) (*upstream.Upstream, error) {
	// Verify the upstream exists.
	existing, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// Validate the new configuration.
	if err := u.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Check name uniqueness, excluding the current upstream.
	if err := s.checkNameUnique(ctx, u.Name, id); err != nil {
		return nil, err
	}

	// Preserve immutable fields and update timestamps.
	u.ID = id
	u.CreatedAt = existing.CreatedAt
	u.UpdatedAt = time.Now().UTC()

	// Update in-memory store.
	if err := s.store.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("update upstream in store: %w", err)
	}

	// Persist to state.json.
	if err := s.persistState(ctx); err != nil {
		s.logger.Error("failed to persist state after update", "upstream_id", id, "error", err)
		return nil, fmt.Errorf("persist state: %w", err)
	}

	s.logger.Info("upstream updated", "id", id, "name", u.Name)

	return s.store.Get(ctx, id)
}

// Delete removes an upstream by ID and persists the change.
// Returns upstream.ErrUpstreamNotFound if the upstream does not exist.
func (s *UpstreamService) Delete(ctx context.Context, id string) error {
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}

	// Persist to state.json.
	if err := s.persistState(ctx); err != nil {
		s.logger.Error("failed to persist state after delete", "upstream_id", id, "error", err)
		return fmt.Errorf("persist state: %w", err)
	}

	s.logger.Info("upstream deleted", "id", id)
	return nil
}

// SetEnabled toggles the enabled flag on an upstream and persists the change.
// Returns the updated upstream.
func (s *UpstreamService) SetEnabled(ctx context.Context, id string, enabled bool) (*upstream.Upstream, error) {
	u, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	u.Enabled = enabled
	u.UpdatedAt = time.Now().UTC()

	if err := s.store.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("update upstream in store: %w", err)
	}

	// Persist to state.json.
	if err := s.persistState(ctx); err != nil {
		s.logger.Error("failed to persist state after set-enabled", "upstream_id", id, "error", err)
		return nil, fmt.Errorf("persist state: %w", err)
	}

	s.logger.Info("upstream enabled toggled", "id", id, "enabled", enabled)

	return s.store.Get(ctx, id)
}

// LoadFromState populates the in-memory store from the given AppState.
// Called at boot to restore persisted upstream configuration.
// The ctx parameter enables cancellation during startup.
func (s *UpstreamService) LoadFromState(ctx context.Context, appState *state.AppState) error {

	for i := range appState.Upstreams {
		entry := &appState.Upstreams[i]
		u := &upstream.Upstream{
			ID:        entry.ID,
			Name:      entry.Name,
			Type:      upstream.UpstreamType(entry.Type),
			Enabled:   entry.Enabled,
			Command:   entry.Command,
			Args:      entry.Args,
			URL:       entry.URL,
			Env:       entry.Env,
			Status:    upstream.StatusDisconnected,
			CreatedAt: entry.CreatedAt,
			UpdatedAt: entry.UpdatedAt,
		}

		if err := s.store.Add(ctx, u); err != nil {
			return fmt.Errorf("load upstream %q: %w", entry.ID, err)
		}
	}

	s.logger.Info("upstreams loaded from state", "count", len(appState.Upstreams))
	return nil
}

// checkNameUnique verifies that no other upstream uses the given name.
// excludeID is the ID of the upstream being updated (to allow keeping its own name).
// Pass empty string for excludeID when creating a new upstream.
func (s *UpstreamService) checkNameUnique(ctx context.Context, name string, excludeID string) error {
	all, err := s.store.List(ctx)
	if err != nil {
		return fmt.Errorf("list upstreams for uniqueness check: %w", err)
	}

	for _, existing := range all {
		if existing.Name == name && existing.ID != excludeID {
			return upstream.ErrDuplicateUpstreamName
		}
	}
	return nil
}

// persistState reads all upstreams from memory, converts them to UpstreamEntry
// format, loads the full AppState, updates the Upstreams field, and saves.
func (s *UpstreamService) persistState(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Read current upstreams from memory store.
	upstreams, err := s.store.List(ctx)
	if err != nil {
		return fmt.Errorf("list upstreams for persistence: %w", err)
	}

	// Convert to state entries.
	entries := make([]state.UpstreamEntry, len(upstreams))
	for i, u := range upstreams {
		entries[i] = state.UpstreamEntry{
			ID:        u.ID,
			Name:      u.Name,
			Type:      string(u.Type),
			Enabled:   u.Enabled,
			Command:   u.Command,
			Args:      u.Args,
			URL:       u.URL,
			Env:       u.Env,
			CreatedAt: u.CreatedAt,
			UpdatedAt: u.UpdatedAt,
		}
	}

	// Load full state, update upstreams, save.
	appState, err := s.stateStore.Load()
	if err != nil {
		return fmt.Errorf("load state for persistence: %w", err)
	}

	appState.Upstreams = entries

	if err := s.stateStore.Save(appState); err != nil {
		return fmt.Errorf("save state: %w", err)
	}

	return nil
}
