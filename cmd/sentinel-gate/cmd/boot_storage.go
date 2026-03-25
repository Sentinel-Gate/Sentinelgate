package cmd

import (
	"context"
	"path/filepath"
	"time"

	storageAdapter "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/storage"
	"github.com/Sentinel-Gate/Sentinelgate/internal/lifecycle"
)

// bootStorage initializes the storage abstraction layer (A5).
// Creates TimeSeriesStore (SQLite) and VersionedStore (file-based).
// Storage paths are derived from the state file directory.
func (bc *bootContext) bootStorage(_ context.Context) error {
	stateDir := filepath.Dir(bc.statePath)

	// TimeSeriesStore: SQLite embedded.
	tsPath := filepath.Join(stateDir, "sentinelgate-ts.db")
	tsStore, err := storageAdapter.NewSQLiteTimeSeriesStore(tsPath)
	if err != nil {
		bc.logger.Warn("failed to create timeseries store, analytics features disabled", "error", err)
	} else {
		bc.timeSeriesStore = tsStore

		bc.lifecycle.Register(lifecycle.Hook{
			Name: "timeseries-close", Phase: lifecycle.PhaseCleanup,
			Timeout: 5 * time.Second,
			Fn:      func(ctx context.Context) error { return tsStore.Close() },
		})

		bc.logger.Info("timeseries store initialized", "path", tsPath)
	}

	// VersionedStore: file-based directory.
	vsDir := filepath.Join(stateDir, "versioned")
	vsStore, err := storageAdapter.NewFileVersionedStore(vsDir)
	if err != nil {
		bc.logger.Warn("failed to create versioned store, versioned features disabled", "error", err)
	} else {
		bc.versionedStore = vsStore
		bc.lifecycle.Register(lifecycle.Hook{
			Name: "versioned-store-close", Phase: lifecycle.PhaseCleanup,
			Timeout: 3 * time.Second,
			Fn:      func(ctx context.Context) error { return vsStore.Close() },
		})

		bc.logger.Info("versioned store initialized", "path", vsDir)
	}

	return nil
}
