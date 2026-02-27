package recording

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RetentionCleaner runs a background goroutine that periodically deletes
// JSONL recording files older than config.RetentionDays.
type RetentionCleaner struct {
	mu     sync.Mutex
	config RecordingConfig
	logger *slog.Logger
	ticker *time.Ticker
	done   chan struct{}
}

// NewRetentionCleaner creates a RetentionCleaner with a value copy of config.
// The config is protected by a mutex for safe concurrent access between the
// background goroutine (reads) and UpdateConfig (writes).
func NewRetentionCleaner(config RecordingConfig, logger *slog.Logger) *RetentionCleaner {
	return &RetentionCleaner{
		config: config,
		logger: logger,
		done:   make(chan struct{}),
	}
}

// Start begins the background cleanup goroutine that ticks every hour.
// The goroutine stops when ctx is cancelled or Stop is called.
func (r *RetentionCleaner) Start(ctx context.Context) {
	r.ticker = time.NewTicker(time.Hour)
	go func() {
		for {
			select {
			case <-r.ticker.C:
				if _, err := r.RunOnce(); err != nil {
					r.logger.Warn("recording: retention cleanup error", "error", err)
				}
			case <-ctx.Done():
				r.ticker.Stop()
				return
			case <-r.done:
				return
			}
		}
	}()
}

// Stop halts the background goroutine.
func (r *RetentionCleaner) Stop() {
	if r.ticker != nil {
		r.ticker.Stop()
	}
	close(r.done)
}

// UpdateConfig hot-reloads the config by copying the new value.
// The next RunOnce call will use the updated config.
func (r *RetentionCleaner) UpdateConfig(config RecordingConfig) {
	r.mu.Lock()
	r.config = config
	r.mu.Unlock()
}

// RunOnce performs a single retention cleanup pass.
// It deletes all *.jsonl files in StorageDir whose modification time is older
// than RetentionDays. Returns the count of deleted files.
// If RetentionDays == 0, no files are deleted (keep forever).
func (r *RetentionCleaner) RunOnce() (int, error) {
	r.mu.Lock()
	cfg := r.config
	r.mu.Unlock()

	if cfg.RetentionDays == 0 {
		return 0, nil
	}

	pattern := filepath.Join(cfg.StorageDir, "*.jsonl")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return 0, err
	}

	cutoff := time.Now().Add(-time.Duration(cfg.RetentionDays) * 24 * time.Hour)
	deleted := 0

	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil {
			r.logger.Warn("recording: stat failed during retention", "file", path, "error", err)
			continue
		}
		if info.ModTime().Before(cutoff) {
			ageDays := int(time.Since(info.ModTime()).Hours() / 24)
			if err := os.Remove(path); err != nil {
				r.logger.Warn("recording: delete failed during retention",
					"file", path, "error", err)
				continue
			}
			r.logger.Info("recording deleted by retention policy",
				"file", path,
				"age_days", ageDays)
			deleted++
		}
	}

	return deleted, nil
}
