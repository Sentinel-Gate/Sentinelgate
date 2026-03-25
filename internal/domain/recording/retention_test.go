package recording_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/recording"
)

func touchFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %q: %v", path, err)
	}
	_ = f.Close()
	return path
}

func setAge(t *testing.T, path string, age time.Duration) {
	t.Helper()
	mtime := time.Now().Add(-age)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes %q: %v", path, err)
	}
}

func newTestCleaner(cfg recording.RecordingConfig) *recording.RetentionCleaner {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	return recording.NewRetentionCleaner(cfg, logger)
}

// TestRetentionCleaner_DeletesOldFiles verifies that files older than retention_days
// are deleted and newer files are kept.
func TestRetentionCleaner_DeletesOldFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := recording.RecordingConfig{
		StorageDir:    dir,
		RetentionDays: 30,
	}
	cleaner := newTestCleaner(cfg)

	// Build filenames with embedded timestamps: the retention cleaner uses
	// fileTimeFromName() to extract the date from the filename rather than mtime.
	// Use time.Now()-relative dates so the test never goes stale.
	oldDate := time.Now().Add(-40 * 24 * time.Hour).UTC().Format("20060102T150405Z")
	newDate := time.Now().Add(-5 * 24 * time.Hour).UTC().Format("20060102T150405Z")

	old1 := touchFile(t, dir, "sess-old1_"+oldDate+".jsonl")
	old2 := touchFile(t, dir, "sess-old2_"+oldDate+".jsonl")
	newFile := touchFile(t, dir, "sess-new_"+newDate+".jsonl")

	setAge(t, old1, 40*24*time.Hour)
	setAge(t, old2, 40*24*time.Hour)
	setAge(t, newFile, 5*24*time.Hour)

	deleted, err := cleaner.RunOnce()
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if deleted != 2 {
		t.Errorf("expected 2 deleted, got %d", deleted)
	}

	// old files must be gone.
	for _, path := range []string{old1, old2} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("expected %q to be deleted", path)
		}
	}
	// new file must remain.
	if _, err := os.Stat(newFile); err != nil {
		t.Errorf("expected new file to remain: %v", err)
	}
}

// TestRetentionCleaner_KeepsForever verifies that RetentionDays=0 disables deletion.
func TestRetentionCleaner_KeepsForever(t *testing.T) {
	dir := t.TempDir()
	cfg := recording.RecordingConfig{
		StorageDir:    dir,
		RetentionDays: 0, // keep forever
	}
	cleaner := newTestCleaner(cfg)

	// Create an old file.
	path := touchFile(t, dir, "sess-old_20250101T120000Z.jsonl")
	setAge(t, path, 365*24*time.Hour)

	deleted, err := cleaner.RunOnce()
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted (keep forever), got %d", deleted)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file should still exist: %v", err)
	}
}

// TestRetentionCleaner_EmptyDir verifies that RunOnce on an empty directory
// returns 0 without error.
func TestRetentionCleaner_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	cfg := recording.RecordingConfig{
		StorageDir:    dir,
		RetentionDays: 30,
	}
	cleaner := newTestCleaner(cfg)

	deleted, err := cleaner.RunOnce()
	if err != nil {
		t.Fatalf("RunOnce on empty dir: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted for empty dir, got %d", deleted)
	}
}

// TestRetentionCleaner_UpdateConfig verifies that UpdateConfig replaces the value
// copy so RunOnce uses the new config, and the original caller's value is unaffected.
func TestRetentionCleaner_UpdateConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := recording.RecordingConfig{
		StorageDir:    dir,
		RetentionDays: 0, // keep forever initially
	}
	cleaner := newTestCleaner(cfg)

	// Create an old file.
	old := touchFile(t, dir, "sess-update_20250101T120000Z.jsonl")
	setAge(t, old, 40*24*time.Hour)

	// RunOnce with RetentionDays=0 should delete nothing.
	deleted, err := cleaner.RunOnce()
	if err != nil {
		t.Fatalf("RunOnce (keep forever): %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted, got %d", deleted)
	}

	// Hot-reload with a new value: 30 days retention.
	newCfg := recording.RecordingConfig{
		StorageDir:    dir,
		RetentionDays: 30,
	}
	cleaner.UpdateConfig(newCfg)

	// RunOnce should now delete the old file.
	deleted, err = cleaner.RunOnce()
	if err != nil {
		t.Fatalf("RunOnce (30 days): %v", err)
	}
	if deleted != 1 {
		t.Errorf("expected 1 deleted after UpdateConfig, got %d", deleted)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("expected old file to be deleted after config update")
	}

	// Verify the original cfg was NOT mutated (value copy, not pointer).
	if cfg.RetentionDays != 0 {
		t.Errorf("original config was mutated: RetentionDays=%d, want 0", cfg.RetentionDays)
	}
}

// TestRetentionCleaner_IgnoresNonJSONL verifies that non-.jsonl files are not deleted.
func TestRetentionCleaner_IgnoresNonJSONL(t *testing.T) {
	dir := t.TempDir()
	cfg := recording.RecordingConfig{
		StorageDir:    dir,
		RetentionDays: 30,
	}
	cleaner := newTestCleaner(cfg)

	// Create an old .txt file.
	txtPath := touchFile(t, dir, "notes.txt")
	setAge(t, txtPath, 40*24*time.Hour)

	deleted, err := cleaner.RunOnce()
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 deleted (txt file ignored), got %d", deleted)
	}
	if _, err := os.Stat(txtPath); err != nil {
		t.Errorf("txt file should still exist: %v", err)
	}
}
