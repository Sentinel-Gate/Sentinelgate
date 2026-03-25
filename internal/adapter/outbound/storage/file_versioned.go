package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/storage"
)

// Compile-time check.
var _ storage.VersionedStore = (*FileVersionedStore)(nil)

// FileVersionedStore implements VersionedStore using a directory of JSON files.
// Current values are stored as {key}.json in the root directory.
// History is stored in {key}.history/ with timestamped files.
type FileVersionedStore struct {
	mu         sync.RWMutex
	baseDir    string
	archiveSeq uint64 // monotonic counter to prevent archive collisions (H-9)
}

// NewFileVersionedStore creates a file-backed versioned store at the given directory.
func NewFileVersionedStore(baseDir string) (*FileVersionedStore, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("create versioned store directory: %w", err)
	}
	return &FileVersionedStore{baseDir: baseDir}, nil
}

func (s *FileVersionedStore) keyPath(key string) string {
	return filepath.Join(s.baseDir, sanitizeKey(key)+".json")
}

func (s *FileVersionedStore) historyDir(key string) string {
	return filepath.Join(s.baseDir, sanitizeKey(key)+".history")
}

// sanitizeKey percent-encodes characters that are unsafe in file paths.
// Uses percent-encoding instead of __fwd__ markers to prevent collisions
// between keys containing literal marker sequences and keys with special chars (M-21).
func sanitizeKey(key string) string {
	r := strings.NewReplacer(
		"%", "%25", // escape % first to avoid double-encoding
		"/", "%2F",
		"\\", "%5C",
		"..", "%2E%2E",
		":", "%3A",  // L-2: unsafe on Windows
		"<", "%3C",
		">", "%3E",
		"|", "%7C",
		"?", "%3F",
		"*", "%2A",
		"\x00", "%00",
	)
	return r.Replace(key)
}

// unsanitizeKey reverses the percent-encoding applied by sanitizeKey.
// Also supports legacy __fwd__/__bck__/__dot__ format for backward compatibility.
func unsanitizeKey(key string) string {
	if strings.Contains(key, "__fwd__") || strings.Contains(key, "__bck__") || strings.Contains(key, "__dot__") {
		return strings.NewReplacer("__fwd__", "/", "__bck__", "\\", "__dot__", "..").Replace(key)
	}
	r := strings.NewReplacer(
		"%2F", "/",
		"%5C", "\\",
		"%2E%2E", "..",
		"%25", "%", // decode % last to avoid double-decoding
	)
	return r.Replace(key)
}

func (s *FileVersionedStore) Get(_ context.Context, key string) (storage.Value, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.keyPath(key))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return storage.Value{}, &storage.ErrNotFound{Key: key}
		}
		return storage.Value{}, err
	}

	var v storage.Value
	if err := json.Unmarshal(data, &v); err != nil {
		return storage.Value{}, fmt.Errorf("decode value: %w", err)
	}
	return v, nil
}

func (s *FileVersionedStore) Put(_ context.Context, key string, value storage.Value) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	path := s.keyPath(key)

	// Read current version to determine next version number.
	var prevVersion int64
	var prevData []byte
	var prevUpdatedAt time.Time
	if existing, err := os.ReadFile(path); err == nil {
		var prev storage.Value
		if json.Unmarshal(existing, &prev) == nil {
			prevVersion = prev.Version
			prevData = existing
			prevUpdatedAt = prev.UpdatedAt
		}
	}

	// Set version metadata.
	value.Version = prevVersion + 1
	if value.UpdatedAt.IsZero() {
		value.UpdatedAt = time.Now().UTC()
	}

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode value: %w", err)
	}

	// M-23: Archive the previous version before writing the new one.
	// If we wrote first and crashed before archiving, the previous
	// version would be lost permanently.
	if prevData != nil {
		if err := s.archiveVersion(key, prevData, prevUpdatedAt); err != nil {
			return fmt.Errorf("archive previous version: %w", err)
		}
	}

	if err := writeFileAtomic(path, data); err != nil {
		return err
	}

	return nil
}

// writeFileAtomic writes data to a temp file, fsyncs it, and renames it
// over the target path. On any error the temp file is cleaned up.
func writeFileAtomic(path string, data []byte) error {
	tmpPath := path + ".tmp"

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmpPath)
	}

	if _, err := f.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp to target: %w", err)
	}

	// L-13: Fsync the parent directory to ensure the rename is durable on crash.
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close() // L-35
	}
	return nil
}

func (s *FileVersionedStore) archiveVersion(key string, data []byte, updatedAt time.Time) error {
	dir := s.historyDir(key)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// H-9: Append a monotonic counter to prevent collisions when two updates
	// happen within the same millisecond timestamp.
	ts := updatedAt.Format("20060102T150405.000")
	seq := atomic.AddUint64(&s.archiveSeq, 1)
	archivePath := filepath.Join(dir, fmt.Sprintf("%s_%04d.json", ts, seq))
	return writeFileAtomic(archivePath, data)
}

func (s *FileVersionedStore) History(_ context.Context, key string, limit int) ([]storage.VersionedValue, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := s.historyDir(key)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	// Sort by name descending (newest first, since names are timestamps).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() > entries[j].Name()
	})

	// M-20: Apply limit after filtering non-JSON entries, not before.
	var history []storage.VersionedValue
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}

		var v storage.Value
		if err := json.Unmarshal(data, &v); err != nil {
			continue
		}

		history = append(history, storage.VersionedValue{
			Value:     v,
			CreatedAt: v.UpdatedAt,
		})

		if limit > 0 && len(history) >= limit {
			break
		}
	}
	return history, nil
}

func (s *FileVersionedStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	if err := os.Remove(s.keyPath(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("remove key: %w", err))
	}
	if err := os.RemoveAll(s.historyDir(key)); err != nil {
		errs = append(errs, fmt.Errorf("remove history: %w", err))
	}
	return errors.Join(errs...)
}

func (s *FileVersionedStore) List(_ context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.baseDir)
	if err != nil {
		return nil, err
	}

	// L-24: The prefix must be encoded exactly once via sanitizeKey, matching the
	// single encoding applied when files are created (via keyPath → sanitizeKey).
	// This ensures keys containing "%" are found correctly:
	// e.g., prefix "a%" → sanitizeKey → "a%25" matches file "a%25b.json" (key "a%b").
	sanitizedPrefix := sanitizeKey(prefix)
	var keys []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		key := strings.TrimSuffix(name, ".json")
		if prefix == "" || strings.HasPrefix(key, sanitizedPrefix) {
			keys = append(keys, unsanitizeKey(key))
		}
	}
	return keys, nil
}

func (s *FileVersionedStore) Close() error {
	// No resources to release for file-based store.
	return nil
}
