package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// FileStateStore manages reading and writing the state.json file.
// It provides atomic writes (write-tmp-then-rename), automatic backups,
// file locking (flock for cross-process, mutex for in-process), and
// first-boot initialization with a deny-all default policy.
type FileStateStore struct {
	path   string
	mu     sync.Mutex
	logger *slog.Logger
}

// NewFileStateStore creates a new FileStateStore for the given file path.
func NewFileStateStore(path string, logger *slog.Logger) *FileStateStore {
	return &FileStateStore{
		path:   path,
		logger: logger,
	}
}

// Load reads and parses the state.json file.
// If the file does not exist, it returns DefaultState().
// If the file contains invalid JSON, it returns an error.
// SECU-07: Warns if existing file has permissions more open than 0600.
func (s *FileStateStore) Load() (*AppState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

// loadLocked is the lock-free implementation of Load. Caller must hold s.mu.
func (s *FileStateStore) loadLocked() (*AppState, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s.logger.Info("state file not found, using default state", "path", s.path)
			return s.DefaultState(), nil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}

	// SECU-07: Check file permissions and warn if too open.
	// Skip on Windows where Unix file permission bits are not supported.
	if runtime.GOOS != "windows" {
		if info, statErr := os.Stat(s.path); statErr == nil {
			mode := info.Mode().Perm()
			if mode&0077 != 0 { // group or other has access
				s.logger.Warn("state.json has too-open permissions, should be 0600",
					"path", s.path, "current_mode", fmt.Sprintf("%04o", mode))
			}
		}
	}

	var state AppState
	if err := json.Unmarshal(data, &state); err != nil {
		// Fallback: try .bak file before giving up
		s.logger.Warn("state.json is corrupt, trying backup", "path", s.path, "error", err)
		bakPath := s.path + ".bak"
		// L-58: Apply same permissions check to backup file.
		if bakInfo, statErr := os.Stat(bakPath); statErr == nil {
			if mode := bakInfo.Mode().Perm(); mode&0077 != 0 {
				s.logger.Warn("state.json.bak has too-open permissions, should be 0600",
					"path", bakPath, "current_mode", fmt.Sprintf("%04o", mode))
			}
		}
		bakData, bakErr := os.ReadFile(bakPath)
		if bakErr != nil {
			return nil, fmt.Errorf("parse state file: %w (backup also unavailable: %w)", err, bakErr)
		}
		var bakState AppState
		if bakErr := json.Unmarshal(bakData, &bakState); bakErr != nil {
			return nil, fmt.Errorf("parse state file: %w (backup also corrupt: %w)", err, bakErr)
		}
		s.logger.Warn("loaded state from backup file", "path", bakPath)
		// M4: Signal that backup data was used so callers know it may be stale.
		bakState.RestoredFromBackup = true
		s.validateVersion(&bakState)
		validateState(&bakState, s.logger)
		return &bakState, nil
	}

	// L-43: Validate version field after loading state.
	s.validateVersion(&state)
	validateState(&state, s.logger)

	return &state, nil
}

// Save writes the AppState to disk atomically.
//
// The write sequence is:
//  1. Acquire in-process mutex
//  2. Acquire flock on path+".lock"
//  3. Copy current file to path+".bak" (ignored if no current file)
//  4. Marshal state as indented JSON
//  5. Write to path+".tmp" with 0600 permissions
//  6. Fsync the temp file
//  7. Rename path+".tmp" -> path
//  8. Release flock
//  9. Release mutex
func (s *FileStateStore) Save(state *AppState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(state)
}

// saveLocked is the lock-free implementation of Save. Caller must hold s.mu.
func (s *FileStateStore) saveLocked(state *AppState) error {
	// Update the modification timestamp.
	state.UpdatedAt = time.Now().UTC()

	// Acquire cross-process file lock.
	lockPath := s.path + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer func() { _ = lockFile.Close() }()

	if err := flockLock(lockFile.Fd()); err != nil {
		return fmt.Errorf("acquire file lock: %w", err)
	}
	defer flockUnlock(lockFile.Fd()) //nolint:errcheck

	// Create backup of current file atomically (M-19: non-atomic backup
	// write could corrupt both .bak and main file on crash).
	if currentData, readErr := os.ReadFile(s.path); readErr == nil {
		bakPath := s.path + ".bak"
		if writeErr := writeFileAtomic(bakPath, currentData); writeErr != nil {
			s.logger.Warn("failed to create backup", "error", writeErr)
		}
	}

	// Marshal state as indented JSON with trailing newline.
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	data = append(data, '\n')

	// Atomic write: tmp -> fsync -> rename.
	if err := s.writeAtomic(data); err != nil {
		return err
	}

	// SECU-07: Explicitly ensure 0600 permissions after rename as a safety net.
	if err := os.Chmod(s.path, 0600); err != nil {
		s.logger.Warn("failed to set permissions on state file", "error", err)
	}

	s.logger.Debug("state saved", "path", s.path)
	return nil
}

// Mutate atomically reads the state, applies fn, and writes back.
// If fn returns an error the state is NOT saved and the error is returned.
// This prevents cross-service read-modify-write races on state.json.
func (s *FileStateStore) Mutate(fn func(*AppState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.loadLocked()
	if err != nil {
		return err
	}
	if err := fn(st); err != nil {
		return err
	}
	return s.saveLocked(st)
}

// writeAtomic writes data to s.path atomically.
func (s *FileStateStore) writeAtomic(data []byte) error {
	return writeFileAtomic(s.path, data)
}

// writeFileAtomic writes data to a temp file, fsyncs it, and renames it
// over the target path. On any error the temp file is cleaned up.
func writeFileAtomic(targetPath string, data []byte) error {
	tmpPath := targetPath + ".tmp"

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

	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp to target: %w", err)
	}

	// M-14: Fsync the parent directory to ensure the rename is durable on crash.
	// Matches the pattern used in file_versioned.go.
	if dir, err := os.Open(filepath.Dir(targetPath)); err == nil {
		_ = dir.Sync()
		_ = dir.Close() // L-35
	}

	return nil
}

// DefaultState returns a new AppState with secure defaults:
// - Version "1"
// - DefaultPolicy "deny" (deny-all until explicit allow rules are added)
// - Empty slices for upstreams, identities, and API keys
func (s *FileStateStore) DefaultState() *AppState {
	now := time.Now().UTC()
	return &AppState{
		Version:       "1",
		DefaultPolicy: "deny",
		Upstreams:     []UpstreamEntry{},
		Policies:      []PolicyEntry{},
		Identities:    []IdentityEntry{},
		APIKeys:       []APIKeyEntry{},
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// validateVersion checks the Version field of the loaded state.
// L-43: If empty, set to "1". If unrecognized, log a warning for future migration support.
func (s *FileStateStore) validateVersion(st *AppState) {
	switch st.Version {
	case "":
		st.Version = "1"
		s.logger.Info("state version was empty, set to \"1\"", "path", s.path)
	case "1":
		// Current version, nothing to do.
	default:
		s.logger.Warn("state.json has unrecognized version, proceeding with best effort",
			"path", s.path, "version", st.Version)
	}
}

// Exists returns true if the state file exists on disk.
func (s *FileStateStore) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// Path returns the configured file path.
func (s *FileStateStore) Path() string {
	return s.path
}
