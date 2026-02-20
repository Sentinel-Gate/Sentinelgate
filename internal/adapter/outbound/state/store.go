package state

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
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
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
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
		return nil, fmt.Errorf("parse state file: %w", err)
	}

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

	// Create backup of current file (ignore error if file doesn't exist).
	if currentData, readErr := os.ReadFile(s.path); readErr == nil {
		bakPath := s.path + ".bak"
		if writeErr := os.WriteFile(bakPath, currentData, 0600); writeErr != nil {
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

// writeAtomic writes data to a temp file, fsyncs it, and renames it
// over the target path. On any error the temp file is cleaned up.
func (s *FileStateStore) writeAtomic(data []byte) error {
	tmpPath := s.path + ".tmp"

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	// cleanup closes and removes the temp file on error.
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

	if err := os.Rename(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename temp to state: %w", err)
	}
	return nil
}

// DefaultState returns a new AppState with permissive defaults:
// - Version "1"
// - DefaultPolicy "allow"
// - No default policies (users add deny rules as needed)
// - Empty slices for upstreams, identities, and API keys
func (s *FileStateStore) DefaultState() *AppState {
	now := time.Now().UTC()
	return &AppState{
		Version:       "1",
		DefaultPolicy: "allow",
		Upstreams:     []UpstreamEntry{},
		Policies:      []PolicyEntry{},
		Identities:    []IdentityEntry{},
		APIKeys:       []APIKeyEntry{},
		CreatedAt:     now,
		UpdatedAt:     now,
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
