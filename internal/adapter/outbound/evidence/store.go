package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	ev "github.com/Sentinel-Gate/Sentinelgate/internal/domain/evidence"
)

// FileStore is an append-only evidence store that writes signed records
// as JSON Lines to a file.
type FileStore struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	path string
}

// NewFileStore creates or opens an append-only evidence file.
func NewFileStore(path string) (*FileStore, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create evidence directory: %w", err)
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open evidence file: %w", err)
	}

	return &FileStore{
		f:    f,
		enc:  json.NewEncoder(f),
		path: path,
	}, nil
}

// Append writes a signed evidence record to the store and fsyncs to disk.
func (s *FileStore) Append(record ev.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enc.Encode(record); err != nil {
		return err
	}
	return s.f.Sync()
}

// Close closes the underlying file.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// Path returns the file path for this store.
func (s *FileStore) Path() string { return s.path }
