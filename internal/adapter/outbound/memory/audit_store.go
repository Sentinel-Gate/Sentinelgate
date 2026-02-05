// Package memory provides in-memory implementations of outbound ports.
package memory

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// MemoryAuditStore implements audit.AuditStore writing to stdout or a file.
// For development/testing only. Does not support queries (write-only).
type MemoryAuditStore struct {
	encoder *json.Encoder
	writer  io.Writer
	mu      sync.Mutex
}

// NewAuditStore creates a new audit store writing to stdout.
func NewAuditStore() *MemoryAuditStore {
	return &MemoryAuditStore{
		encoder: json.NewEncoder(os.Stdout),
		writer:  os.Stdout,
	}
}

// NewAuditStoreWithWriter creates an audit store writing to the given writer.
func NewAuditStoreWithWriter(w io.Writer) *MemoryAuditStore {
	return &MemoryAuditStore{
		encoder: json.NewEncoder(w),
		writer:  w,
	}
}

// Append stores audit records by writing them as JSON to the output.
func (s *MemoryAuditStore) Append(ctx context.Context, records ...audit.AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, r := range records {
		if err := s.encoder.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

// Flush forces pending records to storage.
// No-op for this implementation (no buffering).
func (s *MemoryAuditStore) Flush(ctx context.Context) error {
	return nil
}

// Close releases resources.
func (s *MemoryAuditStore) Close() error {
	// Close file if it's not stdout/stderr
	if f, ok := s.writer.(*os.File); ok && f != os.Stdout && f != os.Stderr {
		return f.Close()
	}
	return nil
}

// Compile-time interface verification.
var _ audit.AuditStore = (*MemoryAuditStore)(nil)
