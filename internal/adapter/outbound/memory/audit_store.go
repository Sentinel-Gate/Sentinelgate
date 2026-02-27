// Package memory provides in-memory implementations of outbound ports.
package memory

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

const defaultRecentCap = 1000

// MemoryAuditStore implements audit.AuditStore writing to stdout or a file.
// Also keeps a bounded in-memory ring buffer for recent record queries.
type MemoryAuditStore struct {
	encoder *json.Encoder
	writer  io.Writer
	mu      sync.Mutex
	// recent is a bounded ring buffer of the most recent records.
	recent []audit.AuditRecord
	cap    int
}

// resolveCapacity returns the first positive capacity value, or defaultRecentCap.
func resolveCapacity(capacity ...int) int {
	if len(capacity) > 0 && capacity[0] > 0 {
		return capacity[0]
	}
	return defaultRecentCap
}

// NewAuditStore creates a new audit store writing to stdout.
// An optional capacity parameter sets the ring buffer size (default 1000).
func NewAuditStore(capacity ...int) *MemoryAuditStore {
	cap := resolveCapacity(capacity...)
	return &MemoryAuditStore{
		encoder: json.NewEncoder(os.Stdout),
		writer:  os.Stdout,
		recent:  make([]audit.AuditRecord, 0, cap),
		cap:     cap,
	}
}

// NewAuditStoreWithWriter creates an audit store writing to the given writer.
// An optional capacity parameter sets the ring buffer size (default 1000).
func NewAuditStoreWithWriter(w io.Writer, capacity ...int) *MemoryAuditStore {
	cap := resolveCapacity(capacity...)
	return &MemoryAuditStore{
		encoder: json.NewEncoder(w),
		writer:  w,
		recent:  make([]audit.AuditRecord, 0, cap),
		cap:     cap,
	}
}

// Append stores audit records by writing them as JSON to the output
// and keeping them in the in-memory ring buffer.
func (s *MemoryAuditStore) Append(ctx context.Context, records ...audit.AuditRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, r := range records {
		if err := s.encoder.Encode(r); err != nil {
			return err
		}
		// Add to ring buffer.
		if len(s.recent) >= s.cap {
			// Shift left, drop oldest.
			copy(s.recent, s.recent[1:])
			s.recent[len(s.recent)-1] = r
		} else {
			s.recent = append(s.recent, r)
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

// GetRecent returns the N most recent audit records (newest first).
func (s *MemoryAuditStore) GetRecent(n int) []audit.AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := len(s.recent)
	if n > total {
		n = total
	}
	if n == 0 {
		return nil
	}
	// Return newest first.
	result := make([]audit.AuditRecord, n)
	for i := 0; i < n; i++ {
		result[i] = s.recent[total-1-i]
	}
	return result
}

// Query retrieves audit records matching the filter from the in-memory buffer.
func (s *MemoryAuditStore) Query(filter audit.AuditFilter) ([]audit.AuditRecord, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	limit := filter.Limit
	if limit <= 0 || limit > 100 {
		limit = 100
	}

	var result []audit.AuditRecord
	// Iterate newest first.
	for i := len(s.recent) - 1; i >= 0 && len(result) < limit; i-- {
		rec := s.recent[i]
		if !filter.StartTime.IsZero() && rec.Timestamp.Before(filter.StartTime) {
			continue
		}
		if !filter.EndTime.IsZero() && rec.Timestamp.After(filter.EndTime) {
			continue
		}
		if filter.Decision != "" && !strings.EqualFold(rec.Decision, filter.Decision) {
			continue
		}
		if filter.ToolName != "" && rec.ToolName != filter.ToolName {
			continue
		}
		if filter.UserID != "" && rec.IdentityID != filter.UserID {
			continue
		}
		if filter.Protocol != "" && !strings.EqualFold(rec.Protocol, filter.Protocol) {
			continue
		}
		result = append(result, rec)
	}

	return result, "", nil
}

// Compile-time interface verification.
var _ audit.AuditStore = (*MemoryAuditStore)(nil)
