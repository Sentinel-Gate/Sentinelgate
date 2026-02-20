// Package audit provides file-based audit persistence with JSON Lines format,
// daily rotation, size caps, retention cleanup, and an in-memory cache.
package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// auditFileInfo holds parsed information about an audit file.
type auditFileInfo struct {
	name   string
	date   string
	suffix int
}

// parseAuditFilename parses an audit filename and returns its components.
func parseAuditFilename(name string) (auditFileInfo, bool) {
	matches := auditFilePattern.FindStringSubmatch(name)
	if matches == nil {
		return auditFileInfo{}, false
	}

	info := auditFileInfo{
		name: name,
		date: matches[1],
	}

	if matches[2] != "" {
		n, err := strconv.Atoi(matches[2])
		if err != nil {
			return auditFileInfo{}, false
		}
		info.suffix = n
	}

	return info, true
}

// sortAuditFiles sorts audit file info by date then suffix (chronological order).
func sortAuditFiles(files []auditFileInfo) {
	sort.Slice(files, func(i, j int) bool {
		if files[i].date != files[j].date {
			return files[i].date < files[j].date
		}
		return files[i].suffix < files[j].suffix
	})
}

// AuditFileConfig holds configuration for the file-based audit store.
type AuditFileConfig struct {
	// Dir is the directory where audit files are stored.
	Dir string
	// RetentionDays is the number of days to keep audit files (default 7).
	RetentionDays int
	// MaxFileSizeMB is the maximum file size in megabytes before rotation (default 100).
	MaxFileSizeMB int
	// CacheSize is the number of recent entries to keep in memory (default 1000).
	CacheSize int
}

// FileAuditStore implements audit.AuditStore with file rotation, retention, and cache.
type FileAuditStore struct {
	dir           string
	maxFileSize   int64
	retentionDays int
	currentFile   *os.File
	currentDate   string
	currentSize   int64
	currentSuffix int
	cache         *auditCache
	mu            sync.Mutex
	logger        *slog.Logger
	cancel        context.CancelFunc
	closed        bool
}

// auditFilePattern matches audit log filenames: audit-YYYY-MM-DD.log or audit-YYYY-MM-DD-N.log
var auditFilePattern = regexp.MustCompile(`^audit-(\d{4}-\d{2}-\d{2})(?:-(\d+))?\.log$`)

// NewFileAuditStore creates a new file-based audit store.
// It creates the directory if it does not exist, opens today's log file,
// runs retention cleanup, populates the cache from the most recent file,
// and starts the hourly cleanup goroutine.
func NewFileAuditStore(cfg AuditFileConfig, logger *slog.Logger) (*FileAuditStore, error) {
	// Apply defaults
	if cfg.RetentionDays <= 0 {
		cfg.RetentionDays = 7
	}
	if cfg.MaxFileSizeMB <= 0 {
		cfg.MaxFileSizeMB = 100
	}
	if cfg.CacheSize <= 0 {
		cfg.CacheSize = 1000
	}

	// Create directory with restricted permissions
	if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
		return nil, fmt.Errorf("create audit directory: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &FileAuditStore{
		dir:           cfg.Dir,
		maxFileSize:   int64(cfg.MaxFileSizeMB) * 1024 * 1024,
		retentionDays: cfg.RetentionDays,
		cache:         newAuditCache(cfg.CacheSize),
		logger:        logger,
		cancel:        cancel,
	}

	// Open today's log file
	today := time.Now().UTC().Format("2006-01-02")
	if err := s.openCurrentFile(today); err != nil {
		cancel()
		return nil, fmt.Errorf("open audit file: %w", err)
	}

	// Run retention cleanup at boot
	s.runCleanup()

	// Populate cache from most recent file
	s.populateCache()

	// Start hourly cleanup goroutine
	go s.startCleanupLoop(ctx)

	return s, nil
}

// Append stores audit records as JSON Lines to the current audit file.
// It handles date and size rotation as needed.
func (s *FileAuditStore) Append(ctx context.Context, records ...audit.AuditRecord) error {
	if len(records) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, rec := range records {
		dateStr := rec.Timestamp.UTC().Format("2006-01-02")

		// Check if date rotation is needed
		if dateStr != s.currentDate {
			if err := s.rotateDateLocked(dateStr); err != nil {
				return fmt.Errorf("date rotation: %w", err)
			}
		}

		// Check if size rotation is needed
		if s.currentSize >= s.maxFileSize {
			if err := s.rotateSizeLocked(); err != nil {
				return fmt.Errorf("size rotation: %w", err)
			}
		}

		// Marshal record as compact JSON (no indentation)
		data, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("marshal audit record: %w", err)
		}

		// Write JSON line
		line := append(data, '\n')
		n, err := s.currentFile.Write(line)
		if err != nil {
			return fmt.Errorf("write audit record: %w", err)
		}
		s.currentSize += int64(n)

		// Add to cache
		s.cache.Add(rec)
	}

	return nil
}

// Flush forces pending records to disk by syncing the current file.
func (s *FileAuditStore) Flush(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentFile != nil {
		return s.currentFile.Sync()
	}
	return nil
}

// Close releases resources, stops the cleanup goroutine, and closes the current file.
func (s *FileAuditStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	// Cancel the cleanup goroutine
	s.cancel()

	// Sync and close the current file
	if s.currentFile != nil {
		_ = s.currentFile.Sync()
		err := s.currentFile.Close()
		s.currentFile = nil
		return err
	}

	return nil
}

// GetRecent returns the last n audit records from the cache, newest first.
func (s *FileAuditStore) GetRecent(n int) []audit.AuditRecord {
	return s.cache.Recent(n)
}

// openCurrentFile opens or creates the audit file for the given date.
// It determines the correct suffix by checking existing files on disk.
func (s *FileAuditStore) openCurrentFile(dateStr string) error {
	// Find the highest existing suffix for this date
	suffix := s.findHighestSuffix(dateStr)

	f, size, err := s.openFile(dateStr, suffix)
	if err != nil {
		return err
	}

	s.currentFile = f
	s.currentDate = dateStr
	s.currentSize = size
	s.currentSuffix = suffix

	return nil
}

// findHighestSuffix returns the highest existing suffix for a date, or 0 if none.
func (s *FileAuditStore) findHighestSuffix(dateStr string) int {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0
	}

	highest := 0
	for _, e := range entries {
		info, ok := parseAuditFilename(e.Name())
		if !ok || info.date != dateStr {
			continue
		}
		if info.suffix > highest {
			highest = info.suffix
		}
	}

	return highest
}

// openFile opens an audit file with the given date and suffix.
// Returns the file handle and its current size.
func (s *FileAuditStore) openFile(dateStr string, suffix int) (*os.File, int64, error) {
	filename := s.buildFilename(dateStr, suffix)
	path := filepath.Join(s.dir, filename)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, 0, fmt.Errorf("open file %s: %w", filename, err)
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("stat file %s: %w", filename, err)
	}

	return f, info.Size(), nil
}

// buildFilename constructs the audit filename for a date and suffix.
func (s *FileAuditStore) buildFilename(dateStr string, suffix int) string {
	if suffix == 0 {
		return fmt.Sprintf("audit-%s.log", dateStr)
	}
	return fmt.Sprintf("audit-%s-%d.log", dateStr, suffix)
}

// rotateDateLocked closes the current file and opens a new one for the given date.
// Must be called with s.mu held.
func (s *FileAuditStore) rotateDateLocked(dateStr string) error {
	if s.currentFile != nil {
		_ = s.currentFile.Sync()
		_ = s.currentFile.Close()
		s.currentFile = nil
	}

	s.currentSuffix = 0
	s.currentSize = 0
	s.currentDate = dateStr

	f, size, err := s.openFile(dateStr, 0)
	if err != nil {
		return err
	}

	s.currentFile = f
	s.currentSize = size

	return nil
}

// rotateSizeLocked closes the current file and opens a new one with an incremented suffix.
// Must be called with s.mu held.
func (s *FileAuditStore) rotateSizeLocked() error {
	if s.currentFile != nil {
		_ = s.currentFile.Sync()
		_ = s.currentFile.Close()
		s.currentFile = nil
	}

	s.currentSuffix++
	s.currentSize = 0

	f, size, err := s.openFile(s.currentDate, s.currentSuffix)
	if err != nil {
		return err
	}

	s.currentFile = f
	s.currentSize = size

	return nil
}

// runCleanup deletes audit files older than the retention period.
func (s *FileAuditStore) runCleanup() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		s.logger.Error("audit cleanup: failed to read directory", "dir", s.dir, "error", err)
		return
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -s.retentionDays)
	deleted := 0

	for _, e := range entries {
		info, ok := parseAuditFilename(e.Name())
		if !ok {
			continue
		}

		fileDate, err := time.Parse("2006-01-02", info.date)
		if err != nil {
			continue
		}

		if fileDate.Before(cutoff) {
			path := filepath.Join(s.dir, e.Name())
			if err := os.Remove(path); err != nil {
				s.logger.Error("audit cleanup: failed to delete file",
					"file", e.Name(), "error", err)
			} else {
				deleted++
			}
		}
	}

	if deleted > 0 {
		s.logger.Info("audit cleanup completed", "deleted", deleted)
	}
}

// startCleanupLoop runs retention cleanup every hour until the context is cancelled.
func (s *FileAuditStore) startCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runCleanup()
		}
	}
}

// populateCache reads the most recent audit file and fills the cache.
func (s *FileAuditStore) populateCache() {
	// Find the most recent audit file
	mostRecent := s.findMostRecentFile()
	if mostRecent == "" {
		return
	}

	path := filepath.Join(s.dir, mostRecent)
	f, err := os.Open(path)
	if err != nil {
		s.logger.Error("audit cache: failed to open file for population",
			"file", mostRecent, "error", err)
		return
	}
	defer func() { _ = f.Close() }()

	// Read all lines and take the last cacheSize entries
	var records []audit.AuditRecord
	scanner := bufio.NewScanner(f)
	// Increase buffer for potentially large JSON lines
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var rec audit.AuditRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			s.logger.Warn("audit cache: skipping malformed line",
				"file", mostRecent, "error", err)
			continue
		}
		records = append(records, rec)
	}

	if err := scanner.Err(); err != nil {
		s.logger.Error("audit cache: error reading file",
			"file", mostRecent, "error", err)
	}

	// Take last cacheSize entries
	start := 0
	if len(records) > s.cache.size {
		start = len(records) - s.cache.size
	}

	// Add in chronological order so newest ends up as most recent in cache
	for _, rec := range records[start:] {
		s.cache.Add(rec)
	}
}

// findMostRecentFile returns the filename of the most recent non-empty audit file,
// or an empty string if none exist.
func (s *FileAuditStore) findMostRecentFile() string {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return ""
	}

	var files []auditFileInfo
	for _, e := range entries {
		info, ok := parseAuditFilename(e.Name())
		if !ok {
			continue
		}
		// Skip empty files
		finfo, err := e.Info()
		if err != nil || finfo.Size() == 0 {
			continue
		}
		files = append(files, info)
	}

	if len(files) == 0 {
		return ""
	}

	sortAuditFiles(files)

	// Return the last one (most recent date, highest suffix)
	return files[len(files)-1].name
}

// Compile-time interface verification.
var _ audit.AuditStore = (*FileAuditStore)(nil)

// auditCache is a ring buffer of recent audit entries for fast UI access.
type auditCache struct {
	entries []audit.AuditRecord
	size    int
	head    int
	count   int
	mu      sync.RWMutex
}

// newAuditCache creates a new cache with the given capacity.
func newAuditCache(size int) *auditCache {
	if size <= 0 {
		size = 1000
	}
	return &auditCache{
		entries: make([]audit.AuditRecord, size),
		size:    size,
	}
}

// Add adds a record to the ring buffer, overwriting the oldest entry if full.
func (c *auditCache) Add(rec audit.AuditRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[c.head] = rec
	c.head = (c.head + 1) % c.size
	if c.count < c.size {
		c.count++
	}
}

// Recent returns the last n entries, newest first.
// If n exceeds the number of entries, returns all entries.
func (c *auditCache) Recent(n int) []audit.AuditRecord {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if n <= 0 || c.count == 0 {
		return nil
	}

	if n > c.count {
		n = c.count
	}

	result := make([]audit.AuditRecord, n)
	for i := 0; i < n; i++ {
		// head points to next write position, so head-1 is most recent
		idx := (c.head - 1 - i + c.size) % c.size
		result[i] = c.entries[idx]
	}

	return result
}

// Len returns the number of entries currently in the cache.
func (c *auditCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.count
}
