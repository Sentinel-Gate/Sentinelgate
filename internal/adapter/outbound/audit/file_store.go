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
	wg            sync.WaitGroup // L-33: tracks cleanup goroutine for graceful shutdown
	closeOnce     sync.Once
	closeErr      error
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

	// L-33: Track cleanup goroutine with WaitGroup for graceful shutdown.
	s.wg.Add(1)
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
		line := make([]byte, len(data)+1)
		copy(line, data)
		line[len(data)] = '\n'
		n, err := s.currentFile.Write(line)
		if err != nil {
			return fmt.Errorf("write audit record: %w", err)
		}
		s.currentSize += int64(n)

		// Add to cache
		s.cache.Add(rec)
	}

	// Fsync to ensure all records are persisted to disk.
	if err := s.currentFile.Sync(); err != nil {
		return fmt.Errorf("sync audit file: %w", err)
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
// L-33: Waits for the cleanup goroutine to finish before closing the file.
func (s *FileAuditStore) Close() error {
	s.closeOnce.Do(func() {
		// Cancel context to signal goroutines to stop.
		s.cancel()

		// L-33: Wait for the cleanup goroutine to finish outside the lock.
		// The goroutine may be running runCleanup which does not hold s.mu,
		// so this is safe. Waiting ensures no cleanup is in-flight when we
		// close the file.
		s.wg.Wait()

		s.mu.Lock()
		defer s.mu.Unlock()

		if s.currentFile != nil {
			_ = s.currentFile.Sync()
			s.closeErr = s.currentFile.Close()
			s.currentFile = nil
		}
	})
	return s.closeErr
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
// L-17: The new file is opened before closing the old one. If opening the new file
// fails, the old file remains valid and subsequent writes will not nil-pointer panic.
// Must be called with s.mu held.
func (s *FileAuditStore) rotateDateLocked(dateStr string) error {
	// L-17: Open new file first, before closing the old one.
	// If this fails, s.currentFile remains valid for subsequent writes.
	f, size, err := s.openFile(dateStr, 0)
	if err != nil {
		return err
	}

	// New file opened successfully — now close the old one.
	if s.currentFile != nil {
		if syncErr := s.currentFile.Sync(); syncErr != nil {
			s.logger.Error("failed to sync audit file during date rotation", "error", syncErr)
		}
		if closeErr := s.currentFile.Close(); closeErr != nil {
			s.logger.Error("failed to close audit file during date rotation", "error", closeErr)
		}
	}

	s.currentFile = f
	s.currentDate = dateStr
	s.currentSuffix = 0
	s.currentSize = size

	return nil
}

// rotateSizeLocked closes the current file and opens a new one with an incremented suffix.
// Must be called with s.mu held.
func (s *FileAuditStore) rotateSizeLocked() error {
	// L-1: Open the new file BEFORE closing the old one so that on failure
	// the old file remains valid and we do not lose audit records.
	nextSuffix := s.currentSuffix + 1
	f, size, err := s.openFile(s.currentDate, nextSuffix)
	if err != nil {
		return err
	}

	// New file opened successfully — now close the old one.
	if s.currentFile != nil {
		if syncErr := s.currentFile.Sync(); syncErr != nil {
			s.logger.Error("failed to sync audit file during size rotation", "error", syncErr)
		}
		if closeErr := s.currentFile.Close(); closeErr != nil {
			s.logger.Error("failed to close audit file during size rotation", "error", closeErr)
		}
	}

	s.currentFile = f
	s.currentSuffix = nextSuffix
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
// L-33: Defers wg.Done() so Close() can wait for this goroutine to finish.
func (s *FileAuditStore) startCleanupLoop(ctx context.Context) {
	defer s.wg.Done()
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

// populateCache reads recent audit files (newest first, scanning backwards)
// and fills the cache up to its configured capacity.
// L-18: Scans multiple files instead of just the most recent one, so the cache
// is fully populated even if the latest file has fewer entries than the cache size.
// Uses bufio.Scanner with a generous buffer (L-7: allows up to 10MB lines).
func (s *FileAuditStore) populateCache() {
	// L-18: Get all audit files sorted chronologically.
	sortedFiles := s.findSortedAuditFiles()
	if len(sortedFiles) == 0 {
		return
	}

	cacheSize := s.cache.size

	// L-18: Collect records from files in reverse order (most recent first),
	// stopping once we have enough to fill the cache.
	// We use a ring buffer to keep only the last cacheSize records per file,
	// then accumulate across files.
	var allRecords []audit.AuditRecord

	for i := len(sortedFiles) - 1; i >= 0 && len(allRecords) < cacheSize; i-- {
		records := s.readRecordsFromFile(sortedFiles[i].name, cacheSize-len(allRecords))
		if len(records) > 0 {
			// Prepend: older files go before newer files in chronological order.
			allRecords = append(records, allRecords...)
		}
	}

	// Trim to cache size (keep the most recent entries).
	if len(allRecords) > cacheSize {
		allRecords = allRecords[len(allRecords)-cacheSize:]
	}

	// Add records to cache in chronological order (oldest first).
	for _, rec := range allRecords {
		s.cache.Add(rec)
	}
}

// readRecordsFromFile reads up to maxRecords from a single audit file,
// keeping only the last maxRecords entries (most recent in the file).
func (s *FileAuditStore) readRecordsFromFile(filename string, maxRecords int) []audit.AuditRecord {
	path := filepath.Join(s.dir, filename)
	f, err := os.Open(path)
	if err != nil {
		s.logger.Error("audit cache: failed to open file for population",
			"file", filename, "error", err)
		return nil
	}
	defer func() { _ = f.Close() }()

	ring := make([]audit.AuditRecord, maxRecords)
	ringIdx := 0
	count := 0

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024) // L-7: allow up to 10MB lines
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec audit.AuditRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			s.logger.Warn("audit cache: skipping malformed record",
				"file", filename, "error", err)
			continue
		}
		ring[ringIdx%maxRecords] = rec
		ringIdx++
		count++
	}
	// L-32: Check scanner error after loop to detect truncated/corrupt reads.
	if err := scanner.Err(); err != nil {
		s.logger.Warn("audit cache: scanner error, cache may be incomplete",
			"file", filename, "error", err)
	}

	if count == 0 {
		return nil
	}

	n := count
	if n > maxRecords {
		n = maxRecords
	}

	result := make([]audit.AuditRecord, n)
	if count <= maxRecords {
		copy(result, ring[:n])
	} else {
		start := ringIdx % maxRecords
		for i := 0; i < n; i++ {
			result[i] = ring[(start+i)%maxRecords]
		}
	}

	return result
}

// findSortedAuditFiles returns all non-empty audit files sorted chronologically
// (oldest first). L-18: Used by populateCache to scan multiple files.
func (s *FileAuditStore) findSortedAuditFiles() []auditFileInfo {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
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

	sortAuditFiles(files)
	return files
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
