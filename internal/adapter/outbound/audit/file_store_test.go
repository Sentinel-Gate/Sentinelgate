package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// testLogger returns a silent logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// makeRecord creates a test AuditRecord with the given timestamp and request ID.
func makeRecord(ts time.Time, reqID string) audit.AuditRecord {
	return audit.AuditRecord{
		Timestamp:  ts,
		SessionID:  "sess-1",
		IdentityID: "user-1",
		ToolName:   "test_tool",
		Decision:   audit.DecisionAllow,
		RequestID:  reqID,
	}
}

func TestNewFileAuditStore_CreatesDirectory(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "subdir", "audit")
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("Expected directory, got file")
	}
	// Check permissions (0700)
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("Directory permissions = %o, want 0700", perm)
	}
}

func TestFileAuditStore_AppendWritesJSONLines(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()

	records := []audit.AuditRecord{
		makeRecord(now, "req-1"),
		makeRecord(now, "req-2"),
		makeRecord(now, "req-3"),
	}

	if err := store.Append(ctx, records...); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	if err := store.Flush(ctx); err != nil {
		t.Fatalf("Flush() error: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	// Read the audit file and verify JSON Lines format
	dateStr := now.Format("2006-01-02")
	filename := filepath.Join(dir, fmt.Sprintf("audit-%s.log", dateStr))

	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read audit file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("Expected 3 lines, got %d", len(lines))
	}

	for i, line := range lines {
		var decoded audit.AuditRecord
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Errorf("Line %d is not valid JSON: %v", i, err)
			continue
		}
		expectedReqID := fmt.Sprintf("req-%d", i+1)
		if decoded.RequestID != expectedReqID {
			t.Errorf("Line %d RequestID = %q, want %q", i, decoded.RequestID, expectedReqID)
		}
	}
}

func TestFileAuditStore_DailyFileNaming(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()

	// Append a record for today
	if err := store.Append(ctx, makeRecord(now, "req-today")); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	if err := store.Flush(ctx); err != nil {
		t.Fatalf("Flush() error: %v", err)
	}
	_ = store.Close()

	// Verify file name matches pattern audit-YYYY-MM-DD.log
	dateStr := now.Format("2006-01-02")
	expectedFile := filepath.Join(dir, fmt.Sprintf("audit-%s.log", dateStr))

	if _, err := os.Stat(expectedFile); err != nil {
		t.Errorf("Expected audit file %s not found: %v", expectedFile, err)
	}
}

func TestFileAuditStore_DateRotation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	ctx := context.Background()
	day1 := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 2, 2, 10, 0, 0, 0, time.UTC)

	// Write record for day 1
	if err := store.Append(ctx, makeRecord(day1, "req-day1")); err != nil {
		t.Fatalf("Append() day1 error: %v", err)
	}

	// Write record for day 2 (should trigger rotation)
	if err := store.Append(ctx, makeRecord(day2, "req-day2")); err != nil {
		t.Fatalf("Append() day2 error: %v", err)
	}

	if err := store.Flush(ctx); err != nil {
		t.Fatalf("Flush() error: %v", err)
	}
	_ = store.Close()

	// Verify both files exist
	file1 := filepath.Join(dir, "audit-2026-02-01.log")
	file2 := filepath.Join(dir, "audit-2026-02-02.log")

	if _, err := os.Stat(file1); err != nil {
		t.Errorf("Day 1 audit file not found: %v", err)
	}
	if _, err := os.Stat(file2); err != nil {
		t.Errorf("Day 2 audit file not found: %v", err)
	}

	// Verify contents
	data1, _ := os.ReadFile(file1)
	data2, _ := os.ReadFile(file2)

	if !strings.Contains(string(data1), "req-day1") {
		t.Error("Day 1 file should contain req-day1")
	}
	if !strings.Contains(string(data2), "req-day2") {
		t.Error("Day 2 file should contain req-day2")
	}
}

func TestFileAuditStore_SizeRotation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 0, // Will use bytes directly
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	// Override maxFileSize to a small value for testing (500 bytes)
	store.maxFileSize = 500

	ctx := context.Background()
	now := time.Now().UTC()
	dateStr := now.Format("2006-01-02")

	// Write records until size rotation triggers
	for i := 0; i < 20; i++ {
		rec := makeRecord(now, fmt.Sprintf("req-%03d", i))
		rec.ToolArguments = map[string]interface{}{
			"data": strings.Repeat("x", 50), // make each record ~200+ bytes
		}
		if err := store.Append(ctx, rec); err != nil {
			t.Fatalf("Append() error at record %d: %v", i, err)
		}
	}

	_ = store.Close()

	// Verify the base file and at least one suffixed file exist
	baseFile := filepath.Join(dir, fmt.Sprintf("audit-%s.log", dateStr))
	suffixFile := filepath.Join(dir, fmt.Sprintf("audit-%s-1.log", dateStr))

	if _, err := os.Stat(baseFile); err != nil {
		t.Errorf("Base audit file not found: %v", err)
	}
	if _, err := os.Stat(suffixFile); err != nil {
		t.Errorf("Suffixed audit file not found: %v", err)
	}
}

func TestFileAuditStore_RetentionCleanup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create some old audit files
	oldDate := time.Now().UTC().AddDate(0, 0, -10)
	recentDate := time.Now().UTC().AddDate(0, 0, -3)

	oldFile := filepath.Join(dir, fmt.Sprintf("audit-%s.log", oldDate.Format("2006-01-02")))
	recentFile := filepath.Join(dir, fmt.Sprintf("audit-%s.log", recentDate.Format("2006-01-02")))

	if err := os.WriteFile(oldFile, []byte(`{"RequestID":"old"}`+"\n"), 0600); err != nil {
		t.Fatalf("Failed to create old file: %v", err)
	}
	if err := os.WriteFile(recentFile, []byte(`{"RequestID":"recent"}`+"\n"), 0600); err != nil {
		t.Fatalf("Failed to create recent file: %v", err)
	}

	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Old file (10 days) should be deleted
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Error("Old file (10 days) should have been deleted by retention cleanup")
	}

	// Recent file (3 days) should still exist
	if _, err := os.Stat(recentFile); err != nil {
		t.Error("Recent file (3 days) should NOT have been deleted")
	}
}

func TestFileAuditStore_RetentionCleanupWithSuffix(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create old suffixed files
	oldDate := time.Now().UTC().AddDate(0, 0, -10)
	oldFile1 := filepath.Join(dir, fmt.Sprintf("audit-%s.log", oldDate.Format("2006-01-02")))
	oldFile2 := filepath.Join(dir, fmt.Sprintf("audit-%s-1.log", oldDate.Format("2006-01-02")))

	_ = os.WriteFile(oldFile1, []byte("old\n"), 0600)
	_ = os.WriteFile(oldFile2, []byte("old-suffix\n"), 0600)

	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Both old files should be deleted
	if _, err := os.Stat(oldFile1); !os.IsNotExist(err) {
		t.Error("Old base file should have been deleted")
	}
	if _, err := os.Stat(oldFile2); !os.IsNotExist(err) {
		t.Error("Old suffixed file should have been deleted")
	}
}

func TestAuditCache_AddAndRecent(t *testing.T) {
	t.Parallel()

	cache := newAuditCache(5)

	for i := 0; i < 3; i++ {
		cache.Add(makeRecord(time.Now().UTC(), fmt.Sprintf("req-%d", i)))
	}

	if cache.Len() != 3 {
		t.Errorf("cache.Len() = %d, want 3", cache.Len())
	}

	recent := cache.Recent(2)
	if len(recent) != 2 {
		t.Fatalf("Recent(2) returned %d entries, want 2", len(recent))
	}

	// Newest first
	if recent[0].RequestID != "req-2" {
		t.Errorf("Recent[0].RequestID = %q, want %q", recent[0].RequestID, "req-2")
	}
	if recent[1].RequestID != "req-1" {
		t.Errorf("Recent[1].RequestID = %q, want %q", recent[1].RequestID, "req-1")
	}
}

func TestAuditCache_RingBufferOverflow(t *testing.T) {
	t.Parallel()

	cache := newAuditCache(3) // Only 3 slots

	// Add 5 records (overflow by 2)
	for i := 0; i < 5; i++ {
		cache.Add(makeRecord(time.Now().UTC(), fmt.Sprintf("req-%d", i)))
	}

	// Should only hold 3 entries
	if cache.Len() != 3 {
		t.Errorf("cache.Len() = %d, want 3", cache.Len())
	}

	// Should have the 3 most recent
	recent := cache.Recent(5) // request more than available
	if len(recent) != 3 {
		t.Fatalf("Recent(5) returned %d entries, want 3", len(recent))
	}

	// Newest first: req-4, req-3, req-2
	if recent[0].RequestID != "req-4" {
		t.Errorf("Recent[0].RequestID = %q, want %q", recent[0].RequestID, "req-4")
	}
	if recent[1].RequestID != "req-3" {
		t.Errorf("Recent[1].RequestID = %q, want %q", recent[1].RequestID, "req-3")
	}
	if recent[2].RequestID != "req-2" {
		t.Errorf("Recent[2].RequestID = %q, want %q", recent[2].RequestID, "req-2")
	}
}

func TestAuditCache_RecentEmpty(t *testing.T) {
	t.Parallel()

	cache := newAuditCache(5)

	recent := cache.Recent(3)
	if len(recent) != 0 {
		t.Errorf("Recent on empty cache returned %d entries, want 0", len(recent))
	}

	if cache.Len() != 0 {
		t.Errorf("Len on empty cache = %d, want 0", cache.Len())
	}
}

func TestAuditCache_RecentZero(t *testing.T) {
	t.Parallel()

	cache := newAuditCache(5)
	cache.Add(makeRecord(time.Now().UTC(), "req-1"))

	recent := cache.Recent(0)
	if len(recent) != 0 {
		t.Errorf("Recent(0) returned %d entries, want 0", len(recent))
	}
}

func TestFileAuditStore_CachePopulatedOnAppend(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()

	// Append records
	for i := 0; i < 5; i++ {
		if err := store.Append(ctx, makeRecord(now, fmt.Sprintf("req-%d", i))); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}

	// Verify cache has the records
	recent := store.GetRecent(3)
	if len(recent) != 3 {
		t.Fatalf("GetRecent(3) returned %d entries, want 3", len(recent))
	}

	// Newest first
	if recent[0].RequestID != "req-4" {
		t.Errorf("GetRecent[0].RequestID = %q, want %q", recent[0].RequestID, "req-4")
	}

	_ = store.Close()
}

func TestFileAuditStore_CachePopulatedAtBoot(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Pre-populate an audit file
	now := time.Now().UTC()
	dateStr := now.Format("2006-01-02")
	filename := filepath.Join(dir, fmt.Sprintf("audit-%s.log", dateStr))

	f, err := os.Create(filename)
	if err != nil {
		t.Fatalf("Failed to create pre-existing audit file: %v", err)
	}
	enc := json.NewEncoder(f)
	for i := 0; i < 10; i++ {
		rec := makeRecord(now.Add(time.Duration(i)*time.Second), fmt.Sprintf("boot-req-%d", i))
		if err := enc.Encode(rec); err != nil {
			t.Fatalf("Failed to write record: %v", err)
		}
	}
	_ = f.Close()

	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     5,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Cache should have last 5 entries from the file
	recent := store.GetRecent(10)
	if len(recent) != 5 {
		t.Fatalf("GetRecent(10) returned %d entries, want 5 (cache size)", len(recent))
	}

	// Newest first: boot-req-9, boot-req-8, ..., boot-req-5
	if recent[0].RequestID != "boot-req-9" {
		t.Errorf("GetRecent[0].RequestID = %q, want %q", recent[0].RequestID, "boot-req-9")
	}
	if recent[4].RequestID != "boot-req-5" {
		t.Errorf("GetRecent[4].RequestID = %q, want %q", recent[4].RequestID, "boot-req-5")
	}
}

func TestFileAuditStore_GetRecentReturnsNewestFirst(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()

	for i := 0; i < 10; i++ {
		ts := now.Add(time.Duration(i) * time.Second)
		if err := store.Append(ctx, makeRecord(ts, fmt.Sprintf("req-%d", i))); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}

	recent := store.GetRecent(5)
	if len(recent) != 5 {
		t.Fatalf("GetRecent(5) returned %d entries, want 5", len(recent))
	}

	// Verify newest first order
	for i, r := range recent {
		expectedID := fmt.Sprintf("req-%d", 9-i)
		if r.RequestID != expectedID {
			t.Errorf("GetRecent[%d].RequestID = %q, want %q", i, r.RequestID, expectedID)
		}
	}

	_ = store.Close()
}

func TestFileAuditStore_ConcurrentAppend(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     1000,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// 100 concurrent appends
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rec := makeRecord(now, fmt.Sprintf("concurrent-%d", idx))
			if err := store.Append(ctx, rec); err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent Append() error: %v", err)
	}

	if err := store.Flush(ctx); err != nil {
		t.Fatalf("Flush() error: %v", err)
	}
	_ = store.Close()

	// Count total lines written across all files
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir error: %v", err)
	}

	totalLines := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "audit-") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("ReadFile error: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if lines[0] != "" {
			totalLines += len(lines)
		}
	}

	if totalLines != 100 {
		t.Errorf("Expected 100 total lines, got %d", totalLines)
	}
}

func TestFileAuditStore_FlushSyncsFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()

	if err := store.Append(ctx, makeRecord(now, "req-flush")); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	// Flush should not error
	if err := store.Flush(ctx); err != nil {
		t.Errorf("Flush() error: %v", err)
	}

	_ = store.Close()

	// Verify data is on disk after flush
	dateStr := now.Format("2006-01-02")
	filename := filepath.Join(dir, fmt.Sprintf("audit-%s.log", dateStr))
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile after flush error: %v", err)
	}
	if !strings.Contains(string(data), "req-flush") {
		t.Error("Data not found on disk after Flush()")
	}
}

func TestFileAuditStore_CloseStopsCleanup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	// Close should not error and should stop cleanup goroutine
	if err := store.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}

	// Double close should not panic
	if err := store.Close(); err != nil {
		t.Errorf("Double Close() error: %v", err)
	}
}

func TestFileAuditStore_FilePermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()

	if err := store.Append(ctx, makeRecord(now, "req-perm")); err != nil {
		t.Fatalf("Append() error: %v", err)
	}
	_ = store.Close()

	dateStr := now.Format("2006-01-02")
	filename := filepath.Join(dir, fmt.Sprintf("audit-%s.log", dateStr))

	info, err := os.Stat(filename)
	if err != nil {
		t.Fatalf("Stat error: %v", err)
	}

	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("File permissions = %o, want 0600", perm)
	}
}

func TestFileAuditStore_ImplementsAuditStoreInterface(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Compile-time interface check
	var _ audit.AuditStore = store
}

func TestFileAuditStore_DefaultConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir: dir,
		// Leave all optional fields at zero values
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Verify defaults were applied
	if store.retentionDays != 7 {
		t.Errorf("Default retentionDays = %d, want 7", store.retentionDays)
	}
	if store.maxFileSize != 100*1024*1024 {
		t.Errorf("Default maxFileSize = %d, want %d", store.maxFileSize, 100*1024*1024)
	}
	if store.cache.size != 1000 {
		t.Errorf("Default cache size = %d, want 1000", store.cache.size)
	}
}

func TestFileAuditStore_AppendToExistingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create an existing audit file with some content
	now := time.Now().UTC()
	dateStr := now.Format("2006-01-02")
	filename := filepath.Join(dir, fmt.Sprintf("audit-%s.log", dateStr))

	existing := makeRecord(now.Add(-time.Hour), "existing-req")
	data, _ := json.Marshal(existing)
	_ = os.WriteFile(filename, append(data, '\n'), 0600)

	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	// Append a new record
	if err := store.Append(context.Background(), makeRecord(now, "new-req")); err != nil {
		t.Fatalf("Append() error: %v", err)
	}
	_ = store.Close()

	// Read file and verify both records exist
	fileData, _ := os.ReadFile(filename)
	lines := strings.Split(strings.TrimSpace(string(fileData)), "\n")
	if len(lines) != 2 {
		t.Fatalf("Expected 2 lines in file, got %d", len(lines))
	}

	if !strings.Contains(lines[0], "existing-req") {
		t.Error("First line should contain existing-req")
	}
	if !strings.Contains(lines[1], "new-req") {
		t.Error("Second line should contain new-req")
	}
}

func TestFileAuditStore_SizeRotationFileName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 0,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	// Very small max to force multiple rotations
	store.maxFileSize = 200

	ctx := context.Background()
	now := time.Now().UTC()
	dateStr := now.Format("2006-01-02")

	// Write enough records to trigger multiple rotations
	for i := 0; i < 30; i++ {
		rec := makeRecord(now, fmt.Sprintf("req-%03d", i))
		rec.ToolArguments = map[string]interface{}{"k": strings.Repeat("v", 50)}
		if err := store.Append(ctx, rec); err != nil {
			t.Fatalf("Append() error: %v", err)
		}
	}
	_ = store.Close()

	// Verify multiple suffixed files exist
	entries, _ := os.ReadDir(dir)
	var fileInfos []auditFileInfo
	for _, e := range entries {
		info, ok := parseAuditFilename(e.Name())
		if ok && strings.HasPrefix(e.Name(), "audit-"+dateStr) {
			fileInfos = append(fileInfos, info)
		}
	}

	sortAuditFiles(fileInfos)

	if len(fileInfos) < 3 {
		t.Errorf("Expected at least 3 audit files after size rotation, got %d", len(fileInfos))
	}

	// Verify naming pattern
	expectedBase := fmt.Sprintf("audit-%s.log", dateStr)
	expectedSuffix1 := fmt.Sprintf("audit-%s-1.log", dateStr)
	expectedSuffix2 := fmt.Sprintf("audit-%s-2.log", dateStr)

	if fileInfos[0].name != expectedBase {
		t.Errorf("First file = %q, want %q", fileInfos[0].name, expectedBase)
	}
	if fileInfos[1].name != expectedSuffix1 {
		t.Errorf("Second file = %q, want %q", fileInfos[1].name, expectedSuffix1)
	}
	if len(fileInfos) > 2 && fileInfos[2].name != expectedSuffix2 {
		t.Errorf("Third file = %q, want %q", fileInfos[2].name, expectedSuffix2)
	}
}

func TestFileAuditStore_CleanupPreservesTodaysFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create today's file
	todayStr := time.Now().UTC().Format("2006-01-02")
	todayFile := filepath.Join(dir, fmt.Sprintf("audit-%s.log", todayStr))
	_ = os.WriteFile(todayFile, []byte(`{"RequestID":"today"}`+"\n"), 0600)

	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Today's file should still exist
	if _, err := os.Stat(todayFile); err != nil {
		t.Errorf("Today's file should not be deleted by cleanup: %v", err)
	}
}

func TestFileAuditStore_AppendEmptyRecords(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Append with no records should not error
	if err := store.Append(context.Background()); err != nil {
		t.Errorf("Append() with no records error: %v", err)
	}
}

func TestFileAuditStore_PopulateCacheFromMostRecentFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create files for two different dates
	oldDate := time.Now().UTC().AddDate(0, 0, -2)
	recentDate := time.Now().UTC().AddDate(0, 0, -1)

	oldFile := filepath.Join(dir, fmt.Sprintf("audit-%s.log", oldDate.Format("2006-01-02")))
	recentFile := filepath.Join(dir, fmt.Sprintf("audit-%s.log", recentDate.Format("2006-01-02")))

	// Write to old file
	f1, _ := os.Create(oldFile)
	enc1 := json.NewEncoder(f1)
	for i := 0; i < 5; i++ {
		_ = enc1.Encode(makeRecord(oldDate, fmt.Sprintf("old-%d", i)))
	}
	_ = f1.Close()

	// Write to recent file
	f2, _ := os.Create(recentFile)
	enc2 := json.NewEncoder(f2)
	for i := 0; i < 5; i++ {
		_ = enc2.Encode(makeRecord(recentDate, fmt.Sprintf("recent-%d", i)))
	}
	_ = f2.Close()

	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     3,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Cache should contain entries from the most recent file
	recent := store.GetRecent(10)
	if len(recent) != 3 {
		t.Fatalf("GetRecent(10) returned %d entries, want 3", len(recent))
	}

	// Should be from the recent file, newest first
	if recent[0].RequestID != "recent-4" {
		t.Errorf("GetRecent[0].RequestID = %q, want %q", recent[0].RequestID, "recent-4")
	}
}

func TestFileAuditStore_JSONFormatNoIndentation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()

	rec := makeRecord(now, "req-format")
	rec.ToolArguments = map[string]interface{}{"key": "value", "nested": map[string]interface{}{"a": 1}}

	if err := store.Append(ctx, rec); err != nil {
		t.Fatalf("Append() error: %v", err)
	}
	_ = store.Close()

	dateStr := now.Format("2006-01-02")
	filename := filepath.Join(dir, fmt.Sprintf("audit-%s.log", dateStr))

	data, _ := os.ReadFile(filename)
	content := strings.TrimSpace(string(data))

	// Should be a single line (no newlines within JSON, no indentation)
	lines := strings.Split(content, "\n")
	if len(lines) != 1 {
		t.Errorf("JSON should be single line, got %d lines", len(lines))
	}

	// Should not contain indentation
	if strings.Contains(content, "  ") {
		t.Error("JSON should not contain indentation")
	}

	// Should be valid JSON
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(content), &decoded); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}
}

func TestAuditCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	cache := newAuditCache(100)

	var wg sync.WaitGroup

	// Concurrent writers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cache.Add(makeRecord(time.Now().UTC(), fmt.Sprintf("req-%d", idx)))
		}(i)
	}

	// Concurrent readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cache.Recent(10)
			_ = cache.Len()
		}()
	}

	wg.Wait()

	// Should not panic and should have entries
	if cache.Len() == 0 {
		t.Error("Cache should have entries after concurrent writes")
	}
}

func TestFileAuditStore_PopulateCacheFromEmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Cache should be empty when no existing files
	recent := store.GetRecent(10)
	if len(recent) != 0 {
		t.Errorf("GetRecent on empty dir returned %d entries, want 0", len(recent))
	}
}

func TestFileAuditStore_LargeBootPopulation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Create a file with many records
	now := time.Now().UTC()
	dateStr := now.Format("2006-01-02")
	filename := filepath.Join(dir, fmt.Sprintf("audit-%s.log", dateStr))

	f, _ := os.Create(filename)
	enc := json.NewEncoder(f)
	for i := 0; i < 2000; i++ {
		_ = enc.Encode(makeRecord(now.Add(time.Duration(i)*time.Millisecond), fmt.Sprintf("large-%d", i)))
	}
	_ = f.Close()

	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Cache should have exactly cacheSize entries
	recent := store.GetRecent(200)
	if len(recent) != 100 {
		t.Fatalf("GetRecent(200) returned %d entries, want 100 (cache size)", len(recent))
	}

	// Should be the last 100 records, newest first
	if recent[0].RequestID != "large-1999" {
		t.Errorf("GetRecent[0].RequestID = %q, want %q", recent[0].RequestID, "large-1999")
	}
}

func TestFileAuditStore_PopulateCacheHandlesMalformedLines(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	now := time.Now().UTC()
	dateStr := now.Format("2006-01-02")
	filename := filepath.Join(dir, fmt.Sprintf("audit-%s.log", dateStr))

	// Write a mix of valid and invalid JSON lines
	f, _ := os.Create(filename)
	validRec := makeRecord(now, "valid-1")
	data, _ := json.Marshal(validRec)
	_, _ = fmt.Fprintf(f, "%s\n", data)
	_, _ = fmt.Fprintf(f, "this is not json\n")
	validRec2 := makeRecord(now, "valid-2")
	data2, _ := json.Marshal(validRec2)
	_, _ = fmt.Fprintf(f, "%s\n", data2)
	_ = f.Close()

	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Should have loaded the 2 valid records, skipping the bad line
	recent := store.GetRecent(10)
	if len(recent) != 2 {
		t.Fatalf("GetRecent(10) returned %d entries, want 2", len(recent))
	}
}

func TestFileAuditStore_AllFieldsSerialized(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := AuditFileConfig{
		Dir:           dir,
		RetentionDays: 7,
		MaxFileSizeMB: 100,
		CacheSize:     100,
	}

	store, err := NewFileAuditStore(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewFileAuditStore() error: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	rec := audit.AuditRecord{
		Timestamp:      now,
		SessionID:      "sess-full",
		IdentityID:     "user-full",
		ToolName:       "full_tool",
		ToolArguments:  map[string]interface{}{"path": "/etc/passwd"},
		Decision:       audit.DecisionDeny,
		Reason:         "blocked by policy",
		RuleID:         "rule-42",
		RequestID:      "req-full",
		LatencyMicros:  2500,
		ScanDetections: 3,
		ScanAction:     "redacted",
		ScanTypes:      "secret,pii,injection",
	}

	if err := store.Append(ctx, rec); err != nil {
		t.Fatalf("Append() error: %v", err)
	}
	_ = store.Close()

	// Read and decode
	dateStr := now.Format("2006-01-02")
	filename := filepath.Join(dir, fmt.Sprintf("audit-%s.log", dateStr))
	data, _ := os.ReadFile(filename)

	// Read using scanner to handle the JSON line
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	if !scanner.Scan() {
		t.Fatal("No lines in file")
	}

	var decoded audit.AuditRecord
	if err := json.Unmarshal(scanner.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}

	if decoded.SessionID != "sess-full" {
		t.Errorf("SessionID = %q, want %q", decoded.SessionID, "sess-full")
	}
	if decoded.Decision != audit.DecisionDeny {
		t.Errorf("Decision = %q, want %q", decoded.Decision, audit.DecisionDeny)
	}
	if decoded.Reason != "blocked by policy" {
		t.Errorf("Reason = %q, want %q", decoded.Reason, "blocked by policy")
	}
	if decoded.RuleID != "rule-42" {
		t.Errorf("RuleID = %q, want %q", decoded.RuleID, "rule-42")
	}
	if decoded.LatencyMicros != 2500 {
		t.Errorf("LatencyMicros = %d, want %d", decoded.LatencyMicros, 2500)
	}
	if decoded.ScanDetections != 3 {
		t.Errorf("ScanDetections = %d, want %d", decoded.ScanDetections, 3)
	}
	if decoded.ScanAction != "redacted" {
		t.Errorf("ScanAction = %q, want %q", decoded.ScanAction, "redacted")
	}
	if decoded.ScanTypes != "secret,pii,injection" {
		t.Errorf("ScanTypes = %q, want %q", decoded.ScanTypes, "secret,pii,injection")
	}
}
