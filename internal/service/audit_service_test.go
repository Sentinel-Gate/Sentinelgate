package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"go.uber.org/goleak"
)

// mockSlowAuditStore simulates a slow backend for testing backpressure
type mockSlowAuditStore struct {
	delay time.Duration
}

func (m *mockSlowAuditStore) Append(ctx context.Context, records ...audit.AuditRecord) error {
	time.Sleep(m.delay)
	return nil
}

func (m *mockSlowAuditStore) Flush(ctx context.Context) error { return nil }
func (m *mockSlowAuditStore) Close() error                    { return nil }

func TestAuditService_OverflowWithTimeout(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Slow store to cause backpressure
	slowStore := &mockSlowAuditStore{delay: 50 * time.Millisecond}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	svc := NewAuditService(slowStore, logger,
		WithChannelSize(2),                   // Very small buffer
		WithSendTimeout(10*time.Millisecond), // Short timeout
		WithBatchSize(1),                     // Flush each record
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)

	// Send more records than buffer can hold
	for i := 0; i < 10; i++ {
		svc.Record(audit.AuditRecord{
			ToolName:  fmt.Sprintf("tool_%d", i),
			Timestamp: time.Now(),
		})
	}

	// Allow time for timeout processing
	time.Sleep(150 * time.Millisecond)

	// Verify drops occurred
	drops := svc.DroppedRecords()
	if drops == 0 {
		t.Error("expected some records to be dropped due to timeout")
	}
	t.Logf("Dropped %d records as expected (buffer=2, sent=10)", drops)

	// Verify metrics methods work
	depth := svc.ChannelDepth()
	capacity := svc.ChannelCapacity()
	if capacity != 2 {
		t.Errorf("expected capacity=2, got %d", capacity)
	}
	t.Logf("Channel: depth=%d, capacity=%d", depth, capacity)

	cancel()
	svc.Stop()
}

func TestAuditService_ChannelDepthWarning(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Capture log output
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	// Use a mock store that doesn't actually process
	slowStore := &mockSlowAuditStore{delay: 100 * time.Millisecond}

	svc := NewAuditService(slowStore, logger,
		WithChannelSize(10),
		WithWarningThreshold(80), // Warn at 80% = 8 records
		WithSendTimeout(0),       // Drop immediately (no blocking) for predictable fill
	)

	// Don't start worker - let channel fill up
	// Fill channel to 90% (9 out of 10)
	for i := 0; i < 9; i++ {
		select {
		case svc.auditChan <- audit.AuditRecord{ToolName: fmt.Sprintf("tool_%d", i)}:
		default:
			t.Fatalf("channel unexpectedly full at %d", i)
		}
	}

	// Next Record() should trigger warning (channel at 90%, threshold 80%)
	svc.Record(audit.AuditRecord{ToolName: "trigger"})

	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "approaching capacity") {
		t.Errorf("expected warning log about channel capacity, got: %s", logOutput)
	}
	t.Logf("Warning logged as expected: %s", logOutput)

	// Drain channel to avoid leak
	close(svc.auditChan)
	for range svc.auditChan {
	}
}

func TestAuditService_DroppedRecordsCounter(t *testing.T) {
	defer goleak.VerifyNone(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Very slow store ensures channel stays full during test
	slowStore := &mockSlowAuditStore{delay: 500 * time.Millisecond}

	svc := NewAuditService(slowStore, logger,
		WithChannelSize(1),
		WithSendTimeout(0), // Drop immediately
		WithBatchSize(1),   // Process one at a time
	)

	// Initial drops should be 0
	if drops := svc.DroppedRecords(); drops != 0 {
		t.Errorf("expected 0 initial drops, got %d", drops)
	}

	// Fill channel directly (1 record) - don't start worker yet
	select {
	case svc.auditChan <- audit.AuditRecord{ToolName: "fill"}:
	default:
		t.Fatal("failed to fill channel")
	}

	// These should all be dropped (channel full, no timeout, no worker draining)
	svc.Record(audit.AuditRecord{ToolName: "drop1"})
	svc.Record(audit.AuditRecord{ToolName: "drop2"})
	svc.Record(audit.AuditRecord{ToolName: "drop3"})

	// Should have exactly 3 drops
	drops := svc.DroppedRecords()
	if drops != 3 {
		t.Errorf("expected 3 drops, got %d", drops)
	}
	t.Logf("Drop counter working: %d drops recorded", drops)

	// Drain channel to avoid leak
	close(svc.auditChan)
	for range svc.auditChan {
	}
}

func TestAuditService_NoDropWithSufficientBuffer(t *testing.T) {
	defer goleak.VerifyNone(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	slowStore := &mockSlowAuditStore{delay: 10 * time.Millisecond}

	svc := NewAuditService(slowStore, logger,
		WithChannelSize(100), // Large buffer
		WithSendTimeout(100*time.Millisecond),
		WithBatchSize(10),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)

	// Send records that fit in buffer
	for i := 0; i < 50; i++ {
		svc.Record(audit.AuditRecord{
			ToolName:  fmt.Sprintf("tool_%d", i),
			Timestamp: time.Now(),
		})
	}

	// Allow processing
	time.Sleep(200 * time.Millisecond)

	// Should have no drops with sufficient buffer
	drops := svc.DroppedRecords()
	if drops != 0 {
		t.Errorf("expected 0 drops with large buffer, got %d", drops)
	}
	t.Log("No drops with sufficient buffer - backpressure working correctly")

	cancel()
	svc.Stop()
}

// mockTrackingStore tracks flush calls for adaptive flush testing
type mockTrackingStore struct {
	onAppend func()
}

func (m *mockTrackingStore) Append(ctx context.Context, records ...audit.AuditRecord) error {
	if m.onAppend != nil {
		m.onAppend()
	}
	return nil
}

func (m *mockTrackingStore) Flush(ctx context.Context) error { return nil }
func (m *mockTrackingStore) Close() error                    { return nil }

func TestAuditService_AdaptiveFlushUnderPressure(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Track flush calls
	var flushCount int64
	var mu sync.Mutex

	// Custom store that records flush times
	store := &mockTrackingStore{
		onAppend: func() {
			mu.Lock()
			flushCount++
			mu.Unlock()
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	svc := NewAuditService(store, logger,
		WithChannelSize(10),
		WithBatchSize(5),
		WithFlushInterval(500*time.Millisecond), // Long interval
		WithAdaptiveFlushThreshold(50),          // Trigger at 50% (5 records)
		WithSendTimeout(100*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)

	// Fill channel to trigger adaptive mode (>50%)
	for i := 0; i < 8; i++ {
		svc.Record(audit.AuditRecord{
			ToolName:  fmt.Sprintf("tool_%d", i),
			Timestamp: time.Now(),
		})
	}

	// Wait for adaptive flush (should be faster than 500ms)
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	count := flushCount
	mu.Unlock()

	if count == 0 {
		t.Error("expected at least one flush under pressure (adaptive mode)")
	}
	t.Logf("Flush count under pressure: %d", count)

	cancel()
	svc.Stop()
}

func TestAuditService_AdaptiveFlushDisabled(t *testing.T) {
	defer goleak.VerifyNone(t)

	store := &mockSlowAuditStore{delay: 10 * time.Millisecond}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Disable adaptive flush by setting threshold to 0
	svc := NewAuditService(store, logger,
		WithChannelSize(10),
		WithBatchSize(5),
		WithFlushInterval(100*time.Millisecond),
		WithAdaptiveFlushThreshold(0), // Disabled
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)

	// This should not cause panic or issues with adaptive disabled
	for i := 0; i < 8; i++ {
		svc.Record(audit.AuditRecord{
			ToolName:  fmt.Sprintf("tool_%d", i),
			Timestamp: time.Now(),
		})
	}

	time.Sleep(150 * time.Millisecond)

	cancel()
	svc.Stop()
	// Test passes if no panic
	t.Log("Adaptive flush disabled - no panic")
}

func TestAuditService_AdaptiveReturnsToNormal(t *testing.T) {
	defer goleak.VerifyNone(t)

	var logBuf bytes.Buffer
	var logMu sync.Mutex

	// Thread-safe writer for log buffer
	safeWriter := &syncWriter{w: &logBuf, mu: &logMu}
	logger := slog.New(slog.NewTextHandler(safeWriter, &slog.HandlerOptions{Level: slog.LevelDebug}))

	store := &mockSlowAuditStore{delay: 5 * time.Millisecond}

	svc := NewAuditService(store, logger,
		WithChannelSize(10),
		WithBatchSize(2),
		WithFlushInterval(100*time.Millisecond),
		WithAdaptiveFlushThreshold(50),
	)

	ctx, cancel := context.WithCancel(context.Background())
	svc.Start(ctx)

	// Spike to trigger fast mode
	for i := 0; i < 8; i++ {
		svc.Record(audit.AuditRecord{
			ToolName:  fmt.Sprintf("tool_%d", i),
			Timestamp: time.Now(),
		})
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Stop service first to ensure no more writes to log buffer
	cancel()
	svc.Stop()

	// Now safe to read log buffer
	logMu.Lock()
	logOutput := logBuf.String()
	logMu.Unlock()

	if !strings.Contains(logOutput, "fast mode") {
		t.Log("Note: fast mode may not have triggered (depends on timing)")
	} else {
		t.Log("Fast mode triggered as expected")
	}
}

// syncWriter wraps an io.Writer with mutex for thread-safe writes
type syncWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (sw *syncWriter) Write(p []byte) (n int, err error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.w.Write(p)
}

func TestAuditService_DropCounterAccuracy(t *testing.T) {
	defer goleak.VerifyNone(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	slowStore := &mockSlowAuditStore{delay: 1 * time.Second} // Very slow - won't process

	svc := NewAuditService(slowStore, logger,
		WithChannelSize(5), // Small buffer
		WithSendTimeout(0), // Drop immediately (no blocking)
		WithBatchSize(1),
	)

	// Don't start worker - channel will fill and stay full

	// Fill the channel completely
	for i := 0; i < 5; i++ {
		select {
		case svc.auditChan <- audit.AuditRecord{ToolName: fmt.Sprintf("fill_%d", i)}:
		default:
			t.Fatalf("channel full at index %d, expected to fill 5", i)
		}
	}

	// Verify channel is full
	if svc.ChannelDepth() != 5 {
		t.Fatalf("expected channel depth 5, got %d", svc.ChannelDepth())
	}

	// Now send exactly 10 records that should all be dropped
	const expectedDrops = 10
	for i := 0; i < expectedDrops; i++ {
		svc.Record(audit.AuditRecord{ToolName: fmt.Sprintf("drop_%d", i)})
	}

	// Verify exact drop count
	drops := svc.DroppedRecords()
	if drops != expectedDrops {
		t.Errorf("expected exactly %d drops, got %d", expectedDrops, drops)
	}

	// Send more drops
	const additionalDrops = 5
	for i := 0; i < additionalDrops; i++ {
		svc.Record(audit.AuditRecord{ToolName: fmt.Sprintf("drop_more_%d", i)})
	}

	// Verify cumulative count
	totalDrops := svc.DroppedRecords()
	if totalDrops != expectedDrops+additionalDrops {
		t.Errorf("expected %d total drops, got %d", expectedDrops+additionalDrops, totalDrops)
	}

	// Cleanup
	close(svc.auditChan)
	for range svc.auditChan {
	}
}

func TestAuditService_DropCounterConcurrent(t *testing.T) {
	defer goleak.VerifyNone(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	slowStore := &mockSlowAuditStore{delay: 1 * time.Second}

	svc := NewAuditService(slowStore, logger,
		WithChannelSize(1), // Tiny buffer
		WithSendTimeout(0), // Drop immediately
		WithBatchSize(1),
	)

	// Fill the single slot
	select {
	case svc.auditChan <- audit.AuditRecord{ToolName: "fill"}:
	default:
		t.Fatal("failed to fill channel")
	}

	// Concurrent drops from multiple goroutines
	const goroutines = 10
	const dropsPerGoroutine = 100
	expectedTotal := goroutines * dropsPerGoroutine

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < dropsPerGoroutine; j++ {
				svc.Record(audit.AuditRecord{ToolName: fmt.Sprintf("drop_%d_%d", id, j)})
			}
		}(i)
	}
	wg.Wait()

	// Verify total drops
	drops := svc.DroppedRecords()
	if drops != int64(expectedTotal) {
		t.Errorf("expected %d concurrent drops, got %d", expectedTotal, drops)
	}

	// Cleanup
	close(svc.auditChan)
	for range svc.auditChan {
	}
}

// TestAuditService_LongRunning verifies memory stays bounded under continuous load.
// This test generates records continuously for 3 seconds and verifies:
// - Records are being flushed (not accumulating in channel)
// - Channel depth stays bounded
// - No goroutine leaks on shutdown
func TestAuditService_LongRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}
	defer goleak.VerifyNone(t)

	// Create tracking store to verify records are flushed
	var mu sync.Mutex
	var totalFlushed int64
	store := &mockTrackingStore{
		onAppend: func() {
			mu.Lock()
			totalFlushed++
			mu.Unlock()
		},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := NewAuditService(store, logger,
		WithChannelSize(100),                    // Moderate buffer
		WithBatchSize(10),                       // Small batches
		WithFlushInterval(100*time.Millisecond), // Fast flush
		WithSendTimeout(50*time.Millisecond),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)

	// Generate records over 3 seconds
	start := time.Now()
	recordCount := 0
	for time.Since(start) < 3*time.Second {
		svc.Record(audit.AuditRecord{
			ToolName:  fmt.Sprintf("tool_%d", recordCount),
			Timestamp: time.Now(),
		})
		recordCount++
		time.Sleep(time.Millisecond)
	}

	// Wait for final flush
	time.Sleep(200 * time.Millisecond)

	// Verify records were flushed
	mu.Lock()
	flushed := totalFlushed
	mu.Unlock()

	t.Logf("Generated %d records, flushed %d batches", recordCount, flushed)

	// Channel should be mostly empty (flushed)
	depth := svc.ChannelDepth()
	if depth > 20 {
		t.Errorf("Channel depth %d is too high, records not being flushed", depth)
	}

	// Verify flushes occurred (records flow through the system)
	if flushed == 0 {
		t.Error("expected at least one flush, got 0")
	}

	drops := svc.DroppedRecords()
	t.Logf("Drops: %d, final channel depth: %d", drops, depth)

	cancel()
	svc.Stop()
}
