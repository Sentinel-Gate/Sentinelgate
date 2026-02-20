package service

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// mockFastAuditStore is a no-op store for benchmarking.
// Simulates fastest possible backend to measure channel/service overhead.
type mockFastAuditStore struct{}

func (m *mockFastAuditStore) Append(ctx context.Context, records ...audit.AuditRecord) error {
	return nil
}

func (m *mockFastAuditStore) Flush(ctx context.Context) error { return nil }
func (m *mockFastAuditStore) Close() error                    { return nil }

// BenchmarkAuditRecord measures audit record submission (fast path).
// Tests the hot path of submitting records to the channel.
func BenchmarkAuditRecord(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &mockFastAuditStore{}

	svc := NewAuditService(store, logger,
		WithChannelSize(10000), // Large buffer to avoid blocking
		WithBatchSize(100),
		WithFlushInterval(time.Second),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)

	record := audit.AuditRecord{
		ToolName:  "read_file",
		SessionID: "bench-session",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for b.Loop() {
		svc.Record(record)
	}

	b.StopTimer()
	cancel()
	svc.Stop()
}

// BenchmarkAuditRecordParallel measures concurrent audit submission.
// Tests channel send performance under multi-goroutine contention.
func BenchmarkAuditRecordParallel(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &mockFastAuditStore{}

	svc := NewAuditService(store, logger,
		WithChannelSize(100000), // Very large buffer for parallel
		WithBatchSize(100),
		WithFlushInterval(time.Second),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		record := audit.AuditRecord{
			ToolName:  "read_file",
			SessionID: "bench-session",
			Timestamp: time.Now(),
		}
		for pb.Next() {
			svc.Record(record)
		}
	})

	b.StopTimer()
	cancel()
	svc.Stop()
}

// BenchmarkAuditRecordWithBackpressure measures audit behavior under pressure.
// Uses a slow store and small buffer to trigger backpressure handling.
func BenchmarkAuditRecordWithBackpressure(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Slow store simulates real I/O latency
	store := &mockSlowAuditStore{delay: time.Microsecond}

	svc := NewAuditService(store, logger,
		WithChannelSize(100), // Smaller buffer to create pressure
		WithBatchSize(10),
		WithFlushInterval(10*time.Millisecond),
		WithSendTimeout(time.Millisecond), // Quick timeout for benchmark
		WithAdaptiveFlushThreshold(50),    // Lower threshold for testing
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)

	record := audit.AuditRecord{
		ToolName:  "read_file",
		SessionID: "bench-session",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for b.Loop() {
		svc.Record(record)
	}

	b.StopTimer()
	b.ReportMetric(float64(svc.DroppedRecords()), "drops")
	cancel()
	svc.Stop()
}

// BenchmarkAuditFlush measures batch flush performance.
// Tests the store.Append() call path without channel overhead.
func BenchmarkAuditFlush(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &mockFastAuditStore{}

	svc := NewAuditService(store, logger,
		WithChannelSize(10000),
		WithBatchSize(100),
		WithFlushInterval(time.Hour), // Disable timed flush
	)

	// Pre-fill batch data
	records := make([]audit.AuditRecord, 100)
	for i := range records {
		records[i] = audit.AuditRecord{
			ToolName:  "tool",
			SessionID: "session",
			Timestamp: time.Now(),
		}
	}

	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		svc.flush(ctx, records)
	}
}

// BenchmarkAuditChannelDepthCheck measures the overhead of depth warning check.
// This runs on every Record() call when warningThreshold > 0.
func BenchmarkAuditChannelDepthCheck(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := &mockFastAuditStore{}

	svc := NewAuditService(store, logger,
		WithChannelSize(10000),
		WithWarningThreshold(80), // Enable depth checking
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Start(ctx)

	record := audit.AuditRecord{
		ToolName:  "read_file",
		SessionID: "bench-session",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for b.Loop() {
		svc.Record(record)
	}

	b.StopTimer()
	cancel()
	svc.Stop()
}
