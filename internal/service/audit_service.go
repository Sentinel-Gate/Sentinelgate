package service

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// AuditService provides async audit logging with a buffered channel and background worker.
// Tool calls are logged without blocking the proxy hot path.
type AuditService struct {
	store         audit.AuditStore
	auditChan     chan audit.AuditRecord
	done          chan struct{}
	wg            sync.WaitGroup
	logger        *slog.Logger
	batchSize     int
	flushInterval time.Duration

	// Phase 2 backpressure additions
	channelSize int           // Track capacity for monitoring
	sendTimeout time.Duration // 0 = drop immediately, >0 = block up to this duration
	dropCount   atomic.Int64  // Lock-free drop counter

	// Phase 2 channel depth warning
	warningThreshold int          // Percentage (0-100), e.g., 80
	lastWarning      atomic.Int64 // Rate-limit warning logs (Unix nanos)

	// Phase 5 adaptive flush
	adaptiveFlushThreshold int // Depth % that triggers faster flushing (default 80)
}

// AuditOption configures AuditService.
type AuditOption func(*AuditService)

// WithBatchSize sets the number of records to batch before writing.
func WithBatchSize(size int) AuditOption {
	return func(s *AuditService) {
		s.batchSize = size
	}
}

// WithFlushInterval sets the interval to flush pending records.
func WithFlushInterval(interval time.Duration) AuditOption {
	return func(s *AuditService) {
		s.flushInterval = interval
	}
}

// WithChannelSize sets the size of the audit channel buffer.
func WithChannelSize(size int) AuditOption {
	return func(s *AuditService) {
		s.auditChan = make(chan audit.AuditRecord, size)
		s.channelSize = size // Track capacity for monitoring
	}
}

// WithSendTimeout sets the backpressure timeout.
// 0 = drop immediately (no blocking), >0 = block up to this duration before dropping.
func WithSendTimeout(timeout time.Duration) AuditOption {
	return func(s *AuditService) {
		s.sendTimeout = timeout
	}
}

// WithWarningThreshold sets the channel depth warning percentage (0-100).
// A warning is logged when channel depth exceeds this percentage of capacity.
func WithWarningThreshold(percent int) AuditOption {
	return func(s *AuditService) {
		if percent < 0 {
			percent = 0
		}
		if percent > 100 {
			percent = 100
		}
		s.warningThreshold = percent
	}
}

// WithAdaptiveFlushThreshold sets the channel depth % that triggers faster flushing.
// When channel depth exceeds this %, flush interval is reduced to 1/4 normal.
// Default is 80%. Set to 0 to disable adaptive flushing.
func WithAdaptiveFlushThreshold(percent int) AuditOption {
	return func(s *AuditService) {
		if percent < 0 {
			percent = 0
		}
		if percent > 100 {
			percent = 100
		}
		s.adaptiveFlushThreshold = percent
	}
}

// NewAuditService creates a new AuditService with the given store and options.
func NewAuditService(store audit.AuditStore, logger *slog.Logger, opts ...AuditOption) *AuditService {
	defaultChannelSize := 1000
	s := &AuditService{
		store:                  store,
		auditChan:              make(chan audit.AuditRecord, defaultChannelSize), // 10x burst for 10 seconds
		done:                   make(chan struct{}),
		logger:                 logger,
		batchSize:              100,
		flushInterval:          time.Second,
		channelSize:            defaultChannelSize,     // Track capacity for monitoring
		sendTimeout:            100 * time.Millisecond, // Default 100ms backpressure
		warningThreshold:       80,                     // Warn at 80% full
		adaptiveFlushThreshold: 80,                     // Speed up flush at 80% full
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Start begins the background worker that batches and writes audit records.
func (s *AuditService) Start(ctx context.Context) {
	s.wg.Add(1)
	go s.worker(ctx)
}

// Record sends an audit record to the background worker.
// Applies backpressure: attempts fast non-blocking send, then blocks up to sendTimeout.
// If timeout expires, record is dropped and counted.
func (s *AuditService) Record(record audit.AuditRecord) {
	// Check channel depth for early warning (rate-limited)
	if s.warningThreshold > 0 {
		depth := len(s.auditChan)
		threshold := s.channelSize * s.warningThreshold / 100
		if depth >= threshold {
			s.warnChannelDepth(depth)
		}
	}

	// Fast path: non-blocking send
	select {
	case s.auditChan <- record:
		return // Sent successfully
	default:
		// Channel full - apply backpressure
	}

	// If no timeout configured, drop immediately (legacy behavior)
	if s.sendTimeout <= 0 {
		s.recordDrop(record)
		return
	}

	// Slow path: block with timeout
	select {
	case s.auditChan <- record:
		return // Sent after waiting
	case <-time.After(s.sendTimeout):
		s.recordDrop(record)
	}
}

// recordDrop increments counter and logs drop
func (s *AuditService) recordDrop(record audit.AuditRecord) {
	drops := s.dropCount.Add(1)
	s.logger.Warn("audit record dropped",
		"tool", record.ToolName,
		"session", record.SessionID,
		"total_drops", drops,
	)
}

// warnChannelDepth logs warning about channel capacity (rate-limited to once per second).
func (s *AuditService) warnChannelDepth(depth int) {
	now := time.Now().UnixNano()
	last := s.lastWarning.Load()

	// Only warn once per second
	if now-last < int64(time.Second) {
		return
	}

	// Try to claim this warning slot (CAS for thread safety)
	if s.lastWarning.CompareAndSwap(last, now) {
		s.logger.Warn("audit channel approaching capacity",
			"depth", depth,
			"capacity", s.channelSize,
			"percent", depth*100/s.channelSize,
		)
	}
}

// DroppedRecords returns total dropped records (for metrics/alerting).
func (s *AuditService) DroppedRecords() int64 {
	return s.dropCount.Load()
}

// ChannelDepth returns current channel usage (for monitoring).
func (s *AuditService) ChannelDepth() int {
	return len(s.auditChan)
}

// ChannelCapacity returns channel buffer size (for percentage calculation).
func (s *AuditService) ChannelCapacity() int {
	return s.channelSize
}

// Stop signals the worker to stop and waits for it to finish.
// Pending records are flushed before returning.
func (s *AuditService) Stop() {
	close(s.auditChan)
	s.wg.Wait()
}

// worker is the background goroutine that collects and flushes audit records.
func (s *AuditService) worker(ctx context.Context) {
	defer s.wg.Done()

	batch := make([]audit.AuditRecord, 0, s.batchSize)
	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	// Track whether we're in fast-flush mode
	fastMode := false

	for {
		select {
		case record, ok := <-s.auditChan:
			if !ok {
				// Channel closed - final flush with bounded deadline
				if len(batch) > 0 {
					flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
					s.flush(flushCtx, batch)
					flushCancel()
				}
				return
			}
			batch = append(batch, record)

			// Check if we should flush (batch full or adaptive trigger)
			shouldFlush := len(batch) >= s.batchSize

			// Adaptive: check channel depth and flush early if under pressure
			if !shouldFlush && s.adaptiveFlushThreshold > 0 && len(batch) > 0 {
				depth := len(s.auditChan)
				depthPercent := depth * 100 / s.channelSize
				if depthPercent >= s.adaptiveFlushThreshold {
					shouldFlush = true
				}
			}

			if shouldFlush {
				s.flush(ctx, batch)
				batch = batch[:0]
			}

			// Adaptive interval: adjust ticker based on channel pressure
			if s.adaptiveFlushThreshold > 0 {
				depth := len(s.auditChan)
				depthPercent := depth * 100 / s.channelSize

				if depthPercent >= s.adaptiveFlushThreshold && !fastMode {
					// Enter fast mode: 4x faster flush
					ticker.Reset(s.flushInterval / 4)
					fastMode = true
					s.logger.Debug("audit adaptive flush: entering fast mode",
						"depth_percent", depthPercent,
						"interval", s.flushInterval/4,
					)
				} else if depthPercent < s.adaptiveFlushThreshold && fastMode {
					// Return to normal mode
					ticker.Reset(s.flushInterval)
					fastMode = false
					s.logger.Debug("audit adaptive flush: returning to normal mode",
						"depth_percent", depthPercent,
						"interval", s.flushInterval,
					)
				}
			}

		case <-ticker.C:
			if len(batch) > 0 {
				s.flush(ctx, batch)
				batch = batch[:0]
			}

		case <-ctx.Done():
			// Context cancelled - drain channel and flush with bounded deadline
			for record := range s.auditChan {
				batch = append(batch, record)
			}
			if len(batch) > 0 {
				flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
				s.flush(flushCtx, batch)
				flushCancel()
			}
			return
		}
	}
}

// flush writes a batch of records to the store.
// Errors are logged but not propagated - audit should not fail proxy operations.
func (s *AuditService) flush(ctx context.Context, batch []audit.AuditRecord) {
	if err := s.store.Append(ctx, batch...); err != nil {
		s.logger.Error("failed to write audit batch",
			"error", err,
			"count", len(batch),
		)
	}
}
