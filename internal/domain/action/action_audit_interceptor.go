package action

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
)

// ActionAuditInterceptor logs tool call decisions to the audit system.
// It wraps downstream interceptors to capture allow/deny outcomes.
// Native ActionInterceptor replacement for proxy.AuditInterceptor.
type ActionAuditInterceptor struct {
	recorder          proxy.AuditRecorder
	stats             proxy.StatsRecorder // optional, may be nil
	next              ActionInterceptor
	logger            *slog.Logger
	frameworkGetter   func(sessionID string) string // optional, returns client framework for session
	cbMu              sync.RWMutex
	recordingCallback func(audit.AuditRecord) // optional, spawned in goroutine
	callbackWg        sync.WaitGroup
}

// Compile-time check that ActionAuditInterceptor implements ActionInterceptor.
var _ ActionInterceptor = (*ActionAuditInterceptor)(nil)

// NewActionAuditInterceptor creates a new ActionAuditInterceptor.
func NewActionAuditInterceptor(
	recorder proxy.AuditRecorder,
	stats proxy.StatsRecorder,
	next ActionInterceptor,
	logger *slog.Logger,
) *ActionAuditInterceptor {
	return &ActionAuditInterceptor{
		recorder: recorder,
		stats:    stats,
		next:     next,
		logger:   logger,
	}
}

// Intercept records tool call decisions and passes actions to the next interceptor.
// Non-tool-call actions and responses are passed through without audit logging.
func (a *ActionAuditInterceptor) Intercept(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
	// Only audit tool calls with a name (skip protocol messages and responses)
	if act.Type != ActionToolCall || act.Name == "" {
		return a.next.Intercept(ctx, act)
	}

	startTime := time.Now()

	// Create scan, transform, quota warning, and policy decision holders in context for downstream interceptors
	ctx, scanHolder := audit.NewScanResultContext(ctx)
	ctx, transformHolder := audit.NewTransformResultContext(ctx)
	ctx, quotaWarningHolder := audit.NewQuotaWarningContext(ctx)
	ctx, policyHolder := audit.NewPolicyDecisionContext(ctx)

	// Call next interceptor to get decision
	result, err := a.next.Intercept(ctx, act)

	// Detect quota warnings (call succeeded but with warnings)
	hasQuotaWarnings := quotaWarningHolder != nil && len(quotaWarningHolder.Warnings) > 0

	// Record stats
	if a.stats != nil {
		if err == nil {
			if hasQuotaWarnings {
				a.stats.RecordWarned()
			} else {
				a.stats.RecordAllow()
			}
		} else {
			var rateLimitErr *proxy.RateLimitError
			if errors.As(err, &rateLimitErr) {
				a.stats.RecordRateLimited()
			} else if errors.Is(err, proxy.ErrQuotaExceeded) {
				a.stats.RecordBlocked()
			} else {
				a.stats.RecordDeny()
			}
		}
		a.stats.RecordProtocol(act.Protocol)
		a.cbMu.RLock()
		fg := a.frameworkGetter
		a.cbMu.RUnlock()
		if fg != nil {
			if fw := fg(act.Identity.SessionID); fw != "" {
				a.stats.RecordFramework(fw)
			}
		}
	}

	// Build audit record from CanonicalAction fields
	record := a.buildAuditRecord(act, startTime, err, hasQuotaWarnings)

	// Populate framework field from getter (same source as stats)
	a.cbMu.RLock()
	fwGetter := a.frameworkGetter
	a.cbMu.RUnlock()
	if fwGetter != nil {
		if fw := fwGetter(act.Identity.SessionID); fw != "" {
			record.Framework = fw
		}
	}

	// Extract response body from successful result for recording.
	if result != nil {
		record.ResponseBody = extractResponseText(result)
	}

	// Populate scan fields from holder (filled by ResponseScanInterceptor)
	if scanHolder != nil && scanHolder.Detections > 0 {
		record.ScanDetections = scanHolder.Detections
		record.ScanAction = scanHolder.Action
		record.ScanTypes = scanHolder.Types
	}

	// Populate transform fields from holder (filled by TransformInterceptor)
	if transformHolder != nil && len(transformHolder.Results) > 0 {
		record.TransformResults = transformHolder.Results
	}

	// Populate policy rule ID from holder (filled by PolicyActionInterceptor)
	if policyHolder != nil && policyHolder.RuleID != "" {
		record.RuleID = policyHolder.RuleID
	}

	// Record asynchronously (non-blocking)
	a.recorder.Record(record)

	// Invoke recording callback in a goroutine for zero latency impact
	a.cbMu.RLock()
	cb := a.recordingCallback
	a.cbMu.RUnlock()
	if cb != nil {
		a.callbackWg.Add(1)
		go func() {
			defer a.callbackWg.Done()
			cb(record)
		}()
	}

	a.logger.Debug("audit recorded",
		"tool", record.ToolName,
		"decision", record.Decision,
		"latency_us", record.LatencyMicros,
	)

	return result, err
}

// buildAuditRecord creates an AuditRecord from CanonicalAction fields.
func (a *ActionAuditInterceptor) buildAuditRecord(act *CanonicalAction, startTime time.Time, err error, hasQuotaWarnings bool) audit.AuditRecord {
	record := audit.AuditRecord{
		Timestamp:     startTime,
		LatencyMicros: time.Since(startTime).Microseconds(),
		Protocol:      act.Protocol,
	}

	// Identity from CanonicalAction
	if act.Identity.SessionID != "" {
		record.SessionID = act.Identity.SessionID
		record.IdentityID = act.Identity.ID
		record.IdentityName = act.Identity.Name
		record.Roles = act.Identity.Roles
	} else {
		record.SessionID = "anonymous"
		record.IdentityID = "anonymous"
	}

	// Tool info from CanonicalAction (already parsed by normalizer)
	record.ToolName = act.Name
	record.ToolArguments = audit.RedactSensitiveArgs(act.Arguments)

	// Decision based on error type
	if err == nil {
		if hasQuotaWarnings {
			record.Decision = audit.DecisionWarn
		} else {
			record.Decision = audit.DecisionAllow
		}
		record.Reason = ""
	} else if errors.Is(err, proxy.ErrQuotaExceeded) {
		record.Decision = audit.DecisionBlocked
		record.Reason = err.Error()
	} else {
		record.Decision = audit.DecisionDeny
		record.Reason = err.Error()
	}

	// Request ID from CanonicalAction
	record.RequestID = act.RequestID

	// RuleID is populated by the PolicyDecisionHolder after chain execution

	return record
}

// SetFrameworkGetter registers a function that returns the client framework name
// extracted from the MCP initialize handshake. This enables the Framework Activity
// widget in the admin dashboard.
func (a *ActionAuditInterceptor) SetFrameworkGetter(getter func(sessionID string) string) {
	a.cbMu.Lock()
	defer a.cbMu.Unlock()
	a.frameworkGetter = getter
}

// SetRecordingCallback registers an optional callback invoked asynchronously after
// each tool call is audited. Pass nil to remove the callback.
func (a *ActionAuditInterceptor) SetRecordingCallback(cb func(audit.AuditRecord)) {
	a.cbMu.Lock()
	a.recordingCallback = cb
	a.cbMu.Unlock()
}

// Drain blocks until all in-flight recording callbacks have completed.
// Uses a 5-second timeout to prevent shutdown hangs from stuck callbacks.
func (a *ActionAuditInterceptor) Drain() {
	done := make(chan struct{})
	go func() {
		a.callbackWg.Wait()
		close(done)
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		a.logger.Warn("drain timeout: some recording callbacks still in-flight after 5s")
	}
}
