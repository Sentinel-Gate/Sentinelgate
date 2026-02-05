package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// AuditRecorder records audit events.
// This interface is satisfied by AuditService.
type AuditRecorder interface {
	Record(record audit.AuditRecord)
}

// AuditInterceptor logs tool call decisions to the audit system.
// It wraps the PolicyInterceptor to capture allow/deny outcomes.
// Chain order: Auth -> Audit -> Policy -> Passthrough
type AuditInterceptor struct {
	recorder AuditRecorder
	next     MessageInterceptor
	logger   *slog.Logger
}

// NewAuditInterceptor creates a new AuditInterceptor.
func NewAuditInterceptor(
	recorder AuditRecorder,
	next MessageInterceptor,
	logger *slog.Logger,
) *AuditInterceptor {
	return &AuditInterceptor{
		recorder: recorder,
		next:     next,
		logger:   logger,
	}
}

// Intercept records tool call decisions and passes messages to the next interceptor.
// Non-tool-call messages are passed through without audit logging.
func (a *AuditInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// Only audit tool calls
	if !msg.IsToolCall() {
		return a.next.Intercept(ctx, msg)
	}

	// Record start time for latency measurement
	startTime := time.Now()

	// Call next interceptor (PolicyInterceptor) to get decision
	result, err := a.next.Intercept(ctx, msg)

	// Build audit record with context (for scan result)
	record := a.buildAuditRecord(ctx, msg, startTime, err)

	// Record asynchronously (non-blocking)
	a.recorder.Record(record)

	// Log at debug level
	a.logger.Debug("audit recorded",
		"tool", record.ToolName,
		"decision", record.Decision,
		"latency_us", record.LatencyMicros,
	)

	// Return original result and error unchanged
	return result, err
}

// buildAuditRecord creates an AuditRecord from the message and decision outcome.
func (a *AuditInterceptor) buildAuditRecord(ctx context.Context, msg *mcp.Message, startTime time.Time, err error) audit.AuditRecord {
	record := audit.AuditRecord{
		Timestamp:     startTime,
		LatencyMicros: time.Since(startTime).Microseconds(),
	}

	// Session context (may be nil if AuthInterceptor didn't run)
	if msg.Session != nil {
		record.SessionID = msg.Session.ID
		record.IdentityID = msg.Session.IdentityID
	} else {
		record.SessionID = "anonymous"
		record.IdentityID = "anonymous"
	}

	// Extract tool info from params
	record.ToolName, record.ToolArguments = a.extractToolInfo(msg)

	// Decision based on error from PolicyInterceptor
	if err == nil {
		record.Decision = audit.DecisionAllow
		record.Reason = ""
	} else {
		record.Decision = audit.DecisionDeny
		record.Reason = err.Error()
	}

	// Request ID for correlation (from JSON-RPC request ID)
	record.RequestID = a.extractRequestID(msg)

	// RuleID is empty for MVP - PolicyInterceptor returns error strings, not structured data
	record.RuleID = ""

	return record
}

// extractToolInfo extracts tool name and arguments from message params.
func (a *AuditInterceptor) extractToolInfo(msg *mcp.Message) (string, map[string]interface{}) {
	req := msg.Request()
	if req == nil || req.Params == nil {
		return msg.Method(), nil
	}

	// Parse tools/call params
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		a.logger.Debug("failed to parse tool params for audit", "error", err)
		return msg.Method(), nil
	}

	if params.Name == "" {
		return msg.Method(), params.Arguments
	}

	return params.Name, params.Arguments
}

// extractRequestID gets the JSON-RPC request ID for correlation.
func (a *AuditInterceptor) extractRequestID(msg *mcp.Message) string {
	req := msg.Request()
	if req == nil {
		return ""
	}

	// ID.Raw() returns the underlying value (string, float64, or nil)
	id := req.ID.Raw()
	if id == nil {
		return ""
	}

	return fmt.Sprintf("%v", id)
}

// Compile-time check that AuditInterceptor implements MessageInterceptor.
var _ MessageInterceptor = (*AuditInterceptor)(nil)
