package quota

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// ErrQuotaExceeded is re-exported from proxy to avoid import cycles.
// Use proxy.ErrQuotaExceeded as the canonical sentinel.
var ErrQuotaExceeded = proxy.ErrQuotaExceeded

// QuotaDenyError wraps a quota denial with structured information.
type QuotaDenyError struct {
	Reason     string
	IdentityID string
}

// Error implements the error interface.
func (e *QuotaDenyError) Error() string {
	return fmt.Sprintf("quota exceeded: %s", e.Reason)
}

// Unwrap returns ErrQuotaExceeded so errors.Is works.
func (e *QuotaDenyError) Unwrap() error {
	return ErrQuotaExceeded
}

// QuotaInterceptor enforces per-identity quota limits on tool calls.
// Position in chain: between audit and policy interceptors.
type QuotaInterceptor struct {
	quotaService *QuotaService
	tracker      *session.SessionTracker
	next         proxy.MessageInterceptor
	logger       *slog.Logger
}

// Compile-time check that QuotaInterceptor implements MessageInterceptor.
var _ proxy.MessageInterceptor = (*QuotaInterceptor)(nil)

// NewQuotaInterceptor creates a new QuotaInterceptor.
func NewQuotaInterceptor(
	quotaService *QuotaService,
	tracker *session.SessionTracker,
	next proxy.MessageInterceptor,
	logger *slog.Logger,
) *QuotaInterceptor {
	return &QuotaInterceptor{
		quotaService: quotaService,
		tracker:      tracker,
		next:         next,
		logger:       logger,
	}
}

// Intercept enforces quota limits on tool calls.
// Non-tool-call messages and anonymous messages (no session) pass through unchanged.
func (q *QuotaInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// Non-tool-call messages pass through
	if !msg.IsToolCall() {
		return q.next.Intercept(ctx, msg)
	}

	// No session means anonymous — no quota applicable
	if msg.Session == nil {
		return q.next.Intercept(ctx, msg)
	}

	// Extract tool name from message params
	toolName := q.extractToolName(msg)

	// Check quota
	result := q.quotaService.Check(ctx, msg.Session.IdentityID, msg.Session.ID, toolName)

	if !result.Allowed {
		return nil, &QuotaDenyError{
			Reason:     result.DenyReason,
			IdentityID: msg.Session.IdentityID,
		}
	}

	// Log warnings if any
	for _, w := range result.Warnings {
		q.logger.Warn("quota warning",
			"identity_id", msg.Session.IdentityID,
			"session_id", msg.Session.ID,
			"warning", w,
		)
	}

	// Record the call AFTER check passes (count the call that's about to execute)
	argKeys := q.extractArgKeys(msg)
	q.tracker.RecordCall(msg.Session.ID, toolName, msg.Session.IdentityID, msg.Session.IdentityName, argKeys)

	return q.next.Intercept(ctx, msg)
}

// extractToolName extracts the tool name from message params.
func (q *QuotaInterceptor) extractToolName(msg *mcp.Message) string {
	req := msg.Request()
	if req == nil || req.Params == nil {
		return ""
	}

	var params struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		q.logger.Debug("failed to parse tool params for quota check", "error", err)
		return ""
	}

	return params.Name
}

// extractArgKeys extracts the argument key names from message params.
// MCP tools/call params: {"name": "...", "arguments": {"key1": ..., "key2": ...}}
func (q *QuotaInterceptor) extractArgKeys(msg *mcp.Message) []string {
	req := msg.Request()
	if req == nil || req.Params == nil {
		return nil
	}

	var params struct {
		Arguments map[string]json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil || len(params.Arguments) == 0 {
		return nil
	}

	keys := make([]string, 0, len(params.Arguments))
	for k := range params.Arguments {
		keys = append(keys, k)
	}
	return keys
}
