package action

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
)

// QuarantineChecker is satisfied by ToolSecurityService.
type QuarantineChecker interface {
	IsQuarantined(toolName string) bool
}

// QuarantineInterceptor blocks calls to quarantined tools.
// It sits before the PolicyActionInterceptor in the chain so that
// quarantined tools are immediately rejected regardless of policy.
type QuarantineInterceptor struct {
	checker QuarantineChecker
	next    ActionInterceptor
	logger  *slog.Logger
}

// Compile-time check.
var _ ActionInterceptor = (*QuarantineInterceptor)(nil)

// NewQuarantineInterceptor creates a QuarantineInterceptor.
func NewQuarantineInterceptor(checker QuarantineChecker, next ActionInterceptor, logger *slog.Logger) *QuarantineInterceptor {
	return &QuarantineInterceptor{checker: checker, next: next, logger: logger}
}

// Intercept blocks quarantined tool calls, passes everything else through.
func (q *QuarantineInterceptor) Intercept(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
	if act.Type == ActionToolCall && q.checker.IsQuarantined(act.Name) {
		q.logger.Warn("tool call blocked: tool is quarantined",
			"tool", act.Name,
			"identity", act.Identity.Name,
		)
		return nil, fmt.Errorf("%w: tool %q is quarantined", proxy.ErrPolicyDenied, act.Name)
	}
	return q.next.Intercept(ctx, act)
}
