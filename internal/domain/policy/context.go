package policy

import (
	"context"
	"time"
)

// SessionActionRecord captures a single tool call for session history analysis.
// This is a policy-level mirror of session.ActionRecord to avoid importing
// the session package into the policy package.
type SessionActionRecord struct {
	ToolName  string
	CallType  string // "read", "write", "delete", "other"
	Timestamp time.Time
	ArgKeys   []string
}

// EvaluationContext contains all information needed to evaluate a policy rule.
type EvaluationContext struct {
	// ToolName is the name of the tool being invoked.
	ToolName string
	// ToolArguments are the arguments passed to the tool.
	ToolArguments map[string]interface{}
	// UserRoles are the roles assigned to the user making the request.
	UserRoles []string
	// SessionID is the current session identifier.
	SessionID string
	// IdentityID is the authenticated user's identity identifier.
	IdentityID string
	// IdentityName is the human-readable name of the identity.
	IdentityName string
	// RequestTime is when the tool call was received.
	RequestTime time.Time

	// Framework context (Phase 19)
	// Framework identifies which framework is in use ("crewai", "autogen", or "").
	Framework string
	// FrameworkAttrs contains framework-specific attributes for CEL evaluation.
	// Keys follow the pattern "crewai.role", "autogen.agent_type", etc.
	FrameworkAttrs map[string]string

	// Universal fields (populated from CanonicalAction)
	// ActionType is the canonical action type: "tool_call", "http_request", "command_exec", etc.
	ActionType string
	// ActionName is the universal action name (alias for ToolName).
	ActionName string
	// Protocol is the originating protocol: "mcp", "http", "websocket", "runtime".
	Protocol string
	// Gateway is the gateway that received the request: "mcp-gateway", "http-gateway", "runtime".
	Gateway string

	// Destination fields
	// DestURL is the full destination URL for outbound requests.
	DestURL string
	// DestDomain is the destination domain name.
	DestDomain string
	// DestIP is the destination IP address.
	DestIP string
	// DestPort is the destination port number.
	DestPort int
	// DestScheme is the destination URL scheme (http, https, ws, wss).
	DestScheme string
	// DestPath is the destination URL path.
	DestPath string
	// DestCommand is the command being executed (for command_exec actions).
	DestCommand string

	// Session usage fields (Phase 15: Budget & Quota)
	// SessionCallCount is the total number of tool calls in the current session.
	SessionCallCount int64
	// SessionWriteCount is the number of write-type tool calls in the current session.
	SessionWriteCount int64
	// SessionDeleteCount is the number of delete-type tool calls in the current session.
	SessionDeleteCount int64
	// SessionDurationSeconds is the elapsed time since the session started, in seconds.
	SessionDurationSeconds int64
	// SessionCumulativeCost is the running cost total for the current session.
	SessionCumulativeCost float64

	// Session history fields (Phase 17: Session-Aware Policies)
	// SessionActionHistory is the ordered list of action records in the current session.
	// Each entry has ToolName, CallType, Timestamp, ArgKeys.
	// Used by session_sequence, session_count, session_count_window, session_time_since_action.
	SessionActionHistory []SessionActionRecord
	// SessionActionSet is the set of unique tool names called in the current session.
	// Used by session_has_action.
	SessionActionSet map[string]bool
	// SessionArgKeySet is the set of unique argument key names seen in the current session.
	// Used by session_has_arg.
	SessionArgKeySet map[string]bool

	// Agent Health variables (Upgrade 11: Health Dashboard)
	// UserDenyRate is the agent's deny rate (0.0 to 1.0) over the last 24h.
	UserDenyRate float64
	// UserDriftScore is the agent's behavioral drift score (0.0 to 1.0).
	UserDriftScore float64
	// UserViolationCount is the number of policy violations in the last 24h.
	UserViolationCount int64
	// UserTotalCalls is the total number of tool calls in the last 24h.
	UserTotalCalls int64
	// UserErrorRate is the agent's error rate (0.0 to 1.0) over the last 24h.
	UserErrorRate float64

	// SkipCache bypasses the result cache for this evaluation.
	// Used by the test/playground endpoint to ensure fresh results.
	SkipCache bool
}

// policyDecisionKey is the context key type for policy decisions.
type policyDecisionKey struct{}

// WithDecision stores a policy decision in the context.
// This allows downstream interceptors (e.g., ApprovalInterceptor) to access
// the decision made by PolicyInterceptor.
func WithDecision(ctx context.Context, d *Decision) context.Context {
	return context.WithValue(ctx, policyDecisionKey{}, d)
}

// DecisionFromContext retrieves a policy decision from the context.
// Returns nil if no decision is stored.
func DecisionFromContext(ctx context.Context) *Decision {
	d, _ := ctx.Value(policyDecisionKey{}).(*Decision)
	return d
}
