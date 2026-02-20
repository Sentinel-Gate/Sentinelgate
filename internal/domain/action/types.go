// Package action defines the CanonicalAction type system: a protocol-agnostic
// representation of any agent action flowing through SentinelGate.
// Every action — regardless of protocol (MCP, HTTP, WebSocket, runtime) —
// is normalized into a CanonicalAction for uniform policy evaluation.
package action

import "time"

// ActionType categorizes the kind of action being performed.
type ActionType string

const (
	// ActionToolCall represents an MCP tools/call or equivalent tool invocation.
	ActionToolCall ActionType = "tool_call"
	// ActionHTTPRequest represents an outbound HTTP request from an agent.
	ActionHTTPRequest ActionType = "http_request"
	// ActionWebSocketMessage represents a WebSocket message.
	ActionWebSocketMessage ActionType = "websocket_message"
	// ActionCommandExec represents a command execution (shell, subprocess).
	ActionCommandExec ActionType = "command_exec"
	// ActionFileAccess represents a file read/write/delete operation.
	ActionFileAccess ActionType = "file_access"
	// ActionNetworkConnect represents a raw network connection attempt.
	ActionNetworkConnect ActionType = "network_connect"
	// ActionSampling represents an MCP sampling/createMessage request.
	ActionSampling ActionType = "sampling"
	// ActionElicitation represents an MCP elicitation/create request.
	ActionElicitation ActionType = "elicitation"
)

// String returns the string representation of the ActionType.
func (t ActionType) String() string {
	return string(t)
}

// Destination captures where an action is directed: URL, domain, IP, port,
// scheme, path, command, and command arguments.
type Destination struct {
	// URL is the full URL if available.
	URL string
	// Domain is the domain name (e.g., "api.example.com").
	Domain string
	// IP is the resolved IP address.
	IP string
	// Port is the port number (0 = unset).
	Port int
	// Scheme is the protocol scheme (http, https, ws, wss, etc.).
	Scheme string
	// Path is the URL path or file path.
	Path string
	// Command is the command name for command_exec actions.
	Command string
	// CmdArgs are the command arguments for command_exec actions.
	CmdArgs []string
}

// ActionIdentity represents the WHO of an action: the actor performing it.
type ActionIdentity struct {
	// ID is the unique identifier for the actor.
	ID string
	// Name is the display name of the actor.
	Name string
	// Roles are the roles assigned to the actor.
	Roles []string
	// SessionID is the session identifier for the actor.
	SessionID string
}

// CanonicalAction is the universal representation of any agent action.
// It uses a WHO/WHAT/WHERE/HOW/CONTEXT model to capture all relevant
// information for policy evaluation, regardless of the originating protocol.
type CanonicalAction struct {
	// --- WHO ---

	// Identity identifies the actor performing the action.
	Identity ActionIdentity

	// --- WHAT ---

	// Type categorizes the action (tool_call, http_request, etc.).
	Type ActionType
	// Name is the action name (tool name, HTTP method, command name, etc.).
	Name string
	// Arguments contains the action parameters (tool args, query params, etc.).
	Arguments map[string]interface{}

	// --- WHERE ---

	// Destination captures the target of the action.
	Destination Destination

	// --- HOW ---

	// Protocol is the originating protocol (mcp, http, websocket, runtime).
	Protocol string
	// Framework is the agent framework (crewai, autogen, langchain, etc.).
	Framework string
	// Gateway is the gateway that received the action (mcp-gateway, http-gateway, runtime).
	Gateway string

	// --- CONTEXT ---

	// RequestTime is when the action was received.
	RequestTime time.Time
	// RequestID uniquely identifies this action request.
	RequestID string
	// Metadata is an extensible bag for protocol-specific data.
	Metadata map[string]interface{}

	// --- INTERNAL ---

	// OriginalMessage stores the original protocol-specific message
	// (e.g., *mcp.Message, *http.Request) for denormalization.
	OriginalMessage interface{}
}

// Decision represents the outcome of policy evaluation for an action.
type Decision string

const (
	// DecisionAllow permits the action to proceed.
	DecisionAllow Decision = "allow"
	// DecisionDeny blocks the action.
	DecisionDeny Decision = "deny"
	// DecisionApprovalRequired blocks the action pending human approval.
	DecisionApprovalRequired Decision = "approval_required"
)

// String returns the string representation of the Decision.
func (d Decision) String() string {
	return string(d)
}

// InterceptResult carries the result of intercepting and evaluating an action.
type InterceptResult struct {
	// Decision is the evaluation outcome (allow, deny, approval_required).
	Decision Decision
	// Reason explains why the decision was made.
	Reason string
	// RuleID is the identifier of the rule that produced this result.
	RuleID string
	// RuleName is the human-readable name of the matching rule.
	RuleName string
	// HelpURL points to documentation about why the action was blocked.
	HelpURL string
	// HelpText provides inline guidance about the decision.
	HelpText string
	// Modifications contains optional modifications to the action
	// (e.g., argument rewriting, header injection).
	Modifications map[string]interface{}
	// ApprovalTimeout is how long to wait for human approval.
	ApprovalTimeout time.Duration
	// ApprovalTimeoutAction is the fallback decision when approval times out.
	ApprovalTimeoutAction Decision
}

// IsAllowed returns true if the decision permits the action to proceed.
func (r *InterceptResult) IsAllowed() bool {
	return r.Decision == DecisionAllow
}
