// Package sentinelgate provides a Go SDK for the SentinelGate Policy Decision API.
//
// SentinelGate is a governance layer for AI agent actions. This SDK enables Go
// developers to programmatically evaluate actions against SentinelGate policies
// before executing them. It uses only the Go standard library (net/http) with
// zero external dependencies.
//
// Quick start:
//
//	// Set SENTINELGATE_SERVER_ADDR and SENTINELGATE_API_KEY env vars, then:
//	client := sentinelgate.NewClient()
//
//	resp, err := client.Evaluate(ctx, sentinelgate.EvaluateRequest{
//	    ActionType:    "tool_call",
//	    ActionName:    "read_file",
//	    IdentityName:  "agent-1",
//	    IdentityRoles: []string{"developer"},
//	})
//	if err != nil {
//	    var denied *sentinelgate.PolicyDeniedError
//	    if errors.As(err, &denied) {
//	        fmt.Printf("Denied by rule %s: %s\n", denied.RuleName, denied.Reason)
//	    }
//	}
package sentinelgate

// Decision represents the outcome of a policy evaluation.
type Decision string

const (
	// DecisionAllow indicates the action is permitted.
	DecisionAllow Decision = "allow"

	// DecisionDeny indicates the action is denied by policy.
	DecisionDeny Decision = "deny"

	// DecisionApprovalRequired indicates the action needs human approval.
	DecisionApprovalRequired Decision = "approval_required"
)

// EvaluateRequest represents a policy evaluation request sent to the SentinelGate server.
// Fields map to the PolicyEvaluateRequest schema on the server side.
type EvaluateRequest struct {
	// ActionType is the category of the action (e.g., "tool_call", "http_request", "file_access").
	ActionType string `json:"action_type"`

	// ActionName is the specific action identifier (e.g., "read_file", "write_file").
	ActionName string `json:"action_name"`

	// Protocol is the communication protocol (e.g., "mcp", "a2a", "sdk").
	Protocol string `json:"protocol,omitempty"`

	// Framework is the AI framework in use (e.g., "langchain", "openai").
	Framework string `json:"framework,omitempty"`

	// Gateway is the gateway through which the request arrives.
	Gateway string `json:"gateway,omitempty"`

	// Arguments contains action-specific parameters as key-value pairs.
	Arguments map[string]any `json:"arguments,omitempty"`

	// IdentityName is the name of the identity performing the action.
	IdentityName string `json:"identity_name"`

	// IdentityRoles is the list of roles assigned to the identity.
	IdentityRoles []string `json:"identity_roles"`

	// Destination contains optional destination details for the action.
	Destination *Destination `json:"destination,omitempty"`
}

// Destination represents the target endpoint or resource for an action.
type Destination struct {
	// URL is the full URL of the destination.
	URL string `json:"url,omitempty"`

	// Domain is the domain name of the destination.
	Domain string `json:"domain,omitempty"`

	// IP is the IP address of the destination.
	IP string `json:"ip,omitempty"`

	// Port is the port number of the destination.
	Port int `json:"port,omitempty"`

	// Scheme is the protocol scheme (e.g., "https").
	Scheme string `json:"scheme,omitempty"`

	// Path is the URL path of the destination.
	Path string `json:"path,omitempty"`

	// Command is the command to execute at the destination.
	Command string `json:"command,omitempty"`
}

// EvaluateResponse represents the structured result of a policy evaluation
// returned by the SentinelGate server.
type EvaluateResponse struct {
	// Decision is the evaluation outcome: "allow", "deny", or "approval_required".
	Decision Decision `json:"decision"`

	// RuleID is the identifier of the rule that matched.
	RuleID string `json:"rule_id,omitempty"`

	// RuleName is the human-readable name of the matching rule.
	RuleName string `json:"rule_name,omitempty"`

	// Reason explains why the decision was made.
	Reason string `json:"reason"`

	// HelpURL points to the admin UI for the matching rule.
	HelpURL string `json:"help_url,omitempty"`

	// HelpText provides human-readable guidance for denied actions.
	HelpText string `json:"help_text,omitempty"`

	// RequestID is the unique identifier for this evaluation.
	RequestID string `json:"request_id"`

	// LatencyMs is the server-side evaluation latency in milliseconds.
	LatencyMs int64 `json:"latency_ms"`
}

// StatusResponse represents the approval polling status for a previously
// submitted evaluation.
type StatusResponse struct {
	// RequestID is the unique identifier for the evaluation.
	RequestID string `json:"request_id"`

	// Status is the current status of the evaluation.
	Status string `json:"status"`

	// Decision is the current decision value.
	Decision Decision `json:"decision"`

	// UpdatedAt is the ISO 8601 timestamp of the last status update.
	UpdatedAt string `json:"updated_at"`
}
