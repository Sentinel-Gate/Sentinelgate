// Package policy contains domain types for RBAC policy evaluation.
package policy

import "time"

// Action represents the result of a policy rule evaluation.
type Action string

const (
	// ActionAllow permits the tool call to proceed.
	ActionAllow Action = "allow"
	// ActionDeny blocks the tool call.
	ActionDeny Action = "deny"
	// ActionApprovalRequired requires human approval before the tool call proceeds.
	ActionApprovalRequired Action = "approval_required"
)

// Rule defines a single policy rule for tool call authorization.
type Rule struct {
	// ID is the unique identifier for this rule.
	ID string
	// Name is a human-readable name for this rule.
	Name string
	// Priority determines rule evaluation order (lower = higher priority).
	Priority int
	// ToolMatch is a glob pattern to match tool names (e.g., "file_*").
	ToolMatch string
	// Condition is a CEL expression that must evaluate to true for the rule to apply.
	Condition string
	// Action is the result when this rule matches and condition is true.
	Action Action
	// CreatedAt is when the rule was created (UTC).
	CreatedAt time.Time

	// ApprovalTimeout is how long to wait for approval when Action is ActionApprovalRequired.
	// Defaults to 5 minutes if not specified.
	ApprovalTimeout time.Duration
	// TimeoutAction specifies what to do when an approval request times out.
	// Must be ActionDeny (default) or ActionAllow.
	TimeoutAction Action

	// HelpText is optional admin-provided guidance shown when this rule denies an action.
	// When empty, a default help text is generated from the rule name.
	HelpText string
}

// Decision represents the outcome of policy evaluation for a tool call.
type Decision struct {
	// Allowed is true if the tool call is permitted.
	Allowed bool
	// RuleID is the ID of the rule that produced this decision.
	RuleID string
	// Reason explains why the decision was made.
	Reason string

	// RequiresApproval is true when the matching rule has Action = ActionApprovalRequired.
	// When true, the tool call should be blocked pending human approval.
	RequiresApproval bool
	// ApprovalTimeout is the timeout duration from the rule (when RequiresApproval is true).
	ApprovalTimeout time.Duration
	// ApprovalTimeoutAction is the fallback action when approval times out.
	ApprovalTimeoutAction Action

	// RuleName is the human-readable name of the rule that produced this decision.
	RuleName string
	// HelpURL is a direct link to the rule in the Admin UI (e.g., "/admin/policies#rule-{ruleID}").
	HelpURL string
	// HelpText is a human explanation of how to resolve a denial
	// (e.g., "This tool is blocked. Ask an admin to modify the 'block-exec' rule.").
	HelpText string
}

// Policy is a collection of rules for tool call authorization.
type Policy struct {
	// ID is the unique identifier for this policy.
	ID string
	// Name is the human-readable name for this policy.
	Name string
	// Description provides additional context about the policy.
	Description string
	// Priority determines policy evaluation order (lower = higher priority).
	Priority int
	// Rules are the authorization rules in this policy.
	Rules []Rule
	// Enabled indicates if this policy is active.
	Enabled bool
	// CreatedAt is when the policy was created (UTC).
	CreatedAt time.Time
	// UpdatedAt is when the policy was last modified (UTC).
	UpdatedAt time.Time
}
