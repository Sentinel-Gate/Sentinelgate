package policy

import "context"

// PolicyEngine evaluates tool calls against RBAC policies.
type PolicyEngine interface {
	// Evaluate evaluates a tool call against loaded policies.
	// Returns Decision with Allowed=true/false and reason.
	Evaluate(ctx context.Context, evalCtx EvaluationContext) (Decision, error)
}

// PolicyStore persists and retrieves policies.
// Interface in domain package (like AuthStore pattern from 02-01).
type PolicyStore interface {
	// GetAllPolicies returns all enabled policies.
	GetAllPolicies(ctx context.Context) ([]Policy, error)
	// GetPolicy returns a policy by ID.
	GetPolicy(ctx context.Context, id string) (*Policy, error)
	// SavePolicy creates or updates a policy.
	SavePolicy(ctx context.Context, p *Policy) error
	// DeletePolicy removes a policy by ID.
	DeletePolicy(ctx context.Context, id string) error
	// GetPolicyWithRules returns a policy with all its rules loaded.
	GetPolicyWithRules(ctx context.Context, id string) (*Policy, error)
	// SaveRule creates or updates a rule within a policy.
	SaveRule(ctx context.Context, policyID string, r *Rule) error
	// DeleteRule removes a rule by ID.
	DeleteRule(ctx context.Context, policyID, ruleID string) error
}
