// Package proxy contains the core domain logic for the MCP proxy.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// Error types for policy evaluation failures.
var ErrPolicyDenied = errors.New("policy denied")

// ErrMissingSession indicates a tool call was received without session context.
var ErrMissingSession = errors.New("missing session context")

// PolicyDenyError wraps a policy denial with structured information.
// It includes rule details and human-readable guidance for resolving the denial.
type PolicyDenyError struct {
	RuleID   string
	RuleName string
	Reason   string
	HelpURL  string
	HelpText string
}

// Error implements the error interface.
func (e *PolicyDenyError) Error() string {
	return fmt.Sprintf("policy denied: %s", e.Reason)
}

// Unwrap returns ErrPolicyDenied so errors.Is(err, ErrPolicyDenied) works.
func (e *PolicyDenyError) Unwrap() error {
	return ErrPolicyDenied
}

// PolicyInterceptor evaluates tool calls against RBAC policies.
// It wraps another MessageInterceptor (e.g., PassthroughInterceptor).
type PolicyInterceptor struct {
	policyEngine policy.PolicyEngine
	next         MessageInterceptor
	logger       *slog.Logger
}

// NewPolicyInterceptor creates a new PolicyInterceptor.
func NewPolicyInterceptor(
	engine policy.PolicyEngine,
	next MessageInterceptor,
	logger *slog.Logger,
) *PolicyInterceptor {
	return &PolicyInterceptor{
		policyEngine: engine,
		next:         next,
		logger:       logger,
	}
}

// Intercept evaluates tool calls against policies before passing to next interceptor.
// Returns error to BLOCK message propagation - ProxyService MUST check error
// and send JSON-RPC error response back to client instead of forwarding.
func (p *PolicyInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// Non-tool-call messages pass through without policy check
	if !msg.IsToolCall() {
		return p.next.Intercept(ctx, msg)
	}

	// Defensive: session should be set by AuthInterceptor
	if msg.Session == nil {
		p.logger.Warn("tool call without session context")
		return nil, ErrMissingSession
	}

	// Build evaluation context from message
	evalCtx, err := buildEvaluationContext(msg)
	if err != nil {
		p.logger.Warn("failed to build evaluation context",
			"error", err,
			"session_id", msg.Session.ID,
		)
		return nil, fmt.Errorf("invalid tool call params: %w", err)
	}

	// Evaluate against policy engine
	decision, err := p.policyEngine.Evaluate(ctx, evalCtx)
	if err != nil {
		p.logger.Error("policy evaluation failed",
			"error", err,
			"tool", evalCtx.ToolName,
			"session_id", msg.Session.ID,
		)
		return nil, fmt.Errorf("policy evaluation error: %w", err)
	}

	// Check decision
	if !decision.Allowed && !decision.RequiresApproval {
		p.logger.Info("tool call denied by policy",
			"tool", evalCtx.ToolName,
			"rule_id", decision.RuleID,
			"rule_name", decision.RuleName,
			"reason", decision.Reason,
			"session_id", msg.Session.ID,
			"identity_id", msg.Session.IdentityID,
		)
		return nil, &PolicyDenyError{
			RuleID:   decision.RuleID,
			RuleName: decision.RuleName,
			Reason:   decision.Reason,
			HelpURL:  decision.HelpURL,
			HelpText: decision.HelpText,
		}
	}

	// Store decision in context for downstream interceptors (ApprovalInterceptor)
	ctx = policy.WithDecision(ctx, &decision)

	// Log decision
	if decision.RequiresApproval {
		p.logger.Info("tool call requires approval",
			"tool", evalCtx.ToolName,
			"rule_id", decision.RuleID,
			"session_id", msg.Session.ID,
			"timeout", decision.ApprovalTimeout,
		)
	} else {
		p.logger.Debug("tool call allowed by policy",
			"tool", evalCtx.ToolName,
			"rule_id", decision.RuleID,
			"session_id", msg.Session.ID,
		)
	}

	return p.next.Intercept(ctx, msg)
}

// toolCallParams represents the JSON-RPC params for a tools/call request.
type toolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// buildEvaluationContext extracts tool call context from an MCP message.
func buildEvaluationContext(msg *mcp.Message) (policy.EvaluationContext, error) {
	req := msg.Request()
	if req == nil || req.Params == nil {
		return policy.EvaluationContext{}, errors.New("missing request params")
	}

	// Parse tools/call params
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return policy.EvaluationContext{}, fmt.Errorf("failed to parse params: %w", err)
	}

	if params.Name == "" {
		return policy.EvaluationContext{}, errors.New("missing tool name")
	}

	// Convert auth.Role to string for CEL evaluation
	roles := make([]string, len(msg.Session.Roles))
	for i, role := range msg.Session.Roles {
		roles[i] = string(role)
	}

	return policy.EvaluationContext{
		ToolName:       params.Name,
		ToolArguments:  params.Arguments,
		UserRoles:      roles,
		SessionID:      msg.Session.ID,
		IdentityID:     msg.Session.IdentityID,
		IdentityName:   msg.Session.IdentityName,
		RequestTime:    msg.Timestamp,
		Framework:      "",
		FrameworkAttrs: nil,
		// Universal fields
		ActionType: "tool_call",
		ActionName: params.Name,
		Protocol:   "mcp",
		Gateway:    "mcp-gateway",
	}, nil
}

// Compile-time check that PolicyInterceptor implements MessageInterceptor.
var _ MessageInterceptor = (*PolicyInterceptor)(nil)
