package admin

import (
	"context"
	"net/http"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// PolicyTestRequest is the JSON request body for testing a policy evaluation.
type PolicyTestRequest struct {
	// ToolName is the tool to test against (required).
	ToolName string `json:"tool_name"`
	// Arguments are optional tool arguments for CEL evaluation.
	Arguments map[string]interface{} `json:"arguments,omitempty"`
	// Roles are user roles to simulate (defaults to empty).
	Roles []string `json:"roles,omitempty"`
	// IdentityID is a simulated identity ID.
	IdentityID string `json:"identity_id,omitempty"`
	// IdentityName is a simulated identity name.
	IdentityName string `json:"identity_name,omitempty"`
	// ActionType is the canonical action type: "tool_call", "file_read", "file_write", "command_exec", etc.
	ActionType string `json:"action_type,omitempty"`
	// Protocol is the originating protocol: "mcp", "http", "runtime".
	Protocol string `json:"protocol,omitempty"`
	// Framework is the AI framework: "crewai", "langchain", "autogen", etc.
	Framework string `json:"framework,omitempty"`
	// Gateway is the gateway that received the request.
	Gateway string `json:"gateway,omitempty"`
	// DestURL is the destination URL for outbound requests.
	DestURL string `json:"dest_url,omitempty"`
	// DestDomain is the destination domain.
	DestDomain string `json:"dest_domain,omitempty"`
	// DestCommand is the command being executed.
	DestCommand string `json:"dest_command,omitempty"`
}

// PolicyTestResponse is the JSON response from a policy test evaluation.
type PolicyTestResponse struct {
	// Allowed indicates whether the tool call would be permitted.
	Allowed bool `json:"allowed"`
	// Decision is "allow" or "deny".
	Decision string `json:"decision"`
	// RuleID is the ID of the matched rule (empty if default deny with no match).
	RuleID string `json:"rule_id"`
	// RuleName is the name of the matched rule.
	RuleName string `json:"rule_name"`
	// Reason is the explanation from the policy engine.
	Reason string `json:"reason"`
	// MatchedRule contains the full rule details if a rule matched, nil otherwise.
	MatchedRule *MatchedRuleDetail `json:"matched_rule"`
}

// MatchedRuleDetail contains the details of the rule that matched during evaluation.
type MatchedRuleDetail struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Priority  int    `json:"priority"`
	ToolMatch string `json:"tool_match"`
	Condition string `json:"condition"`
	Action    string `json:"action"`
}

// handleTestPolicy evaluates a hypothetical tool call against the current policy ruleset.
// POST /admin/api/policies/test
func (h *AdminAPIHandler) handleTestPolicy(w http.ResponseWriter, r *http.Request) {
	if h.policyService == nil {
		h.respondError(w, http.StatusInternalServerError, "policy service not configured")
		return
	}

	var req PolicyTestRequest
	if err := h.readJSON(r, &req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}

	if req.ToolName == "" {
		h.respondError(w, http.StatusBadRequest, "tool_name is required")
		return
	}

	// Build evaluation context from the test request.
	evalCtx := policy.EvaluationContext{
		ToolName:      req.ToolName,
		ToolArguments: req.Arguments,
		UserRoles:     req.Roles,
		IdentityID:    req.IdentityID,
		IdentityName:  req.IdentityName,
		ActionType:    req.ActionType,
		Protocol:      req.Protocol,
		Framework:     req.Framework,
		Gateway:       req.Gateway,
		DestURL:       req.DestURL,
		DestDomain:    req.DestDomain,
		DestCommand:   req.DestCommand,
	}

	decision, err := h.policyService.Evaluate(r.Context(), evalCtx)
	if err != nil {
		h.logger.Error("policy evaluation failed", "error", err, "tool", req.ToolName)
		h.respondError(w, http.StatusInternalServerError, "policy evaluation failed")
		return
	}

	// Build response.
	resp := PolicyTestResponse{
		Allowed: decision.Allowed,
		RuleID:  decision.RuleID,
		Reason:  decision.Reason,
	}
	if decision.Allowed {
		resp.Decision = "allow"
	} else {
		resp.Decision = "deny"
	}

	// Look up matched rule details if a rule was matched.
	if decision.RuleID != "" && h.policyStore != nil {
		if detail := h.findMatchedRule(r.Context(), decision.RuleID); detail != nil {
			resp.RuleName = detail.Name
			resp.MatchedRule = detail
		}
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// findMatchedRule searches all policies for a rule with the given ID.
func (h *AdminAPIHandler) findMatchedRule(ctx context.Context, ruleID string) *MatchedRuleDetail {
	policies, err := h.policyStore.GetAllPolicies(ctx)
	if err != nil {
		h.logger.Error("failed to load policies for rule lookup", "error", err)
		return nil
	}

	for _, p := range policies {
		for _, r := range p.Rules {
			if r.ID == ruleID || r.Name == ruleID {
				return &MatchedRuleDetail{
					ID:        r.ID,
					Name:      r.Name,
					Priority:  r.Priority,
					ToolMatch: r.ToolMatch,
					Condition: r.Condition,
					Action:    string(r.Action),
				}
			}
		}
	}

	return nil
}
