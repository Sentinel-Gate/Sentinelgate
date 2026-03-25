package admin

import (
	"net/http"
	"path/filepath"
	"strings"

	celAdapter "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/cel"
)

// lintRequest is the JSON body for POST /admin/api/policies/lint.
type lintRequest struct {
	Condition string `json:"condition"`
	ToolMatch string `json:"tool_match"`
	Action    string `json:"action"`
	Priority  int    `json:"priority"`
	RuleID    string `json:"rule_id,omitempty"`
}

// lintWarning represents a single lint finding.
type lintWarning struct {
	Type     string `json:"type"`     // "syntax", "permissive", "shadowed", "conflict"
	Severity string `json:"severity"` // "error", "warning", "info"
	Message  string `json:"message"`
}

// lintResponse is the JSON response for the lint endpoint.
type lintResponse struct {
	Valid    bool          `json:"valid"`
	Warnings []lintWarning `json:"warnings"`
}

// handleLintPolicy validates a policy rule and checks for common issues.
// POST /admin/api/policies/lint
func (h *AdminAPIHandler) handleLintPolicy(w http.ResponseWriter, r *http.Request) {
	var req lintRequest
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}

	// BUG-9 FIX: If condition is empty, return an error instead of valid:true.
	// Without this, a request with a wrong field name (e.g. "expression" instead of
	// "condition") would silently return valid:true for any input.
	if req.Condition == "" {
		h.respondError(w, http.StatusBadRequest, "condition field is required")
		return
	}

	var warnings []lintWarning

	// 1. Syntax check: compile the CEL expression
	if req.Condition != "true" {
		evaluator, err := celAdapter.NewEvaluator()
		if err != nil {
			h.respondError(w, http.StatusInternalServerError, "failed to create CEL evaluator")
			return
		}
		if err := evaluator.ValidateExpression(req.Condition); err != nil {
			errMsg := err.Error()
			// Strip the "invalid CEL expression: " prefix for cleaner messages
			errMsg = strings.TrimPrefix(errMsg, "invalid CEL expression: ")
			errMsg = strings.TrimPrefix(errMsg, "compilation failed: ")
			warnings = append(warnings, lintWarning{
				Type:     "syntax",
				Severity: "error",
				Message:  errMsg,
			})
			h.respondJSON(w, http.StatusOK, lintResponse{
				Valid:    false,
				Warnings: warnings,
			})
			return
		}
	}

	// 2. Permissiveness check: wildcard tool_match + trivial condition + allow
	if req.Action == "allow" {
		isWildcard := req.ToolMatch == "*" || req.ToolMatch == ""
		isTrivialCondition := req.Condition == "true"
		if isWildcard && isTrivialCondition {
			warnings = append(warnings, lintWarning{
				Type:     "permissive",
				Severity: "warning",
				Message:  "Rule allows all tools with no restrictions. Consider adding identity or role conditions.",
			})
		}
		// Check if allow rule has no identity/role restriction in condition
		if isWildcard && !isTrivialCondition && !containsIdentityCheck(req.Condition) {
			warnings = append(warnings, lintWarning{
				Type:     "permissive",
				Severity: "info",
				Message:  "Allow rule applies to all tools. Consider restricting by identity or role.",
			})
		}
	}

	// 3. Shadowing and conflict checks: compare against existing rules
	if h.policyAdminService != nil {
		policies, err := h.policyAdminService.List(r.Context())
		if err == nil {
			for _, pol := range policies {
				if !pol.Enabled {
					continue
				}
				for _, rule := range pol.Rules {
					if rule.ID == req.RuleID {
						continue // skip self
					}

					// Shadowing: higher-priority rule with broader/equal scope
					if rule.Priority > req.Priority && string(rule.Action) == req.Action {
						if toolMatchCovers(rule.ToolMatch, req.ToolMatch) {
							if rule.Condition == "true" || rule.Condition == "" {
								warnings = append(warnings, lintWarning{
									Type:     "shadowed",
									Severity: "warning",
									Message:  "Rule may be shadowed by '" + rule.Name + "' (priority " + itoa(rule.Priority) + ") which matches the same or broader scope with no conditions.",
								})
							}
						}
					}

					// Conflict: same priority, overlapping scope, different action
					if rule.Priority == req.Priority && string(rule.Action) != req.Action {
						if toolMatchOverlaps(rule.ToolMatch, req.ToolMatch) {
							warnings = append(warnings, lintWarning{
								Type:     "conflict",
								Severity: "warning",
								Message:  "Potential conflict with '" + rule.Name + "' at same priority (" + itoa(rule.Priority) + ") — different actions on overlapping scope.",
							})
						}
					}
				}
			}
		}
	}

	h.respondJSON(w, http.StatusOK, lintResponse{
		Valid:    len(warnings) == 0 || !hasSeverity(warnings, "error"),
		Warnings: warnings,
	})
}

// containsIdentityCheck returns true if the CEL expression references identity/role variables.
func containsIdentityCheck(cel string) bool {
	return strings.Contains(cel, "identity_name") ||
		strings.Contains(cel, "identity_id") ||
		strings.Contains(cel, "identity_roles") ||
		strings.Contains(cel, "user_roles")
}

// toolMatchCovers returns true if pattern `a` covers all tools matched by pattern `b`.
// A covers B if A is "*" or A == B, or A is a prefix glob that includes B.
func toolMatchCovers(a, b string) bool {
	if a == "*" || a == "" {
		return true
	}
	if a == b {
		return true
	}
	// a="read_*" covers b="read_file" or b="read_*"
	if strings.Contains(a, "*") {
		matched, _ := filepath.Match(a, b)
		if matched {
			return true
		}
		// Also check if a's pattern is broader: a="*_file" covers b="read_file"
		if !strings.Contains(b, "*") {
			return false
		}
		// Both are globs — a covers b only if a is "*" (already checked)
	}
	return false
}

// toolMatchOverlaps returns true if patterns `a` and `b` could match the same tool name.
func toolMatchOverlaps(a, b string) bool {
	if a == "*" || a == "" || b == "*" || b == "" {
		return true
	}
	if a == b {
		return true
	}
	// If neither has wildcards, they overlap only if equal
	if !strings.Contains(a, "*") && !strings.Contains(b, "*") {
		return false
	}
	// If one has wildcard, check if the other matches it
	if strings.Contains(a, "*") && !strings.Contains(b, "*") {
		matched, _ := filepath.Match(a, b)
		return matched
	}
	if strings.Contains(b, "*") && !strings.Contains(a, "*") {
		matched, _ := filepath.Match(b, a)
		return matched
	}
	// Both have wildcards — conservatively assume overlap
	return true
}

// hasSeverity returns true if any warning has the given severity.
func hasSeverity(warnings []lintWarning, severity string) bool {
	for _, w := range warnings {
		if w.Severity == severity {
			return true
		}
	}
	return false
}

// itoa converts int to string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	if neg {
		buf = append(buf, '-')
	}
	// reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
