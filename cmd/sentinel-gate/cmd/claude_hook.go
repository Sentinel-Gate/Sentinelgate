package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var claudeHookCmd = &cobra.Command{
	Use:           "claude-hook",
	Short:         "Internal: Claude Code PreToolUse hook handler",
	Hidden:        true,
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE:          runClaudeHook,
}

func init() {
	rootCmd.AddCommand(claudeHookCmd)
}

// claudeHookInput matches the JSON that Claude Code sends to PreToolUse hooks on stdin.
type claudeHookInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// claudeHookDenyOutput is the JSON response format for denying a tool use.
type claudeHookDenyOutput struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	} `json:"hookSpecificOutput"`
}

// policyEvalRequest is the request body for POST /admin/api/v1/policy/evaluate.
type policyEvalRequest struct {
	ActionType    string          `json:"action_type"`
	ActionName    string          `json:"action_name"`
	Arguments     json.RawMessage `json:"arguments"`
	IdentityName  string          `json:"identity_name"`
	IdentityRoles []string        `json:"identity_roles"`
	Protocol      string          `json:"protocol"`
}

// policyEvalResponse is the response from the policy evaluate endpoint.
type policyEvalResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Error    string `json:"error"`
}

func runClaudeHook(cmd *cobra.Command, args []string) error {
	serverAddr := os.Getenv("SENTINELGATE_SERVER_ADDR")
	apiKey := os.Getenv("SENTINELGATE_API_KEY")
	agentID := os.Getenv("SENTINELGATE_AGENT_ID")
	failMode := os.Getenv("SENTINELGATE_FAIL_MODE")

	// Debug: log hook invocation to a file for troubleshooting.
	if debugFile := os.Getenv("SENTINELGATE_HOOK_DEBUG"); debugFile != "" {
		if f, err := os.OpenFile(debugFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			fmt.Fprintf(f, "claude-hook invoked: server=%s failMode=%s agentID=%s\n", serverAddr, failMode, agentID)
			f.Close()
		}
	}

	if serverAddr == "" {
		return nil // no server configured, allow
	}

	// Read input from stdin.
	inputBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return claudeHookError(failMode, "read stdin: "+err.Error())
	}

	// Try to detect the hook event type. If it's not a PreToolUse event
	// (e.g. SessionStart, Stop), silently allow — we only gate tool usage.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(inputBytes, &raw); err != nil {
		return nil // unparseable input, silently allow
	}
	if _, hasToolName := raw["tool_name"]; !hasToolName {
		return nil // not a PreToolUse event (e.g. SessionStart), allow
	}

	var input claudeHookInput
	if err := json.Unmarshal(inputBytes, &input); err != nil {
		return claudeHookError(failMode, "parse input: "+err.Error())
	}

	// Map tool to action type; allow unknown tools.
	actionType := claudeToolToAction(input.ToolName)
	if actionType == "" {
		return nil
	}

	// Build and send policy evaluate request.
	evalReq := policyEvalRequest{
		ActionType:    actionType,
		ActionName:    input.ToolName,
		Arguments:     input.ToolInput,
		IdentityName:  fmt.Sprintf("runtime-%s", agentID),
		IdentityRoles: []string{"agent"},
		Protocol:      "runtime",
	}

	body, _ := json.Marshal(evalReq)
	evalURL := serverAddr + "/admin/api/v1/policy/evaluate"

	httpReq, err := http.NewRequest(http.MethodPost, evalURL, bytes.NewReader(body))
	if err != nil {
		return claudeHookError(failMode, err.Error())
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return claudeHookError(failMode, "policy evaluate: "+err.Error())
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var evalResp policyEvalResponse
	if err := json.Unmarshal(respBody, &evalResp); err != nil {
		return claudeHookError(failMode, "parse response: "+err.Error())
	}

	// Server error without a decision.
	if evalResp.Error != "" && evalResp.Decision == "" {
		return claudeHookError(failMode, "server: "+evalResp.Error)
	}

	if evalResp.Decision == "deny" {
		reason := evalResp.Reason
		if reason == "" {
			reason = "policy denied"
		}
		return claudeHookDeny("SentinelGate: " + reason)
	}

	return nil // allow
}

// claudeToolToAction maps Claude Code tool names to SentinelGate action types.
func claudeToolToAction(tool string) string {
	switch tool {
	case "Read", "Glob", "Grep":
		return "file_access"
	case "Write", "Edit", "NotebookEdit":
		return "file_access"
	case "Bash":
		return "command_exec"
	case "WebFetch", "WebSearch":
		return "http_request"
	default:
		return ""
	}
}

// claudeHookDeny outputs a deny response to stdout.
func claudeHookDeny(reason string) error {
	var output claudeHookDenyOutput
	output.HookSpecificOutput.HookEventName = "PreToolUse"
	output.HookSpecificOutput.PermissionDecision = "deny"
	output.HookSpecificOutput.PermissionDecisionReason = reason
	return json.NewEncoder(os.Stdout).Encode(output)
}

// claudeHookError handles errors based on fail mode.
// Fail-closed: deny with error message. Fail-open: log warning, allow.
func claudeHookError(failMode, msg string) error {
	if failMode == "closed" {
		return claudeHookDeny("SentinelGate error: " + msg)
	}
	fmt.Fprintf(os.Stderr, "[sentinelgate] hook warning: %s (fail-open, allowing)\n", msg)
	return nil
}
