package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

// hookHTTPClient is used for all policy evaluate requests from the claude-hook command.
// An explicit 10s timeout prevents the hook from hanging indefinitely when the
// SentinelGate server is unreachable, which would block Claude Code's tool execution.
var hookHTTPClient = &http.Client{Timeout: 10 * time.Second}

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

// outboundTestReq is the request body for POST /admin/api/v1/security/outbound/test.
type outboundTestReq struct {
	Domain string `json:"domain"`
	IP     string `json:"ip,omitempty"`
	Port   int    `json:"port"`
}

// outboundTestResp is the response from the outbound test endpoint.
type outboundTestResp struct {
	Blocked bool                 `json:"blocked"`
	Rule    *outboundMatchedRule `json:"rule,omitempty"`
	Message string               `json:"message"`
}

// outboundMatchedRule contains the matched rule details from the outbound test response.
type outboundMatchedRule struct {
	Name     string `json:"name"`
	HelpText string `json:"help_text"`
}

// hookDebugf writes a debug log line when SENTINELGATE_HOOK_DEBUG is set.
// It opens/closes the file on each call to keep the function simple and safe
// for a short-lived hook process.
func hookDebugf(format string, args ...interface{}) {
	debugFile := os.Getenv("SENTINELGATE_HOOK_DEBUG")
	if debugFile == "" {
		return
	}
	f, err := os.OpenFile(debugFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, format+"\n", args...)
}

func runClaudeHook(cmd *cobra.Command, args []string) error {
	serverAddr := os.Getenv("SENTINELGATE_SERVER_ADDR")
	apiKey := os.Getenv("SENTINELGATE_API_KEY")
	agentID := os.Getenv("SENTINELGATE_AGENT_ID")
	failMode := os.Getenv("SENTINELGATE_FAIL_MODE")

	// If SENTINELGATE_SERVER_ADDR is not set (e.g. "sentinel-gate start" mode
	// where hooks persist in settings.json but env vars aren't injected),
	// try the default server address. This makes hooks work even when Claude
	// Code is started independently of "sentinel-gate run".
	if serverAddr == "" {
		serverAddr = "http://127.0.0.1:8080"
	}

	hookDebugf("claude-hook invoked: server=%s failMode=%s agentID=%s", serverAddr, failMode, agentID)

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

	hookDebugf("tool=%s actionType=%s", input.ToolName, actionType)

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

	resp, err := hookHTTPClient.Do(httpReq)
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

	// For WebFetch/WebSearch: also check outbound rules so the user gets a clear
	// error with help_text instead of a generic connection-refused message.
	if input.ToolName == "WebFetch" || input.ToolName == "WebSearch" {
		if deny := checkOutboundRule(input, serverAddr, apiKey, failMode); deny != nil {
			return deny
		}
	}

	return nil // allow
}

// checkOutboundRule extracts the URL from a WebFetch/WebSearch tool input,
// parses the domain, and tests it against outbound rules.  Returns a deny
// error when the destination is blocked, nil otherwise.  On any error (parse,
// HTTP, timeout) it falls through to allow so the proxy-level enforcement
// still applies.
func checkOutboundRule(input claudeHookInput, serverAddr, apiKey, failMode string) error {
	// Parse tool_input to extract the "url" field.
	var toolArgs map[string]interface{}
	if err := json.Unmarshal(input.ToolInput, &toolArgs); err != nil {
		hookDebugf("outbound: can't parse tool_input: %v", err)
		return nil // can't parse, let it through
	}

	rawURL, ok := toolArgs["url"]
	if !ok {
		hookDebugf("outbound: no 'url' field in tool_input (tool=%s), skipping", input.ToolName)
		return nil // no URL field (e.g. WebSearch without explicit URL)
	}
	urlStr, ok := rawURL.(string)
	if !ok || urlStr == "" {
		hookDebugf("outbound: 'url' field is empty or not a string")
		return nil
	}

	parsed, err := url.Parse(urlStr)
	if err != nil || parsed.Host == "" {
		hookDebugf("outbound: unparseable URL %q: %v", urlStr, err)
		return nil // unparseable URL, let proxy handle it
	}

	hostname := parsed.Hostname() // strips port if present

	// Distinguish IP addresses from domain names so the test endpoint
	// receives the value in the correct field (CIDR matching only works
	// on the IP field, not Domain).
	var testDomain, testIP string
	if net.ParseIP(hostname) != nil {
		testIP = hostname
	} else {
		testDomain = hostname
	}

	// Use the actual port from the URL instead of hardcoding 443.
	testPort := defaultPortForScheme(parsed.Scheme)
	if portStr := parsed.Port(); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p >= 1 && p <= 65535 {
			testPort = p
		}
	}

	hookDebugf("outbound: checking domain=%s ip=%s port=%d (from url=%s)", testDomain, testIP, testPort, urlStr)

	// Call the outbound test endpoint.
	testReq := outboundTestReq{Domain: testDomain, IP: testIP, Port: testPort}
	body, _ := json.Marshal(testReq)
	testURL := serverAddr + "/admin/api/v1/security/outbound/test"

	httpReq, err := http.NewRequest(http.MethodPost, testURL, bytes.NewReader(body))
	if err != nil {
		hookDebugf("outbound: failed to build request: %v", err)
		return nil // fail-open on request build error
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := hookHTTPClient.Do(httpReq)
	if err != nil {
		hookDebugf("outbound: HTTP request failed: %v", err)
		return nil // server unreachable, fail-open
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	hookDebugf("outbound: response status=%d body=%s", resp.StatusCode, string(respBody))

	// Non-200 means server error (e.g. 503 outbound service unavailable).
	// Treat as fail-open but log a warning so the user knows.
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "[sentinelgate] outbound check: server returned %d: %s\n", resp.StatusCode, string(respBody))
		return nil
	}

	var testResp outboundTestResp
	if err := json.Unmarshal(respBody, &testResp); err != nil {
		hookDebugf("outbound: can't parse response JSON: %v", err)
		return nil // unparseable response, fail-open
	}

	hookDebugf("outbound: result blocked=%v message=%q", testResp.Blocked, testResp.Message)

	if testResp.Blocked {
		// Build a helpful deny message.
		dest := hostname
		msg := fmt.Sprintf("SentinelGate: outbound blocked — %s", dest)
		if testResp.Rule != nil && testResp.Rule.HelpText != "" {
			msg = fmt.Sprintf("SentinelGate: outbound blocked — %s (%s)", dest, testResp.Rule.HelpText)
		} else if testResp.Rule != nil && testResp.Rule.Name != "" {
			msg = fmt.Sprintf("SentinelGate: outbound blocked — %s (blocked by outbound rule: %s)", dest, testResp.Rule.Name)
		}
		return claudeHookDeny(msg)
	}

	return nil // allowed
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

// defaultPortForScheme returns the default port for a URL scheme.
func defaultPortForScheme(scheme string) int {
	switch scheme {
	case "https", "wss":
		return 443
	default:
		return 80
	}
}
