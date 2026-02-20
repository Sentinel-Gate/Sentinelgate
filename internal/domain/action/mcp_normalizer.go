package action

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// MCPNormalizer converts mcp.Message to/from CanonicalAction.
// It handles tools/call, sampling/createMessage, and elicitation/create methods,
// mapping each to the appropriate ActionType.
type MCPNormalizer struct{}

// Compile-time check that MCPNormalizer implements Normalizer.
var _ Normalizer = (*MCPNormalizer)(nil)

// NewMCPNormalizer creates a new MCPNormalizer.
func NewMCPNormalizer() *MCPNormalizer {
	return &MCPNormalizer{}
}

// Normalize converts an mcp.Message to a CanonicalAction.
// The msg parameter must be a *mcp.Message; other types return an error.
// Non-request messages (responses) are passed through with minimal fields.
func (n *MCPNormalizer) Normalize(ctx context.Context, msg interface{}) (*CanonicalAction, error) {
	mcpMsg, ok := msg.(*mcp.Message)
	if !ok {
		return nil, fmt.Errorf("MCPNormalizer: expected *mcp.Message, got %T", msg)
	}

	action := &CanonicalAction{
		Protocol:        "mcp",
		Gateway:         "mcp-gateway",
		OriginalMessage: mcpMsg,
		Metadata:        make(map[string]interface{}),
	}

	// Non-request messages get passthrough treatment
	if !mcpMsg.IsRequest() {
		action.Type = ActionToolCall
		action.RequestTime = mcpMsg.Timestamp
		return action, nil
	}

	// Set timing and request ID
	action.RequestTime = mcpMsg.Timestamp
	action.RequestID = formatRawID(mcpMsg.RawID())

	// Populate identity from session (nil-safe)
	if mcpMsg.Session != nil {
		roles := make([]string, len(mcpMsg.Session.Roles))
		for i, r := range mcpMsg.Session.Roles {
			roles[i] = string(r)
		}
		action.Identity = ActionIdentity{
			ID:        mcpMsg.Session.IdentityID,
			Name:      mcpMsg.Session.IdentityName,
			SessionID: mcpMsg.Session.ID,
			Roles:     roles,
		}
	}

	// Map method to action type and extract parameters
	method := mcpMsg.Method()
	switch method {
	case "tools/call":
		action.Type = ActionToolCall
		n.extractToolCallParams(mcpMsg, action)
	case "sampling/createMessage":
		action.Type = ActionSampling
		action.Name = method
	case "elicitation/create":
		action.Type = ActionElicitation
		action.Name = method
	default:
		// Unknown request methods get passthrough as tool_call
		action.Type = ActionToolCall
		action.Name = method
	}

	return action, nil
}

// extractToolCallParams parses tools/call params to set Name and Arguments.
func (n *MCPNormalizer) extractToolCallParams(msg *mcp.Message, action *CanonicalAction) {
	params := msg.ParseParams()
	if params == nil {
		return
	}

	if name, ok := params["name"].(string); ok {
		action.Name = name
	}

	if args, ok := params["arguments"].(map[string]interface{}); ok {
		action.Arguments = args
	}
}

// Denormalize converts an InterceptResult back to a protocol-specific response.
// For allow decisions, returns the original mcp.Message unchanged.
// For deny or approval_required decisions, returns nil and an error.
func (n *MCPNormalizer) Denormalize(action *CanonicalAction, result *InterceptResult) (interface{}, error) {
	if result.Decision == DecisionAllow {
		return action.OriginalMessage, nil
	}

	// Build error message with reason and optional help text
	errMsg := fmt.Sprintf("action denied: %s", result.Reason)
	if result.HelpText != "" {
		errMsg = fmt.Sprintf("%s (%s)", errMsg, result.HelpText)
	}

	return nil, fmt.Errorf("%s", errMsg)
}

// Protocol returns "mcp" indicating this normalizer handles MCP protocol messages.
func (n *MCPNormalizer) Protocol() string {
	return "mcp"
}

// formatRawID converts a json.RawMessage ID to a string representation.
func formatRawID(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	// Try to unmarshal as string first
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Try as number
	var num float64
	if err := json.Unmarshal(raw, &num); err == nil {
		return fmt.Sprintf("%.0f", num)
	}
	// Fallback: use raw string
	return string(raw)
}
