package action

import (
	"encoding/json"
	"strings"

	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// extractResponseText extracts the tool result text from a CanonicalAction response.
// Returns empty string if no text content is found.
func extractResponseText(result *CanonicalAction) string {
	if result == nil || result.OriginalMessage == nil {
		return ""
	}
	msg, ok := result.OriginalMessage.(*mcp.Message)
	if !ok || msg.Raw == nil {
		return ""
	}

	// Parse envelope to get the "result" field.
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(msg.Raw, &envelope); err != nil || envelope.Result == nil {
		return ""
	}

	// Try MCP tool result format: { content: [{type:"text", text:"..."}] }
	var toolResult struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(envelope.Result, &toolResult); err == nil && len(toolResult.Content) > 0 {
		var buf strings.Builder
		for i, c := range toolResult.Content {
			if c.Type == "text" || c.Text != "" {
				if i > 0 && buf.Len() > 0 {
					buf.WriteString("\n")
				}
				buf.WriteString(c.Text)
			}
		}
		return buf.String()
	}

	// Try plain string result.
	var strResult string
	if err := json.Unmarshal(envelope.Result, &strResult); err == nil {
		return strResult
	}

	return ""
}
