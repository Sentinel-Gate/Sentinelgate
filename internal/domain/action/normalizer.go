package action

import "context"

// Normalizer converts between protocol-specific messages and CanonicalAction.
// Each protocol (MCP, HTTP, WebSocket, runtime) has its own Normalizer
// implementation that knows how to extract WHO/WHAT/WHERE/HOW/CONTEXT fields
// from its native message format.
type Normalizer interface {
	// Normalize converts a protocol-specific message to a CanonicalAction.
	// The original message is stored in CanonicalAction.OriginalMessage
	// for denormalization on the response path.
	Normalize(ctx context.Context, msg interface{}) (*CanonicalAction, error)

	// Denormalize converts an InterceptResult back to a protocol-specific response.
	// Uses CanonicalAction.OriginalMessage to construct the response.
	// For allow decisions, returns the original message.
	// For deny decisions, returns nil and an error describing the denial.
	Denormalize(action *CanonicalAction, result *InterceptResult) (interface{}, error)

	// Protocol returns the protocol name this normalizer handles (e.g., "mcp").
	Protocol() string
}
