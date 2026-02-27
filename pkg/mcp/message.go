// Package mcp provides MCP message types and JSON-RPC codec utilities
// for the sentinel-gate proxy.
package mcp

import (
	"encoding/json"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// Direction indicates the flow direction of a message through the proxy.
type Direction int

const (
	// ClientToServer indicates a message flowing from client to MCP server.
	ClientToServer Direction = iota
	// ServerToClient indicates a message flowing from MCP server to client.
	ServerToClient
)

// String returns the string representation of the Direction.
func (d Direction) String() string {
	switch d {
	case ClientToServer:
		return "client->server"
	case ServerToClient:
		return "server->client"
	default:
		return "unknown"
	}
}

// Message wraps a decoded JSON-RPC message with proxy metadata.
// It stores both the raw bytes (for efficient passthrough) and the decoded
// message (for policy inspection).
type Message struct {
	// Raw contains the original bytes of the message.
	// Used for passthrough when no modification is needed.
	Raw []byte

	// Direction indicates whether this message is flowing from
	// client to server or server to client.
	Direction Direction

	// Decoded contains the parsed JSON-RPC message.
	// May be nil if parsing failed but passthrough is still desired.
	// The concrete type is either *jsonrpc.Request or *jsonrpc.Response.
	Decoded jsonrpc.Message

	// Timestamp records when the message was received by the proxy.
	Timestamp time.Time

	// APIKey contains the raw API key extracted from the message.
	// Extracted from JSON-RPC params by ExtractAPIKey().
	// Used by AuthInterceptor for initial authentication.
	APIKey string

	// Session contains the authenticated user's session context.
	// Set by AuthInterceptor after successful authentication.
	// Used by policy engine for RBAC evaluation.
	Session *session.Session

	// FrameworkContext is nil in OSS (framework context is a PRO feature).
	// Field retained for interface compatibility with PRO.
	FrameworkContext interface{}

	// ParsedParams contains the parsed params from a JSON-RPC request.
	// Set by ParseParams() for reuse across interceptors.
	// Nil if not a request or parsing failed.
	ParsedParams map[string]interface{}
}

// IsRequest returns true if the message is a JSON-RPC request.
func (m *Message) IsRequest() bool {
	if m.Decoded == nil {
		return false
	}
	_, ok := m.Decoded.(*jsonrpc.Request)
	return ok
}

// IsResponse returns true if the message is a JSON-RPC response.
func (m *Message) IsResponse() bool {
	if m.Decoded == nil {
		return false
	}
	_, ok := m.Decoded.(*jsonrpc.Response)
	return ok
}

// Method returns the method name if this is a request, empty string otherwise.
func (m *Message) Method() string {
	if m.Decoded == nil {
		return ""
	}
	req, ok := m.Decoded.(*jsonrpc.Request)
	if !ok {
		return ""
	}
	return req.Method
}

// IsToolCall returns true if this is a tools/call request.
// This is the primary method for identifying tool invocations that need
// policy evaluation.
func (m *Message) IsToolCall() bool {
	return m.Method() == "tools/call"
}

// Request returns the underlying Request if this is a request message.
// Returns nil if this is not a request.
func (m *Message) Request() *jsonrpc.Request {
	if m.Decoded == nil {
		return nil
	}
	req, _ := m.Decoded.(*jsonrpc.Request)
	return req
}

// Response returns the underlying Response if this is a response message.
// Returns nil if this is not a response.
func (m *Message) Response() *jsonrpc.Response {
	if m.Decoded == nil {
		return nil
	}
	resp, _ := m.Decoded.(*jsonrpc.Response)
	return resp
}

// IsAuthenticated returns true if the message has a valid session.
func (m *Message) IsAuthenticated() bool {
	return m.Session != nil && !m.Session.IsExpired()
}

// HasAPIKey returns true if the message contains an API key.
func (m *Message) HasAPIKey() bool {
	return m.APIKey != ""
}

// ParseParams parses the request params and stores in ParsedParams.
// Safe to call multiple times (no-op if already parsed).
// Returns the parsed params or nil if not a request or parsing fails.
func (m *Message) ParseParams() map[string]interface{} {
	// Already parsed
	if m.ParsedParams != nil {
		return m.ParsedParams
	}

	req := m.Request()
	if req == nil || req.Params == nil {
		return nil
	}

	var params map[string]interface{}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil
	}

	m.ParsedParams = params
	return params
}

// ExtractAPIKey extracts the API key from JSON-RPC params.
// MCP doesn't use HTTP headers, so API key is passed in JSON-RPC params.
// Looks in these locations (in priority order):
// 1. params._meta.apiKey (MCP standard metadata location)
// 2. params.apiKey (top-level for simplicity)
// Returns empty string if not found (not an error - may use cached session).
func (m *Message) ExtractAPIKey() string {
	// Use parsed params if available, otherwise parse
	params := m.ParsedParams
	if params == nil {
		params = m.ParseParams()
	}
	if params == nil {
		return ""
	}

	// Check params._meta.apiKey first (MCP convention)
	if meta, ok := params["_meta"].(map[string]interface{}); ok {
		if apiKey, ok := meta["apiKey"].(string); ok && apiKey != "" {
			return apiKey
		}
	}

	// Fallback: check params.apiKey (simpler clients)
	if apiKey, ok := params["apiKey"].(string); ok {
		return apiKey
	}

	return ""
}

// HasFrameworkContext returns true if the message has framework context.
func (m *Message) HasFrameworkContext() bool {
	return m.FrameworkContext != nil
}

// RawID extracts the request ID from the raw message bytes as json.RawMessage.
// This is needed because the SDK's jsonrpc.ID type doesn't marshal correctly
// through interface{}, so we extract the ID directly from the raw JSON.
// Returns nil if no ID is found or if the message is not a request.
func (m *Message) RawID() json.RawMessage {
	if m.Raw == nil {
		return nil
	}

	// Parse raw bytes to extract "id" field
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(m.Raw, &raw); err != nil {
		return nil
	}

	// Return the raw ID value (preserves original format: number, string, or null)
	return raw["id"]
}
