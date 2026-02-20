package mcp

import (
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// EncodeMessage serializes a JSON-RPC message to its wire format.
// This delegates to the MCP SDK's jsonrpc package.
func EncodeMessage(msg jsonrpc.Message) ([]byte, error) {
	return jsonrpc.EncodeMessage(msg)
}

// DecodeMessage deserializes JSON-RPC wire format data into a Message.
// It returns either a *jsonrpc.Request or *jsonrpc.Response based on the message content.
// This delegates to the MCP SDK's jsonrpc package.
func DecodeMessage(data []byte) (jsonrpc.Message, error) {
	return jsonrpc.DecodeMessage(data)
}

// WrapMessage decodes raw JSON-RPC bytes and wraps them in a Message struct
// with the specified direction and current timestamp.
//
// If decoding fails, returns an error. For passthrough scenarios where
// the raw bytes should be preserved even on decode failure, callers can
// construct a Message manually.
func WrapMessage(raw []byte, dir Direction) (*Message, error) {
	decoded, err := jsonrpc.DecodeMessage(raw)
	if err != nil {
		return nil, err
	}

	return &Message{
		Raw:       raw,
		Direction: dir,
		Decoded:   decoded,
		Timestamp: time.Now(),
	}, nil
}
