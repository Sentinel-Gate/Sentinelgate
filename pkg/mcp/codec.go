package mcp

import (
	"encoding/json"
	"fmt"
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
// This delegates to the MCP SDK's jsonrpc package, with additional validation
// for edge cases the SDK does not reject (e.g. "method": null).
func DecodeMessage(data []byte) (jsonrpc.Message, error) {
	// Pre-validate: reject "method": null before the SDK sees it.
	// Per JSON-RPC 2.0, method MUST be a string. The SDK silently accepts null.
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) == nil {
		if methodRaw, exists := raw["method"]; exists && string(methodRaw) == "null" {
			return nil, fmt.Errorf("invalid JSON-RPC: method must be a string, got null")
		}
	}

	msg, err := jsonrpc.DecodeMessage(data)
	if err != nil {
		return nil, err
	}
	return msg, nil
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
