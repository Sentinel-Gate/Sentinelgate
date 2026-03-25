// Package validation provides MCP message validation logic.
// It validates JSON-RPC structure and MCP-specific requirements
// to reject malformed messages early in the proxy chain.
package validation

import "fmt"

// JSON-RPC 2.0 standard error codes.
// These are defined in the JSON-RPC 2.0 specification:
// https://www.jsonrpc.org/specification#error_object
const (
	// ErrCodeParseError indicates invalid JSON was received.
	ErrCodeParseError = -32700

	// ErrCodeInvalidRequest indicates the JSON is not a valid Request object.
	ErrCodeInvalidRequest = -32600

	// ErrCodeMethodNotFound indicates the method does not exist or is not available.
	ErrCodeMethodNotFound = -32601

	// ErrCodeInvalidParams indicates invalid method parameters.
	ErrCodeInvalidParams = -32602

	// ErrCodeInternalError indicates an internal JSON-RPC error.
	ErrCodeInternalError = -32603
)

// ValidationError represents a validation failure with a JSON-RPC error code.
// The Message field contains a safe message for the client (no internal details).
type ValidationError struct {
	// Code is the JSON-RPC error code.
	Code int

	// Message is a safe, client-facing error message.
	// This MUST NOT contain internal details like file paths or stack traces.
	Message string
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error %d: %s", e.Code, e.Message)
}

// NewValidationError creates a new ValidationError with the given code and message.
func NewValidationError(code int, message string) *ValidationError {
	return &ValidationError{
		Code:    code,
		Message: message,
	}
}
