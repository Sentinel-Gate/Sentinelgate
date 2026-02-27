package validation

import (
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// MessageValidator validates MCP messages for JSON-RPC compliance
// and MCP-specific requirements.
type MessageValidator struct{}

// NewMessageValidator creates a new MessageValidator.
func NewMessageValidator() *MessageValidator {
	return &MessageValidator{}
}

// Validate checks if the message is a valid JSON-RPC/MCP message.
// Returns nil if valid, or a *ValidationError if invalid.
//
// Validation rules:
// - Message must have a non-nil Decoded field (parse error if nil)
// - Requests must have non-nil ID and non-empty Method
// - Request Method must be a valid MCP method
// - Notifications (Request with nil ID) must have non-empty Method
// - Responses must have ID and either Result or Error (not both, not neither)
func (v *MessageValidator) Validate(msg *mcp.Message) error {
	if msg.Decoded == nil {
		return NewValidationError(ErrCodeParseError, "Parse error")
	}

	switch m := msg.Decoded.(type) {
	case *jsonrpc.Request:
		return v.validateRequest(m)

	case *jsonrpc.Response:
		return v.validateResponse(m)

	default:
		return NewValidationError(ErrCodeInvalidRequest, "Invalid Request")
	}
}

// validateRequest validates a JSON-RPC request or notification.
// In the MCP SDK, a notification is a Request with nil ID.
func (v *MessageValidator) validateRequest(req *jsonrpc.Request) error {
	// Check if this is a call (has ID) or notification (no ID)
	isCall := req.IsCall()

	if isCall {
		// For calls, ID is already guaranteed non-nil by IsCall()
		// Validate method is present
		if req.Method == "" {
			return NewValidationError(ErrCodeInvalidRequest, "Invalid Request")
		}

		// Validate method is a known MCP method
		if !IsValidMCPMethod(req.Method) {
			return NewValidationError(ErrCodeMethodNotFound, "Method not found")
		}
	} else {
		// For notifications, validate method is present
		if req.Method == "" {
			return NewValidationError(ErrCodeInvalidRequest, "Invalid Request")
		}

		// Validate method is a known MCP method (notifications too)
		if !IsValidMCPMethod(req.Method) {
			return NewValidationError(ErrCodeMethodNotFound, "Method not found")
		}
	}

	return nil
}

// validateResponse validates a JSON-RPC response.
func (v *MessageValidator) validateResponse(resp *jsonrpc.Response) error {
	// Response must have an ID
	if !resp.ID.IsValid() {
		return NewValidationError(ErrCodeInvalidRequest, "Invalid Request")
	}

	// Response must have either Result or Error, but not both
	hasResult := resp.Result != nil
	hasError := resp.Error != nil

	if hasResult && hasError {
		return NewValidationError(ErrCodeInvalidRequest, "Invalid Request")
	}

	if !hasResult && !hasError {
		return NewValidationError(ErrCodeInvalidRequest, "Invalid Request")
	}

	return nil
}

// Compile-time check that MessageValidator can be used.
var _ = NewMessageValidator()
