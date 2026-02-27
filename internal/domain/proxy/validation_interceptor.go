// Package proxy contains the core domain logic for the MCP proxy.
package proxy

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/validation"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// ValidationInterceptor validates incoming messages before authentication.
// It ensures JSON-RPC structure compliance, tracks pending requests for
// confused deputy protection, and sanitizes tool call arguments.
//
// Must be first in the interceptor chain (before AuthInterceptor).
type ValidationInterceptor struct {
	next            MessageInterceptor
	validator       *validation.MessageValidator
	sanitizer       *validation.Sanitizer
	logger          *slog.Logger
	pendingRequests sync.Map // map[interface{}]struct{} for request ID tracking
}

// NewValidationInterceptor creates a new ValidationInterceptor.
// It wraps the next interceptor in the chain (typically AuthInterceptor).
func NewValidationInterceptor(next MessageInterceptor, logger *slog.Logger) *ValidationInterceptor {
	return &ValidationInterceptor{
		next:      next,
		validator: validation.NewMessageValidator(),
		sanitizer: validation.NewSanitizer(),
		logger:    logger,
	}
}

// Intercept validates the message based on direction.
// ClientToServer messages are validated and sanitized.
// ServerToClient messages are checked for confused deputy attacks.
func (v *ValidationInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	if msg.Direction == mcp.ClientToServer {
		return v.validateClientMessage(ctx, msg)
	}
	return v.validateServerMessage(ctx, msg)
}

// validateClientMessage validates and sanitizes client messages.
func (v *ValidationInterceptor) validateClientMessage(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// Step 1: Validate JSON-RPC structure
	if err := v.validator.Validate(msg); err != nil {
		v.logger.Warn("invalid JSON-RPC message",
			"error", err,
			"direction", msg.Direction.String(),
		)
		// Return the ValidationError (contains safe message)
		if valErr, ok := err.(*validation.ValidationError); ok {
			return nil, valErr
		}
		return nil, validation.NewValidationError(validation.ErrCodeInvalidRequest, "Invalid Request")
	}

	// Step 2: Track request ID for confused deputy protection
	if req := msg.Request(); req != nil && req.IsCall() {
		// Store request ID to verify matching response later
		v.pendingRequests.Store(req.ID, struct{}{})
	}

	// Step 3: For tool calls, sanitize arguments
	if msg.IsToolCall() {
		if err := v.sanitizeToolCallArguments(msg); err != nil {
			v.logger.Warn("tool call sanitization failed",
				"error", err,
			)
			// Return the ValidationError (contains safe message)
			if valErr, ok := err.(*validation.ValidationError); ok {
				return nil, valErr
			}
			return nil, validation.NewValidationError(validation.ErrCodeInvalidParams, "Invalid tool call parameters")
		}
	}

	// Step 4: Pass to next interceptor
	return v.next.Intercept(ctx, msg)
}

// validateServerMessage validates server responses against pending requests.
// This prevents confused deputy attacks where a malicious server sends
// unsolicited responses.
func (v *ValidationInterceptor) validateServerMessage(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// Check if this is a response
	if resp := msg.Response(); resp != nil {
		// Verify response ID matches a pending request
		_, exists := v.pendingRequests.LoadAndDelete(resp.ID)
		if !exists {
			v.logger.Warn("unexpected response ID (confused deputy protection)",
				"response_id", resp.ID,
			)
			return nil, validation.NewValidationError(validation.ErrCodeInternalError, "Invalid response")
		}
	}

	// Pass to next interceptor
	return v.next.Intercept(ctx, msg)
}

// sanitizeToolCallArguments extracts params, sanitizes them, and re-encodes.
func (v *ValidationInterceptor) sanitizeToolCallArguments(msg *mcp.Message) error {
	req := msg.Request()
	if req == nil || req.Params == nil {
		return validation.NewValidationError(validation.ErrCodeInvalidParams, "Missing params")
	}

	// Parse params as map
	var params map[string]interface{}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return validation.NewValidationError(validation.ErrCodeInvalidParams, "Invalid params")
	}

	// Sanitize tool call (validates name, sanitizes arguments)
	sanitized, err := v.sanitizer.SanitizeToolCall(params)
	if err != nil {
		return err // Already a ValidationError
	}

	// Re-encode sanitized params back to the request
	sanitizedBytes, err := json.Marshal(sanitized)
	if err != nil {
		return validation.NewValidationError(validation.ErrCodeInternalError, "Request processing error")
	}
	req.Params = sanitizedBytes

	return nil
}

// Compile-time check that ValidationInterceptor implements MessageInterceptor.
var _ MessageInterceptor = (*ValidationInterceptor)(nil)
