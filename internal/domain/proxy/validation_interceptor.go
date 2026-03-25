// Package proxy contains the core domain logic for the MCP proxy.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
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

	// Step 2: Track request ID for confused deputy protection.
	// Normalize ID to string so that e.g. int(1) and string("1") from
	// different JSON decodings match as the same sync.Map key.
	// M-13: Store before calling next; remove on error to prevent unbounded leak.
	var pendingKey string
	if req := msg.Request(); req != nil && req.IsCall() {
		pendingKey = fmt.Sprintf("%v", req.ID)
		v.pendingRequests.Store(pendingKey, struct{}{})
	}

	// Step 3: For tool calls, sanitize arguments
	if msg.IsToolCall() {
		if err := v.sanitizeToolCallArguments(msg); err != nil {
			// M-13: Clean up pending entry on rejection.
			if pendingKey != "" {
				v.pendingRequests.Delete(pendingKey)
			}
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
	resp, err := v.next.Intercept(ctx, msg)
	if err != nil {
		// M-13: Clean up pending entry when downstream rejects the request.
		if pendingKey != "" {
			v.pendingRequests.Delete(pendingKey)
		}
		return nil, err
	}
	return resp, nil
}

// validateServerMessage validates server responses against pending requests.
// This prevents confused deputy attacks where a malicious server sends
// unsolicited responses.
func (v *ValidationInterceptor) validateServerMessage(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// Check if this is a response
	if resp := msg.Response(); resp != nil {
		// Verify response ID matches a pending request (normalized to string).
		key := fmt.Sprintf("%v", resp.ID)
		_, exists := v.pendingRequests.LoadAndDelete(key)
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

	// Update msg.Raw so downstream forwarding uses sanitized data
	var rawMsg map[string]json.RawMessage
	if err := json.Unmarshal(msg.Raw, &rawMsg); err == nil {
		rawMsg["params"] = sanitizedBytes
		if newRaw, err := json.Marshal(rawMsg); err == nil {
			msg.Raw = newRaw
		}
	}
	msg.ParsedParams = nil // invalidate cached params

	return nil
}

func (v *ValidationInterceptor) Reset() {
	v.pendingRequests.Range(func(k, _ any) bool {
		v.pendingRequests.Delete(k)
		return true
	})
}

// Compile-time check that ValidationInterceptor implements MessageInterceptor.
var _ MessageInterceptor = (*ValidationInterceptor)(nil)
