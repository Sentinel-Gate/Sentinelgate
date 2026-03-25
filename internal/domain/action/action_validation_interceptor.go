package action

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/validation"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// ActionValidationInterceptor validates incoming messages before authentication.
// It ensures JSON-RPC structure compliance, tracks pending requests for
// confused deputy protection, and sanitizes tool call arguments.
// Native ActionInterceptor replacement for proxy.ValidationInterceptor.
//
// Must be first in the interceptor chain (before ActionAuthInterceptor).
type ActionValidationInterceptor struct {
	next            ActionInterceptor
	validator       *validation.MessageValidator
	sanitizer       *validation.Sanitizer
	logger          *slog.Logger
	pendingRequests sync.Map // map[interface{}]struct{} for request ID tracking
}

// Compile-time check that ActionValidationInterceptor implements ActionInterceptor.
var _ ActionInterceptor = (*ActionValidationInterceptor)(nil)

// NewActionValidationInterceptor creates a new ActionValidationInterceptor.
func NewActionValidationInterceptor(next ActionInterceptor, logger *slog.Logger) *ActionValidationInterceptor {
	return &ActionValidationInterceptor{
		next:      next,
		validator: validation.NewMessageValidator(),
		sanitizer: validation.NewSanitizer(),
		logger:    logger,
	}
}

// Intercept validates the message based on direction.
func (v *ActionValidationInterceptor) Intercept(ctx context.Context, act *CanonicalAction) (*CanonicalAction, error) {
	mcpMsg, ok := act.OriginalMessage.(*mcp.Message)
	if !ok {
		return v.next.Intercept(ctx, act)
	}

	if mcpMsg.Direction == mcp.ClientToServer {
		return v.validateClientMessage(ctx, act, mcpMsg)
	}
	return v.validateServerMessage(ctx, act, mcpMsg)
}

// validateClientMessage validates and sanitizes client messages.
func (v *ActionValidationInterceptor) validateClientMessage(ctx context.Context, act *CanonicalAction, mcpMsg *mcp.Message) (*CanonicalAction, error) {
	// Step 1: Validate JSON-RPC structure
	if err := v.validator.Validate(mcpMsg); err != nil {
		v.logger.Warn("invalid JSON-RPC message",
			"error", err,
			"direction", mcpMsg.Direction.String(),
		)
		if valErr, ok := err.(*validation.ValidationError); ok {
			return nil, valErr
		}
		return nil, validation.NewValidationError(validation.ErrCodeInvalidRequest, "Invalid Request")
	}

	// Step 2: Track request ID for confused deputy protection (normalized to string)
	// M-13: Store before calling next; remove on error to prevent unbounded leak.
	var pendingKey string
	if req := mcpMsg.Request(); req != nil && req.IsCall() {
		pendingKey = fmt.Sprintf("%v", req.ID)
		v.pendingRequests.Store(pendingKey, struct{}{})
	}

	// Step 3: For tool calls, sanitize arguments
	if mcpMsg.IsToolCall() {
		if err := v.sanitizeToolCallArguments(act, mcpMsg); err != nil {
			// M-13: Clean up pending entry on rejection.
			if pendingKey != "" {
				v.pendingRequests.Delete(pendingKey)
			}
			v.logger.Warn("tool call sanitization failed",
				"error", err,
			)
			if valErr, ok := err.(*validation.ValidationError); ok {
				return nil, valErr
			}
			return nil, validation.NewValidationError(validation.ErrCodeInvalidParams, "Invalid tool call parameters")
		}
	}

	resp, err := v.next.Intercept(ctx, act)
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
func (v *ActionValidationInterceptor) validateServerMessage(ctx context.Context, act *CanonicalAction, mcpMsg *mcp.Message) (*CanonicalAction, error) {
	if resp := mcpMsg.Response(); resp != nil {
		key := fmt.Sprintf("%v", resp.ID)
		_, exists := v.pendingRequests.LoadAndDelete(key)
		if !exists {
			v.logger.Warn("unexpected response ID (confused deputy protection)",
				"response_id", resp.ID,
			)
			return nil, validation.NewValidationError(validation.ErrCodeInternalError, "Invalid response")
		}
	}

	return v.next.Intercept(ctx, act)
}

func (v *ActionValidationInterceptor) Reset() {
	v.pendingRequests.Range(func(k, _ any) bool {
		v.pendingRequests.Delete(k)
		return true
	})
}

// sanitizeToolCallArguments sanitizes tool call params and syncs to both
// the mcp.Message (for downstream mcp-specific code) and the CanonicalAction.
func (v *ActionValidationInterceptor) sanitizeToolCallArguments(act *CanonicalAction, mcpMsg *mcp.Message) error {
	req := mcpMsg.Request()
	if req == nil || req.Params == nil {
		return validation.NewValidationError(validation.ErrCodeInvalidParams, "Missing params")
	}

	var params map[string]interface{}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return validation.NewValidationError(validation.ErrCodeInvalidParams, "Invalid params")
	}

	sanitized, err := v.sanitizer.SanitizeToolCall(params)
	if err != nil {
		return err // Already a ValidationError
	}

	// Re-encode sanitized params back to the mcp.Message
	sanitizedBytes, err := json.Marshal(sanitized)
	if err != nil {
		return validation.NewValidationError(validation.ErrCodeInternalError, "Request processing error")
	}
	req.Params = sanitizedBytes

	// Update mcpMsg.Raw so downstream forwarding uses sanitized data
	var rawMsg map[string]json.RawMessage
	if err := json.Unmarshal(mcpMsg.Raw, &rawMsg); err == nil {
		rawMsg["params"] = sanitizedBytes
		if newRaw, err := json.Marshal(rawMsg); err == nil {
			mcpMsg.Raw = newRaw
		}
	}
	mcpMsg.ParsedParams = nil // invalidate cached params

	// Sync sanitized values to CanonicalAction
	if args, ok := sanitized["arguments"].(map[string]interface{}); ok {
		act.Arguments = args
	}
	if name, ok := sanitized["name"].(string); ok {
		act.Name = name
	}

	return nil
}
