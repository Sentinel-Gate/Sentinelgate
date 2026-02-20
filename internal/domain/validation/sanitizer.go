// Package validation provides MCP message validation logic.
package validation

import (
	"regexp"
	"strings"
)

// Size limits for sanitization.
const (
	// MaxStringLength is the maximum length of any string value (1MB).
	// Strings longer than this are truncated to prevent memory exhaustion.
	MaxStringLength = 1048576

	// MaxToolNameLength is the maximum length of a tool name.
	MaxToolNameLength = 255
)

// toolNamePattern validates tool names.
// Tool names must start with a letter and contain only alphanumeric characters,
// underscores, and hyphens. This prevents injection attacks via tool names.
var toolNamePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`)

// Sanitizer provides input sanitization for tool call arguments.
// It validates tool names and recursively sanitizes string values
// to prevent injection attacks and policy bypass attempts.
type Sanitizer struct {
	// Stateless - regex is package-level
}

// NewSanitizer creates a new Sanitizer instance.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{}
}

// ValidateToolName validates a tool name against injection patterns.
// It returns a ValidationError if the name is invalid.
//
// Valid tool names:
//   - Start with a letter
//   - Contain only alphanumeric characters, underscores, and hyphens
//   - Are at most MaxToolNameLength characters
//   - Do not contain path traversal sequences
func (s *Sanitizer) ValidateToolName(name string) error {
	// Empty name check
	if name == "" {
		return NewValidationError(ErrCodeInvalidParams, "tool name is required")
	}

	// Length check
	if len(name) > MaxToolNameLength {
		return NewValidationError(ErrCodeInvalidParams, "tool name too long")
	}

	// Path traversal check (before pattern match for clearer error)
	if strings.Contains(name, "..") || strings.Contains(name, "/") {
		return NewValidationError(ErrCodeInvalidParams, "invalid characters in tool name")
	}

	// Pattern check
	if !toolNamePattern.MatchString(name) {
		return NewValidationError(ErrCodeInvalidParams, "invalid tool name format")
	}

	return nil
}

// SanitizeValue recursively sanitizes a value.
// For strings, it removes null bytes and truncates at MaxStringLength.
// For maps and slices, it recurses into each element.
// For other types (numbers, booleans, nil), it returns them unchanged.
func (s *Sanitizer) SanitizeValue(v interface{}) (interface{}, error) {
	switch val := v.(type) {
	case string:
		return s.sanitizeString(val), nil

	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, v := range val {
			sanitized, err := s.SanitizeValue(v)
			if err != nil {
				return nil, err
			}
			result[k] = sanitized
		}
		return result, nil

	case []interface{}:
		result := make([]interface{}, len(val))
		for i, v := range val {
			sanitized, err := s.SanitizeValue(v)
			if err != nil {
				return nil, err
			}
			result[i] = sanitized
		}
		return result, nil

	default:
		// Numbers, booleans, nil pass through unchanged
		return v, nil
	}
}

// sanitizeString removes null bytes and truncates oversized strings.
func (s *Sanitizer) sanitizeString(str string) string {
	// Remove null bytes
	str = strings.ReplaceAll(str, "\x00", "")

	// Truncate if too long
	if len(str) > MaxStringLength {
		str = str[:MaxStringLength]
	}

	return str
}

// SanitizeToolCall sanitizes tool call parameters.
// It validates the tool name and sanitizes all argument values.
//
// Expected params structure:
//
//	{
//	  "name": "tool_name",
//	  "arguments": { ... }
//	}
//
// Returns sanitized params with validated name and sanitized arguments.
func (s *Sanitizer) SanitizeToolCall(params map[string]interface{}) (map[string]interface{}, error) {
	// Extract and validate tool name
	name, ok := params["name"].(string)
	if !ok {
		return nil, NewValidationError(ErrCodeInvalidParams, "tool name is required")
	}

	if err := s.ValidateToolName(name); err != nil {
		return nil, err
	}

	// Create result with validated name
	result := make(map[string]interface{}, len(params))
	result["name"] = name

	// Copy and sanitize other fields
	for k, v := range params {
		if k == "name" {
			continue // Already handled
		}

		if k == "arguments" {
			// Sanitize arguments recursively
			sanitized, err := s.SanitizeValue(v)
			if err != nil {
				return nil, err
			}
			result[k] = sanitized
		} else {
			// Pass through other fields (like _meta)
			result[k] = v
		}
	}

	return result, nil
}
