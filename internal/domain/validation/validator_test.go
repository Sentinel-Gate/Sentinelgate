package validation

import (
	"encoding/json"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func TestMessageValidator_ValidRequest(t *testing.T) {
	v := NewMessageValidator()

	// Create a valid request
	id, _ := jsonrpc.MakeID(float64(1))
	req := &jsonrpc.Request{
		ID:     id,
		Method: "tools/list",
	}

	msg := &mcp.Message{
		Decoded: req,
	}

	err := v.Validate(msg)
	if err != nil {
		t.Errorf("expected no error for valid request, got: %v", err)
	}
}

func TestMessageValidator_ValidResponse(t *testing.T) {
	v := NewMessageValidator()

	// Create a valid response with result
	id, _ := jsonrpc.MakeID(float64(1))
	resp := &jsonrpc.Response{
		ID:     id,
		Result: json.RawMessage(`{"tools":[]}`),
	}

	msg := &mcp.Message{
		Decoded: resp,
	}

	err := v.Validate(msg)
	if err != nil {
		t.Errorf("expected no error for valid response, got: %v", err)
	}
}

func TestMessageValidator_ValidNotification(t *testing.T) {
	v := NewMessageValidator()

	// Create a valid notification (request with no ID)
	req := &jsonrpc.Request{
		// ID is zero value (not set) - makes this a notification
		Method: "notifications/progress",
	}

	msg := &mcp.Message{
		Decoded: req,
	}

	err := v.Validate(msg)
	if err != nil {
		t.Errorf("expected no error for valid notification, got: %v", err)
	}
}

func TestMessageValidator_NilDecoded(t *testing.T) {
	v := NewMessageValidator()

	msg := &mcp.Message{
		Decoded: nil,
	}

	err := v.Validate(msg)
	if err == nil {
		t.Fatal("expected error for nil decoded, got nil")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	if valErr.Code != ErrCodeParseError {
		t.Errorf("expected code %d, got %d", ErrCodeParseError, valErr.Code)
	}
}

func TestMessageValidator_RequestMissingID(t *testing.T) {
	v := NewMessageValidator()

	// A request with no ID is a notification, which is valid if method is present
	// So we test that a notification without method fails
	req := &jsonrpc.Request{
		// No ID - this is a notification
		Method: "", // Empty method should fail
	}

	msg := &mcp.Message{
		Decoded: req,
	}

	err := v.Validate(msg)
	if err == nil {
		t.Fatal("expected error for notification missing method, got nil")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	if valErr.Code != ErrCodeInvalidRequest {
		t.Errorf("expected code %d, got %d", ErrCodeInvalidRequest, valErr.Code)
	}
}

func TestMessageValidator_RequestMissingMethod(t *testing.T) {
	v := NewMessageValidator()

	id, _ := jsonrpc.MakeID(float64(1))
	req := &jsonrpc.Request{
		ID:     id,
		Method: "", // Empty method
	}

	msg := &mcp.Message{
		Decoded: req,
	}

	err := v.Validate(msg)
	if err == nil {
		t.Fatal("expected error for missing method, got nil")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	if valErr.Code != ErrCodeInvalidRequest {
		t.Errorf("expected code %d, got %d", ErrCodeInvalidRequest, valErr.Code)
	}
}

func TestMessageValidator_RequestUnknownMethod(t *testing.T) {
	v := NewMessageValidator()

	id, _ := jsonrpc.MakeID(float64(1))
	req := &jsonrpc.Request{
		ID:     id,
		Method: "unknown/method", // Not in ValidMCPMethods
	}

	msg := &mcp.Message{
		Decoded: req,
	}

	err := v.Validate(msg)
	if err == nil {
		t.Fatal("expected error for unknown method, got nil")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	if valErr.Code != ErrCodeMethodNotFound {
		t.Errorf("expected code %d, got %d", ErrCodeMethodNotFound, valErr.Code)
	}
}

func TestMessageValidator_ResponseMissingID(t *testing.T) {
	v := NewMessageValidator()

	resp := &jsonrpc.Response{
		// ID is zero value (invalid)
		Result: json.RawMessage(`{}`),
	}

	msg := &mcp.Message{
		Decoded: resp,
	}

	err := v.Validate(msg)
	if err == nil {
		t.Fatal("expected error for response missing ID, got nil")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	if valErr.Code != ErrCodeInvalidRequest {
		t.Errorf("expected code %d, got %d", ErrCodeInvalidRequest, valErr.Code)
	}
}

func TestMessageValidator_ResponseBothResultAndError(t *testing.T) {
	v := NewMessageValidator()

	id, _ := jsonrpc.MakeID(float64(1))
	resp := &jsonrpc.Response{
		ID:     id,
		Result: json.RawMessage(`{}`),
		Error:  &jsonrpc.Error{Code: -32000, Message: "some error"},
	}

	msg := &mcp.Message{
		Decoded: resp,
	}

	err := v.Validate(msg)
	if err == nil {
		t.Fatal("expected error for response with both result and error, got nil")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	if valErr.Code != ErrCodeInvalidRequest {
		t.Errorf("expected code %d, got %d", ErrCodeInvalidRequest, valErr.Code)
	}
}

func TestMessageValidator_ResponseNeitherResultNorError(t *testing.T) {
	v := NewMessageValidator()

	id, _ := jsonrpc.MakeID(float64(1))
	resp := &jsonrpc.Response{
		ID: id,
		// No Result, no Error
	}

	msg := &mcp.Message{
		Decoded: resp,
	}

	err := v.Validate(msg)
	if err == nil {
		t.Fatal("expected error for response with neither result nor error, got nil")
	}

	valErr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	if valErr.Code != ErrCodeInvalidRequest {
		t.Errorf("expected code %d, got %d", ErrCodeInvalidRequest, valErr.Code)
	}
}

func TestMessageValidator_AllValidMethods(t *testing.T) {
	v := NewMessageValidator()

	for method := range ValidMCPMethods {
		t.Run(method, func(t *testing.T) {
			id, _ := jsonrpc.MakeID(float64(1))
			req := &jsonrpc.Request{
				ID:     id,
				Method: method,
			}

			msg := &mcp.Message{
				Decoded: req,
			}

			err := v.Validate(msg)
			if err != nil {
				t.Errorf("expected valid MCP method %q to pass validation, got: %v", method, err)
			}
		})
	}
}

func TestMessageValidator_ResponseWithErrorOnly(t *testing.T) {
	v := NewMessageValidator()

	id, _ := jsonrpc.MakeID(float64(1))
	resp := &jsonrpc.Response{
		ID:    id,
		Error: &jsonrpc.Error{Code: -32600, Message: "Invalid Request"},
	}

	msg := &mcp.Message{
		Decoded: resp,
	}

	err := v.Validate(msg)
	if err != nil {
		t.Errorf("expected no error for response with error only, got: %v", err)
	}
}
