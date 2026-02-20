package proxy_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/validation"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// mockInterceptor records calls and returns configurable results.
type mockInterceptor struct {
	calledWith *mcp.Message
	returnMsg  *mcp.Message
	returnErr  error
}

func (m *mockInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	m.calledWith = msg
	if m.returnMsg != nil {
		return m.returnMsg, m.returnErr
	}
	return msg, m.returnErr
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// helper to create ID without error handling noise
func makeID(v float64) jsonrpc.ID {
	id, _ := jsonrpc.MakeID(v)
	return id
}

func TestValidationInterceptor_ValidRequest_PassesThrough(t *testing.T) {
	mock := &mockInterceptor{}
	interceptor := proxy.NewValidationInterceptor(mock, newTestLogger())

	// Create a valid initialize request
	req := &jsonrpc.Request{
		ID:     makeID(1),
		Method: "initialize",
	}
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Decoded:   req,
	}

	result, err := interceptor.Intercept(context.Background(), msg)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != msg {
		t.Error("expected same message to be returned")
	}
	if mock.calledWith != msg {
		t.Error("expected next interceptor to be called with message")
	}
}

func TestValidationInterceptor_InvalidRequest_ReturnsError(t *testing.T) {
	mock := &mockInterceptor{}
	interceptor := proxy.NewValidationInterceptor(mock, newTestLogger())

	// Create a message with nil Decoded (parse error simulation)
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Decoded:   nil,
	}

	result, err := interceptor.Intercept(context.Background(), msg)

	if err == nil {
		t.Error("expected error for invalid message")
	}
	if result != nil {
		t.Error("expected nil result for invalid message")
	}
	if mock.calledWith != nil {
		t.Error("expected next interceptor NOT to be called")
	}

	// Check error is a ValidationError with correct code
	valErr, ok := err.(*validation.ValidationError)
	if !ok {
		t.Errorf("expected ValidationError, got %T", err)
	}
	if valErr.Code != validation.ErrCodeParseError {
		t.Errorf("expected ErrCodeParseError (%d), got %d", validation.ErrCodeParseError, valErr.Code)
	}
}

func TestValidationInterceptor_TracksRequestID(t *testing.T) {
	mock := &mockInterceptor{}
	interceptor := proxy.NewValidationInterceptor(mock, newTestLogger())

	// Send a request (client -> server)
	req := &jsonrpc.Request{
		ID:     makeID(42),
		Method: "ping",
	}
	clientMsg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Decoded:   req,
	}

	_, err := interceptor.Intercept(context.Background(), clientMsg)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// Now send a valid response with matching ID (server -> client)
	resp := &jsonrpc.Response{
		ID:     makeID(42),
		Result: json.RawMessage(`{}`),
	}
	serverMsg := &mcp.Message{
		Direction: mcp.ServerToClient,
		Decoded:   resp,
	}

	_, err = interceptor.Intercept(context.Background(), serverMsg)
	if err != nil {
		t.Errorf("expected valid response to pass, got error: %v", err)
	}
}

func TestValidationInterceptor_ValidatesServerResponse_ConfusedDeputy(t *testing.T) {
	mock := &mockInterceptor{}
	interceptor := proxy.NewValidationInterceptor(mock, newTestLogger())

	// Send a request with ID 1
	req := &jsonrpc.Request{
		ID:     makeID(1),
		Method: "ping",
	}
	clientMsg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Decoded:   req,
	}
	_, _ = interceptor.Intercept(context.Background(), clientMsg)

	// Try to send a response with a DIFFERENT ID (confused deputy attack)
	resp := &jsonrpc.Response{
		ID:     makeID(999), // Wrong ID!
		Result: json.RawMessage(`{}`),
	}
	serverMsg := &mcp.Message{
		Direction: mcp.ServerToClient,
		Decoded:   resp,
	}

	result, err := interceptor.Intercept(context.Background(), serverMsg)

	if err == nil {
		t.Error("expected error for confused deputy attack")
	}
	if result != nil {
		t.Error("expected nil result for rejected response")
	}

	// Check it's a ValidationError
	valErr, ok := err.(*validation.ValidationError)
	if !ok {
		t.Errorf("expected ValidationError, got %T", err)
	}
	if valErr.Code != validation.ErrCodeInternalError {
		t.Errorf("expected ErrCodeInternalError (%d), got %d", validation.ErrCodeInternalError, valErr.Code)
	}
}

func TestValidationInterceptor_RejectsUnexpectedResponse(t *testing.T) {
	mock := &mockInterceptor{}
	interceptor := proxy.NewValidationInterceptor(mock, newTestLogger())

	// Don't send any request - just try to receive a response
	resp := &jsonrpc.Response{
		ID:     makeID(123),
		Result: json.RawMessage(`{}`),
	}
	serverMsg := &mcp.Message{
		Direction: mcp.ServerToClient,
		Decoded:   resp,
	}

	result, err := interceptor.Intercept(context.Background(), serverMsg)

	if err == nil {
		t.Error("expected error for unexpected response")
	}
	if result != nil {
		t.Error("expected nil result for rejected response")
	}
}

func TestValidationInterceptor_SanitizesToolCallArguments(t *testing.T) {
	mock := &mockInterceptor{}
	interceptor := proxy.NewValidationInterceptor(mock, newTestLogger())

	// Create a tool call with null bytes in arguments
	params := map[string]interface{}{
		"name": "test_tool",
		"arguments": map[string]interface{}{
			"path": "/home/user\x00/evil",
		},
	}
	paramsBytes, _ := json.Marshal(params)

	req := &jsonrpc.Request{
		ID:     makeID(1),
		Method: "tools/call",
		Params: paramsBytes,
	}
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Decoded:   req,
	}

	result, err := interceptor.Intercept(context.Background(), msg)

	if err != nil {
		t.Errorf("expected sanitization to succeed, got error: %v", err)
	}
	if result == nil {
		t.Fatal("expected message to be returned")
	}

	// Check the params were sanitized (null byte removed)
	var sanitizedParams map[string]interface{}
	if err := json.Unmarshal(req.Params, &sanitizedParams); err != nil {
		t.Fatalf("failed to unmarshal sanitized params: %v", err)
	}

	args := sanitizedParams["arguments"].(map[string]interface{})
	path := args["path"].(string)
	if path != "/home/user/evil" {
		t.Errorf("expected null byte to be removed, got %q", path)
	}
}

func TestValidationInterceptor_PreservesNonToolCallMessages(t *testing.T) {
	mock := &mockInterceptor{}
	interceptor := proxy.NewValidationInterceptor(mock, newTestLogger())

	// Create a tools/list request (not tools/call)
	req := &jsonrpc.Request{
		ID:     makeID(1),
		Method: "tools/list",
	}
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Decoded:   req,
	}

	result, err := interceptor.Intercept(context.Background(), msg)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if result != msg {
		t.Error("expected same message to be returned")
	}
}

func TestValidationInterceptor_RejectsInvalidToolName(t *testing.T) {
	mock := &mockInterceptor{}
	interceptor := proxy.NewValidationInterceptor(mock, newTestLogger())

	// Create a tool call with path traversal in name
	params := map[string]interface{}{
		"name":      "../../../etc/passwd",
		"arguments": map[string]interface{}{},
	}
	paramsBytes, _ := json.Marshal(params)

	req := &jsonrpc.Request{
		ID:     makeID(1),
		Method: "tools/call",
		Params: paramsBytes,
	}
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Decoded:   req,
	}

	result, err := interceptor.Intercept(context.Background(), msg)

	if err == nil {
		t.Error("expected error for invalid tool name")
	}
	if result != nil {
		t.Error("expected nil result for rejected tool call")
	}

	valErr, ok := err.(*validation.ValidationError)
	if !ok {
		t.Errorf("expected ValidationError, got %T", err)
	}
	if valErr.Code != validation.ErrCodeInvalidParams {
		t.Errorf("expected ErrCodeInvalidParams (%d), got %d", validation.ErrCodeInvalidParams, valErr.Code)
	}
}

func TestValidationInterceptor_RejectsUnknownMethod(t *testing.T) {
	mock := &mockInterceptor{}
	interceptor := proxy.NewValidationInterceptor(mock, newTestLogger())

	// Create a request with unknown method
	req := &jsonrpc.Request{
		ID:     makeID(1),
		Method: "unknown/method",
	}
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Decoded:   req,
	}

	result, err := interceptor.Intercept(context.Background(), msg)

	if err == nil {
		t.Error("expected error for unknown method")
	}
	if result != nil {
		t.Error("expected nil result")
	}

	valErr, ok := err.(*validation.ValidationError)
	if !ok {
		t.Errorf("expected ValidationError, got %T", err)
	}
	if valErr.Code != validation.ErrCodeMethodNotFound {
		t.Errorf("expected ErrCodeMethodNotFound (%d), got %d", validation.ErrCodeMethodNotFound, valErr.Code)
	}
}

func TestValidationInterceptor_PassesServerNotifications(t *testing.T) {
	mock := &mockInterceptor{}
	interceptor := proxy.NewValidationInterceptor(mock, newTestLogger())

	// Server notifications (not responses) should pass through
	// Notifications are requests with nil ID
	notification := &jsonrpc.Request{
		ID:     jsonrpc.ID{}, // Zero value = invalid/nil
		Method: "notifications/message",
	}
	msg := &mcp.Message{
		Direction: mcp.ServerToClient,
		Decoded:   notification,
	}

	result, err := interceptor.Intercept(context.Background(), msg)

	if err != nil {
		t.Errorf("expected notification to pass, got error: %v", err)
	}
	if result == nil {
		t.Error("expected message to be returned")
	}
}
