package action

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/validation"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func newValidationLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestActionValidation_NonMCPMessage(t *testing.T) {
	interceptor := NewActionValidationInterceptor(&passThrough{}, newValidationLogger())

	// OriginalMessage is a plain string, not *mcp.Message -- should pass through
	act := &CanonicalAction{
		Type:            ActionToolCall,
		Name:            "test_tool",
		Arguments:       map[string]interface{}{"key": "value"},
		OriginalMessage: "not-an-mcp-message",
	}

	result, err := interceptor.Intercept(context.Background(), act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for non-MCP message")
	}
	if result.Name != "test_tool" {
		t.Errorf("expected tool name 'test_tool', got %q", result.Name)
	}
}

func TestActionValidation_ValidClientMessage(t *testing.T) {
	interceptor := NewActionValidationInterceptor(&passThrough{}, newValidationLogger())

	id, _ := jsonrpc.MakeID(float64(1))
	mcpMsg := &mcp.Message{
		Raw:       []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_tool","arguments":{"key":"value"}}}`),
		Direction: mcp.ClientToServer,
		Decoded: &jsonrpc.Request{
			ID:     id,
			Method: "tools/call",
			Params: json.RawMessage(`{"name":"test_tool","arguments":{"key":"value"}}`),
		},
	}

	act := &CanonicalAction{
		Type:            ActionToolCall,
		Name:            "test_tool",
		Arguments:       map[string]interface{}{"key": "value"},
		OriginalMessage: mcpMsg,
	}

	result, err := interceptor.Intercept(context.Background(), act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for valid client message")
	}
}

func TestActionValidation_InvalidJSON(t *testing.T) {
	interceptor := NewActionValidationInterceptor(&passThrough{}, newValidationLogger())

	// Decoded is nil -- validator should reject with parse error
	mcpMsg := &mcp.Message{
		Raw:       []byte(`not valid json`),
		Direction: mcp.ClientToServer,
		Decoded:   nil,
	}

	act := &CanonicalAction{
		Type:            ActionToolCall,
		Name:            "test_tool",
		OriginalMessage: mcpMsg,
	}

	_, err := interceptor.Intercept(context.Background(), act)
	if err == nil {
		t.Fatal("expected validation error for nil Decoded")
	}

	var valErr *validation.ValidationError
	if !errors.As(err, &valErr) {
		t.Fatalf("expected *validation.ValidationError, got %T: %v", err, err)
	}
	if valErr.Code != validation.ErrCodeParseError {
		t.Errorf("expected error code %d, got %d", validation.ErrCodeParseError, valErr.Code)
	}
}
