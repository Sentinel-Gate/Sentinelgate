package transform

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// testLogger returns a logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// mockNextInterceptor records calls and returns a configurable response.
type mockNextInterceptor struct {
	called bool
	result *action.CanonicalAction
	err    error
}

func (m *mockNextInterceptor) Intercept(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
	m.called = true
	if m.result != nil {
		return m.result, m.err
	}
	return a, m.err
}

// buildToolCallAction creates a CanonicalAction representing a tool call request.
func buildToolCallAction(toolName string, rawJSON string) *action.CanonicalAction {
	return &action.CanonicalAction{
		Type:     action.ActionToolCall,
		Name:     toolName,
		Protocol: "mcp",
		OriginalMessage: &mcp.Message{
			Raw:       []byte(rawJSON),
			Direction: mcp.ClientToServer,
			Timestamp: time.Now(),
		},
		Metadata: make(map[string]interface{}),
	}
}

// buildToolCallResponse creates a CanonicalAction representing a tool call response.
func buildToolCallResponse(toolName string, rawJSON string) *action.CanonicalAction {
	return &action.CanonicalAction{
		Type:     action.ActionToolCall,
		Name:     toolName,
		Protocol: "mcp",
		OriginalMessage: &mcp.Message{
			Raw:       []byte(rawJSON),
			Direction: mcp.ServerToClient,
			Timestamp: time.Now(),
		},
		Metadata: make(map[string]interface{}),
	}
}

func TestTransformInterceptor_DryRun_ShortCircuits(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	_ = store.Put(ctx, &TransformRule{
		ID:        "dr1",
		Name:      "dry-run-test",
		Type:      TransformDryRun,
		ToolMatch: "dangerous_tool",
		Priority:  1,
		Enabled:   true,
		Config:    TransformConfig{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	mock := &mockNextInterceptor{}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("dangerous_tool", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dangerous_tool"}}`)

	result, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.called {
		t.Error("next interceptor should NOT have been called (dry-run short-circuit)")
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Verify the synthetic response contains dry_run.
	mcpMsg, ok := result.OriginalMessage.(*mcp.Message)
	if !ok {
		t.Fatal("expected mcp.Message in result")
	}
	if mcpMsg.Direction != mcp.ServerToClient {
		t.Error("expected ServerToClient direction")
	}
	if !strings.Contains(string(mcpMsg.Raw), "dry_run") {
		t.Errorf("expected synthetic response to contain dry_run, got: %s", mcpMsg.Raw)
	}

	// Verify metadata has transform_results.
	results, ok := result.Metadata["transform_results"].([]TransformResult)
	if !ok {
		t.Fatal("expected transform_results in metadata")
	}
	if len(results) != 1 || !results[0].Applied {
		t.Error("expected 1 applied transform result for dry-run")
	}
}

func TestTransformInterceptor_DryRun_CustomResponse(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	customResponse := `{"status": "simulated", "data": "test-output"}`
	_ = store.Put(ctx, &TransformRule{
		ID:        "dr2",
		Name:      "dry-run-custom",
		Type:      TransformDryRun,
		ToolMatch: "my_tool",
		Priority:  1,
		Enabled:   true,
		Config:    TransformConfig{Response: customResponse},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	mock := &mockNextInterceptor{}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("my_tool", `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"my_tool"}}`)

	result, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.called {
		t.Error("next interceptor should NOT have been called")
	}

	mcpMsg, _ := result.OriginalMessage.(*mcp.Message)
	// The custom response is embedded in the MCP content text field, so it gets
	// JSON-escaped. Check that the escaped version is present.
	escapedCustom, _ := json.Marshal(customResponse)
	// escapedCustom includes surrounding quotes, strip them for contains check.
	escapedStr := string(escapedCustom[1 : len(escapedCustom)-1])
	if !strings.Contains(string(mcpMsg.Raw), escapedStr) {
		t.Errorf("expected custom response (escaped) in synthetic message, got: %s", mcpMsg.Raw)
	}
}

func TestTransformInterceptor_Redact_ModifiesResponse(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	_ = store.Put(ctx, &TransformRule{
		ID:        "red1",
		Name:      "redact-ssn",
		Type:      TransformRedact,
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config: TransformConfig{
			Patterns:    []string{`\d{3}-\d{2}-\d{4}`},
			Replacement: "[SSN_REDACTED]",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	responseJSON := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"SSN is 123-45-6789 and name is John"}]}}`
	responseAction := buildToolCallResponse("read_file", responseJSON)

	mock := &mockNextInterceptor{result: responseAction}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("read_file", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`)

	result, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.called {
		t.Error("next interceptor should have been called")
	}

	mcpMsg, _ := result.OriginalMessage.(*mcp.Message)
	raw := string(mcpMsg.Raw)
	if strings.Contains(raw, "123-45-6789") {
		t.Errorf("SSN should have been redacted, got: %s", raw)
	}
	if !strings.Contains(raw, "[SSN_REDACTED]") {
		t.Errorf("expected [SSN_REDACTED] in response, got: %s", raw)
	}
}

func TestTransformInterceptor_Truncate_LongResponse(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	_ = store.Put(ctx, &TransformRule{
		ID:        "trunc1",
		Name:      "truncate-response",
		Type:      TransformTruncate,
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config:    TransformConfig{MaxBytes: 20},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	longText := strings.Repeat("A", 100)
	responseJSON := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"` + longText + `"}]}}`
	responseAction := buildToolCallResponse("read_file", responseJSON)

	mock := &mockNextInterceptor{result: responseAction}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("read_file", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`)

	result, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mcpMsg, _ := result.OriginalMessage.(*mcp.Message)
	raw := string(mcpMsg.Raw)
	if strings.Contains(raw, longText) {
		t.Error("response should have been truncated")
	}
	if !strings.Contains(raw, "[truncated]") {
		t.Errorf("expected truncation suffix, got: %s", raw)
	}
}

func TestTransformInterceptor_Inject_AddsWarning(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	_ = store.Put(ctx, &TransformRule{
		ID:        "inj1",
		Name:      "inject-warning",
		Type:      TransformInject,
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config:    TransformConfig{Prepend: "WARNING: This data may be outdated."},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	responseJSON := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Current temperature: 22C"}]}}`
	responseAction := buildToolCallResponse("get_weather", responseJSON)

	mock := &mockNextInterceptor{result: responseAction}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("get_weather", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}`)

	result, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mcpMsg, _ := result.OriginalMessage.(*mcp.Message)
	raw := string(mcpMsg.Raw)
	if !strings.Contains(raw, "WARNING: This data may be outdated.") {
		t.Errorf("expected warning prepended, got: %s", raw)
	}
	if !strings.Contains(raw, "Current temperature: 22C") {
		t.Errorf("original text should still be present, got: %s", raw)
	}
}

func TestTransformInterceptor_Mask_APIKeys(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	_ = store.Put(ctx, &TransformRule{
		ID:        "mask1",
		Name:      "mask-api-keys",
		Type:      TransformMask,
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config: TransformConfig{
			MaskPatterns:  []string{`sk-[A-Za-z0-9]{20,}`},
			VisiblePrefix: 3,
			VisibleSuffix: 4,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	apiKey := "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234"
	responseJSON := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Your key is ` + apiKey + `"}]}}`
	responseAction := buildToolCallResponse("get_config", responseJSON)

	mock := &mockNextInterceptor{result: responseAction}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("get_config", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_config"}}`)

	result, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mcpMsg, _ := result.OriginalMessage.(*mcp.Message)
	raw := string(mcpMsg.Raw)
	if strings.Contains(raw, apiKey) {
		t.Errorf("API key should have been masked, got: %s", raw)
	}
	// Should contain partial key (prefix "sk-" and suffix "1234")
	if !strings.Contains(raw, "sk-") {
		t.Errorf("expected visible prefix sk-, got: %s", raw)
	}
}

func TestTransformInterceptor_BinarySkip(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	_ = store.Put(ctx, &TransformRule{
		ID:        "red1",
		Name:      "redact-all",
		Type:      TransformRedact,
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config:    TransformConfig{Patterns: []string{`.*`}},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	// PNG magic bytes followed by some data.
	binaryData := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	responseAction := &action.CanonicalAction{
		Type:     action.ActionToolCall,
		Name:     "get_image",
		Protocol: "mcp",
		OriginalMessage: &mcp.Message{
			Raw:       binaryData,
			Direction: mcp.ServerToClient,
		},
		Metadata: make(map[string]interface{}),
	}

	mock := &mockNextInterceptor{result: responseAction}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("get_image", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_image"}}`)

	result, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Binary content should pass through unchanged.
	mcpMsg, _ := result.OriginalMessage.(*mcp.Message)
	if len(mcpMsg.Raw) != len(binaryData) {
		t.Errorf("binary response should not be modified, got len=%d want len=%d", len(mcpMsg.Raw), len(binaryData))
	}
}

func TestTransformInterceptor_NoMatchingRules(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	_ = store.Put(ctx, &TransformRule{
		ID:        "red1",
		Name:      "redact-specific",
		Type:      TransformRedact,
		ToolMatch: "secret_tool",
		Priority:  10,
		Enabled:   true,
		Config:    TransformConfig{Patterns: []string{`secret`}},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	responseJSON := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"This has a secret value"}]}}`
	responseAction := buildToolCallResponse("other_tool", responseJSON)

	mock := &mockNextInterceptor{result: responseAction}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("other_tool", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"other_tool"}}`)

	result, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Response should be unchanged because rule doesn't match "other_tool".
	mcpMsg, _ := result.OriginalMessage.(*mcp.Message)
	if !strings.Contains(string(mcpMsg.Raw), "secret") {
		t.Error("response should be unchanged since rule doesn't match tool")
	}
}

func TestTransformInterceptor_MultipleRules_PriorityOrder(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	// Lower priority number runs first. Inject runs before redact.
	_ = store.Put(ctx, &TransformRule{
		ID:        "inj1",
		Name:      "inject-first",
		Type:      TransformInject,
		ToolMatch: "*",
		Priority:  1,
		Enabled:   true,
		Config:    TransformConfig{Prepend: "HEADER:"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})
	_ = store.Put(ctx, &TransformRule{
		ID:        "red1",
		Name:      "redact-second",
		Type:      TransformRedact,
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config:    TransformConfig{Patterns: []string{`password123`}, Replacement: "[REDACTED]"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	responseJSON := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"The password is password123"}]}}`
	responseAction := buildToolCallResponse("read_config", responseJSON)

	mock := &mockNextInterceptor{result: responseAction}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("read_config", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_config"}}`)

	result, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mcpMsg, _ := result.OriginalMessage.(*mcp.Message)
	raw := string(mcpMsg.Raw)
	// Both transforms should have been applied.
	if !strings.Contains(raw, "HEADER:") {
		t.Errorf("expected HEADER: from inject, got: %s", raw)
	}
	if strings.Contains(raw, "password123") {
		t.Errorf("password should have been redacted, got: %s", raw)
	}
	if !strings.Contains(raw, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in response, got: %s", raw)
	}
}

func TestTransformInterceptor_DisabledRule_Skipped(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	_ = store.Put(ctx, &TransformRule{
		ID:        "red1",
		Name:      "disabled-redact",
		Type:      TransformRedact,
		ToolMatch: "*",
		Priority:  10,
		Enabled:   false, // Disabled
		Config:    TransformConfig{Patterns: []string{`secret`}},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	responseJSON := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"This is a secret value"}]}}`
	responseAction := buildToolCallResponse("read_file", responseJSON)

	mock := &mockNextInterceptor{result: responseAction}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("read_file", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`)

	result, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Response should be unchanged since rule is disabled.
	mcpMsg, _ := result.OriginalMessage.(*mcp.Message)
	if !strings.Contains(string(mcpMsg.Raw), "secret") {
		t.Error("disabled rule should not redact content")
	}
}

func TestTransformInterceptor_NonToolCall_PassesThrough(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	_ = store.Put(ctx, &TransformRule{
		ID:        "red1",
		Name:      "catch-all-redact",
		Type:      TransformRedact,
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config:    TransformConfig{Patterns: []string{`.*`}},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	// Non-tool-call action.
	httpAction := &action.CanonicalAction{
		Type:     action.ActionHTTPRequest,
		Name:     "GET /api/data",
		Protocol: "http",
		Metadata: make(map[string]interface{}),
	}

	mock := &mockNextInterceptor{}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	_, err := interceptor.Intercept(ctx, httpAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.called {
		t.Error("next interceptor should have been called for non-tool-call action")
	}
}

func TestTransformInterceptor_MetadataPopulated(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	// Create a transform result context (simulates what AuditInterceptor does).
	ctx, transformHolder := audit.NewTransformResultContext(ctx)

	_ = store.Put(ctx, &TransformRule{
		ID:        "red1",
		Name:      "redact-ssn",
		Type:      TransformRedact,
		ToolMatch: "*",
		Priority:  10,
		Enabled:   true,
		Config:    TransformConfig{Patterns: []string{`\d{3}-\d{2}-\d{4}`}, Replacement: "[SSN]"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	responseJSON := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"SSN: 123-45-6789"}]}}`
	responseAction := buildToolCallResponse("read_file", responseJSON)

	mock := &mockNextInterceptor{result: responseAction}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("read_file", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`)

	result, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check metadata.
	results, ok := result.Metadata["transform_results"].([]TransformResult)
	if !ok {
		t.Fatal("expected transform_results in metadata")
	}
	if len(results) == 0 {
		t.Error("expected at least one transform result")
	}

	// Check audit context holder was populated.
	if len(transformHolder.Results) == 0 {
		t.Error("expected audit context holder to be populated")
	}
	if transformHolder.Results[0].RuleName != "redact-ssn" {
		t.Errorf("expected rule name redact-ssn in audit context, got %s", transformHolder.Results[0].RuleName)
	}
}

func TestTransformInterceptor_DryRun_AuditContext(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	// Create audit context.
	ctx, transformHolder := audit.NewTransformResultContext(ctx)

	_ = store.Put(ctx, &TransformRule{
		ID:        "dr1",
		Name:      "dry-run-audit",
		Type:      TransformDryRun,
		ToolMatch: "test_tool",
		Priority:  1,
		Enabled:   true,
		Config:    TransformConfig{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	mock := &mockNextInterceptor{}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("test_tool", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_tool"}}`)

	_, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify audit context was populated for dry-run.
	if len(transformHolder.Results) != 1 {
		t.Fatalf("expected 1 audit result, got %d", len(transformHolder.Results))
	}
	if transformHolder.Results[0].Type != "dry_run" {
		t.Errorf("expected type dry_run, got %s", transformHolder.Results[0].Type)
	}
	if transformHolder.Results[0].Detail != "dry-run: call intercepted before upstream" {
		t.Errorf("unexpected detail: %s", transformHolder.Results[0].Detail)
	}
}

func TestTransformInterceptor_SyntheticResponse_PreservesID(t *testing.T) {
	store := NewMemoryTransformStore()
	ctx := context.Background()

	_ = store.Put(ctx, &TransformRule{
		ID:        "dr1",
		Name:      "dry-run-id-test",
		Type:      TransformDryRun,
		ToolMatch: "test_tool",
		Priority:  1,
		Enabled:   true,
		Config:    TransformConfig{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	mock := &mockNextInterceptor{}
	executor := NewTransformExecutor(testLogger())
	interceptor := NewTransformInterceptor(store, executor, mock, testLogger())

	reqAction := buildToolCallAction("test_tool", `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"test_tool"}}`)

	result, err := interceptor.Intercept(ctx, reqAction)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mcpMsg, _ := result.OriginalMessage.(*mcp.Message)

	// Parse the response to verify ID is preserved.
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(mcpMsg.Raw, &resp); err != nil {
		t.Fatalf("failed to parse synthetic response: %v", err)
	}
	if string(resp["id"]) != "42" {
		t.Errorf("expected response ID=42, got %s", resp["id"])
	}
}
