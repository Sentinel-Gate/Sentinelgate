package action

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// newToolCallMessage creates a test mcp.Message for a tools/call request.
func newToolCallMessage(toolName string, args map[string]interface{}, sess *session.Session) *mcp.Message {
	params := map[string]interface{}{
		"name":      toolName,
		"arguments": args,
	}
	paramsJSON, _ := json.Marshal(params)

	rawMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  json.RawMessage(paramsJSON),
	}
	rawBytes, _ := json.Marshal(rawMsg)

	id, _ := jsonrpc.MakeID(float64(1))
	req := &jsonrpc.Request{
		ID:     id,
		Method: "tools/call",
		Params: paramsJSON,
	}

	return &mcp.Message{
		Raw:       rawBytes,
		Direction: mcp.ClientToServer,
		Decoded:   req,
		Timestamp: time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC),
		Session:   sess,
	}
}

// newMethodMessage creates a test mcp.Message for an arbitrary method.
func newMethodMessage(method string, sess *session.Session) *mcp.Message {
	params := map[string]interface{}{}
	paramsJSON, _ := json.Marshal(params)

	rawMsg := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  method,
		"params":  json.RawMessage(paramsJSON),
	}
	rawBytes, _ := json.Marshal(rawMsg)

	id, _ := jsonrpc.MakeID(float64(2))
	req := &jsonrpc.Request{
		ID:     id,
		Method: method,
		Params: paramsJSON,
	}

	return &mcp.Message{
		Raw:       rawBytes,
		Direction: mcp.ClientToServer,
		Decoded:   req,
		Timestamp: time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC),
		Session:   sess,
	}
}

func testSession() *session.Session {
	return &session.Session{
		ID:           "sess-123",
		IdentityID:   "id-456",
		IdentityName: "test-user",
		Roles:        []auth.Role{auth.RoleUser, auth.RoleAdmin},
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		LastAccess:   time.Now().UTC(),
	}
}

func TestMCPNormalizer_Normalize_ToolCall(t *testing.T) {
	normalizer := NewMCPNormalizer()
	sess := testSession()
	args := map[string]interface{}{"path": "/tmp/test"}
	msg := newToolCallMessage("read_file", args, sess)

	action, err := normalizer.Normalize(context.Background(), msg)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	// WHAT
	if action.Type != ActionToolCall {
		t.Errorf("Type = %q, want %q", action.Type, ActionToolCall)
	}
	if action.Name != "read_file" {
		t.Errorf("Name = %q, want %q", action.Name, "read_file")
	}
	if action.Arguments["path"] != "/tmp/test" {
		t.Errorf("Arguments[path] = %v, want %q", action.Arguments["path"], "/tmp/test")
	}

	// HOW
	if action.Protocol != "mcp" {
		t.Errorf("Protocol = %q, want %q", action.Protocol, "mcp")
	}
	if action.Gateway != "mcp-gateway" {
		t.Errorf("Gateway = %q, want %q", action.Gateway, "mcp-gateway")
	}

	// WHO
	if action.Identity.ID != "id-456" {
		t.Errorf("Identity.ID = %q, want %q", action.Identity.ID, "id-456")
	}
	if action.Identity.Name != "test-user" {
		t.Errorf("Identity.Name = %q, want %q", action.Identity.Name, "test-user")
	}
	if len(action.Identity.Roles) != 2 {
		t.Errorf("Identity.Roles len = %d, want 2", len(action.Identity.Roles))
	}
	if action.Identity.SessionID != "sess-123" {
		t.Errorf("Identity.SessionID = %q, want %q", action.Identity.SessionID, "sess-123")
	}

	// CONTEXT
	if !action.RequestTime.Equal(msg.Timestamp) {
		t.Errorf("RequestTime = %v, want %v", action.RequestTime, msg.Timestamp)
	}

	// INTERNAL
	if action.OriginalMessage != msg {
		t.Error("OriginalMessage should be the original mcp.Message")
	}
}

func TestMCPNormalizer_Normalize_Sampling(t *testing.T) {
	normalizer := NewMCPNormalizer()
	sess := testSession()
	msg := newMethodMessage("sampling/createMessage", sess)

	action, err := normalizer.Normalize(context.Background(), msg)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if action.Type != ActionSampling {
		t.Errorf("Type = %q, want %q", action.Type, ActionSampling)
	}
	if action.Name != "sampling/createMessage" {
		t.Errorf("Name = %q, want %q", action.Name, "sampling/createMessage")
	}
}

func TestMCPNormalizer_Normalize_Elicitation(t *testing.T) {
	normalizer := NewMCPNormalizer()
	sess := testSession()
	msg := newMethodMessage("elicitation/create", sess)

	action, err := normalizer.Normalize(context.Background(), msg)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if action.Type != ActionElicitation {
		t.Errorf("Type = %q, want %q", action.Type, ActionElicitation)
	}
	if action.Name != "elicitation/create" {
		t.Errorf("Name = %q, want %q", action.Name, "elicitation/create")
	}
}

func TestMCPNormalizer_Normalize_NonRequest(t *testing.T) {
	normalizer := NewMCPNormalizer()

	// Create a response message (not a request)
	id, _ := jsonrpc.MakeID(float64(1))
	resp := &jsonrpc.Response{
		ID:     id,
		Result: json.RawMessage(`{"content":"hello"}`),
	}

	msg := &mcp.Message{
		Direction: mcp.ServerToClient,
		Decoded:   resp,
		Timestamp: time.Now().UTC(),
	}

	action, err := normalizer.Normalize(context.Background(), msg)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	// Passthrough: Type should be ActionToolCall with empty name
	if action.Type != ActionToolCall {
		t.Errorf("Type = %q, want %q", action.Type, ActionToolCall)
	}
	if action.Name != "" {
		t.Errorf("Name = %q, want empty", action.Name)
	}
	if action.OriginalMessage != msg {
		t.Error("OriginalMessage should be the original mcp.Message")
	}
}

func TestMCPNormalizer_Normalize_NilSession(t *testing.T) {
	normalizer := NewMCPNormalizer()
	args := map[string]interface{}{"path": "/tmp/test"}
	msg := newToolCallMessage("read_file", args, nil) // nil session

	action, err := normalizer.Normalize(context.Background(), msg)
	if err != nil {
		t.Fatalf("Normalize() error = %v, should not panic on nil session", err)
	}

	// Identity should be zero-valued
	if action.Identity.ID != "" {
		t.Errorf("Identity.ID = %q, want empty", action.Identity.ID)
	}
	if action.Identity.Name != "" {
		t.Errorf("Identity.Name = %q, want empty", action.Identity.Name)
	}
	if len(action.Identity.Roles) != 0 {
		t.Errorf("Identity.Roles len = %d, want 0", len(action.Identity.Roles))
	}
	if action.Identity.SessionID != "" {
		t.Errorf("Identity.SessionID = %q, want empty", action.Identity.SessionID)
	}
}

func TestMCPNormalizer_Denormalize_Allow(t *testing.T) {
	normalizer := NewMCPNormalizer()
	sess := testSession()
	msg := newToolCallMessage("read_file", map[string]interface{}{}, sess)

	ca := &CanonicalAction{
		OriginalMessage: msg,
	}
	result := &InterceptResult{
		Decision: DecisionAllow,
	}

	resp, err := normalizer.Denormalize(ca, result)
	if err != nil {
		t.Fatalf("Denormalize() error = %v", err)
	}

	// Should return the original message unchanged
	returnedMsg, ok := resp.(*mcp.Message)
	if !ok {
		t.Fatalf("Denormalize() returned %T, want *mcp.Message", resp)
	}
	if returnedMsg != msg {
		t.Error("Denormalize() should return the exact original message")
	}
}

func TestMCPNormalizer_Denormalize_Deny(t *testing.T) {
	normalizer := NewMCPNormalizer()
	sess := testSession()
	msg := newToolCallMessage("read_file", map[string]interface{}{}, sess)

	ca := &CanonicalAction{
		OriginalMessage: msg,
	}
	result := &InterceptResult{
		Decision: DecisionDeny,
		Reason:   "policy violation",
		HelpText: "Contact admin for access",
		HelpURL:  "https://docs.example.com/policy",
	}

	resp, err := normalizer.Denormalize(ca, result)
	if resp != nil {
		t.Errorf("Denormalize() returned non-nil response for deny: %v", resp)
	}
	if err == nil {
		t.Fatal("Denormalize() should return error for deny decision")
	}

	errMsg := err.Error()
	if errMsg == "" {
		t.Error("Error message should not be empty")
	}
	// Error should contain the reason
	if !strings.Contains(errMsg, "policy violation") {
		t.Errorf("Error message %q should contain reason %q", errMsg, "policy violation")
	}
	// Error should contain help text
	if !strings.Contains(errMsg, "Contact admin for access") {
		t.Errorf("Error message %q should contain help text %q", errMsg, "Contact admin for access")
	}
}

func TestMCPNormalizer_Protocol(t *testing.T) {
	normalizer := NewMCPNormalizer()
	if got := normalizer.Protocol(); got != "mcp" {
		t.Errorf("Protocol() = %q, want %q", got, "mcp")
	}
}

func TestMCPNormalizer_Normalize_InvalidType(t *testing.T) {
	normalizer := NewMCPNormalizer()

	// Pass a non-mcp.Message type
	_, err := normalizer.Normalize(context.Background(), "not a message")
	if err == nil {
		t.Error("Normalize() should return error for non-mcp.Message type")
	}
}
