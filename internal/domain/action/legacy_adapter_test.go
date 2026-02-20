package action

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// mockMessageInterceptor is a test double for proxy.MessageInterceptor.
type mockMessageInterceptor struct {
	interceptFn func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error)
}

func (m *mockMessageInterceptor) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	return m.interceptFn(ctx, msg)
}

func TestLegacyAdapter_Passthrough(t *testing.T) {
	mock := &mockMessageInterceptor{
		interceptFn: func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
			return msg, nil // Return unchanged
		},
	}

	adapter := NewLegacyAdapter(mock, "test-passthrough")

	mcpMsg := &mcp.Message{
		Raw:       []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1}`),
		Direction: mcp.ClientToServer,
		Timestamp: time.Now(),
	}

	action := &CanonicalAction{
		Type:            ActionToolCall,
		Name:            "read_file",
		OriginalMessage: mcpMsg,
	}

	result, err := adapter.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result != action {
		t.Fatal("expected same action returned")
	}
	if result.Name != "read_file" {
		t.Fatalf("expected name 'read_file', got %q", result.Name)
	}

	// Verify OriginalMessage was updated
	resultMsg, ok := result.OriginalMessage.(*mcp.Message)
	if !ok {
		t.Fatal("expected OriginalMessage to be *mcp.Message")
	}
	if resultMsg != mcpMsg {
		t.Fatal("expected same mcp.Message")
	}
}

func TestLegacyAdapter_Error(t *testing.T) {
	expectedErr := errors.New("policy denied")
	mock := &mockMessageInterceptor{
		interceptFn: func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
			return nil, expectedErr
		},
	}

	adapter := NewLegacyAdapter(mock, "test-error")

	action := &CanonicalAction{
		Type:            ActionToolCall,
		OriginalMessage: &mcp.Message{},
	}

	_, err := adapter.Intercept(context.Background(), action)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error %v, got %v", expectedErr, err)
	}
}

func TestLegacyAdapter_SessionSync(t *testing.T) {
	sess := &session.Session{
		ID:           "sess-123",
		IdentityID:   "id-456",
		IdentityName: "test-user",
		Roles:        []auth.Role{auth.RoleUser, auth.RoleAdmin},
	}

	mock := &mockMessageInterceptor{
		interceptFn: func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
			// AuthInterceptor sets the session on the message
			msg.Session = sess
			return msg, nil
		},
	}

	adapter := NewLegacyAdapter(mock, "test-session-sync")

	action := &CanonicalAction{
		Type:            ActionToolCall,
		OriginalMessage: &mcp.Message{},
		// Identity is empty (no session yet)
	}

	result, err := adapter.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify identity was synced from session
	if result.Identity.SessionID != "sess-123" {
		t.Fatalf("expected SessionID 'sess-123', got %q", result.Identity.SessionID)
	}
	if result.Identity.ID != "id-456" {
		t.Fatalf("expected ID 'id-456', got %q", result.Identity.ID)
	}
	if result.Identity.Name != "test-user" {
		t.Fatalf("expected Name 'test-user', got %q", result.Identity.Name)
	}
	if len(result.Identity.Roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(result.Identity.Roles))
	}
	if result.Identity.Roles[0] != "user" {
		t.Fatalf("expected first role 'user', got %q", result.Identity.Roles[0])
	}
	if result.Identity.Roles[1] != "admin" {
		t.Fatalf("expected second role 'admin', got %q", result.Identity.Roles[1])
	}
}

func TestLegacyAdapter_SessionSyncSkipsWhenIdentityAlreadySet(t *testing.T) {
	sess := &session.Session{
		ID:           "sess-new",
		IdentityID:   "id-new",
		IdentityName: "new-user",
		Roles:        []auth.Role{auth.RoleUser},
	}

	mock := &mockMessageInterceptor{
		interceptFn: func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
			msg.Session = sess
			return msg, nil
		},
	}

	adapter := NewLegacyAdapter(mock, "test-no-overwrite")

	action := &CanonicalAction{
		Type:            ActionToolCall,
		OriginalMessage: &mcp.Message{},
		Identity: ActionIdentity{
			SessionID: "existing-session",
			ID:        "existing-id",
			Name:      "existing-user",
			Roles:     []string{"admin"},
		},
	}

	result, err := adapter.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Identity should NOT be overwritten because SessionID was already set
	if result.Identity.SessionID != "existing-session" {
		t.Fatalf("expected existing SessionID, got %q", result.Identity.SessionID)
	}
	if result.Identity.ID != "existing-id" {
		t.Fatalf("expected existing ID, got %q", result.Identity.ID)
	}
}

func TestLegacyAdapter_NonMCPMessage(t *testing.T) {
	mock := &mockMessageInterceptor{
		interceptFn: func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
			return msg, nil
		},
	}

	adapter := NewLegacyAdapter(mock, "test-non-mcp")

	action := &CanonicalAction{
		Type:            ActionToolCall,
		OriginalMessage: "not-an-mcp-message", // String instead of *mcp.Message
	}

	_, err := adapter.Intercept(context.Background(), action)
	if err == nil {
		t.Fatal("expected error for non-MCP message")
	}
	if expected := "LegacyAdapter(test-non-mcp): expected *mcp.Message, got string"; err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err.Error())
	}
}

func TestLegacyAdapter_NilOriginalMessage(t *testing.T) {
	mock := &mockMessageInterceptor{
		interceptFn: func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
			return msg, nil
		},
	}

	adapter := NewLegacyAdapter(mock, "test-nil-msg")

	action := &CanonicalAction{
		Type:            ActionToolCall,
		OriginalMessage: nil,
	}

	_, err := adapter.Intercept(context.Background(), action)
	if err == nil {
		t.Fatal("expected error for nil OriginalMessage")
	}
	if expected := "LegacyAdapter(test-nil-msg): OriginalMessage is nil"; err.Error() != expected {
		t.Fatalf("expected error %q, got %q", expected, err.Error())
	}
}
