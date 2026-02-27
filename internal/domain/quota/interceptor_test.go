package quota

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// mockNextInterceptor tracks if Intercept was called.
type mockNextInterceptor struct {
	interceptCalled bool
	returnMsg       *mcp.Message
	returnErr       error
}

func (m *mockNextInterceptor) Intercept(_ context.Context, msg *mcp.Message) (*mcp.Message, error) {
	m.interceptCalled = true
	if m.returnMsg != nil {
		return m.returnMsg, m.returnErr
	}
	return msg, m.returnErr
}

// Compile-time check.
var _ proxy.MessageInterceptor = (*mockNextInterceptor)(nil)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func createToolCallMessage(toolName string, sess *session.Session) *mcp.Message {
	params := []byte(`{"name":"` + toolName + `","arguments":{"path":"/test/file"}}`)
	id, _ := jsonrpc.MakeID(float64(1))

	return &mcp.Message{
		Raw:       []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{}}`),
		Direction: mcp.ClientToServer,
		Decoded: &jsonrpc.Request{
			ID:     id,
			Method: "tools/call",
			Params: params,
		},
		Timestamp: time.Now(),
		Session:   sess,
	}
}

func createNonToolCallMessage(sess *session.Session) *mcp.Message {
	params := []byte(`{}`)
	id, _ := jsonrpc.MakeID(float64(2))

	return &mcp.Message{
		Raw:       []byte(`{"jsonrpc":"2.0","method":"resources/list","params":{}}`),
		Direction: mcp.ClientToServer,
		Decoded: &jsonrpc.Request{
			ID:     id,
			Method: "resources/list",
			Params: params,
		},
		Timestamp: time.Now(),
		Session:   sess,
	}
}

func createTestSession() *session.Session {
	return &session.Session{
		ID:           "test-session-123",
		IdentityID:   "test-identity",
		IdentityName: "Test User",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(30 * time.Minute),
		LastAccess:   time.Now(),
	}
}

func setupQuotaInterceptor(cfg *QuotaConfig) (*QuotaInterceptor, *mockNextInterceptor, *session.SessionTracker, *MemoryQuotaStore) {
	store := NewMemoryQuotaStore()
	tracker := session.NewSessionTracker(1*time.Minute, session.DefaultClassifier())

	if cfg != nil {
		_ = store.Put(context.Background(), cfg)
	}

	quotaService := NewQuotaService(store, tracker)
	next := &mockNextInterceptor{}
	interceptor := NewQuotaInterceptor(quotaService, tracker, next, testLogger())

	return interceptor, next, tracker, store
}

func TestQuotaInterceptor_NonToolCall_PassesThrough(t *testing.T) {
	interceptor, next, _, _ := setupQuotaInterceptor(nil)

	sess := createTestSession()
	msg := createNonToolCallMessage(sess)

	result, err := interceptor.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected message to be returned")
	}
	if !next.interceptCalled {
		t.Error("expected next.Intercept to be called")
	}
}

func TestQuotaInterceptor_NoSession_PassesThrough(t *testing.T) {
	interceptor, next, _, _ := setupQuotaInterceptor(nil)

	msg := createToolCallMessage("read_file", nil) // nil session

	result, err := interceptor.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected message to be returned")
	}
	if !next.interceptCalled {
		t.Error("expected next.Intercept to be called")
	}
}

func TestQuotaInterceptor_NoQuotaConfig_PassesThrough(t *testing.T) {
	// No config for this identity
	interceptor, next, _, _ := setupQuotaInterceptor(nil)

	sess := createTestSession()
	msg := createToolCallMessage("read_file", sess)

	result, err := interceptor.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected message to be returned")
	}
	if !next.interceptCalled {
		t.Error("expected next.Intercept to be called")
	}
}

func TestQuotaInterceptor_WithinLimits_PassesThrough_AndRecordsCall(t *testing.T) {
	cfg := &QuotaConfig{
		IdentityID:         "test-identity",
		MaxCallsPerSession: 10,
		Action:             QuotaActionDeny,
		Enabled:            true,
	}
	interceptor, next, tracker, _ := setupQuotaInterceptor(cfg)

	sess := createTestSession()
	msg := createToolCallMessage("read_file", sess)

	result, err := interceptor.Intercept(context.Background(), msg)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected message to be returned")
	}
	if !next.interceptCalled {
		t.Error("expected next.Intercept to be called")
	}

	// Verify call was recorded in tracker
	usage, found := tracker.GetUsage("test-session-123")
	if !found {
		t.Fatal("expected session to be tracked")
	}
	if usage.TotalCalls != 1 {
		t.Errorf("expected 1 total call, got %d", usage.TotalCalls)
	}
	if usage.CallsByToolName["read_file"] != 1 {
		t.Errorf("expected 1 call for read_file, got %d", usage.CallsByToolName["read_file"])
	}
}

func TestQuotaInterceptor_ExceedsLimit_ReturnsDenyError(t *testing.T) {
	cfg := &QuotaConfig{
		IdentityID:         "test-identity",
		MaxCallsPerSession: 2,
		Action:             QuotaActionDeny,
		Enabled:            true,
	}
	interceptor, next, tracker, _ := setupQuotaInterceptor(cfg)

	sess := createTestSession()

	// Pre-record 2 calls so the 3rd exceeds the limit
	tracker.RecordCall(sess.ID, "read_file", sess.IdentityID, sess.IdentityName, nil)
	tracker.RecordCall(sess.ID, "read_file", sess.IdentityID, sess.IdentityName, nil)

	msg := createToolCallMessage("read_file", sess)

	result, err := interceptor.Intercept(context.Background(), msg)

	if err == nil {
		t.Fatal("expected error for quota exceeded")
	}
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("expected ErrQuotaExceeded, got: %v", err)
	}

	var denyErr *QuotaDenyError
	if !errors.As(err, &denyErr) {
		t.Fatalf("expected QuotaDenyError, got: %T", err)
	}
	if denyErr.IdentityID != "test-identity" {
		t.Errorf("expected IdentityID 'test-identity', got %q", denyErr.IdentityID)
	}
	if denyErr.Reason == "" {
		t.Error("expected non-empty deny reason")
	}

	if result != nil {
		t.Error("expected nil message on quota denial")
	}
	if next.interceptCalled {
		t.Error("expected next.Intercept NOT to be called on quota denial")
	}
}

func TestQuotaInterceptor_WarnMode_PassesThrough_LogsWarning(t *testing.T) {
	cfg := &QuotaConfig{
		IdentityID:         "test-identity",
		MaxCallsPerSession: 2,
		Action:             QuotaActionWarn,
		Enabled:            true,
	}
	interceptor, next, tracker, _ := setupQuotaInterceptor(cfg)

	sess := createTestSession()

	// Pre-record 2 calls so the 3rd exceeds the limit (warn mode)
	tracker.RecordCall(sess.ID, "read_file", sess.IdentityID, sess.IdentityName, nil)
	tracker.RecordCall(sess.ID, "read_file", sess.IdentityID, sess.IdentityName, nil)

	msg := createToolCallMessage("read_file", sess)

	result, err := interceptor.Intercept(context.Background(), msg)

	// In warn mode, the call should still pass through
	if err != nil {
		t.Fatalf("expected no error in warn mode, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected message to be returned in warn mode")
	}
	if !next.interceptCalled {
		t.Error("expected next.Intercept to be called in warn mode")
	}

	// Call should still be recorded
	usage, found := tracker.GetUsage(sess.ID)
	if !found {
		t.Fatal("expected session to be tracked")
	}
	// 2 pre-recorded + 1 from interceptor = 3
	if usage.TotalCalls != 3 {
		t.Errorf("expected 3 total calls, got %d", usage.TotalCalls)
	}
}
