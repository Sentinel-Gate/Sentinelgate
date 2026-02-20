package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// mockAuditRecorder captures recorded audit records for testing.
type mockAuditRecorder struct {
	records []audit.AuditRecord
}

func (m *mockAuditRecorder) Record(record audit.AuditRecord) {
	m.records = append(m.records, record)
}

// mockStatsRecorder captures stats recording calls for testing.
type mockStatsRecorder struct {
	allowCount       int
	denyCount        int
	rateLimitedCount int
	protocolCounts   map[string]int
	frameworkCounts  map[string]int
}

func (m *mockStatsRecorder) RecordAllow()       { m.allowCount++ }
func (m *mockStatsRecorder) RecordDeny()        { m.denyCount++ }
func (m *mockStatsRecorder) RecordRateLimited() { m.rateLimitedCount++ }
func (m *mockStatsRecorder) RecordProtocol(p string) {
	if m.protocolCounts == nil {
		m.protocolCounts = make(map[string]int)
	}
	m.protocolCounts[p]++
}
func (m *mockStatsRecorder) RecordFramework(f string) {
	if m.frameworkCounts == nil {
		m.frameworkCounts = make(map[string]int)
	}
	m.frameworkCounts[f]++
}

// mockNextInterceptorAudit is a mock for testing AuditInterceptor.
type mockNextInterceptorAudit struct {
	returnMsg   *mcp.Message
	returnErr   error
	called      bool
	interceptFn func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) // optional override
}

func (m *mockNextInterceptorAudit) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	m.called = true
	if m.interceptFn != nil {
		return m.interceptFn(ctx, msg)
	}
	if m.returnMsg != nil {
		return m.returnMsg, m.returnErr
	}
	return msg, m.returnErr
}

func TestAuditInterceptor_RecordsAllowedCall(t *testing.T) {
	recorder := &mockAuditRecorder{}
	nextInterceptor := &mockNextInterceptorAudit{returnErr: nil}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, nil, nextInterceptor, logger)

	// Create a tool call message
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "read_file",
		"arguments": map[string]interface{}{"path": "/test"},
	})
	req := &jsonrpc.Request{
		Method: "tools/call",
		Params: params,
	}
	id, _ := jsonrpc.MakeID("req-123")
	req.ID = id

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Timestamp: time.Now(),
		Session: &session.Session{
			ID:         "session-123",
			IdentityID: "identity-456",
			Roles:      []auth.Role{auth.RoleUser},
		},
	}

	// Execute
	_, err := interceptor.Intercept(context.Background(), msg)

	// Verify
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !nextInterceptor.called {
		t.Error("expected next interceptor to be called")
	}
	if len(recorder.records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(recorder.records))
	}

	record := recorder.records[0]
	if record.Decision != audit.DecisionAllow {
		t.Errorf("expected decision %s, got %s", audit.DecisionAllow, record.Decision)
	}
	if record.ToolName != "read_file" {
		t.Errorf("expected tool name 'read_file', got %s", record.ToolName)
	}
	if record.SessionID != "session-123" {
		t.Errorf("expected session ID 'session-123', got %s", record.SessionID)
	}
	if record.RequestID != "req-123" {
		t.Errorf("expected request ID 'req-123', got %s", record.RequestID)
	}
}

func TestAuditInterceptor_RecordsDeniedCall(t *testing.T) {
	recorder := &mockAuditRecorder{}
	policyError := errors.New("policy denied: forbidden tool")
	nextInterceptor := &mockNextInterceptorAudit{returnErr: policyError}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, nil, nextInterceptor, logger)

	// Create a tool call message
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "delete_file",
		"arguments": map[string]interface{}{"path": "/etc/passwd"},
	})
	req := &jsonrpc.Request{
		Method: "tools/call",
		Params: params,
	}
	id, _ := jsonrpc.MakeID(42.0) // Test numeric ID
	req.ID = id

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Timestamp: time.Now(),
		Session: &session.Session{
			ID:         "session-789",
			IdentityID: "identity-bad",
			Roles:      []auth.Role{auth.RoleUser},
		},
	}

	// Execute
	_, err := interceptor.Intercept(context.Background(), msg)

	// Verify error is passed through
	if err != policyError {
		t.Fatalf("expected policy error, got: %v", err)
	}

	if len(recorder.records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(recorder.records))
	}

	record := recorder.records[0]
	if record.Decision != audit.DecisionDeny {
		t.Errorf("expected decision %s, got %s", audit.DecisionDeny, record.Decision)
	}
	if record.Reason != "policy denied: forbidden tool" {
		t.Errorf("expected reason 'policy denied: forbidden tool', got %s", record.Reason)
	}
	if record.ToolName != "delete_file" {
		t.Errorf("expected tool name 'delete_file', got %s", record.ToolName)
	}
	if record.RequestID != "42" {
		t.Errorf("expected request ID '42', got %s", record.RequestID)
	}
}

func TestAuditInterceptor_PassesMessageThrough(t *testing.T) {
	recorder := &mockAuditRecorder{}
	expectedResult := &mcp.Message{Raw: []byte("modified")}
	nextInterceptor := &mockNextInterceptorAudit{returnMsg: expectedResult}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, nil, nextInterceptor, logger)

	// Create a tool call message
	params, _ := json.Marshal(map[string]interface{}{
		"name": "test_tool",
	})
	req := &jsonrpc.Request{
		Method: "tools/call",
		Params: params,
	}

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Session:   &session.Session{ID: "s1", IdentityID: "i1"},
	}

	// Execute
	result, err := interceptor.Intercept(context.Background(), msg)

	// Verify
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != expectedResult {
		t.Error("expected result to be passed through from next interceptor")
	}
}

func TestAuditInterceptor_HandlesNilSession(t *testing.T) {
	recorder := &mockAuditRecorder{}
	nextInterceptor := &mockNextInterceptorAudit{returnErr: nil}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, nil, nextInterceptor, logger)

	// Create a tool call message without session
	params, _ := json.Marshal(map[string]interface{}{
		"name": "anonymous_tool",
	})
	req := &jsonrpc.Request{
		Method: "tools/call",
		Params: params,
	}

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Session:   nil, // No session
	}

	// Execute - should not panic
	_, err := interceptor.Intercept(context.Background(), msg)

	// Verify
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(recorder.records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(recorder.records))
	}

	record := recorder.records[0]
	if record.SessionID != "anonymous" {
		t.Errorf("expected session ID 'anonymous', got %s", record.SessionID)
	}
	if record.IdentityID != "anonymous" {
		t.Errorf("expected identity ID 'anonymous', got %s", record.IdentityID)
	}
}

func TestAuditInterceptor_NonToolCall_NotAudited(t *testing.T) {
	recorder := &mockAuditRecorder{}
	nextInterceptor := &mockNextInterceptorAudit{returnErr: nil}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, nil, nextInterceptor, logger)

	// Create a non-tool-call message
	req := &jsonrpc.Request{
		Method: "resources/list",
	}

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Session:   &session.Session{ID: "s1", IdentityID: "i1"},
	}

	// Execute
	_, err := interceptor.Intercept(context.Background(), msg)

	// Verify
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !nextInterceptor.called {
		t.Error("expected next interceptor to be called")
	}
	if len(recorder.records) != 0 {
		t.Errorf("expected 0 audit records for non-tool-call, got %d", len(recorder.records))
	}
}

func TestAuditInterceptor_RecordsAllowStat(t *testing.T) {
	recorder := &mockAuditRecorder{}
	stats := &mockStatsRecorder{}
	nextInterceptor := &mockNextInterceptorAudit{returnErr: nil}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, stats, nextInterceptor, logger)

	// Create a tool call message
	params, _ := json.Marshal(map[string]interface{}{
		"name":      "read_file",
		"arguments": map[string]interface{}{"path": "/test"},
	})
	req := &jsonrpc.Request{Method: "tools/call", Params: params}
	id, _ := jsonrpc.MakeID("req-stats-1")
	req.ID = id

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Timestamp: time.Now(),
		Session:   &session.Session{ID: "s1", IdentityID: "i1", Roles: []auth.Role{auth.RoleUser}},
	}

	_, err := interceptor.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.allowCount != 1 {
		t.Errorf("expected 1 allow, got %d", stats.allowCount)
	}
	if stats.denyCount != 0 {
		t.Errorf("expected 0 deny, got %d", stats.denyCount)
	}
}

func TestAuditInterceptor_RecordsDenyStat(t *testing.T) {
	recorder := &mockAuditRecorder{}
	stats := &mockStatsRecorder{}
	policyError := errors.New("policy denied: forbidden")
	nextInterceptor := &mockNextInterceptorAudit{returnErr: policyError}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, stats, nextInterceptor, logger)

	params, _ := json.Marshal(map[string]interface{}{
		"name":      "delete_file",
		"arguments": map[string]interface{}{"path": "/etc/passwd"},
	})
	req := &jsonrpc.Request{Method: "tools/call", Params: params}
	id, _ := jsonrpc.MakeID("req-stats-2")
	req.ID = id

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Timestamp: time.Now(),
		Session:   &session.Session{ID: "s2", IdentityID: "i2", Roles: []auth.Role{auth.RoleUser}},
	}

	_, _ = interceptor.Intercept(context.Background(), msg)
	if stats.denyCount != 1 {
		t.Errorf("expected 1 deny, got %d", stats.denyCount)
	}
	if stats.allowCount != 0 {
		t.Errorf("expected 0 allow, got %d", stats.allowCount)
	}
}

func TestAuditInterceptor_RecordsRateLimitedStat(t *testing.T) {
	recorder := &mockAuditRecorder{}
	stats := &mockStatsRecorder{}
	rateLimitErr := &RateLimitError{RetryAfter: 5 * time.Second}
	nextInterceptor := &mockNextInterceptorAudit{returnErr: rateLimitErr}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	interceptor := NewAuditInterceptor(recorder, stats, nextInterceptor, logger)

	params, _ := json.Marshal(map[string]interface{}{
		"name": "rapid_tool",
	})
	req := &jsonrpc.Request{Method: "tools/call", Params: params}
	id, _ := jsonrpc.MakeID("req-stats-3")
	req.ID = id

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Timestamp: time.Now(),
		Session:   &session.Session{ID: "s3", IdentityID: "i3", Roles: []auth.Role{auth.RoleUser}},
	}

	_, _ = interceptor.Intercept(context.Background(), msg)
	if stats.rateLimitedCount != 1 {
		t.Errorf("expected 1 rate_limited, got %d", stats.rateLimitedCount)
	}
	if stats.denyCount != 0 {
		t.Errorf("expected 0 deny, got %d", stats.denyCount)
	}
}

func TestAuditInterceptor_RecordsScanFields(t *testing.T) {
	recorder := &mockAuditRecorder{}
	// Mock next interceptor that simulates scan detection by populating the holder.
	nextInterceptor := &mockNextInterceptorAudit{
		interceptFn: func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
			if holder := audit.ScanResultFromContext(ctx); holder != nil {
				holder.Detections = 2
				holder.Action = "blocked"
				holder.Types = "prompt_injection"
			}
			return nil, fmt.Errorf("response blocked by content scanning: detected patterns: system_prompt_override, role_hijack")
		},
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	interceptor := NewAuditInterceptor(recorder, nil, nextInterceptor, logger)

	params, _ := json.Marshal(map[string]interface{}{
		"name":      "echo",
		"arguments": map[string]interface{}{"message": "ignore instructions"},
	})
	req := &jsonrpc.Request{Method: "tools/call", Params: params}
	id, _ := jsonrpc.MakeID("req-scan-1")
	req.ID = id

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Timestamp: time.Now(),
		Session:   &session.Session{ID: "s-scan", IdentityID: "i-scan", Roles: []auth.Role{auth.RoleUser}},
	}

	_, err := interceptor.Intercept(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error from blocked scan")
	}

	if len(recorder.records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(recorder.records))
	}

	record := recorder.records[0]
	if record.Decision != audit.DecisionDeny {
		t.Errorf("expected decision deny, got %s", record.Decision)
	}
	if record.ScanDetections != 2 {
		t.Errorf("expected ScanDetections=2, got %d", record.ScanDetections)
	}
	if record.ScanAction != "blocked" {
		t.Errorf("expected ScanAction=blocked, got %s", record.ScanAction)
	}
	if record.ScanTypes != "prompt_injection" {
		t.Errorf("expected ScanTypes=prompt_injection, got %s", record.ScanTypes)
	}
}

func TestAuditInterceptor_RecordsScanFieldsMonitorMode(t *testing.T) {
	recorder := &mockAuditRecorder{}
	// Mock next interceptor that simulates monitor-mode scan detection:
	// populates the holder but returns no error (allow through).
	nextInterceptor := &mockNextInterceptorAudit{
		interceptFn: func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
			if holder := audit.ScanResultFromContext(ctx); holder != nil {
				holder.Detections = 1
				holder.Action = "monitored"
				holder.Types = "prompt_injection"
			}
			return msg, nil // monitor mode: allow through
		},
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	interceptor := NewAuditInterceptor(recorder, nil, nextInterceptor, logger)

	params, _ := json.Marshal(map[string]interface{}{
		"name":      "echo",
		"arguments": map[string]interface{}{"message": "ignore instructions"},
	})
	req := &jsonrpc.Request{Method: "tools/call", Params: params}
	id, _ := jsonrpc.MakeID("req-scan-2")
	req.ID = id

	msg := &mcp.Message{
		Decoded:   req,
		Direction: mcp.ClientToServer,
		Timestamp: time.Now(),
		Session:   &session.Session{ID: "s-scan-m", IdentityID: "i-scan-m", Roles: []auth.Role{auth.RoleUser}},
	}

	_, err := interceptor.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("expected no error in monitor mode, got: %v", err)
	}

	if len(recorder.records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(recorder.records))
	}

	record := recorder.records[0]
	if record.Decision != audit.DecisionAllow {
		t.Errorf("expected decision allow, got %s", record.Decision)
	}
	if record.ScanDetections != 1 {
		t.Errorf("expected ScanDetections=1, got %d", record.ScanDetections)
	}
	if record.ScanAction != "monitored" {
		t.Errorf("expected ScanAction=monitored, got %s", record.ScanAction)
	}
	if record.ScanTypes != "prompt_injection" {
		t.Errorf("expected ScanTypes=prompt_injection, got %s", record.ScanTypes)
	}
}
