package action

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// stubRecorder captures audit records for assertion.
type stubRecorder struct {
	mu      sync.Mutex
	records []audit.AuditRecord
}

func (s *stubRecorder) Record(rec audit.AuditRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
}

func (s *stubRecorder) getRecords() []audit.AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]audit.AuditRecord, len(s.records))
	copy(cp, s.records)
	return cp
}

// stubStats captures stats method calls for assertion.
type stubStats struct {
	mu          sync.Mutex
	allows      int
	denies      int
	rateLimited int
}

func (s *stubStats) RecordAllow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allows++
}
func (s *stubStats) RecordDeny() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denies++
}
func (s *stubStats) RecordRateLimited() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rateLimited++
}
func (s *stubStats) RecordBlocked() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.denies++
}
func (s *stubStats) RecordWarned() {
	s.mu.Lock()
	defer s.mu.Unlock()
}
func (s *stubStats) RecordProtocol(string)  {}
func (s *stubStats) RecordFramework(string) {}

// denyNext always returns an error when intercepting.
type denyNext struct{}

func (d *denyNext) Intercept(_ context.Context, _ *CanonicalAction) (*CanonicalAction, error) {
	return nil, errors.New("denied by policy")
}


func newAuditLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestActionAuditInterceptor_RecordAllow(t *testing.T) {
	rec := &stubRecorder{}
	stats := &stubStats{}
	interceptor := NewActionAuditInterceptor(rec, stats, &passThrough{}, newAuditLogger())

	act := &CanonicalAction{
		Type:      ActionToolCall,
		Name:      "read_file",
		Arguments: map[string]interface{}{"path": "/tmp/test.txt"},
		Identity:  ActionIdentity{ID: "user-1", Name: "Alice", SessionID: "sess-1"},
	}

	result, err := interceptor.Intercept(context.Background(), act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	records := rec.getRecords()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Decision != audit.DecisionAllow {
		t.Errorf("expected decision %q, got %q", audit.DecisionAllow, records[0].Decision)
	}
	if records[0].ToolName != "read_file" {
		t.Errorf("expected tool name 'read_file', got %q", records[0].ToolName)
	}
}

func TestActionAuditInterceptor_RecordDeny(t *testing.T) {
	rec := &stubRecorder{}
	stats := &stubStats{}
	interceptor := NewActionAuditInterceptor(rec, stats, &denyNext{}, newAuditLogger())

	act := &CanonicalAction{
		Type:      ActionToolCall,
		Name:      "write_file",
		Arguments: map[string]interface{}{"content": "data"},
		Identity:  ActionIdentity{ID: "user-1", Name: "Alice", SessionID: "sess-1"},
	}

	_, err := interceptor.Intercept(context.Background(), act)
	if err == nil {
		t.Fatal("expected error from deny next")
	}

	records := rec.getRecords()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
	if records[0].Decision != audit.DecisionDeny {
		t.Errorf("expected decision %q, got %q", audit.DecisionDeny, records[0].Decision)
	}
	if records[0].Reason == "" {
		t.Error("expected non-empty reason on deny")
	}
}

func TestActionAuditInterceptor_SkipsNonToolCall(t *testing.T) {
	rec := &stubRecorder{}
	interceptor := NewActionAuditInterceptor(rec, nil, &passThrough{}, newAuditLogger())

	act := &CanonicalAction{
		Type: ActionHTTPRequest,
		Name: "GET",
	}

	result, err := interceptor.Intercept(context.Background(), act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	records := rec.getRecords()
	if len(records) != 0 {
		t.Errorf("expected 0 audit records for non-tool-call, got %d", len(records))
	}
}

func TestActionAuditInterceptor_SkipsEmptyName(t *testing.T) {
	rec := &stubRecorder{}
	interceptor := NewActionAuditInterceptor(rec, nil, &passThrough{}, newAuditLogger())

	act := &CanonicalAction{
		Type: ActionToolCall,
		Name: "", // empty name
	}

	result, err := interceptor.Intercept(context.Background(), act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	records := rec.getRecords()
	if len(records) != 0 {
		t.Errorf("expected 0 audit records for empty tool name, got %d", len(records))
	}
}

func TestActionAuditInterceptor_StatsAllow(t *testing.T) {
	rec := &stubRecorder{}
	stats := &stubStats{}
	interceptor := NewActionAuditInterceptor(rec, stats, &passThrough{}, newAuditLogger())

	act := &CanonicalAction{
		Type: ActionToolCall,
		Name: "test_tool",
	}

	_, err := interceptor.Intercept(context.Background(), act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.allows != 1 {
		t.Errorf("expected 1 allow stat, got %d", stats.allows)
	}
	if stats.denies != 0 {
		t.Errorf("expected 0 deny stats, got %d", stats.denies)
	}
}

func TestActionAuditInterceptor_StatsDeny(t *testing.T) {
	rec := &stubRecorder{}
	stats := &stubStats{}
	interceptor := NewActionAuditInterceptor(rec, stats, &denyNext{}, newAuditLogger())

	act := &CanonicalAction{
		Type: ActionToolCall,
		Name: "test_tool",
	}

	_, _ = interceptor.Intercept(context.Background(), act)

	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.denies != 1 {
		t.Errorf("expected 1 deny stat, got %d", stats.denies)
	}
	if stats.allows != 0 {
		t.Errorf("expected 0 allow stats, got %d", stats.allows)
	}
}

func TestActionAuditInterceptor_NilStats(t *testing.T) {
	rec := &stubRecorder{}
	// nil stats should not panic
	interceptor := NewActionAuditInterceptor(rec, nil, &passThrough{}, newAuditLogger())

	act := &CanonicalAction{
		Type: ActionToolCall,
		Name: "test_tool",
	}

	result, err := interceptor.Intercept(context.Background(), act)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Verify audit record was still created
	records := rec.getRecords()
	if len(records) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(records))
	}
}
