package quota

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
)

// mockQuotaStore is an in-memory QuotaStore for testing.
type mockQuotaStore struct {
	mu      sync.RWMutex
	configs map[string]*QuotaConfig
}

func newMockQuotaStore() *mockQuotaStore {
	return &mockQuotaStore{
		configs: make(map[string]*QuotaConfig),
	}
}

func (m *mockQuotaStore) Get(_ context.Context, identityID string) (*QuotaConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.configs[identityID]
	if !ok {
		return nil, ErrQuotaNotFound
	}
	copy := *cfg
	return &copy, nil
}

func (m *mockQuotaStore) Put(_ context.Context, config *QuotaConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[config.IdentityID] = config
	return nil
}

func (m *mockQuotaStore) Delete(_ context.Context, identityID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.configs, identityID)
	return nil
}

func (m *mockQuotaStore) List(_ context.Context) ([]*QuotaConfig, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*QuotaConfig, 0, len(m.configs))
	for _, cfg := range m.configs {
		copy := *cfg
		result = append(result, &copy)
	}
	return result, nil
}

func TestQuotaService_Check_NoConfig_Allows(t *testing.T) {
	store := newMockQuotaStore()
	tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
	svc := NewQuotaService(store, tracker)

	result := svc.Check(context.Background(), "unknown-id", "sess-1", "read_file")
	if !result.Allowed {
		t.Errorf("Check() Allowed = false, want true (no config)")
	}
}

func TestQuotaService_Check_DisabledConfig_Allows(t *testing.T) {
	store := newMockQuotaStore()
	tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
	svc := NewQuotaService(store, tracker)

	_ = store.Put(context.Background(), &QuotaConfig{
		IdentityID:         "id-1",
		MaxCallsPerSession: 1,
		Action:             QuotaActionDeny,
		Enabled:            false, // disabled
	})

	// Record many calls to exceed the limit
	for i := 0; i < 10; i++ {
		tracker.RecordCall("sess-1", "read_file", "id-1", "user", nil)
	}

	result := svc.Check(context.Background(), "id-1", "sess-1", "read_file")
	if !result.Allowed {
		t.Errorf("Check() Allowed = false, want true (disabled config)")
	}
}

func TestQuotaService_Check_WithinLimits_Allows(t *testing.T) {
	store := newMockQuotaStore()
	tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
	svc := NewQuotaService(store, tracker)

	_ = store.Put(context.Background(), &QuotaConfig{
		IdentityID:         "id-1",
		MaxCallsPerSession: 100,
		Action:             QuotaActionDeny,
		Enabled:            true,
	})

	// Record a few calls
	tracker.RecordCall("sess-1", "read_file", "id-1", "user", nil)
	tracker.RecordCall("sess-1", "read_file", "id-1", "user", nil)

	result := svc.Check(context.Background(), "id-1", "sess-1", "read_file")
	if !result.Allowed {
		t.Errorf("Check() Allowed = false, want true (within limits)")
	}
	if len(result.Warnings) != 0 {
		t.Errorf("Check() Warnings = %v, want empty", result.Warnings)
	}
}

func TestQuotaService_Check_ExceedsMaxCalls_Denies(t *testing.T) {
	store := newMockQuotaStore()
	tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
	svc := NewQuotaService(store, tracker)

	_ = store.Put(context.Background(), &QuotaConfig{
		IdentityID:         "id-1",
		MaxCallsPerSession: 5,
		Action:             QuotaActionDeny,
		Enabled:            true,
	})

	// Record exactly limit calls
	for i := 0; i < 5; i++ {
		tracker.RecordCall("sess-1", "read_file", "id-1", "user", nil)
	}

	// Next call should be denied (5+1=6 > 5)
	result := svc.Check(context.Background(), "id-1", "sess-1", "read_file")
	if result.Allowed {
		t.Error("Check() Allowed = true, want false (max calls exceeded)")
	}
	if result.DenyReason == "" {
		t.Error("Check() DenyReason is empty, want non-empty")
	}
}

func TestQuotaService_Check_ExceedsMaxWrites_Denies(t *testing.T) {
	store := newMockQuotaStore()
	tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
	svc := NewQuotaService(store, tracker)

	_ = store.Put(context.Background(), &QuotaConfig{
		IdentityID:          "id-1",
		MaxWritesPerSession: 2,
		Action:              QuotaActionDeny,
		Enabled:             true,
	})

	tracker.RecordCall("sess-1", "write_file", "id-1", "user", nil)
	tracker.RecordCall("sess-1", "write_file", "id-1", "user", nil)

	// Next write should be denied
	result := svc.Check(context.Background(), "id-1", "sess-1", "write_file")
	if result.Allowed {
		t.Error("Check() Allowed = true, want false (max writes exceeded)")
	}

	// Read should still be allowed (not a write)
	result = svc.Check(context.Background(), "id-1", "sess-1", "read_file")
	if !result.Allowed {
		t.Error("Check() Allowed = false for read, want true (writes limit doesn't apply)")
	}
}

func TestQuotaService_Check_ExceedsMaxDeletes_Denies(t *testing.T) {
	store := newMockQuotaStore()
	tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
	svc := NewQuotaService(store, tracker)

	_ = store.Put(context.Background(), &QuotaConfig{
		IdentityID:           "id-1",
		MaxDeletesPerSession: 1,
		Action:               QuotaActionDeny,
		Enabled:              true,
	})

	tracker.RecordCall("sess-1", "delete_file", "id-1", "user", nil)

	// Next delete should be denied
	result := svc.Check(context.Background(), "id-1", "sess-1", "delete_file")
	if result.Allowed {
		t.Error("Check() Allowed = true, want false (max deletes exceeded)")
	}
}

func TestQuotaService_Check_ExceedsWindowRate_Denies(t *testing.T) {
	store := newMockQuotaStore()
	tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
	svc := NewQuotaService(store, tracker)

	_ = store.Put(context.Background(), &QuotaConfig{
		IdentityID:        "id-1",
		MaxCallsPerMinute: 3,
		Action:            QuotaActionDeny,
		Enabled:           true,
	})

	tracker.RecordCall("sess-1", "read_file", "id-1", "user", nil)
	tracker.RecordCall("sess-1", "read_file", "id-1", "user", nil)
	tracker.RecordCall("sess-1", "read_file", "id-1", "user", nil)

	// 4th call in the window should be denied
	result := svc.Check(context.Background(), "id-1", "sess-1", "read_file")
	if result.Allowed {
		t.Error("Check() Allowed = true, want false (window rate exceeded)")
	}
}

func TestQuotaService_Check_ExceedsToolLimit_Denies(t *testing.T) {
	store := newMockQuotaStore()
	tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
	svc := NewQuotaService(store, tracker)

	_ = store.Put(context.Background(), &QuotaConfig{
		IdentityID: "id-1",
		ToolLimits: map[string]int64{"write_file": 2},
		Action:     QuotaActionDeny,
		Enabled:    true,
	})

	tracker.RecordCall("sess-1", "write_file", "id-1", "user", nil)
	tracker.RecordCall("sess-1", "write_file", "id-1", "user", nil)

	// 3rd write_file should be denied
	result := svc.Check(context.Background(), "id-1", "sess-1", "write_file")
	if result.Allowed {
		t.Error("Check() Allowed = true, want false (tool limit exceeded)")
	}

	// Different tool should still be allowed
	result = svc.Check(context.Background(), "id-1", "sess-1", "read_file")
	if !result.Allowed {
		t.Error("Check() Allowed = false for different tool, want true")
	}
}

func TestQuotaService_Check_WarnMode_AllowsButWarns(t *testing.T) {
	store := newMockQuotaStore()
	tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
	svc := NewQuotaService(store, tracker)

	_ = store.Put(context.Background(), &QuotaConfig{
		IdentityID:         "id-1",
		MaxCallsPerSession: 5,
		Action:             QuotaActionWarn,
		Enabled:            true,
	})

	// Exceed the limit
	for i := 0; i < 5; i++ {
		tracker.RecordCall("sess-1", "read_file", "id-1", "user", nil)
	}

	result := svc.Check(context.Background(), "id-1", "sess-1", "read_file")
	if !result.Allowed {
		t.Error("Check() Allowed = false, want true (warn mode)")
	}
	if len(result.Warnings) == 0 {
		t.Error("Check() Warnings is empty, want non-empty (warn mode)")
	}
}

func TestQuotaService_Check_WarningAt80Percent(t *testing.T) {
	store := newMockQuotaStore()
	tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
	svc := NewQuotaService(store, tracker)

	_ = store.Put(context.Background(), &QuotaConfig{
		IdentityID:         "id-1",
		MaxCallsPerSession: 10,
		Action:             QuotaActionDeny,
		Enabled:            true,
	})

	// Record 7 calls (7+1=8, which is 80% of 10)
	for i := 0; i < 7; i++ {
		tracker.RecordCall("sess-1", "read_file", "id-1", "user", nil)
	}

	result := svc.Check(context.Background(), "id-1", "sess-1", "read_file")
	if !result.Allowed {
		t.Error("Check() Allowed = false, want true (at 80%, not exceeded)")
	}
	if len(result.Warnings) == 0 {
		t.Error("Check() Warnings is empty, want warning at 80% threshold")
	}
}

func TestQuotaService_Check_MultipleViolations(t *testing.T) {
	store := newMockQuotaStore()
	tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
	svc := NewQuotaService(store, tracker)

	_ = store.Put(context.Background(), &QuotaConfig{
		IdentityID:          "id-1",
		MaxCallsPerSession:  3,
		MaxWritesPerSession: 2,
		MaxCallsPerMinute:   3,
		Action:              QuotaActionDeny,
		Enabled:             true,
	})

	tracker.RecordCall("sess-1", "write_file", "id-1", "user", nil)
	tracker.RecordCall("sess-1", "write_file", "id-1", "user", nil)
	tracker.RecordCall("sess-1", "write_file", "id-1", "user", nil)

	// Multiple limits exceeded: total=3+1>3, writes=2+1>2 (since write_file is a write), window=3+1>3
	result := svc.Check(context.Background(), "id-1", "sess-1", "write_file")
	if result.Allowed {
		t.Error("Check() Allowed = true, want false (multiple violations)")
	}
	if result.DenyReason == "" {
		t.Error("Check() DenyReason is empty, want non-empty")
	}
}

func TestQuotaService_Check_NoSession_Allows(t *testing.T) {
	store := newMockQuotaStore()
	tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
	svc := NewQuotaService(store, tracker)

	_ = store.Put(context.Background(), &QuotaConfig{
		IdentityID:         "id-1",
		MaxCallsPerSession: 1,
		Action:             QuotaActionDeny,
		Enabled:            true,
	})

	// No calls recorded, session doesn't exist in tracker
	result := svc.Check(context.Background(), "id-1", "sess-no-calls", "read_file")
	if !result.Allowed {
		t.Error("Check() Allowed = false, want true (no session data yet)")
	}
}
