package session

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
)

// mockSessionStore is a simple in-memory mock for testing.
type mockSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func newMockSessionStore() *mockSessionStore {
	return &mockSessionStore{
		sessions: make(map[string]*Session),
	}
}

func (m *mockSessionStore) Create(ctx context.Context, session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionStore) Get(ctx context.Context, id string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	session, ok := m.sessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}
	// Return a copy to avoid mutation
	copy := *session
	copy.Roles = make([]auth.Role, len(session.Roles))
	for i, r := range session.Roles {
		copy.Roles[i] = r
	}
	return &copy, nil
}

func (m *mockSessionStore) Update(ctx context.Context, session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[session.ID]; !ok {
		return ErrSessionNotFound
	}
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionStore) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

func TestGenerateSessionID(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "generates unique IDs"},
		{name: "ID is 64 hex characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "generates unique IDs":
				ids := make(map[string]bool)
				for i := 0; i < 100; i++ {
					id, err := GenerateSessionID()
					if err != nil {
						t.Fatalf("GenerateSessionID() error = %v", err)
					}
					if ids[id] {
						t.Errorf("GenerateSessionID() generated duplicate ID: %s", id)
					}
					ids[id] = true
				}

			case "ID is 64 hex characters":
				id, err := GenerateSessionID()
				if err != nil {
					t.Fatalf("GenerateSessionID() error = %v", err)
				}
				if len(id) != 64 {
					t.Errorf("GenerateSessionID() len = %d, want 64", len(id))
				}
				// Verify it's valid hex
				for _, c := range id {
					if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
						t.Errorf("GenerateSessionID() contains non-hex character: %c", c)
					}
				}
			}
		})
	}
}

func TestSessionService_Create(t *testing.T) {
	store := newMockSessionStore()
	service := NewSessionService(store, Config{Timeout: 30 * time.Minute})
	ctx := context.Background()

	identity := &auth.Identity{
		ID:    "user-123",
		Name:  "Test User",
		Roles: []auth.Role{auth.RoleUser},
	}

	session, err := service.Create(ctx, identity)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify session fields
	if session.ID == "" {
		t.Error("Create() session.ID is empty")
	}
	if len(session.ID) != 64 {
		t.Errorf("Create() session.ID len = %d, want 64", len(session.ID))
	}
	if session.IdentityID != identity.ID {
		t.Errorf("Create() session.IdentityID = %q, want %q", session.IdentityID, identity.ID)
	}
	if len(session.Roles) != 1 || session.Roles[0] != auth.RoleUser {
		t.Errorf("Create() session.Roles = %v, want [%s]", session.Roles, auth.RoleUser)
	}
	if session.CreatedAt.IsZero() {
		t.Error("Create() session.CreatedAt is zero")
	}
	if session.ExpiresAt.IsZero() {
		t.Error("Create() session.ExpiresAt is zero")
	}
	if session.LastAccess.IsZero() {
		t.Error("Create() session.LastAccess is zero")
	}

	// Verify expiration is ~30 minutes from now
	expectedExpiry := time.Now().Add(30 * time.Minute)
	if session.ExpiresAt.Before(expectedExpiry.Add(-time.Second)) ||
		session.ExpiresAt.After(expectedExpiry.Add(time.Second)) {
		t.Errorf("Create() session.ExpiresAt = %v, want ~%v", session.ExpiresAt, expectedExpiry)
	}
}

func TestSessionService_Get(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(*mockSessionStore, *SessionService) string
		wantErr   error
		wantValid bool
	}{
		{
			name: "returns session if not expired",
			setup: func(store *mockSessionStore, svc *SessionService) string {
				ctx := context.Background()
				identity := &auth.Identity{ID: "user-1", Roles: []auth.Role{auth.RoleUser}}
				session, _ := svc.Create(ctx, identity)
				return session.ID
			},
			wantErr:   nil,
			wantValid: true,
		},
		{
			name: "returns error if session does not exist",
			setup: func(store *mockSessionStore, svc *SessionService) string {
				return "nonexistent-session-id"
			},
			wantErr:   ErrSessionNotFound,
			wantValid: false,
		},
		{
			name: "returns error if session expired",
			setup: func(store *mockSessionStore, svc *SessionService) string {
				// Create an already-expired session directly in store
				session := &Session{
					ID:         "expired-session",
					IdentityID: "user-1",
					Roles:      []auth.Role{auth.RoleUser},
					CreatedAt:  time.Now().Add(-2 * time.Hour),
					ExpiresAt:  time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
					LastAccess: time.Now().Add(-2 * time.Hour),
				}
				_ = store.Create(context.Background(), session)
				return session.ID
			},
			wantErr:   ErrSessionNotFound,
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockSessionStore()
			service := NewSessionService(store, Config{Timeout: 30 * time.Minute})
			ctx := context.Background()

			sessionID := tt.setup(store, service)
			session, err := service.Get(ctx, sessionID)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Get() error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Get() unexpected error = %v", err)
			}

			if tt.wantValid && session == nil {
				t.Error("Get() returned nil session, want valid session")
			}
		})
	}
}

func TestSessionService_Refresh(t *testing.T) {
	store := newMockSessionStore()
	service := NewSessionService(store, Config{Timeout: 30 * time.Minute})
	ctx := context.Background()

	identity := &auth.Identity{ID: "user-1", Roles: []auth.Role{auth.RoleUser}}
	session, _ := service.Create(ctx, identity)

	originalExpiry := session.ExpiresAt

	// Wait a tiny bit to ensure timestamps differ
	time.Sleep(10 * time.Millisecond)

	// Refresh the session
	err := service.Refresh(ctx, session.ID)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	// Get the refreshed session
	refreshed, err := service.Get(ctx, session.ID)
	if err != nil {
		t.Fatalf("Get() after Refresh() error = %v", err)
	}

	// Verify expiration was extended
	if !refreshed.ExpiresAt.After(originalExpiry) {
		t.Errorf("Refresh() ExpiresAt = %v, want after %v", refreshed.ExpiresAt, originalExpiry)
	}

	// Verify last access was updated
	if !refreshed.LastAccess.After(session.LastAccess) {
		t.Errorf("Refresh() LastAccess = %v, want after %v", refreshed.LastAccess, session.LastAccess)
	}
}

func TestSessionService_Delete(t *testing.T) {
	store := newMockSessionStore()
	service := NewSessionService(store, Config{Timeout: 30 * time.Minute})
	ctx := context.Background()

	identity := &auth.Identity{ID: "user-1", Roles: []auth.Role{auth.RoleUser}}
	session, _ := service.Create(ctx, identity)

	// Delete the session
	err := service.Delete(ctx, session.ID)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify session is gone
	_, err = service.Get(ctx, session.ID)
	if err != ErrSessionNotFound {
		t.Errorf("Get() after Delete() error = %v, want %v", err, ErrSessionNotFound)
	}
}

func TestSession_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired when ExpiresAt is in future",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "expired when ExpiresAt is in past",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				ExpiresAt: tt.expiresAt,
			}
			if got := session.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_Refresh(t *testing.T) {
	session := &Session{
		ExpiresAt:  time.Now().Add(10 * time.Minute),
		LastAccess: time.Now().Add(-5 * time.Minute),
	}

	timeout := 30 * time.Minute
	beforeRefresh := time.Now()
	session.Refresh(timeout)

	// LastAccess should be updated to now
	if session.LastAccess.Before(beforeRefresh) {
		t.Errorf("Refresh() LastAccess = %v, want >= %v", session.LastAccess, beforeRefresh)
	}

	// ExpiresAt should be ~30 minutes from now
	expectedExpiry := time.Now().Add(timeout)
	if session.ExpiresAt.Before(expectedExpiry.Add(-time.Second)) ||
		session.ExpiresAt.After(expectedExpiry.Add(time.Second)) {
		t.Errorf("Refresh() ExpiresAt = %v, want ~%v", session.ExpiresAt, expectedExpiry)
	}
}

func TestNewSessionService_DefaultTimeout(t *testing.T) {
	store := newMockSessionStore()

	// Create service with zero timeout (should use default)
	service := NewSessionService(store, Config{Timeout: 0})

	ctx := context.Background()
	identity := &auth.Identity{ID: "user-1", Roles: []auth.Role{auth.RoleUser}}
	session, _ := service.Create(ctx, identity)

	// Verify default 30 minute timeout was applied
	expectedExpiry := time.Now().Add(DefaultTimeout)
	if session.ExpiresAt.Before(expectedExpiry.Add(-time.Second)) ||
		session.ExpiresAt.After(expectedExpiry.Add(time.Second)) {
		t.Errorf("Default timeout: ExpiresAt = %v, want ~%v", session.ExpiresAt, expectedExpiry)
	}
}
