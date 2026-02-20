// Package memory provides in-memory implementations of outbound ports.
package memory

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
)

func TestAuthStore_GetAPIKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(*AuthStore)
		keyHash string
		wantErr error
		wantKey *auth.APIKey
	}{
		{
			name: "existing key",
			setup: func(s *AuthStore) {
				s.AddKey(&auth.APIKey{
					Key:        "hash123",
					IdentityID: "user-1",
					Revoked:    false,
				})
			},
			keyHash: "hash123",
			wantErr: nil,
			wantKey: &auth.APIKey{
				Key:        "hash123",
				IdentityID: "user-1",
				Revoked:    false,
			},
		},
		{
			name:    "non-existent key",
			setup:   func(s *AuthStore) {},
			keyHash: "missing",
			wantErr: ErrKeyNotFound,
			wantKey: nil,
		},
		{
			name: "revoked key still returns",
			setup: func(s *AuthStore) {
				s.AddKey(&auth.APIKey{
					Key:        "revoked-key",
					IdentityID: "user-2",
					Revoked:    true,
				})
			},
			keyHash: "revoked-key",
			wantErr: nil,
			wantKey: &auth.APIKey{
				Key:        "revoked-key",
				IdentityID: "user-2",
				Revoked:    true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			store := NewAuthStore()
			tt.setup(store)

			got, err := store.GetAPIKey(ctx, tt.keyHash)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
				return
			}

			if tt.wantKey != nil {
				if got == nil {
					t.Fatalf("GetAPIKey() returned nil, want %+v", tt.wantKey)
				}
				if got.Key != tt.wantKey.Key {
					t.Errorf("Key = %q, want %q", got.Key, tt.wantKey.Key)
				}
				if got.IdentityID != tt.wantKey.IdentityID {
					t.Errorf("IdentityID = %q, want %q", got.IdentityID, tt.wantKey.IdentityID)
				}
				if got.Revoked != tt.wantKey.Revoked {
					t.Errorf("Revoked = %v, want %v", got.Revoked, tt.wantKey.Revoked)
				}
			}
		})
	}
}

func TestAuthStore_GetIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		setup        func(*AuthStore)
		identityID   string
		wantErr      error
		wantIdentity *auth.Identity
	}{
		{
			name: "existing identity",
			setup: func(s *AuthStore) {
				s.AddIdentity(&auth.Identity{
					ID:    "user-1",
					Name:  "Test User",
					Roles: []auth.Role{auth.RoleUser},
				})
			},
			identityID: "user-1",
			wantErr:    nil,
			wantIdentity: &auth.Identity{
				ID:    "user-1",
				Name:  "Test User",
				Roles: []auth.Role{auth.RoleUser},
			},
		},
		{
			name:         "non-existent identity",
			setup:        func(s *AuthStore) {},
			identityID:   "missing",
			wantErr:      ErrIdentityNotFound,
			wantIdentity: nil,
		},
		{
			name: "identity with multiple roles",
			setup: func(s *AuthStore) {
				s.AddIdentity(&auth.Identity{
					ID:    "admin-1",
					Name:  "Admin User",
					Roles: []auth.Role{auth.RoleAdmin, auth.RoleUser},
				})
			},
			identityID: "admin-1",
			wantErr:    nil,
			wantIdentity: &auth.Identity{
				ID:    "admin-1",
				Name:  "Admin User",
				Roles: []auth.Role{auth.RoleAdmin, auth.RoleUser},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			store := NewAuthStore()
			tt.setup(store)

			got, err := store.GetIdentity(ctx, tt.identityID)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("GetIdentity() error = %v, want %v", err, tt.wantErr)
				return
			}

			if tt.wantIdentity != nil {
				if got == nil {
					t.Fatalf("GetIdentity() returned nil, want %+v", tt.wantIdentity)
				}
				if got.ID != tt.wantIdentity.ID {
					t.Errorf("ID = %q, want %q", got.ID, tt.wantIdentity.ID)
				}
				if got.Name != tt.wantIdentity.Name {
					t.Errorf("Name = %q, want %q", got.Name, tt.wantIdentity.Name)
				}
				if len(got.Roles) != len(tt.wantIdentity.Roles) {
					t.Errorf("Roles count = %d, want %d", len(got.Roles), len(tt.wantIdentity.Roles))
				} else {
					for i, role := range got.Roles {
						if role != tt.wantIdentity.Roles[i] {
							t.Errorf("Roles[%d] = %q, want %q", i, role, tt.wantIdentity.Roles[i])
						}
					}
				}
			}
		})
	}
}

func TestAuthStore_CopyOnReturn_APIKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewAuthStore()

	store.AddKey(&auth.APIKey{
		Key:        "key-copy-test",
		IdentityID: "user-1",
		Revoked:    false,
	})

	// Get and modify
	key1, err := store.GetAPIKey(ctx, "key-copy-test")
	if err != nil {
		t.Fatalf("GetAPIKey() unexpected error: %v", err)
	}
	key1.IdentityID = "modified-user"
	key1.Revoked = true

	// Get again - should not be modified
	key2, err := store.GetAPIKey(ctx, "key-copy-test")
	if err != nil {
		t.Fatalf("GetAPIKey() second call unexpected error: %v", err)
	}
	if key2.IdentityID == "modified-user" {
		t.Error("Store returned reference instead of copy (IdentityID was modified)")
	}
	if key2.Revoked {
		t.Error("Store returned reference instead of copy (Revoked was modified)")
	}
}

func TestAuthStore_CopyOnReturn_Identity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewAuthStore()

	store.AddIdentity(&auth.Identity{
		ID:    "user-copy-test",
		Name:  "Original Name",
		Roles: []auth.Role{auth.RoleUser},
	})

	// Get and modify
	identity1, err := store.GetIdentity(ctx, "user-copy-test")
	if err != nil {
		t.Fatalf("GetIdentity() unexpected error: %v", err)
	}
	identity1.Name = "Modified Name"
	identity1.Roles = append(identity1.Roles, auth.RoleAdmin)

	// Get again - should not be modified
	identity2, err := store.GetIdentity(ctx, "user-copy-test")
	if err != nil {
		t.Fatalf("GetIdentity() second call unexpected error: %v", err)
	}
	if identity2.Name == "Modified Name" {
		t.Error("Store returned reference instead of copy (Name was modified)")
	}
	if len(identity2.Roles) != 1 {
		t.Errorf("Store returned reference instead of copy (Roles length = %d, want 1)", len(identity2.Roles))
	}
}

func TestAuthStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewAuthStore()

	// Add test data
	store.AddKey(&auth.APIKey{Key: "concurrent-key", IdentityID: "user-1"})
	store.AddIdentity(&auth.Identity{ID: "user-1", Name: "Test User", Roles: []auth.Role{auth.RoleUser}})

	var wg sync.WaitGroup
	errCh := make(chan error, 200)

	// 100 goroutines reading API key
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.GetAPIKey(ctx, "concurrent-key")
			if err != nil {
				errCh <- err
			}
		}()
	}

	// 100 goroutines reading identity
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.GetIdentity(ctx, "user-1")
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Concurrent access error: %v", err)
	}
}

func TestAuthStore_AddKey_Overwrites(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewAuthStore()

	// Add key
	store.AddKey(&auth.APIKey{
		Key:        "overwrite-key",
		IdentityID: "user-1",
	})

	// Overwrite with same key hash
	store.AddKey(&auth.APIKey{
		Key:        "overwrite-key",
		IdentityID: "user-2",
	})

	// Should return the new value
	got, err := store.GetAPIKey(ctx, "overwrite-key")
	if err != nil {
		t.Fatalf("GetAPIKey() unexpected error: %v", err)
	}
	if got.IdentityID != "user-2" {
		t.Errorf("IdentityID = %q, want %q (overwrite failed)", got.IdentityID, "user-2")
	}
}

func TestAuthStore_AddIdentity_Overwrites(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := NewAuthStore()

	// Add identity
	store.AddIdentity(&auth.Identity{
		ID:   "overwrite-user",
		Name: "Original Name",
	})

	// Overwrite with same ID
	store.AddIdentity(&auth.Identity{
		ID:   "overwrite-user",
		Name: "New Name",
	})

	// Should return the new value
	got, err := store.GetIdentity(ctx, "overwrite-user")
	if err != nil {
		t.Fatalf("GetIdentity() unexpected error: %v", err)
	}
	if got.Name != "New Name" {
		t.Errorf("Name = %q, want %q (overwrite failed)", got.Name, "New Name")
	}
}
