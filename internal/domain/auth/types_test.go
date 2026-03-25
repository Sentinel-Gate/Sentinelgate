package auth

import (
	"testing"
	"time"
)

func TestIdentity_HasRole_Present(t *testing.T) {
	identity := &Identity{
		ID:    "id-1",
		Name:  "Alice",
		Roles: []Role{RoleAdmin, RoleUser},
	}

	if !identity.HasRole(RoleAdmin) {
		t.Error("HasRole(RoleAdmin) = false, want true")
	}
	if !identity.HasRole(RoleUser) {
		t.Error("HasRole(RoleUser) = false, want true")
	}
}

func TestIdentity_HasRole_Missing(t *testing.T) {
	identity := &Identity{
		ID:    "id-2",
		Name:  "Bob",
		Roles: []Role{RoleUser},
	}

	if identity.HasRole(RoleAdmin) {
		t.Error("HasRole(RoleAdmin) = true, want false")
	}
	if identity.HasRole(RoleReadOnly) {
		t.Error("HasRole(RoleReadOnly) = true, want false")
	}
}

func TestIdentity_HasRole_EmptyRoles(t *testing.T) {
	identity := &Identity{
		ID:    "id-3",
		Name:  "Empty",
		Roles: nil,
	}

	if identity.HasRole(RoleAdmin) {
		t.Error("HasRole on nil Roles = true, want false")
	}
}

func TestIdentity_HasAnyRole_Match(t *testing.T) {
	identity := &Identity{
		ID:    "id-4",
		Name:  "Carol",
		Roles: []Role{RoleReadOnly},
	}

	// One of the provided roles matches.
	if !identity.HasAnyRole(RoleAdmin, RoleReadOnly) {
		t.Error("HasAnyRole(RoleAdmin, RoleReadOnly) = false, want true")
	}

	// Single matching role.
	if !identity.HasAnyRole(RoleReadOnly) {
		t.Error("HasAnyRole(RoleReadOnly) = false, want true")
	}
}

func TestIdentity_HasAnyRole_None(t *testing.T) {
	identity := &Identity{
		ID:    "id-5",
		Name:  "Dave",
		Roles: []Role{RoleUser},
	}

	if identity.HasAnyRole(RoleAdmin, RoleReadOnly) {
		t.Error("HasAnyRole(RoleAdmin, RoleReadOnly) = true, want false")
	}

	// No arguments should always return false.
	if identity.HasAnyRole() {
		t.Error("HasAnyRole() with no args = true, want false")
	}
}

func TestAPIKey_IsExpired_Past(t *testing.T) {
	past := time.Now().UTC().Add(-2 * time.Hour)
	key := &APIKey{
		Key:        "hash-1",
		IdentityID: "id-1",
		ExpiresAt:  &past,
	}

	if !key.IsExpired() {
		t.Error("IsExpired() = false for past ExpiresAt, want true")
	}
}

func TestAPIKey_IsExpired_NotExpired(t *testing.T) {
	future := time.Now().UTC().Add(24 * time.Hour)
	key := &APIKey{
		Key:        "hash-2",
		IdentityID: "id-2",
		ExpiresAt:  &future,
	}

	if key.IsExpired() {
		t.Error("IsExpired() = true for future ExpiresAt, want false")
	}
}

func TestAPIKey_IsExpired_ZeroTime(t *testing.T) {
	// nil ExpiresAt means the key never expires.
	key := &APIKey{
		Key:        "hash-3",
		IdentityID: "id-3",
		ExpiresAt:  nil,
	}

	if key.IsExpired() {
		t.Error("IsExpired() = true for nil ExpiresAt, want false (never expires)")
	}
}
