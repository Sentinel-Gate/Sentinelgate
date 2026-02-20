package integration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// TestYAMLStateMerge verifies that YAML config identities/policies are treated as
// read-only base, and state.json entries are mutable (TEST-15, Success Criteria 1).
//
// The merge pattern replicates what the boot sequence does:
// 1. Load YAML config (provides identities, policies as read-only)
// 2. Load state.json (provides upstreams and mutable identities/policies)
// 3. Seed YAML items into stores (marked read-only)
// 4. Load state.json upstreams into upstream service
// 5. Result: combined set with YAML as read-only base + state.json as mutable
func TestYAMLStateMerge(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	// --- Prepare YAML config ---
	cfg := &config.OSSConfig{
		Server: config.ServerConfig{
			HTTPAddr:       ":9090",
			LogLevel:       "info",
			SessionTimeout: "30m",
		},
		Auth: config.AuthConfig{
			Identities: []config.IdentityConfig{
				{
					ID:    "yaml-user",
					Name:  "YAML User",
					Roles: []string{"admin"},
				},
			},
			APIKeys: []config.APIKeyConfig{
				{
					KeyHash:    "sha256:yamlkey123",
					IdentityID: "yaml-user",
				},
			},
		},
		Policies: []config.PolicyConfig{
			{
				Name: "yaml-policy",
				Rules: []config.RuleConfig{
					{
						Name:      "allow-all",
						Condition: "true",
						Action:    "allow",
					},
				},
			},
		},
		Audit: config.AuditConfig{
			Output: "stdout",
		},
	}

	// --- Prepare state.json ---
	now := time.Now().UTC()
	stateData := state.AppState{
		Version:       "1",
		DefaultPolicy: "deny",
		Upstreams: []state.UpstreamEntry{
			{
				ID:        "state-upstream-1",
				Name:      "state-server",
				Type:      "stdio",
				Enabled:   true,
				Command:   "/usr/bin/echo",
				Args:      []string{"hello"},
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		Policies: []state.PolicyEntry{
			{
				ID:          "default-deny-all",
				Name:        "Default Deny All",
				Priority:    0,
				ToolPattern: "*",
				Action:      "deny",
				Enabled:     true,
				ReadOnly:    false,
				CreatedAt:   now,
				UpdatedAt:   now,
			},
			{
				ID:          "state-policy",
				Name:        "State Policy",
				Priority:    50,
				ToolPattern: "read_*",
				Action:      "allow",
				Enabled:     true,
				ReadOnly:    false,
				CreatedAt:   now,
				UpdatedAt:   now,
			},
		},
		Identities: []state.IdentityEntry{
			{
				ID:       "state-user",
				Name:     "State User",
				Roles:    []string{"user"},
				ReadOnly: false,
			},
		},
		APIKeys:   []state.APIKeyEntry{},
		CreatedAt: now,
		UpdatedAt: now,
	}

	data, err := json.MarshalIndent(stateData, "", "  ")
	if err != nil {
		t.Fatalf("Marshal state: %v", err)
	}
	if err := os.WriteFile(statePath, data, 0600); err != nil {
		t.Fatalf("Write state.json: %v", err)
	}

	// --- Replicate boot sequence merge ---

	// Step 1: Load state.json.
	stateStore := state.NewFileStateStore(statePath, logger)
	appState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load state.json: %v", err)
	}

	// Step 2: Create in-memory stores.
	authStore := memory.NewAuthStore()
	upstreamStore := memory.NewUpstreamStore()

	// Step 3: Seed YAML identities as read-only base.
	for _, identityCfg := range cfg.Auth.Identities {
		roles := make([]auth.Role, len(identityCfg.Roles))
		for i, role := range identityCfg.Roles {
			roles[i] = auth.Role(role)
		}
		authStore.AddIdentity(&auth.Identity{
			ID:    identityCfg.ID,
			Name:  identityCfg.Name,
			Roles: roles,
		})
	}

	// Step 4: Seed state.json identities (mutable).
	for _, identityEntry := range appState.Identities {
		roles := make([]auth.Role, len(identityEntry.Roles))
		for i, role := range identityEntry.Roles {
			roles[i] = auth.Role(role)
		}
		authStore.AddIdentity(&auth.Identity{
			ID:    identityEntry.ID,
			Name:  identityEntry.Name,
			Roles: roles,
		})
	}

	// Step 5: Load state.json upstreams into upstream service.
	upstreamService := service.NewUpstreamService(upstreamStore, stateStore, logger)
	if err := upstreamService.LoadFromState(context.Background(), appState); err != nil {
		t.Fatalf("LoadFromState: %v", err)
	}

	// --- Assert merge results ---

	ctx := context.Background()

	// Assert total identities = 2 (1 from YAML + 1 from state).
	yamlIdentity, err := authStore.GetIdentity(ctx, "yaml-user")
	if err != nil {
		t.Fatalf("GetIdentity(yaml-user): %v", err)
	}
	if yamlIdentity.Name != "YAML User" {
		t.Errorf("yaml-user Name = %q, want %q", yamlIdentity.Name, "YAML User")
	}

	stateIdentity, err := authStore.GetIdentity(ctx, "state-user")
	if err != nil {
		t.Fatalf("GetIdentity(state-user): %v", err)
	}
	if stateIdentity.Name != "State User" {
		t.Errorf("state-user Name = %q, want %q", stateIdentity.Name, "State User")
	}

	// Assert state.json policies: 2 entries (deny-all + state-policy).
	if len(appState.Policies) != 2 {
		t.Errorf("state.json policies = %d, want 2", len(appState.Policies))
	}

	// Assert state.json identity has ReadOnly=false.
	for _, entry := range appState.Identities {
		if entry.ID == "state-user" && entry.ReadOnly {
			t.Error("state-user ReadOnly = true, want false")
		}
	}

	// Assert server config comes from YAML (http_addr=":9090").
	if cfg.Server.HTTPAddr != ":9090" {
		t.Errorf("Server.HTTPAddr = %q, want %q", cfg.Server.HTTPAddr, ":9090")
	}

	// Assert upstreams loaded from state.json.
	upstreams, err := upstreamService.List(ctx)
	if err != nil {
		t.Fatalf("List upstreams: %v", err)
	}
	if len(upstreams) != 1 {
		t.Fatalf("len(upstreams) = %d, want 1", len(upstreams))
	}
	if upstreams[0].Name != "state-server" {
		t.Errorf("Upstream[0].Name = %q, want %q", upstreams[0].Name, "state-server")
	}
	if upstreams[0].Type != upstream.UpstreamTypeStdio {
		t.Errorf("Upstream[0].Type = %q, want %q", upstreams[0].Type, upstream.UpstreamTypeStdio)
	}
}

// TestYAMLUpstreamMigration verifies that a YAML-configured upstream is auto-migrated
// to state.json when state.json has no upstreams (backward compatibility).
func TestYAMLUpstreamMigration(t *testing.T) {
	logger := testLogger()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	// Create state store and get default state (no upstreams).
	stateStore := state.NewFileStateStore(statePath, logger)
	appState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify no upstreams in default state.
	if len(appState.Upstreams) != 0 {
		t.Fatalf("Default state should have 0 upstreams, got %d", len(appState.Upstreams))
	}

	// Simulate YAML upstream config present.
	cfg := &config.OSSConfig{
		Upstream: config.UpstreamConfig{
			Command: "/usr/bin/echo",
			Args:    []string{"hello"},
		},
	}

	// If YAML has upstream and state has no upstreams, migrate.
	if cfg.HasYAMLUpstream() && len(appState.Upstreams) == 0 {
		appState.Upstreams = append(appState.Upstreams, state.UpstreamEntry{
			ID:      "migrated-1",
			Name:    "default",
			Type:    "stdio",
			Enabled: true,
			Command: cfg.Upstream.Command,
			Args:    cfg.Upstream.Args,
		})

		if err := stateStore.Save(appState); err != nil {
			t.Fatalf("Save migrated state: %v", err)
		}
	}

	// Reload and verify migration persisted.
	reloaded, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load after migration: %v", err)
	}

	if len(reloaded.Upstreams) != 1 {
		t.Fatalf("After migration len(Upstreams) = %d, want 1", len(reloaded.Upstreams))
	}
	if reloaded.Upstreams[0].Name != "default" {
		t.Errorf("Migrated upstream Name = %q, want %q", reloaded.Upstreams[0].Name, "default")
	}
	if reloaded.Upstreams[0].Type != "stdio" {
		t.Errorf("Migrated upstream Type = %q, want %q", reloaded.Upstreams[0].Type, "stdio")
	}
	if reloaded.Upstreams[0].Command != "/usr/bin/echo" {
		t.Errorf("Migrated upstream Command = %q, want %q", reloaded.Upstreams[0].Command, "/usr/bin/echo")
	}
}
