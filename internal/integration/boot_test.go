// Package integration provides end-to-end integration tests that verify
// Phase 1 success criteria across multiple components working together.
package integration

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// testLogger returns a logger that writes to stderr at error level (quiet tests).
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestBootEmptyState verifies that booting with no existing state.json creates
// a default state with deny-all policy (TEST-13, Success Criteria 1).
func TestBootEmptyState(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := testLogger()

	// Create FileStateStore pointing to nonexistent file.
	store := state.NewFileStateStore(statePath, logger)

	// Load should return default state (file doesn't exist).
	appState, err := store.Load()
	if err != nil {
		t.Fatalf("Load() on empty dir: unexpected error: %v", err)
	}

	// Assert default state structure.
	if appState.Version != "1" {
		t.Errorf("Version = %q, want %q", appState.Version, "1")
	}
	if appState.DefaultPolicy != "deny" {
		t.Errorf("DefaultPolicy = %q, want %q", appState.DefaultPolicy, "deny")
	}

	// Assert exactly 1 deny-all policy.
	if len(appState.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(appState.Policies))
	}

	denyAll := appState.Policies[0]
	if denyAll.Priority != 0 {
		t.Errorf("Policies[0].Priority = %d, want 0", denyAll.Priority)
	}
	if denyAll.Action != "deny" {
		t.Errorf("Policies[0].Action = %q, want %q", denyAll.Action, "deny")
	}
	if denyAll.ToolPattern != "*" {
		t.Errorf("Policies[0].ToolPattern = %q, want %q", denyAll.ToolPattern, "*")
	}
	if !denyAll.Enabled {
		t.Error("Policies[0].Enabled = false, want true")
	}

	// Assert empty collections.
	if len(appState.Upstreams) != 0 {
		t.Errorf("len(Upstreams) = %d, want 0", len(appState.Upstreams))
	}
	if len(appState.Identities) != 0 {
		t.Errorf("len(Identities) = %d, want 0", len(appState.Identities))
	}
	if len(appState.APIKeys) != 0 {
		t.Errorf("len(APIKeys) = %d, want 0", len(appState.APIKeys))
	}

	// Save the state and verify file is created.
	if err := store.Save(appState); err != nil {
		t.Fatalf("Save() unexpected error: %v", err)
	}

	// Verify file exists.
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("state.json not created: %v", err)
	}

	// Verify file permissions are 0600 — skip on Windows where Unix permissions are unsupported.
	if runtime.GOOS != "windows" {
		perm := info.Mode().Perm()
		if perm != 0600 {
			t.Errorf("state.json permissions = %o, want 0600", perm)
		}
	}

	// Load again and verify content persisted correctly.
	reloaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() after Save: unexpected error: %v", err)
	}
	if reloaded.Version != "1" {
		t.Errorf("Reloaded Version = %q, want %q", reloaded.Version, "1")
	}
	if reloaded.DefaultPolicy != "deny" {
		t.Errorf("Reloaded DefaultPolicy = %q, want %q", reloaded.DefaultPolicy, "deny")
	}
	if len(reloaded.Policies) != 1 {
		t.Fatalf("Reloaded len(Policies) = %d, want 1", len(reloaded.Policies))
	}
	if reloaded.Policies[0].Action != "deny" {
		t.Errorf("Reloaded Policies[0].Action = %q, want %q", reloaded.Policies[0].Action, "deny")
	}
}

// TestBootExistingState verifies that booting with an existing state.json loads
// upstreams, policies, identities, and API keys correctly (TEST-14, Success Criteria 2).
func TestBootExistingState(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
	logger := testLogger()

	// Write a state.json file with 2 upstreams, 3 policies, 1 identity, 1 API key.
	existingState := state.AppState{
		Version:       "1",
		DefaultPolicy: "deny",
		Upstreams: []state.UpstreamEntry{
			{
				ID:      "up-1",
				Name:    "filesystem-server",
				Type:    "stdio",
				Enabled: true,
				Command: "/usr/local/bin/mcp-fs",
				Args:    []string{"/tmp"},
			},
			{
				ID:      "up-2",
				Name:    "web-search",
				Type:    "http",
				Enabled: true,
				URL:     "http://localhost:3001/mcp",
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
			},
			{
				ID:          "allow-read",
				Name:        "Allow Read",
				Priority:    10,
				ToolPattern: "read_*",
				Action:      "allow",
				Enabled:     true,
			},
			{
				ID:          "allow-search",
				Name:        "Allow Search",
				Priority:    20,
				ToolPattern: "search_*",
				Action:      "allow",
				Enabled:     true,
			},
		},
		Identities: []state.IdentityEntry{
			{
				ID:    "user-1",
				Name:  "Test User",
				Roles: []string{"admin", "user"},
			},
		},
		APIKeys: []state.APIKeyEntry{
			{
				ID:         "key-1",
				KeyHash:    "sha256:abc123",
				IdentityID: "user-1",
				Name:       "Test Key",
			},
		},
	}

	data, err := json.MarshalIndent(existingState, "", "  ")
	if err != nil {
		t.Fatalf("Marshal existing state: %v", err)
	}
	if err := os.WriteFile(statePath, data, 0600); err != nil {
		t.Fatalf("Write state.json: %v", err)
	}

	// Create FileStateStore and load.
	stateStore := state.NewFileStateStore(statePath, logger)
	appState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	// Assert all data loaded correctly.
	if len(appState.Upstreams) != 2 {
		t.Fatalf("len(Upstreams) = %d, want 2", len(appState.Upstreams))
	}
	if len(appState.Policies) != 3 {
		t.Fatalf("len(Policies) = %d, want 3", len(appState.Policies))
	}
	if len(appState.Identities) != 1 {
		t.Fatalf("len(Identities) = %d, want 1", len(appState.Identities))
	}
	if len(appState.APIKeys) != 1 {
		t.Fatalf("len(APIKeys) = %d, want 1", len(appState.APIKeys))
	}

	// Verify upstream details.
	up1 := appState.Upstreams[0]
	if up1.ID != "up-1" {
		t.Errorf("Upstreams[0].ID = %q, want %q", up1.ID, "up-1")
	}
	if up1.Name != "filesystem-server" {
		t.Errorf("Upstreams[0].Name = %q, want %q", up1.Name, "filesystem-server")
	}
	if up1.Type != "stdio" {
		t.Errorf("Upstreams[0].Type = %q, want %q", up1.Type, "stdio")
	}

	up2 := appState.Upstreams[1]
	if up2.ID != "up-2" {
		t.Errorf("Upstreams[1].ID = %q, want %q", up2.ID, "up-2")
	}
	if up2.Type != "http" {
		t.Errorf("Upstreams[1].Type = %q, want %q", up2.Type, "http")
	}

	// Create UpstreamService and load from state.
	upstreamStore := memory.NewUpstreamStore()
	upstreamService := service.NewUpstreamService(upstreamStore, stateStore, logger)

	if err := upstreamService.LoadFromState(context.Background(), appState); err != nil {
		t.Fatalf("LoadFromState() unexpected error: %v", err)
	}

	// Assert 2 upstreams in service.
	ctx := t.Context()
	upstreams, err := upstreamService.List(ctx)
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}
	if len(upstreams) != 2 {
		t.Fatalf("upstreamService.List() = %d upstreams, want 2", len(upstreams))
	}

	// Verify upstream names and types loaded correctly.
	nameTypeMap := make(map[string]upstream.UpstreamType)
	for _, u := range upstreams {
		nameTypeMap[u.Name] = u.Type
	}

	if typ, ok := nameTypeMap["filesystem-server"]; !ok || typ != upstream.UpstreamTypeStdio {
		t.Errorf("filesystem-server type = %q, want %q", typ, upstream.UpstreamTypeStdio)
	}
	if typ, ok := nameTypeMap["web-search"]; !ok || typ != upstream.UpstreamTypeHTTP {
		t.Errorf("web-search type = %q, want %q", typ, upstream.UpstreamTypeHTTP)
	}
}
