package state

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// ---------------------------------------------------------------------------
// DefaultState tests
// ---------------------------------------------------------------------------

func TestDefaultState_HasDenyAllPolicy(t *testing.T) {
	s := NewFileStateStore(filepath.Join(t.TempDir(), "state.json"), testLogger())
	state := s.DefaultState()

	if state.Version != "1" {
		t.Errorf("expected Version '1', got %q", state.Version)
	}
	if state.DefaultPolicy != "deny" {
		t.Errorf("expected DefaultPolicy 'deny', got %q", state.DefaultPolicy)
	}
	if len(state.Policies) != 1 {
		t.Fatalf("expected 1 default policy, got %d", len(state.Policies))
	}

	p := state.Policies[0]
	if p.Priority != 0 {
		t.Errorf("expected priority 0, got %d", p.Priority)
	}
	if p.ToolPattern != "*" {
		t.Errorf("expected ToolPattern '*', got %q", p.ToolPattern)
	}
	if p.Action != "deny" {
		t.Errorf("expected Action 'deny', got %q", p.Action)
	}
	if !p.Enabled {
		t.Error("expected default deny-all policy to be enabled")
	}
	if p.ReadOnly {
		t.Error("expected default deny-all policy to not be ReadOnly")
	}
	if state.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
}

func TestDefaultState_EmptyCollections(t *testing.T) {
	s := NewFileStateStore(filepath.Join(t.TempDir(), "state.json"), testLogger())
	state := s.DefaultState()

	if state.Upstreams == nil || len(state.Upstreams) != 0 {
		t.Errorf("expected empty Upstreams slice, got %v", state.Upstreams)
	}
	if state.Identities == nil || len(state.Identities) != 0 {
		t.Errorf("expected empty Identities slice, got %v", state.Identities)
	}
	if state.APIKeys == nil || len(state.APIKeys) != 0 {
		t.Errorf("expected empty APIKeys slice, got %v", state.APIKeys)
	}
	if state.AdminPasswordHash != "" {
		t.Errorf("expected empty AdminPasswordHash, got %q", state.AdminPasswordHash)
	}
}

// ---------------------------------------------------------------------------
// Load tests
// ---------------------------------------------------------------------------

func TestLoad_NoFile_ReturnsDefaultState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := NewFileStateStore(path, testLogger())

	state, err := s.Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	if state.Version != "1" {
		t.Errorf("expected Version '1', got %q", state.Version)
	}
	if state.DefaultPolicy != "deny" {
		t.Errorf("expected DefaultPolicy 'deny', got %q", state.DefaultPolicy)
	}
	if len(state.Policies) != 1 {
		t.Fatalf("expected 1 default policy, got %d", len(state.Policies))
	}
	if state.Policies[0].Action != "deny" {
		t.Errorf("expected deny action, got %q", state.Policies[0].Action)
	}
}

func TestLoad_ValidFile_ReturnsParsedState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	now := time.Now().UTC().Truncate(time.Second)
	original := &AppState{
		Version:       "1",
		DefaultPolicy: "allow",
		Upstreams: []UpstreamEntry{
			{
				ID:      "upstream-1",
				Name:    "test-upstream",
				Type:    "http",
				Enabled: true,
				URL:     "http://localhost:3000/mcp",
			},
		},
		Policies: []PolicyEntry{
			{
				ID:          "policy-1",
				Name:        "test-policy",
				Priority:    10,
				ToolPattern: "file_*",
				Action:      "allow",
				Enabled:     true,
			},
		},
		Identities: []IdentityEntry{
			{
				ID:    "id-1",
				Name:  "test-user",
				Roles: []string{"admin"},
			},
		},
		APIKeys: []APIKeyEntry{
			{
				ID:         "key-1",
				KeyHash:    "argon2:hash",
				IdentityID: "id-1",
				Name:       "test-key",
			},
		},
		AdminPasswordHash: "argon2:adminhash",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	data, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal test state: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("failed to write test state: %v", err)
	}

	s := NewFileStateStore(path, testLogger())
	state, err := s.Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	if state.Version != "1" {
		t.Errorf("expected Version '1', got %q", state.Version)
	}
	if state.DefaultPolicy != "allow" {
		t.Errorf("expected DefaultPolicy 'allow', got %q", state.DefaultPolicy)
	}
	if len(state.Upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(state.Upstreams))
	}
	if state.Upstreams[0].ID != "upstream-1" {
		t.Errorf("expected upstream ID 'upstream-1', got %q", state.Upstreams[0].ID)
	}
	if state.Upstreams[0].URL != "http://localhost:3000/mcp" {
		t.Errorf("expected upstream URL, got %q", state.Upstreams[0].URL)
	}
	if len(state.Policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(state.Policies))
	}
	if state.Policies[0].ToolPattern != "file_*" {
		t.Errorf("expected ToolPattern 'file_*', got %q", state.Policies[0].ToolPattern)
	}
	if len(state.Identities) != 1 || state.Identities[0].ID != "id-1" {
		t.Errorf("unexpected identities: %v", state.Identities)
	}
	if len(state.APIKeys) != 1 || state.APIKeys[0].KeyHash != "argon2:hash" {
		t.Errorf("unexpected API keys: %v", state.APIKeys)
	}
	if state.AdminPasswordHash != "argon2:adminhash" {
		t.Errorf("expected admin password hash, got %q", state.AdminPasswordHash)
	}
}

func TestLoad_CorruptFile_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := os.WriteFile(path, []byte("{invalid json"), 0600); err != nil {
		t.Fatalf("failed to write corrupt file: %v", err)
	}

	s := NewFileStateStore(path, testLogger())
	_, err := s.Load()
	if err == nil {
		t.Fatal("expected error for corrupt JSON, got nil")
	}
}

// ---------------------------------------------------------------------------
// Save tests
// ---------------------------------------------------------------------------

func TestSave_CreatesFileWithCorrectContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := NewFileStateStore(path, testLogger())

	state := s.DefaultState()
	state.AdminPasswordHash = "argon2:testhash"

	if err := s.Save(state); err != nil {
		t.Fatalf("Save() returned unexpected error: %v", err)
	}

	// Verify file exists and content is correct
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read saved file: %v", err)
	}

	var loaded AppState
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal saved file: %v", err)
	}

	if loaded.AdminPasswordHash != "argon2:testhash" {
		t.Errorf("expected admin hash 'argon2:testhash', got %q", loaded.AdminPasswordHash)
	}
	if loaded.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be set after Save")
	}
}

func TestSave_SetsFilePermissions0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := NewFileStateStore(path, testLogger())

	state := s.DefaultState()
	if err := s.Save(state); err != nil {
		t.Fatalf("Save() returned unexpected error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat file: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("expected permissions 0600, got %04o", perm)
	}
}

func TestSave_CreatesBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := NewFileStateStore(path, testLogger())

	// Save initial state
	state1 := s.DefaultState()
	state1.AdminPasswordHash = "original"
	if err := s.Save(state1); err != nil {
		t.Fatalf("first Save() failed: %v", err)
	}

	// Save updated state
	state2 := s.DefaultState()
	state2.AdminPasswordHash = "updated"
	if err := s.Save(state2); err != nil {
		t.Fatalf("second Save() failed: %v", err)
	}

	// Verify backup exists with original content
	bakPath := path + ".bak"
	data, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("failed to read backup file: %v", err)
	}

	var backup AppState
	if err := json.Unmarshal(data, &backup); err != nil {
		t.Fatalf("failed to unmarshal backup: %v", err)
	}

	if backup.AdminPasswordHash != "original" {
		t.Errorf("expected backup to contain 'original', got %q", backup.AdminPasswordHash)
	}

	// Verify current file has updated content
	currentData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read current file: %v", err)
	}

	var current AppState
	if err := json.Unmarshal(currentData, &current); err != nil {
		t.Fatalf("failed to unmarshal current: %v", err)
	}

	if current.AdminPasswordHash != "updated" {
		t.Errorf("expected current to contain 'updated', got %q", current.AdminPasswordHash)
	}
}

func TestSave_AtomicWrite_NoTmpFileLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := NewFileStateStore(path, testLogger())

	state := s.DefaultState()
	if err := s.Save(state); err != nil {
		t.Fatalf("Save() returned unexpected error: %v", err)
	}

	// Verify no .tmp file remains
	tmpPath := path + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Errorf("expected .tmp file to not exist after save, but it does")
	}
}

func TestSave_UpdatesUpdatedAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := NewFileStateStore(path, testLogger())

	state := s.DefaultState()
	originalUpdatedAt := state.UpdatedAt

	// Small sleep to ensure time difference
	time.Sleep(10 * time.Millisecond)

	if err := s.Save(state); err != nil {
		t.Fatalf("Save() returned unexpected error: %v", err)
	}

	if !state.UpdatedAt.After(originalUpdatedAt) {
		t.Errorf("expected UpdatedAt to be updated, original=%v, new=%v", originalUpdatedAt, state.UpdatedAt)
	}
}

// ---------------------------------------------------------------------------
// Exists tests
// ---------------------------------------------------------------------------

func TestExists_NoFile_ReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := NewFileStateStore(path, testLogger())

	if s.Exists() {
		t.Error("expected Exists() to return false for missing file")
	}
}

func TestExists_WithFile_ReturnsTrue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	s := NewFileStateStore(path, testLogger())
	if !s.Exists() {
		t.Error("expected Exists() to return true for existing file")
	}
}

// ---------------------------------------------------------------------------
// Path tests
// ---------------------------------------------------------------------------

func TestPath_ReturnsConfiguredPath(t *testing.T) {
	expected := "/some/path/state.json"
	s := NewFileStateStore(expected, testLogger())

	if got := s.Path(); got != expected {
		t.Errorf("expected path %q, got %q", expected, got)
	}
}

// ---------------------------------------------------------------------------
// Concurrent access tests
// ---------------------------------------------------------------------------

func TestConcurrentSaves_DoNotCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := NewFileStateStore(path, testLogger())

	// Save initial state
	initial := s.DefaultState()
	if err := s.Save(initial); err != nil {
		t.Fatalf("initial Save() failed: %v", err)
	}

	// Run concurrent saves
	const goroutines = 20
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			st := s.DefaultState()
			st.AdminPasswordHash = "hash-from-goroutine"
			if err := s.Save(st); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent Save() error: %v", err)
	}

	// Verify file is valid JSON after concurrent writes
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file after concurrent saves: %v", err)
	}

	var final AppState
	if err := json.Unmarshal(data, &final); err != nil {
		t.Fatalf("file corrupted after concurrent saves: %v", err)
	}

	if final.Version != "1" {
		t.Errorf("expected Version '1' after concurrent saves, got %q", final.Version)
	}
}

// ---------------------------------------------------------------------------
// Round-trip test
// ---------------------------------------------------------------------------

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := NewFileStateStore(path, testLogger())

	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(24 * time.Hour)

	original := &AppState{
		Version:       "1",
		DefaultPolicy: "deny",
		Upstreams: []UpstreamEntry{
			{
				ID:      "u1",
				Name:    "my-mcp",
				Type:    "stdio",
				Enabled: true,
				Command: "/usr/bin/mcp-server",
				Args:    []string{"--port", "3000"},
				Env:     map[string]string{"HOME": "/tmp"},
			},
		},
		Policies: []PolicyEntry{
			{
				ID:          "p1",
				Name:        "deny-all",
				Priority:    0,
				ToolPattern: "*",
				Action:      "deny",
				Enabled:     true,
			},
			{
				ID:          "p2",
				Name:        "allow-read",
				Priority:    10,
				ToolPattern: "read_*",
				Condition:   "identity.roles.exists(r, r == 'admin')",
				Action:      "allow",
				Enabled:     true,
			},
		},
		Identities: []IdentityEntry{
			{
				ID:    "i1",
				Name:  "admin",
				Roles: []string{"admin", "user"},
			},
		},
		APIKeys: []APIKeyEntry{
			{
				ID:         "k1",
				KeyHash:    "argon2:somehash",
				IdentityID: "i1",
				Name:       "admin-key",
				ExpiresAt:  &expires,
			},
		},
		AdminPasswordHash: "argon2:adminpass",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := s.Save(original); err != nil {
		t.Fatalf("Save() failed: %v", err)
	}

	loaded, err := s.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify key fields survive round trip
	if loaded.Version != original.Version {
		t.Errorf("Version mismatch: %q vs %q", loaded.Version, original.Version)
	}
	if loaded.DefaultPolicy != original.DefaultPolicy {
		t.Errorf("DefaultPolicy mismatch: %q vs %q", loaded.DefaultPolicy, original.DefaultPolicy)
	}
	if len(loaded.Upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(loaded.Upstreams))
	}
	if loaded.Upstreams[0].Command != "/usr/bin/mcp-server" {
		t.Errorf("upstream command mismatch")
	}
	if len(loaded.Upstreams[0].Args) != 2 || loaded.Upstreams[0].Args[0] != "--port" {
		t.Errorf("upstream args mismatch: %v", loaded.Upstreams[0].Args)
	}
	if loaded.Upstreams[0].Env["HOME"] != "/tmp" {
		t.Errorf("upstream env mismatch: %v", loaded.Upstreams[0].Env)
	}
	if len(loaded.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(loaded.Policies))
	}
	if loaded.Policies[1].Condition != "identity.roles.exists(r, r == 'admin')" {
		t.Errorf("policy condition mismatch: %q", loaded.Policies[1].Condition)
	}
	if loaded.APIKeys[0].ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to survive round trip")
	}
	if !loaded.APIKeys[0].ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt mismatch: %v vs %v", loaded.APIKeys[0].ExpiresAt, expires)
	}
	if loaded.AdminPasswordHash != "argon2:adminpass" {
		t.Errorf("admin hash mismatch: %q", loaded.AdminPasswordHash)
	}
}

// ---------------------------------------------------------------------------
// Permission tests (SECU-07)
// ---------------------------------------------------------------------------

func TestLoad_TooOpenPermissions_WarnsButSucceeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	// Write a valid state file with world-readable permissions.
	data := []byte(`{"version":"1","default_policy":"deny","policies":[],"upstreams":[],"identities":[],"api_keys":[]}`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Capture log output to verify warning.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	s := NewFileStateStore(path, logger)

	state, err := s.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if state == nil {
		t.Fatal("Load() returned nil state")
	}

	// Check that a warning was logged about permissions.
	logOutput := buf.String()
	if !strings.Contains(logOutput, "too-open permissions") {
		t.Errorf("expected warning about too-open permissions, got log output: %q", logOutput)
	}
}

func TestLoad_CorrectPermissions_NoWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	data := []byte(`{"version":"1","default_policy":"deny","policies":[],"upstreams":[],"identities":[],"api_keys":[]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	s := NewFileStateStore(path, logger)

	state, err := s.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if state == nil {
		t.Fatal("Load() returned nil state")
	}

	// No permission warning should be logged.
	logOutput := buf.String()
	if strings.Contains(logOutput, "too-open permissions") {
		t.Errorf("unexpected warning for correctly permissioned file, got: %q", logOutput)
	}
}

func TestSave_ExplicitChmod0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := NewFileStateStore(path, testLogger())

	state := s.DefaultState()
	if err := s.Save(state); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	// Manually change permissions to something too open.
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	// Save again - should restore 0600.
	if err := s.Save(state); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected 0600 after save, got %04o", perm)
	}
}
