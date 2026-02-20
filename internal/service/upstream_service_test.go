package service

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// testUpstreamEnv sets up a fresh UpstreamService with in-memory store
// and a temporary state file for each test.
func testUpstreamEnv(t *testing.T) (*UpstreamService, string) {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(statePath, logger)
	memStore := memory.NewUpstreamStore()

	// Initialize the state file with defaults so Save/Load work.
	defaultState := stateStore.DefaultState()
	if err := stateStore.Save(defaultState); err != nil {
		t.Fatalf("save default state: %v", err)
	}

	svc := NewUpstreamService(memStore, stateStore, logger)
	return svc, statePath
}

// validStdioUpstream returns a valid stdio upstream for testing.
func validStdioUpstream() *upstream.Upstream {
	return &upstream.Upstream{
		Name:    "test-mcp-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/npx",
		Args:    []string{"@modelcontextprotocol/server-filesystem", "/tmp"},
		Env:     map[string]string{"NODE_ENV": "production"},
	}
}

// validHTTPUpstream returns a valid HTTP upstream for testing.
func validHTTPUpstream() *upstream.Upstream {
	return &upstream.Upstream{
		Name:    "remote-mcp-server",
		Type:    upstream.UpstreamTypeHTTP,
		Enabled: true,
		URL:     "http://localhost:8080/mcp",
	}
}

// --- Add Tests ---

func TestUpstreamService_Add_ValidStdio(t *testing.T) {
	svc, statePath := testUpstreamEnv(t)
	ctx := context.Background()
	u := validStdioUpstream()

	result, err := svc.Add(ctx, u)
	if err != nil {
		t.Fatalf("Add() unexpected error: %v", err)
	}

	// Must have generated a UUID.
	if result.ID == "" {
		t.Error("Add() did not generate an ID")
	}

	// Must have set timestamps.
	if result.CreatedAt.IsZero() {
		t.Error("Add() did not set CreatedAt")
	}
	if result.UpdatedAt.IsZero() {
		t.Error("Add() did not set UpdatedAt")
	}

	// Must have preserved fields.
	if result.Name != "test-mcp-server" {
		t.Errorf("Add() Name = %q, want %q", result.Name, "test-mcp-server")
	}
	if result.Type != upstream.UpstreamTypeStdio {
		t.Errorf("Add() Type = %q, want %q", result.Type, upstream.UpstreamTypeStdio)
	}
	if result.Command != "/usr/bin/npx" {
		t.Errorf("Add() Command = %q, want %q", result.Command, "/usr/bin/npx")
	}

	// Must be retrievable.
	got, err := svc.Get(ctx, result.ID)
	if err != nil {
		t.Fatalf("Get() after Add() unexpected error: %v", err)
	}
	if got.Name != result.Name {
		t.Errorf("Get() Name = %q, want %q", got.Name, result.Name)
	}

	// Must be persisted to state.json.
	stateStore := state.NewFileStateStore(statePath, slog.Default())
	appState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load state: %v", err)
	}
	if len(appState.Upstreams) != 1 {
		t.Fatalf("Persisted upstreams count = %d, want 1", len(appState.Upstreams))
	}
	if appState.Upstreams[0].Name != "test-mcp-server" {
		t.Errorf("Persisted upstream name = %q, want %q", appState.Upstreams[0].Name, "test-mcp-server")
	}
}

func TestUpstreamService_Add_ValidHTTP(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()
	u := validHTTPUpstream()

	result, err := svc.Add(ctx, u)
	if err != nil {
		t.Fatalf("Add() unexpected error: %v", err)
	}

	if result.ID == "" {
		t.Error("Add() did not generate an ID")
	}
	if result.Type != upstream.UpstreamTypeHTTP {
		t.Errorf("Add() Type = %q, want %q", result.Type, upstream.UpstreamTypeHTTP)
	}
	if result.URL != "http://localhost:8080/mcp" {
		t.Errorf("Add() URL = %q, want %q", result.URL, "http://localhost:8080/mcp")
	}
}

func TestUpstreamService_Add_DuplicateName(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u1 := validStdioUpstream()
	if _, err := svc.Add(ctx, u1); err != nil {
		t.Fatalf("Add() first upstream: %v", err)
	}

	u2 := validStdioUpstream() // same name
	u2.Command = "/usr/bin/other"
	_, err := svc.Add(ctx, u2)
	if err == nil {
		t.Fatal("Add() duplicate name should return error")
	}
	if err != upstream.ErrDuplicateUpstreamName {
		t.Errorf("Add() error = %v, want %v", err, upstream.ErrDuplicateUpstreamName)
	}
}

func TestUpstreamService_Add_EmptyName(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u := validStdioUpstream()
	u.Name = ""

	_, err := svc.Add(ctx, u)
	if err == nil {
		t.Fatal("Add() empty name should return validation error")
	}
}

func TestUpstreamService_Add_NameTooLong(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u := validStdioUpstream()
	// 101 character name
	u.Name = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeefffffffff" +
		"fgggggggggghhhhhhhhhhiiiiiiiiiijjjjjjjjjjk"

	_, err := svc.Add(ctx, u)
	if err == nil {
		t.Fatal("Add() name too long should return validation error")
	}
}

func TestUpstreamService_Add_NameWithSpecialChars(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u := validStdioUpstream()
	u.Name = "test<script>alert(1)</script>"

	_, err := svc.Add(ctx, u)
	if err == nil {
		t.Fatal("Add() name with special chars should return validation error")
	}
}

func TestUpstreamService_Add_ValidNameChars(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	// Allowed: alphanumeric, spaces, hyphens, underscores
	u := validStdioUpstream()
	u.Name = "My MCP Server-v2_test"

	result, err := svc.Add(ctx, u)
	if err != nil {
		t.Fatalf("Add() valid name chars unexpected error: %v", err)
	}
	if result.Name != "My MCP Server-v2_test" {
		t.Errorf("Add() Name = %q, want %q", result.Name, "My MCP Server-v2_test")
	}
}

func TestUpstreamService_Add_StdioWithoutCommand(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u := &upstream.Upstream{
		Name:    "no-command",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
	}

	_, err := svc.Add(ctx, u)
	if err == nil {
		t.Fatal("Add() stdio without command should return validation error")
	}
}

func TestUpstreamService_Add_HTTPWithoutURL(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u := &upstream.Upstream{
		Name:    "no-url",
		Type:    upstream.UpstreamTypeHTTP,
		Enabled: true,
	}

	_, err := svc.Add(ctx, u)
	if err == nil {
		t.Fatal("Add() http without URL should return validation error")
	}
}

func TestUpstreamService_Add_HTTPInvalidURL(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u := &upstream.Upstream{
		Name:    "bad-url",
		Type:    upstream.UpstreamTypeHTTP,
		Enabled: true,
		URL:     "not-a-valid-url",
	}

	_, err := svc.Add(ctx, u)
	if err == nil {
		t.Fatal("Add() http with invalid URL should return validation error")
	}
}

func TestUpstreamService_Add_InvalidType(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u := &upstream.Upstream{
		Name:    "bad-type",
		Type:    upstream.UpstreamType("grpc"),
		Enabled: true,
	}

	_, err := svc.Add(ctx, u)
	if err == nil {
		t.Fatal("Add() invalid type should return validation error")
	}
}

// --- List Tests ---

func TestUpstreamService_List_Empty(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	list, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("List() count = %d, want 0", len(list))
	}
}

func TestUpstreamService_List_Multiple(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u1 := validStdioUpstream()
	u2 := validHTTPUpstream()

	if _, err := svc.Add(ctx, u1); err != nil {
		t.Fatalf("Add() u1: %v", err)
	}
	if _, err := svc.Add(ctx, u2); err != nil {
		t.Fatalf("Add() u2: %v", err)
	}

	list, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List() unexpected error: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("List() count = %d, want 2", len(list))
	}
}

// --- Get Tests ---

func TestUpstreamService_Get_Exists(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u := validStdioUpstream()
	created, err := svc.Add(ctx, u)
	if err != nil {
		t.Fatalf("Add(): %v", err)
	}

	got, err := svc.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get() unexpected error: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("Get() ID = %q, want %q", got.ID, created.ID)
	}
	if got.Name != created.Name {
		t.Errorf("Get() Name = %q, want %q", got.Name, created.Name)
	}
}

func TestUpstreamService_Get_NotFound(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	_, err := svc.Get(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("Get() nonexistent should return error")
	}
	if err != upstream.ErrUpstreamNotFound {
		t.Errorf("Get() error = %v, want %v", err, upstream.ErrUpstreamNotFound)
	}
}

// --- Update Tests ---

func TestUpstreamService_Update_Name(t *testing.T) {
	svc, statePath := testUpstreamEnv(t)
	ctx := context.Background()

	u := validStdioUpstream()
	created, err := svc.Add(ctx, u)
	if err != nil {
		t.Fatalf("Add(): %v", err)
	}

	update := &upstream.Upstream{
		Name:    "renamed-server",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/npx",
		Args:    []string{"@modelcontextprotocol/server-filesystem", "/tmp"},
	}

	result, err := svc.Update(ctx, created.ID, update)
	if err != nil {
		t.Fatalf("Update() unexpected error: %v", err)
	}
	if result.Name != "renamed-server" {
		t.Errorf("Update() Name = %q, want %q", result.Name, "renamed-server")
	}
	if result.UpdatedAt.Equal(created.UpdatedAt) || result.UpdatedAt.Before(created.UpdatedAt) {
		t.Error("Update() should advance UpdatedAt")
	}

	// Verify persistence.
	stateStore := state.NewFileStateStore(statePath, slog.Default())
	appState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load state: %v", err)
	}
	if len(appState.Upstreams) != 1 {
		t.Fatalf("Persisted upstreams count = %d, want 1", len(appState.Upstreams))
	}
	if appState.Upstreams[0].Name != "renamed-server" {
		t.Errorf("Persisted name = %q, want %q", appState.Upstreams[0].Name, "renamed-server")
	}
}

func TestUpstreamService_Update_DuplicateName(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u1 := validStdioUpstream()
	if _, err := svc.Add(ctx, u1); err != nil {
		t.Fatalf("Add() u1: %v", err)
	}

	u2 := validHTTPUpstream()
	created2, err := svc.Add(ctx, u2)
	if err != nil {
		t.Fatalf("Add() u2: %v", err)
	}

	// Try to rename u2 to have u1's name.
	update := &upstream.Upstream{
		Name:    "test-mcp-server", // u1's name
		Type:    upstream.UpstreamTypeHTTP,
		Enabled: true,
		URL:     "http://localhost:8080/mcp",
	}

	_, err = svc.Update(ctx, created2.ID, update)
	if err == nil {
		t.Fatal("Update() duplicate name should return error")
	}
	if err != upstream.ErrDuplicateUpstreamName {
		t.Errorf("Update() error = %v, want %v", err, upstream.ErrDuplicateUpstreamName)
	}
}

func TestUpstreamService_Update_SameNameSameUpstream(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u := validStdioUpstream()
	created, err := svc.Add(ctx, u)
	if err != nil {
		t.Fatalf("Add(): %v", err)
	}

	// Update keeping the same name (should NOT trigger duplicate error).
	update := &upstream.Upstream{
		Name:    "test-mcp-server", // same name
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/other",
	}

	result, err := svc.Update(ctx, created.ID, update)
	if err != nil {
		t.Fatalf("Update() same name unexpected error: %v", err)
	}
	if result.Command != "/usr/bin/other" {
		t.Errorf("Update() Command = %q, want %q", result.Command, "/usr/bin/other")
	}
}

func TestUpstreamService_Update_NotFound(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	update := &upstream.Upstream{
		Name:    "ghost",
		Type:    upstream.UpstreamTypeStdio,
		Enabled: true,
		Command: "/usr/bin/npx",
	}

	_, err := svc.Update(ctx, "nonexistent-id", update)
	if err == nil {
		t.Fatal("Update() nonexistent should return error")
	}
	if err != upstream.ErrUpstreamNotFound {
		t.Errorf("Update() error = %v, want %v", err, upstream.ErrUpstreamNotFound)
	}
}

// --- Delete Tests ---

func TestUpstreamService_Delete_Existing(t *testing.T) {
	svc, statePath := testUpstreamEnv(t)
	ctx := context.Background()

	u := validStdioUpstream()
	created, err := svc.Add(ctx, u)
	if err != nil {
		t.Fatalf("Add(): %v", err)
	}

	if err := svc.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete() unexpected error: %v", err)
	}

	// Must be gone from store.
	_, err = svc.Get(ctx, created.ID)
	if err != upstream.ErrUpstreamNotFound {
		t.Errorf("Get() after Delete() error = %v, want %v", err, upstream.ErrUpstreamNotFound)
	}

	// Must be gone from state.json.
	stateStore := state.NewFileStateStore(statePath, slog.Default())
	appState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load state: %v", err)
	}
	if len(appState.Upstreams) != 0 {
		t.Errorf("Persisted upstreams count = %d, want 0", len(appState.Upstreams))
	}
}

func TestUpstreamService_Delete_NotFound(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	err := svc.Delete(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("Delete() nonexistent should return error")
	}
	if err != upstream.ErrUpstreamNotFound {
		t.Errorf("Delete() error = %v, want %v", err, upstream.ErrUpstreamNotFound)
	}
}

// --- SetEnabled Tests ---

func TestUpstreamService_SetEnabled_Disable(t *testing.T) {
	svc, statePath := testUpstreamEnv(t)
	ctx := context.Background()

	u := validStdioUpstream()
	u.Enabled = true
	created, err := svc.Add(ctx, u)
	if err != nil {
		t.Fatalf("Add(): %v", err)
	}

	result, err := svc.SetEnabled(ctx, created.ID, false)
	if err != nil {
		t.Fatalf("SetEnabled() unexpected error: %v", err)
	}
	if result.Enabled {
		t.Error("SetEnabled(false) Enabled = true, want false")
	}

	// Verify in-memory.
	got, _ := svc.Get(ctx, created.ID)
	if got.Enabled {
		t.Error("Get() after SetEnabled(false) Enabled = true, want false")
	}

	// Verify persistence.
	stateStore := state.NewFileStateStore(statePath, slog.Default())
	appState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load state: %v", err)
	}
	if len(appState.Upstreams) != 1 {
		t.Fatalf("Persisted upstreams count = %d, want 1", len(appState.Upstreams))
	}
	if appState.Upstreams[0].Enabled {
		t.Error("Persisted Enabled = true, want false")
	}
}

func TestUpstreamService_SetEnabled_Enable(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	u := validStdioUpstream()
	u.Enabled = true
	created, err := svc.Add(ctx, u)
	if err != nil {
		t.Fatalf("Add(): %v", err)
	}

	// Disable then re-enable.
	if _, err := svc.SetEnabled(ctx, created.ID, false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}

	result, err := svc.SetEnabled(ctx, created.ID, true)
	if err != nil {
		t.Fatalf("SetEnabled(true) unexpected error: %v", err)
	}
	if !result.Enabled {
		t.Error("SetEnabled(true) Enabled = false, want true")
	}
}

func TestUpstreamService_SetEnabled_NotFound(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	_, err := svc.SetEnabled(ctx, "nonexistent-id", false)
	if err == nil {
		t.Fatal("SetEnabled() nonexistent should return error")
	}
	if err != upstream.ErrUpstreamNotFound {
		t.Errorf("SetEnabled() error = %v, want %v", err, upstream.ErrUpstreamNotFound)
	}
}

// --- LoadFromState Tests ---

func TestUpstreamService_LoadFromState(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	appState := &state.AppState{
		Version:       "1",
		DefaultPolicy: "deny",
		Upstreams: []state.UpstreamEntry{
			{
				ID:      "upstream-1",
				Name:    "MCP Filesystem",
				Type:    "stdio",
				Enabled: true,
				Command: "/usr/bin/npx",
				Args:    []string{"@modelcontextprotocol/server-filesystem", "/tmp"},
				Env:     map[string]string{"DEBUG": "1"},
			},
			{
				ID:      "upstream-2",
				Name:    "MCP Remote",
				Type:    "http",
				Enabled: false,
				URL:     "http://localhost:9090/mcp",
			},
		},
	}

	if err := svc.LoadFromState(context.Background(), appState); err != nil {
		t.Fatalf("LoadFromState() unexpected error: %v", err)
	}

	// Verify all upstreams loaded.
	list, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List() after LoadFromState: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List() count = %d, want 2", len(list))
	}

	// Verify first upstream.
	u1, err := svc.Get(ctx, "upstream-1")
	if err != nil {
		t.Fatalf("Get() upstream-1: %v", err)
	}
	if u1.Name != "MCP Filesystem" {
		t.Errorf("upstream-1 Name = %q, want %q", u1.Name, "MCP Filesystem")
	}
	if u1.Type != upstream.UpstreamTypeStdio {
		t.Errorf("upstream-1 Type = %q, want %q", u1.Type, upstream.UpstreamTypeStdio)
	}
	if u1.Command != "/usr/bin/npx" {
		t.Errorf("upstream-1 Command = %q, want %q", u1.Command, "/usr/bin/npx")
	}
	if len(u1.Args) != 2 {
		t.Errorf("upstream-1 Args count = %d, want 2", len(u1.Args))
	}
	if u1.Env["DEBUG"] != "1" {
		t.Errorf("upstream-1 Env[DEBUG] = %q, want %q", u1.Env["DEBUG"], "1")
	}

	// Verify second upstream.
	u2, err := svc.Get(ctx, "upstream-2")
	if err != nil {
		t.Fatalf("Get() upstream-2: %v", err)
	}
	if u2.Name != "MCP Remote" {
		t.Errorf("upstream-2 Name = %q, want %q", u2.Name, "MCP Remote")
	}
	if u2.Type != upstream.UpstreamTypeHTTP {
		t.Errorf("upstream-2 Type = %q, want %q", u2.Type, upstream.UpstreamTypeHTTP)
	}
	if u2.Enabled {
		t.Error("upstream-2 Enabled = true, want false")
	}
	if u2.URL != "http://localhost:9090/mcp" {
		t.Errorf("upstream-2 URL = %q, want %q", u2.URL, "http://localhost:9090/mcp")
	}
}

func TestUpstreamService_LoadFromState_EmptyUpstreams(t *testing.T) {
	svc, _ := testUpstreamEnv(t)
	ctx := context.Background()

	appState := &state.AppState{
		Version:       "1",
		DefaultPolicy: "deny",
		Upstreams:     []state.UpstreamEntry{},
	}

	if err := svc.LoadFromState(context.Background(), appState); err != nil {
		t.Fatalf("LoadFromState() unexpected error: %v", err)
	}

	list, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List(): %v", err)
	}
	if len(list) != 0 {
		t.Errorf("List() count = %d, want 0", len(list))
	}
}

// --- Validation Edge Cases ---

func TestUpstream_Validate_ValidStdio(t *testing.T) {
	u := validStdioUpstream()
	if err := u.Validate(); err != nil {
		t.Errorf("Validate() valid stdio: %v", err)
	}
}

func TestUpstream_Validate_ValidHTTP(t *testing.T) {
	u := validHTTPUpstream()
	if err := u.Validate(); err != nil {
		t.Errorf("Validate() valid http: %v", err)
	}
}

func TestUpstream_Validate_EmptyName(t *testing.T) {
	u := validStdioUpstream()
	u.Name = ""
	if err := u.Validate(); err == nil {
		t.Error("Validate() empty name should fail")
	}
}

func TestUpstream_Validate_InvalidType(t *testing.T) {
	u := &upstream.Upstream{
		Name: "test",
		Type: upstream.UpstreamType("websocket"),
	}
	if err := u.Validate(); err == nil {
		t.Error("Validate() invalid type should fail")
	}
}

func TestUpstream_Validate_StdioNoCommand(t *testing.T) {
	u := &upstream.Upstream{
		Name: "test",
		Type: upstream.UpstreamTypeStdio,
	}
	if err := u.Validate(); err == nil {
		t.Error("Validate() stdio without command should fail")
	}
}

func TestUpstream_Validate_HTTPNoURL(t *testing.T) {
	u := &upstream.Upstream{
		Name: "test",
		Type: upstream.UpstreamTypeHTTP,
	}
	if err := u.Validate(); err == nil {
		t.Error("Validate() http without URL should fail")
	}
}

func TestUpstream_Validate_HTTPInvalidURL(t *testing.T) {
	u := &upstream.Upstream{
		Name: "test",
		Type: upstream.UpstreamTypeHTTP,
		URL:  "://missing-scheme",
	}
	if err := u.Validate(); err == nil {
		t.Error("Validate() http with invalid URL should fail")
	}
}

func TestUpstream_Validate_NameSpecialChars(t *testing.T) {
	u := validStdioUpstream()
	u.Name = "test@server!#$"
	if err := u.Validate(); err == nil {
		t.Error("Validate() name with special chars should fail")
	}
}

func TestUpstream_Validate_NameMaxLength(t *testing.T) {
	u := validStdioUpstream()
	u.Name = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeefffffffff" +
		"fgggggggggghhhhhhhhhhiiiiiiiiiijjjjjjjjjjk" // 101 chars
	if err := u.Validate(); err == nil {
		t.Error("Validate() name >100 chars should fail")
	}
}
