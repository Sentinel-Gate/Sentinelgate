package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestIsGeminiCLI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"bare gemini", "gemini", true},
		{"gemini with path", "/usr/local/bin/gemini", true},
		{"gemini uppercase", "Gemini", true},
		{"not gemini", "claude", false},
		{"not gemini python", "python", false},
		{"empty", "", false},
		{"node", "node", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsGeminiCLI(tt.command)
			if got != tt.want {
				t.Errorf("IsGeminiCLI(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestSetupGeminiHooks_NewFile(t *testing.T) {
	// Not parallel: uses t.Setenv.

	// Use a temp dir as fake home.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	cfg := GeminiHookConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "test-key-123",
	}

	setup, err := SetupGeminiHooks(cfg)
	if err != nil {
		t.Fatalf("SetupGeminiHooks() error: %v", err)
	}

	// Verify file was created.
	expectedPath := filepath.Join(tmpHome, ".gemini", "settings.json")
	if setup.SettingsPath != expectedPath {
		t.Errorf("SettingsPath = %q, want %q", setup.SettingsPath, expectedPath)
	}
	// Verify refcount file was created with count=1.
	if count := readRefcount(setup.RefcountPath); count != 1 {
		t.Errorf("refcount = %d, want 1", count)
	}

	// Read and parse the created file.
	data, err := os.ReadFile(setup.SettingsPath)
	if err != nil {
		t.Fatalf("failed to read settings: %v", err)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatalf("failed to parse settings: %v", err)
	}

	// Verify MCP server was added.
	mcpServers, ok := settings["mcpServers"].(map[string]interface{})
	if !ok {
		t.Fatal("mcpServers not found in settings")
	}
	sg, ok := mcpServers["sentinelgate"].(map[string]interface{})
	if !ok {
		t.Fatal("sentinelgate server not found in mcpServers")
	}
	httpURL, ok := sg["httpUrl"].(string)
	if !ok || httpURL != "http://localhost:8080/mcp" {
		t.Errorf("httpUrl = %q, want %q", httpURL, "http://localhost:8080/mcp")
	}

	// Verify Authorization header was set.
	headers, ok := sg["headers"].(map[string]interface{})
	if !ok {
		t.Fatal("headers not found in sentinelgate MCP server config")
	}
	authHeader, ok := headers["Authorization"].(string)
	if !ok || authHeader != "Bearer test-key-123" {
		t.Errorf("Authorization = %q, want %q", authHeader, "Bearer test-key-123")
	}

	// Verify tools.exclude was set.
	tools, ok := settings["tools"].(map[string]interface{})
	if !ok {
		t.Fatal("tools not found in settings")
	}
	excludeRaw, ok := tools["exclude"].([]interface{})
	if !ok {
		t.Fatal("tools.exclude not found")
	}

	excludeSet := make(map[string]bool)
	for _, e := range excludeRaw {
		excludeSet[e.(string)] = true
	}
	for _, expected := range geminiNativeToolsToExclude {
		if !excludeSet[expected] {
			t.Errorf("tools.exclude missing %q", expected)
		}
	}
}

func TestSetupGeminiHooks_PreservesExisting(t *testing.T) {
	// Not parallel: uses t.Setenv.

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Create existing settings with user config.
	geminiDir := filepath.Join(tmpHome, ".gemini")
	if err := os.MkdirAll(geminiDir, 0755); err != nil {
		t.Fatal(err)
	}
	existing := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"my-server": map[string]interface{}{
				"command": "my-mcp-server",
			},
		},
		"tools": map[string]interface{}{
			"allowed": []string{"run_shell_command(git)"},
		},
		"theme": "dark",
	}
	existingData, _ := json.MarshalIndent(existing, "", "  ")
	settingsPath := filepath.Join(geminiDir, "settings.json")
	if err := os.WriteFile(settingsPath, existingData, 0644); err != nil {
		t.Fatal(err)
	}

	cfg := GeminiHookConfig{
		ServerAddr: "http://localhost:9090",
	}

	setup, err := SetupGeminiHooks(cfg)
	if err != nil {
		t.Fatalf("SetupGeminiHooks() error: %v", err)
	}

	// Verify backup was created.
	if _, err := os.Stat(setup.BackupPath); err != nil {
		t.Error("backup file should exist when original settings existed")
	}

	// Parse modified settings.
	data, _ := os.ReadFile(setup.SettingsPath)
	var settings map[string]interface{}
	json.Unmarshal(data, &settings)

	// Verify existing MCP server preserved.
	mcpServers := settings["mcpServers"].(map[string]interface{})
	if _, ok := mcpServers["my-server"]; !ok {
		t.Error("existing MCP server 'my-server' was removed")
	}
	if _, ok := mcpServers["sentinelgate"]; !ok {
		t.Error("sentinelgate MCP server was not added")
	}

	// Verify existing settings preserved.
	if settings["theme"] != "dark" {
		t.Error("existing 'theme' setting was removed")
	}

	// Verify tools.allowed preserved.
	tools := settings["tools"].(map[string]interface{})
	if _, ok := tools["allowed"]; !ok {
		t.Error("existing tools.allowed was removed")
	}
}

func TestCleanupGeminiHooks_RestoresOriginal(t *testing.T) {
	// Not parallel: uses t.Setenv.

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Create original file.
	geminiDir := filepath.Join(tmpHome, ".gemini")
	os.MkdirAll(geminiDir, 0755)
	original := []byte(`{"theme": "light"}`)
	settingsPath := filepath.Join(geminiDir, "settings.json")
	os.WriteFile(settingsPath, original, 0644)

	// Setup hooks (modifies file).
	setup, err := SetupGeminiHooks(GeminiHookConfig{ServerAddr: "http://localhost:8080"})
	if err != nil {
		t.Fatal(err)
	}

	// Cleanup should restore original.
	if err := CleanupGeminiHooks(setup); err != nil {
		t.Fatalf("CleanupGeminiHooks() error: %v", err)
	}

	restored, _ := os.ReadFile(settingsPath)
	if string(restored) != string(original) {
		t.Errorf("restored content = %q, want %q", string(restored), string(original))
	}
}

func TestCleanupGeminiHooks_RemovesNewFile(t *testing.T) {
	// Not parallel: uses t.Setenv.

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Setup hooks (creates new file).
	setup, err := SetupGeminiHooks(GeminiHookConfig{ServerAddr: "http://localhost:8080"})
	if err != nil {
		t.Fatal(err)
	}

	// File should exist after setup.
	if _, err := os.Stat(setup.SettingsPath); err != nil {
		t.Fatal("settings file should exist after setup")
	}

	// Cleanup should remove file.
	if err := CleanupGeminiHooks(setup); err != nil {
		t.Fatalf("CleanupGeminiHooks() error: %v", err)
	}

	if _, err := os.Stat(setup.SettingsPath); !os.IsNotExist(err) {
		t.Error("settings file should be removed after cleanup")
	}
}

func TestGeminiExcludeDoesNotBlockMCPTools(t *testing.T) {
	t.Parallel()

	// Verify that tools with MCP name collisions are NOT in the exclude list.
	excludeSet := make(map[string]bool)
	for _, tool := range geminiNativeToolsToExclude {
		excludeSet[tool] = true
	}

	for _, tool := range geminiNativeToolsWithMCPConflict {
		if excludeSet[tool] {
			t.Errorf("geminiNativeToolsToExclude should NOT contain %q (MCP name collision)", tool)
		}
	}

	// Verify the conflict list has the expected tools.
	conflictSet := make(map[string]bool)
	for _, tool := range geminiNativeToolsWithMCPConflict {
		conflictSet[tool] = true
	}
	for _, expected := range []string{"read_file", "write_file", "list_directory"} {
		if !conflictSet[expected] {
			t.Errorf("geminiNativeToolsWithMCPConflict should contain %q", expected)
		}
	}
}

func TestCleanupGeminiHooks_Nil(t *testing.T) {
	t.Parallel()

	if err := CleanupGeminiHooks(nil); err != nil {
		t.Errorf("CleanupGeminiHooks(nil) should not error, got: %v", err)
	}
}
