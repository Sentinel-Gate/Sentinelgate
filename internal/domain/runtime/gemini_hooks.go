package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// GeminiHookConfig holds the configuration for setting up Gemini CLI hooks.
type GeminiHookConfig struct {
	// ServerAddr is the SentinelGate server address (e.g., "http://localhost:8080").
	ServerAddr string

	// APIKey is the runtime API key for authenticating MCP requests.
	APIKey string
}

// GeminiHookSetup holds the state needed to clean up Gemini CLI hooks on exit.
type GeminiHookSetup struct {
	// SettingsPath is the absolute path to ~/.gemini/settings.json.
	SettingsPath string
	// RefcountPath is the path to the refcount file (.sentinelgate-hook-refcount).
	RefcountPath string
	// BackupPath is the path to the backup file (.sentinelgate-settings-backup).
	BackupPath string
}

// geminiNativeToolsToExclude lists Gemini CLI built-in tools that we can safely
// exclude without breaking MCP tool access. These are native tools whose names
// do NOT collide with standard MCP server tools (e.g., @modelcontextprotocol/server-filesystem).

var geminiNativeToolsToExclude = []string{
	"edit",
	"replace",
	"run_shell_command",
	"grep_search",
	"glob",
}

var geminiNativeToolsWithMCPConflict = []string{
	"read_file",
	"write_file",
	"list_directory",
}

// IsGeminiCLI checks if the given command is the Gemini CLI binary.
// It checks the command name (with or without path) for "gemini".
func IsGeminiCLI(command string) bool {
	base := strings.ToLower(filepath.Base(command))
	// Handle "gemini", "gemini.exe", "gemini.cmd", etc.
	name := strings.TrimSuffix(base, filepath.Ext(base))
	if name == "gemini" {
		return true
	}

	// Also check if the resolved path contains "gemini-cli".
	resolved, err := exec.LookPath(command)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(resolved), "gemini")
}

// SetupGeminiHooks configures Gemini CLI to route file operations through
// SentinelGate by modifying ~/.gemini/settings.json. Uses reference counting
// to safely support multiple concurrent sentinel-gate run instances.
//
// First instance: saves original settings as backup, writes MCP config + tool exclusions.
// Subsequent instances: increments refcount only (config already in place).
func SetupGeminiHooks(cfg GeminiHookConfig) (*GeminiHookSetup, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home dir: %w", err)
	}

	geminiDir := filepath.Join(homeDir, ".gemini")
	settingsPath := filepath.Join(geminiDir, "settings.json")
	refcountPath := filepath.Join(geminiDir, ".sentinelgate-hook-refcount")
	backupPath := filepath.Join(geminiDir, ".sentinelgate-settings-backup")

	setup := &GeminiHookSetup{
		SettingsPath: settingsPath,
		RefcountPath: refcountPath,
		BackupPath:   backupPath,
	}

	// Ensure ~/.gemini/ directory exists.
	if err := os.MkdirAll(geminiDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create .gemini dir: %w", err)
	}

	count := readRefcount(refcountPath)

	if count == 0 {
		// First instance: save original settings as backup and write config.
		if existingData, readErr := os.ReadFile(settingsPath); readErr == nil {
			if writeErr := os.WriteFile(backupPath, existingData, 0644); writeErr != nil {
				return nil, fmt.Errorf("failed to save settings backup: %w", writeErr)
			}
		}

		if err := writeGeminiConfig(settingsPath, cfg); err != nil {
			return nil, err
		}
	}

	if err := writeRefcount(refcountPath, count+1); err != nil {
		return nil, fmt.Errorf("failed to write refcount: %w", err)
	}

	return setup, nil
}

// writeGeminiConfig reads the current settings.json (if any), adds SentinelGate
// as MCP server and excludes native tools, then writes the file back.
func writeGeminiConfig(settingsPath string, cfg GeminiHookConfig) error {
	// Parse existing settings or create empty map.
	var settings map[string]interface{}
	if existingData, err := os.ReadFile(settingsPath); err == nil {
		if jsonErr := json.Unmarshal(existingData, &settings); jsonErr != nil {
			settings = make(map[string]interface{})
		}
	} else {
		settings = make(map[string]interface{})
	}

	// Add SentinelGate as MCP server.
	mcpServers, ok := settings["mcpServers"].(map[string]interface{})
	if !ok {
		mcpServers = make(map[string]interface{})
	}
	serverCfg := map[string]interface{}{
		"httpUrl": cfg.ServerAddr + "/mcp",
	}
	if cfg.APIKey != "" {
		serverCfg["headers"] = map[string]interface{}{
			"Authorization": "Bearer " + cfg.APIKey,
		}
	}
	mcpServers["sentinelgate"] = serverCfg
	settings["mcpServers"] = mcpServers

	// Exclude native filesystem tools.
	tools, ok := settings["tools"].(map[string]interface{})
	if !ok {
		tools = make(map[string]interface{})
	}

	// Merge our exclusions with any existing ones.
	existingExclude, _ := tools["exclude"].([]interface{})
	excludeSet := make(map[string]bool)
	for _, e := range existingExclude {
		if s, ok := e.(string); ok {
			excludeSet[s] = true
		}
	}
	for _, tool := range geminiNativeToolsToExclude {
		excludeSet[tool] = true
	}
	excludeList := make([]string, 0, len(excludeSet))
	for tool := range excludeSet {
		excludeList = append(excludeList, tool)
	}
	tools["exclude"] = excludeList
	settings["tools"] = tools

	// Write updated settings.
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(settingsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write settings.json: %w", err)
	}

	return nil
}

// CleanupGeminiHooks decrements the reference count and restores the original
// settings.json only when the last instance exits.
func CleanupGeminiHooks(setup *GeminiHookSetup) error {
	if setup == nil {
		return nil
	}

	count := readRefcount(setup.RefcountPath)
	count--

	if count <= 0 {
		// Last instance: restore original settings from backup.
		if backupData, err := os.ReadFile(setup.BackupPath); err == nil {
			if writeErr := os.WriteFile(setup.SettingsPath, backupData, 0644); writeErr != nil {
				return fmt.Errorf("failed to restore settings backup: %w", writeErr)
			}
		} else {
			// No backup means settings.json didn't exist before — remove it.
			os.Remove(setup.SettingsPath)
		}
		// Clean up refcount and backup files.
		os.Remove(setup.RefcountPath)
		os.Remove(setup.BackupPath)
	} else {
		// Other instances still running, just decrement the count.
		if err := writeRefcount(setup.RefcountPath, count); err != nil {
			return fmt.Errorf("failed to update refcount: %w", err)
		}
	}

	return nil
}
