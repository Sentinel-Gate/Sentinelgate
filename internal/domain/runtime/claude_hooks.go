package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ClaudeHookConfig holds the configuration for setting up Claude Code hooks.
type ClaudeHookConfig struct {
	// SentinelGateExe is the absolute path to the sentinel-gate binary.
	SentinelGateExe string
}

// ClaudeHookSetup holds the state needed to clean up Claude Code hooks on exit.
type ClaudeHookSetup struct {
	// SettingsPath is the absolute path to ~/.claude/settings.json.
	SettingsPath string
	// RefcountPath is the path to the refcount file (.sentinelgate-hook-refcount).
	RefcountPath string
	// BackupPath is the path to the backup file (.sentinelgate-settings-backup).
	BackupPath string
}

// SetupClaudeHooks configures Claude Code PreToolUse hooks by writing to
// ~/.claude/settings.json (user-level settings). Uses reference counting
// to safely support multiple concurrent sentinel-gate run instances.
//
// First instance: saves original settings as backup, writes hook.
// Subsequent instances: increments refcount only (hook already in place).
func SetupClaudeHooks(cfg ClaudeHookConfig) (*ClaudeHookSetup, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home dir: %w", err)
	}

	claudeDir := filepath.Join(homeDir, ".claude")
	settingsPath := filepath.Join(claudeDir, "settings.json")
	refcountPath := filepath.Join(claudeDir, ".sentinelgate-hook-refcount")
	backupPath := filepath.Join(claudeDir, ".sentinelgate-settings-backup")

	setup := &ClaudeHookSetup{
		SettingsPath: settingsPath,
		RefcountPath: refcountPath,
		BackupPath:   backupPath,
	}

	// Ensure ~/.claude/ directory exists.
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create .claude dir: %w", err)
	}

	count := readRefcount(refcountPath)

	if count == 0 {
		// First instance: save original settings as backup and write hook.
		if existingData, readErr := os.ReadFile(settingsPath); readErr == nil {
			if writeErr := os.WriteFile(backupPath, existingData, 0644); writeErr != nil {
				return nil, fmt.Errorf("failed to save settings backup: %w", writeErr)
			}
		}
		// else: settings.json doesn't exist yet, no backup needed.

		if err := writeClaudeHook(settingsPath, cfg); err != nil {
			return nil, err
		}
	}
	// else: hook already in place from another instance, just bump the count.

	if err := writeRefcount(refcountPath, count+1); err != nil {
		return nil, fmt.Errorf("failed to write refcount: %w", err)
	}

	return setup, nil
}

// writeClaudeHook reads the current settings.json (if any), prepends our
// PreToolUse hook entry, and writes the file back.
func writeClaudeHook(settingsPath string, cfg ClaudeHookConfig) error {
	// Parse existing settings or create empty map.
	var settings map[string]interface{}
	if existingData, err := os.ReadFile(settingsPath); err == nil {
		if jsonErr := json.Unmarshal(existingData, &settings); jsonErr != nil {
			settings = make(map[string]interface{})
		}
	} else {
		settings = make(map[string]interface{})
	}

	// Build our PreToolUse hook entry.
	hookEntry := map[string]interface{}{
		"matcher": "Read|Write|Edit|Bash|Glob|Grep|WebFetch|WebSearch|NotebookEdit",
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": cfg.SentinelGateExe + " claude-hook",
				"timeout": 10,
			},
		},
	}

	// Merge into existing hooks structure.
	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		hooks = make(map[string]interface{})
	}

	existingPTU, _ := hooks["PreToolUse"].([]interface{})
	hooks["PreToolUse"] = append([]interface{}{hookEntry}, existingPTU...)
	settings["hooks"] = hooks

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

// CleanupClaudeHooks decrements the reference count and restores the original
// settings.json only when the last instance exits.
func CleanupClaudeHooks(setup *ClaudeHookSetup) error {
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
