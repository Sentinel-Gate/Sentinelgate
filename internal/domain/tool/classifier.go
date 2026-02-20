package tool

import (
	"strings"
)

// criticalPatterns contains patterns indicating destructive operations or system commands.
// Tools matching these patterns require admin access.
var criticalPatterns = []string{
	"delete", "remove", "drop", "destroy", "execute", "exec",
	"shell", "command", "admin", "sudo", "root", "truncate",
}

// highPatterns contains patterns indicating write operations or network access.
// Tools matching these patterns require elevated access.
var highPatterns = []string{
	"write", "create", "update", "modify", "send", "post",
	"upload", "deploy", "install", "connect", "put",
}

// mediumPatterns contains patterns indicating read operations with potential sensitivity.
// Tools matching these patterns require standard user access.
var mediumPatterns = []string{
	"fetch", "download", "export", "query", "search", "get",
}

// ClassifyTool determines the risk level of a tool based on its name.
// Classification is case-insensitive and uses pattern matching.
//
// Priority order (highest to lowest):
//   - CRITICAL: destructive operations (delete, exec, shell, admin)
//   - HIGH: write operations (write, create, update, send)
//   - MEDIUM: sensitive reads (fetch, download, export, search)
//   - LOW: everything else (list, help, version)
//
// Limitations:
//   - Uses simple substring matching (e.g., "undelete" also matches "delete")
//   - For v1, this is acceptable; admin overrides can address edge cases
//   - Tool descriptions are not analyzed, only names
func ClassifyTool(tool Tool) RiskLevel {
	name := strings.ToLower(tool.Name)

	// Check CRITICAL patterns first (highest priority)
	for _, pattern := range criticalPatterns {
		if strings.Contains(name, pattern) {
			return RiskLevelCritical
		}
	}

	// Check HIGH patterns
	for _, pattern := range highPatterns {
		if strings.Contains(name, pattern) {
			return RiskLevelHigh
		}
	}

	// Check MEDIUM patterns
	for _, pattern := range mediumPatterns {
		if strings.Contains(name, pattern) {
			return RiskLevelMedium
		}
	}

	// Default to LOW (safe, informational)
	return RiskLevelLow
}

// ClassifyTools returns a new slice of tools with RiskLevel populated on each.
// The input slice is not modified.
func ClassifyTools(tools []Tool) []Tool {
	result := make([]Tool, len(tools))
	for i, tool := range tools {
		result[i] = tool
		result[i].RiskLevel = ClassifyTool(tool)
	}
	return result
}
