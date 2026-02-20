// Package tool contains domain types for tool discovery and risk classification.
package tool

import (
	"encoding/json"
	"time"
)

// RiskLevel represents the security risk level of a tool.
type RiskLevel string

const (
	// RiskLevelLow indicates read-only, informational operations.
	// Examples: list_files, get_status, help, version.
	RiskLevelLow RiskLevel = "LOW"

	// RiskLevelMedium indicates read operations with potential sensitivity.
	// Examples: fetch_data, download_file, export_report, search_users.
	RiskLevelMedium RiskLevel = "MEDIUM"

	// RiskLevelHigh indicates write operations or network access.
	// Examples: file_write, create_user, update_config, send_email.
	RiskLevelHigh RiskLevel = "HIGH"

	// RiskLevelCritical indicates destructive operations, system commands, or admin ops.
	// Examples: file_delete, execute_command, shell_exec, admin_reset.
	RiskLevelCritical RiskLevel = "CRITICAL"
)

// IsValid returns true if the risk level is a known valid level.
func (r RiskLevel) IsValid() bool {
	switch r {
	case RiskLevelLow, RiskLevelMedium, RiskLevelHigh, RiskLevelCritical:
		return true
	default:
		return false
	}
}

// Tool represents a tool from the MCP tools/list response.
// Fields match the MCP specification 2025-06-18.
type Tool struct {
	// Name is the unique identifier for this tool (required).
	Name string `json:"name"`

	// Title is an optional human-readable display name.
	Title *string `json:"title,omitempty"`

	// Description is an optional human-readable description.
	Description *string `json:"description,omitempty"`

	// InputSchema is the JSON Schema for the tool's parameters (required).
	InputSchema json.RawMessage `json:"inputSchema"`

	// OutputSchema is an optional JSON Schema for the tool's output.
	OutputSchema *json.RawMessage `json:"outputSchema,omitempty"`

	// RiskLevel is the computed security risk level (not from MCP, added by classifier).
	RiskLevel RiskLevel `json:"-"`
}

// ToolCatalog represents a cached collection of tools from an upstream MCP server.
type ToolCatalog struct {
	// Tools is the list of tools available from the server.
	Tools []Tool `json:"tools"`

	// NextCursor is the pagination cursor for fetching more tools.
	NextCursor *string `json:"nextCursor,omitempty"`

	// CachedAt is when this catalog was cached (UTC).
	CachedAt time.Time `json:"cachedAt"`

	// ServerID identifies which upstream server this catalog is from.
	ServerID string `json:"serverId"`
}
