// Package upstream contains domain types for MCP upstream server configuration.
package upstream

import (
	"fmt"
	"net/url"
	"regexp"
	"time"
)

// UpstreamType identifies the transport protocol for an upstream server.
type UpstreamType string

const (
	// UpstreamTypeStdio represents an upstream that communicates via stdin/stdout.
	UpstreamTypeStdio UpstreamType = "stdio"
	// UpstreamTypeHTTP represents an upstream that communicates via HTTP/SSE.
	UpstreamTypeHTTP UpstreamType = "http"
)

// ConnectionStatus represents the runtime connection state of an upstream.
type ConnectionStatus string

const (
	// StatusConnected indicates the upstream is connected and operational.
	StatusConnected ConnectionStatus = "connected"
	// StatusDisconnected indicates the upstream is not connected.
	StatusDisconnected ConnectionStatus = "disconnected"
	// StatusConnecting indicates a connection attempt is in progress.
	StatusConnecting ConnectionStatus = "connecting"
	// StatusError indicates the upstream encountered a connection error.
	StatusError ConnectionStatus = "error"
)

// namePattern allows alphanumeric, spaces, hyphens, and underscores.
var namePattern = regexp.MustCompile(`^[a-zA-Z0-9 _-]+$`)

// nameMaxLength is the maximum allowed length for an upstream name.
const nameMaxLength = 100

// Upstream represents a configured MCP upstream server.
type Upstream struct {
	// ID is the unique identifier (UUID).
	ID string
	// Name is the human-readable display name (unique).
	Name string
	// Type is the transport type: stdio or http.
	Type UpstreamType
	// Enabled indicates whether this upstream is active.
	Enabled bool
	// Command is the executable path (stdio only).
	Command string
	// Args are the command-line arguments (stdio only).
	Args []string
	// URL is the endpoint (HTTP only).
	URL string
	// Env holds environment variables passed to stdio upstreams.
	Env map[string]string

	// Status is the runtime connection state (not persisted).
	Status ConnectionStatus
	// LastError is the most recent error message (not persisted).
	LastError string
	// ToolCount is the number of tools discovered (not persisted).
	ToolCount int

	// CreatedAt is when this upstream was added.
	CreatedAt time.Time
	// UpdatedAt is when this upstream was last modified.
	UpdatedAt time.Time
}

// Validate checks that the upstream has valid configuration.
// Returns nil if valid, or an error describing the first validation failure.
func (u *Upstream) Validate() error {
	// Name is required.
	if u.Name == "" {
		return fmt.Errorf("name is required")
	}

	// Name length check.
	if len(u.Name) > nameMaxLength {
		return fmt.Errorf("name must be %d characters or less", nameMaxLength)
	}

	// Name character check: alphanumeric, spaces, hyphens, underscores only.
	if !namePattern.MatchString(u.Name) {
		return fmt.Errorf("name contains invalid characters (allowed: alphanumeric, spaces, hyphens, underscores)")
	}

	// Type must be stdio or http.
	switch u.Type {
	case UpstreamTypeStdio:
		if u.Command == "" {
			return fmt.Errorf("command is required for stdio upstream")
		}
	case UpstreamTypeHTTP:
		if u.URL == "" {
			return fmt.Errorf("url is required for http upstream")
		}
		parsed, err := url.Parse(u.URL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("url is not a valid URL")
		}
	default:
		return fmt.Errorf("type must be %q or %q", UpstreamTypeStdio, UpstreamTypeHTTP)
	}

	return nil
}
