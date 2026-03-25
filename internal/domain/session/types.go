// Package session manages user sessions across MCP tool calls.
package session

import (
	"strings"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
)

// CallType classifies a tool call into a category.
type CallType string

const (
	CallTypeRead   CallType = "read"
	CallTypeWrite  CallType = "write"
	CallTypeDelete CallType = "delete"
	CallTypeOther  CallType = "other"
)

// ToolCallClassifier maps a tool name to its CallType.
type ToolCallClassifier func(toolName string) CallType

// MaxActionHistory is the maximum number of action records per session before FIFO eviction.
const MaxActionHistory = 1000

// ActionRecord captures a single tool call for session history analysis.
type ActionRecord struct {
	ToolName  string
	CallType  CallType
	Timestamp time.Time
	ArgKeys   []string // sorted argument key names (not values, for privacy)
}

// ActionHistory is an ordered list of action records in a session.
type ActionHistory []ActionRecord

// SessionUsage holds per-session call usage counters.
type SessionUsage struct {
	TotalCalls      int64
	ReadCalls       int64
	WriteCalls      int64
	DeleteCalls     int64
	CumulativeCost  float64 // running cost total for the session
	CallsByToolName map[string]int64
	WindowCalls     int64     // calls in current sliding window
	StartedAt       time.Time
	LastCallAt      time.Time
}

// ActiveSessionInfo provides a snapshot of a tracked session.
type ActiveSessionInfo struct {
	SessionID    string
	IdentityID   string
	IdentityName string
	Usage        SessionUsage
}

// DefaultClassifier returns a ToolCallClassifier using naming conventions.
func DefaultClassifier() ToolCallClassifier {
	writeSuffixes := []string{"_write", "_create", "_insert", "_update", "_put", "_set", "_save", "_append", "_edit"}
	writePrefixes := []string{"write_", "create_", "edit_"}
	deleteSuffixes := []string{"_delete", "_remove", "_drop"}
	deletePrefixes := []string{"delete_", "remove_"}
	readSuffixes := []string{"_read", "_get", "_list", "_search", "_find", "_query"}
	readPrefixes := []string{"read_", "get_", "list_", "search_"}

	return func(toolName string) CallType {
		// Strip namespace prefix (e.g. "desktop/read_file" → "read_file")
		// so classification works correctly for namespaced tool names.
		if idx := strings.Index(toolName, "/"); idx >= 0 {
			toolName = toolName[idx+1:]
		}
		lower := strings.ToLower(toolName)

		for _, s := range writeSuffixes {
			if strings.HasSuffix(lower, s) {
				return CallTypeWrite
			}
		}
		for _, p := range writePrefixes {
			if strings.HasPrefix(lower, p) {
				return CallTypeWrite
			}
		}

		for _, s := range deleteSuffixes {
			if strings.HasSuffix(lower, s) {
				return CallTypeDelete
			}
		}
		for _, p := range deletePrefixes {
			if strings.HasPrefix(lower, p) {
				return CallTypeDelete
			}
		}

		for _, s := range readSuffixes {
			if strings.HasSuffix(lower, s) {
				return CallTypeRead
			}
		}
		for _, p := range readPrefixes {
			if strings.HasPrefix(lower, p) {
				return CallTypeRead
			}
		}

		return CallTypeOther
	}
}

// Session tracks an authenticated user's context across tool calls.
type Session struct {
	// ID is a cryptographically random identifier, 32 bytes hex-encoded.
	ID string
	// IdentityID references the auth.Identity this session belongs to.
	IdentityID string
	// IdentityName is the human-readable name of the identity.
	IdentityName string
	// Roles are cached from the Identity for fast RBAC lookup.
	Roles []auth.Role
	// CreatedAt is when the session was created (UTC).
	CreatedAt time.Time
	// ExpiresAt is when the session will expire (UTC).
	ExpiresAt time.Time
	// LastAccess is the last time the session was used (UTC).
	LastAccess time.Time
}

// IsExpired checks if the session has exceeded its timeout.
func (s *Session) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}

// Refresh updates LastAccess and extends ExpiresAt by the given duration.
func (s *Session) Refresh(timeout time.Duration) {
	now := time.Now().UTC()
	s.LastAccess = now
	s.ExpiresAt = now.Add(timeout)
}
