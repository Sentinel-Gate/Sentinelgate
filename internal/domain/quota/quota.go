// Package quota provides per-identity quota configuration and enforcement.
package quota

import (
	"errors"
	"fmt"
)

// QuotaAction defines what happens when a quota limit is breached.
type QuotaAction string

const (
	// QuotaActionDeny blocks the call when a limit is exceeded.
	QuotaActionDeny QuotaAction = "deny"
	// QuotaActionWarn allows the call but emits a warning.
	QuotaActionWarn QuotaAction = "warn"
)

// QuotaConfig specifies quota limits for an identity.
type QuotaConfig struct {
	IdentityID           string            `json:"identity_id"`
	MaxCallsPerSession   int64             `json:"max_calls_per_session,omitempty"`
	MaxWritesPerSession  int64             `json:"max_writes_per_session,omitempty"`
	MaxDeletesPerSession int64             `json:"max_deletes_per_session,omitempty"`
	MaxCallsPerMinute    int64             `json:"max_calls_per_minute,omitempty"`
	MaxCallsPerDay       int64             `json:"max_calls_per_day,omitempty"`
	ToolLimits           map[string]int64  `json:"tool_limits,omitempty"`
	Action               QuotaAction       `json:"action"`
	Enabled              bool              `json:"enabled"`
}

// Validate checks that the QuotaConfig is well-formed.
// An enabled config requires at least one non-zero limit.
func (c *QuotaConfig) Validate() error {
	if c.IdentityID == "" {
		return errors.New("identity_id is required")
	}

	// M-22: MaxCallsPerDay is not enforced in Check() — reject if set so
	// operators don't mistakenly believe they have daily-limit protection.
	if c.MaxCallsPerDay != 0 {
		return errors.New("max_calls_per_day is not yet supported")
	}

	if c.Enabled {
		if c.Action != QuotaActionDeny && c.Action != QuotaActionWarn {
			return fmt.Errorf("action must be %q or %q, got %q", QuotaActionDeny, QuotaActionWarn, c.Action)
		}

		hasLimit := c.MaxCallsPerSession > 0 ||
			c.MaxWritesPerSession > 0 ||
			c.MaxDeletesPerSession > 0 ||
			c.MaxCallsPerMinute > 0 ||
			len(c.ToolLimits) > 0

		if !hasLimit {
			return errors.New("enabled quota must have at least one non-zero limit")
		}
	}

	return nil
}

// QuotaCheckResult is the outcome of checking a call against quota limits.
type QuotaCheckResult struct {
	Allowed    bool             `json:"allowed"`
	Warnings   []string         `json:"warnings,omitempty"`
	DenyReason string           `json:"deny_reason,omitempty"`
	Usage      QuotaUsageSummary `json:"usage"`
}

// QuotaUsageSummary provides a snapshot of current usage counters.
type QuotaUsageSummary struct {
	TotalCalls  int64 `json:"total_calls"`
	WriteCalls  int64 `json:"write_calls"`
	DeleteCalls int64 `json:"delete_calls"`
	WindowCalls int64 `json:"window_calls"`
}

// ErrQuotaNotFound is returned when no quota config exists for an identity.
var ErrQuotaNotFound = errors.New("quota config not found")
