// Package transform defines domain types and execution logic for response
// transformation rules. Transform rules modify tool call responses (redact
// secrets, truncate large outputs, inject warnings, mask sensitive values,
// or replace with synthetic dry-run responses).
package transform

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// TransformType identifies the kind of transformation a rule applies.
type TransformType string

const (
	// TransformRedact replaces regex-matched patterns with a placeholder.
	TransformRedact TransformType = "redact"
	// TransformTruncate limits response length by bytes or lines.
	TransformTruncate TransformType = "truncate"
	// TransformInject prepends or appends text to the response.
	TransformInject TransformType = "inject"
	// TransformDryRun is a marker for synthetic responses (handled at pipeline level).
	TransformDryRun TransformType = "dry_run"
	// TransformMask preserves prefix/suffix characters and masks the middle.
	TransformMask TransformType = "mask"
)

// validTypes enumerates all valid transform types for validation.
var validTypes = map[TransformType]bool{
	TransformRedact:   true,
	TransformTruncate: true,
	TransformInject:   true,
	TransformDryRun:   true,
	TransformMask:     true,
}

// TransformRule defines a named transformation with a tool match pattern,
// transform type, priority, and type-specific configuration.
type TransformRule struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Type      TransformType   `json:"type"`
	ToolMatch string          `json:"tool_match"` // glob pattern (e.g., "read_file", "file_*", "*")
	Priority  int             `json:"priority"`    // lower = runs first
	Enabled   bool            `json:"enabled"`
	Config    TransformConfig `json:"config"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// TransformConfig is a union of type-specific configuration fields.
// Only the fields relevant to the rule's TransformType are used.
type TransformConfig struct {
	// Redact config
	Patterns    []string `json:"patterns,omitempty"`    // regex patterns to match
	Replacement string   `json:"replacement,omitempty"` // defaults to "[REDACTED]"

	// Truncate config
	MaxBytes int    `json:"max_bytes,omitempty"`
	MaxLines int    `json:"max_lines,omitempty"`
	Suffix   string `json:"suffix,omitempty"` // defaults to "\n... [truncated]"

	// Inject config
	Prepend string `json:"prepend,omitempty"`
	Append  string `json:"append,omitempty"`

	// DryRun config
	Response string `json:"response,omitempty"` // synthetic response template

	// Mask config
	MaskPatterns  []string `json:"mask_patterns,omitempty"`  // regex patterns
	VisiblePrefix int      `json:"visible_prefix,omitempty"` // chars to show at start (default 3)
	VisibleSuffix int      `json:"visible_suffix,omitempty"` // chars to show at end (default 4)
	MaskChar      string   `json:"mask_char,omitempty"`      // defaults to "*"
}

// TransformResult tracks what transformation was applied to a response.
type TransformResult struct {
	RuleID   string        `json:"rule_id"`
	RuleName string        `json:"rule_name"`
	Type     TransformType `json:"type"`
	Applied  bool          `json:"applied"`
	Detail   string        `json:"detail,omitempty"` // e.g., "3 patterns redacted"
}

// Validate checks that a TransformRule has valid configuration for its type.
func (r *TransformRule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("transform rule name is required")
	}
	if r.ToolMatch == "" {
		return fmt.Errorf("transform rule tool_match is required")
	}
	if !validTypes[r.Type] {
		return fmt.Errorf("invalid transform type: %q", r.Type)
	}

	switch r.Type {
	case TransformRedact:
		if len(r.Config.Patterns) == 0 {
			return fmt.Errorf("redact transform requires at least one pattern")
		}
		for i, p := range r.Config.Patterns {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("redact pattern[%d] invalid regex: %w", i, err)
			}
		}
	case TransformTruncate:
		if r.Config.MaxBytes <= 0 && r.Config.MaxLines <= 0 {
			return fmt.Errorf("truncate transform requires max_bytes > 0 or max_lines > 0")
		}
	case TransformInject:
		if r.Config.Prepend == "" && r.Config.Append == "" {
			return fmt.Errorf("inject transform requires at least one of prepend or append")
		}
	case TransformDryRun:
		// No extra validation needed; defaults are acceptable.
	case TransformMask:
		if len(r.Config.MaskPatterns) == 0 {
			return fmt.Errorf("mask transform requires at least one mask_pattern")
		}
		for i, p := range r.Config.MaskPatterns {
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("mask pattern[%d] invalid regex: %w", i, err)
			}
		}
	}

	return nil
}

// MatchesTool returns true if this rule's ToolMatch glob pattern matches
// the given tool name. Uses filepath.Match for glob semantics.
func (r *TransformRule) MatchesTool(toolName string) bool {
	matched, err := filepath.Match(r.ToolMatch, toolName)
	if err != nil {
		return false
	}
	return matched
}

// SortByPriority returns a copy of the rules sorted by Priority ascending
// (lower priority number = runs first). The sort is stable.
func SortByPriority(rules []TransformRule) []TransformRule {
	sorted := make([]TransformRule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})
	return sorted
}
