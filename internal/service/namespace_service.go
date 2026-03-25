package service

import (
	"log/slog"
	"sync"
)

// NamespaceConfig maps roles to their visible/hidden tools.
type NamespaceConfig struct {
	Enabled bool                        `json:"enabled"`
	Rules   map[string]*NamespaceRule   `json:"rules"` // role name -> rule
}

// NamespaceRule defines tool visibility for a role.
type NamespaceRule struct {
	VisibleTools  []string `json:"visible_tools,omitempty"`  // whitelist (if set, only these are visible)
	HiddenTools   []string `json:"hidden_tools,omitempty"`   // blacklist (these are hidden, rest visible)
}

// DefaultNamespaceConfig returns disabled config.
func DefaultNamespaceConfig() NamespaceConfig {
	return NamespaceConfig{
		Enabled: false,
		Rules:   make(map[string]*NamespaceRule),
	}
}

// NamespaceService manages tool visibility per role.
type NamespaceService struct {
	mu     sync.RWMutex
	config NamespaceConfig
	logger *slog.Logger
}

// NewNamespaceService creates a new namespace service.
func NewNamespaceService(logger *slog.Logger) *NamespaceService {
	return &NamespaceService{
		config: DefaultNamespaceConfig(),
		logger: logger,
	}
}

// Config returns the current config.
func (s *NamespaceService) Config() NamespaceConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// SetConfig updates the namespace config.
func (s *NamespaceService) SetConfig(cfg NamespaceConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.Rules == nil {
		cfg.Rules = make(map[string]*NamespaceRule)
	}
	s.config = cfg
}

// IsToolVisible returns whether a tool should be visible for the given roles.
// When disabled, all tools are visible (default permissive).
func (s *NamespaceService) IsToolVisible(toolName string, roles []string) bool {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if !cfg.Enabled || len(cfg.Rules) == 0 {
		return true
	}

	// Check each role — if ANY role grants visibility, tool is visible.
	for _, role := range roles {
		rule, ok := cfg.Rules[role]
		if !ok {
			// No rule for this role = no restrictions from this role.
			// But we need at least one role to explicitly allow.
			continue
		}

		if len(rule.VisibleTools) > 0 {
			// Whitelist mode: only listed tools are visible.
			for _, t := range rule.VisibleTools {
				if matchToolPattern(t, toolName) {
					return true
				}
			}
		} else if len(rule.HiddenTools) > 0 {
			// Blacklist mode: listed tools are hidden, rest visible.
			hidden := false
			for _, t := range rule.HiddenTools {
				if matchToolPattern(t, toolName) {
					hidden = true
					break
				}
			}
			if !hidden {
				return true
			}
		} else {
			// Rule exists but empty = all visible for this role.
			return true
		}
	}

	// M-10: When namespace filtering is enabled, roles without explicit rules
	// default to deny (no tool visibility). This prevents accidental access
	// for unconfigured roles.
	return false
}

// FilterTools returns only tools visible to the given roles.
func (s *NamespaceService) FilterTools(toolNames []string, roles []string) []string {
	s.mu.RLock()
	cfg := s.config
	s.mu.RUnlock()

	if !cfg.Enabled || len(cfg.Rules) == 0 {
		return toolNames
	}

	var visible []string
	for _, name := range toolNames {
		if s.IsToolVisible(name, roles) {
			visible = append(visible, name)
		}
	}
	return visible
}

// matchToolPattern matches a tool name against a pattern.
// Supports exact match and simple glob with trailing * (e.g., "read_*").
func matchToolPattern(pattern, toolName string) bool {
	if pattern == "*" {
		return true
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(toolName) >= len(prefix) && toolName[:len(prefix)] == prefix
	}
	return pattern == toolName
}
