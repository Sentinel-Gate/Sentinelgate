// Package service provides application-level services for SentinelGate.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// ToolBaselineEntry stores a snapshot of a tool's schema at baseline capture time.
type ToolBaselineEntry struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"input_schema"`
	CapturedAt  time.Time   `json:"captured_at"`
}

// DriftReport describes a difference between the baseline and current tool set.
type DriftReport struct {
	ToolName  string      `json:"tool_name"`
	DriftType string      `json:"drift_type"` // "added", "removed", "changed"
	Baseline  interface{} `json:"baseline,omitempty"`
	Current   interface{} `json:"current,omitempty"`
}

// ToolSecurityService manages tool baseline capture, drift detection, and quarantine.
type ToolSecurityService struct {
	toolCache   *upstream.ToolCache
	stateStore  *state.FileStateStore
	logger      *slog.Logger
	mu          sync.RWMutex
	baseline    map[string]ToolBaselineEntry
	quarantined map[string]bool
}

// NewToolSecurityService creates a new ToolSecurityService.
func NewToolSecurityService(toolCache *upstream.ToolCache, stateStore *state.FileStateStore, logger *slog.Logger) *ToolSecurityService {
	return &ToolSecurityService{
		toolCache:   toolCache,
		stateStore:  stateStore,
		logger:      logger,
		baseline:    make(map[string]ToolBaselineEntry),
		quarantined: make(map[string]bool),
	}
}

// CaptureBaseline snapshots all current tools from the ToolCache as the baseline.
func (s *ToolSecurityService) CaptureBaseline(_ context.Context) (int, error) {
	tools := s.toolCache.GetAllTools()
	if len(tools) == 0 {
		return 0, fmt.Errorf("no tools discovered; cannot capture baseline")
	}

	now := time.Now().UTC()
	newBaseline := make(map[string]ToolBaselineEntry, len(tools))
	for _, t := range tools {
		// Parse InputSchema into a generic interface{} for comparison later.
		var schema interface{}
		if len(t.InputSchema) > 0 {
			_ = json.Unmarshal(t.InputSchema, &schema)
		}
		newBaseline[t.Name] = ToolBaselineEntry{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: schema,
			CapturedAt:  now,
		}
	}

	s.mu.Lock()
	s.baseline = newBaseline
	s.mu.Unlock()

	if err := s.persist(); err != nil {
		return 0, fmt.Errorf("failed to persist baseline: %w", err)
	}

	s.logger.Info("tool baseline captured", "tools", len(newBaseline))
	return len(newBaseline), nil
}

// DetectDrift compares the current ToolCache tools against the stored baseline.
func (s *ToolSecurityService) DetectDrift(_ context.Context) ([]DriftReport, error) {
	s.mu.RLock()
	baseline := s.baseline
	s.mu.RUnlock()

	if len(baseline) == 0 {
		return nil, fmt.Errorf("no baseline captured; run CaptureBaseline first")
	}

	currentTools := s.toolCache.GetAllTools()
	currentMap := make(map[string]*upstream.DiscoveredTool, len(currentTools))
	for _, t := range currentTools {
		currentMap[t.Name] = t
	}

	var drifts []DriftReport

	// Check for removed and changed tools.
	for name, baseEntry := range baseline {
		current, exists := currentMap[name]
		if !exists {
			drifts = append(drifts, DriftReport{
				ToolName:  name,
				DriftType: "removed",
				Baseline:  baseEntry,
			})
			continue
		}

		// Compare schemas via JSON round-trip.
		var currentSchema interface{}
		if len(current.InputSchema) > 0 {
			_ = json.Unmarshal(current.InputSchema, &currentSchema)
		}

		baseJSON, _ := json.Marshal(baseEntry.InputSchema)
		currJSON, _ := json.Marshal(currentSchema)

		if string(baseJSON) != string(currJSON) || baseEntry.Description != current.Description {
			drifts = append(drifts, DriftReport{
				ToolName:  name,
				DriftType: "changed",
				Baseline:  baseEntry,
				Current: map[string]interface{}{
					"description":  current.Description,
					"input_schema": currentSchema,
				},
			})
		}
	}

	// Check for added tools.
	for _, t := range currentTools {
		if _, exists := baseline[t.Name]; !exists {
			var schema interface{}
			if len(t.InputSchema) > 0 {
				_ = json.Unmarshal(t.InputSchema, &schema)
			}
			drifts = append(drifts, DriftReport{
				ToolName:  t.Name,
				DriftType: "added",
				Current: map[string]interface{}{
					"description":  t.Description,
					"input_schema": schema,
				},
			})
		}
	}

	return drifts, nil
}

// Quarantine marks a tool as quarantined and persists the change.
func (s *ToolSecurityService) Quarantine(toolName string) error {
	s.mu.Lock()
	s.quarantined[toolName] = true
	s.mu.Unlock()

	if err := s.persist(); err != nil {
		return fmt.Errorf("failed to persist quarantine: %w", err)
	}

	s.logger.Info("tool quarantined", "tool", toolName)
	return nil
}

// Unquarantine removes quarantine from a tool and persists the change.
func (s *ToolSecurityService) Unquarantine(toolName string) error {
	s.mu.Lock()
	wasQuarantined := s.quarantined[toolName]
	delete(s.quarantined, toolName)
	s.mu.Unlock()

	if !wasQuarantined {
		return fmt.Errorf("tool %q is not quarantined", toolName)
	}

	if err := s.persist(); err != nil {
		return fmt.Errorf("failed to persist unquarantine: %w", err)
	}

	s.logger.Info("tool unquarantined", "tool", toolName)
	return nil
}

// IsQuarantined returns true if the tool is quarantined. Thread-safe for hot-path use.
func (s *ToolSecurityService) IsQuarantined(toolName string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.quarantined[toolName]
}

// GetBaseline returns the current baseline entries.
func (s *ToolSecurityService) GetBaseline() map[string]ToolBaselineEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]ToolBaselineEntry, len(s.baseline))
	for k, v := range s.baseline {
		result[k] = v
	}
	return result
}

// GetQuarantinedTools returns the list of quarantined tool names.
func (s *ToolSecurityService) GetQuarantinedTools() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]string, 0, len(s.quarantined))
	for name := range s.quarantined {
		result = append(result, name)
	}
	return result
}

// LoadFromState restores baseline and quarantine state from a previously loaded AppState.
func (s *ToolSecurityService) LoadFromState(appState *state.AppState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if appState.ToolBaseline != nil {
		s.baseline = make(map[string]ToolBaselineEntry, len(appState.ToolBaseline))
		for k, v := range appState.ToolBaseline {
			s.baseline[k] = ToolBaselineEntry{
				Name:        v.Name,
				Description: v.Description,
				InputSchema: v.InputSchema,
				CapturedAt:  v.CapturedAt,
			}
		}
		s.logger.Debug("loaded tool baseline from state", "tools", len(s.baseline))
	}

	if len(appState.QuarantinedTools) > 0 {
		s.quarantined = make(map[string]bool, len(appState.QuarantinedTools))
		for _, name := range appState.QuarantinedTools {
			s.quarantined[name] = true
		}
		s.logger.Debug("loaded quarantined tools from state", "tools", len(s.quarantined))
	}
}

// persist saves the current baseline and quarantine state to state.json.
func (s *ToolSecurityService) persist() error {
	s.mu.RLock()
	baselineCopy := make(map[string]state.ToolBaselineEntry, len(s.baseline))
	for k, v := range s.baseline {
		baselineCopy[k] = state.ToolBaselineEntry{
			Name:        v.Name,
			Description: v.Description,
			InputSchema: v.InputSchema,
			CapturedAt:  v.CapturedAt,
		}
	}
	quarantinedCopy := make([]string, 0, len(s.quarantined))
	for name := range s.quarantined {
		quarantinedCopy = append(quarantinedCopy, name)
	}
	s.mu.RUnlock()

	appState, err := s.stateStore.Load()
	if err != nil {
		return err
	}

	appState.ToolBaseline = baselineCopy
	appState.QuarantinedTools = quarantinedCopy

	return s.stateStore.Save(appState)
}
