// Package service provides application-level services for SentinelGate.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// ErrNoBaseline is returned when drift detection is attempted before a baseline has been captured.
var ErrNoBaseline = errors.New("no baseline captured")

// ErrNotQuarantined is returned when trying to unquarantine a tool that is not quarantined.
var ErrNotQuarantined = errors.New("tool is not quarantined")

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
	eventBus    event.Bus
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
			if err := json.Unmarshal(t.InputSchema, &schema); err != nil {
				s.logger.Warn("failed to unmarshal tool input schema", "tool", t.Name, "error", err)
			}
		}
		newBaseline[t.Name] = ToolBaselineEntry{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: schema,
			CapturedAt:  now,
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	oldBaseline := s.baseline
	s.baseline = newBaseline
	if err := s.persistLocked(); err != nil {
		s.baseline = oldBaseline // rollback
		return 0, fmt.Errorf("failed to persist baseline: %w", err)
	}

	s.logger.Info("tool baseline captured", "tools", len(newBaseline))
	return len(newBaseline), nil
}

// ClearBaseline removes the stored baseline entirely.
// Called when the last upstream is removed so stale data
// does not trigger false-positive drift reports.
func (s *ToolSecurityService) ClearBaseline() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldBaseline := s.baseline
	s.baseline = make(map[string]ToolBaselineEntry)
	if err := s.persistLocked(); err != nil {
		s.baseline = oldBaseline // rollback
		return fmt.Errorf("failed to persist cleared baseline: %w", err)
	}

	s.logger.Info("tool baseline cleared (no upstreams remaining)")
	return nil
}

// DetectDrift compares the current ToolCache tools against the stored baseline.
func (s *ToolSecurityService) DetectDrift(_ context.Context) ([]DriftReport, error) {
	s.mu.RLock()
	baseline := s.baseline
	s.mu.RUnlock()

	if len(baseline) == 0 {
		return nil, fmt.Errorf("%w; run CaptureBaseline first", ErrNoBaseline)
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
			if err := json.Unmarshal(current.InputSchema, &currentSchema); err != nil {
				s.logger.Warn("failed to unmarshal current tool schema", "tool", name, "error", err)
			}
		}

		baseJSON, errBase := json.Marshal(baseEntry.InputSchema)
		currJSON, errCurr := json.Marshal(currentSchema)

		// Fail-secure: marshal errors mean we can't compare, treat as drift.
		if errBase != nil || errCurr != nil || string(baseJSON) != string(currJSON) || baseEntry.Description != current.Description {
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
				if err := json.Unmarshal(t.InputSchema, &schema); err != nil {
					s.logger.Warn("failed to unmarshal tool input schema", "tool", t.Name, "error", err)
				}
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
	defer s.mu.Unlock()

	alreadyQuarantined := s.quarantined[toolName]
	s.quarantined[toolName] = true
	if err := s.persistLocked(); err != nil {
		// Rollback.
		if !alreadyQuarantined {
			delete(s.quarantined, toolName)
		}
		return fmt.Errorf("failed to persist quarantine: %w", err)
	}

	s.logger.Info("tool quarantined", "tool", toolName)
	return nil
}

// Unquarantine removes quarantine from a tool and persists the change.
func (s *ToolSecurityService) Unquarantine(toolName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.quarantined[toolName] {
		return ErrNotQuarantined
	}

	delete(s.quarantined, toolName)
	if err := s.persistLocked(); err != nil {
		// Rollback.
		s.quarantined[toolName] = true
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

// persistLocked saves the current baseline and quarantine state to state.json.
// Caller must hold s.mu (Lock or RLock).
func (s *ToolSecurityService) persistLocked() error {
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

	return s.stateStore.Mutate(func(appState *state.AppState) error {
		appState.ToolBaseline = baselineCopy
		appState.QuarantinedTools = quarantinedCopy
		return nil
	})
}

// SetEventBus sets the event bus for emitting tool integrity events.
func (s *ToolSecurityService) SetEventBus(bus event.Bus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventBus = bus
}

// CheckIntegrityAndEmit runs drift detection and emits events for each finding.
// Called automatically after tool discovery to detect changes since last baseline.
// If no baseline exists, captures one automatically (first run).
func (s *ToolSecurityService) CheckIntegrityAndEmit(ctx context.Context) {
	s.mu.RLock()
	hasBaseline := len(s.baseline) > 0
	bus := s.eventBus
	s.mu.RUnlock()

	if !hasBaseline {
		// First run: capture baseline silently.
		count, err := s.CaptureBaseline(ctx)
		if err != nil {
			s.logger.Warn("auto-baseline capture failed", "error", err)
			return
		}
		s.logger.Info("auto-captured initial tool baseline", "tools", count)
		return
	}

	drifts, err := s.DetectDrift(ctx)
	if err != nil {
		s.logger.Warn("integrity check failed", "error", err)
		return
	}

	if len(drifts) == 0 {
		return
	}

	s.logger.Warn("tool integrity changes detected", "count", len(drifts))

	if bus == nil {
		return
	}

	// Build upstream lookup for event payloads.
	currentTools := s.toolCache.GetAllTools()
	upstreamByTool := make(map[string]string, len(currentTools))
	for _, t := range currentTools {
		upstreamByTool[t.Name] = t.UpstreamName
	}

	for _, d := range drifts {
		var evtType string
		var severity event.Severity
		switch d.DriftType {
		case "added":
			evtType = "tool.new"
			severity = event.SeverityWarning
			// SEC-1 FIX: Auto-quarantine new tools not present in the baseline.
			// An attacker who compromises an upstream could inject a malicious tool
			// (e.g., execute_shell). Without quarantine, it would be available to
			// all agents immediately. Admin must explicitly accept new tools.
			if err := s.Quarantine(d.ToolName); err != nil {
				s.logger.Warn("auto-quarantine failed for new tool", "tool", d.ToolName, "error", err)
			} else {
				s.logger.Warn("new tool auto-quarantined until admin review", "tool", d.ToolName)
			}
		case "removed":
			evtType = "tool.removed"
			severity = event.SeverityWarning
		case "changed":
			evtType = "tool.changed"
			severity = event.SeverityWarning
			// Auto-quarantine: block the tool immediately until admin reviews.
			if err := s.Quarantine(d.ToolName); err != nil {
				s.logger.Warn("auto-quarantine failed", "tool", d.ToolName, "error", err)
			} else {
				s.logger.Warn("tool auto-quarantined due to schema change", "tool", d.ToolName)
			}
		default:
			continue
		}

		bus.Publish(ctx, event.Event{
			Type:           evtType,
			Source:         "tool-integrity",
			Severity:       severity,
			RequiresAction: d.DriftType == "changed" || d.DriftType == "added",
			Payload: map[string]string{
				"tool_name":  d.ToolName,
				"drift_type": d.DriftType,
				"upstream":   upstreamByTool[d.ToolName],
			},
		})
	}
}

// AcceptChange updates the baseline for a single tool to accept its current definition.
func (s *ToolSecurityService) AcceptChange(ctx context.Context, toolName string) error {
	tools := s.toolCache.GetAllTools()
	var found *upstream.DiscoveredTool
	for _, t := range tools {
		if t.Name == toolName {
			found = t
			break
		}
	}
	if found == nil {
		return fmt.Errorf("tool %q not found in current tool cache", toolName)
	}

	var schema interface{}
	if len(found.InputSchema) > 0 {
		if err := json.Unmarshal(found.InputSchema, &schema); err != nil {
			s.logger.Warn("failed to unmarshal tool input schema", "tool", toolName, "error", err)
		}
	}

	newEntry := ToolBaselineEntry{
		Name:        found.Name,
		Description: found.Description,
		InputSchema: schema,
		CapturedAt:  time.Now().UTC(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	oldEntry, hadOld := s.baseline[toolName]
	s.baseline[toolName] = newEntry
	if err := s.persistLocked(); err != nil {
		// Rollback.
		if hadOld {
			s.baseline[toolName] = oldEntry
		} else {
			delete(s.baseline, toolName)
		}
		return fmt.Errorf("failed to persist baseline update: %w", err)
	}

	s.logger.Info("tool change accepted", "tool", toolName)
	return nil
}
