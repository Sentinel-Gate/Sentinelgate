package quota

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
)

// QuotaStore provides persistence for quota configurations.
type QuotaStore interface {
	Get(ctx context.Context, identityID string) (*QuotaConfig, error)
	Put(ctx context.Context, config *QuotaConfig) error
	Delete(ctx context.Context, identityID string) error
	List(ctx context.Context) ([]*QuotaConfig, error)
}

// QuotaService enforces quota limits by comparing session usage against config.
type QuotaService struct {
	store      QuotaStore
	tracker    *session.SessionTracker
	classifier session.ToolCallClassifier
	pendingMu  sync.Mutex
	pending    map[string]*int64
}

// NewQuotaService creates a new QuotaService.
func NewQuotaService(store QuotaStore, tracker *session.SessionTracker) *QuotaService {
	return &QuotaService{
		store:      store,
		tracker:    tracker,
		classifier: session.DefaultClassifier(),
		pending:    make(map[string]*int64),
	}
}

func (s *QuotaService) getPendingCounter(sessionID string) *int64 {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	counter, ok := s.pending[sessionID]
	if !ok {
		var v int64
		counter = &v
		s.pending[sessionID] = counter
	}
	return counter
}

// Check evaluates whether a tool call is allowed under the identity's quota.
// It compares current session usage (plus the pending call) against configured limits.
// Returns Allowed=true if no config exists, config is disabled, or no session data.
//
// Note: the pending counter is a single total per session (not per call type).
// This means per-type checks (writes, deletes) may over-count when multiple
// concurrent calls of different types are in flight. This is intentionally
// conservative — it ensures the quota is never exceeded, at the cost of
// occasionally rejecting a call that would have been within limits.
func (s *QuotaService) Check(ctx context.Context, identityID, sessionID, toolName string) QuotaCheckResult {
	result := QuotaCheckResult{Allowed: true}

	// Get quota config for this identity
	cfg, err := s.store.Get(ctx, identityID)
	if err != nil {
		if errors.Is(err, ErrQuotaNotFound) {
			return result
		}
		// On store error, allow (fail-open)
		return result
	}

	if !cfg.Enabled {
		return result
	}

	counter := s.getPendingCounter(sessionID)
	pendingCount := atomic.AddInt64(counter, 1)
	defer func() {
		if atomic.AddInt64(counter, -1) == 0 {
			s.pendingMu.Lock()
			// Re-check under lock to avoid racing with another goroutine that just incremented.
			if atomic.LoadInt64(counter) == 0 {
				delete(s.pending, sessionID)
			}
			s.pendingMu.Unlock()
		}
	}()

	// Get current session usage
	usage, found := s.tracker.GetUsage(sessionID)
	if !found {
		if pendingCount <= 1 {
			return result
		}
		usage = session.SessionUsage{CallsByToolName: make(map[string]int64)}
	}

	// Fill usage summary
	result.Usage = QuotaUsageSummary{
		TotalCalls:  usage.TotalCalls,
		WriteCalls:  usage.WriteCalls,
		DeleteCalls: usage.DeleteCalls,
		WindowCalls: usage.WindowCalls,
	}

	// Classify the pending tool call
	callType := s.classifier(toolName)

	var violations []string
	var warnings []string

	// Check MaxCallsPerSession
	if cfg.MaxCallsPerSession > 0 {
		next := usage.TotalCalls + pendingCount
		s.checkLimit("total calls per session", next, cfg.MaxCallsPerSession, &violations, &warnings)
	}

	// Check MaxWritesPerSession
	if cfg.MaxWritesPerSession > 0 && callType == session.CallTypeWrite {
		next := usage.WriteCalls + pendingCount
		s.checkLimit("writes per session", next, cfg.MaxWritesPerSession, &violations, &warnings)
	}

	// Check MaxDeletesPerSession
	if cfg.MaxDeletesPerSession > 0 && callType == session.CallTypeDelete {
		next := usage.DeleteCalls + pendingCount
		s.checkLimit("deletes per session", next, cfg.MaxDeletesPerSession, &violations, &warnings)
	}

	// Check MaxCallsPerMinute (sliding window)
	if cfg.MaxCallsPerMinute > 0 {
		next := usage.WindowCalls + pendingCount
		s.checkLimit("calls per minute", next, cfg.MaxCallsPerMinute, &violations, &warnings)
	}

	// Check per-tool limits.
	// Try both the full name and the bare name (for namespaced tools like "desktop/read_file")
	// since operators configure ToolLimits using bare names.
	bareToolName := toolName
	if idx := strings.Index(toolName, "/"); idx >= 0 {
		bareToolName = toolName[idx+1:]
	}
	toolLimit, limitFound := cfg.ToolLimits[toolName]
	if !limitFound {
		toolLimit, limitFound = cfg.ToolLimits[bareToolName]
	}
	if limitFound && toolLimit > 0 {
		// Count calls for both the namespaced and bare name to handle mixed storage.
		callCount := usage.CallsByToolName[toolName]
		if bareToolName != toolName {
			callCount += usage.CallsByToolName[bareToolName]
		}
		next := callCount + pendingCount
		s.checkLimit(fmt.Sprintf("calls for tool %q", bareToolName), next, toolLimit, &violations, &warnings)
	}

	// Apply action
	if len(violations) > 0 {
		if cfg.Action == QuotaActionDeny {
			result.Allowed = false
			result.DenyReason = violations[0]
		} else {
			// Warn mode — allow but add warnings
			warnings = append(warnings, violations...)
		}
	}

	result.Warnings = warnings
	return result
}

// checkLimit compares a next value against a limit and records violations/warnings.
func (s *QuotaService) checkLimit(name string, next, limit int64, violations, warnings *[]string) {
	if next > limit {
		*violations = append(*violations, fmt.Sprintf("%s: %d/%d", name, next, limit))
	} else {
		// Check 80% warning threshold
		threshold := float64(limit) * 0.8
		if float64(next) >= threshold {
			*warnings = append(*warnings, fmt.Sprintf("%s at %.0f%%: %d/%d", name, float64(next)/float64(limit)*100, next, limit))
		}
	}
}
