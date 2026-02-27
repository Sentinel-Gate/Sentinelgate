package quota

import (
	"context"
	"errors"
	"fmt"

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
}

// NewQuotaService creates a new QuotaService.
func NewQuotaService(store QuotaStore, tracker *session.SessionTracker) *QuotaService {
	return &QuotaService{
		store:      store,
		tracker:    tracker,
		classifier: session.DefaultClassifier(),
	}
}

// Check evaluates whether a tool call is allowed under the identity's quota.
// It compares current session usage (plus the pending call) against configured limits.
// Returns Allowed=true if no config exists, config is disabled, or no session data.
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

	// Get current session usage
	usage, found := s.tracker.GetUsage(sessionID)
	if !found {
		// No calls recorded yet — the pending call will be the first, all limits OK
		return result
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
		next := usage.TotalCalls + 1
		s.checkLimit("total calls per session", next, cfg.MaxCallsPerSession, &violations, &warnings)
	}

	// Check MaxWritesPerSession
	if cfg.MaxWritesPerSession > 0 && callType == session.CallTypeWrite {
		next := usage.WriteCalls + 1
		s.checkLimit("writes per session", next, cfg.MaxWritesPerSession, &violations, &warnings)
	}

	// Check MaxDeletesPerSession
	if cfg.MaxDeletesPerSession > 0 && callType == session.CallTypeDelete {
		next := usage.DeleteCalls + 1
		s.checkLimit("deletes per session", next, cfg.MaxDeletesPerSession, &violations, &warnings)
	}

	// Check MaxCallsPerMinute (sliding window)
	if cfg.MaxCallsPerMinute > 0 {
		next := usage.WindowCalls + 1
		s.checkLimit("calls per minute", next, cfg.MaxCallsPerMinute, &violations, &warnings)
	}

	// Check per-tool limits
	if limit, ok := cfg.ToolLimits[toolName]; ok && limit > 0 {
		next := usage.CallsByToolName[toolName] + 1
		s.checkLimit(fmt.Sprintf("calls for tool %q", toolName), next, limit, &violations, &warnings)
	}

	// Apply action
	if len(violations) > 0 {
		if cfg.Action == QuotaActionDeny {
			result.Allowed = false
			result.DenyReason = fmt.Sprintf("quota exceeded: %s", violations[0])
		} else {
			// Warn mode — allow but add warnings
			for _, v := range violations {
				warnings = append(warnings, fmt.Sprintf("quota exceeded: %s", v))
			}
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
