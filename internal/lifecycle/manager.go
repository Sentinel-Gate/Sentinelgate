// Package lifecycle provides an ordered shutdown framework for SentinelGate.
// Components register shutdown hooks at specific phases. During shutdown,
// hooks execute phase by phase in order, each with its own timeout.
// Errors are logged but do not block subsequent phases (A6).
package lifecycle

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// Phase defines when a shutdown hook runs. Phases execute in ascending order.
type Phase int

const (
	// PhaseStopAccepting stops accepting new connections/requests.
	PhaseStopAccepting Phase = iota
	// PhaseDrainRequests completes in-flight requests and drains queues.
	PhaseDrainRequests
	// PhaseFlushBuffers flushes audit, evidence, OTel, event bus buffers.
	PhaseFlushBuffers
	// PhaseCloseConnections closes upstream, SSE, webhook connections.
	PhaseCloseConnections
	// PhaseSaveState persists state, baselines, registry to disk.
	// L-24: Reserved for future use; part of the public Phase enum API.
	PhaseSaveState
	// PhaseCleanup releases file locks, removes temp files.
	PhaseCleanup
)

// String returns a human-readable name for the phase.
func (p Phase) String() string {
	switch p {
	case PhaseStopAccepting:
		return "stop-accepting"
	case PhaseDrainRequests:
		return "drain-requests"
	case PhaseFlushBuffers:
		return "flush-buffers"
	case PhaseCloseConnections:
		return "close-connections"
	case PhaseSaveState:
		return "save-state"
	case PhaseCleanup:
		return "cleanup"
	default:
		return fmt.Sprintf("phase-%d", p)
	}
}

// Hook is a shutdown action registered by a component.
type Hook struct {
	// Name identifies the hook for logging.
	Name string
	// Phase determines when this hook runs relative to others.
	Phase Phase
	// Timeout is the maximum time allowed for this hook.
	// If zero, defaults to 5 seconds.
	Timeout time.Duration
	// Fn is the shutdown function. It receives a context with the hook's timeout.
	Fn func(ctx context.Context) error
}

// Manager coordinates ordered shutdown of all registered components.
// Thread-safe: Register can be called concurrently from multiple goroutines.
type Manager struct {
	mu     sync.Mutex
	hooks  []Hook
	logger *slog.Logger
}

// NewManager creates a new lifecycle Manager.
func NewManager(logger *slog.Logger) *Manager {
	return &Manager{
		logger: logger,
	}
}

// Register adds a shutdown hook. Can be called at any time before Shutdown.
func (m *Manager) Register(hook Hook) {
	if hook.Timeout == 0 {
		hook.Timeout = 5 * time.Second
	}
	m.mu.Lock()
	m.hooks = append(m.hooks, hook)
	m.mu.Unlock()
	m.logger.Debug("lifecycle hook registered",
		"name", hook.Name,
		"phase", hook.Phase.String(),
		"timeout", hook.Timeout,
	)
}

// Shutdown executes all hooks in phase order. Within each phase, hooks run
// sequentially in registration order. Each hook gets its own timeout context.
// Errors are logged but do not prevent subsequent hooks from running.
// Returns an aggregated error if any hooks failed.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	hooks := make([]Hook, len(m.hooks))
	copy(hooks, m.hooks)
	m.mu.Unlock()

	if len(hooks) == 0 {
		return nil
	}

	// Sort by phase (stable sort preserves registration order within phase)
	sort.SliceStable(hooks, func(i, j int) bool {
		return hooks[i].Phase < hooks[j].Phase
	})

	m.logger.Info("lifecycle shutdown starting", "hooks", len(hooks))

	var errs []string
	currentPhase := Phase(-1)

	for _, hook := range hooks {
		// Check if parent context is cancelled (hard shutdown)
		if ctx.Err() != nil {
			m.logger.Warn("lifecycle shutdown aborted: context cancelled",
				"remaining_hooks", len(hooks))
			errs = append(errs, "shutdown aborted: context cancelled")
			break
		}

		// Log phase transitions
		if hook.Phase != currentPhase {
			currentPhase = hook.Phase
			m.logger.Info("lifecycle phase starting", "phase", currentPhase.String())
		}

		// Run hook with its own timeout (recover from panics during shutdown)
		hookCtx, cancel := context.WithTimeout(ctx, hook.Timeout)
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					if e, ok := r.(error); ok {
						err = fmt.Errorf("panic: %w", e)
					} else {
						err = fmt.Errorf("panic: %v", r)
					}
				}
			}()
			err = hook.Fn(hookCtx)
		}()
		cancel()

		if err != nil {
			m.logger.Error("lifecycle hook failed",
				"name", hook.Name,
				"phase", hook.Phase.String(),
				"error", err,
			)
			errs = append(errs, fmt.Sprintf("%s: %v", hook.Name, err))
		} else {
			m.logger.Debug("lifecycle hook completed",
				"name", hook.Name,
				"phase", hook.Phase.String(),
			)
		}
	}

	m.logger.Info("lifecycle shutdown complete", "errors", len(errs))

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// HookCount returns the number of registered hooks. Primarily for testing.
func (m *Manager) HookCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.hooks)
}
