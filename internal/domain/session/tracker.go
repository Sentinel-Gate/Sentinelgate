package session

import (
	"sync"
	"time"
)

// sessionState holds internal per-session tracking data.
type sessionState struct {
	usage         SessionUsage
	windowEntries []time.Time
	identityID    string
	identityName  string
	actionHistory ActionHistory
	actionSet     map[string]bool
	argKeySet     map[string]bool
}

// SessionTracker provides thread-safe per-session call counting with sliding window.
type SessionTracker struct {
	mu         sync.Mutex
	sessions   map[string]*sessionState
	windowSize time.Duration
	classifier ToolCallClassifier
}

// NewSessionTracker creates a new SessionTracker.
// windowSize defines the sliding window duration for rate counting.
// classifier maps tool names to call types; if nil, DefaultClassifier is used.
func NewSessionTracker(windowSize time.Duration, classifier ToolCallClassifier) *SessionTracker {
	if classifier == nil {
		classifier = DefaultClassifier()
	}
	return &SessionTracker{
		sessions:   make(map[string]*sessionState),
		windowSize: windowSize,
		classifier: classifier,
	}
}

// RecordCall records a tool call for a session. It increments total calls,
// calls-by-type, and calls-by-tool-name atomically. Identity info is stored
// on the first call for a session and not overwritten by subsequent calls.
// argKeys is an optional sorted list of argument key names from the tool call.
func (t *SessionTracker) RecordCall(sessionID, toolName, identityID, identityName string, argKeys []string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()

	state, exists := t.sessions[sessionID]
	if !exists {
		state = &sessionState{
			usage: SessionUsage{
				CallsByToolName: make(map[string]int64),
				StartedAt:       now,
			},
			identityID:   identityID,
			identityName: identityName,
			actionSet:    make(map[string]bool),
			argKeySet:    make(map[string]bool),
		}
		t.sessions[sessionID] = state
	}

	state.usage.TotalCalls++
	state.usage.LastCallAt = now

	// Classify and increment typed counter
	callType := t.classifier(toolName)
	switch callType {
	case CallTypeRead:
		state.usage.ReadCalls++
	case CallTypeWrite:
		state.usage.WriteCalls++
	case CallTypeDelete:
		state.usage.DeleteCalls++
	}

	// Per-tool-name tracking
	state.usage.CallsByToolName[toolName]++

	// Action history: append record, FIFO eviction at cap
	record := ActionRecord{
		ToolName:  toolName,
		CallType:  callType,
		Timestamp: now,
		ArgKeys:   argKeys,
	}
	state.actionHistory = append(state.actionHistory, record)
	if len(state.actionHistory) > MaxActionHistory {
		state.actionHistory = state.actionHistory[len(state.actionHistory)-MaxActionHistory:]
	}

	// Action set: unique tool names
	state.actionSet[toolName] = true

	// Arg key set: unique argument key names
	for _, key := range argKeys {
		state.argKeySet[key] = true
	}

	// Sliding window: add entry and trim expired
	state.windowEntries = append(state.windowEntries, now)
	t.trimWindow(state, now)
}

// GetUsage returns a copy of the current usage for a session.
// Returns false if the session is not being tracked.
func (t *SessionTracker) GetUsage(sessionID string) (SessionUsage, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.sessions[sessionID]
	if !exists {
		return SessionUsage{}, false
	}

	// Trim window before returning
	t.trimWindow(state, time.Now())

	return t.copyUsage(state), true
}

// RemoveSession stops tracking a session.
func (t *SessionTracker) RemoveSession(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.sessions, sessionID)
}

// ActiveSessions returns info for all tracked sessions.
func (t *SessionTracker) ActiveSessions() []ActiveSessionInfo {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	result := make([]ActiveSessionInfo, 0, len(t.sessions))

	for id, state := range t.sessions {
		t.trimWindow(state, now)
		result = append(result, ActiveSessionInfo{
			SessionID:    id,
			IdentityID:   state.identityID,
			IdentityName: state.identityName,
			Usage:        t.copyUsage(state),
		})
	}

	return result
}

// GetActionHistory returns a deep copy of the action history for a session.
// Returns false if the session is not being tracked.
func (t *SessionTracker) GetActionHistory(sessionID string) (ActionHistory, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.sessions[sessionID]
	if !exists {
		return nil, false
	}

	// Deep copy: copy slice and each record's ArgKeys
	history := make(ActionHistory, len(state.actionHistory))
	for i, rec := range state.actionHistory {
		history[i] = rec
		if rec.ArgKeys != nil {
			history[i].ArgKeys = make([]string, len(rec.ArgKeys))
			copy(history[i].ArgKeys, rec.ArgKeys)
		}
	}
	return history, true
}

// GetActionSet returns a copy of the action set (unique tool names) for a session.
// Returns false if the session is not being tracked.
func (t *SessionTracker) GetActionSet(sessionID string) (map[string]bool, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.sessions[sessionID]
	if !exists {
		return nil, false
	}

	result := make(map[string]bool, len(state.actionSet))
	for k, v := range state.actionSet {
		result[k] = v
	}
	return result, true
}

// GetArgKeySet returns a copy of the arg key set (unique argument key names) for a session.
// Returns false if the session is not being tracked.
func (t *SessionTracker) GetArgKeySet(sessionID string) (map[string]bool, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.sessions[sessionID]
	if !exists {
		return nil, false
	}

	result := make(map[string]bool, len(state.argKeySet))
	for k, v := range state.argKeySet {
		result[k] = v
	}
	return result, true
}

// trimWindow removes entries older than the window from sessionState.
func (t *SessionTracker) trimWindow(state *sessionState, now time.Time) {
	cutoff := now.Add(-t.windowSize)

	// Find the first entry within the window
	i := 0
	for i < len(state.windowEntries) && state.windowEntries[i].Before(cutoff) {
		i++
	}

	if i > 0 {
		state.windowEntries = state.windowEntries[i:]
	}

	state.usage.WindowCalls = int64(len(state.windowEntries))
}

// copyUsage returns a deep copy of the session usage.
func (t *SessionTracker) copyUsage(state *sessionState) SessionUsage {
	usage := state.usage
	usage.CallsByToolName = make(map[string]int64, len(state.usage.CallsByToolName))
	for k, v := range state.usage.CallsByToolName {
		usage.CallsByToolName[k] = v
	}
	return usage
}
