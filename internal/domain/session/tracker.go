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

// DefaultSessionTTL is the default maximum idle time before a session is reaped.
const DefaultSessionTTL = 30 * time.Minute

// maxActionSetSize caps the number of unique tool names tracked in actionSet per session (M-26).
const maxActionSetSize = 1000

// maxArgKeySetSize caps the number of unique argument key names tracked in argKeySet per session (M-26).
const maxArgKeySetSize = 1000

// maxToolNamesPerSession caps the number of distinct tool names in CallsByToolName per session (M-27).
// Overflow is aggregated into the "_other" bucket.
const maxToolNamesPerSession = 500

// SessionTracker provides thread-safe per-session call counting with sliding window.
type SessionTracker struct {
	mu         sync.Mutex
	sessions   map[string]*sessionState
	windowSize time.Duration
	classifier ToolCallClassifier
	sessionTTL time.Duration  // max idle time before reaping
	stopClean  chan struct{}  // signals cleanup goroutine to stop
	stopOnce   sync.Once      // prevents double-close panic on concurrent Stop() calls
	wg         sync.WaitGroup // tracks cleanup goroutine for graceful shutdown
}

// NewSessionTracker creates a new SessionTracker.
// windowSize defines the sliding window duration for rate counting.
// classifier maps tool names to call types; if nil, DefaultClassifier is used.
// A background goroutine reaps sessions idle for longer than DefaultSessionTTL.
// Call Stop() to release the goroutine when the tracker is no longer needed.
func NewSessionTracker(windowSize time.Duration, classifier ToolCallClassifier) *SessionTracker {
	if classifier == nil {
		classifier = DefaultClassifier()
	}
	t := &SessionTracker{
		sessions:   make(map[string]*sessionState),
		windowSize: windowSize,
		classifier: classifier,
		sessionTTL: DefaultSessionTTL,
		stopClean:  make(chan struct{}),
	}
	t.wg.Add(1)
	go t.cleanupLoop()
	return t
}

// Stop terminates the background cleanup goroutine and waits for it to exit.
// Safe to call concurrently and multiple times (uses sync.Once internally).
func (t *SessionTracker) Stop() {
	t.stopOnce.Do(func() {
		close(t.stopClean)
	})
	t.wg.Wait()
}

// cleanupLoop periodically removes sessions that have been idle longer than sessionTTL.
func (t *SessionTracker) cleanupLoop() {
	defer t.wg.Done()
	// Read sessionTTL under the lock to prevent data race with concurrent writes.
	t.mu.Lock()
	ttl := t.sessionTTL
	t.mu.Unlock()
	ticker := time.NewTicker(ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopClean:
			return
		case <-ticker.C:
			t.cleanupStale()
		}
	}
}

// cleanupStale removes sessions whose last activity is older than sessionTTL.
// Uses LastCallAt if available, otherwise falls back to StartedAt (for sessions
// tracked via TrackSession that haven't received any tool calls yet).
func (t *SessionTracker) cleanupStale() {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-t.sessionTTL)
	for id, state := range t.sessions {
		lastSeen := state.usage.LastCallAt
		if lastSeen.IsZero() {
			lastSeen = state.usage.StartedAt
		}
		if lastSeen.Before(cutoff) {
			delete(t.sessions, id)
		}
	}
}

// TrackSession pre-registers a session in the tracker with identity info.
// This is called when a session is created (during authentication), so the
// session appears in ActiveSessions() immediately — before any tool call.
// If the session already exists (e.g., RecordCall was called first), this is a no-op.
func (t *SessionTracker) TrackSession(sessionID, identityID, identityName string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.sessions[sessionID]; !exists {
		t.sessions[sessionID] = &sessionState{
			usage: SessionUsage{
				CallsByToolName: make(map[string]int64),
				StartedAt:       time.Now(),
			},
			identityID:   identityID,
			identityName: identityName,
			actionSet:    make(map[string]bool),
			argKeySet:    make(map[string]bool),
		}
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

	// Fill in identity name if it was empty (e.g., TrackSession was called
	// before identity name was available, then RecordCall provides it).
	if state.identityName == "" && identityName != "" {
		state.identityName = identityName
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
	case CallTypeOther:
		// Unclassified calls are counted only in TotalCalls above.
	}

	// Per-tool-name tracking (M-27: cap at maxToolNamesPerSession, overflow into "_other").
	if _, known := state.usage.CallsByToolName[toolName]; known {
		state.usage.CallsByToolName[toolName]++
	} else if len(state.usage.CallsByToolName) < maxToolNamesPerSession {
		state.usage.CallsByToolName[toolName]++
	} else {
		state.usage.CallsByToolName["_other"]++
	}

	// Action history: append record, FIFO eviction at cap
	record := ActionRecord{
		ToolName:  toolName,
		CallType:  callType,
		Timestamp: now,
		ArgKeys:   argKeys,
	}
	state.actionHistory = append(state.actionHistory, record)
	if len(state.actionHistory) > MaxActionHistory {
		kept := make(ActionHistory, MaxActionHistory)
		copy(kept, state.actionHistory[len(state.actionHistory)-MaxActionHistory:])
		state.actionHistory = kept
	}

	// Action set: unique tool names (M-26: cap at maxActionSetSize).
	if len(state.actionSet) < maxActionSetSize || state.actionSet[toolName] {
		state.actionSet[toolName] = true
	}

	// Arg key set: unique argument key names (M-26: cap at maxArgKeySetSize).
	for _, key := range argKeys {
		if len(state.argKeySet) < maxArgKeySetSize || state.argKeySet[key] {
			state.argKeySet[key] = true
		}
	}

	// Sliding window: add entry and trim expired
	state.windowEntries = append(state.windowEntries, now)
	t.trimWindow(state, now)
}

// RecordCost adds a cost amount to the session's cumulative cost.
// If the session does not exist or cost is non-positive, the call is silently dropped.
func (t *SessionTracker) RecordCost(sessionID string, cost float64) {
	if cost <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	state, exists := t.sessions[sessionID]
	if !exists {
		return
	}
	state.usage.CumulativeCost += cost
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
	for i < len(state.windowEntries) && !state.windowEntries[i].After(cutoff) {
		i++
	}

	if i > 0 {
		kept := make([]time.Time, len(state.windowEntries)-i)
		copy(kept, state.windowEntries[i:])
		state.windowEntries = kept
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
