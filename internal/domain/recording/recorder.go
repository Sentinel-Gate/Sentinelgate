package recording

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// validSessionIDPattern allows only safe characters in session IDs.
var validSessionIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)

// DefaultMaxConcurrentRecordings is the default limit on simultaneous active recordings.
// Each recording holds an open file handle; OS limits (256-1024 fd on macOS/Linux)
// make unbounded recording dangerous (A7c).
const DefaultMaxConcurrentRecordings = 100

// Sentinel errors.
var (
	// ErrRecordingNotFound is returned when no recording file exists for a session.
	ErrRecordingNotFound = errors.New("recording: not found")
	// ErrRecordingDisabled is returned when recording is disabled in config.
	ErrRecordingDisabled = errors.New("recording: disabled")
	// ErrInvalidSessionID is returned when a session ID contains unsafe characters.
	ErrInvalidSessionID = errors.New("recording: invalid session ID (must match [a-zA-Z0-9_-]+)")
	// ErrMaxRecordingsReached is returned when the concurrent recording limit is hit.
	ErrMaxRecordingsReached = errors.New("recording: max concurrent recordings reached")
)

// ValidateSessionID ensures the session ID cannot be used for path traversal.
func ValidateSessionID(id string) error {
	if id == "" || !validSessionIDPattern.MatchString(id) {
		return ErrInvalidSessionID
	}
	return nil
}

// Recorder is the interface for the session recording subsystem.
type Recorder interface {
	// RecordEvent appends an event to the session's JSONL file.
	RecordEvent(sessionID string, event RecordingEvent) error
	// StartSession creates a new JSONL file and writes a SessionStart event.
	StartSession(sessionID, identityID, identityName string) error
	// EndSession writes a SessionEnd event and closes the file.
	EndSession(sessionID string) error
	// ListRecordings returns all known recordings, sorted by StartedAt descending.
	ListRecordings() ([]SessionRecording, error)
	// GetRecording returns metadata for a single session.
	GetRecording(sessionID string) (*SessionRecording, error)
	// GetEvents returns paginated events for a session, plus total count.
	GetEvents(sessionID string, offset, limit int) ([]RecordingEvent, int, error)
	// DeleteRecording removes the JSONL file from disk.
	DeleteRecording(sessionID string) error
}

// DefaultSessionIdleTimeout is the maximum time a recording session can be idle
// (no events recorded) before it is reaped to reclaim file handles and semaphore slots.
const DefaultSessionIdleTimeout = 30 * time.Minute

// activeRecording holds state for a session currently being recorded.
type activeRecording struct {
	mu           sync.Mutex
	file         *os.File
	encoder      *json.Encoder
	sequence     int
	metadata     SessionRecording
	closed       bool      // set when MaxFileSize exceeded
	lastActivity time.Time // updated on every event, used by the reaper
}

// FileRecorder writes sessions as JSONL files on the local filesystem.
type FileRecorder struct {
	mu         sync.Mutex
	config     RecordingConfig
	sessions   map[string]*activeRecording
	compiled   []*regexp.Regexp // compiled redact patterns
	logger     *slog.Logger
	sem        chan struct{} // semaphore limiting concurrent recordings (A7c)
	stopReaper chan struct{} // signals the reaper goroutine to stop
	reaperWg   sync.WaitGroup // tracks reaper goroutine for clean shutdown (L-20)
	stopOnce   sync.Once      // H-15: prevents double-close race on stopReaper
}

// NewFileRecorder creates a FileRecorder with the given config.
// It creates StorageDir if it does not exist.
func NewFileRecorder(config RecordingConfig, logger *slog.Logger) (*FileRecorder, error) {
	if err := os.MkdirAll(config.StorageDir, 0o755); err != nil {
		return nil, fmt.Errorf("recording: create storage dir %q: %w", config.StorageDir, err)
	}
	compiled, err := compilePatterns(config.RedactPatterns)
	if err != nil {
		return nil, err
	}
	fr := &FileRecorder{
		config:     config,
		sessions:   make(map[string]*activeRecording),
		compiled:   compiled,
		logger:     logger,
		sem:        make(chan struct{}, DefaultMaxConcurrentRecordings),
		stopReaper: make(chan struct{}),
	}
	fr.reaperWg.Add(1)
	go fr.reapOrphanedSessions()
	return fr, nil
}

// GetConfig returns the current recording configuration.
func (r *FileRecorder) GetConfig() RecordingConfig {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.config
}

// UpdateConfig hot-reloads the recorder configuration.
// If the StorageDir changed, it creates the new directory (best-effort).
func (r *FileRecorder) UpdateConfig(config RecordingConfig) error {
	compiled, err := compilePatterns(config.RedactPatterns)
	if err != nil {
		return fmt.Errorf("invalid redact pattern: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Create new storage dir if it changed (best-effort, log on failure).
	if config.StorageDir != r.config.StorageDir && config.StorageDir != "" {
		if err := os.MkdirAll(config.StorageDir, 0o755); err != nil {
			r.logger.Warn("recording: failed to create new storage dir",
				"dir", config.StorageDir, "error", err)
		}
	}

	r.config = config
	r.compiled = compiled
	return nil
}

// startSessionIfNeeded atomically checks whether a session is already active and
// starts it only if it is not. This prevents the TOCTOU race when multiple
// goroutines call OnAuditRecord for the same session concurrently: a nil
// placeholder is inserted under the lock so that concurrent callers see
// "exists" and skip, while the first caller proceeds to create the file.
func (r *FileRecorder) startSessionIfNeeded(sessionID, identityID, identityName string) error {
	if err := ValidateSessionID(sessionID); err != nil {
		return err
	}
	r.mu.Lock()
	if !r.config.Enabled {
		r.mu.Unlock()
		return ErrRecordingDisabled
	}
	if _, exists := r.sessions[sessionID]; exists {
		r.mu.Unlock()
		return nil // already started by another goroutine
	}
	// Check semaphore (non-blocking): reject if at capacity (A7c).
	select {
	case r.sem <- struct{}{}:
		// Acquired slot
	default:
		r.mu.Unlock()
		r.logger.Warn("recording: max concurrent recordings reached, skipping",
			"session_id", sessionID)
		return ErrMaxRecordingsReached
	}

	// Reserve the slot with a nil placeholder so concurrent callers skip.
	r.sessions[sessionID] = nil
	cfg := r.config
	r.mu.Unlock()

	// File creation is outside the lock (per-session, no contention).
	ts := time.Now().UTC()
	filename := fmt.Sprintf("%s_%s.jsonl", sessionID, ts.Format("20060102T150405Z"))
	filePath := filepath.Join(cfg.StorageDir, filename)

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		// Remove the placeholder and release semaphore on failure.
		r.mu.Lock()
		delete(r.sessions, sessionID)
		r.mu.Unlock()
		<-r.sem
		return fmt.Errorf("recording: create file %q: %w", filePath, err)
	}

	enc := json.NewEncoder(f)
	rec := &activeRecording{
		file:    f,
		encoder: enc,
		metadata: SessionRecording{
			SessionID:    sessionID,
			IdentityID:   identityID,
			IdentityName: identityName,
			StartedAt:    ts,
			FilePath:     filePath,
		},
		lastActivity: ts,
	}

	// Write SessionStart event (sequence 1).
	startEvent := RecordingEvent{
		Sequence:     1,
		Timestamp:    ts,
		EventType:    EventSessionStart,
		SessionID:    sessionID,
		IdentityID:   identityID,
		IdentityName: identityName,
	}
	rec.sequence = 1
	if err := enc.Encode(startEvent); err != nil {
		_ = f.Close()
		_ = os.Remove(filePath)
		r.mu.Lock()
		delete(r.sessions, sessionID)
		r.mu.Unlock()
		<-r.sem
		return fmt.Errorf("recording: write session start: %w", err)
	}

	// Replace the nil placeholder with the real recording.
	r.mu.Lock()
	r.sessions[sessionID] = rec
	r.mu.Unlock()
	return nil
}

// StartSession creates a JSONL file for the session and writes a SessionStart event.
func (r *FileRecorder) StartSession(sessionID, identityID, identityName string) error {
	if err := ValidateSessionID(sessionID); err != nil {
		return err
	}
	r.mu.Lock()
	cfg := r.config
	r.mu.Unlock()

	if !cfg.Enabled {
		return ErrRecordingDisabled
	}

	// Acquire semaphore slot (A7c).
	select {
	case r.sem <- struct{}{}:
		// Acquired slot
	default:
		r.logger.Warn("recording: max concurrent recordings reached, skipping",
			"session_id", sessionID)
		return ErrMaxRecordingsReached
	}

	ts := time.Now().UTC()
	filename := fmt.Sprintf("%s_%s.jsonl", sessionID, ts.Format("20060102T150405Z"))
	filePath := filepath.Join(cfg.StorageDir, filename)

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		<-r.sem
		return fmt.Errorf("recording: create file %q: %w", filePath, err)
	}

	enc := json.NewEncoder(f)

	rec := &activeRecording{
		file:    f,
		encoder: enc,
		metadata: SessionRecording{
			SessionID:    sessionID,
			IdentityID:   identityID,
			IdentityName: identityName,
			StartedAt:    ts,
			FilePath:     filePath,
		},
		lastActivity: ts,
	}

	// Write SessionStart event (sequence 1).
	startEvent := RecordingEvent{
		Sequence:     1,
		Timestamp:    ts,
		EventType:    EventSessionStart,
		SessionID:    sessionID,
		IdentityID:   identityID,
		IdentityName: identityName,
	}
	rec.sequence = 1
	if err := enc.Encode(startEvent); err != nil {
		_ = f.Close()
		_ = os.Remove(filePath)
		<-r.sem
		return fmt.Errorf("recording: write session start: %w", err)
	}

	r.mu.Lock()
	r.sessions[sessionID] = rec
	r.mu.Unlock()

	return nil
}

// RecordEvent appends a RecordingEvent to the session's JSONL file.
func (r *FileRecorder) RecordEvent(sessionID string, event RecordingEvent) error {
	r.mu.Lock()
	rec, ok := r.sessions[sessionID]
	cfg := r.config
	compiled := r.compiled
	r.mu.Unlock()

	if !ok || rec == nil {
		// Session not in memory, or nil placeholder (startSessionIfNeeded in progress).
		return nil
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()

	if rec.closed {
		return nil
	}

	// Update activity timestamp for reaper (M-19).
	rec.lastActivity = time.Now()

	// Apply privacy mode.
	if !cfg.RecordPayloads {
		event.RequestArgs = nil
		event.ResponseBody = ""
	} else {
		// Merge user-defined patterns with built-in PII patterns when AutoRedactPII is on.
		effective := effectivePatterns(compiled, cfg.AutoRedactPII)
		if len(effective) > 0 {
			// Apply redaction to ResponseBody.
			event.ResponseBody = applyRedaction(event.ResponseBody, effective)
			// Apply redaction recursively to all string values in RequestArgs,
			// including nested maps and arrays (NOTE-06-03).
			if len(event.RequestArgs) > 0 {
				redacted := make(map[string]interface{}, len(event.RequestArgs))
				for k, v := range event.RequestArgs {
					redacted[k] = redactValue(v, effective)
				}
				event.RequestArgs = redacted
			}
		}
	}

	// Assign sequence number.
	rec.sequence++
	event.Sequence = rec.sequence
	event.SessionID = sessionID

	if err := rec.encoder.Encode(event); err != nil {
		return fmt.Errorf("recording: write event: %w", err)
	}
	if err := rec.file.Sync(); err != nil {
		return fmt.Errorf("recording: fsync event: %w", err)
	}

	// Update metadata counters.
	rec.metadata.EventCount++
	if event.Decision == "deny" || event.Decision == "blocked" {
		rec.metadata.DenyCount++
	}

	// Check file size if limit is set.
	if cfg.MaxFileSize > 0 {
		info, err := rec.file.Stat()
		if err == nil && info.Size() >= cfg.MaxFileSize {
			rec.metadata.FileSize = info.Size()
			r.logger.Warn("recording: max file size reached, stopping recording",
				"session_id", sessionID,
				"file", rec.metadata.FilePath,
				"size", info.Size())
			if syncErr := rec.file.Sync(); syncErr != nil {
				r.logger.Error("recording: fsync failed before close",
					"session_id", sessionID, "error", syncErr)
			}
			if closeErr := rec.file.Close(); closeErr != nil {
				r.logger.Error("recording: close file failed",
					"session_id", sessionID, "error", closeErr)
			}
			rec.closed = true
		} else if err == nil {
			rec.metadata.FileSize = info.Size()
		}
	}

	return nil
}

// EndSession writes a SessionEnd event and closes the JSONL file.
func (r *FileRecorder) EndSession(sessionID string) error {
	r.mu.Lock()
	rec, ok := r.sessions[sessionID]
	if ok {
		delete(r.sessions, sessionID)
	}
	r.mu.Unlock()

	if !ok {
		return nil
	}

	// Release semaphore slot (A7c).
	defer func() { <-r.sem }()

	rec.mu.Lock()
	defer rec.mu.Unlock()

	if rec.closed {
		return nil
	}

	ts := time.Now().UTC()
	rec.sequence++
	endEvent := RecordingEvent{
		Sequence:     rec.sequence,
		Timestamp:    ts,
		EventType:    EventSessionEnd,
		SessionID:    sessionID,
		IdentityID:   rec.metadata.IdentityID,
		IdentityName: rec.metadata.IdentityName,
	}
	if err := rec.encoder.Encode(endEvent); err != nil {
		r.logger.Warn("recording: write session end event failed", "error", err)
	}

	if err := rec.file.Sync(); err != nil {
		r.logger.Warn("recording: fsync failed before close", "session_id", sessionID, "error", err)
	}
	if err := rec.file.Close(); err != nil {
		r.logger.Warn("recording: close file failed", "error", err)
	}

	return nil
}

// ListRecordings scans StorageDir and returns metadata for all JSONL files,
// sorted by StartedAt descending.
func (r *FileRecorder) ListRecordings() ([]SessionRecording, error) {
	r.mu.Lock()
	cfg := r.config
	r.mu.Unlock()

	pattern := filepath.Join(cfg.StorageDir, "*.jsonl")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("recording: glob %q: %w", pattern, err)
	}

	var recordings []SessionRecording
	for _, path := range matches {
		rec, err := r.readFileMetadata(path)
		if err != nil {
			r.logger.Warn("recording: skip unreadable file", "file", path, "error", err)
			continue
		}
		recordings = append(recordings, *rec)
	}

	sort.Slice(recordings, func(i, j int) bool {
		return recordings[i].StartedAt.After(recordings[j].StartedAt)
	})

	return recordings, nil
}

// GetRecording returns metadata for a single session.
func (r *FileRecorder) GetRecording(sessionID string) (*SessionRecording, error) {
	if err := ValidateSessionID(sessionID); err != nil {
		return nil, err
	}
	path, err := r.sessionFilePath(sessionID)
	if err != nil {
		return nil, err
	}
	return r.readFileMetadata(path)
}

// GetEvents returns paginated events for a session using streaming json.Decoder.
// Only the requested page of events is held in memory; other events are decoded
// into a discard variable. This eliminates the OOM risk for large files and
// removes the bufio.Scanner 1MB line limit (NOTE-06-02, NOTE-06-04).
// Returns (events, totalCount, error).
func (r *FileRecorder) GetEvents(sessionID string, offset, limit int) ([]RecordingEvent, int, error) {
	if limit <= 0 {
		return []RecordingEvent{}, 0, fmt.Errorf("recording: limit must be > 0, got %d", limit)
	}
	if err := ValidateSessionID(sessionID); err != nil {
		return nil, 0, err
	}
	path, err := r.sessionFilePath(sessionID)
	if err != nil {
		return nil, 0, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("recording: open %q: %w", path, err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	var events []RecordingEvent
	total := 0

	// L-23: count only successfully decoded events in total, not all lines.
	for dec.More() {
		if total >= offset && total < offset+limit {
			var event RecordingEvent
			if err := dec.Decode(&event); err == nil {
				events = append(events, event)
				total++
			}
		} else {
			var discard json.RawMessage
			if err := dec.Decode(&discard); err == nil {
				total++
			}
		}
	}

	if events == nil {
		events = []RecordingEvent{}
	}
	return events, total, nil
}

// DeleteRecording removes the JSONL file from disk and cleans up any in-memory
// state for the session. This ensures that if the session is still active, new
// events will trigger creation of a fresh recording file instead of being lost
// (BUG-04 fix).
func (r *FileRecorder) DeleteRecording(sessionID string) error {
	if err := ValidateSessionID(sessionID); err != nil {
		return err
	}
	path, err := r.sessionFilePath(sessionID)
	if err != nil {
		return err
	}

	// Remove in-memory session state BEFORE deleting the file.
	// This ensures startSessionIfNeeded will create a new file on the next event.
	r.mu.Lock()
	rec, exists := r.sessions[sessionID]
	if exists {
		delete(r.sessions, sessionID)
	}
	r.mu.Unlock()

	// Close the file handle and release semaphore if the session was active in memory.
	if exists && rec != nil {
		rec.mu.Lock()
		if !rec.closed {
			if syncErr := rec.file.Sync(); syncErr != nil && r.logger != nil {
				r.logger.Error("recording: fsync failed before delete",
					"error", syncErr)
			}
			if closeErr := rec.file.Close(); closeErr != nil && r.logger != nil {
				r.logger.Error("recording: close failed before delete",
					"error", closeErr)
			}
			rec.closed = true
		}
		rec.mu.Unlock()
		<-r.sem // Release semaphore slot (A7c)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("recording: delete %q: %w", path, err)
	}
	return nil
}

// sessionFilePath finds the JSONL file for a session by glob.
func (r *FileRecorder) sessionFilePath(sessionID string) (string, error) {
	r.mu.Lock()
	cfg := r.config
	r.mu.Unlock()

	pattern := filepath.Join(cfg.StorageDir, sessionID+"_*.jsonl")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return "", fmt.Errorf("recording: glob %q: %w", pattern, err)
	}
	if len(matches) == 0 {
		return "", ErrRecordingNotFound
	}
	return matches[0], nil
}

// readFileMetadata opens a JSONL file and builds a SessionRecording from its contents.
// Uses json.Decoder for streaming reads, avoiding the bufio.Scanner 1MB line limit.
func (r *FileRecorder) readFileMetadata(path string) (*SessionRecording, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("recording: open %q: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("recording: stat %q: %w", path, err)
	}

	var rec SessionRecording
	rec.FilePath = path
	rec.FileSize = info.Size()

	dec := json.NewDecoder(f)
	eventCount := 0

	for dec.More() {
		var event RecordingEvent
		if err := dec.Decode(&event); err != nil {
			continue
		}

		if eventCount == 0 {
			// First event: extract session metadata.
			rec.SessionID = event.SessionID
			rec.IdentityID = event.IdentityID
			rec.IdentityName = event.IdentityName
			rec.StartedAt = event.Timestamp
		}

		if event.EventType == EventSessionEnd {
			t := event.Timestamp
			rec.EndedAt = &t
		}

		if event.Decision == "deny" || event.Decision == "blocked" {
			rec.DenyCount++
		}

		eventCount++
	}

	rec.EventCount = eventCount

	// If we couldn't read the session ID from file, try to parse from filename.
	if rec.SessionID == "" {
		base := filepath.Base(path)
		if idx := strings.Index(base, "_"); idx > 0 {
			rec.SessionID = base[:idx]
		}
	}

	return &rec, nil
}

// CloseAllSessions syncs and closes every active recording session, releases
// semaphore slots, and clears the sessions map. Call this during shutdown to
// avoid leaking file handles and losing buffered data (M-28).
func (r *FileRecorder) CloseAllSessions() {
	r.mu.Lock()
	snapshot := make(map[string]*activeRecording, len(r.sessions))
	for id, rec := range r.sessions {
		snapshot[id] = rec
		delete(r.sessions, id)
	}
	r.mu.Unlock()

	for id, rec := range snapshot {
		if rec == nil {
			continue
		}
		rec.mu.Lock()
		if !rec.closed {
			if r.logger != nil {
				r.logger.Info("recording: closing session on shutdown",
					"session_id", id)
			}
			if syncErr := rec.file.Sync(); syncErr != nil && r.logger != nil {
				r.logger.Error("recording: fsync failed on shutdown",
					"session_id", id, "error", syncErr)
			}
			if closeErr := rec.file.Close(); closeErr != nil && r.logger != nil {
				r.logger.Error("recording: close failed on shutdown",
					"session_id", id, "error", closeErr)
			}
			rec.closed = true
		}
		rec.mu.Unlock()
		<-r.sem // release semaphore slot
	}
}

// StopReaper terminates the background reaper goroutine and waits for it to exit.
// H-15: Uses sync.Once to prevent double-close race condition on stopReaper channel.
// Safe to call multiple times and concurrently.
func (r *FileRecorder) StopReaper() {
	r.stopOnce.Do(func() {
		close(r.stopReaper)
	})
	r.reaperWg.Wait()
}

// reapOrphanedSessions periodically checks for sessions that have been idle
// longer than DefaultSessionIdleTimeout and closes them to reclaim file handles
// and semaphore slots (M-19).
func (r *FileRecorder) reapOrphanedSessions() {
	defer r.reaperWg.Done()
	ticker := time.NewTicker(DefaultSessionIdleTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopReaper:
			return
		case <-ticker.C:
			r.reapStale()
		}
	}
}

// reapStale closes sessions that have been idle longer than DefaultSessionIdleTimeout.
func (r *FileRecorder) reapStale() {
	cutoff := time.Now().Add(-DefaultSessionIdleTimeout)

	r.mu.Lock()
	var stale []string
	for id, rec := range r.sessions {
		if rec == nil {
			continue
		}
		rec.mu.Lock()
		idle := rec.lastActivity.Before(cutoff) && !rec.closed
		rec.mu.Unlock()
		if idle {
			stale = append(stale, id)
		}
	}
	// Remove stale sessions from map while still holding r.mu.
	staleRecs := make(map[string]*activeRecording, len(stale))
	for _, id := range stale {
		staleRecs[id] = r.sessions[id]
		delete(r.sessions, id)
	}
	r.mu.Unlock()

	// Close file handles and release semaphore outside the main lock.
	for id, rec := range staleRecs {
		if rec == nil {
			continue
		}
		rec.mu.Lock()
		if !rec.closed {
			if r.logger != nil {
				r.logger.Warn("recording: reaping orphaned session",
					"session_id", id,
					"idle_since", rec.lastActivity)
			}
			if syncErr := rec.file.Sync(); syncErr != nil && r.logger != nil {
				r.logger.Error("recording: fsync failed on orphaned session",
					"session_id", id, "error", syncErr)
			}
			if closeErr := rec.file.Close(); closeErr != nil && r.logger != nil {
				r.logger.Error("recording: close failed on orphaned session",
					"session_id", id, "error", closeErr)
			}
			rec.closed = true
		}
		rec.mu.Unlock()
		<-r.sem // release semaphore slot
	}
}

// redactValue recursively traverses v and applies redaction patterns to all
// string values, including those nested inside maps and arrays (NOTE-06-03).
func redactValue(v interface{}, patterns []*regexp.Regexp) interface{} {
	switch val := v.(type) {
	case string:
		return applyRedaction(val, patterns)
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, inner := range val {
			result[k] = redactValue(inner, patterns)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, inner := range val {
			result[i] = redactValue(inner, patterns)
		}
		return result
	default:
		return v
	}
}

// applyRedaction replaces all occurrences of pattern matches in s with [REDACTED].
func applyRedaction(s string, patterns []*regexp.Regexp) string {
	for _, p := range patterns {
		s = p.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

// builtinPIIPatterns are well-known PII/secret patterns applied when AutoRedactPII is enabled.
// Based on the content scanner patterns, defined here to avoid import cycles.
// Minor variations exist (e.g., broader phone matching) suited for redaction use-case.
var builtinPIIPatterns = []string{
	`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`,                                            // email
	`\b(?:\d[ -]*?){13,19}\b`,                                                                            // credit card
	`\b\d{3}-\d{2}-\d{4}\b`,                                                                              // US SSN
	`\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b`,                          // UK National Insurance
	`\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}(?:[-.\s]?\d{2,4})?\b`,             // phone number
	`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`,                                                                      // AWS key
	`\bAIza[A-Za-z0-9_\-]{35}\b`,                                                                         // GCP key
	`\b[a-zA-Z0-9/+]{86}==`,                                                                               // Azure storage key
	`\b(?:sk|pk|rk)_(test|live)_[A-Za-z0-9]{24,}\b`,                                                      // Stripe key
	`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b`,                                                     // GitHub token
	`(?i)(?:password|passwd|pwd|secret|token|api_key|apikey|api-key)\s*[:=]\s*['"]?[^\s'"]{8,}['"]?`,      // generic secret
}

// compiledPIIPatterns caches the compiled built-in PII patterns (immutable after init).
var compiledPIIPatterns []*regexp.Regexp

func init() {
	for _, p := range builtinPIIPatterns {
		compiledPIIPatterns = append(compiledPIIPatterns, regexp.MustCompile(p))
	}
}

// compilePatterns compiles a slice of regex pattern strings.
func compilePatterns(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("recording: invalid redact pattern %q: %w", p, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

// effectivePatterns returns the compiled patterns to use for redaction,
// including built-in PII patterns when AutoRedactPII is enabled.
func effectivePatterns(userPatterns []*regexp.Regexp, autoRedact bool) []*regexp.Regexp {
	if !autoRedact {
		return userPatterns
	}
	// Combine user patterns + built-in PII patterns (no duplicates needed since
	// builtinPIIPatterns are complex regexes unlikely to overlap with user input).
	combined := make([]*regexp.Regexp, 0, len(userPatterns)+len(compiledPIIPatterns))
	combined = append(combined, userPatterns...)
	combined = append(combined, compiledPIIPatterns...)
	return combined
}
