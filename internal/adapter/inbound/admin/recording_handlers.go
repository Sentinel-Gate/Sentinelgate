package admin

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/recording"
)

// recordingListItem is the API representation of a session recording in list responses.
type recordingListItem struct {
	SessionID    string     `json:"session_id"`
	IdentityID   string     `json:"identity_id"`
	IdentityName string     `json:"identity_name"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	EventCount   int        `json:"event_count"`
	DenyCount    int        `json:"deny_count"`
	FileSize     int64      `json:"file_size"`
}

// recordingDetailResponse is the API representation of a single recording.
type recordingDetailResponse struct {
	SessionID    string     `json:"session_id"`
	IdentityID   string     `json:"identity_id"`
	IdentityName string     `json:"identity_name"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	EventCount   int        `json:"event_count"`
	DenyCount    int        `json:"deny_count"`
	FileSize     int64      `json:"file_size"`
}

// recordingEventResponse is the API representation of a single recording event.
type recordingEventResponse struct {
	Sequence          int                    `json:"sequence"`
	Timestamp         time.Time              `json:"timestamp"`
	EventType         string                 `json:"event_type"`
	SessionID         string                 `json:"session_id"`
	IdentityID        string                 `json:"identity_id,omitempty"`
	IdentityName      string                 `json:"identity_name,omitempty"`
	ToolName          string                 `json:"tool_name,omitempty"`
	Decision          string                 `json:"decision,omitempty"`
	Reason            string                 `json:"reason,omitempty"`
	RuleID            string                 `json:"rule_id,omitempty"`
	RequestArgs       map[string]interface{} `json:"request_args,omitempty"`
	ResponseBody      string                 `json:"response_body,omitempty"`
	TransformsApplied []string               `json:"transforms_applied,omitempty"`
	QuotaState        *quotaStateResponse    `json:"quota_state,omitempty"`
	LatencyMicros     int64                  `json:"latency_micros,omitempty"`
}

// quotaStateResponse mirrors recording.QuotaSnapshot with json tags.
type quotaStateResponse struct {
	TotalCalls  int64 `json:"total_calls"`
	ReadCalls   int64 `json:"read_calls"`
	WriteCalls  int64 `json:"write_calls"`
	DeleteCalls int64 `json:"delete_calls"`
	TotalLimit  int64 `json:"total_limit,omitempty"`
	WriteLimit  int64 `json:"write_limit,omitempty"`
	DeleteLimit int64 `json:"delete_limit,omitempty"`
	MinuteLimit int64 `json:"minute_limit,omitempty"`
}

// recordingConfigResponse is the API representation of the recording configuration.
type recordingConfigResponse struct {
	Enabled        bool     `json:"enabled"`
	RecordPayloads bool     `json:"record_payloads"`
	MaxFileSize    int64    `json:"max_file_size"`
	RetentionDays  int      `json:"retention_days"`
	RedactPatterns []string `json:"redact_patterns"`
	StorageDir     string   `json:"storage_dir"`
	AutoRedactPII  bool     `json:"auto_redact_pii"`
}

// recordingConfigRequest is the JSON body for PUT /admin/api/v1/recordings/config.
type recordingConfigRequest struct {
	Enabled        bool     `json:"enabled"`
	RecordPayloads bool     `json:"record_payloads"`
	MaxFileSize    int64    `json:"max_file_size"`
	RetentionDays  int      `json:"retention_days"`
	RedactPatterns []string `json:"redact_patterns"`
	StorageDir     string   `json:"storage_dir"`
	AutoRedactPII  bool     `json:"auto_redact_pii"`
}

// paginatedEventsResponse wraps a page of recording events with pagination metadata.
type paginatedEventsResponse struct {
	Events []recordingEventResponse `json:"events"`
	Total  int                      `json:"total"`
	Offset int                      `json:"offset"`
	Limit  int                      `json:"limit"`
}

// handleListRecordings returns all session recordings, with optional filtering.
// GET /admin/api/v1/recordings
func (h *AdminAPIHandler) handleListRecordings(w http.ResponseWriter, r *http.Request) {
	if h.recordingService == nil {
		h.respondError(w, http.StatusInternalServerError, "recording service not configured")
		return
	}

	recordings, err := h.recordingService.ListRecordings()
	if err != nil {
		h.logger.Error("failed to list recordings", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to list recordings")
		return
	}

	// Apply optional filters from query params.
	identityFilter := r.URL.Query().Get("identity")
	fromFilter := r.URL.Query().Get("from")
	toFilter := r.URL.Query().Get("to")
	hasDeniesFilter := r.URL.Query().Get("has_denies")

	var fromTime, toTime time.Time
	if fromFilter != "" {
		t, err := time.Parse(time.RFC3339, fromFilter)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid 'from' parameter: "+fromFilter)
			return
		}
		fromTime = t
	}
	if toFilter != "" {
		t, err := time.Parse(time.RFC3339, toFilter)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid 'to' parameter: "+toFilter)
			return
		}
		toTime = t
	}
	onlyWithDenies := hasDeniesFilter == "true" || hasDeniesFilter == "1"

	result := make([]recordingListItem, 0, len(recordings))
	for _, rec := range recordings {
		if identityFilter != "" && rec.IdentityID != identityFilter {
			continue
		}
		if !fromTime.IsZero() && rec.StartedAt.Before(fromTime) {
			continue
		}
		if !toTime.IsZero() && rec.StartedAt.After(toTime) {
			continue
		}
		if onlyWithDenies && rec.DenyCount == 0 {
			continue
		}
		result = append(result, toRecordingListItem(rec))
	}

	h.respondJSON(w, http.StatusOK, result)
}

// handleGetRecording returns metadata for a single recording.
// GET /admin/api/v1/recordings/{id}
func (h *AdminAPIHandler) handleGetRecording(w http.ResponseWriter, r *http.Request) {
	if h.recordingService == nil {
		h.respondError(w, http.StatusInternalServerError, "recording service not configured")
		return
	}

	id := h.pathParam(r, "id")

	rec, err := h.recordingService.GetRecording(id)
	if err != nil {
		if errors.Is(err, recording.ErrRecordingNotFound) {
			h.respondError(w, http.StatusNotFound, "recording not found")
			return
		}
		h.logger.Error("failed to get recording", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to get recording")
		return
	}

	h.respondJSON(w, http.StatusOK, toRecordingDetailResponse(rec))
}

// handleGetRecordingEvents returns paginated events for a session recording.
// GET /admin/api/v1/recordings/{id}/events
func (h *AdminAPIHandler) handleGetRecordingEvents(w http.ResponseWriter, r *http.Request) {
	if h.recordingService == nil {
		h.respondError(w, http.StatusInternalServerError, "recording service not configured")
		return
	}

	id := h.pathParam(r, "id")

	// Parse pagination query params.
	offset := 0
	limit := 100
	if s := r.URL.Query().Get("offset"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid 'offset' parameter")
			return
		}
		if v < 0 {
			h.respondError(w, http.StatusBadRequest, "offset must be non-negative") // L-13
			return
		}
		offset = v
	}
	if s := r.URL.Query().Get("limit"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil {
			h.respondError(w, http.StatusBadRequest, "invalid 'limit' parameter")
			return
		}
		if v > 0 {
			if v > 1000 {
				v = 1000
			}
			limit = v
		}
	}

	events, total, err := h.recordingService.GetEvents(id, offset, limit)
	if err != nil {
		if errors.Is(err, recording.ErrRecordingNotFound) {
			h.respondError(w, http.StatusNotFound, "recording not found")
			return
		}
		h.logger.Error("failed to get recording events", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to get recording events")
		return
	}

	resp := paginatedEventsResponse{
		Events: make([]recordingEventResponse, 0, len(events)),
		Total:  total,
		Offset: offset,
		Limit:  limit,
	}
	for _, e := range events {
		resp.Events = append(resp.Events, toRecordingEventResponse(e))
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// handleExportRecording exports all events from a recording as JSON or CSV.
// GET /admin/api/v1/recordings/{id}/export
func (h *AdminAPIHandler) handleExportRecording(w http.ResponseWriter, r *http.Request) {
	if h.recordingService == nil {
		h.respondError(w, http.StatusInternalServerError, "recording service not configured")
		return
	}

	id := h.pathParam(r, "id")
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	// Fetch all events with a hard cap to prevent memory exhaustion.
	const maxExportEvents = 100_000
	events, _, err := h.recordingService.GetEvents(id, 0, maxExportEvents)
	if err != nil {
		if errors.Is(err, recording.ErrRecordingNotFound) {
			h.respondError(w, http.StatusNotFound, "recording not found")
			return
		}
		h.logger.Error("failed to export recording", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to export recording")
		return
	}

	if len(events) == maxExportEvents {
		w.Header().Set("X-Truncated", "true")
		w.Header().Set("X-Max-Events", strconv.Itoa(maxExportEvents))
	}

	// Sanitize id for use in Content-Disposition header
	safeID := strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r == '\n' || r == '\r' {
			return '_'
		}
		return r
	}, id)

	ctx := r.Context()
	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, safeID))
		w.WriteHeader(http.StatusOK)

		cw := csv.NewWriter(w)
		_ = cw.Write([]string{
			"sequence", "timestamp", "event_type", "tool_name",
			"identity_name", "decision", "reason", "latency_micros",
			"request_args", "quota_total", "quota_reads", "quota_writes", "quota_deletes",
		})
		for _, e := range events {
			// L-35: Check for client disconnection at each iteration.
			if ctx.Err() != nil {
				return
			}
			argsStr := ""
			if len(e.RequestArgs) > 0 {
				if ab, err := json.Marshal(e.RequestArgs); err == nil {
					argsStr = string(ab)
				}
			}
			qtotal, qreads, qwrites, qdeletes := "", "", "", ""
			if e.QuotaState != nil {
				qtotal = strconv.FormatInt(e.QuotaState.TotalCalls, 10)
				qreads = strconv.FormatInt(e.QuotaState.ReadCalls, 10)
				qwrites = strconv.FormatInt(e.QuotaState.WriteCalls, 10)
				qdeletes = strconv.FormatInt(e.QuotaState.DeleteCalls, 10)
			}
			_ = cw.Write([]string{
				strconv.Itoa(e.Sequence),
				e.Timestamp.UTC().Format(time.RFC3339Nano),
				string(e.EventType),
				e.ToolName,
				csvSafe(e.IdentityName),
				e.Decision,
				e.Reason,
				strconv.FormatInt(e.LatencyMicros, 10),
				csvSafe(argsStr),
				qtotal, qreads, qwrites, qdeletes,
			})
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			h.logger.Error("csv recording export write error", "id", id, "error", err)
		}

	default: // "json"
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, safeID))
		w.WriteHeader(http.StatusOK)

		result := make([]recordingEventResponse, 0, len(events))
		for _, e := range events {
			result = append(result, toRecordingEventResponse(e))
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			h.logger.Error("failed to encode export response", "error", err)
		}
	}
}

// handleDeleteRecording removes a recording from disk.
// DELETE /admin/api/v1/recordings/{id}
func (h *AdminAPIHandler) handleDeleteRecording(w http.ResponseWriter, r *http.Request) {
	if h.recordingService == nil {
		h.respondError(w, http.StatusInternalServerError, "recording service not configured")
		return
	}

	id := h.pathParam(r, "id")

	if err := h.recordingService.DeleteRecording(id); err != nil {
		if errors.Is(err, recording.ErrRecordingNotFound) {
			h.respondError(w, http.StatusNotFound, "recording not found")
			return
		}
		h.logger.Error("failed to delete recording", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to delete recording")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleGetRecordingConfig returns the current recording configuration.
// GET /admin/api/v1/recordings/config
func (h *AdminAPIHandler) handleGetRecordingConfig(w http.ResponseWriter, r *http.Request) {
	if h.recordingService == nil {
		h.respondError(w, http.StatusInternalServerError, "recording service not configured")
		return
	}

	cfg := h.recordingService.GetConfig()
	h.respondJSON(w, http.StatusOK, toRecordingConfigResponse(cfg))
}

// handlePutRecordingConfig updates and persists the recording configuration.
// PUT /admin/api/v1/recordings/config
func (h *AdminAPIHandler) handlePutRecordingConfig(w http.ResponseWriter, r *http.Request) {
	if h.recordingService == nil {
		h.respondError(w, http.StatusInternalServerError, "recording service not configured")
		return
	}

	var req recordingConfigRequest
	if err := h.readJSON(r, &req); err != nil {
		h.handleReadJSONErr(w, err)
		return
	}

	cfg := recording.RecordingConfig{
		Enabled:        req.Enabled,
		RecordPayloads: req.RecordPayloads,
		MaxFileSize:    req.MaxFileSize,
		RetentionDays:  req.RetentionDays,
		RedactPatterns: req.RedactPatterns,
		StorageDir:     req.StorageDir,
		AutoRedactPII:  req.AutoRedactPII,
	}

	if err := cfg.Validate(); err != nil {
		h.logger.Warn("recording config validation failed", "error", err)
		h.respondError(w, http.StatusBadRequest, "invalid recording configuration")
		return
	}

	// Persist to state.json FIRST — only mutate in-memory on success.
	if err := h.persistRecordingConfig(cfg); err != nil {
		h.logger.Error("failed to persist recording config to state", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to persist recording config")
		return
	}

	// Apply config to FileRecorder (hot-reload, no restart needed).
	if err := h.recordingService.UpdateConfig(cfg); err != nil {
		h.logger.Warn("recording config update failed", "error", err)
		h.respondError(w, http.StatusBadRequest, "failed to apply recording configuration")
		return
	}

	// Update RetentionCleaner config (value copy, not pointer).
	if h.retentionCleaner != nil {
		h.retentionCleaner.UpdateConfig(cfg)
	}

	h.respondJSON(w, http.StatusOK, toRecordingConfigResponse(cfg))
}

// persistRecordingConfig writes the current RecordingConfig to state.json.
// This follows the same pattern as persistTransforms and persistQuotas.
func (h *AdminAPIHandler) persistRecordingConfig(cfg recording.RecordingConfig) error {
	return h.stateStore.Mutate(func(appState *state.AppState) error {
		appState.RecordingConfig = &state.RecordingConfigEntry{
			Enabled:        cfg.Enabled,
			RecordPayloads: cfg.RecordPayloads,
			MaxFileSize:    cfg.MaxFileSize,
			RetentionDays:  cfg.RetentionDays,
			RedactPatterns: cfg.RedactPatterns,
			StorageDir:     cfg.StorageDir,
			AutoRedactPII:  cfg.AutoRedactPII,
		}
		return nil
	})
}

// --- helpers ---

func toRecordingListItem(rec recording.SessionRecording) recordingListItem {
	return recordingListItem{
		SessionID:    rec.SessionID,
		IdentityID:   rec.IdentityID,
		IdentityName: rec.IdentityName,
		StartedAt:    rec.StartedAt,
		EndedAt:      rec.EndedAt,
		EventCount:   rec.EventCount,
		DenyCount:    rec.DenyCount,
		FileSize:     rec.FileSize,
	}
}

func toRecordingDetailResponse(rec *recording.SessionRecording) recordingDetailResponse {
	return recordingDetailResponse{
		SessionID:    rec.SessionID,
		IdentityID:   rec.IdentityID,
		IdentityName: rec.IdentityName,
		StartedAt:    rec.StartedAt,
		EndedAt:      rec.EndedAt,
		EventCount:   rec.EventCount,
		DenyCount:    rec.DenyCount,
		FileSize:     rec.FileSize,
	}
}

func toRecordingEventResponse(e recording.RecordingEvent) recordingEventResponse {
	r := recordingEventResponse{
		Sequence:          e.Sequence,
		Timestamp:         e.Timestamp,
		EventType:         string(e.EventType),
		SessionID:         e.SessionID,
		IdentityID:        e.IdentityID,
		IdentityName:      e.IdentityName,
		ToolName:          e.ToolName,
		Decision:          e.Decision,
		Reason:            e.Reason,
		RuleID:            e.RuleID,
		RequestArgs:       e.RequestArgs,
		ResponseBody:      e.ResponseBody,
		TransformsApplied: e.TransformsApplied,
		LatencyMicros:     e.LatencyMicros,
	}
	if e.QuotaState != nil {
		r.QuotaState = &quotaStateResponse{
			TotalCalls:  e.QuotaState.TotalCalls,
			ReadCalls:   e.QuotaState.ReadCalls,
			WriteCalls:  e.QuotaState.WriteCalls,
			DeleteCalls: e.QuotaState.DeleteCalls,
			TotalLimit:  e.QuotaState.TotalLimit,
			WriteLimit:  e.QuotaState.WriteLimit,
			DeleteLimit: e.QuotaState.DeleteLimit,
			MinuteLimit: e.QuotaState.MinuteLimit,
		}
	}
	return r
}

func toRecordingConfigResponse(cfg recording.RecordingConfig) recordingConfigResponse {
	patterns := cfg.RedactPatterns
	if patterns == nil {
		patterns = []string{}
	}
	// L-62: Return only the base directory name to avoid exposing absolute paths.
	storageDisplay := filepath.Base(cfg.StorageDir)
	return recordingConfigResponse{
		Enabled:        cfg.Enabled,
		RecordPayloads: cfg.RecordPayloads,
		MaxFileSize:    cfg.MaxFileSize,
		RetentionDays:  cfg.RetentionDays,
		RedactPatterns: patterns,
		StorageDir:     storageDisplay,
		AutoRedactPII:  cfg.AutoRedactPII,
	}
}
