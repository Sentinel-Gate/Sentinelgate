package admin

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
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
}

// recordingConfigResponse is the API representation of the recording configuration.
type recordingConfigResponse struct {
	Enabled        bool     `json:"enabled"`
	RecordPayloads bool     `json:"record_payloads"`
	MaxFileSize    int64    `json:"max_file_size"`
	RetentionDays  int      `json:"retention_days"`
	RedactPatterns []string `json:"redact_patterns"`
	StorageDir     string   `json:"storage_dir"`
}

// recordingConfigRequest is the JSON body for PUT /admin/api/v1/recordings/config.
type recordingConfigRequest struct {
	Enabled        bool     `json:"enabled"`
	RecordPayloads bool     `json:"record_payloads"`
	MaxFileSize    int64    `json:"max_file_size"`
	RetentionDays  int      `json:"retention_days"`
	RedactPatterns []string `json:"redact_patterns"`
	StorageDir     string   `json:"storage_dir"`
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
		if t, err := time.Parse(time.RFC3339, fromFilter); err == nil {
			fromTime = t
		}
	}
	if toFilter != "" {
		if t, err := time.Parse(time.RFC3339, toFilter); err == nil {
			toTime = t
		}
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
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 1000 {
				n = 1000
			}
			limit = n
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

	// Fetch all events (no pagination limit).
	events, _, err := h.recordingService.GetEvents(id, 0, 1<<30)
	if err != nil {
		if errors.Is(err, recording.ErrRecordingNotFound) {
			h.respondError(w, http.StatusNotFound, "recording not found")
			return
		}
		h.logger.Error("failed to export recording", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to export recording")
		return
	}

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, id))
		w.WriteHeader(http.StatusOK)

		cw := csv.NewWriter(w)
		_ = cw.Write([]string{
			"sequence", "timestamp", "event_type", "tool_name",
			"decision", "reason", "latency_micros",
		})
		for _, e := range events {
			_ = cw.Write([]string{
				strconv.Itoa(e.Sequence),
				e.Timestamp.UTC().Format(time.RFC3339Nano),
				string(e.EventType),
				e.ToolName,
				e.Decision,
				e.Reason,
				strconv.FormatInt(e.LatencyMicros, 10),
			})
		}
		cw.Flush()

	default: // "json"
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, id))
		w.WriteHeader(http.StatusOK)

		result := make([]recordingEventResponse, 0, len(events))
		for _, e := range events {
			result = append(result, toRecordingEventResponse(e))
		}
		if err := json.NewEncoder(w).Encode(result); err != nil {
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
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	cfg := recording.RecordingConfig{
		Enabled:        req.Enabled,
		RecordPayloads: req.RecordPayloads,
		MaxFileSize:    req.MaxFileSize,
		RetentionDays:  req.RetentionDays,
		RedactPatterns: req.RedactPatterns,
		StorageDir:     req.StorageDir,
	}

	if err := cfg.Validate(); err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Apply config to FileRecorder (hot-reload, no restart needed).
	h.recordingService.UpdateConfig(cfg)

	// Update RetentionCleaner config (value copy, not pointer).
	if h.retentionCleaner != nil {
		h.retentionCleaner.UpdateConfig(cfg)
	}

	// Persist to state.json.
	if err := h.persistRecordingConfig(cfg); err != nil {
		h.logger.Error("failed to persist recording config to state", "error", err)
	}

	h.respondJSON(w, http.StatusOK, toRecordingConfigResponse(cfg))
}

// persistRecordingConfig writes the current RecordingConfig to state.json.
// This follows the same pattern as persistTransforms and persistQuotas.
func (h *AdminAPIHandler) persistRecordingConfig(cfg recording.RecordingConfig) error {
	appState, err := h.stateStore.Load()
	if err != nil {
		return err
	}
	appState.RecordingConfig = &state.RecordingConfigEntry{
		Enabled:        cfg.Enabled,
		RecordPayloads: cfg.RecordPayloads,
		MaxFileSize:    cfg.MaxFileSize,
		RetentionDays:  cfg.RetentionDays,
		RedactPatterns: cfg.RedactPatterns,
		StorageDir:     cfg.StorageDir,
	}
	return h.stateStore.Save(appState)
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
		}
	}
	return r
}

func toRecordingConfigResponse(cfg recording.RecordingConfig) recordingConfigResponse {
	patterns := cfg.RedactPatterns
	if patterns == nil {
		patterns = []string{}
	}
	// Return only the directory basename to avoid exposing absolute filesystem paths.
	storageDisplay := filepath.Base(cfg.StorageDir)
	if storageDisplay == "." || storageDisplay == "" {
		storageDisplay = ""
	}
	return recordingConfigResponse{
		Enabled:        cfg.Enabled,
		RecordPayloads: cfg.RecordPayloads,
		MaxFileSize:    cfg.MaxFileSize,
		RetentionDays:  cfg.RetentionDays,
		RedactPatterns: patterns,
		StorageDir:     storageDisplay,
	}
}
