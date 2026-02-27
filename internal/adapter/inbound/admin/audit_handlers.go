package admin

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// AuditQueryResponse is the JSON response for GET /admin/api/audit.
type AuditQueryResponse struct {
	Records    []AuditRecordDTO `json:"records"`
	NextCursor string           `json:"next_cursor,omitempty"`
	Count      int              `json:"count"`
}

// AuditRecordDTO is the JSON representation of an audit record.
type AuditRecordDTO struct {
	Timestamp      string                 `json:"timestamp"`
	SessionID      string                 `json:"session_id"`
	IdentityID     string                 `json:"identity_id"`
	IdentityName   string                 `json:"identity_name,omitempty"`
	ToolName       string                 `json:"tool_name"`
	ToolArguments  map[string]interface{} `json:"tool_arguments,omitempty"`
	Decision       string                 `json:"decision"`
	Reason         string                 `json:"reason"`
	RuleID         string                 `json:"rule_id"`
	RequestID      string                 `json:"request_id"`
	LatencyMicros  int64                  `json:"latency_micros"`
	Protocol       string                 `json:"protocol,omitempty"`
	Framework      string                 `json:"framework,omitempty"`
	ScanDetections int                    `json:"scan_detections"`
	ScanAction     string                 `json:"scan_action,omitempty"`
	ScanTypes      string                 `json:"scan_types,omitempty"`
}

func toDTO(r audit.AuditRecord) AuditRecordDTO {
	return AuditRecordDTO{
		Timestamp:      r.Timestamp.UTC().Format(time.RFC3339),
		SessionID:      r.SessionID,
		IdentityID:     r.IdentityID,
		IdentityName:   r.IdentityName,
		ToolName:       r.ToolName,
		ToolArguments:  r.ToolArguments,
		Decision:       r.Decision,
		Reason:         r.Reason,
		RuleID:         r.RuleID,
		RequestID:      r.RequestID,
		LatencyMicros:  r.LatencyMicros,
		Protocol:       r.Protocol,
		Framework:      r.Framework,
		ScanDetections: r.ScanDetections,
		ScanAction:     r.ScanAction,
		ScanTypes:      r.ScanTypes,
	}
}

func (h *AdminAPIHandler) handleQueryAudit(w http.ResponseWriter, r *http.Request) {
	if h.auditReader == nil {
		h.respondError(w, http.StatusServiceUnavailable, "audit reader not configured")
		return
	}
	filter, err := parseAuditFilter(r)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	records, nextCursor, err := h.auditReader.Query(filter)
	if err != nil {
		h.logger.Error("audit query failed", "error", err)
		h.respondError(w, http.StatusInternalServerError, "audit query failed")
		return
	}
	dtos := make([]AuditRecordDTO, len(records))
	for i, rec := range records {
		dtos[i] = toDTO(rec)
	}
	h.respondJSON(w, http.StatusOK, AuditQueryResponse{
		Records:    dtos,
		NextCursor: nextCursor,
		Count:      len(dtos),
	})
}

func (h *AdminAPIHandler) handleAuditStream(w http.ResponseWriter, r *http.Request) {
	if h.auditReader == nil {
		h.respondError(w, http.StatusServiceUnavailable, "audit reader not configured")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.respondError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var lastSeen time.Time
	recent := h.auditReader.GetRecent(50)
	for i := len(recent) - 1; i >= 0; i-- {
		rec := recent[i]
		data, err := json.Marshal(toDTO(rec))
		if err != nil {
			continue
		}
		_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
		if rec.Timestamp.After(lastSeen) {
			lastSeen = rec.Timestamp
		}
	}
	flusher.Flush()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			records := h.auditReader.GetRecent(20)
			newRecords := make([]audit.AuditRecord, 0)
			for _, rec := range records {
				if rec.Timestamp.After(lastSeen) {
					newRecords = append(newRecords, rec)
				}
			}
			for i := len(newRecords) - 1; i >= 0; i-- {
				rec := newRecords[i]
				data, err := json.Marshal(toDTO(rec))
				if err != nil {
					continue
				}
				_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
				if rec.Timestamp.After(lastSeen) {
					lastSeen = rec.Timestamp
				}
			}
			if len(newRecords) > 0 {
				flusher.Flush()
			}
		}
	}
}

func (h *AdminAPIHandler) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if h.auditReader == nil {
		h.respondError(w, http.StatusServiceUnavailable, "audit reader not configured")
		return
	}
	filter, err := parseAuditFilter(r)
	if err != nil {
		h.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if filter.Limit == 0 || filter.Limit == 100 {
		filter.Limit = 1000
	}
	records, _, err := h.auditReader.Query(filter)
	if err != nil {
		h.logger.Error("audit export failed", "error", err)
		h.respondError(w, http.StatusInternalServerError, "audit export failed")
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=audit-export.csv")
	w.WriteHeader(http.StatusOK)
	writer := csv.NewWriter(w)
	defer writer.Flush()
	_ = writer.Write([]string{
		"timestamp", "session_id", "identity_id", "tool_name",
		"decision", "reason", "rule_id", "request_id", "latency_micros",
		"protocol", "framework",
	})
	for _, rec := range records {
		_ = writer.Write([]string{
			rec.Timestamp.UTC().Format(time.RFC3339),
			rec.SessionID,
			rec.IdentityID,
			rec.ToolName,
			rec.Decision,
			rec.Reason,
			rec.RuleID,
			rec.RequestID,
			strconv.FormatInt(rec.LatencyMicros, 10),
			rec.Protocol,
			rec.Framework,
		})
	}
}

func parseAuditFilter(r *http.Request) (audit.AuditFilter, error) {
	q := r.URL.Query()
	filter := audit.AuditFilter{}
	if decision := q.Get("decision"); decision != "" {
		if decision != "allow" && decision != "deny" {
			return filter, fmt.Errorf("invalid decision filter: must be 'allow' or 'deny'")
		}
		filter.Decision = decision
	}
	if protocol := q.Get("protocol"); protocol != "" {
		if protocol != "mcp" && protocol != "http" && protocol != "websocket" && protocol != "runtime" {
			return filter, fmt.Errorf("invalid protocol filter: must be 'mcp', 'http', 'websocket', or 'runtime'")
		}
		filter.Protocol = protocol
	}
	filter.ToolName = q.Get("tool")
	filter.UserID = q.Get("user")
	if startStr := q.Get("start"); startStr != "" {
		t, err := time.Parse(time.RFC3339, startStr)
		if err != nil {
			return filter, fmt.Errorf("invalid start time: %w", err)
		}
		filter.StartTime = t
	} else {
		filter.StartTime = time.Now().UTC().Add(-24 * time.Hour)
	}
	if endStr := q.Get("end"); endStr != "" {
		t, err := time.Parse(time.RFC3339, endStr)
		if err != nil {
			return filter, fmt.Errorf("invalid end time: %w", err)
		}
		filter.EndTime = t
	} else {
		filter.EndTime = time.Now().UTC()
	}
	if limitStr := q.Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 1 {
			return filter, fmt.Errorf("invalid limit: must be a positive integer")
		}
		if limit > 1000 {
			limit = 1000
		}
		filter.Limit = limit
	} else {
		filter.Limit = 100
	}
	filter.Cursor = q.Get("cursor")
	return filter, nil
}
