/**
 * sessions.js — Session Recording & Replay page for SentinelGate admin UI.
 *
 * Provides administrators a visual replay experience for recorded sessions:
 *   - Filterable list of recordings with identity, date range, deny filter
 *   - Clickable rows switch to detail view with vertical event timeline
 *   - Expandable event cards showing args, transforms, quota, rule reason
 *   - Deny events highlighted in red with badge
 *   - Export as JSON or CSV per recording
 *   - Delete recording with confirmation
 *   - Config panel: enable/disable recording, retention days, redact patterns
 *
 * Data sources:
 *   GET  /admin/api/v1/recordings              → list recordings
 *   GET  /admin/api/v1/recordings/{id}         → recording metadata
 *   GET  /admin/api/v1/recordings/{id}/events  → paginated events
 *   GET  /admin/api/v1/recordings/{id}/export  → JSON or CSV download
 *   DELETE /admin/api/v1/recordings/{id}       → delete recording
 *   GET  /admin/api/v1/recordings/config       → get config
 *   PUT  /admin/api/v1/recordings/config       → update config
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // ── Module state ────────────────────────────────────────────────────

  var styleInjected = false;
  var currentMaxFileSize = 0;

  // List view state
  var recordings = [];
  var filteredRecordings = [];
  var listOffset = 0;
  var PAGE_SIZE = 50;

  // Filter state
  var filterIdentity = '';
  var filterFrom = '';
  var filterTo = '';
  var filterHasDenies = false;

  // Detail view state
  var currentRecordingId = null;
  var currentRecording = null;
  var events = [];
  var eventsOffset = 0;
  var eventsTotal = 0;
  var EVENTS_PAGE = 100;
  var expandedEventId = null;
  var timelineEventFilter = '';
  var timelineDecisionFilter = '';

  // ── CSS ─────────────────────────────────────────────────────────────

  var SESSIONS_CSS = [
    /* ── Page header ──────────────────────────────────────────────── */
    '.sessions-header {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  margin-bottom: var(--space-6);',
    '}',
    '.sessions-header h1 {',
    '  font-size: var(--text-2xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0;',
    '  letter-spacing: -0.02em;',
    '}',

    /* ── Config panel ─────────────────────────────────────────────── */
    '.config-panel {',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  background: var(--bg-primary);',
    '  margin-bottom: var(--space-5);',
    '  overflow: hidden;',
    '}',
    '.config-panel-header {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  padding: var(--space-3) var(--space-4);',
    '  cursor: pointer;',
    '  user-select: none;',
    '  border-bottom: 1px solid transparent;',
    '  transition: background var(--transition-fast);',
    '}',
    '.config-panel-header:hover {',
    '  background: var(--bg-secondary);',
    '}',
    '.config-panel-header.open {',
    '  border-bottom-color: var(--border);',
    '}',
    '.config-panel-title {',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '}',
    '.config-panel-chevron {',
    '  color: var(--text-muted);',
    '  transition: transform var(--transition-fast);',
    '}',
    '.config-panel-header.open .config-panel-chevron {',
    '  transform: rotate(180deg);',
    '}',
    '.config-panel-body {',
    '  display: none;',
    '  padding: var(--space-4);',
    '}',
    '.config-panel-body.open {',
    '  display: block;',
    '}',
    '.config-grid {',
    '  display: grid;',
    '  grid-template-columns: 1fr 1fr;',
    '  gap: var(--space-4);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.config-field {',
    '  display: flex;',
    '  flex-direction: column;',
    '  gap: var(--space-1);',
    '}',
    '.config-field label {',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-muted);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '}',
    '.config-field input[type="number"],',
    '.config-field input[type="text"] {',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  outline: none;',
    '}',
    '.config-field input:focus {',
    '  border-color: var(--accent);',
    '  box-shadow: 0 0 0 2px var(--accent-subtle);',
    '}',
    '.config-field input[readonly] {',
    '  background: var(--bg-secondary);',
    '  color: var(--text-muted);',
    '  cursor: default;',
    '}',
    '.config-toggle-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  margin-bottom: var(--space-3);',
    '}',
    '.config-toggle-label {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '}',
    '.config-privacy-warning {',
    '  font-size: var(--text-xs);',
    '  color: var(--warning);',
    '  margin-top: var(--space-1);',
    '}',
    '.config-full-row {',
    '  grid-column: 1 / -1;',
    '}',
    '.config-actions {',
    '  display: flex;',
    '  justify-content: flex-end;',
    '  gap: var(--space-2);',
    '}',

    /* ── Recording filters ────────────────────────────────────────── */
    '.recording-filters {',
    '  display: flex;',
    '  flex-wrap: wrap;',
    '  gap: var(--space-3);',
    '  align-items: flex-end;',
    '  margin-bottom: var(--space-4);',
    '}',
    '.recording-filter-group {',
    '  display: flex;',
    '  flex-direction: column;',
    '  gap: var(--space-1);',
    '}',
    '.recording-filter-group label {',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-muted);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '}',
    '.recording-filter-input {',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  outline: none;',
    '  width: 160px;',
    '}',
    '.recording-filter-input:focus {',
    '  border-color: var(--accent);',
    '  box-shadow: 0 0 0 2px var(--accent-subtle);',
    '}',
    '.recording-filter-actions {',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  align-items: flex-end;',
    '}',
    '.recording-filter-checkbox-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-secondary);',
    '  padding-bottom: var(--space-2);',
    '}',

    /* ── Recording table ──────────────────────────────────────────── */
    '.recording-table-wrap {',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  background: var(--bg-primary);',
    '  overflow: hidden;',
    '}',
    '.recording-table {',
    '  width: 100%;',
    '  border-collapse: collapse;',
    '}',
    '.recording-table th {',
    '  padding: var(--space-3) var(--space-4);',
    '  text-align: left;',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-muted);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '  background: var(--bg-secondary);',
    '  border-bottom: 1px solid var(--border);',
    '  white-space: nowrap;',
    '}',
    '.recording-row {',
    '  border-bottom: 1px solid var(--border);',
    '  cursor: pointer;',
    '  transition: background var(--transition-fast);',
    '}',
    '.recording-row:last-child {',
    '  border-bottom: none;',
    '}',
    '.recording-row:hover {',
    '  background: var(--bg-secondary);',
    '}',
    '.recording-row--has-denies {',
    '  border-left: 3px solid var(--danger);',
    '}',
    '.recording-row td {',
    '  padding: var(--space-3) var(--space-4);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  vertical-align: middle;',
    '}',
    '.recording-id {',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '}',
    '.recording-identity {',
    '  font-weight: var(--font-medium);',
    '}',
    '.recording-time {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-secondary);',
    '  white-space: nowrap;',
    '}',
    '.recording-duration {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-secondary);',
    '  white-space: nowrap;',
    '}',
    '.recording-actions-cell {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  white-space: nowrap;',
    '}',

    /* ── Deny badge ──────────────────────────────────────────────── */
    '.badge-deny-count {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  background: var(--danger-subtle, #fee2e2);',
    '  color: var(--danger, #dc2626);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  padding: 1px 6px;',
    '  border-radius: var(--radius-full);',
    '  min-width: 20px;',
    '}',
    '.badge-zero {',
    '  color: var(--text-muted);',
    '  background: transparent;',
    '}',

    /* ── Load more / empty ────────────────────────────────────────── */
    '.sessions-load-more {',
    '  display: flex;',
    '  justify-content: center;',
    '  padding: var(--space-4);',
    '}',
    '.sessions-empty {',
    '  padding: var(--space-10);',
    '  text-align: center;',
    '  color: var(--text-muted);',
    '}',
    '.sessions-empty-icon {',
    '  margin-bottom: var(--space-3);',
    '  opacity: 0.4;',
    '}',
    '.sessions-empty-text {',
    '  font-size: var(--text-sm);',
    '}',

    /* ── Detail view ──────────────────────────────────────────────── */
    '.detail-back {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-secondary);',
    '  cursor: pointer;',
    '  margin-bottom: var(--space-5);',
    '  padding: var(--space-1) 0;',
    '  background: none;',
    '  border: none;',
    '  transition: color var(--transition-fast);',
    '}',
    '.detail-back:hover {',
    '  color: var(--text-primary);',
    '}',
    '.detail-header {',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  padding: var(--space-5);',
    '  margin-bottom: var(--space-5);',
    '}',
    '.detail-header-top {',
    '  display: flex;',
    '  align-items: flex-start;',
    '  justify-content: space-between;',
    '  margin-bottom: var(--space-4);',
    '}',
    '.detail-session-id {',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-muted);',
    '  margin-bottom: var(--space-1);',
    '}',
    '.detail-identity {',
    '  font-size: var(--text-xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '}',
    '.detail-meta-grid {',
    '  display: grid;',
    '  grid-template-columns: repeat(4, 1fr);',
    '  gap: var(--space-4);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.detail-meta-item label {',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-muted);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '  display: block;',
    '  margin-bottom: var(--space-1);',
    '}',
    '.detail-meta-item span {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  font-weight: var(--font-medium);',
    '}',
    '.detail-export-btns {',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  flex-shrink: 0;',
    '}',

    /* ── Deny ratio bar ───────────────────────────────────────────── */
    '.deny-ratio-bar {',
    '  height: 6px;',
    '  background: var(--success-subtle, #dcfce7);',
    '  border-radius: var(--radius-full);',
    '  overflow: hidden;',
    '}',
    '.deny-ratio-fill {',
    '  height: 100%;',
    '  background: var(--danger, #dc2626);',
    '  border-radius: var(--radius-full);',
    '  transition: width 0.3s ease;',
    '}',
    '.deny-ratio-label {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  margin-top: var(--space-1);',
    '}',

    /* ── Timeline filters ─────────────────────────────────────────── */
    '.timeline-filters {',
    '  display: flex;',
    '  gap: var(--space-3);',
    '  align-items: flex-end;',
    '  margin-bottom: var(--space-5);',
    '}',
    '.timeline-filter-group {',
    '  display: flex;',
    '  flex-direction: column;',
    '  gap: var(--space-1);',
    '}',
    '.timeline-filter-group label {',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-muted);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '}',
    '.timeline-filter-select {',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  outline: none;',
    '  cursor: pointer;',
    '}',
    '.timeline-filter-select:focus {',
    '  border-color: var(--accent);',
    '  box-shadow: 0 0 0 2px var(--accent-subtle);',
    '}',

    /* ── Vertical timeline ────────────────────────────────────────── */
    '.timeline {',
    '  position: relative;',
    '  padding-left: var(--space-8);',
    '}',
    '.timeline::before {',
    '  content: "";',
    '  position: absolute;',
    '  left: 20px;',
    '  top: 0;',
    '  bottom: 0;',
    '  width: 2px;',
    '  background: var(--border-secondary, var(--border));',
    '}',
    '.timeline-event {',
    '  position: relative;',
    '  margin-bottom: var(--space-3);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  background: var(--bg-primary);',
    '  overflow: hidden;',
    '  transition: box-shadow var(--transition-fast);',
    '}',
    '.timeline-event::before {',
    '  content: "";',
    '  position: absolute;',
    '  left: -28px;',
    '  top: 16px;',
    '  width: 10px;',
    '  height: 10px;',
    '  border-radius: 50%;',
    '  background: var(--border);',
    '  border: 2px solid var(--bg-primary);',
    '  z-index: 1;',
    '}',
    '.timeline-event--allow::before {',
    '  background: var(--success, #16a34a);',
    '}',
    '.timeline-event--deny {',
    '  border-left: 3px solid var(--danger, #dc2626);',
    '  box-shadow: 0 1px 4px rgba(220,38,38,0.12);',
    '}',
    '.timeline-event--deny::before {',
    '  background: var(--danger, #dc2626);',
    '}',
    '.timeline-event--session-start,',
    '.timeline-event--session-end {',
    '  background: var(--bg-secondary);',
    '  border-style: dashed;',
    '}',
    '.timeline-event--session-start::before,',
    '.timeline-event--session-end::before {',
    '  background: var(--text-muted);',
    '}',
    '.timeline-event__header {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3) var(--space-4);',
    '  cursor: pointer;',
    '  user-select: none;',
    '  transition: background var(--transition-fast);',
    '}',
    '.timeline-event__header:hover {',
    '  background: var(--bg-secondary);',
    '}',
    '.timeline-event--deny .timeline-event__header:hover {',
    '  background: rgba(220,38,38,0.04);',
    '}',
    '.timeline-event__seq {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  font-family: var(--font-mono);',
    '  min-width: 28px;',
    '  flex-shrink: 0;',
    '}',
    '.timeline-event__time {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  font-family: var(--font-mono);',
    '  min-width: 90px;',
    '  flex-shrink: 0;',
    '}',
    '.timeline-event__tool {',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-primary);',
    '  flex: 1;',
    '  min-width: 0;',
    '  overflow: hidden;',
    '  text-overflow: ellipsis;',
    '  white-space: nowrap;',
    '}',
    '.timeline-event__latency {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  flex-shrink: 0;',
    '  white-space: nowrap;',
    '}',
    '.timeline-event__chevron {',
    '  color: var(--text-muted);',
    '  flex-shrink: 0;',
    '  transition: transform var(--transition-fast);',
    '}',
    '.timeline-event.expanded .timeline-event__chevron {',
    '  transform: rotate(180deg);',
    '}',

    /* ── Event body (expandable) ──────────────────────────────────── */
    '.timeline-event__body {',
    '  display: none;',
    '  padding: var(--space-4);',
    '  padding-top: 0;',
    '  border-top: 1px solid var(--border);',
    '  background: var(--bg-surface, var(--bg-secondary));',
    '}',
    '.timeline-event.expanded .timeline-event__body {',
    '  display: block;',
    '}',
    '.event-body-grid {',
    '  display: grid;',
    '  grid-template-columns: 140px 1fr;',
    '  gap: var(--space-2) var(--space-4);',
    '  padding-top: var(--space-3);',
    '}',
    '.event-body-label {',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-muted);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '  padding-top: 2px;',
    '}',
    '.event-body-value {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  word-break: break-word;',
    '}',
    '.event-body-code {',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-xs);',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-sm);',
    '  padding: var(--space-2) var(--space-3);',
    '  white-space: pre-wrap;',
    '  word-break: break-all;',
    '  max-height: 200px;',
    '  overflow-y: auto;',
    '}',
    '.event-body-truncated {',
    '  max-height: 80px;',
    '  overflow: hidden;',
    '  position: relative;',
    '}',
    '.event-body-show-more {',
    '  background: none;',
    '  border: none;',
    '  color: var(--accent);',
    '  font-size: var(--text-xs);',
    '  cursor: pointer;',
    '  padding: 0;',
    '  margin-top: var(--space-1);',
    '}',
    '.event-body-transforms {',
    '  display: flex;',
    '  flex-wrap: wrap;',
    '  gap: var(--space-1);',
    '}',
    '.transform-pill {',
    '  font-size: var(--text-xs);',
    '  padding: 2px 8px;',
    '  background: var(--accent-subtle);',
    '  color: var(--accent-text);',
    '  border-radius: var(--radius-full);',
    '  font-weight: var(--font-medium);',
    '}',

    /* ── Quota mini-bar ──────────────────────────────────────────── */
    '.quota-mini {',
    '  display: flex;',
    '  flex-direction: column;',
    '  gap: 4px;',
    '}',
    '.quota-mini-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  font-size: var(--text-xs);',
    '}',
    '.quota-mini-label {',
    '  color: var(--text-muted);',
    '  min-width: 50px;',
    '}',
    '.quota-mini-bar {',
    '  flex: 1;',
    '  height: 4px;',
    '  background: var(--bg-tertiary, var(--border));',
    '  border-radius: var(--radius-full);',
    '  overflow: hidden;',
    '}',
    '.quota-mini-fill {',
    '  height: 100%;',
    '  background: var(--accent);',
    '  border-radius: var(--radius-full);',
    '}',
    '.quota-mini-count {',
    '  color: var(--text-secondary);',
    '  min-width: 30px;',
    '  text-align: right;',
    '}',

    /* ── Badge variants ─────────────────────────────────────────── */
    '.timeline-event__badge--allow {',
    '  font-size: 10px;',
    '  padding: 1px 6px;',
    '  background: var(--success-subtle, #dcfce7);',
    '  color: var(--success, #16a34a);',
    '  border-radius: var(--radius-full);',
    '  font-weight: var(--font-semibold);',
    '  flex-shrink: 0;',
    '}',
    '.timeline-event__badge--deny {',
    '  font-size: 10px;',
    '  padding: 1px 6px;',
    '  background: var(--danger-subtle, #fee2e2);',
    '  color: var(--danger, #dc2626);',
    '  border-radius: var(--radius-full);',
    '  font-weight: var(--font-semibold);',
    '  flex-shrink: 0;',
    '}',
    '.timeline-event__badge--neutral {',
    '  font-size: 10px;',
    '  padding: 1px 6px;',
    '  background: var(--bg-secondary);',
    '  color: var(--text-muted);',
    '  border-radius: var(--radius-full);',
    '  font-weight: var(--font-semibold);',
    '  flex-shrink: 0;',
    '}',

    /* ── Load more (timeline) ────────────────────────────────────── */
    '.timeline-load-more {',
    '  display: flex;',
    '  justify-content: center;',
    '  padding: var(--space-4) 0;',
    '}',

    /* ── Confirm modal overlay ────────────────────────────────────── */
    '.sessions-confirm-overlay {',
    '  position: fixed;',
    '  inset: 0;',
    '  background: rgba(0,0,0,0.5);',
    '  z-index: 1000;',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '}',
    '.sessions-confirm-dialog {',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  padding: var(--space-6);',
    '  max-width: 400px;',
    '  width: 100%;',
    '}',
    '.sessions-confirm-dialog h3 {',
    '  font-size: var(--text-lg);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '  margin: 0 0 var(--space-2);',
    '}',
    '.sessions-confirm-dialog p {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-secondary);',
    '  margin-bottom: var(--space-5);',
    '}',
    '.sessions-confirm-actions {',
    '  display: flex;',
    '  justify-content: flex-end;',
    '  gap: var(--space-2);',
    '}',

  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-sessions', '');
    s.textContent = SESSIONS_CSS;
    document.head.appendChild(s);
    styleInjected = true;
  }

  // ── DOM helpers ─────────────────────────────────────────────────────

  function mk(tag, className, attrs) {
    var el = document.createElement(tag);
    if (className) el.className = className;
    if (attrs) {
      var keys = Object.keys(attrs);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (k === 'style') {
          el.style.cssText = attrs[k];
        } else {
          el.setAttribute(k, attrs[k]);
        }
      }
    }
    return el;
  }

  // ── Formatters ──────────────────────────────────────────────────────

  function fmtDateTime(iso) {
    if (!iso) return '-';
    try {
      var d = new Date(iso);
      if (isNaN(d.getTime())) return iso;
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
    } catch (e) { return iso; }
  }

  function fmtTime(iso) {
    if (!iso) return '-';
    try {
      var d = new Date(iso);
      if (isNaN(d.getTime())) return iso;
      var hh = String(d.getHours()).padStart(2, '0');
      var mm = String(d.getMinutes()).padStart(2, '0');
      var ss = String(d.getSeconds()).padStart(2, '0');
      var ms = String(d.getMilliseconds()).padStart(3, '0');
      return hh + ':' + mm + ':' + ss + '.' + ms;
    } catch (e) { return iso; }
  }

  function fmtDuration(startedAt, endedAt) {
    if (!endedAt) return 'Active';
    try {
      var s = new Date(startedAt).getTime();
      var e = new Date(endedAt).getTime();
      if (isNaN(s) || isNaN(e)) return '-';
      var sec = Math.round((e - s) / 1000);
      if (sec < 60) return sec + 's';
      var min = Math.floor(sec / 60);
      if (min < 60) return min + 'm ' + (sec % 60) + 's';
      return Math.floor(min / 60) + 'h ' + (min % 60) + 'm';
    } catch (e2) { return '-'; }
  }

  function fmtLatency(micros) {
    if (!micros || micros <= 0) return '';
    if (micros < 1000) return micros + 'µs';
    return (micros / 1000).toFixed(1) + 'ms';
  }

  function truncateId(id) {
    if (!id) return '-';
    return id.length > 8 ? id.slice(0, 8) : id;
  }

  // ── Decision badge (timeline) ────────────────────────────────────────

  function makeDecisionBadge(decision) {
    var d = String(decision || '').toLowerCase();
    var cls, text;
    if (d === 'allow' || d === 'allowed') {
      cls = 'timeline-event__badge--allow';
      text = 'ALLOW';
    } else if (d === 'deny' || d === 'denied') {
      cls = 'timeline-event__badge--deny';
      text = 'DENY';
    } else {
      cls = 'timeline-event__badge--neutral';
      text = d || 'N/A';
    }
    var span = mk('span', cls);
    span.textContent = text;
    return span;
  }

  // ── Config panel ────────────────────────────────────────────────────

  function buildConfigPanel(container) {
    var panel = mk('div', 'config-panel');
    panel.id = 'sessions-config-panel';

    var header = mk('div', 'config-panel-header');
    header.id = 'sessions-config-panel-header';
    var titleEl = mk('span', 'config-panel-title');
    titleEl.innerHTML = SG.icon('record', 14) + ' Recording Configuration';
    header.appendChild(titleEl);
    var chevron = mk('span', 'config-panel-chevron');
    chevron.innerHTML = SG.icon('chevronDown', 14);
    header.appendChild(chevron);
    panel.appendChild(header);

    var body = mk('div', 'config-panel-body');
    body.id = 'sessions-config-body';

    // Toggle row: enabled
    var toggleRow1 = mk('div', 'config-toggle-row');
    var enabledCb = mk('input', '', { type: 'checkbox', id: 'cfg-enabled' });
    var enabledLabel = mk('label', 'config-toggle-label', { for: 'cfg-enabled' });
    enabledLabel.textContent = 'Enable recording';
    toggleRow1.appendChild(enabledCb);
    toggleRow1.appendChild(enabledLabel);
    body.appendChild(toggleRow1);

    // Toggle row: record payloads
    var toggleRow2 = mk('div', 'config-toggle-row');
    var payloadCb = mk('input', '', { type: 'checkbox', id: 'cfg-record-payloads' });
    var payloadLabel = mk('label', 'config-toggle-label', { for: 'cfg-record-payloads' });
    payloadLabel.textContent = 'Record request/response payloads';
    toggleRow2.appendChild(payloadCb);
    toggleRow2.appendChild(payloadLabel);
    var privacyWarning = mk('div', 'config-privacy-warning');
    privacyWarning.textContent = 'Warning: payloads may contain sensitive data. Use redact patterns below.';
    body.appendChild(toggleRow2);
    body.appendChild(privacyWarning);

    // Grid fields
    var grid = mk('div', 'config-grid');

    var retField = mk('div', 'config-field');
    var retLabel = mk('label', '', { for: 'cfg-retention' });
    retLabel.textContent = 'Retention Days';
    var retInput = mk('input', '', { type: 'number', id: 'cfg-retention', min: '1', max: '365', placeholder: '30' });
    retField.appendChild(retLabel);
    retField.appendChild(retInput);
    grid.appendChild(retField);

    var storageField = mk('div', 'config-field');
    var storageLabel = mk('label', '', { for: 'cfg-storage-dir' });
    storageLabel.textContent = 'Storage Directory';
    var storageInput = mk('input', '', { type: 'text', id: 'cfg-storage-dir', readonly: 'readonly' });
    storageField.appendChild(storageLabel);
    storageField.appendChild(storageInput);
    grid.appendChild(storageField);

    var redactField = mk('div', 'config-field config-full-row');
    var redactLabel = mk('label', '', { for: 'cfg-redact' });
    redactLabel.textContent = 'Redact Patterns (comma-separated)';
    var redactInput = mk('input', '', { type: 'text', id: 'cfg-redact', placeholder: 'password,secret,token' });
    redactField.appendChild(redactLabel);
    redactField.appendChild(redactInput);
    grid.appendChild(redactField);

    body.appendChild(grid);

    var actions = mk('div', 'config-actions');
    var saveBtn = mk('button', 'btn btn-primary btn-sm');
    saveBtn.textContent = 'Save Configuration';
    saveBtn.addEventListener('click', saveConfig);
    actions.appendChild(saveBtn);
    body.appendChild(actions);

    panel.appendChild(body);
    container.appendChild(panel);

    // Toggle collapse
    header.addEventListener('click', function () {
      var isOpen = body.classList.contains('open');
      if (isOpen) {
        body.classList.remove('open');
        header.classList.remove('open');
      } else {
        body.classList.add('open');
        header.classList.add('open');
      }
    });

    // Load current config
    loadConfig();
  }

  function loadConfig() {
    SG.api.get('/v1/recordings/config').then(function (cfg) {
      if (!cfg) return;
      var enabledEl = document.getElementById('cfg-enabled');
      var payloadEl = document.getElementById('cfg-record-payloads');
      var retEl = document.getElementById('cfg-retention');
      var storageEl = document.getElementById('cfg-storage-dir');
      var redactEl = document.getElementById('cfg-redact');

      if (enabledEl) enabledEl.checked = !!cfg.enabled;
      if (payloadEl) payloadEl.checked = !!cfg.record_payloads;
      if (retEl) retEl.value = cfg.retention_days || 30;
      if (storageEl) storageEl.value = cfg.storage_dir || '';
      if (redactEl) redactEl.value = (cfg.redact_patterns || []).join(', ');
      currentMaxFileSize = cfg.max_file_size || 0;
    }).catch(function (err) {
      console.error('Failed to load recording config:', err);
    });
  }

  function saveConfig() {
    var enabledEl = document.getElementById('cfg-enabled');
    var payloadEl = document.getElementById('cfg-record-payloads');
    var retEl = document.getElementById('cfg-retention');
    var redactEl = document.getElementById('cfg-redact');
    var storageEl = document.getElementById('cfg-storage-dir');

    var redactRaw = (redactEl && redactEl.value) ? redactEl.value : '';
    var patterns = redactRaw.split(',').map(function (s) { return s.trim(); }).filter(function (s) { return s.length > 0; });

    var cfg = {
      enabled: enabledEl ? enabledEl.checked : false,
      record_payloads: payloadEl ? payloadEl.checked : false,
      retention_days: retEl ? (parseInt(retEl.value, 10) || 30) : 30,
      redact_patterns: patterns,
      storage_dir: storageEl ? storageEl.value : '',
      max_file_size: currentMaxFileSize || 0
    };

    SG.api.put('/v1/recordings/config', cfg).then(function () {
      SG.toast.show('Configuration saved', 'success');
    }).catch(function (err) {
      SG.toast.show('Failed to save config: ' + (err.message || err), 'error');
    });
  }

  // ── List view ────────────────────────────────────────────────────────

  function buildListView(container) {
    var root = mk('div', '');
    root.id = 'sessions-list-view';

    // Header
    var header = mk('div', 'sessions-header');
    var h1 = mk('h1');
    h1.textContent = 'Sessions';
    header.appendChild(h1);
    root.appendChild(header);

    // Config panel
    buildConfigPanel(root);

    // Filters
    var filtersEl = mk('div', 'recording-filters');
    filtersEl.id = 'recording-filters';

    var identityGroup = mk('div', 'recording-filter-group');
    var identityLabel = mk('label');
    identityLabel.textContent = 'Identity';
    identityGroup.appendChild(identityLabel);
    var identityInput = mk('input', 'recording-filter-input', {
      id: 'filter-identity',
      type: 'text',
      placeholder: 'Filter by identity'
    });
    identityGroup.appendChild(identityInput);
    filtersEl.appendChild(identityGroup);

    var fromGroup = mk('div', 'recording-filter-group');
    var fromLabel = mk('label');
    fromLabel.textContent = 'From';
    fromGroup.appendChild(fromLabel);
    var fromInput = mk('input', 'recording-filter-input', {
      id: 'filter-from',
      type: 'date'
    });
    fromGroup.appendChild(fromInput);
    filtersEl.appendChild(fromGroup);

    var toGroup = mk('div', 'recording-filter-group');
    var toLabel = mk('label');
    toLabel.textContent = 'To';
    toGroup.appendChild(toLabel);
    var toInput = mk('input', 'recording-filter-input', {
      id: 'filter-to',
      type: 'date'
    });
    toGroup.appendChild(toInput);
    filtersEl.appendChild(toGroup);

    var deniesGroup = mk('div', 'recording-filter-group');
    var deniesLabel = mk('label', '', { style: 'visibility:hidden' });
    deniesLabel.textContent = 'x';
    deniesGroup.appendChild(deniesLabel);
    var deniesRow = mk('div', 'recording-filter-checkbox-row');
    var deniesCb = mk('input', '', { type: 'checkbox', id: 'filter-has-denies' });
    var deniesLbl = mk('label', '', { for: 'filter-has-denies' });
    deniesLbl.textContent = 'Has denies';
    deniesRow.appendChild(deniesCb);
    deniesRow.appendChild(deniesLbl);
    deniesGroup.appendChild(deniesRow);
    filtersEl.appendChild(deniesGroup);

    var filterActions = mk('div', 'recording-filter-actions');
    var applyBtn = mk('button', 'btn btn-primary btn-sm');
    applyBtn.textContent = 'Apply';
    applyBtn.addEventListener('click', applyFilters);
    filterActions.appendChild(applyBtn);

    var clearBtn = mk('button', 'btn btn-secondary btn-sm');
    clearBtn.textContent = 'Clear';
    clearBtn.addEventListener('click', clearFilters);
    filterActions.appendChild(clearBtn);

    filtersEl.appendChild(filterActions);
    root.appendChild(filtersEl);

    // Table wrapper
    var tableWrap = mk('div', 'recording-table-wrap');
    tableWrap.id = 'recording-table-wrap';

    var table = mk('table', 'recording-table');
    table.id = 'recording-table';

    var thead = mk('thead');
    var headerRow = mk('tr');
    var cols = ['Session ID', 'Identity', 'Started', 'Duration', 'Events', 'Denies', 'Actions'];
    for (var c = 0; c < cols.length; c++) {
      var th = mk('th');
      th.textContent = cols[c];
      headerRow.appendChild(th);
    }
    thead.appendChild(headerRow);
    table.appendChild(thead);

    var tbody = mk('tbody');
    tbody.id = 'recording-tbody';

    // Empty state (shown inside tbody via tr/td spanning all cols)
    var emptyRow = mk('tr');
    emptyRow.id = 'recording-empty-row';
    var emptyCell = mk('td', 'sessions-empty', { colspan: '7' });
    var emptyIcon = mk('div', 'sessions-empty-icon');
    emptyIcon.innerHTML = SG.icon('record', 32);
    var emptyText = mk('p', 'sessions-empty-text');
    emptyText.textContent = 'No recordings found. Enable recording in the configuration above.';
    emptyCell.appendChild(emptyIcon);
    emptyCell.appendChild(emptyText);
    emptyRow.appendChild(emptyCell);
    tbody.appendChild(emptyRow);

    table.appendChild(tbody);
    tableWrap.appendChild(table);

    // Load more
    var loadMoreWrap = mk('div', 'sessions-load-more');
    loadMoreWrap.id = 'recording-load-more-wrap';
    loadMoreWrap.style.display = 'none';
    var loadMoreBtn = mk('button', 'btn btn-secondary btn-sm');
    loadMoreBtn.textContent = 'Load More';
    loadMoreBtn.addEventListener('click', function () {
      listOffset += PAGE_SIZE;
      renderRecordingRows(false);
    });
    loadMoreWrap.appendChild(loadMoreBtn);
    tableWrap.appendChild(loadMoreWrap);

    root.appendChild(tableWrap);

    container.appendChild(root);

    // Fetch recordings
    loadRecordings();
  }

  function applyFilters() {
    filterIdentity = (document.getElementById('filter-identity') || {}).value || '';
    filterFrom = (document.getElementById('filter-from') || {}).value || '';
    filterTo = (document.getElementById('filter-to') || {}).value || '';
    filterHasDenies = !!(document.getElementById('filter-has-denies') || {}).checked;

    var params = [];
    if (filterFrom) params.push('from=' + encodeURIComponent(new Date(filterFrom).toISOString()));
    if (filterTo) {
      // Set to end of day
      var toDate = new Date(filterTo);
      toDate.setHours(23, 59, 59, 999);
      params.push('to=' + encodeURIComponent(toDate.toISOString()));
    }
    if (filterHasDenies) params.push('has_denies=true');

    var path = '/v1/recordings' + (params.length ? '?' + params.join('&') : '');
    SG.api.get(path).then(function (resp) {
      var all = resp || [];
      // Client-side identity filter
      if (filterIdentity) {
        var needle = filterIdentity.toLowerCase();
        all = all.filter(function (r) {
          return (r.identity_name || r.identity_id || '').toLowerCase().indexOf(needle) !== -1;
        });
      }
      recordings = all;
      filteredRecordings = all;
      listOffset = 0;
      renderRecordingRows(true);
    }).catch(function (err) {
      SG.toast.show('Failed to load recordings: ' + (err.message || err), 'error');
    });
  }

  function clearFilters() {
    var identityEl = document.getElementById('filter-identity');
    var fromEl = document.getElementById('filter-from');
    var toEl = document.getElementById('filter-to');
    var deniesEl = document.getElementById('filter-has-denies');
    if (identityEl) identityEl.value = '';
    if (fromEl) fromEl.value = '';
    if (toEl) toEl.value = '';
    if (deniesEl) deniesEl.checked = false;
    filterIdentity = '';
    filterFrom = '';
    filterTo = '';
    filterHasDenies = false;
    loadRecordings();
  }

  function loadRecordings() {
    SG.api.get('/v1/recordings').then(function (resp) {
      recordings = resp || [];
      filteredRecordings = recordings;
      listOffset = 0;
      renderRecordingRows(true);
    }).catch(function (err) {
      SG.toast.show('Failed to load recordings: ' + (err.message || err), 'error');
    });
  }

  function renderRecordingRows(reset) {
    var tbody = document.getElementById('recording-tbody');
    var emptyRow = document.getElementById('recording-empty-row');
    var loadMoreWrap = document.getElementById('recording-load-more-wrap');
    if (!tbody) return;

    if (reset) {
      // Remove all rows except empty row
      var children = tbody.children;
      for (var i = children.length - 1; i >= 0; i--) {
        if (children[i].id !== 'recording-empty-row') {
          tbody.removeChild(children[i]);
        }
      }
    }

    var slice = filteredRecordings.slice(0, listOffset + PAGE_SIZE);

    if (slice.length === 0) {
      if (emptyRow) emptyRow.style.display = '';
      if (loadMoreWrap) loadMoreWrap.style.display = 'none';
      return;
    }

    if (emptyRow) emptyRow.style.display = 'none';

    // When resetting, render slice; when loading more, render the new slice portion
    var startIdx = reset ? 0 : listOffset;
    for (var j = startIdx; j < slice.length; j++) {
      tbody.appendChild(buildRecordingRow(slice[j]));
    }

    if (loadMoreWrap) {
      loadMoreWrap.style.display = (filteredRecordings.length > listOffset + PAGE_SIZE) ? '' : 'none';
    }
  }

  function buildRecordingRow(rec) {
    var hasDenies = (rec.deny_count || 0) > 0;
    var tr = mk('tr', 'recording-row' + (hasDenies ? ' recording-row--has-denies' : ''));

    // Session ID (truncated)
    var tdId = mk('td');
    var idSpan = mk('span', 'recording-id');
    idSpan.title = rec.session_id || '';
    idSpan.textContent = truncateId(rec.session_id);
    tdId.appendChild(idSpan);
    tr.appendChild(tdId);

    // Identity
    var tdIdent = mk('td');
    var identSpan = mk('span', 'recording-identity');
    identSpan.textContent = rec.identity_name || rec.identity_id || 'anonymous';
    tdIdent.appendChild(identSpan);
    tr.appendChild(tdIdent);

    // Started
    var tdStarted = mk('td');
    var startedSpan = mk('span', 'recording-time');
    startedSpan.textContent = fmtDateTime(rec.started_at);
    tdStarted.appendChild(startedSpan);
    tr.appendChild(tdStarted);

    // Duration
    var tdDuration = mk('td');
    var durSpan = mk('span', 'recording-duration');
    durSpan.textContent = fmtDuration(rec.started_at, rec.ended_at);
    tdDuration.appendChild(durSpan);
    tr.appendChild(tdDuration);

    // Events
    var tdEvents = mk('td');
    tdEvents.textContent = (rec.event_count != null) ? rec.event_count : '-';
    tr.appendChild(tdEvents);

    // Denies
    var tdDenies = mk('td');
    var denyCount = rec.deny_count || 0;
    var denyBadge = mk('span', 'badge-deny-count' + (denyCount === 0 ? ' badge-zero' : ''));
    denyBadge.textContent = denyCount;
    tdDenies.appendChild(denyBadge);
    tr.appendChild(tdDenies);

    // Actions (stop click propagation so row click doesn't also navigate)
    var tdActions = mk('td');
    var actionsCell = mk('div', 'recording-actions-cell');

    var exportJsonBtn = mk('button', 'btn btn-secondary btn-sm');
    exportJsonBtn.textContent = 'JSON';
    exportJsonBtn.title = 'Export as JSON';
    exportJsonBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      exportRecording(rec.session_id, 'json');
    });
    actionsCell.appendChild(exportJsonBtn);

    var exportCsvBtn = mk('button', 'btn btn-secondary btn-sm');
    exportCsvBtn.textContent = 'CSV';
    exportCsvBtn.title = 'Export as CSV';
    exportCsvBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      exportRecording(rec.session_id, 'csv');
    });
    actionsCell.appendChild(exportCsvBtn);

    var deleteBtn = mk('button', 'btn btn-danger btn-sm');
    deleteBtn.textContent = 'Delete';
    deleteBtn.title = 'Delete recording';
    deleteBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      confirmDelete(rec.session_id);
    });
    actionsCell.appendChild(deleteBtn);

    tdActions.appendChild(actionsCell);
    tr.appendChild(tdActions);

    // Row click → detail view
    tr.addEventListener('click', function () {
      openDetailView(rec.session_id);
    });

    return tr;
  }

  function exportRecording(sessionId, format) {
    var url = SG.api.BASE + '/v1/recordings/' + encodeURIComponent(sessionId) + '/export?format=' + format;
    var a = document.createElement('a');
    a.href = url;
    var ext = format === 'csv' ? 'csv' : 'json';
    a.setAttribute('download', 'recording-' + truncateId(sessionId) + '.' + ext);
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  function confirmDelete(sessionId) {
    var overlay = mk('div', 'sessions-confirm-overlay');
    var dialog = mk('div', 'sessions-confirm-dialog');

    var h3 = mk('h3');
    h3.textContent = 'Delete Recording';
    dialog.appendChild(h3);

    var p = mk('p');
    p.textContent = 'Are you sure you want to delete recording ' + truncateId(sessionId) + '? This action cannot be undone.';
    dialog.appendChild(p);

    var actions = mk('div', 'sessions-confirm-actions');
    var cancelBtn = mk('button', 'btn btn-secondary btn-sm');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', function () {
      document.body.removeChild(overlay);
    });
    actions.appendChild(cancelBtn);

    var deleteBtn = mk('button', 'btn btn-danger btn-sm');
    deleteBtn.textContent = 'Delete';
    deleteBtn.addEventListener('click', function () {
      document.body.removeChild(overlay);
      SG.api.del('/v1/recordings/' + encodeURIComponent(sessionId)).then(function () {
        SG.toast.show('Recording deleted', 'success');
        loadRecordings();
      }).catch(function (err) {
        SG.toast.show('Failed to delete: ' + (err.message || err), 'error');
      });
    });
    actions.appendChild(deleteBtn);

    dialog.appendChild(actions);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    // Click outside to close
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay) {
        document.body.removeChild(overlay);
      }
    });
  }

  // ── Detail view ──────────────────────────────────────────────────────

  function openDetailView(sessionId) {
    currentRecordingId = sessionId;
    currentRecording = null;
    events = [];
    eventsOffset = 0;
    eventsTotal = 0;
    expandedEventId = null;
    timelineEventFilter = '';
    timelineDecisionFilter = '';

    var container = document.getElementById('page-content');
    if (!container) return;
    container.innerHTML = '';

    buildDetailView(container, sessionId);
  }

  function buildDetailView(container, sessionId) {
    var root = mk('div', '');
    root.id = 'sessions-detail-view';

    // Back button
    var backBtn = mk('button', 'detail-back');
    backBtn.innerHTML = SG.icon('chevronRight', 14) +
      '<span style="transform:scaleX(-1); display:inline-block;">' + SG.icon('chevronRight', 14) + '</span>';
    backBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg> Back to Sessions';
    backBtn.addEventListener('click', function () {
      currentRecordingId = null;
      container.innerHTML = '';
      buildListView(container);
    });
    root.appendChild(backBtn);

    // Detail header (loading placeholder)
    var detailHeader = mk('div', 'detail-header');
    detailHeader.id = 'detail-header';
    detailHeader.innerHTML = '<div style="color:var(--text-muted);font-size:var(--text-sm);">Loading...</div>';
    root.appendChild(detailHeader);

    // Deny ratio bar placeholder
    var ratioCont = mk('div', '');
    ratioCont.id = 'detail-ratio-container';
    root.appendChild(ratioCont);

    // Timeline filters
    var tlFilters = mk('div', 'timeline-filters');

    var typeGroup = mk('div', 'timeline-filter-group');
    var typeLabel = mk('label');
    typeLabel.textContent = 'Event Type';
    typeGroup.appendChild(typeLabel);
    var typeSelect = mk('select', 'timeline-filter-select', { id: 'tl-filter-type' });
    var typeOpts = [
      { value: '', text: 'All' },
      { value: 'tool_call', text: 'Tool Calls' },
      { value: 'session_start', text: 'Session Start' },
      { value: 'session_end', text: 'Session End' }
    ];
    for (var t = 0; t < typeOpts.length; t++) {
      var tOpt = mk('option');
      tOpt.value = typeOpts[t].value;
      tOpt.textContent = typeOpts[t].text;
      typeSelect.appendChild(tOpt);
    }
    typeGroup.appendChild(typeSelect);
    tlFilters.appendChild(typeGroup);

    var decGroup = mk('div', 'timeline-filter-group');
    var decLabel = mk('label');
    decLabel.textContent = 'Decision';
    decGroup.appendChild(decLabel);
    var decSelect = mk('select', 'timeline-filter-select', { id: 'tl-filter-decision' });
    var decOpts = [
      { value: '', text: 'All' },
      { value: 'allow', text: 'Allow' },
      { value: 'deny', text: 'Deny' }
    ];
    for (var d = 0; d < decOpts.length; d++) {
      var dOpt = mk('option');
      dOpt.value = decOpts[d].value;
      dOpt.textContent = decOpts[d].text;
      decSelect.appendChild(dOpt);
    }
    decGroup.appendChild(decSelect);
    tlFilters.appendChild(decGroup);

    var tlApplyBtn = mk('button', 'btn btn-primary btn-sm', { style: 'align-self:flex-end' });
    tlApplyBtn.textContent = 'Apply';
    tlApplyBtn.addEventListener('click', function () {
      timelineEventFilter = typeSelect.value;
      timelineDecisionFilter = decSelect.value;
      rerenderTimeline();
    });
    tlFilters.appendChild(tlApplyBtn);

    root.appendChild(tlFilters);

    // Timeline container
    var timeline = mk('div', 'timeline');
    timeline.id = 'detail-timeline';
    root.appendChild(timeline);

    // Load more (timeline)
    var tlLoadMore = mk('div', 'timeline-load-more');
    tlLoadMore.id = 'timeline-load-more';
    tlLoadMore.style.display = 'none';
    var tlLoadMoreBtn = mk('button', 'btn btn-secondary btn-sm');
    tlLoadMoreBtn.textContent = 'Load More Events';
    tlLoadMoreBtn.addEventListener('click', function () {
      loadMoreEvents(sessionId);
    });
    tlLoadMore.appendChild(tlLoadMoreBtn);
    root.appendChild(tlLoadMore);

    container.appendChild(root);

    // Fetch metadata and first page of events
    SG.api.get('/v1/recordings/' + encodeURIComponent(sessionId)).then(function (rec) {
      currentRecording = rec;
      renderDetailHeader(rec);
      renderDenyRatioBar(rec);
    }).catch(function (err) {
      var header = document.getElementById('detail-header');
      if (header) {
        header.textContent = '';
        var errDiv = document.createElement('div');
        errDiv.style.color = 'var(--danger)';
        errDiv.textContent = 'Failed to load recording: ' + (err.message || err);
        header.appendChild(errDiv);
      }
    });

    fetchEvents(sessionId, 0, EVENTS_PAGE);
  }

  function renderDetailHeader(rec) {
    var header = document.getElementById('detail-header');
    if (!header) return;
    header.innerHTML = '';

    var top = mk('div', 'detail-header-top');

    var leftSide = mk('div');
    var idDiv = mk('div', 'detail-session-id');
    idDiv.textContent = 'Session ID: ' + (rec.session_id || '-');
    leftSide.appendChild(idDiv);
    var identDiv = mk('div', 'detail-identity');
    identDiv.textContent = rec.identity_name || rec.identity_id || 'anonymous';
    leftSide.appendChild(identDiv);
    top.appendChild(leftSide);

    // Export buttons
    var exportBtns = mk('div', 'detail-export-btns');
    var exportJsonBtn = mk('button', 'btn btn-secondary btn-sm');
    exportJsonBtn.textContent = 'Export JSON';
    exportJsonBtn.addEventListener('click', function () { exportRecording(rec.session_id, 'json'); });
    exportBtns.appendChild(exportJsonBtn);
    var exportCsvBtn = mk('button', 'btn btn-secondary btn-sm');
    exportCsvBtn.textContent = 'Export CSV';
    exportCsvBtn.addEventListener('click', function () { exportRecording(rec.session_id, 'csv'); });
    exportBtns.appendChild(exportCsvBtn);
    top.appendChild(exportBtns);

    header.appendChild(top);

    // Meta grid
    var metaGrid = mk('div', 'detail-meta-grid');

    var metaItems = [
      { label: 'Started', value: fmtDateTime(rec.started_at) },
      { label: 'Duration', value: fmtDuration(rec.started_at, rec.ended_at) },
      { label: 'Total Events', value: (rec.event_count != null) ? String(rec.event_count) : '-' },
      { label: 'Deny Events', value: (rec.deny_count != null) ? String(rec.deny_count) : '0' }
    ];
    for (var m = 0; m < metaItems.length; m++) {
      var item = mk('div', 'detail-meta-item');
      var itemLabel = mk('label');
      itemLabel.textContent = metaItems[m].label;
      var itemSpan = mk('span');
      itemSpan.textContent = metaItems[m].value;
      item.appendChild(itemLabel);
      item.appendChild(itemSpan);
      metaGrid.appendChild(item);
    }
    header.appendChild(metaGrid);
  }

  function renderDenyRatioBar(rec) {
    var container = document.getElementById('detail-ratio-container');
    if (!container) return;
    container.innerHTML = '';

    var eventCount = rec.event_count || 0;
    var denyCount = rec.deny_count || 0;
    if (eventCount === 0) return;

    var pct = Math.min(100, Math.round((denyCount / eventCount) * 100));

    var wrapper = mk('div', '', { style: 'margin-bottom: var(--space-5);' });
    var bar = mk('div', 'deny-ratio-bar');
    var fill = mk('div', 'deny-ratio-fill', { style: 'width: ' + pct + '%' });
    bar.appendChild(fill);
    wrapper.appendChild(bar);

    var ratioLabel = mk('div', 'deny-ratio-label');
    ratioLabel.textContent = denyCount + ' denied / ' + eventCount + ' total (' + pct + '% deny rate)';
    wrapper.appendChild(ratioLabel);

    container.appendChild(wrapper);
  }

  function fetchEvents(sessionId, offset, limit) {
    var path = '/v1/recordings/' + encodeURIComponent(sessionId) + '/events?offset=' + offset + '&limit=' + limit;
    SG.api.get(path).then(function (resp) {
      var newEvents = (resp && resp.events) ? resp.events : [];
      eventsTotal = (resp && resp.total != null) ? resp.total : newEvents.length;

      if (offset === 0) {
        events = newEvents;
      } else {
        events = events.concat(newEvents);
      }
      eventsOffset = events.length;

      renderTimeline(offset === 0);
      updateLoadMoreBtn();
    }).catch(function (err) {
      SG.toast.show('Failed to load events: ' + (err.message || err), 'error');
    });
  }

  function loadMoreEvents(sessionId) {
    fetchEvents(sessionId, eventsOffset, EVENTS_PAGE);
  }

  function updateLoadMoreBtn() {
    var btn = document.getElementById('timeline-load-more');
    if (btn) {
      btn.style.display = (eventsOffset < eventsTotal) ? '' : 'none';
    }
  }

  function getFilteredEvents() {
    return events.filter(function (ev) {
      if (timelineEventFilter) {
        var type = (ev.event_type || '').toLowerCase();
        if (type !== timelineEventFilter.toLowerCase()) return false;
      }
      if (timelineDecisionFilter) {
        var dec = (ev.decision || '').toLowerCase();
        if (dec !== timelineDecisionFilter.toLowerCase()) return false;
      }
      return true;
    });
  }

  function renderTimeline(reset) {
    var timeline = document.getElementById('detail-timeline');
    if (!timeline) return;

    if (reset) {
      timeline.innerHTML = '';
    }

    var filtered = getFilteredEvents();
    var existing = timeline.querySelectorAll('.timeline-event');

    // Determine start index for appending
    var startIdx = reset ? 0 : existing.length;
    var filteredStartIdx = reset ? 0 : startIdx;

    if (reset) {
      timeline.innerHTML = '';
      for (var i = 0; i < filtered.length; i++) {
        timeline.appendChild(buildEventCard(filtered[i], i + 1));
      }
    } else {
      // Append new events that pass filter
      var allFiltered = filtered;
      for (var j = filteredStartIdx; j < allFiltered.length; j++) {
        timeline.appendChild(buildEventCard(allFiltered[j], j + 1));
      }
    }

    if (filtered.length === 0 && events.length > 0) {
      var emptyMsg = mk('div', '', { style: 'padding: var(--space-6); text-align: center; color: var(--text-muted); font-size: var(--text-sm);' });
      emptyMsg.textContent = 'No events match the current filters.';
      timeline.appendChild(emptyMsg);
    } else if (events.length === 0) {
      var noEventsMsg = mk('div', '', { style: 'padding: var(--space-6); text-align: center; color: var(--text-muted); font-size: var(--text-sm);' });
      noEventsMsg.textContent = 'No events recorded for this session.';
      timeline.appendChild(noEventsMsg);
    }
  }

  function rerenderTimeline() {
    expandedEventId = null;
    renderTimeline(true);
  }

  function buildEventCard(ev, seq) {
    var eventType = (ev.event_type || 'tool_call').toLowerCase();
    var decision = (ev.decision || '').toLowerCase();
    var isDeny = (decision === 'deny' || decision === 'denied');
    var isAllow = (decision === 'allow' || decision === 'allowed');
    var isSession = (eventType === 'session_start' || eventType === 'session_end');

    var cardCls = 'timeline-event';
    if (isDeny) cardCls += ' timeline-event--deny';
    else if (isAllow) cardCls += ' timeline-event--allow';
    if (eventType === 'session_start') cardCls += ' timeline-event--session-start';
    if (eventType === 'session_end') cardCls += ' timeline-event--session-end';

    var evId = String(ev.sequence || seq);
    var card = mk('div', cardCls);
    card.setAttribute('data-ev-id', evId);

    // Header
    var header = mk('div', 'timeline-event__header');

    var seqEl = mk('span', 'timeline-event__seq');
    seqEl.textContent = '#' + (ev.sequence || seq);
    header.appendChild(seqEl);

    var timeEl = mk('span', 'timeline-event__time');
    timeEl.textContent = fmtTime(ev.timestamp);
    header.appendChild(timeEl);

    var toolEl = mk('span', 'timeline-event__tool');
    if (isSession) {
      toolEl.textContent = eventType === 'session_start' ? 'Session started' : 'Session ended';
    } else {
      toolEl.textContent = ev.tool_name || eventType;
    }
    header.appendChild(toolEl);

    if (!isSession && ev.decision) {
      header.appendChild(makeDecisionBadge(ev.decision));
    }

    if (!isSession && ev.latency_micros > 0) {
      var latencyEl = mk('span', 'timeline-event__latency');
      latencyEl.textContent = fmtLatency(ev.latency_micros);
      header.appendChild(latencyEl);
    }

    // Chevron (only for expandable cards)
    if (!isSession) {
      var chevronEl = mk('span', 'timeline-event__chevron');
      chevronEl.innerHTML = SG.icon('chevronDown', 14);
      header.appendChild(chevronEl);
    }

    card.appendChild(header);

    // Body (expandable, only for non-session events)
    if (!isSession) {
      var body = mk('div', 'timeline-event__body');
      body.appendChild(buildEventBody(ev));
      card.appendChild(body);

      // Toggle expand
      header.addEventListener('click', function () {
        toggleEventExpand(evId, card);
      });
    }

    return card;
  }

  function buildEventBody(ev) {
    var grid = mk('div', 'event-body-grid');

    // Request args
    addBodyRow(grid, 'Arguments', function (valueEl) {
      if (ev.request_args && Object.keys(ev.request_args).length > 0) {
        var pre = mk('pre', 'event-body-code');
        pre.textContent = JSON.stringify(ev.request_args, null, 2);
        valueEl.appendChild(pre);
      } else {
        valueEl.textContent = 'none';
      }
    });

    // Response body (if recorded) with show-more toggle
    if (ev.response_body) {
      addBodyRow(grid, 'Response', function (valueEl) {
        var text = String(ev.response_body);
        var TRUNC = 500;
        if (text.length <= TRUNC) {
          var pre = mk('pre', 'event-body-code');
          pre.textContent = text;
          valueEl.appendChild(pre);
        } else {
          var truncDiv = mk('div', 'event-body-truncated');
          var pre2 = mk('pre', 'event-body-code', { style: 'max-height:none;overflow:visible;' });
          pre2.textContent = text.slice(0, TRUNC) + '\u2026';
          truncDiv.appendChild(pre2);
          valueEl.appendChild(truncDiv);

          var showMoreBtn = mk('button', 'event-body-show-more');
          showMoreBtn.textContent = 'Show full response';
          var expanded = false;
          showMoreBtn.addEventListener('click', function () {
            expanded = !expanded;
            if (expanded) {
              pre2.textContent = text;
              showMoreBtn.textContent = 'Show less';
            } else {
              pre2.textContent = text.slice(0, TRUNC) + '\u2026';
              showMoreBtn.textContent = 'Show full response';
            }
          });
          valueEl.appendChild(showMoreBtn);
        }
      });
    }

    // Transforms
    addBodyRow(grid, 'Transforms', function (valueEl) {
      var transforms = ev.transforms_applied || [];
      if (transforms.length > 0) {
        var pills = mk('div', 'event-body-transforms');
        for (var i = 0; i < transforms.length; i++) {
          var pill = mk('span', 'transform-pill');
          pill.textContent = transforms[i];
          pills.appendChild(pill);
        }
        valueEl.appendChild(pills);
      } else {
        valueEl.textContent = 'none';
      }
    });

    // Quota state
    if (ev.quota_state) {
      addBodyRow(grid, 'Quota', function (valueEl) {
        var qs = ev.quota_state;
        var mini = mk('div', 'quota-mini');

        var quotaFields = [
          { label: 'Total', used: qs.total_used, limit: qs.total_limit },
          { label: 'Read', used: qs.read_used, limit: qs.read_limit },
          { label: 'Write', used: qs.write_used, limit: qs.write_limit },
          { label: 'Delete', used: qs.delete_used, limit: qs.delete_limit }
        ];
        for (var q = 0; q < quotaFields.length; q++) {
          var qf = quotaFields[q];
          if (qf.limit == null || qf.limit <= 0) continue;
          var row = mk('div', 'quota-mini-row');
          var lbl = mk('span', 'quota-mini-label');
          lbl.textContent = qf.label;
          row.appendChild(lbl);
          var bar = mk('div', 'quota-mini-bar');
          var pct = Math.min(100, Math.round(((qf.used || 0) / qf.limit) * 100));
          var fill = mk('div', 'quota-mini-fill', { style: 'width:' + pct + '%' });
          bar.appendChild(fill);
          row.appendChild(bar);
          var cnt = mk('span', 'quota-mini-count');
          cnt.textContent = (qf.used || 0) + '/' + qf.limit;
          row.appendChild(cnt);
          mini.appendChild(row);
        }

        if (mini.children.length === 0) {
          valueEl.textContent = 'no quota data';
        } else {
          valueEl.appendChild(mini);
        }
      });
    }

    // Rule ID & reason
    addBodyRow(grid, 'Rule ID', function (valueEl) {
      valueEl.textContent = ev.rule_id || '-';
    });

    addBodyRow(grid, 'Reason', function (valueEl) {
      valueEl.textContent = ev.reason || '-';
    });

    return grid;
  }

  function addBodyRow(grid, label, buildValueFn) {
    var labelEl = mk('div', 'event-body-label');
    labelEl.textContent = label;
    grid.appendChild(labelEl);
    var valueEl = mk('div', 'event-body-value');
    buildValueFn(valueEl);
    grid.appendChild(valueEl);
  }

  function toggleEventExpand(evId, cardEl) {
    if (expandedEventId === evId) {
      cardEl.classList.remove('expanded');
      expandedEventId = null;
    } else {
      // Collapse previous
      if (expandedEventId) {
        var prev = document.querySelector('.timeline-event[data-ev-id="' + CSS.escape(expandedEventId) + '"]');
        if (prev) prev.classList.remove('expanded');
      }
      cardEl.classList.add('expanded');
      expandedEventId = evId;
    }
  }

  // ── Lifecycle ────────────────────────────────────────────────────────

  function render(container) {
    cleanup();
    injectStyles();

    // Reset state
    recordings = [];
    filteredRecordings = [];
    listOffset = 0;
    filterIdentity = '';
    filterFrom = '';
    filterTo = '';
    filterHasDenies = false;

    buildListView(container);
  }

  function cleanup() {
    // Remove any confirm overlays that might be open
    var overlays = document.querySelectorAll('.sessions-confirm-overlay');
    for (var i = 0; i < overlays.length; i++) {
      if (overlays[i].parentNode) overlays[i].parentNode.removeChild(overlays[i]);
    }

    // Reset module state
    currentRecordingId = null;
    currentRecording = null;
    events = [];
    eventsOffset = 0;
    eventsTotal = 0;
    expandedEventId = null;
  }

  // ── Registration ─────────────────────────────────────────────────────

  SG.router.register('sessions', render);
  SG.router.registerCleanup('sessions', cleanup);
})();
