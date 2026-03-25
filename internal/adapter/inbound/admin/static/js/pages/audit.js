/**
 * audit.js — Unified Timeline page for SentinelGate admin UI.
 *
 * Real-time unified timeline viewer with Server-Sent Events (SSE) streaming,
 * live connection indicator, slide-in animations, protocol badges, and
 * expandable row details. Primary observability tool for monitoring
 * multi-protocol proxy activity.
 *
 * Data sources:
 *   SSE /admin/api/audit/stream → real-time audit entries
 *   GET /admin/api/audit?...    → filtered query results
 *   GET /admin/api/audit/export → CSV download
 *
 * Design features:
 *   - Live indicator (pulsing green dot) for SSE connection state
 *   - Protocol badges on each row (MCP, HTTP, WS)
 *   - New entries slide in from left with CSS animation
 *   - Clickable rows expand inline detail panel
 *   - Only one row expanded at a time
 *   - Entry count footer updates in real time
 *   - Max 200 entries in the list (oldest dropped)
 *   - Filter bar: Decision, Protocol, Tool, User, Period with presets
 *   - CSV export with current filter state
 *   - Filter mode pauses SSE, Resume Live reconnects
 *   - All user data rendered via textContent (XSS-safe)
 *
 * Requirements:
 *   AUD-01  SSE stream from /admin/api/audit/stream
 *   AUD-02  Live indicator (green=connected, gray=disconnected)
 *   AUD-03  Slide-in animation for new entries
 *   AUD-04  Expandable row details (tool, args, user, decision, protocol, framework)
 *   AUD-05  Entry count footer
 *   AUD-06  Filter bar with Decision/Protocol/Tool/User/Period controls
 *   AUD-07  Period presets (Today, Last hour, Last 24h, Last 7d, Custom)
 *   AUD-08  CSV export with current filter params
 *   AUD-09  Protocol badges with color coding per protocol
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // ── State ──────────────────────────────────────────────────────────

  var eventSource = null;
  var entries = [];
  var styleInjected = false;
  var expandedRowId = null;
  var filterMode = false;
  var MAX_ENTRIES = 200;
  var currentSort = { key: 'timestamp', dir: 'desc' };

  // ── Audit-specific styles ──────────────────────────────────────────
  // Injected once into <head> on first render; co-located here so
  // audit layout, animations, and micro-interactions live with the
  // code that uses them.

  var AUDIT_CSS = [
    /* ── Header ────────────────────────────────────────────────── */
    '.audit-header {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  margin-bottom: var(--space-6);',
    '}',
    '.audit-header h1 {',
    '  font-size: var(--text-2xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0;',
    '  letter-spacing: -0.02em;',
    '}',

    /* ── Live indicator ────────────────────────────────────────── */
    '.audit-live {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--success);',
    '}',
    '.audit-live.disconnected {',
    '  color: var(--text-muted);',
    '}',
    '.audit-live-dot {',
    '  width: 8px;',
    '  height: 8px;',
    '  border-radius: var(--radius-full);',
    '  background: var(--success);',
    '  flex-shrink: 0;',
    '}',
    '.audit-live.disconnected .audit-live-dot {',
    '  background: var(--text-muted);',
    '  animation: none;',
    '}',
    '.audit-live-dot.connected {',
    '  animation: auditPulse 2s ease-in-out infinite;',
    '}',
    '@keyframes auditPulse {',
    '  0%, 100% { opacity: 1; }',
    '  50% { opacity: 0.5; }',
    '}',

    /* ── Filter bar ──────────────────────────────────────────────── */
    '.audit-filters {',
    '  margin-bottom: var(--space-4);',
    '}',
    '.audit-filter-row {',
    '  display: flex;',
    '  flex-wrap: wrap;',
    '  gap: var(--space-3);',
    '  align-items: flex-end;',
    '}',
    '.audit-filter-group {',
    '  display: flex;',
    '  flex-direction: column;',
    '  gap: var(--space-1);',
    '}',
    '.audit-filter-group label {',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-muted);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '}',
    '.audit-filter-input {',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  outline: none;',
    '  width: 160px;',
    '  height: 34px;',
    '  box-sizing: border-box;',
    '}',
    '.audit-filter-input:focus {',
    '  border-color: var(--accent);',
    '  box-shadow: 0 0 0 2px var(--accent-subtle);',
    '}',
    '.audit-filter-select {',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  outline: none;',
    '  cursor: pointer;',
    '  height: 34px;',
    '  box-sizing: border-box;',
    '}',
    '.audit-filter-select:focus {',
    '  border-color: var(--accent);',
    '  box-shadow: 0 0 0 2px var(--accent-subtle);',
    '}',
    '.audit-custom-period {',
    '  display: none;',
    '  flex-wrap: wrap;',
    '  gap: var(--space-3);',
    '  align-items: flex-end;',
    '  margin-top: var(--space-3);',
    '}',
    '.audit-custom-period.visible {',
    '  display: flex;',
    '}',
    '.audit-filter-actions {',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  align-items: flex-end;',
    '}',
    '.audit-filter-actions .btn {',
    '  height: 34px;',
    '  box-sizing: border-box;',
    '}',
    '.audit-resume-btn {',
    '  display: none;',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--accent);',
    '  background: var(--accent-subtle);',
    '  border: 1px solid var(--accent);',
    '  border-radius: var(--radius-md);',
    '  cursor: pointer;',
    '  transition: background var(--transition-fast);',
    '}',
    '.audit-resume-btn:hover {',
    '  background: var(--accent);',
    '  color: var(--bg-primary);',
    '}',
    '.audit-resume-btn.visible {',
    '  display: inline-flex;',
    '}',

    /* ── Export button ────────────────────────────────────────────── */
    '.audit-export-btn {',
    '  margin-left: auto;',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-1);',
    '  padding: var(--space-1) var(--space-3);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-secondary);',
    '  background: var(--bg-secondary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  cursor: pointer;',
    '  transition: background var(--transition-fast), color var(--transition-fast);',
    '}',
    '.audit-export-btn:hover {',
    '  background: var(--bg-tertiary);',
    '  color: var(--text-primary);',
    '}',
    '.audit-export-btn:disabled {',
    '  opacity: 0.5;',
    '  cursor: default;',
    '}',

    /* ── Entries container ─────────────────────────────────────── */
    '.audit-entries {',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  background: var(--bg-primary);',
    '  overflow: hidden;',
    '}',

    /* ── Row ────────────────────────────────────────────────────── */
    '.audit-row {',
    '  border-bottom: 1px solid var(--border);',
    '  cursor: pointer;',
    '  transition: background var(--transition-fast);',
    '}',
    '.audit-row:last-child {',
    '  border-bottom: none;',
    '}',
    '.audit-row:hover {',
    '  background: var(--bg-secondary);',
    '}',
    '.audit-row.expanded {',
    '  background: var(--bg-secondary);',
    '}',

    /* ── Row summary (collapsed view) ──────────────────────────── */
    '.audit-row-summary {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3) var(--space-4);',
    '}',
    '.audit-row-time {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  min-width: 60px;',
    '  flex-shrink: 0;',
    '}',
    '.audit-row-tool {',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-primary);',
    '  flex: 1;',
    '  min-width: 0;',
    '  overflow: hidden;',
    '  text-overflow: ellipsis;',
    '  white-space: nowrap;',
    '}',
    '.audit-row-identity {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  flex-shrink: 0;',
    '  max-width: 120px;',
    '  overflow: hidden;',
    '  text-overflow: ellipsis;',
    '  white-space: nowrap;',
    '}',
    '.badge-scan {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  padding: 1px var(--space-2);',
    '  font-size: 10px;',
    '  font-weight: var(--font-medium);',
    '  border-radius: var(--radius-full);',
    '  background: rgba(234, 179, 8, 0.15);',
    '  color: var(--warning);',
    '  border: 1px solid rgba(234, 179, 8, 0.25);',
    '  flex-shrink: 0;',
    '}',

    /* ── Detail panel (expanded view) ──────────────────────────── */
    '.audit-detail {',
    '  display: none;',
    '  padding: var(--space-4);',
    '  padding-top: 0;',
    '  background: var(--bg-surface);',
    '  border-top: 1px solid var(--border);',
    '}',
    '.audit-row.expanded .audit-detail {',
    '  display: block;',
    '}',
    '.audit-detail-grid {',
    '  display: grid;',
    '  grid-template-columns: 140px 1fr;',
    '  gap: var(--space-2) var(--space-4);',
    '  padding-top: var(--space-3);',
    '}',
    '.audit-detail-label {',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-muted);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '}',
    '.audit-detail-value {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  word-break: break-all;',
    '}',
    '.audit-detail-code {',
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

    /* ── Slide-in animation ────────────────────────────────────── */
    '@keyframes auditSlideIn {',
    '  from { opacity: 0; transform: translateX(-20px); }',
    '  to   { opacity: 1; transform: translateX(0); }',
    '}',
    '.audit-slide-in {',
    '  animation: auditSlideIn 300ms ease-out;',
    '}',

    /* ── Entry count footer ────────────────────────────────────── */
    '.audit-count {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  padding: var(--space-3) var(--space-4);',
    '  text-align: right;',
    '}',

    /* ── Protocol badges ────────────────────────────────────────── */
    '.badge-protocol-mcp { background: var(--accent-subtle); color: var(--accent); }',
    '.badge-protocol-http { background: var(--success-subtle); color: var(--success); }',
    '.badge-protocol-ws { background: var(--warning-subtle); color: var(--warning); }',
    '.badge-protocol-mcp, .badge-protocol-http, .badge-protocol-ws {',
    '  font-size: 10px;',
    '  padding: 1px 6px;',
    '}',

    /* ── Distribution widgets ────────────────────────────────────── */
    '.audit-widgets {',
    '  display: grid;',
    '  grid-template-columns: 1fr 1fr;',
    '  gap: var(--space-4);',
    '  margin-top: var(--space-6);',
    '}',
    '@media (max-width: 768px) {',
    '  .audit-widgets { grid-template-columns: 1fr; }',
    '}',
    '.dist-bar-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  padding: var(--space-1) 0;',
    '}',
    '.dist-bar-label {',
    '  min-width: 100px;',
    '  font-size: var(--text-sm);',
    '  color: var(--text-secondary);',
    '  flex-shrink: 0;',
    '}',
    '.dist-bar-track {',
    '  flex: 1;',
    '  height: 24px;',
    '  background: var(--bg-surface);',
    '  border-radius: var(--radius-sm);',
    '  overflow: hidden;',
    '}',
    '.dist-bar {',
    '  height: 100%;',
    '  border-radius: var(--radius-sm);',
    '  transition: width 0.4s ease;',
    '  min-width: 2px;',
    '}',
    '.dist-bar-mcp       { background: var(--accent); }',
    '.dist-bar-http      { background: var(--success); }',
    '.dist-bar-websocket { background: var(--warning); }',
    '.dist-bar-default   { background: var(--text-muted); }',
    '.dist-bar-count {',
    '  min-width: 48px;',
    '  text-align: right;',
    '  font-weight: 600;',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  flex-shrink: 0;',
    '}',
    '.dist-empty-state {',
    '  padding: var(--space-4);',
    '  text-align: center;',
    '  color: var(--text-muted);',
    '  font-size: var(--text-sm);',
    '}',

    /* ── Empty state ───────────────────────────────────────────── */
    '.audit-empty {',
    '  padding: var(--space-8);',
    '  text-align: center;',
    '  color: var(--text-muted);',
    '}',
    '.audit-empty-icon {',
    '  margin-bottom: var(--space-3);',
    '  opacity: 0.5;',
    '}',
    '.audit-empty-text {',
    '  font-size: var(--text-sm);',
    '}'
  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-audit', '');
    s.textContent = AUDIT_CSS;
    document.head.appendChild(s);
    styleInjected = true;
  }

  // ── DOM helpers ────────────────────────────────────────────────────

  function mk(tag, className, attrs) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (attrs) {
      var keys = Object.keys(attrs);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (k === 'style') {
          node.style.cssText = attrs[k];
        } else {
          node.setAttribute(k, attrs[k]);
        }
      }
    }
    return node;
  }

  // ── Empty state for activity feed (2.3) ────────────────────────────

  function renderActivityEmpty() {
    return '<div class="empty-state" style="padding: var(--space-8) var(--space-4);">' +
      '<div class="empty-state-illustration" style="width: 80px; height: 80px;">' +
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 80" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' +
          '<path d="M40 10v60" />' +
          '<circle cx="40" cy="20" r="4" />' +
          '<circle cx="40" cy="40" r="4" />' +
          '<circle cx="40" cy="60" r="4" />' +
          '<path d="M44 20h16" />' +
          '<path d="M44 40h12" />' +
          '<path d="M44 60h20" />' +
        '</svg>' +
      '</div>' +
      '<h3 class="empty-state-title">No activity yet</h3>' +
      '<p class="empty-state-description">Activity will appear here when agents start making tool calls through SentinelGate.</p>' +
    '</div>';
  }

  // ── Skeleton loading for audit activity feed (2.4) ────────────────

  function renderAuditSkeleton(count) {
    var html = '';
    for (var i = 0; i < count; i++) {
      html +=
        '<div class="audit-skeleton-row" style="border-bottom: 1px solid var(--border); pointer-events: none;">' +
          '<div style="display: flex; align-items: center; gap: var(--space-3); padding: var(--space-3) var(--space-4);">' +
            '<div class="skeleton skeleton-text" style="width: 50px; height: 12px;"></div>' +
            '<div class="skeleton skeleton-text" style="width: 40px; height: 18px; border-radius: 9px;"></div>' +
            '<div class="skeleton skeleton-text" style="width: 50px; height: 18px; border-radius: 9px;"></div>' +
            '<div class="skeleton skeleton-text" style="flex: 1; height: 14px;"></div>' +
            '<div class="skeleton skeleton-circle" style="width: 24px; height: 24px;"></div>' +
          '</div>' +
        '</div>';
    }
    return html;
  }

  function showAuditSkeleton() {
    var container = document.getElementById('audit-entries');
    if (!container) return;
    var emptyEl = document.getElementById('audit-empty');
    if (emptyEl) emptyEl.style.display = 'none';
    // Remove existing rows but keep empty-state element
    var children = container.children;
    for (var r = children.length - 1; r >= 0; r--) {
      if (children[r].id !== 'audit-empty') {
        container.removeChild(children[r]);
      }
    }
    var skeletonWrap = mk('div', '', { id: 'audit-skeleton' });
    skeletonWrap.innerHTML = renderAuditSkeleton(6);
    container.appendChild(skeletonWrap);
  }

  function removeAuditSkeleton() {
    var el = document.getElementById('audit-skeleton');
    if (el && el.parentNode) el.parentNode.removeChild(el);
  }

  // ── Sort helpers (2.7) ────────────────────────────────────────────

  var SORT_KEYS = {
    'Time': 'timestamp',
    'Protocol': 'protocol',
    'Decision': 'decision',
    'Tool': 'tool_name',
    'Identity': 'identity_name'
  };

  function sortEntries() {
    var key = currentSort.key;
    var dir = currentSort.dir;
    entries.sort(function (a, b) {
      var va = String(a[key] || '').toLowerCase();
      var vb = String(b[key] || '').toLowerCase();
      if (va < vb) return dir === 'asc' ? -1 : 1;
      if (va > vb) return dir === 'asc' ? 1 : -1;
      return 0;
    });
  }

  function handleSortClick(th, sortKey) {
    if (currentSort.key === sortKey) {
      currentSort.dir = currentSort.dir === 'asc' ? 'desc' : 'asc';
    } else {
      currentSort.key = sortKey;
      currentSort.dir = (sortKey === 'timestamp') ? 'desc' : 'asc';
    }
    // Update header classes
    var allTh = th.parentNode.querySelectorAll('.table-sortable');
    for (var i = 0; i < allTh.length; i++) {
      allTh[i].classList.remove('sort-asc', 'sort-desc');
    }
    th.classList.add(currentSort.dir === 'asc' ? 'sort-asc' : 'sort-desc');
    // Re-sort and re-render
    sortEntries();
    expandedRowId = null;
    renderEntries(-1);
  }

  // Sort icon SVG for table headers
  var SORT_ICON_SVG = '<span class="table-sort-icon">' +
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
      '<polyline points="6 9 12 4 18 9"/><polyline points="6 15 12 20 18 15"/>' +
    '</svg></span>';

  // ── Period presets ────────────────────────────────────────────────
  // Each preset returns {start: Date, end: Date} in UTC.

  function getPeriodRange(period) {
    var now = new Date();
    var start;
    switch (period) {
      case 'today':
        start = new Date(now);
        start.setUTCHours(0, 0, 0, 0);
        return { start: start, end: now };
      case 'last_hour':
        return { start: new Date(now.getTime() - 60 * 60 * 1000), end: now };
      case 'last_24h':
        return { start: new Date(now.getTime() - 24 * 60 * 60 * 1000), end: now };
      case 'last_7d':
        return { start: new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000), end: now };
      default:
        return null; // custom — caller reads date inputs
    }
  }

  // ── Build filter query string from current controls ──────────────

  function buildFilterQuery() {
    var params = [];
    var decisionEl = document.getElementById('audit-filter-decision');
    var protocolEl = document.getElementById('audit-filter-protocol');
    var toolEl = document.getElementById('audit-filter-tool');
    var userEl = document.getElementById('audit-filter-user');
    var periodEl = document.getElementById('audit-filter-period');

    if (decisionEl && decisionEl.value) {
      params.push('decision=' + encodeURIComponent(decisionEl.value));
    }
    if (protocolEl && protocolEl.value) {
      params.push('protocol=' + encodeURIComponent(protocolEl.value));
    }
    if (toolEl && toolEl.value.trim()) {
      params.push('tool=' + encodeURIComponent(toolEl.value.trim()));
    }
    if (userEl && userEl.value.trim()) {
      params.push('user=' + encodeURIComponent(userEl.value.trim()));
    }

    // Period → start/end
    var range;
    if (periodEl && periodEl.value === 'custom') {
      var startInput = document.getElementById('audit-filter-start');
      var endInput = document.getElementById('audit-filter-end');
      if (startInput && startInput.value) {
        range = { start: new Date(startInput.value), end: endInput && endInput.value ? new Date(endInput.value) : new Date() };
      } else {
        range = getPeriodRange('last_24h');
      }
    } else if (periodEl && periodEl.value) {
      range = getPeriodRange(periodEl.value);
    } else {
      range = getPeriodRange('last_24h');
    }

    if (range) {
      params.push('start=' + encodeURIComponent(range.start.toISOString()));
      params.push('end=' + encodeURIComponent(range.end.toISOString()));
    }

    params.push('limit=200');
    return params.join('&');
  }

  // ── Enter filter mode ────────────────────────────────────────────

  function applyFilters() {
    var queryStr = buildFilterQuery();
    // Disconnect SSE
    if (eventSource) { eventSource.close(); eventSource = null; }
    setLiveState(false);
    filterMode = true;

    // Show resume button
    var resumeBtn = document.getElementById('audit-resume-btn');
    if (resumeBtn) resumeBtn.classList.add('visible');

    // Show skeleton loading state before API call
    showAuditSkeleton();

    SG.api.get('/audit?' + queryStr).then(function (resp) {
      removeAuditSkeleton();
      entries = resp.records || [];
      expandedRowId = null;
      sortEntries();
      renderEntries(-1); // full re-render
      updateCount();
    }).catch(function (err) {
      removeAuditSkeleton();
      SG.toast.show('Filter query failed: ' + (err.message || err), 'error');
    });
  }

  // ── Leave filter mode (resume live) ──────────────────────────────

  function resumeLive() {
    filterMode = false;
    entries = [];
    expandedRowId = null;

    // Hide resume button
    var resumeBtn = document.getElementById('audit-resume-btn');
    if (resumeBtn) resumeBtn.classList.remove('visible');

    renderEntries(-1);
    startSSE();
  }

  // ── Clear all filters and resume live ────────────────────────────

  function clearFilters() {
    var decisionEl = document.getElementById('audit-filter-decision');
    var protocolEl = document.getElementById('audit-filter-protocol');
    var toolEl = document.getElementById('audit-filter-tool');
    var userEl = document.getElementById('audit-filter-user');
    var periodEl = document.getElementById('audit-filter-period');
    var customRow = document.getElementById('audit-custom-period');

    if (decisionEl) decisionEl.value = '';
    if (protocolEl) protocolEl.value = '';
    if (toolEl) toolEl.value = '';
    if (userEl) userEl.value = '';
    if (periodEl) periodEl.value = 'last_24h';
    if (customRow) customRow.classList.remove('visible');

    if (filterMode) {
      resumeLive();
    }
  }

  // ── CSV export ────────────────────────────────────────────────────

  function exportCSV() {
    var exportBtn = document.getElementById('audit-export-btn');
    if (exportBtn) {
      exportBtn.disabled = true;
      setTimeout(function () { if (exportBtn) exportBtn.disabled = false; }, 1000);
    }

    var queryStr = buildFilterQuery();
    var url = SG.api.BASE + '/audit/export?' + queryStr;

    var a = document.createElement('a');
    a.href = url;
    a.setAttribute('download', 'audit-export.csv');
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  // ── Build filter bar DOM ─────────────────────────────────────────

  function buildFilterBar(container) {
    var row = mk('div', 'audit-filter-row');

    // Decision dropdown
    var decGroup = mk('div', 'audit-filter-group');
    var decLabel = mk('label');
    decLabel.textContent = 'Decision';
    decGroup.appendChild(decLabel);
    var decSelect = mk('select', 'audit-filter-select', { id: 'audit-filter-decision' });
    var decOptions = [
      { value: '', text: 'All' },
      { value: 'allow', text: 'Allow' },
      { value: 'deny', text: 'Deny (policy)' },
      { value: 'blocked', text: 'Blocked (quota)' },
      { value: 'warn', text: 'Warn (quota)' }
    ];
    for (var i = 0; i < decOptions.length; i++) {
      var opt = mk('option');
      opt.value = decOptions[i].value;
      opt.textContent = decOptions[i].text;
      decSelect.appendChild(opt);
    }
    decGroup.appendChild(decSelect);
    row.appendChild(decGroup);

    // Protocol dropdown
    var protoGroup = mk('div', 'audit-filter-group');
    var protoLabel = mk('label');
    protoLabel.textContent = 'Protocol';
    protoGroup.appendChild(protoLabel);
    var protoSelect = mk('select', 'audit-filter-select', { id: 'audit-filter-protocol' });
    var protoOptions = [
      { value: '', text: 'All' },
      { value: 'mcp', text: 'MCP' },
      { value: 'http', text: 'HTTP' },
      { value: 'websocket', text: 'WebSocket' }
    ];
    for (var pi = 0; pi < protoOptions.length; pi++) {
      var popt2 = mk('option');
      popt2.value = protoOptions[pi].value;
      popt2.textContent = protoOptions[pi].text;
      protoSelect.appendChild(popt2);
    }
    protoGroup.appendChild(protoSelect);
    row.appendChild(protoGroup);

    // Tool text input
    var toolGroup = mk('div', 'audit-filter-group');
    var toolLabel = mk('label');
    toolLabel.textContent = 'Tool';
    toolGroup.appendChild(toolLabel);
    var toolInput = mk('input', 'audit-filter-input', { id: 'audit-filter-tool', type: 'text', placeholder: 'Filter by tool name' });
    toolGroup.appendChild(toolInput);
    row.appendChild(toolGroup);

    // User dropdown (populated from identities API)
    var userGroup = mk('div', 'audit-filter-group');
    var userLabel = mk('label');
    userLabel.textContent = 'User';
    userGroup.appendChild(userLabel);
    var userSelect = mk('select', 'audit-filter-select', { id: 'audit-filter-user' });
    var defaultOpt = mk('option');
    defaultOpt.value = '';
    defaultOpt.textContent = 'All Users';
    userSelect.appendChild(defaultOpt);
    userGroup.appendChild(userSelect);
    row.appendChild(userGroup);
    // Load identities for user dropdown
    SG.api.get('/identities').then(function(identities) {
      (identities || []).forEach(function(ident) {
        var opt = mk('option');
        opt.value = ident.id;
        opt.textContent = ident.name || ident.id;
        userSelect.appendChild(opt);
      });
    }).catch(function() { /* keep empty dropdown as fallback */ });

    // Period dropdown
    var periodGroup = mk('div', 'audit-filter-group');
    var periodLabel = mk('label');
    periodLabel.textContent = 'Period';
    periodGroup.appendChild(periodLabel);
    var periodSelect = mk('select', 'audit-filter-select', { id: 'audit-filter-period' });
    var periodOptions = [
      { value: 'last_24h', text: 'Last 24h' },
      { value: 'today', text: 'Today' },
      { value: 'last_hour', text: 'Last hour' },
      { value: 'last_7d', text: 'Last 7d' },
      { value: 'custom', text: 'Custom' }
    ];
    for (var p = 0; p < periodOptions.length; p++) {
      var popt = mk('option');
      popt.value = periodOptions[p].value;
      popt.textContent = periodOptions[p].text;
      periodSelect.appendChild(popt);
    }
    periodSelect.addEventListener('change', function () {
      var customRow = document.getElementById('audit-custom-period');
      if (customRow) {
        if (periodSelect.value === 'custom') {
          customRow.classList.add('visible');
        } else {
          customRow.classList.remove('visible');
        }
      }
    });
    periodGroup.appendChild(periodSelect);
    row.appendChild(periodGroup);

    // Action buttons
    var actions = mk('div', 'audit-filter-actions');

    var applyBtn = mk('button', 'btn btn-primary btn-sm', { 'aria-label': 'Apply audit filters' });
    applyBtn.textContent = 'Apply';
    applyBtn.addEventListener('click', applyFilters);
    actions.appendChild(applyBtn);

    var clearBtn = mk('button', 'btn btn-secondary btn-sm', { 'aria-label': 'Clear audit filters' });
    clearBtn.textContent = 'Clear';
    clearBtn.addEventListener('click', clearFilters);
    actions.appendChild(clearBtn);

    var resumeBtn = mk('button', 'audit-resume-btn', { id: 'audit-resume-btn', 'aria-label': 'Resume live SSE stream' });
    resumeBtn.textContent = 'Resume Live';
    resumeBtn.addEventListener('click', resumeLive);
    actions.appendChild(resumeBtn);

    row.appendChild(actions);
    container.appendChild(row);

    // Custom period date inputs (hidden by default)
    var customRow = mk('div', 'audit-custom-period', { id: 'audit-custom-period' });

    var startGroup = mk('div', 'audit-filter-group');
    var startLabel = mk('label');
    startLabel.textContent = 'Start';
    startGroup.appendChild(startLabel);
    var startInput = mk('input', 'audit-filter-input', { id: 'audit-filter-start', type: 'datetime-local' });
    startGroup.appendChild(startInput);
    customRow.appendChild(startGroup);

    var endGroup = mk('div', 'audit-filter-group');
    var endLabel = mk('label');
    endLabel.textContent = 'End';
    endGroup.appendChild(endLabel);
    var endInput = mk('input', 'audit-filter-input', { id: 'audit-filter-end', type: 'datetime-local' });
    endGroup.appendChild(endInput);
    customRow.appendChild(endGroup);

    container.appendChild(customRow);
  }

  // ── Relative time formatter ────────────────────────────────────────

  function relativeTime(isoString) {
    if (!isoString) return 'just now';
    var then;
    try { then = new Date(isoString).getTime(); } catch (e) { return 'just now'; }
    if (isNaN(then)) return 'just now';

    var diff = Math.max(0, Math.floor((Date.now() - then) / 1000));
    if (diff < 5) return 'just now';
    if (diff < 60) return diff + 's ago';
    var m = Math.floor(diff / 60);
    if (m < 60) return m + 'm ago';
    var h = Math.floor(m / 60);
    if (h < 24) return h + 'h ago';
    return Math.floor(h / 24) + 'd ago';
  }

  // ── Decision badge helper ──────────────────────────────────────────

  function decisionBadge(decision) {
    var d = String(decision || '').toLowerCase();
    var cls = 'badge-neutral';
    var text = decision || 'unknown';

    if (d === 'allow' || d === 'allowed') {
      cls = 'badge-success';
      text = 'Allow';
    } else if (d === 'blocked') {
      cls = 'badge-blocked';
      text = 'Blocked';
    } else if (d === 'deny' || d === 'denied') {
      cls = 'badge-danger';
      text = 'Deny';
    } else if (d === 'warn') {
      cls = 'badge-warning';
      text = 'Warn';
    } else if (d === 'rate_limited' || d === 'ratelimited') {
      cls = 'badge-warning';
      text = 'Rate Limited';
    }

    var badge = mk('span', 'badge ' + cls);
    badge.textContent = text;
    return badge;
  }

  // ── Protocol badge helper ──────────────────────────────────────────

  function protocolBadge(protocol) {
    var p = String(protocol || '').toLowerCase();
    var cls = 'badge-neutral';
    var text = 'MCP'; // default for backward compat (old entries without protocol)

    if (p === 'mcp') {
      cls = 'badge-protocol-mcp';
      text = 'MCP';
    } else if (p === 'http') {
      cls = 'badge-protocol-http';
      text = 'HTTP';
    } else if (p === 'websocket') {
      cls = 'badge-protocol-ws';
      text = 'WS';
    }

    var badge = mk('span', 'badge ' + cls);
    badge.textContent = text;
    return badge;
  }

  // ── Build page DOM ─────────────────────────────────────────────────

  function buildPage(container) {
    var root = mk('div', '');

    // ── Header row ──
    var header = mk('div', 'audit-header');
    var headerLeft = mk('div', '');
    var h1 = mk('h1');
    h1.textContent = 'Activity';
    headerLeft.appendChild(h1);
    var subtitle = mk('p', 'page-subtitle');
    subtitle.textContent = 'Complete history of every tool call, with search and filters.';
    headerLeft.appendChild(subtitle);
    header.appendChild(headerLeft);

    // ── Header right side: live indicator + export ──
    var headerRight = mk('div', '', { style: 'display:flex;align-items:center;gap:var(--space-4);' });

    var live = mk('div', 'audit-live disconnected', { 'aria-label': 'Live connection status' });
    live.id = 'audit-live';
    var dot = mk('span', 'audit-live-dot');
    live.appendChild(dot);
    var liveLabel = mk('span', '');
    liveLabel.id = 'audit-live-label';
    liveLabel.textContent = 'Disconnected';
    live.appendChild(liveLabel);
    headerRight.appendChild(live);

    var exportBtn = mk('button', 'audit-export-btn', { id: 'audit-export-btn', 'aria-label': 'Export audit log as CSV' });
    exportBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
    var exportLabel = mk('span');
    exportLabel.textContent = 'Export CSV';
    exportBtn.appendChild(exportLabel);
    exportBtn.addEventListener('click', exportCSV);
    headerRight.appendChild(exportBtn);

    header.appendChild(headerRight);

    var helpBtn = mk('button', 'help-btn', { type: 'button', 'aria-label': 'Help for activity page' });
    helpBtn.textContent = '?';
    helpBtn.addEventListener('click', function() { if (SG.help) SG.help.toggle('audit'); });
    header.appendChild(helpBtn);
    root.appendChild(header);

    // ── Distribution widgets (above filters, collapsible) ──
    var widgetToggle = mk('div', '', {
      style: 'display: flex; align-items: center; gap: var(--space-2); cursor: pointer; user-select: none; margin-bottom: var(--space-2); padding: var(--space-1) 0;'
    });
    var widgetArrow = mk('span', '', { style: 'font-size: var(--text-xs); color: var(--text-muted); transition: transform 0.2s;' });
    widgetArrow.textContent = '\u25BC';
    widgetToggle.appendChild(widgetArrow);
    var widgetLabel = mk('span', '', { style: 'font-size: var(--text-sm); font-weight: var(--font-medium); color: var(--text-secondary);' });
    widgetLabel.textContent = 'Protocol & Framework Overview';
    widgetToggle.appendChild(widgetLabel);
    root.appendChild(widgetToggle);

    var widgets = mk('div', 'audit-widgets');
    widgets.id = 'audit-widgets-panel';

    // Protocol Distribution card
    var protoCard = mk('div', 'card');
    var protoHeader = mk('div', 'card-header');
    var protoTitle = mk('span', 'card-title');
    protoTitle.innerHTML = SG.icon('globe', 16) + ' ';
    protoTitle.appendChild(document.createTextNode('Protocol Distribution'));
    protoHeader.appendChild(protoTitle);
    protoCard.appendChild(protoHeader);
    var protoBody = mk('div', 'card-body');
    protoBody.id = 'audit-protocol-dist';
    var protoEmpty = mk('div', 'dist-empty-state');
    protoEmpty.textContent = 'No traffic recorded yet';
    protoBody.appendChild(protoEmpty);
    protoCard.appendChild(protoBody);
    widgets.appendChild(protoCard);

    // Framework Activity card
    var fwCard = mk('div', 'card');
    var fwHeader = mk('div', 'card-header');
    var fwTitle = mk('span', 'card-title');
    fwTitle.innerHTML = SG.icon('layers', 16) + ' ';
    fwTitle.appendChild(document.createTextNode('Framework Activity'));
    fwHeader.appendChild(fwTitle);
    fwCard.appendChild(fwHeader);
    var fwBody = mk('div', 'card-body');
    fwBody.id = 'audit-framework-activity';
    var fwEmpty = mk('div', 'dist-empty-state');
    fwEmpty.textContent = 'No framework activity detected';
    fwBody.appendChild(fwEmpty);
    fwCard.appendChild(fwBody);
    widgets.appendChild(fwCard);

    root.appendChild(widgets);

    widgetToggle.addEventListener('click', function () {
      var panel = document.getElementById('audit-widgets-panel');
      if (panel) {
        var hidden = panel.style.display === 'none';
        panel.style.display = hidden ? '' : 'none';
        widgetArrow.textContent = hidden ? '\u25BC' : '\u25B6';
      }
    });

    // ── Filter bar ──
    var filters = mk('div', 'audit-filters');
    filters.id = 'audit-filters';
    buildFilterBar(filters);
    root.appendChild(filters);

    // ── Sortable column headers ──
    var sortHeader = mk('div', 'audit-sort-header', { style: 'display: flex; align-items: center; gap: var(--space-3); padding: var(--space-2) var(--space-4); border: 1px solid var(--border); border-bottom: none; border-radius: var(--radius-lg) var(--radius-lg) 0 0; background: var(--bg-secondary); font-size: var(--text-xs); font-weight: var(--font-semibold); color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em;' });
    var sortColumns = ['Time', 'Protocol', 'Decision', 'Tool', 'Identity'];
    var sortFlex = { 'Time': '0 0 60px', 'Protocol': '0 0 50px', 'Decision': '0 0 60px', 'Tool': '1 1 0', 'Identity': '0 0 100px' };
    for (var si = 0; si < sortColumns.length; si++) {
      var colName = sortColumns[si];
      var sortKey = SORT_KEYS[colName];
      var th = mk('span', 'table-sortable', { style: 'cursor: pointer; position: relative; padding-right: 20px; flex: ' + sortFlex[colName] + ';', 'aria-label': 'Sort by ' + colName });
      th.appendChild(document.createTextNode(colName));
      th.insertAdjacentHTML('beforeend', SORT_ICON_SVG);
      th.setAttribute('data-sort-key', sortKey);
      if (sortKey === currentSort.key) {
        th.classList.add(currentSort.dir === 'asc' ? 'sort-asc' : 'sort-desc');
      }
      (function (thEl, sk) {
        thEl.addEventListener('click', function () { handleSortClick(thEl, sk); });
      })(th, sortKey);
      sortHeader.appendChild(th);
    }
    root.appendChild(sortHeader);

    // ── Entries container ──
    var entriesWrap = mk('div', 'audit-entries', { style: 'border-top: none; border-radius: 0 0 var(--radius-lg) var(--radius-lg);' });
    entriesWrap.id = 'audit-entries';

    // Empty state (uses new renderActivityEmpty with SVG illustration)
    var empty = mk('div', '');
    empty.id = 'audit-empty';
    empty.innerHTML = renderActivityEmpty();
    entriesWrap.appendChild(empty);

    root.appendChild(entriesWrap);

    // ── Entry count footer ──
    var count = mk('div', 'audit-count');
    count.id = 'audit-count';
    count.textContent = '0 entries';
    root.appendChild(count);

    // (Distribution widgets moved above filters)

    container.appendChild(root);
  }

  // ── Render a single entry row ──────────────────────────────────────

  function renderEntry(entry, isNew) {
    var rowId = entry.request_id || entry.timestamp || String(Math.random());
    var row = mk('div', 'audit-row');
    row.setAttribute('data-row-id', rowId);
    row.setAttribute('aria-expanded', 'false');

    if (isNew) {
      row.classList.add('audit-slide-in');
      row.addEventListener('animationend', function () {
        row.classList.remove('audit-slide-in');
      }, { once: true });
    }

    // ── Summary (collapsed view) ──
    var summary = mk('div', 'audit-row-summary', { 'aria-label': 'Expand details for ' + (entry.tool_name || 'unknown') + ' call', role: 'button', tabindex: '0' });

    var timeEl = mk('span', 'audit-row-time');
    timeEl.textContent = relativeTime(entry.timestamp);

    summary.appendChild(timeEl);
    summary.appendChild(protocolBadge(entry.protocol));
    summary.appendChild(decisionBadge(entry.decision));

    var toolEl = mk('span', 'audit-row-tool');
    toolEl.textContent = entry.tool_name || 'unknown';
    summary.appendChild(toolEl);

    var identityEl = mk('span', 'audit-row-identity');
    identityEl.textContent = entry.identity_name || entry.identity_id || 'anonymous';
    summary.appendChild(identityEl);

    // Scan detections badge (visible even if decision is Allow)
    var scanCount = entry.scan_detections || 0;
    if (scanCount > 0) {
      var scanBadge = mk('span', 'badge badge-scan');
      scanBadge.textContent = scanCount + ' detection' + (scanCount > 1 ? 's' : '');
      scanBadge.title = entry.scan_types || '';
      summary.appendChild(scanBadge);
    }

    // Chevron indicator
    var chevron = mk('span', '');
    chevron.textContent = '\u203A';
    chevron.style.cssText = 'margin-left:auto;font-size:1.2em;color:var(--text-muted);flex-shrink:0';
    summary.appendChild(chevron);

    row.appendChild(summary);

    // ── Detail (expanded view) ──
    var detail = mk('div', 'audit-detail');
    var grid = mk('div', 'audit-detail-grid');

    // Tool Name
    addDetailRow(grid, 'Tool Name', entry.tool_name || 'unknown');

    // Tool Arguments
    var argsLabel = mk('div', 'audit-detail-label');
    argsLabel.textContent = 'Tool Arguments';
    grid.appendChild(argsLabel);

    var argsValue = mk('div', 'audit-detail-value');
    if (entry.tool_arguments && Object.keys(entry.tool_arguments).length > 0) {
      var codeBlock = mk('pre', 'audit-detail-code');
      codeBlock.textContent = JSON.stringify(entry.tool_arguments, null, 2);
      argsValue.appendChild(codeBlock);
    } else {
      argsValue.textContent = 'none';
    }
    grid.appendChild(argsValue);

    // User / Identity ID
    addDetailRow(grid, 'Identity', (entry.identity_name ? entry.identity_name + ' (' + entry.identity_id + ')' : entry.identity_id) || 'anonymous');

    // Decision + Reason
    var decLabel = mk('div', 'audit-detail-label');
    decLabel.textContent = 'Decision';
    grid.appendChild(decLabel);
    var decValue = mk('div', 'audit-detail-value');
    decValue.appendChild(decisionBadge(entry.decision));
    if (entry.reason) {
      var reasonSpan = mk('span', '', { style: 'margin-left: var(--space-2); color: var(--text-muted); font-size: var(--text-xs);' });
      reasonSpan.textContent = entry.reason;
      decValue.appendChild(reasonSpan);
    }
    grid.appendChild(decValue);

    // Rule ID
    addDetailRow(grid, 'Rule ID', entry.rule_id || '-');

    // Request ID
    addDetailRow(grid, 'Request ID', entry.request_id || '-');

    // Timestamp (full ISO)
    addDetailRow(grid, 'Timestamp', entry.timestamp || '-');

    // Latency
    var latencyMs = '-';
    if (entry.latency_micros != null && entry.latency_micros > 0) {
      latencyMs = (entry.latency_micros / 1000).toFixed(2) + ' ms';
    }
    addDetailRow(grid, 'Latency', latencyMs);

    // Protocol
    addDetailRow(grid, 'Protocol', entry.protocol || 'MCP');

    // Framework
    addDetailRow(grid, 'Framework', entry.framework || 'N/A');

    // Scan Detections
    if (entry.scan_detections > 0) {
      var scanInfo = entry.scan_detections + ' detection(s)';
      if (entry.scan_types) scanInfo += ' — ' + entry.scan_types;
      if (entry.scan_action) scanInfo += ' (' + entry.scan_action + ')';
      addDetailRow(grid, 'Scan Detections', scanInfo);
    }

    detail.appendChild(grid);
    row.appendChild(detail);

    // ── Click to expand/collapse ──
    summary.addEventListener('click', function () {
      toggleExpand(rowId, row);
    });

    return row;
  }

  function addDetailRow(grid, label, value) {
    var labelEl = mk('div', 'audit-detail-label');
    labelEl.textContent = label;
    grid.appendChild(labelEl);
    var valueEl = mk('div', 'audit-detail-value');
    valueEl.textContent = value;
    grid.appendChild(valueEl);
  }

  // ── Expand/collapse ────────────────────────────────────────────────

  function toggleExpand(rowId, rowEl) {
    if (expandedRowId === rowId) {
      // Collapse current
      rowEl.classList.remove('expanded');
      rowEl.setAttribute('aria-expanded', 'false');
      expandedRowId = null;
    } else {
      // Collapse previous
      if (expandedRowId) {
        var prev = document.querySelector('.audit-row[data-row-id="' + CSS.escape(expandedRowId) + '"]');
        if (prev) {
          prev.classList.remove('expanded');
          prev.setAttribute('aria-expanded', 'false');
        }
      }
      // Expand new
      rowEl.classList.add('expanded');
      rowEl.setAttribute('aria-expanded', 'true');
      expandedRowId = rowId;
    }
  }

  // ── Render all entries ─────────────────────────────────────────────

  function renderEntries(newEntryIndex) {
    var container = document.getElementById('audit-entries');
    if (!container) return;

    // Remove any leftover skeleton
    removeAuditSkeleton();

    var emptyEl = document.getElementById('audit-empty');

    if (entries.length === 0) {
      // Clear rows, show empty
      var children = container.children;
      for (var r = children.length - 1; r >= 0; r--) {
        if (children[r].id !== 'audit-empty') {
          container.removeChild(children[r]);
        }
      }
      if (emptyEl) emptyEl.style.display = '';
      updateCount();
      return;
    }

    // Hide empty state
    if (emptyEl) emptyEl.style.display = 'none';

    // Sort entries using current sort state
    sortEntries();

    // If we have a new entry at the top, just prepend it
    if (newEntryIndex === 0 && container.querySelector('.audit-row')) {
      var newRow = renderEntry(entries[0], true);
      var firstRow = container.querySelector('.audit-row');
      container.insertBefore(newRow, firstRow);

      // Trim excess rows from DOM
      var rowEls = container.querySelectorAll('.audit-row');
      while (rowEls.length > MAX_ENTRIES) {
        container.removeChild(rowEls[rowEls.length - 1]);
        rowEls = container.querySelectorAll('.audit-row');
      }
    } else {
      // Full re-render (initial load or bulk)
      var children = container.children;
      for (var r = children.length - 1; r >= 0; r--) {
        if (children[r].id !== 'audit-empty') {
          container.removeChild(children[r]);
        }
      }
      for (var i = 0; i < entries.length; i++) {
        container.appendChild(renderEntry(entries[i], false));
      }
    }

    updateCount();
  }

  function updateCount() {
    var countEl = document.getElementById('audit-count');
    if (countEl) {
      var text = entries.length + ' entr' + (entries.length === 1 ? 'y' : 'ies');
      if (filterMode) text += ' (filtered)';
      countEl.textContent = text;
    }
  }

  // ── SSE connection ─────────────────────────────────────────────────

  function startSSE() {
    if (typeof EventSource === 'undefined') return;

    eventSource = new EventSource(SG.api.BASE + '/audit/stream');

    eventSource.onopen = function () {
      setLiveState(true);
      // Remove skeleton and show empty state if no entries arrived yet
      renderEntries();
    };

    eventSource.onerror = function () {
      setLiveState(false);
      // EventSource auto-reconnects; no manual retry needed
    };

    eventSource.onmessage = function (evt) {
      var entry;
      try { entry = JSON.parse(evt.data); } catch (e) { return; }

      entries.unshift(entry);
      if (entries.length > MAX_ENTRIES) {
        entries = entries.slice(0, MAX_ENTRIES);
      }
      renderEntries(0);
    };
  }

  function setLiveState(connected) {
    var liveEl = document.getElementById('audit-live');
    var labelEl = document.getElementById('audit-live-label');
    var dotEl = liveEl ? liveEl.querySelector('.audit-live-dot') : null;

    if (!liveEl) return;

    if (connected) {
      liveEl.classList.remove('disconnected');
      if (dotEl) dotEl.classList.add('connected');
      if (labelEl) labelEl.textContent = 'Live';
    } else {
      liveEl.classList.add('disconnected');
      if (dotEl) dotEl.classList.remove('connected');
      if (labelEl) labelEl.textContent = 'Disconnected';
    }
  }

  // ── Protocol/Framework Distribution (moved from dashboard) ────────

  var PROTOCOL_COLORS = {
    mcp: 'dist-bar-mcp',
    http: 'dist-bar-http',
    websocket: 'dist-bar-websocket'
  };

  var FRAMEWORK_LABELS = {
    langchain: 'LangChain',
    crewai: 'CrewAI',
    autogen: 'AutoGen',
    'openai-agents-sdk': 'OpenAI Agents SDK',
    'unknown': 'Generic / Direct',
    '': 'Generic / Direct'
  };

  function renderAuditProtocolDist(counts, decisions) {
    var container = document.getElementById('audit-protocol-dist');
    if (!container) return;

    var keys = Object.keys(counts);
    var hasData = false;
    for (var i = 0; i < keys.length; i++) {
      if (counts[keys[i]] > 0) { hasData = true; break; }
    }

    container.innerHTML = '';

    if (!hasData) {
      var empty = mk('div', 'dist-empty-state');
      empty.textContent = 'No traffic recorded yet';
      container.appendChild(empty);
      return;
    }

    var maxCount = 0;
    for (var j = 0; j < keys.length; j++) {
      if (counts[keys[j]] > maxCount) maxCount = counts[keys[j]];
    }

    keys.sort(function (a, b) { return counts[b] - counts[a]; });

    for (var k = 0; k < keys.length; k++) {
      var proto = keys[k];
      var count = counts[proto];
      if (count <= 0) continue;

      var row = mk('div', 'dist-bar-row');

      var label = mk('div', 'dist-bar-label');
      label.textContent = proto.toUpperCase();
      row.appendChild(label);

      var track = mk('div', 'dist-bar-track');
      var bar = mk('div', 'dist-bar ' + (PROTOCOL_COLORS[proto] || 'dist-bar-default'));
      var pct = maxCount > 0 ? Math.max(2, Math.round((count / maxCount) * 100)) : 0;
      bar.style.width = pct + '%';
      track.appendChild(bar);
      row.appendChild(track);

      // Count + allow/deny breakdown
      var countEl = mk('div', 'dist-bar-count');
      var dec = decisions && decisions[proto];
      if (dec && dec.deny > 0) {
        countEl.innerHTML = String(count) + ' <span style="font-size:var(--text-xs);color:var(--text-muted)">(' +
          '<span style="color:var(--success)">' + dec.allow + '</span>/' +
          '<span style="color:var(--danger)">' + dec.deny + '</span>)</span>';
      } else {
        countEl.textContent = String(count);
      }
      row.appendChild(countEl);

      container.appendChild(row);
    }
  }

  function renderAuditFrameworkActivity(counts, decisions) {
    var container = document.getElementById('audit-framework-activity');
    if (!container) return;

    var keys = Object.keys(counts);
    var hasData = false;
    for (var i = 0; i < keys.length; i++) {
      if (counts[keys[i]] > 0) { hasData = true; break; }
    }

    container.innerHTML = '';

    if (!hasData) {
      var empty = mk('div', 'dist-empty-state');
      empty.textContent = 'No framework activity detected';
      container.appendChild(empty);
      return;
    }

    var maxCount = 0;
    for (var j = 0; j < keys.length; j++) {
      if (counts[keys[j]] > maxCount) maxCount = counts[keys[j]];
    }

    keys.sort(function (a, b) { return counts[b] - counts[a]; });

    var fwColors = ['dist-bar-mcp', 'dist-bar-http', 'dist-bar-websocket', 'dist-bar-default'];

    for (var k = 0; k < keys.length; k++) {
      var fw = keys[k];
      var count = counts[fw];
      if (count <= 0) continue;

      var row = mk('div', 'dist-bar-row');

      var label = mk('div', 'dist-bar-label');
      label.textContent = FRAMEWORK_LABELS[fw] || fw;
      row.appendChild(label);

      var track = mk('div', 'dist-bar-track');
      var bar = mk('div', 'dist-bar ' + fwColors[k % fwColors.length]);
      var pct = maxCount > 0 ? Math.max(2, Math.round((count / maxCount) * 100)) : 0;
      bar.style.width = pct + '%';
      track.appendChild(bar);
      row.appendChild(track);

      // Count + allow/deny breakdown
      var countEl = mk('div', 'dist-bar-count');
      var dec = decisions && decisions[fw];
      if (dec && dec.deny > 0) {
        countEl.innerHTML = String(count) + ' <span style="font-size:var(--text-xs);color:var(--text-muted)">(' +
          '<span style="color:var(--success)">' + dec.allow + '</span>/' +
          '<span style="color:var(--danger)">' + dec.deny + '</span>)</span>';
      } else {
        countEl.textContent = String(count);
      }
      row.appendChild(countEl);

      container.appendChild(row);
    }
  }

  function loadAuditStats() {
    // Fetch stats for total counts, then recent records for allow/deny breakdown
    Promise.all([
      SG.api.get('/stats'),
      SG.api.get('/audit?limit=500')
    ]).then(function (results) {
      var data = results[0];
      var auditData = results[1];
      if (!data) return;

      // Compute per-protocol and per-framework decision breakdown from recent records
      var records = (auditData && auditData.records) || [];
      var protoDecisions = {};
      var fwDecisions = {};
      for (var i = 0; i < records.length; i++) {
        var rec = records[i];
        var proto = rec.protocol || '';
        var fw = rec.framework || '';
        var dec = (rec.decision || 'allow').toLowerCase();
        if (proto) {
          if (!protoDecisions[proto]) protoDecisions[proto] = { allow: 0, deny: 0, total: 0 };
          protoDecisions[proto].total++;
          if (dec === 'allow' || dec === 'allowed') protoDecisions[proto].allow++;
          else protoDecisions[proto].deny++;
        }
        if (fw) {
          if (!fwDecisions[fw]) fwDecisions[fw] = { allow: 0, deny: 0, total: 0 };
          fwDecisions[fw].total++;
          if (dec === 'allow' || dec === 'allowed') fwDecisions[fw].allow++;
          else fwDecisions[fw].deny++;
        }
      }

      renderAuditProtocolDist(data.protocol_counts || {}, protoDecisions);
      renderAuditFrameworkActivity(data.framework_counts || {}, fwDecisions);
    }).catch(function () {
      // Non-fatal
    });
  }

  // ── Lifecycle ──────────────────────────────────────────────────────

  function render(container) {
    cleanup();
    injectStyles();
    buildPage(container);
    showAuditSkeleton();
    startSSE();
    loadAuditStats();
  }

  function cleanup() {
    if (eventSource) { eventSource.close(); eventSource = null; }
    entries = [];
    expandedRowId = null;
    filterMode = false;
    currentSort = { key: 'timestamp', dir: 'desc' };
  }

  // ── Registration ───────────────────────────────────────────────────

  SG.router.register('audit', render);
  SG.router.registerCleanup('audit', cleanup);
})();
