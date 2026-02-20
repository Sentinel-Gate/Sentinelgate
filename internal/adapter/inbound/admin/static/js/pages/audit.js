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
 *   - Protocol badges on each row (MCP, HTTP, WS, Runtime)
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
    '.badge-protocol-runtime { background: #f3e8ff; color: #7c3aed; }',
    '.badge-protocol-mcp, .badge-protocol-http, .badge-protocol-ws, .badge-protocol-runtime {',
    '  font-size: 10px;',
    '  padding: 1px 6px;',
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

    SG.api.get('/audit?' + queryStr).then(function (resp) {
      entries = resp.records || [];
      expandedRowId = null;
      renderEntries(-1); // full re-render
      updateCount();
    }).catch(function (err) {
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
      { value: 'deny', text: 'Deny' }
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
      { value: 'websocket', text: 'WebSocket' },
      { value: 'runtime', text: 'Runtime' }
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

    // User text input
    var userGroup = mk('div', 'audit-filter-group');
    var userLabel = mk('label');
    userLabel.textContent = 'User';
    userGroup.appendChild(userLabel);
    var userInput = mk('input', 'audit-filter-input', { id: 'audit-filter-user', type: 'text', placeholder: 'Filter by user/identity' });
    userGroup.appendChild(userInput);
    row.appendChild(userGroup);

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

    var applyBtn = mk('button', 'btn btn-primary btn-sm');
    applyBtn.textContent = 'Apply';
    applyBtn.addEventListener('click', applyFilters);
    actions.appendChild(applyBtn);

    var clearBtn = mk('button', 'btn btn-secondary btn-sm');
    clearBtn.textContent = 'Clear';
    clearBtn.addEventListener('click', clearFilters);
    actions.appendChild(clearBtn);

    var resumeBtn = mk('button', 'audit-resume-btn', { id: 'audit-resume-btn' });
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
    } else if (d === 'deny' || d === 'denied') {
      cls = 'badge-danger';
      text = 'Deny';
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
    } else if (p === 'runtime') {
      cls = 'badge-protocol-runtime';
      text = 'Runtime';
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
    var h1 = mk('h1');
    h1.textContent = 'Unified Timeline';
    header.appendChild(h1);

    // ── Header right side: live indicator + export ──
    var headerRight = mk('div', '', { style: 'display:flex;align-items:center;gap:var(--space-4);' });

    var live = mk('div', 'audit-live disconnected');
    live.id = 'audit-live';
    var dot = mk('span', 'audit-live-dot');
    live.appendChild(dot);
    var liveLabel = mk('span', '');
    liveLabel.id = 'audit-live-label';
    liveLabel.textContent = 'Disconnected';
    live.appendChild(liveLabel);
    headerRight.appendChild(live);

    var exportBtn = mk('button', 'audit-export-btn', { id: 'audit-export-btn' });
    exportBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';
    var exportLabel = mk('span');
    exportLabel.textContent = 'Export CSV';
    exportBtn.appendChild(exportLabel);
    exportBtn.addEventListener('click', exportCSV);
    headerRight.appendChild(exportBtn);

    header.appendChild(headerRight);
    root.appendChild(header);

    // ── Filter bar ──
    var filters = mk('div', 'audit-filters');
    filters.id = 'audit-filters';
    buildFilterBar(filters);
    root.appendChild(filters);

    // ── Entries container ──
    var entriesWrap = mk('div', 'audit-entries');
    entriesWrap.id = 'audit-entries';

    // Empty state
    var empty = mk('div', 'audit-empty');
    empty.id = 'audit-empty';
    var emptyIcon = mk('div', 'audit-empty-icon');
    emptyIcon.innerHTML = SG.icon('activity', 32);
    empty.appendChild(emptyIcon);
    var emptyText = mk('p', 'audit-empty-text');
    emptyText.textContent = 'Waiting for audit events\u2026';
    empty.appendChild(emptyText);
    entriesWrap.appendChild(empty);

    root.appendChild(entriesWrap);

    // ── Entry count footer ──
    var count = mk('div', 'audit-count');
    count.id = 'audit-count';
    count.textContent = '0 entries';
    root.appendChild(count);

    container.appendChild(root);
  }

  // ── Render a single entry row ──────────────────────────────────────

  function renderEntry(entry, isNew) {
    var rowId = entry.request_id || entry.timestamp || String(Math.random());
    var row = mk('div', 'audit-row');
    row.setAttribute('data-row-id', rowId);

    if (isNew) {
      row.classList.add('audit-slide-in');
      row.addEventListener('animationend', function () {
        row.classList.remove('audit-slide-in');
      }, { once: true });
    }

    // ── Summary (collapsed view) ──
    var summary = mk('div', 'audit-row-summary');

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
      expandedRowId = null;
    } else {
      // Collapse previous
      if (expandedRowId) {
        var prev = document.querySelector('.audit-row[data-row-id="' + CSS.escape(expandedRowId) + '"]');
        if (prev) prev.classList.remove('expanded');
      }
      // Expand new
      rowEl.classList.add('expanded');
      expandedRowId = rowId;
    }
  }

  // ── Render all entries ─────────────────────────────────────────────

  function renderEntries(newEntryIndex) {
    var container = document.getElementById('audit-entries');
    if (!container) return;

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

  // ── Lifecycle ──────────────────────────────────────────────────────

  function render(container) {
    cleanup();
    injectStyles();
    buildPage(container);
    startSSE();
  }

  function cleanup() {
    if (eventSource) { eventSource.close(); eventSource = null; }
    entries = [];
    expandedRowId = null;
    filterMode = false;
  }

  // ── Registration ───────────────────────────────────────────────────

  SG.router.register('audit', render);
  SG.router.registerCleanup('audit', cleanup);
})();
