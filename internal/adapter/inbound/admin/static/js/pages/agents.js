/**
 * agents.js -- Unified Agent View (UX-F2) + Health Dashboard (Upgrade 11 / Delta 3.2)
 *
 * Three views:
 *   1. Agent List -- active MCP sessions with health overview button
 *   2. Agent Detail -- click an agent row to see:
 *      - Header Card (identity, roles, session, health status badge)
 *      - KPI Strip (calls, denied, deny%, drift, cost)
 *      - Health Trend (30-day sparklines)
 *      - Tool Usage Breakdown
 *      - Behavioral Drift
 *      - Timeline
 *   3. Health Overview -- cross-agent health comparison table
 *
 * Data sources:
 *   GET /admin/api/v1/sessions/active              -> active sessions (list)
 *   GET /admin/api/v1/agents/{id}/summary           -> per-agent aggregated data
 *   GET /admin/api/v1/agents/{id}/health            -> health trend
 *   GET /admin/api/v1/health/overview               -> cross-agent health overview
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // -- State ------------------------------------------------------------------

  var styleInjected = false;
  var pollInterval = null;

  // -- Connected Clients styles -----------------------------------------------

  var CLIENTS_CSS = [
    /* Page */
    '.clients-page {',
    '  padding: var(--space-6);',
    '  max-width: 1000px;',
    '}',

    /* Header */
    '.clients-header {',
    '  margin-bottom: var(--space-6);',
    '  display: flex;',
    '  justify-content: space-between;',
    '  align-items: flex-start;',
    '}',
    '.clients-header-left h1 {',
    '  font-size: var(--text-2xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0 0 var(--space-1) 0;',
    '  letter-spacing: -0.02em;',
    '}',
    '.clients-header-left p {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-muted);',
    '  margin: 0;',
    '}',

    /* Client table */
    '.client-table {',
    '  width: 100%;',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  overflow: hidden;',
    '  border-collapse: separate;',
    '  border-spacing: 0;',
    '}',
    '.client-table th {',
    '  text-align: left;',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-muted);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '  padding: var(--space-3);',
    '  background: var(--bg-secondary);',
    '  border-bottom: 1px solid var(--border);',
    '}',
    '.client-row {',
    '  border-bottom: 1px solid var(--border);',
    '}',
    '.client-row:last-child {',
    '  border-bottom: none;',
    '}',
    '.client-row td {',
    '  padding: var(--space-3);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  vertical-align: middle;',
    '}',

    /* Status dot */
    '.client-status-dot {',
    '  display: inline-block;',
    '  width: 8px;',
    '  height: 8px;',
    '  border-radius: var(--radius-full);',
    '  margin-right: var(--space-2);',
    '  vertical-align: middle;',
    '  background: var(--success);',
    '}',
    '.client-status-dot.idle {',
    '  background: var(--warning, #f59e0b);',
    '}',
    '.client-status-dot.stale {',
    '  background: var(--text-muted, #6b7280);',
    '}',
    '.client-status-dot.offline {',
    '  background: var(--text-muted, #6b7280);',
    '}',

    /* Session ID */
    '.client-session-id {',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  max-width: 120px;',
    '  overflow: hidden;',
    '  text-overflow: ellipsis;',
    '  white-space: nowrap;',
    '}',

    /* Count badge */
    '.client-count-badge {',
    '  display: inline-block;',
    '  background: var(--bg-secondary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-full);',
    '  padding: 1px 8px;',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-secondary);',
    '  min-width: 24px;',
    '  text-align: center;',
    '}',

    /* Empty state */
    '.clients-empty {',
    '  text-align: center;',
    '  padding: var(--space-8);',
    '  color: var(--text-muted);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  background: var(--bg-surface);',
    '}',
    '.clients-empty-icon {',
    '  color: var(--text-muted);',
    '  margin-bottom: var(--space-3);',
    '}',
    '.clients-empty p {',
    '  margin: 0;',
    '  font-size: var(--text-sm);',
    '}',

    /* Stats bar */
    '.clients-stats {',
    '  display: flex;',
    '  gap: var(--space-4);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.clients-stat {',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  padding: var(--space-3) var(--space-4);',
    '  flex: 1;',
    '}',
    '.clients-stat-value {',
    '  font-size: var(--text-xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '}',
    '.clients-stat-label {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '}',

    /* Clickable row */
    '.client-row { cursor: pointer; transition: background 0.15s; }',
    '.client-row:hover { background: var(--bg-secondary); }',
    '.client-row td:last-child { opacity: 0.5; transition: opacity 0.15s; }',
    '.client-row:hover td:last-child { opacity: 1; }',

    /* Agent detail view */
    '.agent-detail { padding: var(--space-6); max-width: 1000px; }',
    '.agent-back-btn { display: inline-flex; align-items: center; gap: var(--space-1); cursor: pointer; font-size: var(--text-sm); color: var(--text-muted); background: none; border: none; padding: 0; margin-bottom: var(--space-4); }',
    '.agent-back-btn:hover { color: var(--text-primary); }',

    /* Header card */
    '.agent-header-card { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-5); margin-bottom: var(--space-4); display: flex; justify-content: space-between; align-items: flex-start; }',
    '.agent-header-info { min-width: 0; overflow: hidden; }',
    '.agent-header-info h2 { margin: 0 0 var(--space-1) 0; font-size: var(--text-xl); font-weight: var(--font-bold); }',
    '.agent-header-meta { display: flex; flex-wrap: wrap; gap: var(--space-4); font-size: var(--text-sm); color: var(--text-muted); margin-top: var(--space-2); }',
    '.agent-header-meta span { display: inline-flex; align-items: center; gap: var(--space-1); overflow: hidden; text-overflow: ellipsis; }',
    '.agent-roles { display: flex; gap: var(--space-1); margin-top: var(--space-2); }',
    '.agent-header-actions { display: flex; align-items: flex-start; gap: var(--space-2); flex-shrink: 0; margin-left: var(--space-4); }',

    /* Health status badge */
    '.health-badge { font-size: var(--text-xs); font-weight: var(--font-bold); padding: 2px 10px; border-radius: var(--radius-full); text-transform: uppercase; letter-spacing: 0.05em; }',
    '.health-badge.healthy { background: rgba(34,197,94,0.15); color: #16a34a; }',
    '.health-badge.attention { background: rgba(245,158,11,0.15); color: #b45309; }',
    '.health-badge.critical { background: rgba(239,68,68,0.15); color: var(--danger); }',

    /* KPI strip */
    '.agent-kpi-strip { display: grid; grid-template-columns: repeat(5, 1fr); gap: var(--space-3); margin-bottom: var(--space-4); }',
    '.agent-kpi { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-3) var(--space-4); text-align: center; }',
    '.agent-kpi-value { font-size: var(--text-2xl); font-weight: var(--font-bold); color: var(--text-primary); }',
    '.agent-kpi-label { font-size: var(--text-xs); color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }',
    '.agent-kpi-value.success { color: var(--success); }',
    '.agent-kpi-value.danger { color: var(--danger); }',
    '.agent-kpi-value.warning { color: var(--warning, #f59e0b); }',

    /* Health trend section */
    '.health-trend-section { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-4); margin-bottom: var(--space-4); }',
    '.health-sparkline-row { display: grid; grid-template-columns: 120px 1fr 80px; gap: var(--space-2); align-items: center; padding: var(--space-2) 0; font-size: var(--text-sm); }',
    '.health-sparkline-label { color: var(--text-secondary); font-weight: var(--font-medium); }',
    '.health-sparkline-svg { height: 24px; width: 100%; }',
    '.health-sparkline-avg { text-align: right; font-size: var(--text-xs); color: var(--text-muted); font-family: var(--font-mono); }',

    /* Health overview table */
    '.health-overview-table { width: 100%; border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; border-collapse: separate; border-spacing: 0; }',
    '.health-overview-table th { text-align: left; font-size: var(--text-xs); font-weight: var(--font-semibold); color: var(--text-muted); text-transform: uppercase; padding: var(--space-3); background: var(--bg-secondary); border-bottom: 1px solid var(--border); }',
    '.health-overview-table td { padding: var(--space-3); font-size: var(--text-sm); border-bottom: 1px solid var(--border); }',
    '.health-overview-table tr:last-child td { border-bottom: none; }',

    /* Tool usage */
    '.agent-section-title { font-size: var(--text-base); font-weight: var(--font-semibold); margin: 0 0 var(--space-3) 0; }',
    '.agent-tool-bar-row { display: flex; align-items: center; gap: var(--space-3); margin-bottom: var(--space-2); font-size: var(--text-sm); }',
    '.agent-tool-name { width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: var(--font-mono); font-size: var(--text-xs); }',
    '.agent-tool-bar-track { flex: 1; height: 20px; background: var(--bg-secondary); border-radius: var(--radius); overflow: hidden; }',
    '.agent-tool-bar-fill { height: 100%; background: var(--accent); border-radius: var(--radius); transition: width 0.3s; min-width: 2px; }',
    '.agent-tool-pct { width: 50px; text-align: right; font-size: var(--text-xs); color: var(--text-muted); }',

    /* Timeline */
    '.agent-timeline { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; margin-top: var(--space-4); }',
    '.agent-timeline-header { padding: var(--space-3) var(--space-4); border-bottom: 1px solid var(--border); }',
    '.agent-timeline-list { max-height: 400px; overflow-y: auto; }',
    '.agent-timeline-item { display: flex; align-items: center; gap: var(--space-3); padding: var(--space-2) var(--space-4); border-bottom: 1px solid var(--border); font-size: var(--text-sm); }',
    '.agent-timeline-item:last-child { border-bottom: none; }',
    '.agent-timeline-dot { width: 8px; height: 8px; border-radius: var(--radius-full); flex-shrink: 0; }',
    '.agent-timeline-dot.allow { background: var(--success); }',
    '.agent-timeline-dot.deny { background: var(--danger); }',
    '.agent-timeline-dot.other { background: var(--warning, #f59e0b); }',
    '.agent-timeline-tool { font-family: var(--font-mono); font-size: var(--text-xs); min-width: 120px; }',
    '.agent-timeline-time { color: var(--text-muted); font-size: var(--text-xs); margin-left: auto; white-space: nowrap; }',
    '.agent-timeline-reason { color: var(--text-muted); font-size: var(--text-xs); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }',
    '.agent-timeline-empty { padding: var(--space-6); text-align: center; color: var(--text-muted); font-size: var(--text-sm); }',
    /* Drift section (Upgrade 5 / Delta 2.1) */
    '.agent-drift-section { margin-bottom: var(--space-4); }',
    '.agent-drift-summary { display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap; padding: var(--space-3); background: var(--bg-secondary); border: 1px solid var(--border); border-radius: var(--radius-lg); }',
    '.agent-drift-score { font-weight: var(--font-bold); font-size: var(--text-sm); padding: 4px 12px; border-radius: var(--radius-full); }',
    '.agent-drift-score.high { background: rgba(239,68,68,0.15); color: var(--danger); }',
    '.agent-drift-score.medium { background: rgba(245,158,11,0.15); color: #b45309; }',
    '.agent-drift-score.low { background: rgba(34,197,94,0.15); color: #16a34a; }',
    '.agent-drift-count { font-size: var(--text-sm); color: var(--text-secondary); }',
    '.drift-detail-bars { margin-bottom: var(--space-3); }',
    '.drift-bar-row { display: grid; grid-template-columns: 120px 1fr 60px 60px 60px; gap: var(--space-2); align-items: center; padding: var(--space-1) 0; font-size: var(--text-sm); }',
    '.drift-bar-name { color: var(--text-primary); font-weight: var(--font-medium); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }',
    '.drift-bar-track { display: flex; gap: 2px; height: 16px; border-radius: var(--radius-sm); overflow: hidden; background: var(--bg-secondary); }',
    '.drift-bar-baseline { background: var(--accent); opacity: 0.4; height: 100%; }',
    '.drift-bar-current { background: var(--accent); height: 100%; }',
    '.drift-bar-pct { text-align: right; font-size: var(--text-xs); color: var(--text-muted); }',
    '.drift-bar-delta { text-align: right; font-size: var(--text-xs); font-weight: var(--font-semibold); }',
    '.drift-bar-delta.positive { color: var(--danger); }',
    '.drift-bar-delta.negative { color: #16a34a; }',
    '.drift-anomaly-card { padding: var(--space-2) var(--space-3); border-left: 3px solid; border-radius: var(--radius-md); margin-bottom: var(--space-2); background: var(--bg-primary); }',
    '.drift-anomaly-card.high { border-color: var(--danger); }',
    '.drift-anomaly-card.medium { border-color: #f59e0b; }',
    '.drift-anomaly-card.low { border-color: var(--accent); }',
    '.drift-anomaly-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-1); }',
    '.drift-anomaly-type { font-size: var(--text-xs); font-weight: var(--font-semibold); text-transform: uppercase; color: var(--text-muted); }',
    '.drift-anomaly-sev { font-size: 10px; padding: 1px 8px; border-radius: var(--radius-full); font-weight: var(--font-bold); }',
    '.drift-anomaly-sev.high { background: rgba(239,68,68,0.15); color: var(--danger); }',
    '.drift-anomaly-sev.medium { background: rgba(245,158,11,0.15); color: #b45309; }',
    '.drift-anomaly-sev.low { background: rgba(34,197,94,0.15); color: #16a34a; }',
    '.drift-anomaly-desc { font-size: var(--text-sm); color: var(--text-primary); }'
  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-clients', '');
    s.textContent = CLIENTS_CSS;
    document.head.appendChild(s);
    styleInjected = true;
  }

  // -- DOM helpers ------------------------------------------------------------

  function mk(tag, className) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    return node;
  }

  // -- Time formatting --------------------------------------------------------

  function formatDuration(startStr) {
    try {
      var start = new Date(startStr);
      var now = new Date();
      var diffMs = now - start;
      var secs = Math.floor(diffMs / 1000);
      if (secs < 60) return secs + 's';
      var mins = Math.floor(secs / 60);
      if (mins < 60) return mins + 'm ' + (secs % 60) + 's';
      var hrs = Math.floor(mins / 60);
      if (hrs < 24) return hrs + 'h ' + (mins % 60) + 'm';
      var days = Math.floor(hrs / 24);
      return days + 'd ' + (hrs % 24) + 'h';
    } catch (e) {
      return '-';
    }
  }

  function formatTime(dateStr) {
    try {
      var d = new Date(dateStr);
      if (isNaN(d.getTime())) return dateStr || '-';
      var yyyy = d.getFullYear();
      var mo = String(d.getMonth() + 1).padStart(2, '0');
      var dd = String(d.getDate()).padStart(2, '0');
      var hh = String(d.getHours()).padStart(2, '0');
      var mi = String(d.getMinutes()).padStart(2, '0');
      var sc = String(d.getSeconds()).padStart(2, '0');
      return yyyy + '-' + mo + '-' + dd + ' ' + hh + ':' + mi + ':' + sc;
    } catch (e) {
      return dateStr || '-';
    }
  }

  // -- Sparkline SVG renderer -------------------------------------------------

  function renderSparkline(values, color) {
    if (!values || values.length === 0) return '';
    var max = 0;
    for (var i = 0; i < values.length; i++) {
      if (values[i] > max) max = values[i];
    }
    if (max === 0) max = 1;
    var w = 200;
    var h = 24;
    var step = w / Math.max(values.length - 1, 1);
    var points = [];
    for (var j = 0; j < values.length; j++) {
      var x = Math.round(j * step);
      var y = Math.round(h - (values[j] / max) * (h - 4) - 2);
      points.push(x + ',' + y);
    }
    return '<svg class="health-sparkline-svg" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
      '<polyline points="' + points.join(' ') + '" fill="none" stroke="' + (color || 'var(--primary)') + '" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>' +
      '</svg>';
  }

  // -- Build stats bar --------------------------------------------------------

  function buildStats(sessions, statsWrapper) {
    statsWrapper.innerHTML = '';

    var activeSessions = 0;
    var staleSessions = 0;
    var totalCalls = 0;
    for (var i = 0; i < (sessions || []).length; i++) {
      totalCalls += sessions[i].total_calls || 0;
      if (sessions[i].status === 'stale') {
        staleSessions++;
      } else {
        activeSessions++;
      }
    }

    var stats = [
      { value: activeSessions, label: 'Active Sessions' },
      { value: staleSessions, label: 'Stale Sessions' },
      { value: totalCalls, label: 'Total Calls' }
    ];

    for (var s = 0; s < stats.length; s++) {
      var card = mk('div', 'clients-stat');
      var val = mk('div', 'clients-stat-value');
      val.textContent = stats[s].value;
      card.appendChild(val);
      var lbl = mk('div', 'clients-stat-label');
      lbl.textContent = stats[s].label;
      card.appendChild(lbl);
      statsWrapper.appendChild(card);
    }
  }

  // -- Build clients table ----------------------------------------------------

  function buildClientsTable(sessions, tableWrapper) {
    tableWrapper.innerHTML = '';

    if (!sessions || sessions.length === 0) {
      var empty = mk('div', 'clients-empty');
      if (SG.icon) {
        var iconWrap = mk('div', 'clients-empty-icon');
        iconWrap.innerHTML = SG.icon('users', 32);
        empty.appendChild(iconWrap);
      }
      var p = mk('p', '');
      p.textContent = 'No agents connected. Configure an agent to connect through this proxy.';
      // Check if identities with API keys exist — show a more helpful message
      SG.api.get('/keys', { silent: true }).then(function (keys) {
        if (keys && keys.length > 0) {
          p.textContent = 'No active sessions. Configured agents will appear here when they connect.';
        }
      }).catch(function () {});
      empty.appendChild(p);
      tableWrapper.appendChild(empty);
      return;
    }

    var table = mk('table', 'client-table');

    // Header
    var thead = mk('thead', '');
    var headRow = mk('tr', '');
    var cols = ['Status', 'Identity', 'Session', 'Connected', 'Requests', 'Last Activity', ''];
    for (var c = 0; c < cols.length; c++) {
      var th = mk('th', '');
      th.textContent = cols[c];
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    // Body
    var tbody = mk('tbody', '');
    for (var i = 0; i < sessions.length; i++) {
      var sess = sessions[i];
      var row = mk('tr', 'client-row');

      // Status — show idle/stale based on last activity (or session start time as fallback)
      var tdStatus = mk('td', '');
      var dot = mk('span', 'client-status-dot');
      var statusLabel = 'connected';
      var lastActivity = sess.last_call_at || sess.last_activity || sess.started_at;
      if (lastActivity) {
        var idleMinutes = (Date.now() - new Date(lastActivity).getTime()) / 60000;
        if (idleMinutes > 15) {
          statusLabel = 'stale';
          dot.classList.add('stale');
        } else if (idleMinutes > 5) {
          statusLabel = 'idle';
          dot.classList.add('idle');
        }
      }
      tdStatus.appendChild(dot);
      tdStatus.appendChild(document.createTextNode(statusLabel));
      row.appendChild(tdStatus);

      // Identity — show name instead of UUID
      var tdIdentity = mk('td', '');
      tdIdentity.textContent = sess.identity_name || sess.identity || sess.identity_id || '-';
      if (sess.identity_id) tdIdentity.title = sess.identity_id;
      row.appendChild(tdIdentity);

      // Session ID
      var tdSession = mk('td', 'client-session-id');
      tdSession.textContent = sess.session_id || sess.id || '-';
      tdSession.title = sess.session_id || sess.id || '';
      row.appendChild(tdSession);

      // Connected duration
      var tdConnected = mk('td', '');
      if (sess.started_at || sess.created_at) {
        tdConnected.textContent = formatDuration(sess.started_at || sess.created_at);
        tdConnected.title = formatTime(sess.started_at || sess.created_at);
      } else {
        tdConnected.textContent = '-';
      }
      row.appendChild(tdConnected);

      // Request count
      var tdReqs = mk('td', '');
      var badge = mk('span', 'client-count-badge');
      badge.textContent = sess.total_calls || 0;
      tdReqs.appendChild(badge);
      row.appendChild(tdReqs);

      // Last activity
      var tdLast = mk('td', '');
      tdLast.textContent = sess.last_call_at ? formatTime(sess.last_call_at) : '-';
      row.appendChild(tdLast);

      // Chevron indicator
      var tdChevron = mk('td', '');
      tdChevron.style.cssText = 'width: 24px; color: var(--text-muted); text-align: center;';
      tdChevron.innerHTML = SG.icon('chevronRight', 14);
      row.appendChild(tdChevron);

      // Click to view agent detail
      (function (identityId) {
        row.addEventListener('click', function () {
          showAgentDetail(identityId);
        });
      })(sess.identity_id || sess.identity || '');

      tbody.appendChild(row);
    }
    table.appendChild(tbody);
    tableWrapper.appendChild(table);
  }

  // -- Agent Detail View (UX-F2 + Delta 3.2 Health Fusion) --------------------

  var currentContainer = null;

  function showAgentDetail(identityId) {
    cleanup(); // stop list polling

    if (!currentContainer) return;
    currentContainer.innerHTML = '<div class="agent-detail"><p style="color: var(--text-muted);">Loading agent data...</p></div>';

    // Fetch summary, health and drift profile in parallel
    var summaryP = SG.api.get('/v1/agents/' + encodeURIComponent(identityId) + '/summary');
    var healthP = SG.api.get('/v1/agents/' + encodeURIComponent(identityId) + '/health').catch(function () { return null; });
    var driftP = SG.api.get('/v1/drift/profiles/' + encodeURIComponent(identityId)).catch(function () { return null; });

    Promise.all([summaryP, healthP, driftP]).then(function (results) {
      if (!currentContainer) return;
      renderAgentDetail(currentContainer, results[0], results[1], results[2]);
    }).catch(function (err) {
      if (!currentContainer) return;
      currentContainer.innerHTML =
        '<div class="agent-detail">' +
          '<button class="agent-back-btn" id="agent-back">&larr; Back to Agents</button>' +
          '<p style="color: var(--danger);">Failed to load agent data: ' + (err.message || 'Unknown error') + '</p>' +
        '</div>';
      wireBackButton();
    });
  }

  function renderAgentDetail(container, data, healthData, driftReport) {
    var id = data.identity || {};
    var sess = data.session;
    var stats = data.stats || {};
    var tools = data.tool_usage || [];
    var timeline = data.timeline || [];

    // Time-based status detection (same logic as the list view and All Sessions table)
    var statusClass = '';
    var statusLabel = 'connected';
    if (sess) {
      var lastAct = sess.last_call_at || sess.last_activity || sess.started_at;
      if (lastAct) {
        var idleMins = (Date.now() - new Date(lastAct).getTime()) / 60000;
        if (idleMins > 15) {
          statusClass = 'stale';
          statusLabel = 'stale';
        } else if (idleMins > 5) {
          statusClass = 'idle';
          statusLabel = 'idle';
        }
      }
    }

    var connectedSince = sess ? formatDuration(sess.started_at) : '-';
    var healthStatus = stats.health_status || 'healthy';

    var rolesHtml = '';
    if (id.roles && id.roles.length) {
      for (var r = 0; r < id.roles.length; r++) {
        rolesHtml += '<span class="badge badge-muted">' + esc(id.roles[r]) + '</span>';
      }
    }

    var denyPct = stats.total_calls > 0 ? ((stats.deny_rate || 0) * 100).toFixed(1) : '0.0';

    var html =
      '<div class="agent-detail">' +
        '<button class="agent-back-btn" id="agent-back">&larr; Back to Agents</button>' +

        // Header Card with health badge
        '<div class="agent-header-card">' +
          '<div class="agent-header-info">' +
            '<h2>' + esc(id.name || id.id) + ' <span class="health-badge ' + healthStatus + '">' + healthStatus + '</span></h2>' +
            '<div class="agent-roles">' + rolesHtml + '</div>' +
            '<div class="agent-header-meta">' +
              '<span><span class="client-status-dot ' + statusClass + '"></span>' + statusLabel + '</span>' +
              '<span>Connected: ' + connectedSince + '</span>' +
              (sess ? '<span>Session: <code>' + esc(sess.session_id) + '</code></span>' : '') +
            '</div>' +
          '</div>' +
          '<div class="agent-header-actions">' +
            (healthStatus !== 'healthy' ? '<button class="btn btn-secondary btn-sm" id="agent-ack-btn">Acknowledge Alert</button>' : '') +
            '<button class="btn btn-secondary btn-sm" id="agent-compliance-btn">View Compliance</button>' +
          '</div>' +
        '</div>' +

        // KPI Strip (consolidated: Calls, Denied, Deny%, Drift, Violations)
        '<div class="agent-kpi-strip">' +
          '<div class="agent-kpi"><div class="agent-kpi-value">' + (stats.total_calls || 0) + '</div><div class="agent-kpi-label">Calls</div></div>' +
          '<div class="agent-kpi"><div class="agent-kpi-value danger">' + (stats.denied_calls || 0) + '</div><div class="agent-kpi-label">Denied</div></div>' +
          '<div class="agent-kpi"><div class="agent-kpi-value' + (parseFloat(denyPct) > 10 ? ' danger' : parseFloat(denyPct) > 0 ? ' warning' : '') + '">' + denyPct + '%</div><div class="agent-kpi-label">Deny Rate</div></div>' +
          '<div class="agent-kpi"><div class="agent-kpi-value' + (stats.drift_score > 0.3 ? ' danger' : stats.drift_score > 0 ? ' warning' : '') + '">' + (stats.drift_score ? stats.drift_score.toFixed(2) : '0.00') + '</div><div class="agent-kpi-label">Drift</div></div>' +
          '<div class="agent-kpi"><div class="agent-kpi-value' + ((stats.violation_count || 0) > 0 ? ' danger' : '') + '">' + (stats.violation_count || 0) + '</div><div class="agent-kpi-label">Violations</div></div>' +
        '</div>';

    // Health Trend (30-day sparklines) -- Delta 3.2
    if (healthData && healthData.trend && healthData.trend.length > 0) {
      var trend = healthData.trend;
      var denyValues = [], driftValues = [], errorValues = [], violValues = [], callValues = [];
      var denySum = 0, driftSum = 0, errorSum = 0, violSum = 0, activeDays = 0;
      for (var ti = 0; ti < trend.length; ti++) {
        denyValues.push(trend[ti].deny_rate || 0);
        driftValues.push(trend[ti].drift_score || 0);
        errorValues.push(trend[ti].error_rate || 0);
        violValues.push(trend[ti].violation_count || 0);
        callValues.push(trend[ti].call_volume || 0);
        if (trend[ti].call_volume > 0) {
          denySum += trend[ti].deny_rate || 0;
          errorSum += trend[ti].error_rate || 0;
          activeDays++;
        }
        driftSum += trend[ti].drift_score || 0;
        violSum += trend[ti].violation_count || 0;
      }
      var avgDeny = activeDays > 0 ? (denySum / activeDays * 100).toFixed(1) + '%' : '0.0%';
      var avgError = activeDays > 0 ? (errorSum / activeDays * 100).toFixed(1) + '%' : '0.0%';
      var totalViol = violSum;

      html += '<div class="health-trend-section">' +
        '<h3 class="agent-section-title">Health Trend (30 days)</h3>' +
        '<div class="health-sparkline-row">' +
          '<span class="health-sparkline-label">Deny Rate</span>' +
          renderSparkline(denyValues, 'var(--danger)') +
          '<span class="health-sparkline-avg">avg: ' + avgDeny + '</span>' +
        '</div>' +
        '<div class="health-sparkline-row">' +
          '<span class="health-sparkline-label">Error Rate</span>' +
          renderSparkline(errorValues, 'var(--warning, #f59e0b)') +
          '<span class="health-sparkline-avg">avg: ' + avgError + '</span>' +
        '</div>' +
        '<div class="health-sparkline-row">' +
          '<span class="health-sparkline-label">Violations</span>' +
          renderSparkline(violValues, 'var(--danger)') +
          '<span class="health-sparkline-avg">total: ' + totalViol + '</span>' +
        '</div>' +
        '<div class="health-sparkline-row">' +
          '<span class="health-sparkline-label">Call Volume</span>' +
          renderSparkline(callValues, 'var(--primary)') +
          '<span class="health-sparkline-avg">' + (callValues.reduce(function(a,b){return a+b},0) > 0 ? 'total: ' + callValues.reduce(function(a,b){return a+b},0) : 'No data yet') + '</span>' +
        '</div>' +
      '</div>';
    }

    // Drift Analysis (Upgrade 5 / Delta 2.1) — inline breakdown
    if (stats.drift_score > 0 || stats.anomaly_count > 0) {
      html += '<div class="agent-drift-section">' +
        '<h3 class="agent-section-title">Behavioral Drift</h3>' +
        '<div class="agent-drift-summary">' +
          '<span class="agent-drift-score ' + (stats.drift_score > 0.5 ? 'high' : stats.drift_score > 0.2 ? 'medium' : 'low') + '">Score: ' + (stats.drift_score || 0).toFixed(2) + '</span>' +
          '<span class="agent-drift-count">' + (stats.anomaly_count || 0) + ' anomalies detected</span>' +
          '<button class="btn btn-secondary btn-sm" id="view-drift-btn" data-identity="' + esc(id.id) + '">Full Tool Distribution</button>' +
          '<button class="btn btn-secondary btn-sm" id="create-policy-drift-btn" data-identity="' + esc(id.id) + '">Create Policy from Drift</button>' +
          '<button class="btn btn-secondary btn-sm" id="reset-baseline-btn" data-identity="' + esc(id.id) + '">Reset Historical Pattern</button>' +
        '</div>' +
        '<div id="drift-inline-breakdown"></div>' +
      '</div>';
    }

    // Tool Usage Breakdown
    if (tools.length > 0) {
      html += '<h3 class="agent-section-title">Tool Usage (Last 24h)</h3>';
      for (var t = 0; t < Math.min(tools.length, 10); t++) {
        var tool = tools[t];
        html +=
          '<div class="agent-tool-bar-row">' +
            '<div class="agent-tool-name" title="' + esc(tool.tool_name) + '">' + esc(tool.tool_name) + '</div>' +
            '<div class="agent-tool-bar-track"><div class="agent-tool-bar-fill" style="width: ' + Math.round(tool.percent) + '%;"></div></div>' +
            '<div class="agent-tool-pct">' + Math.round(tool.percent) + '%</div>' +
          '</div>';
      }
    }

    // Timeline
    html += '<div class="agent-timeline">' +
      '<div class="agent-timeline-header"><h3 class="agent-section-title" style="margin:0;">Recent Activity</h3></div>' +
      '<div class="agent-timeline-list">';

    if (timeline.length === 0) {
      html += '<div class="agent-timeline-empty">No activity in the last 24 hours.</div>';
    } else {
      for (var i = 0; i < timeline.length; i++) {
        var item = timeline[i];
        var dotClass = item.decision === 'allow' ? 'allow' : (item.decision === 'deny' || item.decision === 'blocked' ? 'deny' : 'other');
        html +=
          '<div class="agent-timeline-item">' +
            '<span class="agent-timeline-dot ' + dotClass + '"></span>' +
            '<span class="agent-timeline-tool">' + esc(item.tool_name || '-') + '</span>' +
            '<span class="badge badge-' + (item.decision === 'allow' ? 'success' : 'danger') + '">' + esc(item.decision) + '</span>' +
            (item.reason ? '<span class="agent-timeline-reason" title="' + esc(item.reason) + '">' + esc(item.reason) + '</span>' : '') +
            '<span class="agent-timeline-time">' + formatTime(item.timestamp) + '</span>' +
          '</div>';
      }
    }

    html += '</div></div>';

    // All Sessions placeholder (populated async)
    html += '<div id="agent-all-sessions" style="margin-top:var(--space-4)"><h3 class="agent-section-title">All Sessions</h3><p style="color:var(--text-muted)">Loading sessions...</p></div>';

    html += '</div>';

    container.innerHTML = html;
    wireBackButton();

    // Populate drift breakdown inline if data available
    if (driftReport && (driftReport.drift_score > 0 || (driftReport.anomalies && driftReport.anomalies.length > 0))) {
      var driftEl = document.getElementById('drift-inline-breakdown');
      if (driftEl) { renderDriftBreakdownInline(driftEl, driftReport); }
    }

    // Load all sessions for this identity
    SG.api.get('/v1/sessions/active').then(function (allSess) {
      var sessions = Array.isArray(allSess) ? allSess : (allSess && allSess.sessions ? allSess.sessions : []);
      var identitySessions = sessions.filter(function (s) {
        return s.identity_id === id.id || s.identity === id.id;
      });
      var el = document.getElementById('agent-all-sessions');
      if (!el) return;
      if (identitySessions.length === 0) {
        el.innerHTML = '<h3 class="agent-section-title">All Sessions</h3><p style="color:var(--text-muted)">No sessions found.</p>';
        return;
      }
      var maxRows = 50;
      var shtml = '<h3 class="agent-section-title">All Sessions (' + identitySessions.length + ')</h3>';
      shtml += '<table class="table" style="font-size:var(--text-sm)"><thead><tr><th>Session</th><th>Status</th><th>Started</th><th>Calls</th></tr></thead><tbody>';
      for (var si = 0; si < Math.min(identitySessions.length, maxRows); si++) {
        var s = identitySessions[si];
        shtml += '<tr><td><code style="font-size:var(--text-xs)">' + esc(s.session_id || s.id || '-') + '</code></td>';
        // Time-based status detection (same logic as agent list view)
        var sessStatus = 'connected';
        var sessLastActivity = s.last_call_at || s.last_activity || s.started_at;
        if (sessLastActivity) {
          var sessIdleMins = (Date.now() - new Date(sessLastActivity).getTime()) / 60000;
          if (sessIdleMins > 15) { sessStatus = 'stale'; }
          else if (sessIdleMins > 5) { sessStatus = 'idle'; }
        }
        shtml += '<td><span class="client-status-dot ' + sessStatus + '"></span> ' + esc(sessStatus) + '</td>';
        shtml += '<td>' + (s.started_at ? formatDuration(s.started_at) : '-') + '</td>';
        shtml += '<td>' + (s.total_calls || 0) + '</td></tr>';
      }
      shtml += '</tbody></table>';
      if (identitySessions.length > maxRows) {
        shtml += '<p style="font-size:var(--text-xs);color:var(--text-muted)">Showing ' + maxRows + ' of ' + identitySessions.length + ' sessions.</p>';
      }
      el.innerHTML = shtml;
    }).catch(function () {
      var el = document.getElementById('agent-all-sessions');
      if (el) el.innerHTML = '<h3 class="agent-section-title">All Sessions</h3><p style="color:var(--text-muted)">Could not load sessions.</p>';
    });

    var ackBtn = document.getElementById('agent-ack-btn');
    if (ackBtn) {
      ackBtn.addEventListener('click', function () {
        SG.api.post('/v1/agents/' + encodeURIComponent(id.id) + '/acknowledge', {
          acknowledged_status: healthStatus
        }).then(function () {
          SG.toast.success('Alert acknowledged for ' + (id.name || id.id));
          ackBtn.textContent = 'Acknowledged';
          ackBtn.disabled = true;
        }).catch(function (err) {
          SG.toast.error(err.message || 'Failed to acknowledge');
        });
      });
    }

    var complianceBtn = document.getElementById('agent-compliance-btn');
    if (complianceBtn) {
      complianceBtn.addEventListener('click', function () {
        window.location.hash = '#/compliance';
      });
    }

    // Drift buttons (Upgrade 5)
    var viewDriftBtn = document.getElementById('view-drift-btn');
    if (viewDriftBtn) {
      viewDriftBtn.addEventListener('click', function () {
        var did = viewDriftBtn.getAttribute('data-identity');
        openDriftDetail(did);
      });
    }
    var createPolicyBtn = document.getElementById('create-policy-drift-btn');
    if (createPolicyBtn) {
      createPolicyBtn.addEventListener('click', function () {
        window.location.hash = '#/tools';
        setTimeout(function () {
          if (SG.tools && SG.tools.openRuleModal) {
            SG.tools.openRuleModal(null, null, '*');
          }
        }, 500);
      });
    }
    var resetBtn = document.getElementById('reset-baseline-btn');
    if (resetBtn) {
      resetBtn.addEventListener('click', function () {
        var rid = resetBtn.getAttribute('data-identity');
        SG.api.post('/v1/drift/profiles/' + encodeURIComponent(rid) + '/reset').then(function () {
          SG.toast.success('Historical pattern reset for ' + rid);
          showAgentDetail(rid);
        }).catch(function (err) {
          SG.toast.error(err.message || 'Reset failed');
        });
      });
    }
  }

  // -- Drift Breakdown Inline (shows components + anomalies without a modal) ----

  function driftCountActiveHours(profile) {
    var hp = profile.hourly_pattern || [];
    var n = 0;
    for (var i = 0; i < hp.length; i++) { if (hp[i] > 0) n++; }
    return n;
  }

  function driftCountArgKeys(profile) {
    var abt = profile.arg_keys_by_tool || {};
    var n = 0;
    for (var t in abt) { if (abt.hasOwnProperty(t)) { n += Object.keys(abt[t] || {}).length; } }
    return n;
  }

  function renderDriftBreakdownInline(parentEl, report) {
    var baseline = report.baseline || {};
    var current = report.current || {};

    // Score Components table
    if (baseline.total_calls > 0 || current.total_calls > 0) {
      var title = mk('h4', 'agent-section-title');
      title.style.cssText = 'margin: var(--space-3) 0 var(--space-2) 0; font-size: var(--text-sm);';
      title.textContent = 'Score Components';
      parentEl.appendChild(title);

      var components = [
        { label: 'Deny Rate', hist: ((baseline.deny_rate || 0) * 100).toFixed(1) + '%', curr: ((current.deny_rate || 0) * 100).toFixed(1) + '%' },
        { label: 'Error Rate', hist: ((baseline.error_rate || 0) * 100).toFixed(1) + '%', curr: ((current.error_rate || 0) * 100).toFixed(1) + '%' },
        { label: 'Total Calls', hist: String(baseline.total_calls || 0), curr: String(current.total_calls || 0) },
        { label: 'Avg Latency', hist: ((baseline.avg_latency_us || 0) / 1000).toFixed(0) + 'ms', curr: ((current.avg_latency_us || 0) / 1000).toFixed(0) + 'ms' },
        { label: 'Temporal Pattern', hist: driftCountActiveHours(baseline) + 'h active', curr: driftCountActiveHours(current) + 'h active' },
        { label: 'Argument Shift', hist: driftCountArgKeys(baseline) + ' keys', curr: driftCountArgKeys(current) + ' keys' }
      ];

      var grid = '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:var(--space-1);font-size:var(--text-sm);margin-bottom:var(--space-3);">';
      grid += '<div style="font-weight:var(--font-semibold);font-size:var(--text-xs);color:var(--text-muted);">Metric</div>';
      grid += '<div style="font-weight:var(--font-semibold);font-size:var(--text-xs);color:var(--text-muted);text-align:right;">Historical (14d)</div>';
      grid += '<div style="font-weight:var(--font-semibold);font-size:var(--text-xs);color:var(--text-muted);text-align:right;">Current</div>';
      for (var i = 0; i < components.length; i++) {
        grid += '<div style="color:var(--text-secondary);">' + components[i].label + '</div>';
        grid += '<div style="text-align:right;font-family:var(--font-mono);">' + components[i].hist + '</div>';
        grid += '<div style="text-align:right;font-family:var(--font-mono);">' + components[i].curr + '</div>';
      }
      grid += '</div>';
      var gridEl = document.createElement('div');
      gridEl.innerHTML = grid;
      parentEl.appendChild(gridEl);
    }

    // Anomaly Cards
    var anomalies = report.anomalies || [];
    if (anomalies.length > 0) {
      var anomTitle = mk('h4', 'agent-section-title');
      anomTitle.style.cssText = 'margin: var(--space-2) 0; font-size: var(--text-sm);';
      anomTitle.textContent = 'Anomalies (' + anomalies.length + ')';
      parentEl.appendChild(anomTitle);

      for (var a = 0; a < anomalies.length; a++) {
        var anom = anomalies[a];
        var card = mk('div', 'drift-anomaly-card ' + anom.severity);
        card.innerHTML =
          '<div class="drift-anomaly-header">' +
            '<span class="drift-anomaly-type">' + esc(anom.type) + (anom.tool_name ? ' — ' + esc(anom.tool_name) : '') + '</span>' +
            '<span class="drift-anomaly-sev ' + anom.severity + '">' + anom.severity.toUpperCase() + '</span>' +
          '</div>' +
          '<div class="drift-anomaly-desc">' + esc(anom.description) + '</div>';
        parentEl.appendChild(card);
      }
    }
  }

  // -- Drift Detail Modal (Delta 2.1) -----------------------------------------

  function openDriftDetail(identityId) {
    SG.api.get('/v1/drift/profiles/' + encodeURIComponent(identityId)).then(function (report) {
      var body = document.createElement('div');

      // Score summary
      var scoreLevel = report.drift_score > 0.5 ? 'high' : report.drift_score > 0.2 ? 'medium' : 'low';
      var summary = mk('div', '');
      summary.style.cssText = 'margin-bottom: var(--space-4); font-size: var(--text-sm);';
      summary.innerHTML = '<strong>Drift Score:</strong> <span class="drift-anomaly-sev ' + scoreLevel + '">' + (report.drift_score || 0).toFixed(2) + '</span>' +
        '&nbsp;&nbsp;<strong>Anomalies:</strong> ' + ((report.anomalies || []).length);
      body.appendChild(summary);

      // Drift Score Component Breakdown
      var baseline = report.baseline || {};
      var current = report.current || {};

      if (baseline.total_calls > 0 || current.total_calls > 0) {
        var breakdownTitle = mk('h3', 'agent-section-title');
        breakdownTitle.textContent = 'Score Components';
        body.appendChild(breakdownTitle);

        var components = [
          { label: 'Deny Rate', hist: ((baseline.deny_rate || 0) * 100).toFixed(1) + '%', curr: ((current.deny_rate || 0) * 100).toFixed(1) + '%' },
          { label: 'Error Rate', hist: ((baseline.error_rate || 0) * 100).toFixed(1) + '%', curr: ((current.error_rate || 0) * 100).toFixed(1) + '%' },
          { label: 'Total Calls', hist: String(baseline.total_calls || 0), curr: String(current.total_calls || 0) },
          { label: 'Avg Latency', hist: ((baseline.avg_latency_us || 0) / 1000).toFixed(0) + 'ms', curr: ((current.avg_latency_us || 0) / 1000).toFixed(0) + 'ms' },
          { label: 'Temporal Pattern', hist: driftCountActiveHours(baseline) + 'h active', curr: driftCountActiveHours(current) + 'h active' },
          { label: 'Argument Shift', hist: driftCountArgKeys(baseline) + ' keys', curr: driftCountArgKeys(current) + ' keys' }
        ];

        var bkTable = '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:var(--space-1);font-size:var(--text-sm);margin-bottom:var(--space-4);">';
        bkTable += '<div style="font-weight:var(--font-semibold);font-size:var(--text-xs);color:var(--text-muted);">Metric</div>';
        bkTable += '<div style="font-weight:var(--font-semibold);font-size:var(--text-xs);color:var(--text-muted);text-align:right;">Historical (14d)</div>';
        bkTable += '<div style="font-weight:var(--font-semibold);font-size:var(--text-xs);color:var(--text-muted);text-align:right;">Current</div>';
        for (var ci = 0; ci < components.length; ci++) {
          bkTable += '<div style="color:var(--text-secondary);">' + components[ci].label + '</div>';
          bkTable += '<div style="text-align:right;font-family:var(--font-mono);">' + components[ci].hist + '</div>';
          bkTable += '<div style="text-align:right;font-family:var(--font-mono);">' + components[ci].curr + '</div>';
        }
        bkTable += '</div>';
        var bkEl = document.createElement('div');
        bkEl.innerHTML = bkTable;
        body.appendChild(bkEl);
      }

      // Tool Distribution Comparison
      var bDist = baseline.tool_distribution || {};
      var cDist = current.tool_distribution || {};

      var allTools = {};
      var k;
      for (k in bDist) allTools[k] = true;
      for (k in cDist) allTools[k] = true;
      var toolNames = Object.keys(allTools).sort(function (a, b) {
        return (cDist[b] || 0) - (cDist[a] || 0);
      });

      if (toolNames.length > 0) {
        var barsTitle = mk('h3', 'agent-section-title');
        barsTitle.textContent = 'Tool Distribution (Historical Pattern vs Current)';
        body.appendChild(barsTitle);

        var bars = mk('div', 'drift-detail-bars');
        // Header
        var headerRow = mk('div', 'drift-bar-row');
        headerRow.style.cssText = 'font-weight: var(--font-semibold); font-size: var(--text-xs); color: var(--text-muted);';
        headerRow.innerHTML = '<span>Tool</span><span></span><span style="text-align:right;">Historical</span><span style="text-align:right;">Current</span><span style="text-align:right;">Delta</span>';
        bars.appendChild(headerRow);

        for (var di = 0; di < Math.min(toolNames.length, 15); di++) {
          var dtool = toolNames[di];
          var bPct = (bDist[dtool] || 0) * 100;
          var cPct = (cDist[dtool] || 0) * 100;
          var delta = cPct - bPct;

          var drow = mk('div', 'drift-bar-row');
          drow.innerHTML =
            '<span class="drift-bar-name" title="' + esc(dtool) + '">' + esc(dtool) + '</span>' +
            '<div class="drift-bar-track">' +
              '<div class="drift-bar-baseline" style="width:' + Math.round(bPct) + '%;"></div>' +
              '<div class="drift-bar-current" style="width:' + Math.round(cPct) + '%;"></div>' +
            '</div>' +
            '<span class="drift-bar-pct">' + Math.round(bPct) + '%</span>' +
            '<span class="drift-bar-pct">' + Math.round(cPct) + '%</span>' +
            '<span class="drift-bar-delta ' + (delta > 0 ? 'positive' : delta < 0 ? 'negative' : '') + '">' +
              (delta > 0 ? '+' : '') + Math.round(delta) + '%</span>';
          bars.appendChild(drow);
        }
        body.appendChild(bars);
      }

      // Anomaly Cards
      var anomalies = report.anomalies || [];
      if (anomalies.length > 0) {
        var anomTitle = mk('h3', 'agent-section-title');
        anomTitle.textContent = 'Anomalies Detected (' + anomalies.length + ')';
        body.appendChild(anomTitle);

        for (var a = 0; a < anomalies.length; a++) {
          var anom = anomalies[a];
          var card = mk('div', 'drift-anomaly-card ' + anom.severity);
          card.innerHTML =
            '<div class="drift-anomaly-header">' +
              '<span class="drift-anomaly-type">' + esc(anom.type) + (anom.tool_name ? ' — ' + esc(anom.tool_name) : '') + '</span>' +
              '<span class="drift-anomaly-sev ' + anom.severity + '">' + anom.severity.toUpperCase() + '</span>' +
            '</div>' +
            '<div class="drift-anomaly-desc">' + esc(anom.description) + '</div>';
          body.appendChild(card);
        }
      }

      // Footer with actions
      var footer = mk('div', '');
      footer.style.cssText = 'display: flex; gap: var(--space-2); justify-content: flex-end; margin-top: var(--space-3);';

      var dResetBtn = mk('button', 'btn btn-secondary');
      dResetBtn.textContent = 'Reset Historical Pattern';
      dResetBtn.addEventListener('click', function () {
        SG.api.post('/v1/drift/profiles/' + encodeURIComponent(identityId) + '/reset').then(function () {
          SG.toast.success('Historical pattern reset');
          SG.modal.close();
        }).catch(function (err) { SG.toast.error(err.message); });
      });
      footer.appendChild(dResetBtn);

      var closeBtn = mk('button', 'btn btn-primary');
      closeBtn.textContent = 'Close';
      closeBtn.addEventListener('click', function () { SG.modal.close(); });
      footer.appendChild(closeBtn);
      body.appendChild(footer);

      SG.modal.open({
        title: 'Drift Analysis — ' + identityId,
        body: body,
        width: '750px'
      });
    }).catch(function (err) {
      SG.toast.error(err.message || 'Failed to load drift data');
    });
  }

  // -- Health Overview (cross-agent) ------------------------------------------

  function showHealthOverview() {
    cleanup();
    if (!currentContainer) return;
    currentContainer.innerHTML = '<div class="agent-detail"><p style="color: var(--text-muted);">Loading health overview...</p></div>';

    SG.api.get('/v1/health/overview').then(function (entries) {
      if (!currentContainer) return;
      renderHealthOverview(currentContainer, entries || []);
    }).catch(function (err) {
      if (!currentContainer) return;
      currentContainer.innerHTML =
        '<div class="agent-detail">' +
          '<button class="agent-back-btn" id="agent-back">&larr; Back to Agents</button>' +
          '<p style="color: var(--danger);">Failed to load health overview: ' + (err.message || 'Unknown error') + '</p>' +
        '</div>';
      wireBackButton();
    });
  }

  function renderHealthOverview(container, entries) {
    var html = '<div class="agent-detail">' +
      '<button class="agent-back-btn" id="agent-back">&larr; Back to Agents</button>' +
      '<h2 style="margin: 0 0 var(--space-2) 0; font-size: var(--text-xl); font-weight: var(--font-bold);">Health Overview</h2>' +
      '<p class="page-subtitle">Cross-agent health comparison and activity monitoring.</p>';

    if (entries.length === 0) {
      html += '<div class="clients-empty"><p>No agents with recent activity.</p></div>';
    } else {
      html += '<table class="health-overview-table">' +
        '<thead><tr>' +
          '<th>Agent</th><th>Deny%</th><th>Drift</th><th>Errors</th><th>Violations</th><th>Calls</th><th>Status</th>' +
        '</tr></thead><tbody>';
      for (var i = 0; i < entries.length; i++) {
        var e = entries[i];
        html += '<tr style="cursor:pointer;" data-id="' + esc(e.identity_id) + '" class="health-overview-row">' +
          '<td>' + esc(e.identity_name || e.identity_id) + '</td>' +
          '<td>' + ((e.deny_rate || 0) * 100).toFixed(1) + '%</td>' +
          '<td>' + (e.drift_score || 0).toFixed(2) + '</td>' +
          '<td>' + ((e.error_rate || 0) * 100).toFixed(1) + '%</td>' +
          '<td>' + (e.violations || 0) + '</td>' +
          '<td>' + (e.total_calls || 0) + '</td>' +
          '<td><span class="health-badge ' + e.status + '">' + e.status + '</span></td>' +
        '</tr>';
      }
      html += '</tbody></table>';
    }
    html += '</div>';

    container.innerHTML = html;
    wireBackButton();

    // Click rows to navigate to agent detail
    var rows = container.querySelectorAll('.health-overview-row');
    for (var ri = 0; ri < rows.length; ri++) {
      (function (row) {
        row.addEventListener('click', function () {
          showAgentDetail(row.getAttribute('data-id'));
        });
      })(rows[ri]);
    }
  }

  function wireBackButton() {
    var btn = document.getElementById('agent-back');
    if (btn) {
      btn.addEventListener('click', function () {
        if (currentContainer) render(currentContainer);
      });
    }
  }

  function esc(str) {
    if (!str) return '';
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // -- Load data --------------------------------------------------------------

  function loadSessions(statsWrapper, tableWrapper, opts) {
    SG.api.get('/v1/sessions/active', opts).then(function (sessions) {
      var list = Array.isArray(sessions) ? sessions : (sessions && sessions.sessions ? sessions.sessions : []);
      buildStats(list, statsWrapper);
      buildClientsTable(list, tableWrapper);
    }).catch(function () {
      buildStats([], statsWrapper);
      buildClientsTable([], tableWrapper);
    });
  }

  // -- Render page ------------------------------------------------------------

  function render(container) {
    cleanup();
    injectStyles();
    currentContainer = container;

    var page = mk('div', 'clients-page');

    // Header with Health Overview button
    var header = mk('div', 'clients-header');
    var headerLeft = mk('div', 'clients-header-left');
    var h1 = mk('h1', '');
    h1.textContent = 'Agents';
    headerLeft.appendChild(h1);
    var subtitle = mk('p', '');
    subtitle.textContent = 'Monitor agent behavior, tool usage, and health trends. Click an agent for details.';
    headerLeft.appendChild(subtitle);
    header.appendChild(headerLeft);

    var overviewBtn = mk('button', 'btn btn-secondary btn-sm');
    overviewBtn.textContent = 'Health Overview';
    overviewBtn.addEventListener('click', function () {
      showHealthOverview();
    });
    header.appendChild(overviewBtn);

    var helpBtn = mk('button', 'help-btn', { type: 'button', 'aria-label': 'Help' });
    helpBtn.textContent = '?';
    helpBtn.addEventListener('click', function () { if (SG.help) SG.help.toggle('agents'); });
    header.appendChild(helpBtn);

    page.appendChild(header);

    // Stats bar
    var statsWrapper = mk('div', 'clients-stats');
    page.appendChild(statsWrapper);

    // Table
    var tableWrapper = mk('div', '');
    page.appendChild(tableWrapper);

    container.innerHTML = '';
    container.appendChild(page);

    // Load data
    loadSessions(statsWrapper, tableWrapper);

    // Poll every 5 seconds (silent — no progress bar)
    pollInterval = setInterval(function () {
      loadSessions(statsWrapper, tableWrapper, { silent: true });
    }, 5000);
  }

  // -- Cleanup ----------------------------------------------------------------

  function cleanup() {
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
  }

  // -- Register with router ---------------------------------------------------

  SG.router.register('agents', render);
  SG.router.registerCleanup('agents', function () {
    cleanup();
    currentContainer = null;
  });
})();
