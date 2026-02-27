/**
 * agents.js -- Connected Clients page for SentinelGate admin UI.
 *
 * Displays active MCP sessions (from GET /admin/api/v1/sessions/active).
 * Shows who is connected, since when, how many calls, last activity.
 *
 * Data sources:
 *   GET /admin/api/v1/sessions/active -> active MCP sessions (polled every 5s)
 *
 * Design features:
 *   - Active clients table with status dots
 *   - Empty state when no clients connected
 *   - Polls every 5 seconds
 *   - All user data rendered via textContent (XSS-safe)
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
    '}',
    '.clients-header h1 {',
    '  font-size: var(--text-2xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0 0 var(--space-1) 0;',
    '  letter-spacing: -0.02em;',
    '}',
    '.clients-header p {',
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
    '}'
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
      return d.toLocaleString();
    } catch (e) {
      return dateStr || '-';
    }
  }

  // -- Build stats bar --------------------------------------------------------

  function buildStats(sessions, statsWrapper) {
    statsWrapper.innerHTML = '';

    var totalSessions = sessions ? sessions.length : 0;
    var totalCalls = 0;
    for (var i = 0; i < (sessions || []).length; i++) {
      totalCalls += sessions[i].total_calls || 0;
    }

    var stats = [
      { value: totalSessions, label: 'Active Sessions' },
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
      p.textContent = 'No MCP clients connected. Configure an agent to connect to this server.';
      empty.appendChild(p);
      tableWrapper.appendChild(empty);
      return;
    }

    var table = mk('table', 'client-table');

    // Header
    var thead = mk('thead', '');
    var headRow = mk('tr', '');
    var cols = ['Status', 'Identity', 'Session', 'Connected', 'Requests', 'Last Activity'];
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

      // Status — show idle/stale based on last activity
      var tdStatus = mk('td', '');
      var dot = mk('span', 'client-status-dot');
      var statusLabel = 'connected';
      var lastActivity = sess.last_call_at || sess.last_activity;
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

      tbody.appendChild(row);
    }
    table.appendChild(tbody);
    tableWrapper.appendChild(table);
  }

  // -- Load data --------------------------------------------------------------

  function loadSessions(statsWrapper, tableWrapper) {
    SG.api.get('/v1/sessions/active').then(function (sessions) {
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

    var page = mk('div', 'clients-page');

    // Header
    var header = mk('div', 'clients-header');
    var h1 = mk('h1', '');
    h1.textContent = 'Connected Clients';
    header.appendChild(h1);
    var subtitle = mk('p', '');
    subtitle.textContent = 'Active MCP sessions connected to this server';
    header.appendChild(subtitle);
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

    // Poll every 5 seconds
    pollInterval = setInterval(function () {
      loadSessions(statsWrapper, tableWrapper);
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
  SG.router.registerCleanup('agents', cleanup);
})();
