/**
 * dashboard.js — Dashboard page for SentinelGate admin UI.
 *
 * The command center: live stat cards, upstream health, and real-time
 * activity feed. Self-registers with SG.router and manages its own
 * polling intervals and SSE connection lifecycle.
 *
 * Data sources:
 *   GET /admin/api/stats      → stat card values (polled every 2s)
 *   GET /admin/api/upstreams  → upstream list + status (polled every 5s)
 *   SSE /admin/api/audit/stream → real-time activity entries
 *
 * Design features:
 *   - Staggered entrance animations on page load
 *   - Skeleton loading placeholders before first data arrives
 *   - Value-change pulse animation on stat card updates
 *   - Semantic icon tints (success for Allowed, danger for Denied, etc.)
 *   - Activity entries slide in from left on SSE arrival
 *   - Responsive grid: 5→3→2→1 cols for stat cards
 *   - All user data rendered via textContent (XSS-safe)
 *
 * Requirements:
 *   DASH-01  Five stat cards with live counts
 *   DASH-02  Recent activity feed via SSE (last 10 entries)
 *   DASH-03  Upstream status with connection dots
 *   DASH-04  Click upstream navigates to #/tools?upstream={id}
 *   DASH-05  Live indicator (pulsing green dot) for SSE state
 *   DASH-06  Polling intervals: stats 2s, upstreams 5s
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // ── State ──────────────────────────────────────────────────────────

  var statsInterval = null;
  var upstreamInterval = null;
  var eventSource = null;
  var activityEntries = [];
  var MAX_ACTIVITY = 10;
  var previousStats = {};
  var styleInjected = false;

  // ── Dashboard-specific styles ──────────────────────────────────────
  // Injected once into <head> on first render; co-located here so
  // dashboard layout, animations, and micro-interactions live with the
  // code that uses them.

  var DASHBOARD_CSS = [
    /* ── Layout ───────────────────────────────────────────────── */
    '.dashboard-header {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  margin-bottom: var(--space-6);',
    '}',
    '.dashboard-header h1 {',
    '  font-size: var(--text-2xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0;',
    '  letter-spacing: -0.02em;',
    '}',

    /* Stat cards grid — responsive breakpoints */
    '.stat-cards-grid {',
    '  display: grid;',
    '  grid-template-columns: repeat(5, 1fr);',
    '  gap: var(--space-4);',
    '  margin-bottom: var(--space-6);',
    '}',
    '@media (max-width: 1200px) {',
    '  .stat-cards-grid { grid-template-columns: repeat(3, 1fr); }',
    '}',
    '@media (max-width: 768px) {',
    '  .stat-cards-grid { grid-template-columns: repeat(2, 1fr); }',
    '}',
    '@media (max-width: 480px) {',
    '  .stat-cards-grid { grid-template-columns: 1fr; }',
    '}',

    /* Two-column panels: Upstreams + Activity */
    '.dashboard-panels {',
    '  display: grid;',
    '  grid-template-columns: 1fr 1fr;',
    '  gap: var(--space-4);',
    '}',
    '@media (max-width: 768px) {',
    '  .dashboard-panels { grid-template-columns: 1fr; }',
    '}',

    /* ── Staggered entrance animation ─────────────────────────── */
    '@keyframes dashFadeUp {',
    '  from { opacity: 0; transform: translateY(12px); }',
    '  to   { opacity: 1; transform: translateY(0); }',
    '}',
    '.dash-enter {',
    '  animation: dashFadeUp 0.4s ease both;',
    '}',
    '.dash-enter-1 { animation-delay: 0.04s; }',
    '.dash-enter-2 { animation-delay: 0.08s; }',
    '.dash-enter-3 { animation-delay: 0.12s; }',
    '.dash-enter-4 { animation-delay: 0.16s; }',
    '.dash-enter-5 { animation-delay: 0.20s; }',
    '.dash-enter-6 { animation-delay: 0.26s; }',
    '.dash-enter-7 { animation-delay: 0.32s; }',

    /* ── Stat value change pulse ──────────────────────────────── */
    '@keyframes valuePulse {',
    '  0%   { transform: scale(1);    color: var(--text-primary); }',
    '  30%  { transform: scale(1.12); color: var(--accent-text); }',
    '  100% { transform: scale(1);    color: var(--text-primary); }',
    '}',
    '.stat-card-value.value-changed {',
    '  animation: valuePulse 0.5s ease;',
    '}',

    /* ── Semantic icon tints per stat card type ───────────────── */
    '.stat-icon-accent  .stat-card-icon { background: var(--accent-subtle); color: var(--accent); }',
    '.stat-icon-success .stat-card-icon { background: var(--success-subtle); color: var(--success); }',
    '.stat-icon-danger  .stat-card-icon { background: var(--danger-subtle); color: var(--danger); }',
    '.stat-icon-warning .stat-card-icon { background: var(--warning-subtle); color: var(--warning); }',

    /* ── Skeleton loading shimmer ─────────────────────────────── */
    '@keyframes shimmer {',
    '  0%   { background-position: -200px 0; }',
    '  100% { background-position: 200px 0; }',
    '}',
    '.skeleton {',
    '  background: linear-gradient(90deg, var(--bg-surface) 25%, var(--bg-elevated) 50%, var(--bg-surface) 75%);',
    '  background-size: 400px 100%;',
    '  animation: shimmer 1.5s ease infinite;',
    '  border-radius: var(--radius-sm);',
    '}',
    '.skeleton-value {',
    '  width: 48px;',
    '  height: 28px;',
    '  margin-top: var(--space-1);',
    '}',
    '.skeleton-item {',
    '  height: 52px;',
    '  margin-bottom: var(--space-2);',
    '  border-radius: var(--radius-md);',
    '}',

    /* ── Activity entry slide-in ──────────────────────────────── */
    '@keyframes activitySlideIn {',
    '  from { opacity: 0; transform: translateX(-8px); }',
    '  to   { opacity: 1; transform: translateX(0); }',
    '}',
    '.activity-entry-new {',
    '  animation: activitySlideIn 0.3s ease both;',
    '}',

    /* ── Scroll areas with styled scrollbars ──────────────────── */
    '.dash-scroll {',
    '  max-height: 400px;',
    '  overflow-y: auto;',
    '  scrollbar-width: thin;',
    '  scrollbar-color: var(--bg-elevated) transparent;',
    '}',
    '.dash-scroll::-webkit-scrollbar { width: 4px; }',
    '.dash-scroll::-webkit-scrollbar-track { background: transparent; }',
    '.dash-scroll::-webkit-scrollbar-thumb {',
    '  background: var(--bg-elevated);',
    '  border-radius: var(--radius-full);',
    '}',

    /* ── Clickable upstream rows ──────────────────────────────── */
    '.upstream-item-link { cursor: pointer; }',

    /* ── Live indicator inactive state ────────────────────────── */
    '.live-indicator.inactive {',
    '  color: var(--text-muted);',
    '}',
    '.live-indicator.inactive .live-dot {',
    '  background: var(--text-muted);',
    '}',
    '.live-indicator.inactive .live-dot::before {',
    '  display: none;',
    '}',

    /* ── Protocol/Framework distribution widgets (UI-01, UI-02) ── */
    '.dashboard-widgets {',
    '  display: grid;',
    '  grid-template-columns: 1fr 1fr;',
    '  gap: var(--space-4);',
    '  margin-bottom: var(--space-6);',
    '}',
    '@media (max-width: 768px) {',
    '  .dashboard-widgets { grid-template-columns: 1fr; }',
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
    '.dist-bar-runtime   { background: #a855f7; }',
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
    '}'
  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-dashboard', '');
    s.textContent = DASHBOARD_CSS;
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

  // ── Build full dashboard DOM ───────────────────────────────────────

  function buildDashboard(container) {
    var root = mk('div', '');

    // ── Header row ──
    var header = mk('div', 'dashboard-header dash-enter dash-enter-1');
    var h1 = mk('h1');
    h1.textContent = 'Dashboard';
    header.appendChild(h1);

    var live = mk('div', 'live-indicator inactive');
    live.id = 'live-indicator';
    live.appendChild(mk('span', 'live-dot'));
    var liveLabel = mk('span');
    liveLabel.textContent = 'Live';
    live.appendChild(liveLabel);
    header.appendChild(live);
    root.appendChild(header);

    // ── Stat cards grid ──
    var grid = mk('div', 'stat-cards-grid dash-enter dash-enter-2');
    grid.id = 'stat-cards';

    var cardDefs = [
      { icon: 'server',      label: 'Upstreams',    id: 'stat-upstreams',   tint: 'stat-icon-accent' },
      { icon: 'tool',        label: 'Tools',        id: 'stat-tools',       tint: 'stat-icon-accent' },
      { icon: 'checkCircle', label: 'Allowed',      id: 'stat-allowed',     tint: 'stat-icon-success' },
      { icon: 'xCircle',     label: 'Denied',       id: 'stat-denied',      tint: 'stat-icon-danger' },
      { icon: 'zap',         label: 'Rate Limited', id: 'stat-ratelimited', tint: 'stat-icon-warning' }
    ];
    for (var c = 0; c < cardDefs.length; c++) {
      grid.appendChild(buildStatCard(cardDefs[c]));
    }
    root.appendChild(grid);

    // ── Protocol/Framework distribution widgets (UI-01, UI-02) ──
    var widgets = mk('div', 'dashboard-widgets');

    // Protocol Distribution card
    var protoCard = mk('div', 'card dash-enter dash-enter-3');
    var protoHeader = mk('div', 'card-header');
    var protoTitle = mk('span', 'card-title');
    protoTitle.innerHTML = SG.icon('globe', 16) + ' ';
    protoTitle.appendChild(document.createTextNode('Protocol Distribution'));
    protoHeader.appendChild(protoTitle);
    protoCard.appendChild(protoHeader);
    var protoBody = mk('div', 'card-body');
    protoBody.id = 'protocol-dist';
    var protoEmpty = mk('div', 'dist-empty-state');
    protoEmpty.textContent = 'No traffic recorded yet';
    protoBody.appendChild(protoEmpty);
    protoCard.appendChild(protoBody);
    widgets.appendChild(protoCard);

    // Framework Activity card
    var fwCard = mk('div', 'card dash-enter dash-enter-4');
    var fwHeader = mk('div', 'card-header');
    var fwTitle = mk('span', 'card-title');
    fwTitle.innerHTML = SG.icon('layers', 16) + ' ';
    fwTitle.appendChild(document.createTextNode('Framework Activity'));
    fwHeader.appendChild(fwTitle);
    fwCard.appendChild(fwHeader);
    var fwBody = mk('div', 'card-body');
    fwBody.id = 'framework-activity';
    var fwEmpty = mk('div', 'dist-empty-state');
    fwEmpty.textContent = 'No framework activity detected';
    fwBody.appendChild(fwEmpty);
    fwCard.appendChild(fwBody);
    widgets.appendChild(fwCard);

    root.appendChild(widgets);

    // ── Two-column panels ──
    var panels = mk('div', 'dashboard-panels');

    // Upstreams card
    var upCard = mk('div', 'card dash-enter dash-enter-5');
    var upHeader = mk('div', 'card-header');
    var upTitle = mk('span', 'card-title');
    upTitle.innerHTML = SG.icon('server', 16) + ' ';
    upTitle.appendChild(document.createTextNode('Upstreams'));
    upHeader.appendChild(upTitle);
    upCard.appendChild(upHeader);

    var upBody = mk('div', 'card-body dash-scroll');
    upBody.id = 'upstream-list';
    // Skeleton loading state
    for (var s = 0; s < 3; s++) {
      upBody.appendChild(mk('div', 'skeleton skeleton-item'));
    }
    upCard.appendChild(upBody);
    panels.appendChild(upCard);

    // Activity card
    var actCard = mk('div', 'card dash-enter dash-enter-6');
    var actHeader = mk('div', 'card-header');
    var actTitle = mk('span', 'card-title');
    actTitle.innerHTML = SG.icon('activity', 16) + ' ';
    actTitle.appendChild(document.createTextNode('Recent Activity'));
    actHeader.appendChild(actTitle);
    actCard.appendChild(actHeader);

    var actBody = mk('div', 'card-body dash-scroll');
    actBody.id = 'activity-feed';
    var emptyAct = mk('div', 'empty-state');
    emptyAct.id = 'activity-empty';
    var emptyIcon = mk('div', 'empty-state-icon');
    emptyIcon.innerHTML = SG.icon('activity', 32);
    emptyAct.appendChild(emptyIcon);
    var emptyDesc = mk('p', 'empty-state-description');
    emptyDesc.textContent = 'Waiting for activity\u2026';
    emptyAct.appendChild(emptyDesc);
    actBody.appendChild(emptyAct);
    actCard.appendChild(actBody);
    panels.appendChild(actCard);

    root.appendChild(panels);
    container.appendChild(root);
  }

  function buildStatCard(cfg) {
    var card = mk('div', 'stat-card ' + cfg.tint);

    var content = mk('div', 'stat-card-content');
    var label = mk('div', 'stat-card-label');
    label.textContent = cfg.label;
    content.appendChild(label);

    var value = mk('div', 'stat-card-value');
    value.id = cfg.id;
    // Show skeleton shimmer until first data arrives
    value.appendChild(mk('div', 'skeleton skeleton-value'));
    content.appendChild(value);

    var iconWrap = mk('div', 'stat-card-icon');
    iconWrap.innerHTML = SG.icon(cfg.icon, 22);

    card.appendChild(content);
    card.appendChild(iconWrap);
    return card;
  }

  // ── Data: Stats (DASH-01, DASH-06) ────────────────────────────────

  function loadStats() {
    SG.api.get('/stats').then(function (data) {
      if (!data) return;
      updateStatValue('stat-upstreams', data.upstreams);
      updateStatValue('stat-tools', data.tools);
      updateStatValue('stat-allowed', data.allowed);
      updateStatValue('stat-denied', data.denied);
      updateStatValue('stat-ratelimited', data.rate_limited);

      // Update protocol/framework distribution widgets
      renderProtocolDist(data.protocol_counts || {});
      renderFrameworkActivity(data.framework_counts || {});

      // Sidebar upstream count sync
      var countEl = document.getElementById('upstream-count');
      if (countEl && data.upstreams != null) {
        var n = Number(data.upstreams) || 0;
        countEl.textContent = n + ' upstream' + (n !== 1 ? 's' : '');
      }
    }).catch(function () {
      // Non-fatal — cards retain last values, next poll retries
    });
  }

  function updateStatValue(id, newVal) {
    var node = document.getElementById(id);
    if (!node) return;

    var strVal = (newVal != null) ? String(newVal) : '0';
    var prevVal = previousStats[id];

    // First load: clear skeleton placeholder
    if (node.firstChild && node.firstChild.classList &&
        node.firstChild.classList.contains('skeleton')) {
      node.textContent = strVal;
      previousStats[id] = strVal;
      return;
    }

    if (node.textContent !== strVal) {
      node.textContent = strVal;
      // Pulse animation when value actually changes (not on first load)
      if (prevVal !== undefined && prevVal !== strVal) {
        node.classList.remove('value-changed');
        void node.offsetWidth; // force reflow to restart animation
        node.classList.add('value-changed');
      }
      previousStats[id] = strVal;
    }
  }

  // ── Data: Protocol/Framework Distribution (UI-01, UI-02) ──────────

  var PROTOCOL_COLORS = {
    mcp: 'dist-bar-mcp',
    http: 'dist-bar-http',
    websocket: 'dist-bar-websocket',
    runtime: 'dist-bar-runtime'
  };

  var FRAMEWORK_LABELS = {
    langchain: 'LangChain',
    crewai: 'CrewAI',
    autogen: 'AutoGen',
    'openai-agents-sdk': 'OpenAI Agents SDK',
    'unknown': 'Generic / Direct',
    '': 'Generic / Direct'
  };

  function renderProtocolDist(counts) {
    var container = document.getElementById('protocol-dist');
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

    // Find max for bar proportions
    var maxCount = 0;
    for (var j = 0; j < keys.length; j++) {
      if (counts[keys[j]] > maxCount) maxCount = counts[keys[j]];
    }

    // Sort protocols by count descending
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

      var countEl = mk('div', 'dist-bar-count');
      countEl.textContent = String(count);
      row.appendChild(countEl);

      container.appendChild(row);
    }
  }

  function renderFrameworkActivity(counts) {
    var container = document.getElementById('framework-activity');
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

    // Find max for bar proportions
    var maxCount = 0;
    for (var j = 0; j < keys.length; j++) {
      if (counts[keys[j]] > maxCount) maxCount = counts[keys[j]];
    }

    // Sort frameworks by count descending
    keys.sort(function (a, b) { return counts[b] - counts[a]; });

    // Color cycle for frameworks
    var fwColors = ['dist-bar-mcp', 'dist-bar-http', 'dist-bar-websocket', 'dist-bar-runtime', 'dist-bar-default'];

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

      var countEl = mk('div', 'dist-bar-count');
      countEl.textContent = String(count);
      row.appendChild(countEl);

      container.appendChild(row);
    }
  }

  // ── Data: Upstreams (DASH-03, DASH-04) ────────────────────────────

  function loadUpstreams() {
    SG.api.get('/upstreams').then(function (data) {
      var container = document.getElementById('upstream-list');
      if (!container) return;

      // Empty state
      if (!data || !Array.isArray(data) || data.length === 0) {
        container.innerHTML = '';
        var empty = mk('div', 'empty-state');
        var emptyIcon = mk('div', 'empty-state-icon');
        emptyIcon.innerHTML = SG.icon('server', 32);
        empty.appendChild(emptyIcon);
        var emptyTitle = mk('p', 'empty-state-title');
        emptyTitle.textContent = 'No upstreams';
        empty.appendChild(emptyTitle);
        var emptyDesc = mk('p', 'empty-state-description');
        emptyDesc.textContent = 'Add an MCP server to get started';
        empty.appendChild(emptyDesc);
        container.appendChild(empty);
        return;
      }

      // Build upstream list via DOM (not innerHTML)
      container.innerHTML = '';
      var list = mk('div', 'upstream-list');

      for (var i = 0; i < data.length; i++) {
        var u = data[i];
        var item = mk('div', 'upstream-item upstream-item-link');

        // Click handler with closure for upstream ID (DASH-04)
        (function (upstreamId) {
          item.addEventListener('click', function () {
            window.location.hash = '#/tools?upstream=' + encodeURIComponent(upstreamId);
          });
        })(u.id || u.name || '');

        var info = mk('div', '');
        var name = mk('div', 'upstream-name');
        name.textContent = u.name || u.id || 'Unknown';
        info.appendChild(name);

        var meta = mk('div', '', { style: 'font-size:var(--text-xs);color:var(--text-muted);' });
        var toolCount = (u.tool_count != null) ? u.tool_count : 0;
        meta.textContent = toolCount + ' tool' + (toolCount !== 1 ? 's' : '');
        info.appendChild(meta);

        var statusCls = resolveStatusClass(u.status);
        var status = mk('div', 'upstream-status ' + statusCls);
        status.appendChild(mk('span', 'status-dot ' + statusCls));
        var statusLabel = mk('span', 'text-xs');
        statusLabel.textContent = statusText(statusCls);
        status.appendChild(statusLabel);

        item.appendChild(info);
        item.appendChild(status);
        list.appendChild(item);
      }

      container.appendChild(list);
    }).catch(function () {
      // Non-fatal — upstream list retains last state
    });
  }

  function resolveStatusClass(raw) {
    if (!raw) return 'connecting';
    var s = String(raw).toLowerCase();
    if (s === 'connected' || s === 'running') return 'connected';
    if (s === 'disconnected' || s === 'stopped' || s === 'error' || s === 'failed') return 'disconnected';
    return 'connecting';
  }

  function statusText(cls) {
    if (cls === 'connected') return 'Connected';
    if (cls === 'disconnected') return 'Disconnected';
    return 'Connecting';
  }

  // ── SSE: Activity Feed (DASH-02, DASH-05) ─────────────────────────

  function startSSE() {
    if (typeof EventSource === 'undefined') return;

    eventSource = new EventSource(SG.api.BASE + '/audit/stream');

    eventSource.onopen = function () {
      var indicator = document.getElementById('live-indicator');
      if (indicator) indicator.classList.remove('inactive');
    };

    eventSource.onerror = function () {
      var indicator = document.getElementById('live-indicator');
      if (indicator) indicator.classList.add('inactive');
    };

    eventSource.onmessage = function (evt) {
      var entry;
      try { entry = JSON.parse(evt.data); } catch (e) { return; }

      activityEntries.unshift(entry);
      if (activityEntries.length > MAX_ACTIVITY) {
        activityEntries = activityEntries.slice(0, MAX_ACTIVITY);
      }
      renderActivityFeed(true);
    };
  }

  function renderActivityFeed(hasNewEntry) {
    var feedEl = document.getElementById('activity-feed');
    if (!feedEl) return;

    // Toggle empty state
    var emptyEl = document.getElementById('activity-empty');
    if (emptyEl) {
      emptyEl.style.display = (activityEntries.length > 0) ? 'none' : '';
    }
    if (activityEntries.length === 0) return;

    // Remove previous list (keep empty-state node)
    var children = feedEl.children;
    for (var r = children.length - 1; r >= 0; r--) {
      if (children[r].id !== 'activity-empty') {
        feedEl.removeChild(children[r]);
      }
    }

    // Build entries via DOM (XSS-safe — all user text via textContent)
    var list = mk('div', 'upstream-list');

    for (var i = 0; i < activityEntries.length; i++) {
      var entry = activityEntries[i];

      var item = mk('div', 'upstream-item');
      // Slide-in animation on the newest entry
      if (hasNewEntry && i === 0) {
        item.classList.add('activity-entry-new');
      }

      var info = mk('div', '');
      var toolName = mk('div', 'upstream-name');
      toolName.textContent = entry.tool_name || entry.tool || 'unknown';
      info.appendChild(toolName);

      var meta = mk('div', '', { style: 'font-size:var(--text-xs);color:var(--text-muted);' });
      var identity = entry.identity_name || entry.identity_id || entry.identity || 'anonymous';
      meta.textContent = identity + ' \u00B7 ' + formatRelativeTime(entry.timestamp);
      info.appendChild(meta);

      var decision = String(entry.decision || '').toLowerCase();
      var badgeCls = 'badge-neutral';
      var badgeText = decision || 'unknown';
      if (decision === 'allow' || decision === 'allowed') {
        badgeCls = 'badge-success'; badgeText = 'Allow';
      } else if (decision === 'deny' || decision === 'denied') {
        badgeCls = 'badge-danger'; badgeText = 'Deny';
      } else if (decision === 'rate_limited' || decision === 'ratelimited') {
        badgeCls = 'badge-warning'; badgeText = 'Rate Limited';
      }

      var badge = mk('span', 'badge ' + badgeCls);
      badge.textContent = badgeText;

      item.appendChild(info);
      item.appendChild(badge);
      list.appendChild(item);
    }

    feedEl.insertBefore(list, feedEl.firstChild);
  }

  // ── Relative time formatter ────────────────────────────────────────

  function formatRelativeTime(ts) {
    if (!ts) return 'just now';
    var then;
    try { then = new Date(ts).getTime(); } catch (e) { return 'just now'; }
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

  // ── Lifecycle ──────────────────────────────────────────────────────

  function render(container) {
    cleanup();
    injectStyles();
    buildDashboard(container);

    // Kick off data loading
    loadStats();
    loadUpstreams();
    startSSE();

    // Start polling (DASH-06)
    statsInterval = setInterval(loadStats, 2000);
    upstreamInterval = setInterval(loadUpstreams, 5000);
  }

  function cleanup() {
    if (statsInterval) { clearInterval(statsInterval); statsInterval = null; }
    if (upstreamInterval) { clearInterval(upstreamInterval); upstreamInterval = null; }
    if (eventSource) { eventSource.close(); eventSource = null; }
    activityEntries = [];
    previousStats = {};
  }

  // ── Registration ───────────────────────────────────────────────────

  SG.router.register('dashboard', render);
  SG.router.registerCleanup('dashboard', cleanup);
})();
