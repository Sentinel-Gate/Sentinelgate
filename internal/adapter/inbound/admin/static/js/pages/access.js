/**
 * access.js -- Access page for SentinelGate admin UI.
 *
 * API Keys management: list all keys with identity resolution,
 * create new keys with one-time cleartext display, and revoke
 * existing keys.
 *
 * Identities management: collapsible CRUD section with Add/Edit/Delete
 * modals and role badge display.
 *
 * Quota configuration: per-identity quota limits with enable/disable,
 * action selector, and numeric limit fields.
 *
 * Connect Your Agent: tabbed config snippets for 7 agents with Copy button.
 *
 * Data sources:
 *   GET    /admin/api/keys              -> all API keys
 *   GET    /admin/api/identities        -> identity list for dropdown + name resolution
 *   POST   /admin/api/keys              -> create new API key
 *   DELETE /admin/api/keys/{id}         -> revoke API key
 *   POST   /admin/api/identities        -> create identity
 *   PUT    /admin/api/identities/{id}   -> update identity
 *   DELETE /admin/api/identities/{id}   -> delete identity
 *   GET    /admin/api/v1/quotas         -> all quota configs
 *   PUT    /admin/api/v1/quotas/{id}    -> create/update quota
 *   DELETE /admin/api/v1/quotas/{id}    -> remove quota
 *
 * Design features:
 *   - API Keys table with name, identity, created, status, actions
 *   - Create Key modal with name + identity dropdown
 *   - One-time cleartext key display with Copy button
 *   - Revoke button with confirmation dialog
 *   - Identities collapsible card with Add/Edit/Delete modals
 *   - Role badges per identity
 *   - Quota badge per identity with Configure Quota button
 *   - Quota configuration modal with limits and action selector
 *   - Tabbed agent config snippets (7 agents) with Copy buttons
 *   - Empty state when no keys/identities exist
 *   - All user data rendered via textContent (XSS-safe)
 *
 * Requirements:
 *   ACCS-01  API Keys table listing all keys
 *   ACCS-02  Create Key modal with identity selection
 *   ACCS-03  One-time cleartext key display with Copy button
 *   ACCS-04  Revoke key with confirmation
 *   ACCS-05  Identities section with CRUD
 *   ACCS-06  MCP Client Config snippet with Copy
 *   ACCS-07  Per-identity quota configuration
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  function esc(str) {
    if (!str) return '';
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // -- State ------------------------------------------------------------------

  var styleInjected = false;
  var keys = [];
  var identities = [];
  var identityMap = {};
  var identitiesCollapsed = false;
  var quotaMap = {}; // keyed by identity_id
  var upstreamsList = [];

  // -- Access-specific styles -------------------------------------------------

  var ACCESS_CSS = [
    /* Layout */
    '.access-header {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  margin-bottom: var(--space-6);',
    '}',
    '.access-header h1 {',
    '  font-size: var(--text-2xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0;',
    '  letter-spacing: -0.02em;',
    '}',
    '.access-header-desc {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-muted);',
    '  margin: 0;',
    '  margin-top: var(--space-1);',
    '}',

    /* Section spacing */
    '.access-section {',
    '  margin-bottom: var(--space-6);',
    '}',

    /* Key display block */
    '.key-display {',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  padding: var(--space-3) var(--space-4);',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  word-break: break-all;',
    '  line-height: 1.6;',
    '  margin-bottom: var(--space-3);',
    '  user-select: all;',
    '}',

    /* Warning text */
    '.key-display-warning {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  color: var(--danger);',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  margin-bottom: var(--space-3);',
    '}',

    /* Copy button */
    '.key-copy-btn {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  padding: var(--space-2) var(--space-3);',
    '  background: var(--accent);',
    '  color: var(--accent-contrast);',
    '  border: none;',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '}',
    '.key-copy-btn:hover {',
    '  opacity: 0.9;',
    '}',
    '.key-copy-btn.copied {',
    '  background: var(--success);',
    '}',

    /* Key result footer */
    '.key-result-footer {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  margin-top: var(--space-3);',
    '}',

    /* Table status badges */
    '.key-status-active {',
    '  color: var(--success);',
    '  font-weight: var(--font-medium);',
    '  font-size: var(--text-sm);',
    '}',
    '.key-status-revoked {',
    '  color: var(--danger);',
    '  font-weight: var(--font-medium);',
    '  font-size: var(--text-sm);',
    '}',

    /* Entrance animation */
    '@keyframes accessFadeUp {',
    '  from { opacity: 0; transform: translateY(12px); }',
    '  to   { opacity: 1; transform: translateY(0); }',
    '}',
    '.access-enter {',
    '  animation: accessFadeUp 0.4s ease both;',
    '}',
    '.access-enter-1 { animation-delay: 0.04s; }',
    '.access-enter-2 { animation-delay: 0.08s; }',
    '.access-enter-3 { animation-delay: 0.12s; }',
    '.access-enter-4 { animation-delay: 0.16s; }',

    /* Config snippet */
    '.config-snippet-wrapper {',
    '  position: relative;',
    '  margin-bottom: var(--space-3);',
    '}',
    '.config-snippet {',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  padding: var(--space-4);',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  line-height: 1.6;',
    '  overflow-x: auto;',
    '  white-space: pre;',
    '  margin: 0;',
    '}',
    '.config-copy-btn {',
    '  position: absolute;',
    '  top: var(--space-2);',
    '  right: var(--space-2);',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-1);',
    '  padding: var(--space-1) var(--space-2);',
    '  background: var(--bg-surface);',
    '  color: var(--text-secondary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-xs);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '  opacity: 0.8;',
    '}',
    '.config-copy-btn:hover {',
    '  opacity: 1;',
    '  background: var(--bg-hover);',
    '}',
    '.config-copy-btn.copied {',
    '  background: var(--success);',
    '  color: var(--accent-contrast);',
    '  border-color: var(--success);',
    '}',

    /* Collapsible card header */
    '.access-collapse-header {',
    '  cursor: pointer;',
    '  user-select: none;',
    '}',
    '.access-collapse-header:hover {',
    '  background: var(--bg-surface);',
    '}',
    '.access-collapse-chevron {',
    '  display: inline-block;',
    '  transition: transform var(--transition-fast);',
    '  margin-left: var(--space-2);',
    '}',
    '.access-collapse-chevron.collapsed {',
    '  transform: rotate(-90deg);',
    '}',
    '.access-collapse-body {',
    '  overflow: hidden;',
    '  transition: max-height 0.3s ease, opacity 0.3s ease;',
    '  max-height: 2000px;',
    '  opacity: 1;',
    '}',
    '.access-collapse-body.collapsed {',
    '  max-height: 0;',
    '  opacity: 0;',
    '}',

    /* Role badges */
    '.identity-roles {',
    '  display: flex;',
    '  flex-wrap: wrap;',
    '  gap: var(--space-1);',
    '}',
    '.role-badge {',
    '  display: inline-block;',
    '  padding: 1px var(--space-2);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-medium);',
    '  border-radius: var(--radius-full);',
    '  background: var(--accent-subtle);',
    '  color: var(--accent);',
    '  border: 1px solid rgba(99, 102, 241, 0.2);',
    '}',

    /* Quota badges */
    '.quota-badge {',
    '  display: inline-block;',
    '  padding: 1px var(--space-2);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-medium);',
    '  border-radius: var(--radius-full);',
    '  margin-left: var(--space-2);',
    '}',
    '.quota-badge-enabled {',
    '  background: var(--success-subtle);',
    '  color: var(--success);',
    '  border: 1px solid rgba(34, 197, 94, 0.2);',
    '}',
    '.quota-badge-warn {',
    '  background: var(--warning-subtle);',
    '  color: var(--warning);',
    '  border: 1px solid rgba(234, 179, 8, 0.2);',
    '}',
    '.quota-badge-configured {',
    '  background: rgba(148, 163, 184, 0.1);',
    '  color: var(--text-muted);',
    '  border: 1px solid rgba(148, 163, 184, 0.2);',
    '}',

    /* Quota form fields */
    '.quota-form-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  margin-bottom: var(--space-3);',
    '}',
    '.quota-form-row label {',
    '  min-width: 160px;',
    '  font-size: var(--text-sm);',
    '  color: var(--text-secondary);',
    '}',
    '.quota-form-row input[type="number"] {',
    '  flex: 1;',
    '  padding: var(--space-2) var(--space-3);',
    '  background: var(--bg-primary);',
    '  color: var(--text-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-sm);',
    '}',
    '.quota-form-row input[type="number"]:focus {',
    '  outline: none;',
    '  border-color: var(--accent);',
    '  box-shadow: 0 0 0 2px var(--accent-subtle);',
    '}',
    '.quota-toggle-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  margin-bottom: var(--space-4);',
    '  padding-bottom: var(--space-3);',
    '  border-bottom: 1px solid var(--border);',
    '}',
    '.quota-toggle-label {',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-primary);',
    '}',
    '.quota-action-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.quota-action-row label {',
    '  min-width: 160px;',
    '  font-size: var(--text-sm);',
    '  color: var(--text-secondary);',
    '}',
    '.quota-action-row select {',
    '  flex: 1;',
    '  padding: var(--space-2) var(--space-3);',
    '  background: var(--bg-primary);',
    '  color: var(--text-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-sm);',
    '}',
    '.quota-section-title {',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-bold);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '  color: var(--text-muted);',
    '  margin-bottom: var(--space-3);',
    '  margin-top: var(--space-2);',
    '}',
    '.quota-remove-btn {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-1);',
    '  padding: var(--space-1) var(--space-2);',
    '  background: transparent;',
    '  color: var(--danger);',
    '  border: 1px solid var(--danger);',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-xs);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '}',
    '.quota-remove-btn:hover {',
    '  background: var(--danger);',
    '  color: var(--accent-contrast);',
    '}',


    /* Tool limit items */
    '.tool-limit-item {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  padding: var(--space-2) 0;',
    '  border-bottom: 1px solid var(--border);',
    '}',
    '.tool-limit-item:last-child {',
    '  border-bottom: none;',
    '}',
    '.tool-limit-name {',
    '  flex: 1;',
    '  font-size: var(--text-sm);',
    '  font-family: var(--font-mono);',
    '  color: var(--text-primary);',
    '}',
    '.tool-limit-value {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-secondary);',
    '  min-width: 60px;',
    '  text-align: right;',
    '}',
    '.tool-limit-add-row {',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  margin-top: var(--space-2);',
    '}',
    '.tool-limit-add-row input {',
    '  padding: var(--space-2) var(--space-3);',
    '  background: var(--bg-primary);',
    '  color: var(--text-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-sm);',
    '}',
    '.tool-limit-add-row input:focus {',
    '  outline: none;',
    '  border-color: var(--accent);',
    '}',

    /* Config tabs */
    '.config-tabs {',
    '  display: flex;',
    '  flex-wrap: wrap;',
    '  gap: var(--space-1);',
    '  margin-bottom: var(--space-4);',
    '  border-bottom: 1px solid var(--border);',
    '  padding-bottom: var(--space-1);',
    '}',
    '.config-tab {',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-muted);',
    '  background: transparent;',
    '  border: 1px solid transparent;',
    '  border-bottom: none;',
    '  border-radius: var(--radius-md) var(--radius-md) 0 0;',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '  white-space: nowrap;',
    '}',
    '.config-tab:hover {',
    '  color: var(--text-primary);',
    '  background: var(--bg-secondary);',
    '}',
    '.config-tab.active {',
    '  color: var(--accent);',
    '  background: var(--bg-surface);',
    '  border-color: var(--border);',
    '  border-bottom: 2px solid var(--accent);',
    '  margin-bottom: -2px;',
    '}',
    '.config-tab-content {',
    '  display: none;',
    '}',
    '.config-tab-content.active {',
    '  display: block;',
    '}',

    /* MCP Servers section */
    '.mcp-servers-table {',
    '  width: 100%;',
    '  border-collapse: collapse;',
    '}',
    '.mcp-servers-table th {',
    '  text-align: left;',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-muted);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '  padding: var(--space-3) var(--space-4);',
    '  border-bottom: 1px solid var(--border);',
    '  background: var(--bg-primary);',
    '  white-space: nowrap;',
    '}',
    '.mcp-servers-table td {',
    '  padding: var(--space-3);',
    '  border-bottom: 1px solid var(--border);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  vertical-align: middle;',
    '}',
    '.mcp-servers-table tr:last-child td {',
    '  border-bottom: none;',
    '}',
    '.mcp-servers-type-badge {',
    '  display: inline-block;',
    '  padding: 2px 8px;',
    '  border-radius: var(--radius-full);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-medium);',
    '  background: var(--bg-tertiary);',
    '  color: var(--text-primary);',
    '}',
    '.mcp-servers-status {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  font-size: var(--text-sm);',
    '}',
    '.mcp-servers-actions {',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  justify-content: flex-end;',
    '  padding-right: 39px;',
    '}',
    '.mcp-servers-empty {',
    '  text-align: center;',
    '  padding: var(--space-6);',
    '  color: var(--text-muted);',
    '  font-size: var(--text-sm);',
    '}'
  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-access', '');
    s.textContent = ACCESS_CSS;
    document.head.appendChild(s);
    styleInjected = true;
  }

  // -- Skeleton helpers -------------------------------------------------------

  /**
   * Generate skeleton table rows HTML for loading states.
   * @param {number} rows  - Number of placeholder rows
   * @param {number} cols  - Number of columns per row
   * @returns {string} HTML string
   */
  function skeletonTableRows(rows, cols) {
    var html = '<div class="skeleton-card" style="padding: 0; overflow: hidden;">';
    // Header
    html += '<div style="display: flex; gap: var(--space-4); padding: var(--space-3) var(--space-4); border-bottom: 1px solid var(--border); background: var(--bg-primary);">';
    for (var c = 0; c < cols; c++) {
      html += '<div class="skeleton skeleton-text" style="height: 12px; flex: 1;"></div>';
    }
    html += '</div>';
    // Rows
    for (var r = 0; r < rows; r++) {
      html += '<div style="display: flex; gap: var(--space-4); padding: var(--space-3) var(--space-4); border-bottom: 1px solid var(--border);">';
      for (var cc = 0; cc < cols; cc++) {
        var w = cc === 0 ? '60%' : (cc === cols - 1 ? '30%' : '45%');
        html += '<div class="skeleton skeleton-text" style="height: 14px; flex: 1; width: ' + w + ';"></div>';
      }
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  // -- Empty state SVG helpers ------------------------------------------------

  /**
   * Return an SVG illustration for the identities empty state (users/key icon).
   * @returns {string} SVG markup
   */
  function identitiesEmptyStateSvg() {
    return '<svg viewBox="0 0 120 120" fill="none" xmlns="http://www.w3.org/2000/svg">' +
      '<circle cx="50" cy="40" r="16" stroke="currentColor" stroke-width="2" fill="none"/>' +
      '<path d="M26 90c0-13.255 10.745-24 24-24h0c13.255 0 24 10.745 24 24" stroke="currentColor" stroke-width="2" fill="none"/>' +
      '<circle cx="82" cy="48" r="12" stroke="currentColor" stroke-width="2" fill="none"/>' +
      '<path d="M66 90c0-10.493 8.507-19 19-19h0c7.5 0 14 4.5 17 10.5" stroke="currentColor" stroke-width="2" fill="none" stroke-dasharray="3 3"/>' +
      '<circle cx="96" cy="28" r="4" fill="currentColor" opacity="0.2"/>' +
      '<circle cx="20" cy="55" r="3" fill="currentColor" opacity="0.15"/>' +
    '</svg>';
  }

  // -- DOM helpers ------------------------------------------------------------

  function mk(tag, className, attrs) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (attrs) {
      var ks = Object.keys(attrs);
      for (var i = 0; i < ks.length; i++) {
        var k = ks[i];
        if (k === 'style') {
          node.style.cssText = attrs[k];
        } else {
          node.setAttribute(k, attrs[k]);
        }
      }
    }
    return node;
  }

  // -- Format helpers ---------------------------------------------------------

  function formatDate(iso) {
    if (!iso) return '-';
    try {
      var d = new Date(iso);
      if (isNaN(d.getTime())) return iso;
      var yyyy = d.getFullYear();
      var mo = String(d.getMonth() + 1).padStart(2, '0');
      var dd = String(d.getDate()).padStart(2, '0');
      var hh = String(d.getHours()).padStart(2, '0');
      var mi = String(d.getMinutes()).padStart(2, '0');
      var sc = String(d.getSeconds()).padStart(2, '0');
      return yyyy + '-' + mo + '-' + dd + ' ' + hh + ':' + mi + ':' + sc;
    } catch (e) {
      return iso;
    }
  }

  function resolveIdentityName(identityId) {
    if (!identityId) return 'Unknown';
    return identityMap[identityId] || identityId.substring(0, 8) + '...';
  }

  // -- MCP Servers section ----------------------------------------------------

  function resolveStatusClass(raw) {
    if (!raw) return 'connecting';
    var s = String(raw).toLowerCase();
    if (s === 'connected' || s === 'running') return 'connected';
    if (s === 'disconnected' || s === 'stopped' || s === 'error' || s === 'failed') return 'disconnected';
    return 'connecting';
  }

  function renderMcpServersSection(root) {
    var section = mk('div', 'access-section access-enter access-enter-1');
    var card = mk('div', 'card');

    var cardHeader = mk('div', 'card-header');
    var cardTitle = mk('span', 'card-title');
    cardTitle.innerHTML = SG.icon('server', 16) + ' ';
    cardTitle.appendChild(document.createTextNode('MCP Servers'));
    cardHeader.appendChild(cardTitle);

    var addBtn = mk('button', 'btn btn-primary btn-sm', { 'aria-label': 'Add a new MCP server' });
    addBtn.innerHTML = SG.icon('plus', 14) + ' ';
    addBtn.appendChild(document.createTextNode('Add MCP Server'));
    addBtn.addEventListener('click', function () {
      if (SG.tools && SG.tools.openAddUpstreamModal) {
        SG.tools.openAddUpstreamModal();
      } else {
        SG.toast.error('Please visit Tools & Rules first');
      }
    });
    cardHeader.appendChild(addBtn);
    card.appendChild(cardHeader);

    var cardBody = mk('div', 'card-body');
    cardBody.id = 'mcp-servers-container';
    card.appendChild(cardBody);

    section.appendChild(card);
    root.appendChild(section);

    // Load and render upstreams
    loadMcpServers();
  }

  function loadMcpServers() {
    SG.api.get('/upstreams').then(function (data) {
      upstreamsList = data || [];
      renderMcpServersTable();
    }).catch(function () {
      upstreamsList = [];
      renderMcpServersTable();
    });
  }

  function renderMcpServersTable() {
    var container = document.getElementById('mcp-servers-container');
    if (!container) return;
    container.innerHTML = '';

    if (upstreamsList.length === 0) {
      var empty = mk('div', 'mcp-servers-empty');
      empty.textContent = 'No servers configured yet. Add your first MCP server to get started.';
      container.appendChild(empty);
      return;
    }

    var table = mk('table', 'mcp-servers-table');
    var thead = mk('thead', '');
    var headRow = mk('tr', '');
    var headers = ['Name', 'Type', 'Status', 'Actions'];
    for (var h = 0; h < headers.length; h++) {
      var th = mk('th', '');
      th.textContent = headers[h];
      if (headers[h] === 'Actions') { th.style.textAlign = 'right'; th.style.width = '1%'; th.style.whiteSpace = 'nowrap'; th.style.paddingRight = '49px'; }
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = mk('tbody', '');
    for (var i = 0; i < upstreamsList.length; i++) {
      (function (up) {
        var row = mk('tr', '');

        // Name
        var nameCell = mk('td', '');
        nameCell.textContent = up.name || up.id || 'Unnamed';
        row.appendChild(nameCell);

        // Type
        var typeCell = mk('td', '');
        var typeBadge = mk('span', 'mcp-servers-type-badge');
        typeBadge.textContent = up.type || 'stdio';
        typeCell.appendChild(typeBadge);
        row.appendChild(typeCell);

        // Status
        var statusCell = mk('td', '');
        var statusWrap = mk('span', 'mcp-servers-status');
        var dot = mk('span', 'status-dot ' + resolveStatusClass(up.status));
        statusWrap.appendChild(dot);
        var statusLabel = document.createTextNode(up.status || 'connecting');
        statusWrap.appendChild(statusLabel);
        statusCell.appendChild(statusWrap);
        row.appendChild(statusCell);

        // Actions
        var actionsCell = mk('td', '');
        var actionsWrap = mk('div', 'mcp-servers-actions');

        var editBtn = mk('button', 'btn btn-secondary btn-sm', { 'aria-label': 'Edit server ' + (up.name || up.id || '') });
        editBtn.innerHTML = SG.icon('edit', 12) + ' Edit';
        editBtn.title = 'Edit server';
        editBtn.addEventListener('click', function () {
          if (SG.tools && SG.tools.openAddUpstreamModal) {
            SG.tools.openAddUpstreamModal(up);
          } else {
            SG.toast.error('Please visit Tools & Rules first');
          }
        });
        actionsWrap.appendChild(editBtn);

        var delBtn = mk('button', 'btn btn-danger btn-sm', { 'aria-label': 'Delete server ' + (up.name || up.id || '') });
        delBtn.innerHTML = SG.icon('trash', 12) + ' Delete';
        delBtn.title = 'Delete server';
        delBtn.addEventListener('click', function () {
          SG.modal.confirm({
            title: 'Delete Server',
            message: 'Are you sure you want to delete "' + (up.name || up.id) + '"?',
            confirmText: 'Delete',
            confirmClass: 'btn-danger',
            onConfirm: function () {
              SG.api.del('/upstreams/' + up.id).then(function () {
                SG.toast.success('Server deleted');
                loadMcpServers();
              }).catch(function (err) {
                SG.toast.error('Failed to delete server: ' + (err.message || 'Unknown error'));
              });
            }
          });
        });
        actionsWrap.appendChild(delBtn);

        actionsCell.appendChild(actionsWrap);
        row.appendChild(actionsCell);

        tbody.appendChild(row);
      })(upstreamsList[i]);
    }

    table.appendChild(tbody);
    container.appendChild(table);
  }

  // -- Build page DOM ---------------------------------------------------------

  function buildPage(container) {
    var root = mk('div', '');

    // Header
    var header = mk('div', 'access-header access-enter access-enter-1');
    var headerLeft = mk('div', '');
    var h1 = mk('h1');
    h1.textContent = 'Connections';
    headerLeft.appendChild(h1);
    var desc = mk('p', 'access-header-desc');
    desc.textContent = 'Manage MCP servers, identities, API keys, and agent connections.';
    headerLeft.appendChild(desc);
    header.appendChild(headerLeft);
    var helpBtn = mk('button', 'help-btn', { type: 'button', 'aria-label': 'Toggle help for connections page' });
    helpBtn.textContent = '?';
    helpBtn.addEventListener('click', function() { if (SG.help) SG.help.toggle('access'); });
    header.appendChild(helpBtn);
    root.appendChild(header);

    // MCP Servers section (at the top, before identities/keys)
    renderMcpServersSection(root);

    // Identities section
    var idSection = mk('div', 'access-section access-enter access-enter-2');

    // API Keys section
    var section = mk('div', 'access-section access-enter access-enter-3');

    var card = mk('div', 'card');
    var cardHeader = mk('div', 'card-header');
    var cardTitle = mk('span', 'card-title');
    cardTitle.innerHTML = SG.icon('key', 16) + ' ';
    cardTitle.appendChild(document.createTextNode('API Keys'));
    cardHeader.appendChild(cardTitle);

    var createBtn = mk('button', 'btn btn-primary btn-sm', { 'aria-label': 'Create a new API key' });
    createBtn.innerHTML = SG.icon('plus', 14) + ' ';
    createBtn.appendChild(document.createTextNode('Create Key'));
    createBtn.addEventListener('click', function () {
      openCreateKeyModal();
    });
    cardHeader.appendChild(createBtn);
    card.appendChild(cardHeader);

    var cardBody = mk('div', 'card-body');
    cardBody.id = 'keys-table-container';

    // Skeleton loading — 5 columns: Name, Identity, Created, Status, Actions
    cardBody.innerHTML = skeletonTableRows(3, 5);

    card.appendChild(cardBody);
    section.appendChild(card);
    var idCard = mk('div', 'card');

    var idCardHeader = mk('div', 'card-header access-collapse-header', {
      role: 'button',
      'aria-expanded': identitiesCollapsed ? 'false' : 'true',
      'aria-label': 'Toggle identities section'
    });
    var idCardTitleArea = mk('div', '', { style: 'display: flex; align-items: center; flex: 1;' });
    var idCardTitle = mk('span', 'card-title');
    idCardTitle.innerHTML = SG.icon('user', 16) + ' ';
    idCardTitle.appendChild(document.createTextNode('Identities'));
    idCardTitleArea.appendChild(idCardTitle);

    var chevron = mk('span', 'access-collapse-chevron');
    chevron.innerHTML = SG.icon('chevronDown', 14);
    idCardTitleArea.appendChild(chevron);
    idCardHeader.appendChild(idCardTitleArea);

    var addIdBtn = mk('button', 'btn btn-primary btn-sm');
    addIdBtn.setAttribute('data-action', 'add-identity');
    addIdBtn.setAttribute('aria-label', 'Add a new identity');
    addIdBtn.innerHTML = SG.icon('plus', 14) + ' ';
    addIdBtn.appendChild(document.createTextNode('Add Identity'));
    addIdBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      openAddIdentityModal();
    });
    idCardHeader.appendChild(addIdBtn);

    // Collapse toggle on header click
    idCardHeader.addEventListener('click', function () {
      identitiesCollapsed = !identitiesCollapsed;
      idCardHeader.setAttribute('aria-expanded', identitiesCollapsed ? 'false' : 'true');
      var body = document.getElementById('identities-table-container');
      if (body) {
        if (identitiesCollapsed) {
          body.classList.add('collapsed');
        } else {
          body.classList.remove('collapsed');
        }
      }
      if (identitiesCollapsed) {
        chevron.classList.add('collapsed');
      } else {
        chevron.classList.remove('collapsed');
      }
    });

    idCard.appendChild(idCardHeader);

    var idCardBody = mk('div', 'card-body access-collapse-body');
    idCardBody.id = 'identities-table-container';
    if (identitiesCollapsed) {
      idCardBody.classList.add('collapsed');
      chevron.classList.add('collapsed');
    }

    // Skeleton loading — 4 columns: Name, Roles, Created, Actions
    idCardBody.innerHTML = skeletonTableRows(3, 4);

    idCard.appendChild(idCardBody);
    idSection.appendChild(idCard);
    root.appendChild(idSection);

    // Connect Your Agent section (tabbed config)
    var configSection = mk('div', 'access-section access-enter access-enter-4');
    var configCard = mk('div', 'card');
    var configCardHeader = mk('div', 'card-header');
    var configCardTitle = mk('span', 'card-title');
    configCardTitle.innerHTML = SG.icon('code', 16) + ' ';
    configCardTitle.appendChild(document.createTextNode('Connect Your Agent'));
    configCardHeader.appendChild(configCardTitle);
    configCard.appendChild(configCardHeader);

    var configCardBody = mk('div', 'card-body');

    var configInfo = mk('p', '', {
      style: 'font-size: var(--text-sm); color: var(--text-secondary); margin: 0 0 var(--space-4) 0;'
    });
    configInfo.textContent = 'Choose your agent below and copy the configuration snippet. Replace <your-api-key> with a key from the section above.';
    configCardBody.appendChild(configInfo);

    var terminalGuide = mk('div', 'info-box', { style: 'margin-bottom: var(--space-4);' });
    var terminalIcon = mk('div', 'info-box-icon');
    terminalIcon.innerHTML = SG.icon('terminal', 16);
    terminalGuide.appendChild(terminalIcon);
    var terminalText = mk('div', '');
    terminalText.innerHTML = 'These commands run in a <strong>terminal</strong> (also called command line). <strong>Mac</strong>: open Terminal from Applications \u2192 Utilities. <strong>Windows</strong>: open Command Prompt or PowerShell from the Start menu.';
    terminalGuide.appendChild(terminalText);
    configCardBody.appendChild(terminalGuide);

    var proxyAddress = window.location.host || 'localhost:8080';

    var agentTabs = [
      {
        label: 'Claude Code',
        snippet: '# Option 1: CLI (recommended)\nclaude mcp add --transport http sentinelgate \\\n  http://' + proxyAddress + '/mcp \\\n  --header "Authorization: Bearer <your-api-key>"\n\n# Option 2: ~/.claude/settings.json\n' + JSON.stringify({ mcpServers: { sentinelgate: { type: 'http', url: 'http://' + proxyAddress + '/mcp', headers: { Authorization: 'Bearer <your-api-key>' } } } }, null, 2)
      },
      {
        label: 'Gemini CLI',
        snippet: '# Option 1: CLI (recommended)\ngemini mcp add --transport http -s user \\\n  --header "Authorization: Bearer <your-api-key>" \\\n  sentinelgate http://' + proxyAddress + '/mcp\n\n# Option 2: ~/.gemini/settings.json\n' + JSON.stringify({ mcpServers: { sentinelgate: { url: 'http://' + proxyAddress + '/mcp', type: 'http', headers: { Authorization: 'Bearer <your-api-key>' } } } }, null, 2)
      },
      {
        label: 'Codex CLI',
        snippet: '# Option 1: CLI with env var (recommended)\nexport SG_KEY="<your-api-key>"\ncodex mcp add sentinelgate --url http://' + proxyAddress + '/mcp \\\n  --bearer-token-env-var SG_KEY\n\n# Option 2: ~/.codex/config.toml\n[mcp_servers.sentinelgate]\nurl = "http://' + proxyAddress + '/mcp"\nbearer_token_env_var = "SG_KEY"\n\n# Then launch with: SG_KEY="<your-api-key>" codex\n\n# NOTE: Codex does NOT persist the API key (unlike Claude/Gemini).\n# The env var must be set each time. To make it permanent:\n# echo \'export SG_KEY="<your-api-key>"\' >> ~/.zshrc'
      },
      {
        label: 'Cursor / IDE',
        snippet: '// Add to your IDE\'s MCP settings (e.g. .cursor/mcp.json):\n' + JSON.stringify({ mcpServers: { sentinelgate: { type: 'http', url: 'http://' + proxyAddress + '/mcp', headers: { Authorization: 'Bearer <your-api-key>' } } } }, null, 2)
      },
      {
        label: 'Python',
        snippet: 'import httpx\nfrom mcp import ClientSession\nfrom mcp.client.streamable_http import streamable_http_client\n\nasync def main():\n    http_client = httpx.AsyncClient(\n        headers={"Authorization": "Bearer <your-api-key>"}\n    )\n    async with streamable_http_client(\n        "http://' + proxyAddress + '/mcp", http_client=http_client\n    ) as (r, w, _):\n        async with ClientSession(r, w) as session:\n            await session.initialize()\n\n            # List available tools\n            tools = await session.list_tools()\n            print(tools)\n\n            # Call a tool\n            result = await session.call_tool(\n                "tool_name", {"arg": "value"}\n            )\n            print(result)'
      },
      {
        label: 'Node.js',
        snippet: 'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\nimport { StreamableHTTPClientTransport }\n  from "@modelcontextprotocol/sdk/client/streamableHttp.js";\n\nconst transport = new StreamableHTTPClientTransport(\n  new URL("http://' + proxyAddress + '/mcp"),\n  {\n    requestInit: {\n      headers: { "Authorization": "Bearer <your-api-key>" }\n    }\n  }\n);\n\nconst client = new Client(\n  { name: "my-client", version: "1.0.0" }\n);\nawait client.connect(transport);\n\n// List available tools\nconst { tools } = await client.listTools();\nconsole.log(tools);\n\n// Call a tool\nconst result = await client.callTool(\n  { name: "tool_name", arguments: { arg: "value" } }\n);\nconsole.log(result);'
      },
      {
        label: 'cURL',
        snippet: '# Initialize\ncurl -X POST http://' + proxyAddress + '/mcp \\\n  -H "Authorization: Bearer <your-api-key>" \\\n  -H "Content-Type: application/json" \\\n  -d \'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"curl","version":"1.0"},"capabilities":{}}}\'\n\n# List tools\ncurl -X POST http://' + proxyAddress + '/mcp \\\n  -H "Authorization: Bearer <your-api-key>" \\\n  -H "Content-Type: application/json" \\\n  -d \'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\''
      }
    ];

    // Tab bar
    var tabBar = mk('div', 'config-tabs');
    var tabContents = [];

    for (var t = 0; t < agentTabs.length; t++) {
      (function (idx) {
        var tab = agentTabs[idx];

        // Tab button
        var tabBtn = mk('button', 'config-tab' + (idx === 0 ? ' active' : ''));
        tabBtn.textContent = tab.label;
        tabBtn.setAttribute('data-tab-idx', String(idx));
        tabBar.appendChild(tabBtn);

        // Tab content — split by "# Option" markers for per-option copy buttons
        var content = mk('div', 'config-tab-content' + (idx === 0 ? ' active' : ''));
        var options = tab.snippet.split(/^(?=# Option \d)/m);
        if (options.length <= 1) { options = [tab.snippet]; }

        for (var oi = 0; oi < options.length; oi++) {
          (function (optText, optIdx) {
            var snippetWrapper = mk('div', 'config-snippet-wrapper');
            var snippetPre = mk('pre', 'config-snippet');
            snippetPre.textContent = optText.trim();
            snippetWrapper.appendChild(snippetPre);

            var copyBtn = mk('button', 'config-copy-btn', { 'aria-label': 'Copy option' });
            copyBtn.innerHTML = SG.icon('copy', 12) + ' ';
            var copyLabel = mk('span', '');
            copyLabel.textContent = 'Copy';
            copyBtn.appendChild(copyLabel);

            // Extract only the command (skip comment lines starting with #)
            var commandOnly = optText.split('\n').filter(function (line) {
              var trimmed = line.trim();
              return trimmed !== '' && trimmed.charAt(0) !== '#';
            }).join('\n');

            copyBtn.addEventListener('click', function () {
              var text = commandOnly || optText.trim();
              if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function () {
                  copyBtn.classList.add('copied');
                  copyLabel.textContent = 'Copied!';
                  SG.toast.show('Copied to clipboard', 'success');
                  setTimeout(function () {
                    copyBtn.classList.remove('copied');
                    copyLabel.textContent = 'Copy';
                  }, 2000);
                }).catch(function () {
                  fallbackConfigCopy(text, copyBtn, copyLabel);
                });
              } else {
                fallbackConfigCopy(text, copyBtn, copyLabel);
              }
            });
            snippetWrapper.appendChild(copyBtn);
            content.appendChild(snippetWrapper);
          })(options[oi], oi);
        }
        tabContents.push(content);

        // Tab click handler
        tabBtn.addEventListener('click', function () {
          var allTabs = tabBar.querySelectorAll('.config-tab');
          for (var j = 0; j < allTabs.length; j++) {
            allTabs[j].classList.remove('active');
          }
          tabBtn.classList.add('active');
          for (var j = 0; j < tabContents.length; j++) {
            tabContents[j].classList.remove('active');
          }
          tabContents[idx].classList.add('active');
        });
      })(t);
    }

    configCardBody.appendChild(tabBar);
    for (var tc = 0; tc < tabContents.length; tc++) {
      configCardBody.appendChild(tabContents[tc]);
    }

    configCard.appendChild(configCardBody);
    configSection.appendChild(configCard);
    root.appendChild(configSection);
    root.appendChild(section); // API Keys after Connect Your Agent

    container.appendChild(root);
  }

  // -- Render keys table ------------------------------------------------------

  function renderKeysTable() {
    var container = document.getElementById('keys-table-container');
    if (!container) return;
    container.innerHTML = '';

    if (keys.length === 0) {
      var empty = mk('div', 'empty-state');
      var emptyIcon = mk('div', 'empty-state-icon');
      emptyIcon.innerHTML = SG.icon('key', 32);
      empty.appendChild(emptyIcon);
      var emptyTitle = mk('p', 'empty-state-title');
      emptyTitle.textContent = 'No API keys';
      empty.appendChild(emptyTitle);
      var emptyDesc = mk('p', 'empty-state-description');
      emptyDesc.textContent = 'No API keys yet. First create an identity above, then generate a key for it.';
      empty.appendChild(emptyDesc);
      container.appendChild(empty);
      return;
    }

    var table = mk('table', 'table');

    // Table head
    var thead = mk('thead', '');
    var headRow = mk('tr', '');
    var cols = ['Name', 'Identity', 'Created', 'Status', 'Actions'];
    for (var c = 0; c < cols.length; c++) {
      var th = mk('th', '');
      th.textContent = cols[c];
      if (cols[c] === 'Actions') { th.style.textAlign = 'right'; th.style.width = '1%'; th.style.whiteSpace = 'nowrap'; }
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    // Table body
    var tbody = mk('tbody', '');
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var row = mk('tr', '');

      // Name
      var tdName = mk('td', '');
      var nameSpan = mk('span', '', { style: 'font-weight: var(--font-medium);' });
      nameSpan.textContent = key.name || '-';
      tdName.appendChild(nameSpan);
      row.appendChild(tdName);

      // Identity
      var tdIdentity = mk('td', '');
      tdIdentity.textContent = resolveIdentityName(key.identity_id);
      row.appendChild(tdIdentity);

      // Created
      var tdCreated = mk('td', '');
      tdCreated.textContent = formatDate(key.created_at);
      row.appendChild(tdCreated);

      // Status
      var tdStatus = mk('td', '');
      if (key.revoked) {
        var revokedBadge = mk('span', 'badge badge-danger');
        revokedBadge.textContent = 'Revoked';
        tdStatus.appendChild(revokedBadge);
      } else {
        var activeBadge = mk('span', 'badge badge-success');
        activeBadge.textContent = 'Active';
        tdStatus.appendChild(activeBadge);
      }
      row.appendChild(tdStatus);

      // Actions
      var tdActions = mk('td', '', { style: 'text-align: right; padding-right: 15px;' });
      if (!key.revoked && !key.read_only) {
        var revokeBtn = mk('button', 'btn btn-danger btn-sm', { 'aria-label': 'Revoke API key ' + (key.name || '') });
        revokeBtn.textContent = 'Revoke';
        (function (keyId, keyName) {
          revokeBtn.addEventListener('click', function () {
            revokeKey(keyId, keyName);
          });
        })(key.id, key.name);
        tdActions.appendChild(revokeBtn);
      } else if (key.read_only) {
        var roLabel = mk('span', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted);'
        });
        roLabel.textContent = 'Read-only';
        tdActions.appendChild(roLabel);
      } else {
        var revLabel = mk('span', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted);'
        });
        revLabel.textContent = '-';
        tdActions.appendChild(revLabel);
      }
      row.appendChild(tdActions);

      tbody.appendChild(row);
    }

    table.appendChild(tbody);
    container.appendChild(table);
  }

  // -- Render identities table ------------------------------------------------

  function renderIdentitiesTable() {
    var container = document.getElementById('identities-table-container');
    if (!container) return;
    container.innerHTML = '';

    // Preserve collapse state
    if (identitiesCollapsed) {
      container.classList.add('collapsed');
    }

    if (identities.length === 0) {
      var empty = mk('div', 'empty-state');
      var emptyIllustration = mk('div', 'empty-state-illustration');
      emptyIllustration.innerHTML = identitiesEmptyStateSvg();
      empty.appendChild(emptyIllustration);
      var emptyTitle = mk('p', 'empty-state-title');
      emptyTitle.textContent = 'No identities configured';
      empty.appendChild(emptyTitle);
      var emptyDesc = mk('p', 'empty-state-description');
      emptyDesc.textContent = 'Identities represent each user or service that connects through the proxy. Create your first identity to get started.';
      empty.appendChild(emptyDesc);
      var emptyCta = mk('button', 'btn btn-primary', { 'data-action': 'add-identity' });
      emptyCta.innerHTML = SG.icon('plus', 14) + ' ';
      emptyCta.appendChild(document.createTextNode('Add Identity'));
      emptyCta.setAttribute('aria-label', 'Add a new identity');
      emptyCta.addEventListener('click', function () {
        openAddIdentityModal();
      });
      empty.appendChild(emptyCta);
      container.appendChild(empty);
      return;
    }

    // Search/filter bar
    var searchInput = mk('input', 'form-input', { type: 'text', placeholder: 'Filter identities by name or role...',
      style: 'margin-bottom:var(--space-3);max-width:320px' });
    searchInput.addEventListener('input', function () {
      var query = this.value.toLowerCase();
      var rows = container.querySelectorAll('tbody tr');
      for (var ri = 0; ri < rows.length; ri++) {
        var name = (rows[ri].getAttribute('data-identity-name') || '').toLowerCase();
        var roles = (rows[ri].getAttribute('data-identity-roles') || '').toLowerCase();
        rows[ri].style.display = (name.indexOf(query) !== -1 || roles.indexOf(query) !== -1) ? '' : 'none';
      }
    });
    container.appendChild(searchInput);

    var table = mk('table', 'table');

    // Table head
    var thead = mk('thead', '');
    var headRow = mk('tr', '');
    var cols = ['Name', 'Roles', 'Created', 'Actions', ''];
    for (var c = 0; c < cols.length; c++) {
      var th = mk('th', '');
      th.textContent = cols[c];
      if (cols[c] === 'Actions') { th.style.textAlign = 'right'; th.style.width = '1%'; th.style.whiteSpace = 'nowrap'; }
      if (c === cols.length - 1) th.style.width = '24px';
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    // Table body
    var tbody = mk('tbody', '');
    for (var i = 0; i < identities.length; i++) {
      var identity = identities[i];
      var row = mk('tr', '');
      row.setAttribute('data-identity-name', identity.name || '');
      row.setAttribute('data-identity-roles', (identity.roles || []).join(' '));

      // Name + quota badge
      var tdName = mk('td', '');
      var nameSpan = mk('span', '', { style: 'font-weight: var(--font-medium);' });
      nameSpan.textContent = identity.name || '-';
      tdName.appendChild(nameSpan);
      var uuidEl = mk('div', '', { style: 'font-size: var(--text-xs); color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px;' });
      uuidEl.textContent = identity.id;
      tdName.appendChild(uuidEl);

      // Show quota badge if quota is configured for this identity
      var q = quotaMap[identity.id];
      if (q) {
        var qBadgeCls, qBadgeText;
        if (!q.enabled) {
          qBadgeCls = 'quota-badge quota-badge-configured';
          qBadgeText = 'Quota: configured';
        } else if (q.action === 'warn') {
          qBadgeCls = 'quota-badge quota-badge-warn';
          qBadgeText = 'Quota: warn';
        } else {
          qBadgeCls = 'quota-badge quota-badge-enabled';
          qBadgeText = 'Quota: enforced';
        }
        var qBadge = mk('span', qBadgeCls);
        qBadge.textContent = qBadgeText;
        tdName.appendChild(qBadge);
      }

      row.appendChild(tdName);

      // Roles
      var tdRoles = mk('td', '');
      var rolesContainer = mk('div', 'identity-roles');
      var roles = identity.roles || [];
      if (roles.length === 0) {
        var noRoles = mk('span', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted);'
        });
        noRoles.textContent = 'No roles';
        rolesContainer.appendChild(noRoles);
      } else {
        for (var r = 0; r < roles.length; r++) {
          var roleBadge = mk('span', 'role-badge');
          roleBadge.textContent = roles[r];
          rolesContainer.appendChild(roleBadge);
        }
      }
      tdRoles.appendChild(rolesContainer);
      row.appendChild(tdRoles);

      // Created
      var tdCreated = mk('td', '');
      tdCreated.textContent = formatDate(identity.created_at);
      row.appendChild(tdCreated);

      // Actions
      var tdActions = mk('td', '');
      if (!identity.read_only) {
        var actionsWrap = mk('div', '', { style: 'display: flex; gap: var(--space-2); justify-content: flex-end; white-space: nowrap;' });
        var editBtn = mk('button', 'btn btn-secondary btn-sm', { 'aria-label': 'Edit identity ' + (identity.name || '') });
        editBtn.textContent = 'Edit';
        (function (id) {
          editBtn.addEventListener('click', function () {
            openEditIdentityModal(id);
          });
        })(identity);
        actionsWrap.appendChild(editBtn);

        var quotaBtn = mk('button', 'btn btn-secondary btn-sm', { 'aria-label': 'Configure quota for ' + (identity.name || '') });
        var qStatus = quotaMap[identity.id];
        if (qStatus && qStatus.enabled) {
          quotaBtn.innerHTML = '<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--success);margin-right:6px;vertical-align:middle;"></span>';
          var qBtnText = mk('span', '');
          qBtnText.textContent = 'Quota Active';
          quotaBtn.appendChild(qBtnText);
        } else {
          quotaBtn.textContent = 'Configure Quota';
        }
        (function (id) {
          quotaBtn.addEventListener('click', function () {
            openQuotaModal(id);
          });
        })(identity);
        actionsWrap.appendChild(quotaBtn);

        var rulesBtn = mk('button', 'btn btn-secondary btn-sm', { 'aria-label': 'View rules for ' + (identity.name || '') });
        rulesBtn.textContent = 'View Rules';
        (function (id) {
          rulesBtn.addEventListener('click', function () {
            openIdentityRulesModal(id);
          });
        })(identity);
        actionsWrap.appendChild(rulesBtn);

        var deleteBtn = mk('button', 'btn btn-danger btn-sm', { 'aria-label': 'Delete identity ' + (identity.name || '') });
        deleteBtn.textContent = 'Delete';
        (function (id) {
          deleteBtn.addEventListener('click', function () {
            deleteIdentity(id.id, id.name);
          });
        })(identity);
        actionsWrap.appendChild(deleteBtn);

        tdActions.appendChild(actionsWrap);
      } else {
        var roLabel = mk('span', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted);'
        });
        roLabel.textContent = 'Read-only';
        tdActions.appendChild(roLabel);
      }
      row.appendChild(tdActions);

      // Chevron column
      var tdChevron = mk('td', '');
      var chevronSpan = mk('span', '', { style: 'font-size:1.2em;color:var(--text-muted)' });
      chevronSpan.textContent = '\u203A';
      tdChevron.appendChild(chevronSpan);
      row.appendChild(tdChevron);

      // Row click → open identity rules modal
      (function (id) {
        row.addEventListener('click', function (e) {
          if (e.target.closest('button')) return;
          openIdentityRulesModal(id);
        });
      })(identity);

      tbody.appendChild(row);
    }

    table.appendChild(tbody);
    container.appendChild(table);
  }

  // -- Identity Rules modal ---------------------------------------------------

  function openIdentityRulesModal(identity) {
    var identityName = identity.name || identity.id;
    var identityRoles = identity.roles || [];

    SG.api.get('/policies').then(function (policies) {
      var matchingRules = [];
      for (var pi = 0; pi < policies.length; pi++) {
        var pol = policies[pi];
        if (!pol.enabled) continue;
        var rules = pol.rules || [];
        for (var ri = 0; ri < rules.length; ri++) {
          var rule = rules[ri];
          // BUG-5 FIX: A rule applies to this identity if:
          // 1. No conditions (applies to all)
          // 2. Condition does NOT reference any identity variable → applies to all
          // 3. Condition references identity_name and matches this identity
          // 4. Condition references identity_roles/user_roles and matches a role
          // 5. Condition references identity_id and matches this identity
          // Previously, rules based on tool_name (not identity) were excluded
          // because they didn't match any identity variable check.
          var condition = rule.condition || '';
          var applies = false;
          var refsIdentity = condition.indexOf('identity_name') >= 0 ||
                             condition.indexOf('identity_roles') >= 0 ||
                             condition.indexOf('user_roles') >= 0 ||
                             condition.indexOf('identity_id') >= 0;
          if (!condition || condition === 'true') {
            applies = true;
          } else if (!refsIdentity) {
            // Rule does not reference any identity variable — applies to everyone
            applies = true;
          } else if (condition.indexOf('identity_name') >= 0 && condition.indexOf(identityName) >= 0) {
            applies = true;
          } else if (condition.indexOf('identity_roles') >= 0 || condition.indexOf('user_roles') >= 0) {
            for (var rri = 0; rri < identityRoles.length; rri++) {
              if (condition.indexOf(identityRoles[rri]) >= 0) {
                applies = true;
                break;
              }
            }
          } else if (condition.indexOf('identity_id') >= 0 && condition.indexOf(identity.id) >= 0) {
            applies = true;
          }
          if (applies) {
            matchingRules.push({
              policyName: pol.name || pol.id,
              ruleName: rule.name || 'Unnamed',
              toolMatch: rule.tool_match || '*',
              action: rule.action || 'deny',
              priority: rule.priority != null ? rule.priority : 0,
              condition: condition
            });
          }
        }
      }

      // Sort by priority descending
      matchingRules.sort(function (a, b) { return b.priority - a.priority; });

      var body = mk('div', '');

      // Identity info header
      var infoDiv = mk('div', '', { style: 'margin-bottom: var(--space-3); padding: var(--space-2); background: var(--bg-secondary); border-radius: var(--radius-md);' });
      var nameEl = mk('div', '', { style: 'font-weight: var(--font-bold); font-size: var(--text-lg);' });
      nameEl.textContent = identityName;
      infoDiv.appendChild(nameEl);
      if (identityRoles.length > 0) {
        var rolesEl = mk('div', '', { style: 'margin-top: 4px; font-size: var(--text-sm); color: var(--text-muted);' });
        rolesEl.textContent = 'Roles: ' + identityRoles.join(', ');
        infoDiv.appendChild(rolesEl);
      }
      body.appendChild(infoDiv);

      if (matchingRules.length === 0) {
        var noRules = mk('p', '', { style: 'color: var(--text-muted);' });
        noRules.textContent = 'No policy rules apply to this identity. Default behavior (allow) applies to all tool calls.';
        body.appendChild(noRules);
      } else {
        var countEl = mk('p', '', { style: 'font-size: var(--text-sm); color: var(--text-muted); margin-bottom: var(--space-2);' });
        countEl.textContent = matchingRules.length + ' rule' + (matchingRules.length !== 1 ? 's' : '') + ' apply to this identity:';
        body.appendChild(countEl);

        var table = mk('table', 'table', { style: 'width: 100%;' });
        var thead = mk('thead');
        var headRow = mk('tr');
        ['Policy', 'Rule', 'Tool', 'Action', 'Priority'].forEach(function (h) {
          var th = mk('th');
          th.textContent = h;
          headRow.appendChild(th);
        });
        thead.appendChild(headRow);
        table.appendChild(thead);

        var tbody = mk('tbody');
        for (var mi = 0; mi < matchingRules.length; mi++) {
          var mr = matchingRules[mi];
          var tr = mk('tr');
          var policyTd = mk('td');
          policyTd.textContent = mr.policyName;
          tr.appendChild(policyTd);
          var ruleTd = mk('td');
          ruleTd.textContent = mr.ruleName;
          tr.appendChild(ruleTd);
          var toolTd = mk('td');
          var toolCode = mk('code');
          toolCode.textContent = mr.toolMatch;
          toolTd.appendChild(toolCode);
          tr.appendChild(toolTd);
          var actionTd = mk('td');
          var actionBadge = mk('span', 'badge ' + (mr.action === 'allow' ? 'badge-success' : mr.action === 'deny' ? 'badge-danger' : 'badge-warning'));
          actionBadge.textContent = mr.action;
          actionTd.appendChild(actionBadge);
          tr.appendChild(actionTd);
          var prioTd = mk('td');
          prioTd.textContent = String(mr.priority);
          tr.appendChild(prioTd);
          tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        body.appendChild(table);
      }

      var footerEl = document.createElement('div');
      footerEl.style.display = 'contents';
      var viewBtn = mk('button', 'btn btn-secondary');
      viewBtn.textContent = 'View in Tools & Rules';
      viewBtn.addEventListener('click', function () { window.location.hash = '#/tools'; SG.modal.close(); });
      var closeBtn2 = mk('button', 'btn btn-primary');
      closeBtn2.textContent = 'Close';
      closeBtn2.addEventListener('click', function () { SG.modal.close(); });
      footerEl.appendChild(viewBtn);
      footerEl.appendChild(closeBtn2);
      SG.modal.open({
        title: 'Applicable Rules \u2014 ' + identityName,
        body: body,
        footer: footerEl,
        width: '640px'
      });
    }).catch(function (err) {
      SG.toast.error('Failed to load rules: ' + (err.message || 'Unknown error'));
    });
  }

  // -- Quota modal ------------------------------------------------------------

  function openQuotaModal(identity) {
    // Fetch fresh quota data before opening the modal so saved limits are shown
    SG.api.get('/v1/quotas').then(function (freshQuotas) {
      if (Array.isArray(freshQuotas)) {
        for (var q = 0; q < freshQuotas.length; q++) {
          if (freshQuotas[q].identity_id) {
            quotaMap[freshQuotas[q].identity_id] = freshQuotas[q];
          }
        }
      }
    }).catch(function () {
      // Proceed with cached data if fetch fails
    }).finally(function () {
      openQuotaModalInner(identity);
    });
  }

  function openQuotaModalInner(identity) {
    var existing = quotaMap[identity.id] || null;

    var form = mk('form', '');
    form.addEventListener('submit', function (e) { e.preventDefault(); });
    // Close modal when clicking navigation links inside it
    form.addEventListener('click', function (e) {
      var link = e.target.closest('.quota-nav-link');
      if (link) { SG.modal.close(); }
    });

    // Enabled toggle (at top, most important control)
    var toggleRow = mk('div', 'quota-toggle-row');
    var enabledCheckbox = mk('input', '', { type: 'checkbox', id: 'quota-enabled' });
    if (existing && existing.enabled) {
      enabledCheckbox.checked = true;
    }
    toggleRow.appendChild(enabledCheckbox);
    var toggleLabel = mk('label', 'quota-toggle-label', { for: 'quota-enabled' });
    toggleLabel.textContent = 'Enable quota enforcement';
    toggleRow.appendChild(toggleLabel);
    form.appendChild(toggleRow);

    var quotaHint = mk('div', '', { style: 'font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-3);padding-left:var(--space-1)' });
    quotaHint.innerHTML = 'When enabled, tool calls are counted and checked against the limits below. Changes apply to new sessions. Active sessions keep their current counters. To apply limits immediately, <a href="#/sessions" class="quota-nav-link" style="color:var(--accent)">terminate active sessions</a>. Inactive sessions expire after 30 minutes.';
    form.appendChild(quotaHint);

    // Action selector
    var actionRow = mk('div', 'quota-action-row');
    var actionLabel = mk('label', '');
    actionLabel.textContent = 'Action on limit breach';
    actionRow.appendChild(actionLabel);
    var actionSelect = mk('select', '');
    var optDeny = mk('option', '', { value: 'deny' });
    optDeny.textContent = 'Deny';
    actionSelect.appendChild(optDeny);
    var optWarn = mk('option', '', { value: 'warn' });
    optWarn.textContent = 'Warn';
    actionSelect.appendChild(optWarn);
    if (existing && existing.action === 'warn') {
      actionSelect.value = 'warn';
    }
    actionRow.appendChild(actionSelect);
    form.appendChild(actionRow);

    // Section title
    var limitsTitle = mk('div', 'quota-section-title');
    limitsTitle.textContent = 'Session Limits';
    form.appendChild(limitsTitle);

    var sessionNote = mk('div', '', { style: 'font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-2);padding-left:var(--space-1)' });
    sessionNote.innerHTML = 'Note: agents may open multiple sessions. For stricter control, use daily limits below. <a href="#/sessions" class="quota-nav-link" style="color:var(--accent)">Manage sessions \u2192</a>';
    form.appendChild(sessionNote);

    // Limit fields
    var fields = [
      { key: 'max_calls_per_session', label: 'Max Calls per Session', apiField: 'max_calls_per_session' },
      { key: 'max_writes_per_session', label: 'Max Writes per Session', apiField: 'max_writes_per_session' },
      { key: 'max_deletes_per_session', label: 'Max Deletes per Session', apiField: 'max_deletes_per_session' },
      { key: 'max_calls_per_minute', label: 'Max Calls per Minute', apiField: 'max_calls_per_minute' }
    ];

    var inputs = {};
    for (var f = 0; f < fields.length; f++) {
      var field = fields[f];
      var row = mk('div', 'quota-form-row');
      var lbl = mk('label', '');
      lbl.textContent = field.label;
      row.appendChild(lbl);
      var input = mk('input', '', {
        type: 'number',
        min: '0',
        placeholder: 'Unlimited'
      });
      if (existing && existing[field.key] > 0) {
        input.value = String(existing[field.key]);
      }
      inputs[field.apiField] = input;
      row.appendChild(input);
      form.appendChild(row);
    }

    // Daily Limits section
    var dailyTitle = mk('div', 'quota-section-title');
    dailyTitle.textContent = 'Daily Limits';
    form.appendChild(dailyTitle);

    // Max Calls per Day field
    var dayRow = mk('div', 'quota-form-row');
    var dayLbl = mk('label', '');
    dayLbl.textContent = 'Max Calls per Day';
    dayRow.appendChild(dayLbl);
    var dayInput = mk('input', '', { type: 'number', min: '0', placeholder: 'Unlimited' });
    if (existing && existing.max_calls_per_day > 0) {
      dayInput.value = String(existing.max_calls_per_day);
    }
    dayRow.appendChild(dayInput);
    form.appendChild(dayRow);

    // Per-Tool Limits section
    var toolTitle = mk('div', 'quota-section-title');
    toolTitle.textContent = 'Per-Tool Limits';
    form.appendChild(toolTitle);

    // Local tool limits object
    var toolLimits = {};
    if (existing && existing.tool_limits) {
      var tlKeys = Object.keys(existing.tool_limits);
      for (var t = 0; t < tlKeys.length; t++) {
        toolLimits[tlKeys[t]] = existing.tool_limits[tlKeys[t]];
      }
    }

    // Container for tool limit items (re-rendered on add/remove)
    var toolListContainer = mk('div', '');
    form.appendChild(toolListContainer);

    function renderToolLimitsList() {
      toolListContainer.innerHTML = '';
      var keys = Object.keys(toolLimits);
      if (keys.length === 0) {
        var emptyMsg = mk('div', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted); padding: var(--space-2) 0;'
        });
        emptyMsg.textContent = 'No per-tool limits configured';
        toolListContainer.appendChild(emptyMsg);
      } else {
        for (var ti = 0; ti < keys.length; ti++) {
          (function (toolName) {
            var item = mk('div', 'tool-limit-item');
            var nameSpan = mk('span', 'tool-limit-name');
            nameSpan.textContent = toolName;
            item.appendChild(nameSpan);
            var valSpan = mk('span', 'tool-limit-value');
            valSpan.textContent = String(toolLimits[toolName]);
            item.appendChild(valSpan);
            var rmBtn = mk('button', 'btn btn-danger btn-sm', { type: 'button', 'aria-label': 'Remove limit for tool ' + toolName });
            rmBtn.textContent = 'Remove';
            rmBtn.addEventListener('click', function () {
              delete toolLimits[toolName];
              renderToolLimitsList();
            });
            item.appendChild(rmBtn);
            toolListContainer.appendChild(item);
          })(keys[ti]);
        }
      }
    }
    renderToolLimitsList();

    // Add tool limit row
    var addToolRow = mk('div', 'tool-limit-add-row');
    var toolNameInput = mk('input', '', { type: 'text', placeholder: 'Tool name (e.g. read_file)' });
    toolNameInput.style.flex = '1';
    addToolRow.appendChild(toolNameInput);
    var toolLimitInput = mk('input', '', { type: 'number', min: '1', placeholder: 'Limit' });
    toolLimitInput.style.width = '80px';
    addToolRow.appendChild(toolLimitInput);
    var addToolBtn = mk('button', 'btn btn-primary btn-sm', { type: 'button' });
    addToolBtn.textContent = 'Add';
    addToolBtn.addEventListener('click', function () {
      var tName = toolNameInput.value.trim();
      var tLimit = parseInt(toolLimitInput.value, 10);
      if (!tName) {
        toolNameInput.focus();
        return;
      }
      if (!tLimit || tLimit < 1) {
        toolLimitInput.focus();
        return;
      }
      if (toolLimits[tName] !== undefined) {
        SG.toast.show('Tool "' + tName + '" already has a limit. Remove it first to change.', 'warning');
        return;
      }
      toolLimits[tName] = tLimit;
      toolNameInput.value = '';
      toolLimitInput.value = '';
      renderToolLimitsList();
    });
    addToolRow.appendChild(addToolBtn);
    form.appendChild(addToolRow);

    var toolLimitHelp = mk('div', 'form-help', { style: 'margin-top: var(--space-2);' });
    toolLimitHelp.textContent = 'Exact tool name with max calls per session. Examples: write_file: 10, delete_file: 5, execute_command: 3';
    form.appendChild(toolLimitHelp);

    // (toggle moved to top of form)

    // Footer with buttons
    var footer = mk('div', '', { style: 'display: contents;' });

    // Remove quota button (only if quota exists)
    if (existing) {
      var removeBtn = mk('button', 'quota-remove-btn', { 'aria-label': 'Remove quota for ' + (identity.name || '') });
      removeBtn.type = 'button';
      removeBtn.innerHTML = SG.icon('x', 12) + ' ';
      var removeLabel = mk('span', '');
      removeLabel.textContent = 'Remove Quota';
      removeBtn.appendChild(removeLabel);
      removeBtn.addEventListener('click', function () {
        removeBtn.disabled = true;
        removeLabel.textContent = 'Removing...';
        SG.api.del('/v1/quotas/' + encodeURIComponent(identity.id)).then(function () {
          delete quotaMap[identity.id];
          SG.modal.close();
          SG.toast.show('Quota removed', 'success');
          renderIdentitiesTable();
        }).catch(function (err) {
          removeBtn.disabled = false;
          removeLabel.textContent = 'Remove Quota';
          SG.toast.show(err.message || 'Failed to remove quota', 'error');
        });
      });
      footer.appendChild(removeBtn);
    }

    var cancelBtn = mk('button', 'btn btn-secondary');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.type = 'button';
    cancelBtn.addEventListener('click', function () {
      SG.modal.close();
    });
    footer.appendChild(cancelBtn);

    // Second enable toggle near Save for quick access
    var footerToggle = mk('label', '', { style: 'display:flex;align-items:center;gap:var(--space-1);font-size:var(--text-sm);margin-right:auto;cursor:pointer;' });
    var footerCheckbox = mk('input', '', { type: 'checkbox' });
    footerCheckbox.checked = enabledCheckbox.checked;
    // Keep both checkboxes in sync
    footerCheckbox.addEventListener('change', function () { enabledCheckbox.checked = footerCheckbox.checked; });
    enabledCheckbox.addEventListener('change', function () { footerCheckbox.checked = enabledCheckbox.checked; });
    footerToggle.appendChild(footerCheckbox);
    footerToggle.appendChild(document.createTextNode('Enabled'));
    footer.appendChild(footerToggle);

    var saveBtn = mk('button', 'btn btn-primary');
    saveBtn.textContent = 'Save';
    saveBtn.type = 'submit';
    footer.appendChild(saveBtn);

    SG.modal.open({
      title: 'Quota for ' + (identity.name || 'Unknown'),
      body: form,
      footer: footer,
      width: '520px'
    });

    // Handle save
    saveBtn.addEventListener('click', function () {
      var payload = {
        enabled: enabledCheckbox.checked,
        action: actionSelect.value
      };

      // Collect numeric fields (omit 0 / empty)
      for (var fk = 0; fk < fields.length; fk++) {
        var apiField = fields[fk].apiField;
        var val = parseInt(inputs[apiField].value, 10);
        if (val > 0) {
          payload[apiField] = val;
        }
      }

      // Add daily limit
      var dayVal = parseInt(dayInput.value, 10);
      if (dayVal > 0) {
        payload.max_calls_per_day = dayVal;
      }

      // Always send tool_limits (even empty) so the backend replaces them atomically
      payload.tool_limits = toolLimits;

      saveBtn.disabled = true;
      saveBtn.textContent = 'Saving...';

      SG.api.put('/v1/quotas/' + encodeURIComponent(identity.id), payload).then(function (result) {
        // Update local quotaMap
        quotaMap[identity.id] = result || payload;
        if (!quotaMap[identity.id].identity_id) {
          quotaMap[identity.id].identity_id = identity.id;
        }
        SG.modal.close();
        SG.toast.show('Quota saved', 'success');
        renderIdentitiesTable();
      }).catch(function (err) {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Save';
        SG.toast.show(err.message || 'Failed to save quota', 'error');
      });
    });
  }

  // -- Add Identity modal -----------------------------------------------------

  function openAddIdentityModal() {
    var form = mk('form', '');
    form.addEventListener('submit', function (e) { e.preventDefault(); });

    // Name field
    var nameGroup = mk('div', 'form-group');
    var nameLabel = mk('label', 'form-label');
    nameLabel.textContent = 'Name';
    nameGroup.appendChild(nameLabel);
    var nameInput = mk('input', 'form-input', {
      type: 'text',
      placeholder: 'e.g. developer-team',
      required: 'required'
    });
    nameGroup.appendChild(nameInput);
    var nameHelp = mk('span', 'form-help');
    nameHelp.textContent = 'A unique name for this identity';
    nameGroup.appendChild(nameHelp);
    form.appendChild(nameGroup);

    // Roles field
    var rolesGroup = mk('div', 'form-group');
    var rolesLabel = mk('label', 'form-label');
    rolesLabel.textContent = 'Roles';
    rolesGroup.appendChild(rolesLabel);
    var rolesTextarea = mk('textarea', 'form-input', {
      placeholder: 'admin\nuser\nread-only\ndeveloper\nauditor',
      rows: '4'
    });
    rolesGroup.appendChild(rolesTextarea);
    var rolesHelp = mk('span', 'form-help');
    rolesHelp.textContent = 'One role per line. Valid roles: admin, user, read-only, developer, auditor';
    rolesGroup.appendChild(rolesHelp);
    // Quick-add role chips
    var validRoles = ['admin', 'user', 'read-only', 'developer', 'auditor'];
    var roleChipsWrap = mk('div', '', { style: 'display:flex;flex-wrap:wrap;gap:var(--space-1);margin-top:var(--space-1)' });
    for (var vri = 0; vri < validRoles.length; vri++) {
      (function(role) {
        var chip = mk('button', 'btn btn-sm', { type: 'button', style: 'font-size:var(--text-xs);padding:2px 8px' });
        chip.textContent = '+ ' + role;
        chip.addEventListener('click', function() {
          var current = rolesTextarea.value.trim();
          var lines = current ? current.split('\n').map(function(l) { return l.trim(); }).filter(Boolean) : [];
          if (lines.indexOf(role) === -1) {
            lines.push(role);
            rolesTextarea.value = lines.join('\n');
          }
        });
        roleChipsWrap.appendChild(chip);
      })(validRoles[vri]);
    }
    rolesGroup.appendChild(roleChipsWrap);
    form.appendChild(rolesGroup);

    // Footer with buttons
    var footer = mk('div', '', { style: 'display: contents;' });
    var cancelBtn = mk('button', 'btn btn-secondary');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.type = 'button';
    cancelBtn.addEventListener('click', function () {
      SG.modal.close();
    });
    footer.appendChild(cancelBtn);

    var submitBtn = mk('button', 'btn btn-primary');
    submitBtn.textContent = 'Add Identity';
    submitBtn.type = 'submit';
    footer.appendChild(submitBtn);

    SG.modal.open({
      title: 'Add Identity',
      body: form,
      footer: footer,
      width: '480px'
    });

    // Handle form submission
    submitBtn.addEventListener('click', function () {
      var name = nameInput.value.trim();
      if (!name) {
        nameInput.focus();
        return;
      }

      var rolesArray = parseRoles(rolesTextarea.value);

      submitBtn.disabled = true;
      submitBtn.textContent = 'Adding...';

      SG.api.post('/identities', {
        name: name,
        roles: rolesArray
      }).then(function () {
        SG.modal.close();
        SG.toast.show('Identity added', 'success');

        loadData();
      }).catch(function (err) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Add Identity';
        SG.toast.show(err.message || 'Failed to add identity', 'error');
      });
    });

    // Focus name input
    setTimeout(function () { nameInput.focus(); }, 100);
  }

  // -- Edit Identity modal ----------------------------------------------------

  function openEditIdentityModal(identity) {
    var form = mk('form', '');
    form.addEventListener('submit', function (e) { e.preventDefault(); });

    // Name field
    var nameGroup = mk('div', 'form-group');
    var nameLabel = mk('label', 'form-label');
    nameLabel.textContent = 'Name';
    nameGroup.appendChild(nameLabel);
    var nameInput = mk('input', 'form-input', {
      type: 'text',
      placeholder: 'e.g. developer-team',
      required: 'required'
    });
    nameInput.value = identity.name || '';
    if (identity.read_only) {
      nameInput.disabled = true;
    }
    nameGroup.appendChild(nameInput);
    form.appendChild(nameGroup);

    // Roles field
    var rolesGroup = mk('div', 'form-group');
    var rolesLabel = mk('label', 'form-label');
    rolesLabel.textContent = 'Roles';
    rolesGroup.appendChild(rolesLabel);
    var rolesTextarea = mk('textarea', 'form-input', {
      placeholder: 'admin\nuser\nread-only\ndeveloper\nauditor',
      rows: '4'
    });
    rolesTextarea.value = (identity.roles || []).join('\n');
    rolesGroup.appendChild(rolesTextarea);
    var rolesHelp = mk('span', 'form-help');
    rolesHelp.textContent = 'One role per line. Valid roles: admin, user, read-only, developer, auditor';
    rolesGroup.appendChild(rolesHelp);
    // Quick-add role chips
    var validRoles2 = ['admin', 'user', 'read-only', 'developer', 'auditor'];
    var roleChipsWrap2 = mk('div', '', { style: 'display:flex;flex-wrap:wrap;gap:var(--space-1);margin-top:var(--space-1)' });
    for (var vri2 = 0; vri2 < validRoles2.length; vri2++) {
      (function(role) {
        var chip = mk('button', 'btn btn-sm', { type: 'button', style: 'font-size:var(--text-xs);padding:2px 8px' });
        chip.textContent = '+ ' + role;
        chip.addEventListener('click', function() {
          var current = rolesTextarea.value.trim();
          var lines = current ? current.split('\n').map(function(l) { return l.trim(); }).filter(Boolean) : [];
          if (lines.indexOf(role) === -1) {
            lines.push(role);
            rolesTextarea.value = lines.join('\n');
          }
        });
        roleChipsWrap2.appendChild(chip);
      })(validRoles2[vri2]);
    }
    rolesGroup.appendChild(roleChipsWrap2);
    form.appendChild(rolesGroup);

    // Footer with buttons
    var footer = mk('div', '', { style: 'display: contents;' });
    var cancelBtn = mk('button', 'btn btn-secondary');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.type = 'button';
    cancelBtn.addEventListener('click', function () {
      SG.modal.close();
    });
    footer.appendChild(cancelBtn);

    var submitBtn = mk('button', 'btn btn-primary');
    submitBtn.textContent = 'Save Changes';
    submitBtn.type = 'submit';
    footer.appendChild(submitBtn);

    SG.modal.open({
      title: 'Edit Identity',
      body: form,
      footer: footer,
      width: '480px'
    });

    // Handle form submission
    submitBtn.addEventListener('click', function () {
      var name = nameInput.value.trim();
      if (!name) {
        nameInput.focus();
        return;
      }

      var rolesArray = parseRoles(rolesTextarea.value);

      submitBtn.disabled = true;
      submitBtn.textContent = 'Saving...';

      SG.api.put('/identities/' + encodeURIComponent(identity.id), {
        name: name,
        roles: rolesArray
      }).then(function () {
        SG.modal.close();
        SG.toast.show('Identity updated', 'success');
        loadData();
      }).catch(function (err) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Save Changes';
        SG.toast.show(err.message || 'Failed to update identity', 'error');
      });
    });

    // Focus name input
    setTimeout(function () { nameInput.focus(); }, 100);
  }

  // -- Delete Identity (optimistic) -------------------------------------------

  function deleteIdentity(identityId, identityName) {
    SG.modal.confirm({
      title: 'Delete identity "' + identityName + '"?',
      message: 'This will also delete all API keys associated with this identity. This action cannot be undone.',
      confirmText: 'Delete',
      confirmClass: 'btn-danger',
      onConfirm: function () {
        // Find the row in the identities table for animation
        var container = document.getElementById('identities-table-container');
        var rows = container ? container.querySelectorAll('tbody tr') : [];
        var targetRow = null;
        for (var r = 0; r < rows.length; r++) {
          // Match the identity row by checking its data or position
          if (identities[r] && identities[r].id === identityId) {
            targetRow = rows[r];
            break;
          }
        }

        var optimisticFn = function () {
          // Cache the identity data and row HTML for rollback
          var previousIdentities = identities.slice();
          var previousHtml = targetRow ? targetRow.outerHTML : null;
          var rowParent = targetRow ? targetRow.parentNode : null;
          var nextSibling = targetRow ? targetRow.nextSibling : null;

          // Animate the row out
          if (targetRow) {
            targetRow.style.transition = 'opacity 200ms ease, transform 200ms ease';
            targetRow.style.opacity = '0';
            targetRow.style.transform = 'translateX(-20px)';
            setTimeout(function () {
              if (targetRow.parentNode) targetRow.style.display = 'none';
            }, 200);
          }

          return {
            previousIdentities: previousIdentities,
            previousHtml: previousHtml,
            rowParent: rowParent,
            nextSibling: nextSibling,
            targetRow: targetRow
          };
        };

        var rollbackData;
        try {
          rollbackData = optimisticFn();
        } catch (e) {
          SG.toast.show('Failed to delete identity', 'error');
          return;
        }

        // Fire the real API call
        SG.api.del('/identities/' + encodeURIComponent(identityId)).then(function () {
          // Success — fully remove row and refresh data
          if (rollbackData.targetRow && rollbackData.targetRow.parentNode) {
            rollbackData.targetRow.parentNode.removeChild(rollbackData.targetRow);
          }
          SG.toast.show('Identity deleted', 'success');
          loadData();
        }).catch(function (err) {
          // Rollback — restore the row
          if (rollbackData.targetRow) {
            rollbackData.targetRow.style.display = '';
            rollbackData.targetRow.style.opacity = '1';
            rollbackData.targetRow.style.transform = 'translateX(0)';
          }
          SG.toast.show('Delete failed: ' + (err.message || 'Unknown error'), 'error');
        });
      }
    });
  }

  // -- Parse roles helper -----------------------------------------------------

  function parseRoles(text) {
    if (!text) return [];
    return text.split('\n')
      .map(function (line) { return line.trim(); })
      .filter(function (line) { return line.length > 0; });
  }

  // -- Data loading -----------------------------------------------------------

  function loadData() {
    Promise.all([
      SG.api.get('/keys'),
      SG.api.get('/identities'),
      SG.api.get('/v1/quotas')
    ]).then(function (results) {
      keys = results[0] || [];
      identities = results[1] || [];
      var quotas = results[2] || [];

      // Build identity map for name resolution
      identityMap = {};
      for (var i = 0; i < identities.length; i++) {
        identityMap[identities[i].id] = identities[i].name;
      }

      // Build quota map keyed by identity_id
      quotaMap = {};
      for (var q = 0; q < quotas.length; q++) {
        if (quotas[q].identity_id) {
          quotaMap[quotas[q].identity_id] = quotas[q];
        }
      }

      renderKeysTable();
      renderIdentitiesTable();
    }).catch(function (err) {
      SG.toast.show('Failed to load data: ' + (err.message || 'Unknown error'), 'error');
    });
  }

  // -- Create Key modal -------------------------------------------------------

  function openCreateKeyModal() {
    var form = mk('form', '');
    form.addEventListener('submit', function (e) { e.preventDefault(); });

    // Name field
    var nameGroup = mk('div', 'form-group');
    var nameLabel = mk('label', 'form-label');
    nameLabel.textContent = 'Name';
    nameGroup.appendChild(nameLabel);
    var nameInput = mk('input', 'form-input', {
      type: 'text',
      placeholder: 'e.g. my-agent',
      required: 'required'
    });
    nameGroup.appendChild(nameInput);
    var nameHelp = mk('span', 'form-help');
    nameHelp.textContent = 'A descriptive name for this API key';
    nameGroup.appendChild(nameHelp);
    form.appendChild(nameGroup);

    // Identity field
    var identityGroup = mk('div', 'form-group');
    var identityLabel = mk('label', 'form-label');
    identityLabel.textContent = 'Identity';
    identityGroup.appendChild(identityLabel);
    var identitySelect = mk('select', 'form-select', { required: 'required' });

    var placeholder = mk('option', '', { value: '', disabled: 'disabled', selected: 'selected' });
    placeholder.textContent = 'Select an identity...';
    identitySelect.appendChild(placeholder);

    for (var i = 0; i < identities.length; i++) {
      var opt = mk('option', '', { value: identities[i].id });
      opt.textContent = identities[i].name;
      identitySelect.appendChild(opt);
    }

    identityGroup.appendChild(identitySelect);
    var identityHelp = mk('span', 'form-help');
    identityHelp.textContent = 'The identity this key will authenticate as';
    identityGroup.appendChild(identityHelp);
    form.appendChild(identityGroup);

    // Footer with buttons
    var footer = mk('div', '', { style: 'display: contents;' });
    var cancelBtn = mk('button', 'btn btn-secondary');
    cancelBtn.textContent = 'Cancel';
    cancelBtn.type = 'button';
    cancelBtn.addEventListener('click', function () {
      SG.modal.close();
    });
    footer.appendChild(cancelBtn);

    var submitBtn = mk('button', 'btn btn-primary');
    submitBtn.textContent = 'Create Key';
    submitBtn.type = 'submit';
    footer.appendChild(submitBtn);

    var modalBody = SG.modal.open({
      title: 'Create API Key',
      body: form,
      footer: footer,
      width: '480px'
    });

    // Handle form submission
    submitBtn.addEventListener('click', function () {
      var name = nameInput.value.trim();
      var identityId = identitySelect.value;

      if (!name) {
        nameInput.focus();
        return;
      }
      if (!identityId) {
        identitySelect.focus();
        return;
      }

      submitBtn.disabled = true;
      submitBtn.textContent = 'Creating...';

      SG.api.post('/keys', {
        name: name,
        identity_id: identityId
      }).then(function (result) {

        showKeyResult(modalBody, result);
      }).catch(function (err) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create Key';
        SG.toast.show(err.message || 'Failed to create key', 'error');
      });
    });

    // Focus name input
    setTimeout(function () { nameInput.focus(); }, 100);
  }

  // -- One-time key display ---------------------------------------------------

  function showKeyResult(modalBody, result) {
    modalBody.innerHTML = '';

    // Remove the modal footer (we replace it with a Done button inside body)
    var modal = SG.modal.currentModal || document.querySelector('.modal-backdrop .modal');
    if (modal) {
      var existingFooter = modal.querySelector('.modal-footer');
      if (existingFooter) {
        existingFooter.parentNode.removeChild(existingFooter);
      }
    }

    // Warning
    var warning = mk('div', 'key-display-warning');
    warning.innerHTML = SG.icon('alertTriangle', 16) + ' ';
    var warningText = mk('span', '');
    warningText.textContent = 'Copy this key now. It will not be shown again.';
    warning.appendChild(warningText);
    modalBody.appendChild(warning);

    // Key display (click to copy)
    var keyBlock = mk('div', 'key-display');
    keyBlock.textContent = result.cleartext_key || '';
    if (SG.clipboard) {
      SG.clipboard.makeCopyable(keyBlock, result.cleartext_key || '');
    }
    modalBody.appendChild(keyBlock);

    // Copy + Done row
    var actionRow = mk('div', 'key-result-footer');

    var copyBtn = mk('button', 'key-copy-btn', { 'aria-label': 'Copy API key to clipboard' });
    copyBtn.innerHTML = SG.icon('copy', 14) + ' ';
    var copyLabel = mk('span', '');
    copyLabel.textContent = 'Copy to Clipboard';
    copyBtn.appendChild(copyLabel);

    copyBtn.addEventListener('click', function () {
      var keyText = result.cleartext_key || '';
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(keyText).then(function () {
          copyBtn.classList.add('copied');
          copyLabel.textContent = 'Copied!';
          setTimeout(function () {
            copyBtn.classList.remove('copied');
            copyLabel.textContent = 'Copy to Clipboard';
          }, 2000);
        }).catch(function () {
          fallbackCopy(keyText, copyBtn, copyLabel);
        });
      } else {
        fallbackCopy(keyText, copyBtn, copyLabel);
      }
    });
    actionRow.appendChild(copyBtn);

    var doneBtn = mk('button', 'btn btn-secondary');
    doneBtn.textContent = 'Done';
    doneBtn.addEventListener('click', function () {
      SG.modal.close();
      loadData();
    });
    actionRow.appendChild(doneBtn);

    modalBody.appendChild(actionRow);

    // Info about created key
    var info = mk('div', '', {
      style: 'margin-top: var(--space-4); padding-top: var(--space-3); border-top: 1px solid var(--border);'
    });
    var infoName = mk('div', '', { style: 'font-size: var(--text-sm); color: var(--text-secondary);' });
    infoName.textContent = 'Key name: ' + (result.name || '-');
    info.appendChild(infoName);

    var infoId = mk('div', '', {
      style: 'font-size: var(--text-xs); color: var(--text-muted); margin-top: var(--space-1); font-family: var(--font-mono);'
    });
    infoId.textContent = 'ID: ' + (result.id || '-');
    info.appendChild(infoId);

    modalBody.appendChild(info);
  }

  function fallbackCopy(text, btn, label) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.cssText = 'position:fixed;left:-9999px;top:-9999px;';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      btn.classList.add('copied');
      label.textContent = 'Copied!';
      setTimeout(function () {
        btn.classList.remove('copied');
        label.textContent = 'Copy to Clipboard';
      }, 2000);
    } catch (e) {
      SG.toast.show('Failed to copy. Please select and copy manually.', 'warning');
    }
    document.body.removeChild(textarea);
  }

  function fallbackConfigCopy(text, btn, label) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.cssText = 'position:fixed;left:-9999px;top:-9999px;';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      btn.classList.add('copied');
      label.textContent = 'Copied!';
      SG.toast.show('Copied to clipboard', 'success');
      setTimeout(function () {
        btn.classList.remove('copied');
        label.textContent = 'Copy';
      }, 2000);
    } catch (e) {
      SG.toast.show('Failed to copy. Please select and copy manually.', 'warning');
    }
    document.body.removeChild(textarea);
  }

  // -- Revoke key -------------------------------------------------------------

  function revokeKey(keyId, keyName) {
    SG.modal.confirm({
      title: 'Revoke API key "' + keyName + '"?',
      message: 'This action cannot be undone. Any client using this key will lose access.',
      confirmText: 'Revoke',
      confirmClass: 'btn-danger',
      onConfirm: function () {
        SG.api.del('/keys/' + encodeURIComponent(keyId)).then(function () {
          SG.toast.show('Key revoked', 'success');
  
          loadData();
        }).catch(function (err) {
          SG.toast.show(err.message || 'Failed to revoke key', 'error');
        });
      }
    });
  }

  // -- Lifecycle --------------------------------------------------------------

  function render(container) {
    cleanup();
    injectStyles();
    buildPage(container);
    loadData();
  }

  function cleanup() {
    keys = [];
    identities = [];
    identityMap = {};
    quotaMap = {};
    upstreamsList = [];
    identitiesCollapsed = false;
  }

  // -- Registration -----------------------------------------------------------

  SG.router.register('access', render);
  SG.router.registerCleanup('access', cleanup);
})();
