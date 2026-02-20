/**
 * agents.js -- Agents page for SentinelGate admin UI.
 *
 * Displays running agent processes (from GET /admin/api/agents) and
 * environment variables for manual agent setup (from GET /admin/api/agents/env).
 *
 * Data sources:
 *   GET /admin/api/agents      -> running agent list (polled every 5s)
 *   GET /admin/api/agents/env  -> env vars for manual setup
 *
 * Design features:
 *   - Running agents table with status dots (green/gray)
 *   - Empty state message when no agents running
 *   - Manual setup env vars table with copy buttons
 *   - Polls agents list every 5 seconds
 *   - All user data rendered via textContent (XSS-safe)
 *
 * Requirements:
 *   UI-05  Agents section with running agents and env var display
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // -- State ------------------------------------------------------------------

  var styleInjected = false;
  var pollInterval = null;

  // -- Agents-specific styles -------------------------------------------------

  var AGENTS_CSS = [
    /* Page */
    '.agents-page {',
    '  padding: var(--space-6);',
    '  max-width: 1000px;',
    '}',

    /* Header */
    '.agents-header {',
    '  margin-bottom: var(--space-6);',
    '}',
    '.agents-header h1 {',
    '  font-size: var(--text-2xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0 0 var(--space-1) 0;',
    '  letter-spacing: -0.02em;',
    '}',
    '.agents-header p {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-muted);',
    '  margin: 0;',
    '}',

    /* Section */
    '.agents-section {',
    '  margin-bottom: var(--space-6);',
    '}',
    '.agents-section-title {',
    '  font-size: var(--text-lg);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '  margin: 0 0 var(--space-1) 0;',
    '}',
    '.agents-section-desc {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-muted);',
    '  margin: 0 0 var(--space-4) 0;',
    '}',

    /* Agent table */
    '.agent-table {',
    '  width: 100%;',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  overflow: hidden;',
    '  border-collapse: separate;',
    '  border-spacing: 0;',
    '}',
    '.agent-table th {',
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
    '.agent-row {',
    '  border-bottom: 1px solid var(--border);',
    '}',
    '.agent-row:last-child {',
    '  border-bottom: none;',
    '}',
    '.agent-row td {',
    '  padding: var(--space-3);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  vertical-align: middle;',
    '}',

    /* Status dot */
    '.agent-status-dot {',
    '  display: inline-block;',
    '  width: 8px;',
    '  height: 8px;',
    '  border-radius: var(--radius-full);',
    '  margin-right: var(--space-2);',
    '  vertical-align: middle;',
    '}',
    '.agent-status-dot.running {',
    '  background: var(--success);',
    '}',
    '.agent-status-dot.stopped {',
    '  background: var(--text-muted);',
    '}',

    /* Agent ID */
    '.agent-id {',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  max-width: 120px;',
    '  overflow: hidden;',
    '  text-overflow: ellipsis;',
    '  white-space: nowrap;',
    '}',

    /* Empty state */
    '.agents-empty {',
    '  text-align: center;',
    '  padding: var(--space-8);',
    '  color: var(--text-muted);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  background: var(--bg-surface);',
    '}',
    '.agents-empty-icon {',
    '  color: var(--text-muted);',
    '  margin-bottom: var(--space-3);',
    '}',
    '.agents-empty p {',
    '  margin: 0;',
    '  font-size: var(--text-sm);',
    '}',
    '.agents-empty code {',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-xs);',
    '  background: var(--bg-primary);',
    '  padding: 2px 6px;',
    '  border-radius: var(--radius-sm);',
    '}',

    /* Env var table */
    '.env-table {',
    '  width: 100%;',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  overflow: hidden;',
    '  border-collapse: separate;',
    '  border-spacing: 0;',
    '}',
    '.env-table th {',
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
    '.env-row {',
    '  border-bottom: 1px solid var(--border);',
    '}',
    '.env-row:last-child {',
    '  border-bottom: none;',
    '}',
    '.env-row td {',
    '  padding: var(--space-3);',
    '  font-size: var(--text-sm);',
    '  vertical-align: middle;',
    '}',
    '.env-name {',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-xs);',
    '  color: var(--accent);',
    '  font-weight: var(--font-medium);',
    '}',
    '.env-value {',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-secondary);',
    '}',
    '.env-desc {',
    '  color: var(--text-muted);',
    '}',
    '.env-copy-btn {',
    '  background: var(--bg-secondary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-sm);',
    '  padding: 2px 6px;',
    '  cursor: pointer;',
    '  color: var(--text-muted);',
    '  font-size: var(--text-xs);',
    '  transition: all var(--transition-fast);',
    '  margin-left: var(--space-2);',
    '  vertical-align: middle;',
    '}',
    '.env-copy-btn:hover {',
    '  background: var(--bg-surface);',
    '  color: var(--text-primary);',
    '}'
  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-agents', '');
    s.textContent = AGENTS_CSS;
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

  function formatTime(dateStr) {
    try {
      var d = new Date(dateStr);
      return d.toLocaleString();
    } catch (e) {
      return dateStr;
    }
  }

  // -- Build agents table -----------------------------------------------------

  function buildAgentsTable(agents, wrapper) {
    wrapper.innerHTML = '';

    if (!agents || agents.length === 0) {
      var empty = mk('div', 'agents-empty');
      if (SG.icon) {
        var iconWrap = mk('div', 'agents-empty-icon');
        iconWrap.innerHTML = SG.icon('cpu', 32);
        empty.appendChild(iconWrap);
      }
      var p = mk('p', '');
      p.innerHTML = 'No agents running. Use <code>sentinel-gate run -- &lt;command&gt;</code> to launch an agent.';
      empty.appendChild(p);
      wrapper.appendChild(empty);
      return;
    }

    var table = mk('table', 'agent-table');

    // Header
    var thead = mk('thead', '');
    var headRow = mk('tr', '');
    var cols = ['Status', 'Command', 'Framework', 'Fail Mode', 'Started'];
    for (var c = 0; c < cols.length; c++) {
      var th = mk('th', '');
      th.textContent = cols[c];
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    // Body
    var tbody = mk('tbody', '');
    for (var i = 0; i < agents.length; i++) {
      var agent = agents[i];
      var row = mk('tr', 'agent-row');

      // Status
      var tdStatus = mk('td', '');
      var dot = mk('span', 'agent-status-dot ' + (agent.status || 'stopped'));
      tdStatus.appendChild(dot);
      var statusText = document.createTextNode(agent.status || 'unknown');
      tdStatus.appendChild(statusText);
      row.appendChild(tdStatus);

      // Command
      var tdCmd = mk('td', '');
      var cmdText = agent.command || '';
      if (agent.args && agent.args.length > 0) {
        cmdText += ' ' + agent.args.join(' ');
      }
      tdCmd.textContent = cmdText;
      row.appendChild(tdCmd);

      // Framework
      var tdFw = mk('td', '');
      tdFw.textContent = agent.framework || '-';
      row.appendChild(tdFw);

      // Fail Mode
      var tdFail = mk('td', '');
      tdFail.textContent = agent.fail_mode || '-';
      row.appendChild(tdFail);

      // Started
      var tdStarted = mk('td', '');
      tdStarted.textContent = agent.started_at ? formatTime(agent.started_at) : '-';
      row.appendChild(tdStarted);

      tbody.appendChild(row);
    }
    table.appendChild(tbody);
    wrapper.appendChild(table);
  }

  // -- Build env vars table ---------------------------------------------------

  function buildEnvTable(envVars, wrapper) {
    wrapper.innerHTML = '';

    if (!envVars || envVars.length === 0) {
      return;
    }

    var table = mk('table', 'env-table');

    // Header
    var thead = mk('thead', '');
    var headRow = mk('tr', '');
    var cols = ['Variable', 'Value', 'Description'];
    for (var c = 0; c < cols.length; c++) {
      var th = mk('th', '');
      th.textContent = cols[c];
      headRow.appendChild(th);
    }
    thead.appendChild(headRow);
    table.appendChild(thead);

    // Body
    var tbody = mk('tbody', '');
    for (var i = 0; i < envVars.length; i++) {
      var ev = envVars[i];
      var row = mk('tr', 'env-row');

      // Name
      var tdName = mk('td', 'env-name');
      tdName.textContent = ev.name;
      row.appendChild(tdName);

      // Value with copy button
      var tdValue = mk('td', '');
      var valueSpan = mk('span', 'env-value');
      valueSpan.textContent = ev.value;
      tdValue.appendChild(valueSpan);

      var copyBtn = mk('button', 'env-copy-btn');
      copyBtn.textContent = 'Copy';
      (function (val, btn) {
        btn.addEventListener('click', function () {
          navigator.clipboard.writeText(val).then(function () {
            btn.textContent = 'Copied!';
            setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
          });
        });
      })(ev.value, copyBtn);
      tdValue.appendChild(copyBtn);
      row.appendChild(tdValue);

      // Description
      var tdDesc = mk('td', 'env-desc');
      tdDesc.textContent = ev.description;
      row.appendChild(tdDesc);

      tbody.appendChild(row);
    }
    table.appendChild(tbody);
    wrapper.appendChild(table);
  }

  // -- Load data --------------------------------------------------------------

  function loadAgents(agentWrapper) {
    SG.api.get('/agents').then(function (agents) {
      buildAgentsTable(agents, agentWrapper);
    }).catch(function () {
      buildAgentsTable([], agentWrapper);
    });
  }

  function loadEnvVars(envWrapper) {
    SG.api.get('/agents/env').then(function (data) {
      buildEnvTable(data && data.env_vars ? data.env_vars : [], envWrapper);
    }).catch(function () {
      // Silently fail
    });
  }

  // -- Render page ------------------------------------------------------------

  function render(container) {
    cleanup();
    injectStyles();

    var page = mk('div', 'agents-page');

    // Header
    var header = mk('div', 'agents-header');
    var h1 = mk('h1', '');
    h1.textContent = 'Agents';
    header.appendChild(h1);
    var subtitle = mk('p', '');
    subtitle.textContent = 'Running agent processes and setup';
    header.appendChild(subtitle);
    page.appendChild(header);

    // Section 1: Running Agents
    var runningSection = mk('div', 'agents-section');
    var runTitle = mk('h2', 'agents-section-title');
    runTitle.textContent = 'Running Agents';
    runningSection.appendChild(runTitle);
    var runDesc = mk('p', 'agents-section-desc');
    runDesc.textContent = 'Agents launched via sentinel-gate run are tracked here';
    runningSection.appendChild(runDesc);

    var agentWrapper = mk('div', '');
    runningSection.appendChild(agentWrapper);
    page.appendChild(runningSection);

    // Section 2: Manual Setup
    var setupSection = mk('div', 'agents-section');
    var setupTitle = mk('h2', 'agents-section-title');
    setupTitle.textContent = 'SDK Configuration';
    setupSection.appendChild(setupTitle);
    var setupDesc = mk('p', 'agents-section-desc');
    setupDesc.textContent = 'For developers building custom agents with the SentinelGate SDK. Not needed if you use sentinel-gate run.';
    setupSection.appendChild(setupDesc);

    var envWrapper = mk('div', '');
    setupSection.appendChild(envWrapper);
    page.appendChild(setupSection);

    container.innerHTML = '';
    container.appendChild(page);

    // Load data
    loadAgents(agentWrapper);
    loadEnvVars(envWrapper);

    // Poll agents every 5 seconds
    pollInterval = setInterval(function () {
      loadAgents(agentWrapper);
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
