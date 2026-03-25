/**
 * security.js -- Security page for SentinelGate admin UI.
 *
 * Content Scanning configuration: toggle enable/disable, switch between
 * monitor and enforce modes. Changes take effect immediately and persist
 * to state.json.
 *
 * Data sources:
 *   GET /admin/api/v1/security/content-scanning   -> current config
 *   PUT /admin/api/v1/security/content-scanning   -> update config
 *
 * Design features:
 *   - Enable/disable toggle for content scanning
 *   - Monitor/Enforce mode selector (radio buttons)
 *   - Mode description text explaining each option
 *   - Status badge showing current mode
 *   - Save button with toast feedback
 *   - All user data rendered via textContent (XSS-safe)
 *
 * Requirements:
 *   SECU-UI-01  Content scanning toggle with mode selector
 *   SECU-UI-02  Immediate effect on save (no restart required)
 *   SECU-UI-03  Persist to state.json via admin API
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // -- State ------------------------------------------------------------------

  var styleInjected = false;
  var currentConfig = null;
  var toolSecBaseline = null;
  var toolSecQuarantine = [];
  var toolSecAvailable = true;
  var inputScanConfig = null;
  var inputScanAvailable = true;

  // -- Security-specific styles -----------------------------------------------

  var SECURITY_CSS = [
    /* Layout */
    '.security-header {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  margin-bottom: var(--space-6);',
    '}',
    '.security-header h1 {',
    '  font-size: var(--text-2xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0;',
    '  letter-spacing: -0.02em;',
    '}',
    '.security-header-desc {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-muted);',
    '  margin: 0;',
    '  margin-top: var(--space-1);',
    '}',

    /* Section card */
    '.security-section {',
    '  margin-bottom: var(--space-6);',
    '}',

    /* Toggle switch */
    '.toggle-row {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  padding: var(--space-4);',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.toggle-label {',
    '  display: flex;',
    '  flex-direction: column;',
    '  gap: var(--space-1);',
    '}',
    '.toggle-label-title {',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '}',
    '.toggle-label-desc {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '}',

    /* Toggle switch element */
    '.toggle-switch {',
    '  position: relative;',
    '  width: 44px;',
    '  height: 24px;',
    '  flex-shrink: 0;',
    '}',
    '.toggle-switch input {',
    '  opacity: 0;',
    '  width: 0;',
    '  height: 0;',
    '}',
    '.toggle-slider {',
    '  position: absolute;',
    '  cursor: pointer;',
    '  top: 0; left: 0; right: 0; bottom: 0;',
    '  background-color: var(--bg-elevated);',
    '  border: 1px solid var(--border);',
    '  transition: all var(--transition-fast);',
    '  border-radius: 12px;',
    '}',
    '.toggle-slider:before {',
    '  position: absolute;',
    '  content: "";',
    '  height: 18px;',
    '  width: 18px;',
    '  left: 2px;',
    '  bottom: 2px;',
    '  background-color: var(--text-muted);',
    '  transition: all var(--transition-fast);',
    '  border-radius: 50%;',
    '}',
    '.toggle-switch input:checked + .toggle-slider {',
    '  background-color: var(--accent);',
    '  border-color: var(--accent);',
    '}',
    '.toggle-switch input:checked + .toggle-slider:before {',
    '  background-color: var(--text-inverse);',
    '  transform: translateX(20px);',
    '}',

    /* Mode selector */
    '.mode-selector {',
    '  display: flex;',
    '  flex-direction: column;',
    '  gap: var(--space-3);',
    '  padding: var(--space-4);',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.mode-selector-title {',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '  margin-bottom: var(--space-1);',
    '}',
    '.mode-option {',
    '  display: flex;',
    '  align-items: flex-start;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '}',
    '.mode-option:hover {',
    '  border-color: var(--border-hover);',
    '  background: var(--bg-elevated);',
    '}',
    '.mode-option.selected {',
    '  border-color: var(--accent);',
    '  background: var(--accent-subtle);',
    '}',
    '.mode-option input[type="radio"] {',
    '  margin-top: 2px;',
    '  flex-shrink: 0;',
    '  accent-color: var(--accent);',
    '}',
    '.mode-option-text {',
    '  display: flex;',
    '  flex-direction: column;',
    '  gap: 2px;',
    '}',
    '.mode-option-label {',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-primary);',
    '}',
    '.mode-option-desc {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  line-height: 1.4;',
    '}',

    /* Status badge */
    '.security-status {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  padding: var(--space-1) var(--space-3);',
    '  border-radius: var(--radius-full);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-medium);',
    '}',
    '.security-status-monitor {',
    '  background: rgba(34, 197, 94, 0.1);',
    '  color: var(--success);',
    '}',
    '.security-status-enforce {',
    '  background: rgba(251, 146, 60, 0.1);',
    '  color: var(--warning);',
    '}',
    '.security-status-disabled {',
    '  background: var(--bg-elevated);',
    '  color: var(--text-muted);',
    '}',

    /* Save button row */
    '.security-actions {',
    '  display: flex;',
    '  justify-content: flex-end;',
    '  gap: var(--space-3);',
    '  padding-top: var(--space-4);',
    '  border-top: 1px solid var(--border);',
    '}',

    /* Card header with action button */
    '.card-header-actions {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '}',

    /* Form group used in modals */
    '.ob-form-group {',
    '  margin-bottom: var(--space-3);',
    '}',
    '.ob-form-group label {',
    '  display: block;',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-secondary);',
    '  margin-bottom: var(--space-1);',
    '}',
    '.ob-form-group input[type="text"], .ob-form-group input[type="number"], .ob-form-group textarea, .ob-form-group select {',
    '  width: 100%;',
    '  box-sizing: border-box;',
    '  padding: var(--space-2) var(--space-3);',
    '  background: var(--bg-primary);',
    '  color: var(--text-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-sm);',
    '  line-height: 1.5;',
    '}',
    '.ob-form-group input::placeholder, .ob-form-group textarea::placeholder {',
    '  color: var(--text-muted);',
    '}',
    '.ob-form-group input:focus, .ob-form-group textarea:focus, .ob-form-group select:focus {',
    '  border-color: var(--accent);',
    '  outline: none;',
    '  box-shadow: 0 0 0 3px var(--accent-ring);',
    '}',
    '.ob-form-row {',
    '  display: flex;',
    '  gap: var(--space-3);',
    '}',
    '.ob-form-row .ob-form-group {',
    '  flex: 1;',
    '}',

    /* Tool Security section */
    '.toolsec-action-bar {',
    '  display: flex;',
    '  gap: var(--space-3);',
    '  flex-wrap: wrap;',
    '  margin-bottom: var(--space-4);',
    '}',
    '.toolsec-info {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-secondary);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.toolsec-result-box {',
    '  padding: var(--space-3) var(--space-4);',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.toolsec-result-box.success {',
    '  background: rgba(34, 197, 94, 0.08);',
    '  border-color: var(--success);',
    '}',
    '.toolsec-result-box.warning {',
    '  background: rgba(251, 146, 60, 0.08);',
    '  border-color: var(--warning);',
    '}',
    '.toolsec-baseline-list {',
    '  margin-top: var(--space-3);',
    '}',
    '.toolsec-baseline-item {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  padding: var(--space-2) var(--space-3);',
    '  border-bottom: 1px solid var(--border);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  font-family: var(--font-mono);',
    '}',
    '.toolsec-baseline-item:last-child {',
    '  border-bottom: none;',
    '}',
    '.toolsec-drift-item {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  border-bottom: 1px solid var(--border);',
    '}',
    '.toolsec-drift-item:last-child {',
    '  border-bottom: none;',
    '}',
    '.toolsec-drift-type {',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-medium);',
    '  padding: 1px 8px;',
    '  border-radius: var(--radius-full);',
    '}',
    '.toolsec-drift-added {',
    '  background: rgba(34, 197, 94, 0.1);',
    '  color: var(--success);',
    '}',
    '.toolsec-drift-removed {',
    '  background: rgba(239, 68, 68, 0.1);',
    '  color: var(--danger);',
    '}',
    '.toolsec-drift-changed {',
    '  background: rgba(251, 146, 60, 0.1);',
    '  color: var(--warning);',
    '}',
    '.toolsec-quarantine-row {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  padding: var(--space-3) var(--space-4);',
    '  border-bottom: 1px solid var(--border);',
    '  transition: background var(--transition-fast);',
    '}',
    '.toolsec-quarantine-row:last-child {',
    '  border-bottom: none;',
    '}',
    '.toolsec-quarantine-row:hover {',
    '  background: var(--bg-elevated);',
    '}',
    '.toolsec-quarantine-name {',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-primary);',
    '  font-family: var(--font-mono);',
    '}',
    '.toolsec-quarantine-add {',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  align-items: center;',
    '  padding: var(--space-3) var(--space-4);',
    '}',
    '.toolsec-quarantine-add input {',
    '  flex: 1;',
    '  padding: var(--space-2) var(--space-3);',
    '  background: var(--bg-primary);',
    '  color: var(--text-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-sm);',
    '  line-height: 1.5;',
    '}',
    '.toolsec-quarantine-add input::placeholder {',
    '  color: var(--text-muted);',
    '}',
    '.toolsec-quarantine-add input:focus {',
    '  border-color: var(--accent);',
    '  outline: none;',
    '  box-shadow: 0 0 0 3px var(--accent-ring);',
    '}',
    '.toolsec-collapsible-header {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  cursor: pointer;',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--accent);',
    '  margin-top: var(--space-2);',
    '  user-select: none;',
    '}',
    '.toolsec-collapsible-header:hover {',
    '  text-decoration: underline;',
    '}',
  ].join('\n');

  // -- Helpers ----------------------------------------------------------------

  function injectStyles() {
    if (styleInjected) return;
    var style = document.createElement('style');
    style.textContent = SECURITY_CSS;
    document.head.appendChild(style);
    styleInjected = true;
  }

  function statusBadge(config) {
    if (!config.enabled) {
      return '<span class="security-status security-status-disabled">Content Scanning: Disabled</span>';
    }
    if (config.mode === 'enforce') {
      return '<span class="security-status security-status-enforce">Enforce</span>';
    }
    return '<span class="security-status security-status-monitor">Monitor</span>';
  }

  function esc(text) {
    var el = document.createElement('span');
    el.textContent = text || '';
    return el.innerHTML;
  }

  // -- Load data --------------------------------------------------------------

  function loadConfig() {
    return SG.api.get('/v1/security/content-scanning').then(function (data) {
      currentConfig = data;
      return data;
    }).catch(function (err) {
      if (err.status === 503) {
        currentConfig = null;
        return null;
      }
      throw err;
    });
  }

  function loadInputScanConfig() {
    return SG.api.get('/v1/security/input-scanning').then(function (data) {
      inputScanConfig = data;
      inputScanAvailable = true;
      return data;
    }).catch(function (err) {
      if (err.status === 503) {
        inputScanAvailable = false;
        inputScanConfig = null;
        return null;
      }
      throw err;
    });
  }

  function loadToolSecBaseline() {
    return SG.api.get('/v1/tools/baseline').then(function (data) {
      toolSecBaseline = data;
      toolSecAvailable = true;
      return data;
    }).catch(function (err) {
      if (err.status === 503) {
        toolSecAvailable = false;
        toolSecBaseline = null;
        return null;
      }
      toolSecBaseline = null;
      return null;
    });
  }

  function loadToolSecQuarantine() {
    return SG.api.get('/v1/tools/quarantine').then(function (data) {
      toolSecQuarantine = (data && data.quarantined_tools) ? data.quarantined_tools : [];
      toolSecAvailable = true;
      return toolSecQuarantine;
    }).catch(function (err) {
      if (err.status === 503) {
        toolSecAvailable = false;
        toolSecQuarantine = [];
        return [];
      }
      toolSecQuarantine = [];
      return [];
    });
  }

  function addSecHelpBtn(el) {
    var hdr = el.querySelector('.security-header');
    if (hdr && !hdr.querySelector('.help-btn')) {
      var btn = document.createElement('button');
      btn.type = 'button'; btn.className = 'help-btn'; btn.textContent = '?';
      btn.addEventListener('click', function() { if (SG.help) SG.help.toggle('security'); });
      hdr.appendChild(btn);
    }
  }

  // -- Main render ------------------------------------------------------------

  function render(container) {
    injectStyles();

    container.innerHTML =
      '<div class="security-header"><div><h1>Security</h1>' +
      '<p class="page-subtitle">Security scanning, tool integrity, and threat detection.</p></div></div>' +
      '<div class="card"><div class="card-body" style="padding: var(--space-6);"><p style="color: var(--text-muted);">Loading...</p></div></div>';

    Promise.all([loadConfig(), loadToolSecBaseline(), loadToolSecQuarantine(), loadInputScanConfig()]).then(function (results) {
      renderPage(container, results[0]);
    }).catch(function (err) {
      container.innerHTML =
        '<div class="security-header"><div><h1>Security</h1>' +
        '<p class="page-subtitle">Security scanning, tool integrity, and threat detection.</p></div></div>' +
        '<div class="card"><div class="card-body" style="padding: var(--space-6);">' +
        '<p style="color: var(--danger);">Failed to load security configuration: ' + esc(err.message || 'Unknown error') + '</p></div></div>';
      addSecHelpBtn(container);
    });
  }

  function renderPage(container, config) {
    var shieldIcon = SG.icon ? SG.icon('shield', 20) : '';

    // If scanning is not available (503), show info message
    if (!config) {
      container.innerHTML =
        '<div class="security-header"><div><h1>Security</h1>' +
        '<p class="page-subtitle">Security scanning, tool integrity, and threat detection.</p></div></div>' +
        '<div class="card"><div class="card-header"><h3 class="card-title">' + shieldIcon + ' Content Scanning</h3></div>' +
        '<div class="card-body" style="padding: var(--space-6);">' +
        '<p style="color: var(--text-muted);">Content scanning is not available. The response scan interceptor may not be configured.</p></div></div>' +
        '<div id="toolsec-section"></div>';
      addSecHelpBtn(container);
      renderToolSecuritySection(document.getElementById('toolsec-section'));
      return;
    }

    var enabled = config.enabled;
    var mode = config.mode || 'monitor';

    container.innerHTML =
      '<div class="security-header">' +
        '<div>' +
          '<h1>Security</h1>' +
          '<p class="page-subtitle">Security scanning, tool integrity, and threat detection.</p>' +
        '</div>' +
        '<div id="security-status-badge">' + statusBadge(config) + '</div>' +
      '</div>' +

      '<div class="card security-section">' +
        '<div class="card-header">' +
          '<h3 class="card-title">' + shieldIcon + ' Content Scanning</h3>' +
        '</div>' +
        '<div class="card-body" style="padding: var(--space-6);">' +

          '<p style="font-size: var(--text-sm); color: var(--text-secondary); margin-bottom: var(--space-4);">' +
            'Scan tool responses for prompt injection patterns before forwarding to agents. ' +
            'Detects system prompt overrides, role hijacking, instruction injection, and other attack patterns.' +
          '</p>' +

          /* Enable toggle */
          '<div class="toggle-row">' +
            '<div class="toggle-label">' +
              '<span class="toggle-label-title">Enable Content Scanning</span>' +
              '<span class="toggle-label-desc">When enabled, all tool responses are scanned for prompt injection patterns.</span>' +
            '</div>' +
            '<label class="toggle-switch">' +
              '<input type="checkbox" id="scan-enabled" ' + (enabled ? 'checked' : '') + '>' +
              '<span class="toggle-slider"></span>' +
            '</label>' +
          '</div>' +

          /* Mode selector */
          '<div class="mode-selector" id="mode-selector">' +
            '<div class="mode-selector-title">Scanning Mode</div>' +

            '<label class="mode-option' + (mode === 'monitor' ? ' selected' : '') + '" id="mode-monitor">' +
              '<input type="radio" name="scan-mode" value="monitor" ' + (mode === 'monitor' ? 'checked' : '') + '>' +
              '<div class="mode-option-text">' +
                '<span class="mode-option-label">Monitor</span>' +
                '<span class="mode-option-desc">Log detections without blocking responses. Recommended for initial deployment to evaluate detection accuracy before enforcing.</span>' +
              '</div>' +
            '</label>' +

            '<label class="mode-option' + (mode === 'enforce' ? ' selected' : '') + '" id="mode-enforce">' +
              '<input type="radio" name="scan-mode" value="enforce" ' + (mode === 'enforce' ? 'checked' : '') + '>' +
              '<div class="mode-option-text">' +
                '<span class="mode-option-label">Enforce</span>' +
                '<span class="mode-option-desc">Block responses containing detected prompt injection patterns. Use after validating detections in monitor mode.</span>' +
              '</div>' +
            '</label>' +
          '</div>' +

          /* Save button */
          '<div class="security-actions">' +
            '<button class="btn btn-primary" id="save-scan-config">Save Changes</button>' +
          '</div>' +

          /* Recent Detections stat */
          '<div id="recent-detections-stat" style="margin-top:var(--space-4);padding:var(--space-3);background:var(--bg-elevated);border:1px solid var(--border);border-radius:var(--radius-md);font-size:var(--text-sm);color:var(--text-secondary);">' +
            'Loading recent detections\u2026' +
          '</div>' +

          /* Detection Patterns (read-only) */
          '<details style="margin-top:var(--space-4)">' +
            '<summary style="cursor:pointer;font-weight:var(--font-semibold);font-size:var(--text-sm);color:var(--text-secondary)">Detection Patterns (11)</summary>' +
            '<div style="margin-top:var(--space-2);font-size:var(--text-sm);color:var(--text-secondary)">' +
              '<ul style="margin:0;padding-left:var(--space-4)">' +
                '<li><strong>System Prompt Override</strong> — Detects "ignore/disregard instructions" patterns</li>' +
                '<li><strong>Role Hijacking</strong> — Detects "you are now a..." attempts</li>' +
                '<li><strong>Instruction Injection</strong> — Detects "new instructions:" headers</li>' +
                '<li><strong>System Tag Injection</strong> — Detects &lt;system&gt;, &lt;assistant&gt; tags</li>' +
                '<li><strong>Delimiter Escape</strong> — Detects code block delimiters used to escape context</li>' +
                '<li><strong>DAN/Jailbreak</strong> — Detects DAN mode, jailbreak attempts</li>' +
                '<li><strong>Model Delimiter</strong> — Detects model-specific tokens (im_start, im_end)</li>' +
                '<li><strong>Instruction Format</strong> — Detects [INST], [SYS] instruction markers</li>' +
                '<li><strong>Hidden Instruction</strong> — Detects IMPORTANT/CRITICAL override directives</li>' +
                '<li><strong>Context Switch</strong> — Detects "end of context", "begin new session"</li>' +
                '<li><strong>Tool Poisoning</strong> — Detects tool response containing action directives</li>' +
              '</ul>' +
            '</div>' +
          '</details>' +

        '</div>' +
      '</div>' +

      /* Input Content Scanning section (Upgrade 3) */
      '<div id="input-scan-section"></div>' +

      /* Tool Security section container */
      '<div id="toolsec-section"></div>';

    // -- Wire up content scanning event listeners --------------------------------

    var enabledCheckbox = document.getElementById('scan-enabled');
    var monitorRadio = document.querySelector('input[name="scan-mode"][value="monitor"]');
    var enforceRadio = document.querySelector('input[name="scan-mode"][value="enforce"]');
    var saveBtn = document.getElementById('save-scan-config');
    var monitorOption = document.getElementById('mode-monitor');
    var enforceOption = document.getElementById('mode-enforce');

    function updateModeSelection() {
      if (monitorRadio && monitorRadio.checked) {
        monitorOption.classList.add('selected');
        enforceOption.classList.remove('selected');
      } else {
        monitorOption.classList.remove('selected');
        enforceOption.classList.add('selected');
      }
    }

    if (monitorRadio) monitorRadio.addEventListener('change', updateModeSelection);
    if (enforceRadio) enforceRadio.addEventListener('change', updateModeSelection);

    if (saveBtn) {
      saveBtn.addEventListener('click', function () {
        var newEnabled = enabledCheckbox ? enabledCheckbox.checked : true;
        var newMode = 'monitor';
        if (enforceRadio && enforceRadio.checked) {
          newMode = 'enforce';
        }

        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving...';

        SG.api.put('/v1/security/content-scanning', {
          mode: newMode,
          enabled: newEnabled,
        }).then(function () {
          saveBtn.disabled = false;
          saveBtn.textContent = 'Save Changes';
          SG.toast.success('Content scanning configuration updated');

          var badgeEl = document.getElementById('security-status-badge');
          if (badgeEl) {
            badgeEl.innerHTML = statusBadge({ mode: newMode, enabled: newEnabled });
          }

          currentConfig = { mode: newMode, enabled: newEnabled };
        }).catch(function (err) {
          saveBtn.disabled = false;
          saveBtn.textContent = 'Save Changes';
          SG.toast.error('Failed to update: ' + (err.message || 'Unknown error'));
        });
      });
    }

    // Fetch recent detections count
    var detectionStatEl = document.getElementById('recent-detections-stat');
    if (detectionStatEl && enabled) {
      SG.api.get('/audit?limit=200').then(function (data) {
        var records = data && data.records ? data.records : [];
        var now = Date.now();
        var oneDayAgo = now - 24 * 60 * 60 * 1000;
        var count = 0;
        var lastDetectionTime = null;
        for (var i = 0; i < records.length; i++) {
          var r = records[i];
          if (r.scan_detections && r.scan_detections > 0) {
            var ts = new Date(r.timestamp).getTime();
            if (ts >= oneDayAgo) {
              count++;
              if (!lastDetectionTime || ts > lastDetectionTime) lastDetectionTime = ts;
            }
          }
        }
        if (count > 0) {
          var ago = Math.round((now - lastDetectionTime) / 60000);
          var agoText = ago < 60 ? ago + 'm ago' : Math.round(ago / 60) + 'h ago';
          detectionStatEl.innerHTML = '<strong>' + count + ' detection' + (count !== 1 ? 's' : '') + '</strong> in the last 24h (last: ' + agoText + ') \u2014 <a href="#/audit" style="color:var(--accent)">View in Activity</a>';
          detectionStatEl.style.color = 'var(--danger)';
        } else {
          detectionStatEl.textContent = 'No detections in the last 24h';
          detectionStatEl.style.color = 'var(--success)';
        }
      }).catch(function () {
        detectionStatEl.textContent = 'Unable to load detection data';
      });
    } else if (detectionStatEl && !enabled) {
      detectionStatEl.textContent = 'Enable content scanning to see detection data';
      detectionStatEl.style.color = 'var(--text-muted)';
    }

    addSecHelpBtn(container);

    // Render input scanning section (Upgrade 3 - Delta 1.2)
    renderInputScanSection(document.getElementById('input-scan-section'));

    // Render Tool Security section
    renderToolSecuritySection(document.getElementById('toolsec-section'));
  }

  // -- Input Content Scanning Section (Upgrade 3, Delta 1.2) ------------------

  function renderInputScanSection(sectionEl) {
    if (!sectionEl) return;

    var scanIcon = SG.icon ? SG.icon('search', 20) : '';

    if (!inputScanAvailable) {
      sectionEl.innerHTML =
        '<div class="card security-section">' +
          '<div class="card-header"><h3 class="card-title">' + scanIcon + ' Input Content Scanning</h3></div>' +
          '<div class="card-body" style="padding: var(--space-6);">' +
            '<p style="color: var(--text-muted);">Input content scanning is not available.</p>' +
          '</div>' +
        '</div>';
      return;
    }

    var cfg = inputScanConfig || { enabled: false, whitelist: [] };
    var whitelistItems = cfg.whitelist || [];

    sectionEl.innerHTML =
      '<div class="card security-section">' +
        '<div class="card-header">' +
          '<h3 class="card-title">' + scanIcon + ' Input Content Scanning</h3>' +
          '<span class="badge ' + (cfg.enabled ? 'badge-success' : 'badge-muted') + '" id="input-scan-badge">' +
            (cfg.enabled ? 'Enabled' : 'Disabled') +
          '</span>' +
        '</div>' +
        '<div class="card-body" style="padding: var(--space-6);">' +
          '<p style="font-size: var(--text-sm); color: var(--text-secondary); margin-bottom: var(--space-4);">' +
            'Scan tool call arguments for PII (emails, credit cards, SSNs) and secrets (API keys, passwords) ' +
            'before forwarding to upstream servers. Detected PII is masked; secrets are blocked. ' +
            'If a tool legitimately handles sensitive data (e.g., a contact lookup that uses email addresses), ' +
            'add it to the whitelist below to prevent false positives.' +
          '</p>' +

          '<div class="toggle-row">' +
            '<div class="toggle-label">' +
              '<span class="toggle-label-title">Enable Input Scanning</span>' +
              '<span class="toggle-label-desc">When enabled, all tool call arguments are scanned for sensitive data before forwarding.</span>' +
            '</div>' +
            '<label class="toggle-switch">' +
              '<input type="checkbox" id="input-scan-enabled" ' + (cfg.enabled ? 'checked' : '') + '>' +
              '<span class="toggle-slider"></span>' +
            '</label>' +
          '</div>' +

          '<h4 style="margin-top: var(--space-5); margin-bottom: var(--space-3); font-size: var(--text-base);">Pattern Types</h4>' +
          '<div style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-3);line-height:1.6;display:grid;grid-template-columns:auto 1fr;gap:2px var(--space-3)">' +
            '<strong style="color:var(--danger)">Block:</strong><span>The call is rejected. Sensitive data never reaches the upstream. The agent receives an error.</span>' +
            '<strong style="color:var(--warning)">Mask:</strong><span>Sensitive data is replaced with a placeholder (e.g. [REDACTED-EMAIL]) before forwarding to the upstream.</span>' +
            '<strong style="color:var(--info)">Alert:</strong><span>The data is detected and logged in the audit trail, but the call passes through without modification. Use for monitoring.</span>' +
            '<strong>Off:</strong><span>This pattern type is disabled. No scanning is performed for it.</span>' +
          '</div>' +
          '<div class="input-scan-patterns" id="input-scan-patterns-container"></div>' +

          '<h4 style="margin-top: var(--space-5); margin-bottom: var(--space-3); font-size: var(--text-base);">Whitelist <span class="badge badge-muted">' + whitelistItems.length + '</span></h4>' +
          '<p style="font-size: var(--text-sm); color: var(--text-secondary); margin-bottom: var(--space-2);">' +
            'Contextual exceptions: skip specific patterns for certain tools, agents, or file paths to reduce false positives.' +
          '</p>' +
          '<p style="font-size: var(--text-xs); color: var(--text-muted); margin-bottom: var(--space-3); line-height: 1.5;">' +
            'The scanner may flag tools that legitimately handle sensitive data (e.g., a tool that reads email addresses). ' +
            'Use the whitelist to exclude specific patterns for those tools. Prefer narrow scope (tool-specific) over broad paths. ' +
            'Check Activity for scan detection badges to identify false positives.' +
          '</p>' +
          '<div id="input-scan-whitelist-list"></div>' +

          '<div class="input-scan-whitelist-form" style="margin-top: var(--space-3);">' +
            '<label style="font-size:var(--text-xs);color:var(--text-muted);display:block;margin-bottom:2px">Pattern type to exclude from scanning</label>' +
            '<select id="wl-pattern-type" class="form-select" style="width: auto; display: inline-block; margin-right: var(--space-2);">' +
              '<option value="email">Email</option>' +
              '<option value="credit_card">Credit Card</option>' +
              '<option value="us_ssn">US SSN</option>' +
              '<option value="uk_ni_number">UK NI Number</option>' +
              '<option value="phone_number">Phone</option>' +
              '<option value="aws_key">AWS Key</option>' +
              '<option value="gcp_key">GCP Key</option>' +
              '<option value="azure_key">Azure Key</option>' +
              '<option value="stripe_key">Stripe Key</option>' +
              '<option value="github_token">GitHub Token</option>' +
              '<option value="generic_secret">Generic Secret</option>' +
            '</select>' +
            '<label style="font-size:var(--text-xs);color:var(--text-muted);display:block;margin-bottom:2px;margin-top:var(--space-2)">Scope</label>' +
            '<div style="font-size:var(--text-xs);color:var(--text-muted);margin-bottom:var(--space-1)">Choose where this exception applies: <strong>Tool</strong> = skip for a specific tool (any agent), <strong>Agent</strong> = skip for a specific agent identity (any tool), <strong>Path</strong> = skip for files matching a path pattern.</div>' +
            '<select id="wl-scope" class="form-select" style="width: auto; display: inline-block; margin-right: var(--space-2);">' +
              '<option value="tool">Tool</option>' +
              '<option value="agent">Agent</option>' +
              '<option value="path">Path</option>' +
            '</select>' +
            '<input type="text" id="wl-value" class="form-input" placeholder="e.g. read_file" style="width: 200px; display: inline-block; margin-right: var(--space-2);">' +
            '<button class="btn btn-sm btn-primary" id="add-whitelist-btn">Add Exception</button>' +
          '</div>' +

        '</div>' +
      '</div>';

    renderInputScanWhitelist(whitelistItems);
    wireInputScanEvents(cfg);
  }

  function renderInputScanWhitelist(items) {
    var listEl = document.getElementById('input-scan-whitelist-list');
    if (!listEl) return;

    if (!items || items.length === 0) {
      listEl.innerHTML = '<p style="font-size: var(--text-sm); color: var(--text-muted);">No whitelist entries. All patterns are active for all contexts.</p>';
      return;
    }

    var html = '<div class="table-responsive"><table class="data-table"><thead><tr>' +
      '<th>Pattern</th><th>Scope</th><th>Value</th><th></th>' +
      '</tr></thead><tbody>';

    for (var i = 0; i < items.length; i++) {
      var item = items[i];
      html += '<tr>' +
        '<td><span class="badge badge-muted">' + esc(item.pattern_type) + '</span></td>' +
        '<td>' + esc(item.scope) + '</td>' +
        '<td><code>' + esc(item.value) + '</code></td>' +
        '<td><button class="btn btn-sm btn-danger input-scan-wl-remove" data-wl-id="' + esc(item.id) + '">Remove</button></td>' +
        '</tr>';
    }

    html += '</tbody></table></div>';
    listEl.innerHTML = html;

    // Wire remove buttons.
    var removeBtns = listEl.querySelectorAll('.input-scan-wl-remove');
    for (var j = 0; j < removeBtns.length; j++) {
      (function (btn) {
        btn.addEventListener('click', function () {
          var wlId = btn.getAttribute('data-wl-id');
          btn.disabled = true;
          btn.textContent = 'Removing...';
          SG.api.del('/v1/security/input-scanning/whitelist/' + encodeURIComponent(wlId)).then(function () {
            SG.toast.success('Whitelist entry removed');
            refreshInputScan();
          }).catch(function (err) {
            btn.disabled = false;
            btn.textContent = 'Remove';
            SG.toast.error('Failed to remove: ' + (err.message || 'Unknown error'));
          });
        });
      })(removeBtns[j]);
    }
  }

  function wireInputScanEvents(cfg) {
    // Render configurable pattern types
    var patternsContainer = document.getElementById('input-scan-patterns-container');
    if (patternsContainer && cfg && cfg.pattern_actions) {
      var patternDefs = [
        { key: 'email', label: 'Email addresses', cat: 'PII' },
        { key: 'credit_card', label: 'Credit cards (Luhn)', cat: 'PII' },
        { key: 'us_ssn', label: 'US SSN', cat: 'PII' },
        { key: 'uk_ni_number', label: 'UK NI Number', cat: 'PII' },
        { key: 'phone_number', label: 'Phone numbers', cat: 'PII' },
        { key: 'aws_key', label: 'AWS keys', cat: 'Secret' },
        { key: 'gcp_key', label: 'GCP keys', cat: 'Secret' },
        { key: 'azure_key', label: 'Azure keys', cat: 'Secret' },
        { key: 'stripe_key', label: 'Stripe tokens', cat: 'Secret' },
        { key: 'github_token', label: 'GitHub tokens', cat: 'Secret' },
        { key: 'generic_secret', label: 'Passwords in key=value', cat: 'Secret' }
      ];
      var table = document.createElement('table');
      table.style.cssText = 'width:100%;border-collapse:collapse;font-size:var(--text-sm)';
      table.innerHTML = '<thead><tr style="text-align:left;border-bottom:1px solid var(--border)">' +
        '<th style="padding:var(--space-2) var(--space-3);width:80px">Type</th>' +
        '<th style="padding:var(--space-2) var(--space-3)">Pattern</th>' +
        '<th style="padding:var(--space-2) var(--space-3);width:120px;text-align:right">Action</th>' +
        '</tr></thead>';
      var tbody = document.createElement('tbody');
      patternDefs.forEach(function (pd) {
        var currentAction = cfg.pattern_actions[pd.key] || 'mask';
        var catBadge = pd.cat === 'Secret'
          ? '<span class="badge badge-danger">Secret</span>'
          : '<span class="badge badge-warning">PII</span>';
        var tr = document.createElement('tr');
        tr.style.cssText = 'border-bottom:1px solid var(--border)';
        tr.innerHTML =
          '<td style="padding:var(--space-2) var(--space-3)">' + catBadge + '</td>' +
          '<td style="padding:var(--space-2) var(--space-3);color:var(--text-primary)">' + pd.label + '</td>' +
          '<td style="padding:var(--space-2) var(--space-3);text-align:right">' +
            '<select class="form-select" data-pattern="' + pd.key + '" style="width:110px;font-size:var(--text-sm);padding:var(--space-1) var(--space-2);background:var(--bg-secondary);color:var(--text-primary);border:1px solid var(--border);border-radius:var(--radius-sm)">' +
              '<option value="off"' + (currentAction === 'off' ? ' selected' : '') + '>Off</option>' +
              '<option value="alert"' + (currentAction === 'alert' ? ' selected' : '') + '>Alert</option>' +
              '<option value="mask"' + (currentAction === 'mask' ? ' selected' : '') + '>Mask</option>' +
              '<option value="block"' + (currentAction === 'block' ? ' selected' : '') + '>Block</option>' +
            '</select>' +
          '</td>';
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      patternsContainer.innerHTML = '';
      patternsContainer.appendChild(table);
      // Wire change events
      patternsContainer.querySelectorAll('select[data-pattern]').forEach(function (sel) {
        sel.addEventListener('change', function () {
          var pt = this.getAttribute('data-pattern');
          var act = this.value;
          var payload = { pattern_actions: {} };
          payload.pattern_actions[pt] = act;
          SG.api.put('/v1/security/input-scanning', payload).then(function () {
            SG.toast.success(pt.replace(/_/g, ' ') + ' → ' + act);
          }).catch(function (err) {
            SG.toast.error('Failed: ' + (err.message || 'Unknown error'));
          });
        });
      });
    }

    var enabledCb = document.getElementById('input-scan-enabled');
    var addBtn = document.getElementById('add-whitelist-btn');

    if (enabledCb) {
      enabledCb.addEventListener('change', function () {
        var newEnabled = enabledCb.checked;
        SG.api.put('/v1/security/input-scanning', { enabled: newEnabled }).then(function () {
          SG.toast.success('Input scanning ' + (newEnabled ? 'enabled' : 'disabled'));
          var badge = document.getElementById('input-scan-badge');
          if (badge) {
            badge.className = 'badge ' + (newEnabled ? 'badge-success' : 'badge-muted');
            badge.textContent = newEnabled ? 'Enabled' : 'Disabled';
          }
        }).catch(function (err) {
          enabledCb.checked = !newEnabled;
          SG.toast.error('Failed to update: ' + (err.message || 'Unknown error'));
        });
      });
    }

    // Dynamic placeholder based on scope selection
    var scopeSelect = document.getElementById('wl-scope');
    var valueInput = document.getElementById('wl-value');
    if (scopeSelect && valueInput) {
      var placeholders = { tool: 'e.g. read_file', agent: 'e.g. Maxima1', path: 'e.g. /test/*' };
      // Datalist for tool and agent autocomplete
      var wlToolDl = document.createElement('datalist');
      wlToolDl.id = 'wl-dl-tools';
      var wlAgentDl = document.createElement('datalist');
      wlAgentDl.id = 'wl-dl-agents';
      valueInput.parentNode.appendChild(wlToolDl);
      valueInput.parentNode.appendChild(wlAgentDl);

      // Fetch tools and identities for autocomplete
      SG.api.get('/tools').then(function (data) {
        var toolList = Array.isArray(data) ? data : (data && data.tools ? data.tools : []);
        for (var i = 0; i < toolList.length; i++) {
          var opt = document.createElement('option');
          opt.value = toolList[i].name || '';
          wlToolDl.appendChild(opt);
        }
      }).catch(function () {});
      SG.api.get('/identities').then(function (ids) {
        (ids || []).forEach(function (id) {
          var opt = document.createElement('option');
          opt.value = id.name || id.id;
          wlAgentDl.appendChild(opt);
        });
      }).catch(function () {});

      function updateScopeUI() {
        valueInput.placeholder = placeholders[scopeSelect.value] || '';
        if (scopeSelect.value === 'tool') {
          valueInput.setAttribute('list', 'wl-dl-tools');
        } else if (scopeSelect.value === 'agent') {
          valueInput.setAttribute('list', 'wl-dl-agents');
        } else {
          valueInput.removeAttribute('list');
        }
      }
      scopeSelect.addEventListener('change', updateScopeUI);
      updateScopeUI(); // initial state
    }

    if (addBtn) {
      addBtn.addEventListener('click', function () {
        var patternType = document.getElementById('wl-pattern-type').value;
        var scope = document.getElementById('wl-scope').value;
        var value = document.getElementById('wl-value').value.trim();

        if (!value) {
          SG.toast.error('Value is required');
          return;
        }

        addBtn.disabled = true;
        addBtn.textContent = 'Adding...';

        SG.api.post('/v1/security/input-scanning/whitelist', {
          pattern_type: patternType,
          scope: scope,
          value: value,
        }).then(function () {
          SG.toast.success('Whitelist entry added');
          document.getElementById('wl-value').value = '';
          refreshInputScan();
        }).catch(function (err) {
          SG.toast.error('Failed to add: ' + (err.message || 'Unknown error'));
        }).finally(function () {
          addBtn.disabled = false;
          addBtn.textContent = 'Add Exception';
        });
      });
    }
  }

  function refreshInputScan() {
    loadInputScanConfig().then(function () {
      var sectionEl = document.getElementById('input-scan-section');
      if (sectionEl) {
        renderInputScanSection(sectionEl);
      }
    });
  }

  // -- Tool Security Section ---------------------------------------------------

  function renderToolSecuritySection(sectionEl) {
    if (!sectionEl) return;

    if (!toolSecAvailable) {
      sectionEl.innerHTML =
        '<div class="card security-section">' +
          '<div class="card-header"><h3 class="card-title">' + (SG.icon ? SG.icon('shield', 20) : '') + ' Tool Security</h3></div>' +
          '<div class="card-body" style="padding: var(--space-6);">' +
            '<p style="color: var(--text-muted);">Tool security is not available. The tool security service may not be configured.</p>' +
          '</div>' +
        '</div>';
      return;
    }

    var shieldIcon = SG.icon ? SG.icon('shield', 20) : '';

    sectionEl.innerHTML =
      '<div class="card security-section">' +
        '<div class="card-header">' +
          '<h3 class="card-title">' + shieldIcon + ' Tool Security</h3>' +
        '</div>' +
        '<div class="card-body" style="padding: var(--space-6);">' +
          '<p class="toolsec-info">' +
            'Tool definitions are monitored continuously. The baseline is captured automatically at first boot and updated when you add or remove a server. You can also click Capture Baseline to refresh it manually. ' +
            'Every 5 minutes, all upstream tools are re-checked. If a tool\'s schema changes, it is auto-quarantined until you review it.' +
          '</p>' +

          /* Baseline sub-section */
          '<div style="margin-bottom: var(--space-6);">' +
            '<div style="font-size: var(--text-sm); font-weight: var(--font-semibold); color: var(--text-primary); margin-bottom: var(--space-3);">Tool Baseline</div>' +
            '<div class="toolsec-action-bar">' +
              '<button class="btn btn-primary btn-sm" id="toolsec-capture-btn">' + (SG.icon ? SG.icon('refresh', 16) : '') + ' Capture Baseline</button>' +
              '<button class="btn btn-secondary btn-sm" id="toolsec-view-baseline-btn">' + (SG.icon ? SG.icon('shield', 16) : '') + ' View Baseline</button>' +
              '<button class="btn btn-secondary btn-sm" id="toolsec-export-baseline-btn">' + (SG.icon ? SG.icon('clipboard', 16) : '') + ' Export Baseline</button>' +
            '</div>' +
            '<div id="toolsec-baseline-info"></div>' +
            '<div id="toolsec-baseline-list" style="display: none;"></div>' +
          '</div>' +

          /* Drift Detection sub-section */
          '<div style="margin-bottom: var(--space-6);">' +
            '<div style="font-size: var(--text-sm); font-weight: var(--font-semibold); color: var(--text-primary); margin-bottom: var(--space-3);">Drift Detection</div>' +
            '<div class="toolsec-action-bar">' +
              '<button class="btn btn-primary btn-sm" id="toolsec-drift-btn">' + (SG.icon ? SG.icon('zap', 16) : '') + ' Check Drift</button>' +
            '</div>' +
            '<div id="toolsec-drift-result"></div>' +
          '</div>' +

          /* Quarantine sub-section */
          '<div>' +
            '<div style="font-size: var(--text-sm); font-weight: var(--font-semibold); color: var(--text-primary); margin-bottom: var(--space-3);">Quarantine</div>' +
            '<div id="toolsec-quarantine-list"></div>' +
            '<div class="toolsec-quarantine-add">' +
              '<input type="text" id="toolsec-quarantine-input" placeholder="Tool name to quarantine">' +
              '<button class="btn btn-primary btn-sm" id="toolsec-quarantine-add-btn">Quarantine</button>' +
            '</div>' +
          '</div>' +

        '</div>' +
      '</div>';

    // Show baseline info if we have data
    renderToolSecBaselineInfo();

    // Render quarantine list
    renderToolSecQuarantineList();

    // Wire Capture Baseline button
    var captureBtn = document.getElementById('toolsec-capture-btn');
    if (captureBtn) {
      captureBtn.addEventListener('click', function () {
        captureBtn.disabled = true;
        captureBtn.textContent = 'Capturing...';
        SG.api.post('/v1/tools/baseline').then(function (result) {
          captureBtn.disabled = false;
          captureBtn.innerHTML = (SG.icon ? SG.icon('refresh', 16) : '') + ' Capture Baseline';
          SG.toast.success('Baseline captured: ' + (result.tools_captured || 0) + ' tools');
          // Update info display
          var infoEl = document.getElementById('toolsec-baseline-info');
          if (infoEl) {
            infoEl.innerHTML =
              '<div class="toolsec-result-box success">' +
                '<strong style="font-size: var(--text-sm); color: var(--text-primary);">' + esc(String(result.tools_captured || 0)) + ' tools captured</strong>' +
                '<div style="font-size: var(--text-xs); color: var(--text-muted); margin-top: 2px;">Captured at: ' + esc(result.captured_at || 'now') + '</div>' +
              '</div>';
          }
          // Reload baseline data for View
          loadToolSecBaseline();
        }).catch(function (err) {
          captureBtn.disabled = false;
          captureBtn.innerHTML = (SG.icon ? SG.icon('refresh', 16) : '') + ' Capture Baseline';
          SG.toast.error('Failed to capture baseline: ' + (err.message || 'Unknown error'));
        });
      });
    }

    // Wire View Baseline toggle
    var viewBaselineBtn = document.getElementById('toolsec-view-baseline-btn');
    var baselineListEl = document.getElementById('toolsec-baseline-list');
    if (viewBaselineBtn && baselineListEl) {
      viewBaselineBtn.addEventListener('click', function () {
        if (baselineListEl.style.display === 'none') {
          // Fetch fresh baseline and show
          SG.api.get('/v1/tools/baseline').then(function (data) {
            toolSecBaseline = data;
            var tools = (data && data.tools) ? data.tools : [];
            if (tools.length === 0) {
              baselineListEl.innerHTML =
                '<div class="toolsec-result-box">' +
                  '<span style="color: var(--text-muted); font-size: var(--text-sm);">No baseline yet. It will be captured automatically when upstream tools are discovered.</span>' +
                '</div>';
            } else {
              var html = '<div class="toolsec-result-box"><div class="toolsec-baseline-list">';
              for (var i = 0; i < tools.length; i++) {
                var toolName = typeof tools[i] === 'string' ? tools[i] : (tools[i].name || JSON.stringify(tools[i]));
                html += '<div class="toolsec-baseline-item">' + esc(toolName) + '</div>';
              }
              html += '</div></div>';
              baselineListEl.innerHTML = html;
            }
            baselineListEl.style.display = 'block';
            viewBaselineBtn.innerHTML = (SG.icon ? SG.icon('shield', 16) : '') + ' Hide Baseline';
          }).catch(function (err) {
            SG.toast.error('Failed to load baseline: ' + (err.message || 'Unknown error'));
          });
        } else {
          baselineListEl.style.display = 'none';
          viewBaselineBtn.innerHTML = (SG.icon ? SG.icon('shield', 16) : '') + ' View Baseline';
        }
      });
    }

    // Wire Export Baseline button
    var exportBaselineBtn = document.getElementById('toolsec-export-baseline-btn');
    if (exportBaselineBtn) {
      exportBaselineBtn.addEventListener('click', function () {
        exportBaselineBtn.disabled = true;
        exportBaselineBtn.textContent = 'Exporting...';
        SG.api.get('/v1/tools/baseline').then(function (data) {
          var json = JSON.stringify(data, null, 2);
          var blob = new Blob([json], { type: 'application/json' });
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          var now = new Date().toISOString().slice(0, 10);
          a.href = url;
          a.download = 'baseline-' + now + '.json';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          exportBaselineBtn.disabled = false;
          exportBaselineBtn.innerHTML = (SG.icon ? SG.icon('clipboard', 16) : '') + ' Export Baseline';
          SG.toast.success('Baseline exported');
        }).catch(function (err) {
          exportBaselineBtn.disabled = false;
          exportBaselineBtn.innerHTML = (SG.icon ? SG.icon('clipboard', 16) : '') + ' Export Baseline';
          SG.toast.error('Failed to export baseline: ' + (err.message || 'Unknown error'));
        });
      });
    }

    // Wire Check Drift button
    var driftBtn = document.getElementById('toolsec-drift-btn');
    if (driftBtn) {
      driftBtn.addEventListener('click', function () {
        driftBtn.disabled = true;
        driftBtn.textContent = 'Checking...';
        SG.api.get('/v1/tools/drift').then(function (result) {
          driftBtn.disabled = false;
          driftBtn.innerHTML = (SG.icon ? SG.icon('zap', 16) : '') + ' Check Drift';
          var drifts = (result && result.drifts) ? result.drifts : [];
          var baselineCount = result ? (result.baseline_tools || 0) : 0;
          var resultEl = document.getElementById('toolsec-drift-result');
          if (!resultEl) return;

          if (drifts.length === 0) {
            resultEl.innerHTML =
              '<div class="toolsec-result-box success">' +
                '<strong style="font-size: var(--text-sm); color: var(--success);">No drift detected</strong>' +
                '<div style="font-size: var(--text-xs); color: var(--text-muted); margin-top: 2px;">Baseline tools: ' + esc(String(baselineCount)) + '</div>' +
              '</div>';
          } else {
            var html =
              '<div class="toolsec-result-box warning">' +
                '<strong style="font-size: var(--text-sm); color: var(--warning);">' + drifts.length + ' drift(s) detected</strong>' +
                '<div style="font-size: var(--text-xs); color: var(--text-muted); margin-top: 2px;">Baseline tools: ' + esc(String(baselineCount)) + '</div>' +
                '<div style="margin-top: var(--space-3);">';
            for (var i = 0; i < drifts.length; i++) {
              var d = drifts[i];
              var driftType = d.drift_type || 'unknown';
              var driftName = d.tool_name || '';
              var typeCls = 'toolsec-drift-added';
              if (driftType === 'removed') typeCls = 'toolsec-drift-removed';
              else if (driftType === 'changed') typeCls = 'toolsec-drift-changed';
              html +=
                '<div class="toolsec-drift-item">' +
                  '<span class="toolsec-drift-type ' + typeCls + '">' + esc(driftType) + '</span>' +
                  '<span style="font-family: var(--font-mono);">' + esc(driftName) + '</span>' +
                '</div>';
            }
            html += '</div></div>';
            resultEl.innerHTML = html;
          }
        }).catch(function (err) {
          driftBtn.disabled = false;
          driftBtn.innerHTML = (SG.icon ? SG.icon('zap', 16) : '') + ' Check Drift';
          SG.toast.error('Failed to check drift: ' + (err.message || 'Unknown error'));
        });
      });
    }

    // Wire Quarantine Add button
    var quarantineAddBtn = document.getElementById('toolsec-quarantine-add-btn');
    var quarantineInput = document.getElementById('toolsec-quarantine-input');
    if (quarantineAddBtn && quarantineInput) {
      quarantineAddBtn.addEventListener('click', function () {
        var toolName = quarantineInput.value.trim();
        if (!toolName) {
          SG.toast.error('Enter a tool name to quarantine');
          return;
        }
        quarantineAddBtn.disabled = true;
        quarantineAddBtn.textContent = 'Adding...';
        SG.api.post('/v1/tools/quarantine', { tool_name: toolName }).then(function () {
          quarantineAddBtn.disabled = false;
          quarantineAddBtn.textContent = 'Quarantine';
          quarantineInput.value = '';
          SG.toast.success('Tool "' + toolName + '" quarantined');
          refreshToolSecQuarantine();
        }).catch(function (err) {
          quarantineAddBtn.disabled = false;
          quarantineAddBtn.textContent = 'Quarantine';
          SG.toast.error('Failed to quarantine: ' + (err.message || 'Unknown error'));
        });
      });
    }
  }

  function renderToolSecBaselineInfo() {
    var infoEl = document.getElementById('toolsec-baseline-info');
    if (!infoEl) return;

    if (toolSecBaseline && toolSecBaseline.tools && toolSecBaseline.tools.length > 0) {
      infoEl.innerHTML =
        '<div class="toolsec-result-box">' +
          '<strong style="font-size: var(--text-sm); color: var(--text-primary);">' + esc(String(toolSecBaseline.tools.length)) + ' tools in baseline</strong>' +
        '</div>';
    } else {
      infoEl.innerHTML =
        '<div style="font-size: var(--text-xs); color: var(--text-muted);">No baseline yet. It will be captured automatically when upstream tools are discovered.</div>';
    }
  }

  function renderToolSecQuarantineList() {
    var listEl = document.getElementById('toolsec-quarantine-list');
    if (!listEl) return;

    if (toolSecQuarantine.length === 0) {
      listEl.innerHTML =
        '<div style="padding: var(--space-3) var(--space-4); color: var(--text-muted); font-size: var(--text-sm);">No tools quarantined.</div>';
      return;
    }

    var html = '';
    for (var i = 0; i < toolSecQuarantine.length; i++) {
      html +=
        '<div class="toolsec-quarantine-row">' +
          '<span class="toolsec-quarantine-name">' + esc(toolSecQuarantine[i]) + '</span>' +
          '<button class="btn btn-secondary btn-sm toolsec-unquarantine-btn" data-tool="' + esc(toolSecQuarantine[i]) + '">Remove</button>' +
        '</div>';
    }
    listEl.innerHTML = html;

    // Wire remove buttons
    var removeBtns = listEl.querySelectorAll('.toolsec-unquarantine-btn');
    for (var j = 0; j < removeBtns.length; j++) {
      (function (btn) {
        btn.addEventListener('click', function () {
          var toolName = btn.getAttribute('data-tool');
          btn.disabled = true;
          btn.textContent = 'Removing...';
          SG.api.del('/v1/tools/quarantine/' + encodeURIComponent(toolName)).then(function () {
            SG.toast.success('Tool "' + toolName + '" unquarantined');
            refreshToolSecQuarantine();
          }).catch(function (err) {
            btn.disabled = false;
            btn.textContent = 'Remove';
            SG.toast.error('Failed to unquarantine: ' + (err.message || 'Unknown error'));
          });
        });
      })(removeBtns[j]);
    }
  }

  function refreshToolSecQuarantine() {
    loadToolSecQuarantine().then(function () {
      renderToolSecQuarantineList();
    });
  }

  // -- Cleanup ----------------------------------------------------------------

  function cleanup() {
    currentConfig = null;
    toolSecBaseline = null;
    toolSecQuarantine = [];
    toolSecAvailable = true;
    inputScanConfig = null;
    inputScanAvailable = true;
  }

  // -- Register with router ---------------------------------------------------

  SG.router.register('security', render);
  SG.router.registerCleanup('security', cleanup);
})();
