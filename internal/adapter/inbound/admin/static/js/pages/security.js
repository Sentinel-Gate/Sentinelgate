/**
 * security.js -- Security page for SentinelGate admin UI.
 *
 * Content Scanning configuration: toggle enable/disable, switch between
 * monitor and enforce modes. Changes take effect immediately and persist
 * to state.json.
 *
 * Outbound Control: CRUD management for outbound rules, visual target
 * builder, test panel, and stats bar. Admins can create, edit, delete,
 * and test outbound rules directly from the browser.
 *
 * Data sources:
 *   GET /admin/api/v1/security/content-scanning   -> current config
 *   PUT /admin/api/v1/security/content-scanning   -> update config
 *   GET /admin/api/v1/security/outbound/rules     -> rule list
 *   POST /admin/api/v1/security/outbound/rules    -> create rule
 *   PUT /admin/api/v1/security/outbound/rules/{id} -> update rule
 *   DELETE /admin/api/v1/security/outbound/rules/{id} -> delete rule
 *   POST /admin/api/v1/security/outbound/test     -> test destination
 *   GET /admin/api/v1/security/outbound/stats     -> aggregate stats
 *
 * Design features:
 *   - Enable/disable toggle for content scanning
 *   - Monitor/Enforce mode selector (radio buttons)
 *   - Mode description text explaining each option
 *   - Status badge showing current mode
 *   - Save button with toast feedback
 *   - Outbound rule list with inline enable/disable toggle
 *   - Visual target builder in add/edit rule modal
 *   - Test panel for testing destinations against rules
 *   - Stats bar showing rule aggregates
 *   - Default blocklist rules shown as read-only
 *   - All user data rendered via textContent (XSS-safe)
 *
 * Requirements:
 *   SECU-UI-01  Content scanning toggle with mode selector
 *   SECU-UI-02  Immediate effect on save (no restart required)
 *   SECU-UI-03  Persist to state.json via admin API
 *   OUT-14      Admin API for outbound rule CRUD, test, stats
 *   OUT-15      Admin UI for outbound control management
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // -- State ------------------------------------------------------------------

  var styleInjected = false;
  var currentConfig = null;
  var outboundRules = [];
  var outboundStats = null;
  var outboundAvailable = true;
  var httpGatewayConfig = null;
  var httpGatewayAvailable = true;

  // -- Delegated click handler for expandable target tags ----------------------
  document.addEventListener('click', function (e) {
    var expand = e.target.getAttribute('data-toggle-targets');
    if (expand) {
      document.getElementById(expand + '-short').style.display = 'none';
      document.getElementById(expand + '-full').style.display = 'inline';
      return;
    }
    var collapse = e.target.getAttribute('data-collapse-targets');
    if (collapse) {
      document.getElementById(collapse + '-full').style.display = 'none';
      document.getElementById(collapse + '-short').style.display = 'inline';
      return;
    }
  });

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

    /* Outbound Stats Bar */
    '.outbound-stats-bar {',
    '  display: flex;',
    '  gap: var(--space-4);',
    '  margin-bottom: var(--space-4);',
    '  flex-wrap: wrap;',
    '}',
    '.outbound-stat {',
    '  flex: 1;',
    '  min-width: 120px;',
    '  padding: var(--space-3) var(--space-4);',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  text-align: center;',
    '}',
    '.outbound-stat-value {',
    '  font-size: var(--text-xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '}',
    '.outbound-stat-label {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  margin-top: 2px;',
    '}',

    /* Outbound Rule List */
    '.outbound-rule-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3) var(--space-4);',
    '  border-bottom: 1px solid var(--border);',
    '  transition: background var(--transition-fast);',
    '}',
    '.outbound-rule-row:last-child {',
    '  border-bottom: none;',
    '}',
    '.outbound-rule-row:hover {',
    '  background: var(--bg-elevated);',
    '}',
    '.outbound-rule-priority {',
    '  width: 40px;',
    '  text-align: center;',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  font-weight: var(--font-medium);',
    '}',
    '.outbound-rule-name {',
    '  flex: 1;',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-primary);',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '}',
    '.outbound-rule-name .lock-icon {',
    '  color: var(--text-muted);',
    '  font-size: var(--text-xs);',
    '}',
    '.outbound-rule-targets {',
    '  flex: 1.5;',
    '  display: flex;',
    '  flex-wrap: wrap;',
    '  gap: 4px;',
    '}',

    /* Badges */
    '.outbound-badge {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  padding: 1px 8px;',
    '  border-radius: var(--radius-full);',
    '  font-size: 11px;',
    '  font-weight: var(--font-medium);',
    '  letter-spacing: 0.02em;',
    '}',
    '.outbound-badge-blocklist {',
    '  background: rgba(239, 68, 68, 0.1);',
    '  color: var(--danger);',
    '}',
    '.outbound-badge-allowlist {',
    '  background: rgba(34, 197, 94, 0.1);',
    '  color: var(--success);',
    '}',
    '.outbound-badge-block {',
    '  background: rgba(239, 68, 68, 0.1);',
    '  color: var(--danger);',
    '}',
    '.outbound-badge-alert {',
    '  background: rgba(251, 146, 60, 0.1);',
    '  color: var(--warning);',
    '}',
    '.outbound-badge-log {',
    '  background: rgba(96, 165, 250, 0.1);',
    '  color: var(--accent);',
    '}',

    /* Target tags */
    '.outbound-target-tag {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  padding: 1px 6px;',
    '  background: var(--bg-elevated);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-sm);',
    '  font-size: 11px;',
    '  color: var(--text-secondary);',
    '  font-family: var(--font-mono);',
    '}',

    '.outbound-target-more {',
    '  cursor: pointer;',
    '  color: var(--accent);',
    '  border-color: var(--accent);',
    '  background: rgba(96, 165, 250, 0.08);',
    '}',
    '.outbound-target-more:hover {',
    '  background: rgba(96, 165, 250, 0.18);',
    '}',

    /* Rule actions */
    '.outbound-rule-actions {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '}',
    '.outbound-rule-actions button {',
    '  padding: 4px 8px;',
    '  font-size: var(--text-xs);',
    '  border-radius: var(--radius-sm);',
    '  cursor: pointer;',
    '  border: 1px solid var(--border);',
    '  background: var(--bg-surface);',
    '  color: var(--text-secondary);',
    '  transition: all var(--transition-fast);',
    '}',
    '.outbound-rule-actions button:hover {',
    '  border-color: var(--border-hover);',
    '  color: var(--text-primary);',
    '}',
    '.outbound-rule-actions button.delete-btn:hover {',
    '  border-color: var(--danger);',
    '  color: var(--danger);',
    '}',

    /* Test panel */
    '.outbound-test-result {',
    '  margin-top: var(--space-4);',
    '  padding: var(--space-3) var(--space-4);',
    '  border-radius: var(--radius-md);',
    '  border: 1px solid var(--border);',
    '}',
    '.outbound-test-result.allowed {',
    '  background: rgba(34, 197, 94, 0.08);',
    '  border-color: var(--success);',
    '}',
    '.outbound-test-result.blocked {',
    '  background: rgba(239, 68, 68, 0.08);',
    '  border-color: var(--danger);',
    '}',
    '.outbound-test-badge {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  padding: 2px 10px;',
    '  border-radius: var(--radius-full);',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-semibold);',
    '}',
    '.outbound-test-badge.allowed {',
    '  background: rgba(34, 197, 94, 0.15);',
    '  color: var(--success);',
    '}',
    '.outbound-test-badge.blocked {',
    '  background: rgba(239, 68, 68, 0.15);',
    '  color: var(--danger);',
    '}',

    /* Target builder in modal */
    '.outbound-target-builder {',
    '  margin-top: var(--space-3);',
    '}',
    '.outbound-target-builder-list {',
    '  display: flex;',
    '  flex-direction: column;',
    '  gap: var(--space-2);',
    '  margin-bottom: var(--space-3);',
    '}',
    '.outbound-target-builder-item {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  padding: var(--space-2) var(--space-3);',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '}',
    '.outbound-target-builder-item .target-type {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  font-weight: var(--font-medium);',
    '  min-width: 80px;',
    '}',
    '.outbound-target-builder-item .target-value {',
    '  flex: 1;',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  font-family: var(--font-mono);',
    '}',
    '.outbound-target-add-row {',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  align-items: center;',
    '}',
    '.outbound-target-add-row select, .outbound-target-add-row input {',
    '  font-size: var(--text-sm);',
    '  padding: var(--space-2) var(--space-3);',
    '  background: var(--bg-primary);',
    '  color: var(--text-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  line-height: 1.5;',
    '}',
    '.outbound-target-add-row input::placeholder {',
    '  color: var(--text-muted);',
    '}',
    '.outbound-target-add-row input:focus, .outbound-target-add-row select:focus {',
    '  outline: none;',
    '  border-color: var(--accent);',
    '}',

    /* Card header with action button */
    '.card-header-actions {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '}',

    /* Empty state */
    '.outbound-empty {',
    '  padding: var(--space-6);',
    '  text-align: center;',
    '  color: var(--text-muted);',
    '  font-size: var(--text-sm);',
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
    '.ob-radio-group {',
    '  display: flex;',
    '  gap: var(--space-4);',
    '}',
    '.ob-radio-group label {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-1);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  cursor: pointer;',
    '}',
    '.ob-checkbox-label {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  cursor: pointer;',
    '}',

    /* HTTP Gateway section */
    '.httpgw-bypass-list {',
    '  display: flex;',
    '  flex-wrap: wrap;',
    '  gap: 6px;',
    '  margin-bottom: var(--space-3);',
    '  min-height: 32px;',
    '}',
    '.httpgw-bypass-tag {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: 4px;',
    '  padding: 2px 8px;',
    '  background: var(--bg-elevated);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-sm);',
    '  font-size: 12px;',
    '  color: var(--text-secondary);',
    '  font-family: var(--font-mono);',
    '}',
    '.httpgw-bypass-tag button {',
    '  background: none;',
    '  border: none;',
    '  color: var(--text-muted);',
    '  cursor: pointer;',
    '  padding: 0;',
    '  font-size: 14px;',
    '  line-height: 1;',
    '}',
    '.httpgw-bypass-tag button:hover {',
    '  color: var(--danger);',
    '}',
    '.httpgw-bypass-add {',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  align-items: center;',
    '  margin-bottom: var(--space-3);',
    '}',
    '.httpgw-bypass-add input {',
    '  flex: 1;',
    '  padding: var(--space-2) var(--space-3);',
    '  background: var(--bg-primary);',
    '  color: var(--text-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-sm);',
    '  line-height: 1.5;',
    '}',
    '.httpgw-bypass-add input::placeholder {',
    '  color: var(--text-muted);',
    '}',
    '.httpgw-bypass-add input:focus {',
    '  border-color: var(--accent);',
    '  outline: none;',
    '  box-shadow: 0 0 0 3px var(--accent-ring);',
    '}',
    '.httpgw-download-row {',
    '  display: flex;',
    '  gap: var(--space-3);',
    '  padding: var(--space-4);',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  margin-top: var(--space-4);',
    '}',
    '.httpgw-download-row button {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '}',
    '.ca-trust-banner {',
    '  display: flex;',
    '  align-items: flex-start;',
    '  gap: var(--space-3);',
    '  padding: var(--space-4);',
    '  background: var(--accent-subtle, rgba(59, 130, 246, 0.08));',
    '  border: 1px solid var(--accent, #3b82f6);',
    '  border-radius: var(--radius-md);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.ca-trust-banner-icon {',
    '  flex-shrink: 0;',
    '  width: 20px;',
    '  height: 20px;',
    '  color: var(--accent, #3b82f6);',
    '  margin-top: 2px;',
    '}',
    '.ca-trust-banner strong {',
    '  display: block;',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '  margin-bottom: var(--space-1);',
    '}',
    '.ca-trust-banner p {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-secondary);',
    '  margin: 0 0 var(--space-2) 0;',
    '}',
    '.ca-trust-banner code {',
    '  display: inline-block;',
    '  font-size: var(--text-xs);',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-sm);',
    '  padding: var(--space-1) var(--space-2);',
    '  font-family: var(--font-mono, monospace);',
    '  color: var(--text-primary);',
    '  user-select: all;',
    '}',
    '.ca-trust-banner .btn-copy {',
    '  margin-left: var(--space-2);',
    '  font-size: var(--text-xs);',
    '  padding: var(--space-1) var(--space-2);',
    '  vertical-align: middle;',
    '}',
    '.httpgw-target-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3) var(--space-4);',
    '  border-bottom: 1px solid var(--border);',
    '  transition: background var(--transition-fast);',
    '}',
    '.httpgw-target-row:last-child {',
    '  border-bottom: none;',
    '}',
    '.httpgw-target-row:hover {',
    '  background: var(--bg-elevated);',
    '}',
    '.httpgw-target-name {',
    '  flex: 1;',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-primary);',
    '}',
    '.httpgw-target-prefix {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-secondary);',
    '  font-family: var(--font-mono);',
    '}',
    '.httpgw-target-upstream {',
    '  flex: 1.5;',
    '  font-size: var(--text-sm);',
    '  color: var(--text-secondary);',
    '  font-family: var(--font-mono);',
    '  overflow: hidden;',
    '  text-overflow: ellipsis;',
    '  white-space: nowrap;',
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
      return '<span class="security-status security-status-disabled">Disabled</span>';
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

  function modeBadge(mode) {
    var cls = mode === 'allowlist' ? 'outbound-badge-allowlist' : 'outbound-badge-blocklist';
    return '<span class="outbound-badge ' + cls + '">' + esc(mode) + '</span>';
  }

  function actionBadge(act) {
    var cls = 'outbound-badge-block';
    if (act === 'alert') cls = 'outbound-badge-alert';
    if (act === 'log') cls = 'outbound-badge-log';
    return '<span class="outbound-badge ' + cls + '">' + esc(act) + '</span>';
  }

  var _targetTagUid = 0;
  function targetTags(targets, max) {
    max = max || 3;
    if (targets.length <= max) {
      var html = '';
      for (var i = 0; i < targets.length; i++) {
        html += '<span class="outbound-target-tag">' + esc(targets[i].value) + '</span>';
      }
      return html;
    }
    var uid = 'tt-' + (++_targetTagUid);
    var html = '<span id="' + uid + '-short">';
    for (var i = 0; i < max; i++) {
      html += '<span class="outbound-target-tag">' + esc(targets[i].value) + '</span>';
    }
    html += '<span class="outbound-target-tag outbound-target-more" data-toggle-targets="' + uid + '">+' + (targets.length - max) + ' more</span>';
    html += '</span>';
    html += '<span id="' + uid + '-full" style="display:none">';
    for (var i = 0; i < targets.length; i++) {
      html += '<span class="outbound-target-tag">' + esc(targets[i].value) + '</span>';
    }
    html += '<span class="outbound-target-tag outbound-target-more" data-collapse-targets="' + uid + '">Show less</span>';
    html += '</span>';
    return html;
  }

  var TARGET_PLACEHOLDERS = {
    domain: 'example.com',
    ip: '10.0.0.1',
    cidr: '10.0.0.0/8',
    domain_glob: '*.evil.com',
    port_range: '8000-9000',
  };

  var TARGET_LABELS = {
    domain: 'Domain',
    ip: 'IP',
    cidr: 'CIDR',
    domain_glob: 'Domain Glob',
    port_range: 'Port Range',
  };

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

  function loadOutboundRules() {
    return SG.api.get('/v1/security/outbound/rules').then(function (data) {
      outboundRules = data || [];
      outboundAvailable = true;
      return data;
    }).catch(function (err) {
      if (err.status === 503) {
        outboundAvailable = false;
        outboundRules = [];
        return [];
      }
      throw err;
    });
  }

  function loadOutboundStats() {
    return SG.api.get('/v1/security/outbound/stats').then(function (data) {
      outboundStats = data;
      return data;
    }).catch(function () {
      outboundStats = null;
      return null;
    });
  }

  function loadHTTPGatewayConfig() {
    return SG.api.get('/v1/security/http-gateway').then(function (data) {
      httpGatewayConfig = data;
      httpGatewayAvailable = true;
      return data;
    }).catch(function (err) {
      if (err.status === 503) {
        httpGatewayAvailable = false;
        httpGatewayConfig = null;
        return null;
      }
      throw err;
    });
  }

  // -- Main render ------------------------------------------------------------

  function render(container) {
    injectStyles();

    container.innerHTML =
      '<div class="security-header"><div><h1>Security</h1>' +
      '<p class="security-header-desc">Configure response content scanning, outbound control, and security features.</p></div></div>' +
      '<div class="card"><div class="card-body" style="padding: var(--space-6);"><p style="color: var(--text-muted);">Loading...</p></div></div>';

    Promise.all([loadConfig(), loadOutboundRules(), loadOutboundStats(), loadHTTPGatewayConfig()]).then(function (results) {
      renderPage(container, results[0]);
    }).catch(function (err) {
      container.innerHTML =
        '<div class="security-header"><div><h1>Security</h1></div></div>' +
        '<div class="card"><div class="card-body" style="padding: var(--space-6);">' +
        '<p style="color: var(--danger);">Failed to load security configuration: ' + esc(err.message || 'Unknown error') + '</p></div></div>';
    });
  }

  function renderPage(container, config) {
    var shieldIcon = SG.icon ? SG.icon('shield', 20) : '';

    // If scanning is not available (503), show info message
    if (!config) {
      container.innerHTML =
        '<div class="security-header"><div><h1>Security</h1>' +
        '<p class="security-header-desc">Configure response content scanning, outbound control, and security features.</p></div></div>' +
        '<div class="card"><div class="card-header"><h3 class="card-title">' + shieldIcon + ' Content Scanning</h3></div>' +
        '<div class="card-body" style="padding: var(--space-6);">' +
        '<p style="color: var(--text-muted);">Content scanning is not available. The response scan interceptor may not be configured.</p></div></div>' +
        '<div id="outbound-section"></div>' +
        '<div id="httpgw-section"></div>';
      renderOutboundSection(document.getElementById('outbound-section'));
      renderHTTPGatewaySection(document.getElementById('httpgw-section'));
      return;
    }

    var enabled = config.enabled;
    var mode = config.mode || 'monitor';

    container.innerHTML =
      '<div class="security-header">' +
        '<div>' +
          '<h1>Security</h1>' +
          '<p class="security-header-desc">Configure response content scanning, outbound control, and security features.</p>' +
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

        '</div>' +
      '</div>' +

      /* Outbound Control section container */
      '<div id="outbound-section"></div>' +

      /* HTTP Gateway section container */
      '<div id="httpgw-section"></div>';

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

    // Render outbound section
    renderOutboundSection(document.getElementById('outbound-section'));

    // Render HTTP Gateway section
    renderHTTPGatewaySection(document.getElementById('httpgw-section'));
  }

  // -- Outbound Control Section -----------------------------------------------

  function renderOutboundSection(sectionEl) {
    if (!sectionEl) return;

    if (!outboundAvailable) {
      sectionEl.innerHTML =
        '<div class="card security-section">' +
          '<div class="card-header"><h3 class="card-title">' + (SG.icon ? SG.icon('shield', 20) : '') + ' Outbound Control</h3></div>' +
          '<div class="card-body" style="padding: var(--space-6);">' +
            '<p style="color: var(--text-muted);">Outbound control is not available. The outbound admin service may not be configured.</p>' +
          '</div>' +
        '</div>';
      return;
    }

    sectionEl.innerHTML =
      '<div id="outbound-stats-container"></div>' +
      '<div id="outbound-rules-container"></div>' +
      '<div id="outbound-test-container"></div>';

    renderOutboundStats(document.getElementById('outbound-stats-container'));
    renderOutboundRuleList(document.getElementById('outbound-rules-container'));
    renderOutboundTestPanel(document.getElementById('outbound-test-container'));
  }

  function renderOutboundStats(el) {
    if (!el || !outboundStats) return;

    var s = outboundStats;
    el.innerHTML =
      '<div class="outbound-stats-bar">' +
        '<div class="outbound-stat"><div class="outbound-stat-value">' + s.total_rules + '</div><div class="outbound-stat-label">Total Rules</div></div>' +
        '<div class="outbound-stat"><div class="outbound-stat-value">' + s.enabled_rules + '</div><div class="outbound-stat-label">Enabled</div></div>' +
        '<div class="outbound-stat"><div class="outbound-stat-value">' + s.blocklist_rules + '</div><div class="outbound-stat-label">Blocklist</div></div>' +
        '<div class="outbound-stat"><div class="outbound-stat-value">' + s.allowlist_rules + '</div><div class="outbound-stat-label">Allowlist</div></div>' +
        '<div class="outbound-stat"><div class="outbound-stat-value">' + s.default_rules + '</div><div class="outbound-stat-label">Default</div></div>' +
        '<div class="outbound-stat"><div class="outbound-stat-value">' + s.custom_rules + '</div><div class="outbound-stat-label">Custom</div></div>' +
      '</div>';
  }

  function renderOutboundRuleList(el) {
    if (!el) return;

    var shieldIcon = SG.icon ? SG.icon('shield', 20) : '';
    var plusIcon = SG.icon ? SG.icon('plus', 16) : '+';

    var hasCustom = outboundRules.some(function (r) { return !r.read_only; });

    el.innerHTML =
      '<div class="card security-section">' +
        '<div class="card-header card-header-actions">' +
          '<h3 class="card-title">' + shieldIcon + ' Outbound Control</h3>' +
          '<button class="btn btn-primary btn-sm" id="add-outbound-rule-btn">' + plusIcon + ' Add Rule</button>' +
        '</div>' +
        '<div class="card-body" style="padding: 0;" id="outbound-rule-list-body"></div>' +
      '</div>';

    var listBody = document.getElementById('outbound-rule-list-body');

    if (outboundRules.length === 0) {
      listBody.innerHTML = '<div class="outbound-empty">No outbound rules configured. The default blocklist may not be loaded.</div>';
    } else {
      var html = '';
      for (var i = 0; i < outboundRules.length; i++) {
        var r = outboundRules[i];
        html += buildRuleRow(r);
      }
      listBody.innerHTML = html;

      // Wire enable toggles
      for (var j = 0; j < outboundRules.length; j++) {
        wireRuleRowEvents(outboundRules[j]);
      }
    }

    if (!hasCustom && outboundRules.length > 0) {
      var emptyNote = document.createElement('div');
      emptyNote.className = 'outbound-empty';
      emptyNote.style.paddingTop = '0';
      emptyNote.textContent = 'No custom outbound rules yet. The default blocklist is active.';
      listBody.appendChild(emptyNote);
    }

    // Wire Add Rule button
    var addBtn = document.getElementById('add-outbound-rule-btn');
    if (addBtn) {
      addBtn.addEventListener('click', function () {
        openRuleModal(null);
      });
    }
  }

  function buildRuleRow(r) {
    var lockHtml = (r.read_only && r.enabled) ? '<span class="lock-icon" title="Default rule (read-only)">&#128274;</span>' : '';
    var toggleChecked = r.enabled ? 'checked' : '';
    var actionsHtml = '';

    if (!r.read_only) {
      actionsHtml =
        '<button class="edit-rule-btn" data-id="' + esc(r.id) + '" title="Edit">Edit</button>' +
        '<button class="delete-rule-btn delete-btn" data-id="' + esc(r.id) + '" data-name="' + esc(r.name) + '" title="Delete">Delete</button>';
    }

    return '<div class="outbound-rule-row" data-rule-id="' + esc(r.id) + '">' +
      '<div class="outbound-rule-priority">' + r.priority + '</div>' +
      '<div class="outbound-rule-name">' + lockHtml + esc(r.name) + '</div>' +
      '<div>' + modeBadge(r.mode) + '</div>' +
      '<div>' + actionBadge(r.action) + '</div>' +
      '<div class="outbound-rule-targets">' + targetTags(r.targets || []) + '</div>' +
      '<label class="toggle-switch" style="margin: 0;">' +
        '<input type="checkbox" class="rule-enabled-toggle" data-id="' + esc(r.id) + '" ' + toggleChecked + '>' +
        '<span class="toggle-slider"></span>' +
      '</label>' +
      '<div class="outbound-rule-actions">' + actionsHtml + '</div>' +
    '</div>';
  }

  function wireRuleRowEvents(rule) {
    // Enable toggle
    var toggle = document.querySelector('.rule-enabled-toggle[data-id="' + rule.id + '"]');
    if (toggle) {
      toggle.addEventListener('change', function () {
        var newEnabled = toggle.checked;
        toggleRuleEnabled(rule, newEnabled, toggle);
      });
    }

    // Edit button
    var editBtn = document.querySelector('.edit-rule-btn[data-id="' + rule.id + '"]');
    if (editBtn) {
      editBtn.addEventListener('click', function () {
        openRuleModal(rule);
      });
    }

    // Delete button
    var deleteBtn = document.querySelector('.delete-rule-btn[data-id="' + rule.id + '"]');
    if (deleteBtn) {
      deleteBtn.addEventListener('click', function () {
        confirmDeleteRule(rule);
      });
    }
  }

  function toggleRuleEnabled(rule, newEnabled) {
    // Disable ALL rule toggles during update to prevent concurrent requests.
    var allToggles = document.querySelectorAll('.rule-enabled-toggle');
    for (var i = 0; i < allToggles.length; i++) allToggles[i].disabled = true;

    SG.api.put('/v1/security/outbound/rules/' + rule.id, {
      name: rule.name,
      mode: rule.mode,
      action: rule.action,
      targets: rule.targets,
      priority: rule.priority,
      enabled: newEnabled,
      base64_scan: rule.base64_scan,
      scope: rule.scope || '',
      help_text: rule.help_text || '',
      help_url: rule.help_url || '',
    }).then(function () {
      SG.toast.success('Rule ' + (newEnabled ? 'enabled' : 'disabled'));
      return refreshOutbound();
    }).catch(function (err) {
      SG.toast.error('Failed to update rule: ' + (err.message || 'Unknown error'));
      return refreshOutbound();
    });
  }

  function confirmDeleteRule(rule) {
    SG.modal.confirm({
      title: 'Delete rule "' + rule.name + '"?',
      message: 'This action cannot be undone.',
      confirmText: 'Delete',
      confirmClass: 'btn-danger',
      onConfirm: function () {
        SG.api.del('/v1/security/outbound/rules/' + rule.id).then(function () {
          SG.toast.success('Rule deleted');
          refreshOutbound();
        }).catch(function (err) {
          SG.toast.error('Failed to delete rule: ' + (err.message || 'Unknown error'));
        });
      },
    });
  }

  function refreshOutbound() {
    return Promise.all([loadOutboundRules(), loadOutboundStats()]).then(function () {
      var statsEl = document.getElementById('outbound-stats-container');
      var rulesEl = document.getElementById('outbound-rules-container');
      if (statsEl) renderOutboundStats(statsEl);
      if (rulesEl) renderOutboundRuleList(rulesEl);
    });
  }

  // -- Rule Add/Edit Modal ----------------------------------------------------

  function openRuleModal(existingRule) {
    var isEdit = !!existingRule;
    var title = isEdit ? 'Edit Outbound Rule' : 'Add Outbound Rule';
    var targets = isEdit ? (existingRule.targets || []).slice() : [];

    var bodyEl = document.createElement('div');

    // Name
    var nameGroup = makeFormGroup('Name *', 'text', 'ob-rule-name', existingRule ? existingRule.name : '', 'Rule name');
    bodyEl.appendChild(nameGroup);

    // Mode and Action row
    var modeActionRow = document.createElement('div');
    modeActionRow.className = 'ob-form-row';

    var modeGroup = document.createElement('div');
    modeGroup.className = 'ob-form-group';
    modeGroup.innerHTML =
      '<label>Mode</label>' +
      '<div class="ob-radio-group">' +
        '<label><input type="radio" name="ob-rule-mode" value="blocklist" ' + (!isEdit || existingRule.mode === 'blocklist' ? 'checked' : '') + '> Blocklist</label>' +
        '<label><input type="radio" name="ob-rule-mode" value="allowlist" ' + (isEdit && existingRule.mode === 'allowlist' ? 'checked' : '') + '> Allowlist</label>' +
      '</div>';

    var actionGroup = document.createElement('div');
    actionGroup.className = 'ob-form-group';
    actionGroup.innerHTML =
      '<label>Action</label>' +
      '<div class="ob-radio-group">' +
        '<label><input type="radio" name="ob-rule-action" value="block" ' + (!isEdit || existingRule.action === 'block' ? 'checked' : '') + '> Block</label>' +
        '<label><input type="radio" name="ob-rule-action" value="alert" ' + (isEdit && existingRule.action === 'alert' ? 'checked' : '') + '> Alert</label>' +
        '<label><input type="radio" name="ob-rule-action" value="log" ' + (isEdit && existingRule.action === 'log' ? 'checked' : '') + '> Log</label>' +
      '</div>';

    modeActionRow.appendChild(modeGroup);
    modeActionRow.appendChild(actionGroup);
    bodyEl.appendChild(modeActionRow);

    // Priority and Enabled row
    var prioEnabledRow = document.createElement('div');
    prioEnabledRow.className = 'ob-form-row';

    var prioGroup = makeFormGroup('Priority', 'number', 'ob-rule-priority', isEdit ? existingRule.priority : 500, '500');
    var enabledGroup = document.createElement('div');
    enabledGroup.className = 'ob-form-group';
    enabledGroup.style.display = 'flex';
    enabledGroup.style.alignItems = 'flex-end';
    enabledGroup.style.paddingBottom = 'var(--space-1)';
    var enabledChecked = (!isEdit || existingRule.enabled) ? 'checked' : '';
    enabledGroup.innerHTML =
      '<label class="ob-checkbox-label"><input type="checkbox" id="ob-rule-enabled" ' + enabledChecked + '> Enabled</label>';

    prioEnabledRow.appendChild(prioGroup);
    prioEnabledRow.appendChild(enabledGroup);
    bodyEl.appendChild(prioEnabledRow);

    // Base64 scan checkbox
    var b64Group = document.createElement('div');
    b64Group.className = 'ob-form-group';
    var b64Checked = (isEdit && existingRule.base64_scan) ? 'checked' : '';
    b64Group.innerHTML =
      '<label class="ob-checkbox-label"><input type="checkbox" id="ob-rule-b64" ' + b64Checked + '> Enable Base64 Scanning</label>';
    bodyEl.appendChild(b64Group);

    // Help text and URL
    var helpGroup = document.createElement('div');
    helpGroup.className = 'ob-form-group';
    helpGroup.innerHTML = '<label>Help Text (optional)</label>';
    var helpTextarea = document.createElement('textarea');
    helpTextarea.id = 'ob-rule-helptext';
    helpTextarea.rows = 2;
    helpTextarea.placeholder = 'Shown in deny messages';
    helpTextarea.value = isEdit ? (existingRule.help_text || '') : '';
    helpGroup.appendChild(helpTextarea);
    bodyEl.appendChild(helpGroup);

    var helpUrlGroup = makeFormGroup('Help URL (optional)', 'text', 'ob-rule-helpurl', isEdit ? (existingRule.help_url || '') : '', 'https://docs.example.com/...');
    bodyEl.appendChild(helpUrlGroup);

    // Targets section
    var targetsSection = document.createElement('div');
    targetsSection.className = 'outbound-target-builder';
    targetsSection.innerHTML =
      '<label style="font-size: var(--text-xs); font-weight: var(--font-semibold); color: var(--text-secondary); display: block; margin-bottom: var(--space-2);">Targets *</label>' +
      '<div class="outbound-target-builder-list" id="ob-target-list"></div>' +
      '<div class="outbound-target-add-row">' +
        '<select id="ob-target-type-select">' +
          '<option value="domain">Domain</option>' +
          '<option value="ip">IP</option>' +
          '<option value="cidr">CIDR</option>' +
          '<option value="domain_glob">Domain Glob</option>' +
          '<option value="port_range">Port Range</option>' +
        '</select>' +
        '<input type="text" id="ob-target-value-input" placeholder="example.com" style="flex: 1;">' +
        '<button class="btn btn-secondary btn-sm" id="ob-add-target-btn">Add</button>' +
      '</div>';
    bodyEl.appendChild(targetsSection);

    // Footer
    var footerEl = document.createElement('div');
    footerEl.style.display = 'contents';

    var cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-secondary';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', function () { SG.modal.close(); });

    var saveBtn = document.createElement('button');
    saveBtn.className = 'btn btn-primary';
    saveBtn.textContent = isEdit ? 'Save Changes' : 'Create Rule';

    footerEl.appendChild(cancelBtn);
    footerEl.appendChild(saveBtn);

    SG.modal.open({
      title: title,
      body: bodyEl,
      footer: footerEl,
      width: '600px',
    });

    // Render existing targets
    renderTargetList(targets);

    // Wire target type select to update placeholder
    var typeSelect = document.getElementById('ob-target-type-select');
    var valueInput = document.getElementById('ob-target-value-input');
    if (typeSelect) {
      typeSelect.addEventListener('change', function () {
        valueInput.placeholder = TARGET_PLACEHOLDERS[typeSelect.value] || '';
      });
    }

    // Wire add target
    var addTargetBtn = document.getElementById('ob-add-target-btn');
    if (addTargetBtn) {
      addTargetBtn.addEventListener('click', function () {
        var type = typeSelect.value;
        var val = valueInput.value.trim();
        if (!val) return;
        targets.push({ type: type, value: val });
        renderTargetList(targets);
        valueInput.value = '';
      });
    }

    // Wire save
    saveBtn.addEventListener('click', function () {
      var name = document.getElementById('ob-rule-name').value.trim();
      var modeRadio = document.querySelector('input[name="ob-rule-mode"]:checked');
      var actionRadio = document.querySelector('input[name="ob-rule-action"]:checked');
      var priority = parseInt(document.getElementById('ob-rule-priority').value, 10) || 500;
      var enabledCheck = document.getElementById('ob-rule-enabled');
      var b64Check = document.getElementById('ob-rule-b64');
      var helpText = document.getElementById('ob-rule-helptext').value;
      var helpUrl = document.getElementById('ob-rule-helpurl').value;

      if (!name) {
        SG.toast.error('Name is required');
        return;
      }
      if (targets.length === 0) {
        SG.toast.error('At least one target is required');
        return;
      }

      var payload = {
        name: name,
        mode: modeRadio ? modeRadio.value : 'blocklist',
        action: actionRadio ? actionRadio.value : 'block',
        priority: priority,
        enabled: enabledCheck ? enabledCheck.checked : true,
        base64_scan: b64Check ? b64Check.checked : false,
        targets: targets,
        help_text: helpText,
        help_url: helpUrl,
        scope: '',
      };

      saveBtn.disabled = true;
      saveBtn.textContent = 'Saving...';

      var apiCall;
      if (isEdit) {
        apiCall = SG.api.put('/v1/security/outbound/rules/' + existingRule.id, payload);
      } else {
        apiCall = SG.api.post('/v1/security/outbound/rules', payload);
      }

      apiCall.then(function () {
        SG.modal.close();
        SG.toast.success(isEdit ? 'Rule updated' : 'Rule created');
        refreshOutbound();
      }).catch(function (err) {
        saveBtn.disabled = false;
        saveBtn.textContent = isEdit ? 'Save Changes' : 'Create Rule';
        SG.toast.error('Failed: ' + (err.message || 'Unknown error'));
      });
    });
  }

  function renderTargetList(targets) {
    var listEl = document.getElementById('ob-target-list');
    if (!listEl) return;

    if (targets.length === 0) {
      listEl.innerHTML = '<p style="color: var(--text-muted); font-size: var(--text-xs); margin: 0;">No targets added yet.</p>';
      return;
    }

    listEl.innerHTML = '';
    for (var i = 0; i < targets.length; i++) {
      (function (idx) {
        var item = document.createElement('div');
        item.className = 'outbound-target-builder-item';

        var typeSpan = document.createElement('span');
        typeSpan.className = 'target-type';
        typeSpan.textContent = TARGET_LABELS[targets[idx].type] || targets[idx].type;

        var valueSpan = document.createElement('span');
        valueSpan.className = 'target-value';
        valueSpan.textContent = targets[idx].value;

        var removeBtn = document.createElement('button');
        removeBtn.className = 'btn btn-secondary btn-sm';
        removeBtn.textContent = 'Remove';
        removeBtn.style.padding = '2px 8px';
        removeBtn.style.fontSize = '11px';
        removeBtn.addEventListener('click', function () {
          targets.splice(idx, 1);
          renderTargetList(targets);
        });

        item.appendChild(typeSpan);
        item.appendChild(valueSpan);
        item.appendChild(removeBtn);
        listEl.appendChild(item);
      })(i);
    }
  }

  function makeFormGroup(label, type, id, value, placeholder) {
    var group = document.createElement('div');
    group.className = 'ob-form-group';
    var lbl = document.createElement('label');
    lbl.textContent = label;
    group.appendChild(lbl);
    var input = document.createElement('input');
    input.type = type;
    input.id = id;
    input.value = value != null ? value : '';
    input.placeholder = placeholder || '';
    group.appendChild(input);
    return group;
  }

  // -- Test Panel -------------------------------------------------------------

  function renderOutboundTestPanel(el) {
    if (!el) return;

    el.innerHTML =
      '<div class="card security-section">' +
        '<div class="card-header">' +
          '<h3 class="card-title">' + (SG.icon ? SG.icon('zap', 20) : '') + ' Test Destination</h3>' +
        '</div>' +
        '<div class="card-body" style="padding: var(--space-6);">' +
          '<p style="font-size: var(--text-sm); color: var(--text-secondary); margin-bottom: var(--space-4);">' +
            'Test whether a destination would be blocked or allowed by the current outbound rules.' +
          '</p>' +
          '<div class="ob-form-row">' +
            '<div class="ob-form-group">' +
              '<label>Domain</label>' +
              '<input type="text" id="test-domain" class="form-input" placeholder="e.g. evil.ngrok.io">' +
            '</div>' +
            '<div class="ob-form-group">' +
              '<label>IP (optional)</label>' +
              '<input type="text" id="test-ip" class="form-input" placeholder="e.g. 10.0.0.1">' +
            '</div>' +
            '<div class="ob-form-group" style="max-width: 100px;">' +
              '<label>Port</label>' +
              '<input type="number" id="test-port" class="form-input" placeholder="443">' +
            '</div>' +
          '</div>' +
          '<button class="btn btn-primary" id="test-outbound-btn">Test</button>' +
          '<div id="test-outbound-result"></div>' +
        '</div>' +
      '</div>';

    var testBtn = document.getElementById('test-outbound-btn');
    if (testBtn) {
      testBtn.addEventListener('click', function () {
        var domain = document.getElementById('test-domain').value.trim();
        var ip = document.getElementById('test-ip').value.trim();
        var port = parseInt(document.getElementById('test-port').value, 10) || 0;

        if (!domain && !ip) {
          SG.toast.error('Enter a domain or IP to test');
          return;
        }

        testBtn.disabled = true;
        testBtn.textContent = 'Testing...';

        SG.api.post('/v1/security/outbound/test', {
          domain: domain,
          ip: ip,
          port: port,
        }).then(function (result) {
          testBtn.disabled = false;
          testBtn.textContent = 'Test';
          renderTestResult(result);
        }).catch(function (err) {
          testBtn.disabled = false;
          testBtn.textContent = 'Test';
          SG.toast.error('Test failed: ' + (err.message || 'Unknown error'));
        });
      });
    }
  }

  function renderTestResult(result) {
    var el = document.getElementById('test-outbound-result');
    if (!el) return;

    if (result.blocked) {
      var ruleInfo = '';
      if (result.rule) {
        ruleInfo = '<div style="margin-top: var(--space-2); font-size: var(--text-sm); color: var(--text-secondary);">' +
          '<strong>Rule:</strong> ' + esc(result.rule.name) + '</div>';
        if (result.rule.help_text) {
          ruleInfo += '<div style="margin-top: var(--space-1); font-size: var(--text-xs); color: var(--text-muted);">' + esc(result.rule.help_text) + '</div>';
        }
      }
      el.innerHTML =
        '<div class="outbound-test-result blocked">' +
          '<span class="outbound-test-badge blocked">Blocked</span>' +
          ruleInfo +
        '</div>';
    } else {
      el.innerHTML =
        '<div class="outbound-test-result allowed">' +
          '<span class="outbound-test-badge allowed">Allowed</span>' +
          '<div style="margin-top: var(--space-2); font-size: var(--text-sm); color: var(--text-secondary);">' + esc(result.message) + '</div>' +
        '</div>';
    }
  }

  // -- HTTP Gateway Section ----------------------------------------------------

  function renderHTTPGatewaySection(sectionEl) {
    if (!sectionEl) return;

    if (!httpGatewayAvailable) {
      sectionEl.innerHTML =
        '<div class="card security-section">' +
          '<div class="card-header"><h3 class="card-title">' + (SG.icon ? SG.icon('globe', 20) : '') + ' HTTP Gateway</h3></div>' +
          '<div class="card-body" style="padding: var(--space-6);">' +
            '<p style="color: var(--text-muted);">HTTP Gateway is not available. Enable it in your configuration file.</p>' +
          '</div>' +
        '</div>';
      return;
    }

    var globeIcon = SG.icon ? SG.icon('globe', 20) : '';
    var plusIcon = SG.icon ? SG.icon('plus', 16) : '+';

    var tlsEnabled = httpGatewayConfig && httpGatewayConfig.tls_inspection ? httpGatewayConfig.tls_inspection.enabled : false;
    var bypassList = httpGatewayConfig && httpGatewayConfig.tls_inspection ? (httpGatewayConfig.tls_inspection.bypass_list || []) : [];
    var targets = httpGatewayConfig ? (httpGatewayConfig.targets || []) : [];

    sectionEl.innerHTML =
      '<div class="card security-section">' +
        '<div class="card-header">' +
          '<h3 class="card-title">' + globeIcon + ' HTTP Gateway</h3>' +
        '</div>' +
        '<div class="card-body" style="padding: var(--space-6);">' +

          '<p style="font-size: var(--text-sm); color: var(--text-secondary); margin-bottom: var(--space-4);">' +
            'Configure the HTTP Gateway for forward and reverse proxy with TLS inspection, bypass domains, and upstream targets.' +
          '</p>' +

          /* TLS Inspection toggle */
          '<div class="toggle-row">' +
            '<div class="toggle-label">' +
              '<span class="toggle-label-title">TLS Inspection</span>' +
              '<span class="toggle-label-desc">When enabled, HTTPS requests are intercepted for content scanning. Requires the CA certificate to be trusted by clients.</span>' +
            '</div>' +
            '<div style="display: flex; align-items: center; gap: var(--space-3);">' +
              '<span class="security-status ' + (tlsEnabled ? 'security-status-monitor' : 'security-status-disabled') + '" id="httpgw-tls-badge">' +
                (tlsEnabled ? 'Enabled' : 'Disabled') +
              '</span>' +
              '<label class="toggle-switch">' +
                '<input type="checkbox" id="httpgw-tls-enabled" ' + (tlsEnabled ? 'checked' : '') + '>' +
                '<span class="toggle-slider"></span>' +
              '</label>' +
            '</div>' +
          '</div>' +

          /* CA trust banner */
          '<div class="ca-trust-banner" id="httpgw-ca-trust-banner" style="display: ' + (tlsEnabled ? 'flex' : 'none') + ';">' +
            '<svg class="ca-trust-banner-icon" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"/></svg>' +
            '<div>' +
              '<strong>Trust the CA certificate</strong>' +
              '<p>Run this command to add the CA to your system trust store:</p>' +
              '<code>sentinel-gate trust-ca</code>' +
              '<button class="btn btn-secondary btn-sm btn-copy" id="httpgw-ca-copy-btn">Copy</button>' +
            '</div>' +
          '</div>' +

          /* Bypass list */
          '<div style="margin-bottom: var(--space-4);">' +
            '<div style="font-size: var(--text-sm); font-weight: var(--font-semibold); color: var(--text-primary); margin-bottom: var(--space-2);">Bypass Domains</div>' +
            '<div style="font-size: var(--text-xs); color: var(--text-muted); margin-bottom: var(--space-2);">Domains matching these patterns will not be TLS-inspected. Supports glob patterns (e.g. *.google.com).</div>' +
            '<div class="httpgw-bypass-list" id="httpgw-bypass-list"></div>' +
            '<div class="httpgw-bypass-add">' +
              '<input type="text" id="httpgw-bypass-input" placeholder="*.example.com">' +
              '<button class="btn btn-secondary btn-sm" id="httpgw-bypass-add-btn">Add</button>' +
              '<button class="btn btn-primary btn-sm" id="httpgw-bypass-save-btn">Save Bypass List</button>' +
            '</div>' +
          '</div>' +

          /* Downloads */
          '<div class="httpgw-download-row">' +
            '<button class="btn btn-secondary" id="httpgw-dl-ca">' + (SG.icon ? SG.icon('download', 16) : '') + ' Download CA Certificate</button>' +
            '<button class="btn btn-secondary" id="httpgw-dl-script">' + (SG.icon ? SG.icon('download', 16) : '') + ' Download Setup Script</button>' +
          '</div>' +

        '</div>' +
      '</div>' +

      /* Upstream Targets card */
      '<div class="card security-section">' +
        '<div class="card-header card-header-actions">' +
          '<h3 class="card-title">' + globeIcon + ' Upstream Targets</h3>' +
          '<button class="btn btn-primary btn-sm" id="httpgw-add-target-btn">' + plusIcon + ' Add Target</button>' +
        '</div>' +
        '<div class="card-body" style="padding: 0;" id="httpgw-target-list"></div>' +
      '</div>';

    // Render bypass list
    var currentBypass = bypassList.slice();
    renderBypassList(currentBypass);

    // Wire TLS toggle
    var tlsToggle = document.getElementById('httpgw-tls-enabled');
    if (tlsToggle) {
      tlsToggle.addEventListener('change', function () {
        var newEnabled = tlsToggle.checked;
        SG.api.put('/v1/security/http-gateway/tls', {
          enabled: newEnabled,
          bypass_list: currentBypass,
        }).then(function () {
          SG.toast.success('TLS inspection ' + (newEnabled ? 'enabled' : 'disabled'));
          var badge = document.getElementById('httpgw-tls-badge');
          if (badge) {
            badge.className = 'security-status ' + (newEnabled ? 'security-status-monitor' : 'security-status-disabled');
            badge.textContent = newEnabled ? 'Enabled' : 'Disabled';
          }
          if (httpGatewayConfig && httpGatewayConfig.tls_inspection) {
            httpGatewayConfig.tls_inspection.enabled = newEnabled;
          }
          var banner = document.getElementById('httpgw-ca-trust-banner');
          if (banner) {
            banner.style.display = newEnabled ? 'flex' : 'none';
          }
        }).catch(function (err) {
          SG.toast.error('Failed to update TLS: ' + (err.message || 'Unknown error'));
          tlsToggle.checked = !newEnabled;
        });
      });
    }

    // Wire CA trust copy button
    var caCopyBtn = document.getElementById('httpgw-ca-copy-btn');
    if (caCopyBtn) {
      caCopyBtn.addEventListener('click', function () {
        navigator.clipboard.writeText('sentinel-gate trust-ca').then(function () {
          caCopyBtn.textContent = 'Copied!';
          setTimeout(function () { caCopyBtn.textContent = 'Copy'; }, 2000);
        });
      });
    }

    // Wire bypass list add
    var bypassInput = document.getElementById('httpgw-bypass-input');
    var bypassAddBtn = document.getElementById('httpgw-bypass-add-btn');
    if (bypassAddBtn) {
      bypassAddBtn.addEventListener('click', function () {
        var val = bypassInput.value.trim();
        if (!val) return;
        if (currentBypass.indexOf(val) === -1) {
          currentBypass.push(val);
          renderBypassList(currentBypass);
        }
        bypassInput.value = '';
      });
    }

    // Wire bypass list save
    var bypassSaveBtn = document.getElementById('httpgw-bypass-save-btn');
    if (bypassSaveBtn) {
      bypassSaveBtn.addEventListener('click', function () {
        bypassSaveBtn.disabled = true;
        bypassSaveBtn.textContent = 'Saving...';
        SG.api.put('/v1/security/http-gateway/tls', {
          enabled: tlsToggle ? tlsToggle.checked : tlsEnabled,
          bypass_list: currentBypass,
        }).then(function () {
          bypassSaveBtn.disabled = false;
          bypassSaveBtn.textContent = 'Save Bypass List';
          SG.toast.success('Bypass list updated');
          if (httpGatewayConfig && httpGatewayConfig.tls_inspection) {
            httpGatewayConfig.tls_inspection.bypass_list = currentBypass.slice();
          }
        }).catch(function (err) {
          bypassSaveBtn.disabled = false;
          bypassSaveBtn.textContent = 'Save Bypass List';
          SG.toast.error('Failed to save: ' + (err.message || 'Unknown error'));
        });
      });
    }

    // Wire download buttons
    var dlCaBtn = document.getElementById('httpgw-dl-ca');
    if (dlCaBtn) {
      dlCaBtn.addEventListener('click', function () {
        window.location = '/admin/api/v1/security/http-gateway/ca-cert';
      });
    }
    var dlScriptBtn = document.getElementById('httpgw-dl-script');
    if (dlScriptBtn) {
      dlScriptBtn.addEventListener('click', function () {
        window.location = '/admin/api/v1/security/http-gateway/setup-script';
      });
    }

    // Render target list
    renderHTTPGatewayTargets(targets);

    // Wire Add Target button
    var addTargetBtn = document.getElementById('httpgw-add-target-btn');
    if (addTargetBtn) {
      addTargetBtn.addEventListener('click', function () {
        openHTTPGatewayTargetModal(null);
      });
    }

    // Helper: renderBypassList
    function renderBypassList(list) {
      var el = document.getElementById('httpgw-bypass-list');
      if (!el) return;
      if (list.length === 0) {
        el.innerHTML = '<span style="color: var(--text-muted); font-size: var(--text-xs);">No bypass domains configured.</span>';
        return;
      }
      el.innerHTML = '';
      for (var i = 0; i < list.length; i++) {
        (function (idx) {
          var tag = document.createElement('span');
          tag.className = 'httpgw-bypass-tag';
          var text = document.createElement('span');
          text.textContent = list[idx];
          var removeBtn = document.createElement('button');
          removeBtn.innerHTML = '&times;';
          removeBtn.title = 'Remove';
          removeBtn.addEventListener('click', function () {
            currentBypass.splice(idx, 1);
            renderBypassList(currentBypass);
          });
          tag.appendChild(text);
          tag.appendChild(removeBtn);
          el.appendChild(tag);
        })(i);
      }
    }
  }

  function renderHTTPGatewayTargets(targets) {
    var listEl = document.getElementById('httpgw-target-list');
    if (!listEl) return;

    if (targets.length === 0) {
      listEl.innerHTML = '<div class="outbound-empty">No upstream targets configured.</div>';
      return;
    }

    var html = '';
    for (var i = 0; i < targets.length; i++) {
      var t = targets[i];
      var toggleChecked = t.enabled ? 'checked' : '';
      html +=
        '<div class="httpgw-target-row" data-target-id="' + esc(t.id) + '">' +
          '<div class="httpgw-target-name">' + esc(t.name) + '</div>' +
          '<div class="httpgw-target-prefix">' + esc(t.path_prefix) + '</div>' +
          '<div class="httpgw-target-upstream">' + esc(t.upstream) + '</div>' +
          '<span class="outbound-target-tag">' + (t.strip_prefix ? 'strip' : 'keep') + '</span>' +
          '<label class="toggle-switch" style="margin: 0;">' +
            '<input type="checkbox" class="httpgw-target-toggle" data-id="' + esc(t.id) + '" ' + toggleChecked + '>' +
            '<span class="toggle-slider"></span>' +
          '</label>' +
          '<div class="outbound-rule-actions">' +
            '<button class="httpgw-edit-target-btn" data-id="' + esc(t.id) + '">Edit</button>' +
            '<button class="httpgw-delete-target-btn delete-btn" data-id="' + esc(t.id) + '" data-name="' + esc(t.name) + '">Delete</button>' +
          '</div>' +
        '</div>';
    }
    listEl.innerHTML = html;

    // Wire events for each target
    for (var j = 0; j < targets.length; j++) {
      wireHTTPGatewayTargetEvents(targets[j]);
    }
  }

  function wireHTTPGatewayTargetEvents(target) {
    // Edit
    var editBtn = document.querySelector('.httpgw-edit-target-btn[data-id="' + target.id + '"]');
    if (editBtn) {
      editBtn.addEventListener('click', function () {
        openHTTPGatewayTargetModal(target);
      });
    }
    // Delete
    var deleteBtn = document.querySelector('.httpgw-delete-target-btn[data-id="' + target.id + '"]');
    if (deleteBtn) {
      deleteBtn.addEventListener('click', function () {
        SG.modal.confirm({
          title: 'Delete target "' + target.name + '"?',
          message: 'This action cannot be undone.',
          confirmText: 'Delete',
          confirmClass: 'btn-danger',
          onConfirm: function () {
            SG.api.del('/v1/security/http-gateway/targets/' + target.id).then(function () {
              SG.toast.success('Target deleted');
              refreshHTTPGateway();
            }).catch(function (err) {
              SG.toast.error('Failed to delete: ' + (err.message || 'Unknown error'));
            });
          },
        });
      });
    }
    // Enable toggle
    var toggle = document.querySelector('.httpgw-target-toggle[data-id="' + target.id + '"]');
    if (toggle) {
      toggle.addEventListener('change', function () {
        SG.api.put('/v1/security/http-gateway/targets/' + target.id, {
          name: target.name,
          path_prefix: target.path_prefix,
          upstream: target.upstream,
          strip_prefix: target.strip_prefix,
          headers: target.headers || {},
          enabled: toggle.checked,
        }).then(function () {
          SG.toast.success('Target ' + (toggle.checked ? 'enabled' : 'disabled'));
          refreshHTTPGateway();
        }).catch(function (err) {
          SG.toast.error('Failed to update: ' + (err.message || 'Unknown error'));
          refreshHTTPGateway();
        });
      });
    }
  }

  function openHTTPGatewayTargetModal(existingTarget) {
    var isEdit = !!existingTarget;
    var title = isEdit ? 'Edit Upstream Target' : 'Add Upstream Target';

    var bodyEl = document.createElement('div');

    // Name
    var nameGroup = makeFormGroup('Name *', 'text', 'httpgw-target-name', existingTarget ? existingTarget.name : '', 'My API');
    bodyEl.appendChild(nameGroup);

    // Path Prefix
    var prefixGroup = makeFormGroup('Path Prefix *', 'text', 'httpgw-target-prefix', existingTarget ? existingTarget.path_prefix : '/', '/api/openai/');
    bodyEl.appendChild(prefixGroup);

    // Upstream URL
    var upstreamGroup = makeFormGroup('Upstream URL *', 'text', 'httpgw-target-upstream', existingTarget ? existingTarget.upstream : '', 'https://api.openai.com');
    bodyEl.appendChild(upstreamGroup);

    // Strip prefix checkbox
    var stripGroup = document.createElement('div');
    stripGroup.className = 'ob-form-group';
    var stripChecked = (isEdit && existingTarget.strip_prefix) ? 'checked' : '';
    if (!isEdit) stripChecked = 'checked'; // default to strip
    stripGroup.innerHTML =
      '<label class="ob-checkbox-label"><input type="checkbox" id="httpgw-target-strip" ' + stripChecked + '> Strip path prefix before forwarding</label>';
    bodyEl.appendChild(stripGroup);

    // Enabled checkbox
    var enabledGroup = document.createElement('div');
    enabledGroup.className = 'ob-form-group';
    var enabledChecked = (!isEdit || existingTarget.enabled) ? 'checked' : '';
    enabledGroup.innerHTML =
      '<label class="ob-checkbox-label"><input type="checkbox" id="httpgw-target-enabled" ' + enabledChecked + '> Enabled</label>';
    bodyEl.appendChild(enabledGroup);

    // Footer
    var footerEl = document.createElement('div');
    footerEl.style.display = 'contents';

    var cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-secondary';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', function () { SG.modal.close(); });

    var saveBtn = document.createElement('button');
    saveBtn.className = 'btn btn-primary';
    saveBtn.textContent = isEdit ? 'Save Changes' : 'Create Target';

    footerEl.appendChild(cancelBtn);
    footerEl.appendChild(saveBtn);

    SG.modal.open({
      title: title,
      body: bodyEl,
      footer: footerEl,
      width: '500px',
    });

    // Wire save
    saveBtn.addEventListener('click', function () {
      var name = document.getElementById('httpgw-target-name').value.trim();
      var prefix = document.getElementById('httpgw-target-prefix').value.trim();
      var upstream = document.getElementById('httpgw-target-upstream').value.trim();
      var strip = document.getElementById('httpgw-target-strip').checked;
      var enabled = document.getElementById('httpgw-target-enabled').checked;

      if (!name) { SG.toast.error('Name is required'); return; }
      if (!prefix || prefix[0] !== '/') { SG.toast.error('Path prefix must start with /'); return; }
      if (!upstream) { SG.toast.error('Upstream URL is required'); return; }

      var payload = {
        name: name,
        path_prefix: prefix,
        upstream: upstream,
        strip_prefix: strip,
        headers: {},
        enabled: enabled,
      };

      saveBtn.disabled = true;
      saveBtn.textContent = 'Saving...';

      var apiCall;
      if (isEdit) {
        apiCall = SG.api.put('/v1/security/http-gateway/targets/' + existingTarget.id, payload);
      } else {
        apiCall = SG.api.post('/v1/security/http-gateway/targets', payload);
      }

      apiCall.then(function () {
        SG.modal.close();
        SG.toast.success(isEdit ? 'Target updated' : 'Target created');
        refreshHTTPGateway();
      }).catch(function (err) {
        saveBtn.disabled = false;
        saveBtn.textContent = isEdit ? 'Save Changes' : 'Create Target';
        SG.toast.error('Failed: ' + (err.message || 'Unknown error'));
      });
    });
  }

  function refreshHTTPGateway() {
    loadHTTPGatewayConfig().then(function () {
      var sectionEl = document.getElementById('httpgw-section');
      if (sectionEl) renderHTTPGatewaySection(sectionEl);
    });
  }

  // -- Register with router ---------------------------------------------------

  SG.router.register('security', render);
})();
