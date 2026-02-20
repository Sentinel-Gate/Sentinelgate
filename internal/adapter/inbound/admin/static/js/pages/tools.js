/**
 * tools.js -- Tools & Rules page for SentinelGate admin UI.
 *
 * Displays all discovered tools grouped by upstream, with
 * expand/collapse sections, policy status badges, and filter
 * tabs per upstream. Foundation for all Phase 4 features.
 *
 * Data sources:
 *   GET /admin/api/tools      -> tool list with policy_status
 *   GET /admin/api/upstreams  -> upstream metadata + status
 *   GET /admin/api/policies   -> policy list with rules for rules section
 *
 * Design features:
 *   - Tools grouped by upstream with expand/collapse
 *   - Policy status badges: Allow (green), Deny (red), No rule (neutral, clickable)
 *   - Filter tabs: All + one per upstream with tool count
 *   - Query string ?upstream= pre-filter from dashboard link
 *   - Empty state when no tools/upstreams exist
 *   - Policy Rules section with flat rule list sorted by priority
 *   - Default rule protection (cannot delete)
 *   - Edit Rule modal with Simple (visual builder) and Advanced (CEL editor) tabs
 *   - CEL auto-generation from visual fields, and best-effort parse back
 *   - Tool name and badge clicks open rule modal with context
 *   - Policy Test playground with tool name autocomplete and inline results
 *   - All user data rendered via textContent (XSS-safe)
 *
 * Requirements:
 *   TOOL-01  Tool list grouped by upstream
 *   TOOL-02  Expand/collapse per upstream group
 *   TOOL-03  Policy status badges (Allow/Deny/No rule)
 *   TOOL-04  Filter tabs (All + per upstream)
 *   TOOL-05  Query string pre-filter (?upstream=)
 *   TOOL-06  Empty state for no tools
 *   TRUL-07  Add Upstream modal (stdio/HTTP, validation, API)
 *   TRUL-08  Policy Rules section with rule list
 *   TRUL-03  Click tool opens rule modal
 *   TRUL-09  Rule CRUD (add/edit/delete with confirmation)
 *   TRUL-10  Default rule protection
 *   TRUL-11  Edit Rule modal with Simple and Advanced tabs
 *   TRUL-12  Simple tab: visual rule builder with name, applies-to, action, priority
 *   TRUL-13  Advanced tab: CEL expression editor with variable reference
 *   TRUL-14  Policy Test playground with autocomplete and inline results
 *   TRUL-15  CEL conversion unit tests (tools_test.html)
 *   DPOL-02  Rules ordered by priority
 *   DPOL-03  Default deny rule cannot be deleted
 *   DPOL-04  No rule badge reflects default policy action
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // -- State ------------------------------------------------------------------

  var styleInjected = false;
  var tools = [];
  var upstreams = [];
  var policies = [];
  var conflicts = [];
  var activeFilter = 'all';
  var collapsedGroups = {};

  // -- Tools-specific styles --------------------------------------------------

  var TOOLS_CSS = [
    /* -- Page header -------------------------------------------------------- */
    '.tools-header {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  margin-bottom: var(--space-6);',
    '}',
    '.tools-header h1 {',
    '  font-size: var(--text-2xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0;',
    '  letter-spacing: -0.02em;',
    '}',
    '.tools-header-actions {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '}',

    /* -- Filter tabs -------------------------------------------------------- */
    '.tools-filter-tabs {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-1);',
    '  margin-bottom: var(--space-4);',
    '  border-bottom: 1px solid var(--border);',
    '  padding-bottom: 0;',
    '  overflow-x: auto;',
    '  scrollbar-width: none;',
    '}',
    '.tools-filter-tabs::-webkit-scrollbar { display: none; }',
    '.filter-tab {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-secondary);',
    '  background: none;',
    '  border: none;',
    '  border-bottom: 2px solid transparent;',
    '  cursor: pointer;',
    '  white-space: nowrap;',
    '  transition: all var(--transition-fast);',
    '  margin-bottom: -1px;',
    '}',
    '.filter-tab:hover {',
    '  color: var(--text-primary);',
    '  background: var(--bg-secondary);',
    '}',
    '.filter-tab.active {',
    '  color: var(--accent-text);',
    '  border-bottom-color: var(--accent);',
    '}',
    '.filter-tab-count {',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  background: var(--bg-elevated);',
    '  color: var(--text-muted);',
    '  padding: 1px 6px;',
    '  border-radius: var(--radius-full);',
    '  min-width: 20px;',
    '  text-align: center;',
    '}',
    '.filter-tab.active .filter-tab-count {',
    '  background: var(--accent-subtle);',
    '  color: var(--accent-text);',
    '}',

    /* -- Upstream group ----------------------------------------------------- */
    '.upstream-group {',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  margin-bottom: var(--space-3);',
    '  overflow: hidden;',
    '}',
    '.upstream-group-header {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3) var(--space-4);',
    '  cursor: pointer;',
    '  user-select: none;',
    '  transition: background var(--transition-fast);',
    '}',
    '.upstream-group-header:hover {',
    '  background: var(--bg-secondary);',
    '}',
    '.upstream-group-header .chevron-icon {',
    '  flex-shrink: 0;',
    '  color: var(--text-muted);',
    '  transition: transform var(--transition-fast);',
    '  display: flex;',
    '  align-items: center;',
    '}',
    '.upstream-group-header .chevron-icon.expanded {',
    '  transform: rotate(90deg);',
    '}',
    '.upstream-group-name {',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '  font-size: var(--text-sm);',
    '  flex: 1;',
    '  min-width: 0;',
    '}',
    '.upstream-group-actions {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  margin-left: auto;',
    '}',

    /* -- Upstream group body ------------------------------------------------ */
    '.upstream-group-body {',
    '  border-top: 1px solid var(--border);',
    '}',
    '.upstream-group-body.collapsed {',
    '  display: none;',
    '}',

    /* -- Tool row ----------------------------------------------------------- */
    '.tool-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3) var(--space-4);',
    '  border-bottom: 1px solid var(--border);',
    '  transition: background var(--transition-fast);',
    '}',
    '.tool-row:last-child {',
    '  border-bottom: none;',
    '}',
    '.tool-row:hover {',
    '  background: var(--bg-secondary);',
    '}',
    '.tool-name {',
    '  font-weight: var(--font-medium);',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  white-space: nowrap;',
    '}',
    '.tool-description {',
    '  flex: 1;',
    '  font-size: var(--text-xs);',
    '  color: var(--text-secondary);',
    '  white-space: nowrap;',
    '  overflow: hidden;',
    '  text-overflow: ellipsis;',
    '  min-width: 0;',
    '}',
    '.tool-badge {',
    '  flex-shrink: 0;',
    '}',

    /* -- No rule badge (clickable) ------------------------------------------ */
    '.no-rule-badge {',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '}',
    '.no-rule-badge:hover {',
    '  background: var(--bg-elevated);',
    '  opacity: 0.85;',
    '}',

    /* -- Stagger animation -------------------------------------------------- */
    '@keyframes toolsFadeUp {',
    '  from { opacity: 0; transform: translateY(8px); }',
    '  to   { opacity: 1; transform: translateY(0); }',
    '}',
    '.tools-enter {',
    '  animation: toolsFadeUp 0.35s ease both;',
    '}',

    /* -- Skeleton loading --------------------------------------------------- */
    '.tools-skeleton-group {',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  margin-bottom: var(--space-3);',
    '  padding: var(--space-4);',
    '}',
    '.tools-skeleton-header {',
    '  height: 20px;',
    '  width: 160px;',
    '  margin-bottom: var(--space-3);',
    '}',
    '.tools-skeleton-row {',
    '  height: 40px;',
    '  margin-bottom: var(--space-2);',
    '  border-radius: var(--radius-md);',
    '}',

    /* -- Add Upstream modal form ----------------------------------------- */
    '.add-upstream-form .form-group {',
    '  margin-bottom: var(--space-4);',
    '}',
    '.add-upstream-form .form-label {',
    '  display: block;',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-primary);',
    '  margin-bottom: var(--space-1);',
    '}',
    '.add-upstream-form .form-input,',
    '.add-upstream-form .form-select,',
    '.add-upstream-form .form-textarea {',
    '  width: 100%;',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-sm);',
    '  font-family: inherit;',
    '  color: var(--text-primary);',
    '  background: var(--bg-secondary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  outline: none;',
    '  transition: border-color var(--transition-fast);',
    '  box-sizing: border-box;',
    '}',
    '.add-upstream-form .form-textarea {',
    '  min-height: 72px;',
    '  resize: vertical;',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-xs);',
    '}',
    '.add-upstream-form .form-input:focus,',
    '.add-upstream-form .form-select:focus,',
    '.add-upstream-form .form-textarea:focus {',
    '  border-color: var(--accent);',
    '}',
    '.add-upstream-form .form-help {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  margin-top: var(--space-1);',
    '}',
    '.add-upstream-form .form-group.form-error .form-input,',
    '.add-upstream-form .form-group.form-error .form-select,',
    '.add-upstream-form .form-group.form-error .form-textarea {',
    '  border-color: var(--danger);',
    '}',
    '.add-upstream-form .form-error-text {',
    '  font-size: var(--text-xs);',
    '  color: var(--danger);',
    '  margin-top: var(--space-1);',
    '}',

    /* -- Dropdown --------------------------------------------------------- */
    '.dropdown-wrap {',
    '  position: relative;',
    '}',
    '.dropdown-menu {',
    '  position: absolute;',
    '  right: 0;',
    '  top: 100%;',
    '  margin-top: 4px;',
    '  background: var(--bg-elevated);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  box-shadow: var(--shadow-lg);',
    '  min-width: 160px;',
    '  z-index: 10;',
    '  display: none;',
    '}',
    '.dropdown-menu.open {',
    '  display: block;',
    '}',
    '.dropdown-item {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-secondary);',
    '  cursor: pointer;',
    '  transition: background var(--transition-fast);',
    '  border: none;',
    '  background: none;',
    '  width: 100%;',
    '  text-align: left;',
    '}',
    '.dropdown-item:hover {',
    '  background: var(--bg-secondary);',
    '}',
    '.dropdown-item-danger {',
    '  color: var(--danger);',
    '}',
    '.dropdown-item-danger:hover {',
    '  background: var(--danger-subtle, rgba(239,68,68,0.1));',
    '}',
    '.dropdown-divider {',
    '  height: 1px;',
    '  background: var(--border);',
    '  margin: var(--space-1) 0;',
    '}',

    /* -- Policy Rules section --------------------------------------------- */
    '.rules-section {',
    '  margin-top: var(--space-6);',
    '}',
    '.rules-header {',
    '  display: flex;',
    '  justify-content: space-between;',
    '  align-items: center;',
    '  margin-bottom: var(--space-4);',
    '}',
    '.rules-header h2 {',
    '  font-size: var(--text-xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0;',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '}',
    '.rule-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3);',
    '  border-bottom: 1px solid var(--border);',
    '  transition: background var(--transition-fast);',
    '}',
    '.rule-row:last-child {',
    '  border-bottom: none;',
    '}',
    '.rule-row:hover {',
    '  background: var(--bg-secondary);',
    '}',
    '.rule-priority {',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-muted);',
    '  min-width: 40px;',
    '  text-align: center;',
    '}',
    '.rule-info {',
    '  flex: 1;',
    '  min-width: 0;',
    '}',
    '.rule-name {',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-primary);',
    '}',
    '.rule-pattern {',
    '  font-size: var(--text-xs);',
    '  font-family: var(--font-mono);',
    '  color: var(--text-muted);',
    '  white-space: nowrap;',
    '  overflow: hidden;',
    '  text-overflow: ellipsis;',
    '}',
    '.rule-actions {',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  flex-shrink: 0;',
    '}',
    '.rule-default-label {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  font-style: italic;',
    '}',

    /* -- Spinning refresh icon -------------------------------------------- */
    '@keyframes spin {',
    '  from { transform: rotate(0deg); }',
    '  to { transform: rotate(360deg); }',
    '}',
    '.btn-spinning svg {',
    '  animation: spin 1s linear infinite;',
    '}',

    /* -- Rule modal form -------------------------------------------------- */
    '.rule-modal-form .form-group {',
    '  margin-bottom: var(--space-4);',
    '}',
    '.rule-modal-form .form-label {',
    '  display: block;',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-primary);',
    '  margin-bottom: var(--space-1);',
    '}',
    '.rule-modal-form .form-input,',
    '.rule-modal-form .form-select {',
    '  width: 100%;',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-sm);',
    '  font-family: inherit;',
    '  color: var(--text-primary);',
    '  background: var(--bg-secondary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  outline: none;',
    '  transition: border-color var(--transition-fast);',
    '  box-sizing: border-box;',
    '}',
    '.rule-modal-form .form-input:focus,',
    '.rule-modal-form .form-select:focus {',
    '  border-color: var(--accent);',
    '}',
    '.rule-modal-form .form-help {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  margin-top: var(--space-1);',
    '}',

    /* -- Rule modal tabs -------------------------------------------------- */
    '.rule-tabs {',
    '  display: flex;',
    '  border-bottom: 1px solid var(--border);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.rule-tab {',
    '  padding: var(--space-2) var(--space-4);',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-muted);',
    '  cursor: pointer;',
    '  border: none;',
    '  background: none;',
    '  border-bottom: 2px solid transparent;',
    '  transition: all var(--transition-fast);',
    '  margin-bottom: -1px;',
    '}',
    '.rule-tab:hover {',
    '  color: var(--text-secondary);',
    '}',
    '.rule-tab.active {',
    '  color: var(--accent-text);',
    '  border-bottom-color: var(--accent);',
    '}',
    '.rule-tab-content {',
    '  display: none;',
    '}',
    '.rule-tab-content.active {',
    '  display: block;',
    '}',
    '.cel-editor {',
    '  width: 100%;',
    '  min-height: 120px;',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-sm);',
    '  background: var(--bg-secondary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  padding: var(--space-3);',
    '  color: var(--text-primary);',
    '  resize: vertical;',
    '  line-height: 1.5;',
    '  box-sizing: border-box;',
    '}',
    '.cel-editor:focus {',
    '  border-color: var(--accent);',
    '  outline: none;',
    '}',
    '.cel-help {',
    '  margin-top: var(--space-3);',
    '  padding: var(--space-3);',
    '  background: var(--bg-secondary);',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-xs);',
    '  max-height: 260px;',
    '  overflow-y: auto;',
    '  scrollbar-width: thin;',
    '  scrollbar-color: var(--border) transparent;',
    '}',
    '.cel-help::-webkit-scrollbar { width: 6px; }',
    '.cel-help::-webkit-scrollbar-track { background: transparent; }',
    '.cel-help::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }',
    '.cel-help-title {',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-secondary);',
    '  margin-bottom: var(--space-2);',
    '}',
    '.cel-help-category {',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-secondary);',
    '  font-size: 10px;',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '  margin-top: var(--space-3);',
    '  margin-bottom: var(--space-1);',
    '  padding-bottom: var(--space-1);',
    '  border-bottom: 1px solid var(--border);',
    '}',
    '.cel-help-category:first-of-type { margin-top: 0; }',
    '.cel-help-var {',
    '  font-family: var(--font-mono);',
    '  color: var(--accent-text);',
    '  display: inline-block;',
    '  margin-right: var(--space-2);',
    '}',

    /* -- Policy Test section ----------------------------------------------- */
    '.test-section {',
    '  margin-top: var(--space-6);',
    '}',
    '.test-form {',
    '  display: grid;',
    '  grid-template-columns: 1fr 1fr;',
    '  gap: var(--space-4);',
    '}',
    '.test-form-full {',
    '  grid-column: span 2;',
    '}',
    '.test-result {',
    '  margin-top: var(--space-4);',
    '  padding: var(--space-4);',
    '  border-radius: var(--radius-md);',
    '  border: 1px solid var(--border);',
    '}',
    '.test-result-allow {',
    '  border-color: var(--success);',
    '  background: var(--success-subtle, rgba(74,222,128,0.08));',
    '}',
    '.test-result-deny {',
    '  border-color: var(--danger);',
    '  background: var(--danger-subtle, rgba(239,68,68,0.08));',
    '}',
    '.test-result-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  margin-bottom: var(--space-2);',
    '}',
    '.test-result-row:last-child {',
    '  margin-bottom: 0;',
    '}',
    '.test-result-label {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-muted);',
    '  min-width: 100px;',
    '}',
    '.autocomplete-wrap {',
    '  position: relative;',
    '}',
    '.autocomplete-list {',
    '  position: absolute;',
    '  top: 100%;',
    '  left: 0;',
    '  right: 0;',
    '  max-height: 200px;',
    '  overflow-y: auto;',
    '  background: var(--bg-elevated);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  box-shadow: var(--shadow-lg);',
    '  z-index: 10;',
    '  display: none;',
    '}',
    '.autocomplete-list.open {',
    '  display: block;',
    '}',
    '.autocomplete-item {',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-sm);',
    '  cursor: pointer;',
    '  transition: background var(--transition-fast);',
    '}',
    '.autocomplete-item:hover, .autocomplete-item.selected {',
    '  background: var(--bg-secondary);',
    '}',
    '.autocomplete-item-name {',
    '  font-family: var(--font-mono);',
    '  color: var(--text-primary);',
    '}',
    '.autocomplete-item-desc {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  margin-left: var(--space-2);',
    '}',
    '@media (max-width: 768px) {',
    '  .test-form { grid-template-columns: 1fr; }',
    '  .test-form-full { grid-column: span 1; }',
    '}',

    /* -- Conflict banner ---------------------------------------------------- */
    '.conflict-banner {',
    '  display: flex;',
    '  align-items: flex-start;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3) var(--space-4);',
    '  background: var(--warning-bg, #fef3cd);',
    '  border: 1px solid var(--warning-border, #ffc107);',
    '  border-radius: var(--radius-md);',
    '  margin-bottom: var(--space-4);',
    '  color: var(--warning-text, #856404);',
    '}',
    '.conflict-banner-icon {',
    '  flex-shrink: 0;',
    '  margin-top: 2px;',
    '  color: var(--warning-text, #856404);',
    '}',
    '.conflict-banner-text {',
    '  flex: 1;',
    '}',
    '.conflict-banner-text strong {',
    '  display: block;',
    '  margin-bottom: var(--space-1);',
    '  font-size: var(--text-sm);',
    '}',
    '.conflict-banner-text p {',
    '  margin: 0;',
    '  font-size: var(--text-sm);',
    '  line-height: 1.5;',
    '}'
  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-tools', '');
    s.textContent = TOOLS_CSS;
    document.head.appendChild(s);
    styleInjected = true;
  }

  // -- DOM helpers ------------------------------------------------------------

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

  // -- Env parser helper ------------------------------------------------------

  /**
   * Parse environment variable text (one KEY=VALUE per line) into an object.
   * Blank lines and lines without '=' are silently skipped.
   */
  function parseEnvVars(text) {
    var result = {};
    if (!text) return result;
    var lines = text.split('\n');
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      var eqIdx = line.indexOf('=');
      if (eqIdx < 1) continue; // skip lines with no key before '='
      var key = line.substring(0, eqIdx).trim();
      var value = line.substring(eqIdx + 1);
      if (key) {
        result[key] = value;
      }
    }
    return result;
  }

  // -- Add Upstream modal -----------------------------------------------------

  function openAddUpstreamModal(existing) {
    var isEdit = existing != null;

    // -- Build form via DOM ---------------------------------------------------
    var form = mk('form', 'add-upstream-form');
    form.setAttribute('autocomplete', 'off');

    // 1. Name field
    var nameGroup = mk('div', 'form-group');
    var nameLabel = mk('label', 'form-label');
    nameLabel.textContent = 'Name';
    nameLabel.setAttribute('for', 'upstream-name');
    nameGroup.appendChild(nameLabel);
    var nameInput = mk('input', 'form-input', {
      type: 'text', id: 'upstream-name', name: 'name',
      placeholder: 'e.g. filesystem-server'
    });
    nameGroup.appendChild(nameInput);
    form.appendChild(nameGroup);

    // 2. Type selector
    var typeGroup = mk('div', 'form-group');
    var typeLabel = mk('label', 'form-label');
    typeLabel.textContent = 'Type';
    typeLabel.setAttribute('for', 'upstream-type');
    typeGroup.appendChild(typeLabel);
    var typeSelect = mk('select', 'form-select', {
      id: 'upstream-type', name: 'type'
    });
    var optStdio = mk('option');
    optStdio.value = 'stdio';
    optStdio.textContent = 'stdio';
    typeSelect.appendChild(optStdio);
    var optHttp = mk('option');
    optHttp.value = 'http';
    optHttp.textContent = 'http';
    typeSelect.appendChild(optHttp);
    typeGroup.appendChild(typeSelect);
    form.appendChild(typeGroup);

    // 3. Command field (stdio)
    var cmdGroup = mk('div', 'form-group');
    cmdGroup.setAttribute('data-field', 'stdio');
    var cmdLabel = mk('label', 'form-label');
    cmdLabel.textContent = 'Command';
    cmdLabel.setAttribute('for', 'upstream-command');
    cmdGroup.appendChild(cmdLabel);
    var cmdInput = mk('input', 'form-input', {
      type: 'text', id: 'upstream-command', name: 'command',
      placeholder: 'e.g. npx, python3'
    });
    cmdGroup.appendChild(cmdInput);
    form.appendChild(cmdGroup);

    // 4. Arguments field (stdio)
    var argsGroup = mk('div', 'form-group');
    argsGroup.setAttribute('data-field', 'stdio');
    var argsLabel = mk('label', 'form-label');
    argsLabel.textContent = 'Arguments';
    argsLabel.setAttribute('for', 'upstream-args');
    argsGroup.appendChild(argsLabel);
    var argsInput = mk('input', 'form-input', {
      type: 'text', id: 'upstream-args', name: 'args',
      placeholder: 'e.g. -m mcp_server --port 3001'
    });
    argsGroup.appendChild(argsInput);
    var argsHelp = mk('div', 'form-help');
    argsHelp.textContent = 'Space-separated arguments for the command';
    argsGroup.appendChild(argsHelp);
    form.appendChild(argsGroup);

    // 5. URL field (http) - initially hidden
    var urlGroup = mk('div', 'form-group');
    urlGroup.setAttribute('data-field', 'http');
    urlGroup.style.display = 'none';
    var urlLabel = mk('label', 'form-label');
    urlLabel.textContent = 'URL';
    urlLabel.setAttribute('for', 'upstream-url');
    urlGroup.appendChild(urlLabel);
    var urlInput = mk('input', 'form-input', {
      type: 'text', id: 'upstream-url', name: 'url',
      placeholder: 'e.g. http://localhost:3001/mcp'
    });
    urlGroup.appendChild(urlInput);
    form.appendChild(urlGroup);

    // 6. Environment Variables (stdio)
    var envGroup = mk('div', 'form-group');
    envGroup.setAttribute('data-field', 'stdio');
    var envLabel = mk('label', 'form-label');
    envLabel.textContent = 'Environment Variables';
    envLabel.setAttribute('for', 'upstream-env');
    envGroup.appendChild(envLabel);
    var envTextarea = mk('textarea', 'form-textarea', {
      id: 'upstream-env', name: 'env',
      placeholder: 'KEY=VALUE (one per line)'
    });
    envGroup.appendChild(envTextarea);
    var envHelp = mk('div', 'form-help');
    envHelp.textContent = 'Environment variables, one KEY=VALUE per line';
    envGroup.appendChild(envHelp);
    form.appendChild(envGroup);

    // -- Pre-fill for edit mode ---------------------------------------------
    if (isEdit) {
      nameInput.value = existing.name || '';
      if (existing.type === 'http') {
        typeSelect.value = 'http';
        urlInput.value = existing.url || '';
        // Show HTTP fields, hide stdio fields
        var stdioInit = form.querySelectorAll('[data-field="stdio"]');
        var httpInit = form.querySelectorAll('[data-field="http"]');
        for (var si = 0; si < stdioInit.length; si++) stdioInit[si].style.display = 'none';
        for (var hi = 0; hi < httpInit.length; hi++) httpInit[hi].style.display = 'block';
      } else {
        typeSelect.value = 'stdio';
        cmdInput.value = existing.command || '';
        argsInput.value = (existing.args && existing.args.length) ? existing.args.join(' ') : '';
        // Format env as KEY=VALUE lines
        if (existing.env && typeof existing.env === 'object') {
          var envLines = [];
          var envKeys = Object.keys(existing.env);
          for (var ei = 0; ei < envKeys.length; ei++) {
            envLines.push(envKeys[ei] + '=' + existing.env[envKeys[ei]]);
          }
          envTextarea.value = envLines.join('\n');
        }
      }
    }

    // -- Type toggle logic --------------------------------------------------
    typeSelect.addEventListener('change', function () {
      var selected = typeSelect.value;
      var stdioFields = form.querySelectorAll('[data-field="stdio"]');
      var httpFields = form.querySelectorAll('[data-field="http"]');
      for (var i = 0; i < stdioFields.length; i++) {
        stdioFields[i].style.display = (selected === 'stdio') ? 'block' : 'none';
      }
      for (var j = 0; j < httpFields.length; j++) {
        httpFields[j].style.display = (selected === 'http') ? 'block' : 'none';
      }
      // Clear any validation errors when switching type
      clearFormErrors(form);
    });

    // -- Footer buttons -----------------------------------------------------
    var footerEl = mk('div', '', { style: 'display: contents;' });

    var cancelBtn = mk('button', 'btn btn-secondary');
    cancelBtn.type = 'button';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', function () {
      SG.modal.close();
    });
    footerEl.appendChild(cancelBtn);

    var saveBtn = mk('button', 'btn btn-primary');
    saveBtn.type = 'button';
    saveBtn.textContent = isEdit ? 'Update' : 'Save';
    footerEl.appendChild(saveBtn);

    // -- Validation ---------------------------------------------------------
    function clearFormErrors(formEl) {
      var groups = formEl.querySelectorAll('.form-group');
      for (var i = 0; i < groups.length; i++) {
        groups[i].classList.remove('form-error');
        var errText = groups[i].querySelector('.form-error-text');
        if (errText) errText.parentNode.removeChild(errText);
      }
    }

    function setFieldError(group, message) {
      group.classList.add('form-error');
      var errEl = mk('div', 'form-error-text');
      errEl.textContent = message;
      group.appendChild(errEl);
    }

    function validateForm() {
      clearFormErrors(form);
      var valid = true;
      var firstInvalid = null;
      var selectedType = typeSelect.value;

      // Name required
      if (!nameInput.value.trim()) {
        setFieldError(nameGroup, 'Name is required');
        valid = false;
        if (!firstInvalid) firstInvalid = nameInput;
      }

      // Type-specific fields
      if (selectedType === 'stdio') {
        if (!cmdInput.value.trim()) {
          setFieldError(cmdGroup, 'Command is required for stdio type');
          valid = false;
          if (!firstInvalid) firstInvalid = cmdInput;
        }
      } else if (selectedType === 'http') {
        if (!urlInput.value.trim()) {
          setFieldError(urlGroup, 'URL is required for HTTP type');
          valid = false;
          if (!firstInvalid) firstInvalid = urlInput;
        }
      }

      if (firstInvalid) {
        firstInvalid.focus();
      }
      return valid;
    }

    // -- Submit handler -----------------------------------------------------
    saveBtn.addEventListener('click', function () {
      if (!validateForm()) return;

      var selectedType = typeSelect.value;
      var payload = {
        name: nameInput.value.trim(),
        type: selectedType
      };

      if (selectedType === 'stdio') {
        payload.command = cmdInput.value.trim();
        var argsVal = argsInput.value.trim();
        if (argsVal) {
          payload.args = argsVal.split(/\s+/).filter(Boolean);
        }
        var envObj = parseEnvVars(envTextarea.value);
        if (Object.keys(envObj).length > 0) {
          payload.env = envObj;
        }
      } else {
        payload.url = urlInput.value.trim();
      }

      // Disable save to prevent double-submit
      saveBtn.disabled = true;
      saveBtn.textContent = isEdit ? 'Updating\u2026' : 'Saving\u2026';

      var apiCall = isEdit
        ? SG.api.put('/upstreams/' + existing.id, payload)
        : SG.api.post('/upstreams', payload);

      apiCall.then(function () {
        SG.modal.close();
        SG.toast.success('Upstream "' + payload.name + '" ' + (isEdit ? 'updated' : 'created'));
        // Refresh the tool list
        var contentContainer = document.querySelector('.tools-content');
        if (contentContainer) {
          var pageRoot = contentContainer.parentElement;
          if (pageRoot) {
            loadData(pageRoot);
          }
        }
      }).catch(function (err) {
        SG.toast.error(err.message || ('Failed to ' + (isEdit ? 'update' : 'create') + ' upstream'));
      }).finally(function () {
        saveBtn.disabled = false;
        saveBtn.textContent = isEdit ? 'Update' : 'Save';
      });
    });

    // Prevent form submit on Enter causing page reload
    form.addEventListener('submit', function (e) {
      e.preventDefault();
    });

    // -- Open modal ---------------------------------------------------------
    SG.modal.open({
      title: isEdit ? 'Edit Upstream' : 'Add Upstream',
      body: form,
      footer: footerEl,
      width: '560px'
    });

    // Focus name input after modal opens
    setTimeout(function () {
      nameInput.focus();
    }, 100);
  }

  // -- Data fetching ----------------------------------------------------------

  function loadData(container) {
    Promise.all([
      SG.api.get('/tools'),
      SG.api.get('/upstreams'),
      SG.api.get('/policies')
    ]).then(function (results) {
      var toolData = results[0];
      // Support both old array format and new {tools, conflicts} format
      if (Array.isArray(toolData)) {
        tools = toolData;
        conflicts = [];
      } else if (toolData && typeof toolData === 'object') {
        tools = toolData.tools || [];
        conflicts = toolData.conflicts || [];
      } else {
        tools = [];
        conflicts = [];
      }
      upstreams = results[1] || [];
      policies = results[2] || [];
      if (!Array.isArray(tools)) tools = [];
      if (!Array.isArray(upstreams)) upstreams = [];
      if (!Array.isArray(policies)) policies = [];
      if (!Array.isArray(conflicts)) conflicts = [];
      renderContent(container);
    }).catch(function (err) {
      SG.toast.error('Failed to load tools: ' + (err.message || 'Unknown error'));
    });
  }

  // -- Query string parsing ---------------------------------------------------

  function parseUpstreamFilter() {
    var hash = window.location.hash || '';
    var qIdx = hash.indexOf('?');
    if (qIdx === -1) return null;
    var query = hash.substring(qIdx + 1);
    var parts = query.split('&');
    for (var i = 0; i < parts.length; i++) {
      var pair = parts[i].split('=');
      if (pair[0] === 'upstream' && pair[1]) {
        return decodeURIComponent(pair[1]);
      }
    }
    return null;
  }

  // -- Group tools by upstream ------------------------------------------------

  function groupToolsByUpstream() {
    var groups = {};
    var order = [];

    for (var i = 0; i < tools.length; i++) {
      var t = tools[i];
      var uid = t.upstream_id || t.upstream_name || 'unknown';
      if (!groups[uid]) {
        groups[uid] = {
          id: uid,
          name: t.upstream_name || uid,
          tools: []
        };
        order.push(uid);
      }
      groups[uid].tools.push(t);
    }

    // Enrich with upstream metadata (status + full upstream data)
    for (var u = 0; u < upstreams.length; u++) {
      var up = upstreams[u];
      var key = up.id || up.name || '';
      if (groups[key]) {
        groups[key].status = up.status;
        groups[key].name = up.name || key;
        groups[key].upstream = up;
      }
    }

    var result = [];
    for (var o = 0; o < order.length; o++) {
      result.push(groups[order[o]]);
    }
    return result;
  }

  // -- Status helpers ---------------------------------------------------------

  function resolveStatusClass(raw) {
    if (!raw) return 'connecting';
    var s = String(raw).toLowerCase();
    if (s === 'connected' || s === 'running') return 'connected';
    if (s === 'disconnected' || s === 'stopped' || s === 'error' || s === 'failed') return 'disconnected';
    return 'connecting';
  }

  // -- Rendering --------------------------------------------------------------

  function renderContent(container) {
    // Clear content area (keep only what we build fresh)
    var contentArea = container.querySelector('.tools-content');
    if (!contentArea) return;
    contentArea.innerHTML = '';

    // Apply pre-filter from query string on first render
    var preFilter = parseUpstreamFilter();
    if (preFilter) {
      activeFilter = preFilter;
    }

    var groups = groupToolsByUpstream();

    // Empty state
    if (tools.length === 0) {
      renderEmptyState(contentArea);
      return;
    }

    // Filter tabs
    renderFilterTabs(contentArea, groups);

    // Conflict warning banner (if any)
    renderConflictBanner(contentArea);

    // Tool groups
    var groupsContainer = mk('div', 'tools-groups');
    for (var i = 0; i < groups.length; i++) {
      var group = groups[i];
      var shouldShow = (activeFilter === 'all') || (activeFilter === group.id);
      var groupEl = renderGroup(group, i);
      if (!shouldShow) {
        groupEl.style.display = 'none';
      }
      groupsContainer.appendChild(groupEl);
    }
    contentArea.appendChild(groupsContainer);

    // Policy Rules section
    contentArea.appendChild(buildRulesSection());

    // Policy Test section
    contentArea.appendChild(buildTestSection());
  }

  function renderConflictBanner(container) {
    if (!conflicts || conflicts.length === 0) return;

    var banner = mk('div', 'conflict-banner');

    var icon = mk('span', 'conflict-banner-icon');
    icon.innerHTML = SG.icon('alertTriangle', 18);
    banner.appendChild(icon);

    var textWrap = mk('div', 'conflict-banner-text');
    var title = mk('strong', '');
    title.textContent = 'Tool Name Conflicts Detected';
    textWrap.appendChild(title);

    var desc = mk('p', '');
    var parts = [];
    for (var i = 0; i < conflicts.length; i++) {
      var c = conflicts[i];
      parts.push(c.tool_name + ' (' + (c.upstreams || []).join(', ') + ')');
    }
    desc.textContent = 'The following tools exist in multiple upstreams (first-registered wins): ' +
      parts.join('; ') + '. Consider renaming to avoid shadowing.';
    textWrap.appendChild(desc);

    banner.appendChild(textWrap);
    container.appendChild(banner);
  }

  function renderEmptyState(container) {
    var empty = mk('div', 'empty-state', {
      style: 'padding: var(--space-8) 0; text-align: center;'
    });
    var emptyIcon = mk('div', 'empty-state-icon');
    emptyIcon.innerHTML = SG.icon('wrench', 48);
    empty.appendChild(emptyIcon);
    var emptyTitle = mk('p', 'empty-state-title');
    emptyTitle.textContent = 'No tools discovered yet';
    empty.appendChild(emptyTitle);
    var emptyDesc = mk('p', 'empty-state-description');
    emptyDesc.textContent = 'Add an upstream MCP server to discover available tools.';
    empty.appendChild(emptyDesc);
    container.appendChild(empty);
  }

  function renderFilterTabs(container, groups) {
    var tabs = mk('div', 'tools-filter-tabs tools-enter');

    // "All" tab
    var allCount = tools.length;
    var allTab = mk('button', 'filter-tab' + (activeFilter === 'all' ? ' active' : ''));
    allTab.textContent = 'All';
    var allBadge = mk('span', 'filter-tab-count');
    allBadge.textContent = String(allCount);
    allTab.appendChild(document.createTextNode(' '));
    allTab.appendChild(allBadge);
    allTab.addEventListener('click', function () {
      activeFilter = 'all';
      applyFilter();
    });
    tabs.appendChild(allTab);

    // Per-upstream tabs
    for (var i = 0; i < groups.length; i++) {
      (function (group) {
        var tab = mk('button', 'filter-tab' + (activeFilter === group.id ? ' active' : ''));
        tab.textContent = group.name;
        var badge = mk('span', 'filter-tab-count');
        badge.textContent = String(group.tools.length);
        tab.appendChild(document.createTextNode(' '));
        tab.appendChild(badge);
        tab.addEventListener('click', function () {
          activeFilter = group.id;
          applyFilter();
        });
        tabs.appendChild(tab);
      })(groups[i]);
    }

    container.appendChild(tabs);
  }

  function applyFilter() {
    // Update tab active states
    var tabEls = document.querySelectorAll('.filter-tab');
    for (var t = 0; t < tabEls.length; t++) {
      tabEls[t].classList.remove('active');
    }
    // Set active based on current filter
    // "All" is always the first tab
    if (activeFilter === 'all') {
      if (tabEls.length > 0) tabEls[0].classList.add('active');
    } else {
      // Find matching tab by text content
      for (var t2 = 1; t2 < tabEls.length; t2++) {
        // The tab textContent includes the count badge, so check the group
        // We stored group.id order matching tab order (offset by 1 for All)
        var groups = groupToolsByUpstream();
        if (t2 - 1 < groups.length && groups[t2 - 1].id === activeFilter) {
          tabEls[t2].classList.add('active');
          break;
        }
      }
    }

    // Show/hide groups
    var groupEls = document.querySelectorAll('.upstream-group');
    var groups2 = groupToolsByUpstream();
    for (var g = 0; g < groupEls.length; g++) {
      if (g < groups2.length) {
        var shouldShow = (activeFilter === 'all') || (activeFilter === groups2[g].id);
        groupEls[g].style.display = shouldShow ? '' : 'none';
      }
    }
  }

  function renderGroup(group, index) {
    var groupEl = mk('div', 'upstream-group tools-enter', {
      style: 'animation-delay: ' + (index * 0.05) + 's;'
    });
    groupEl.setAttribute('data-upstream-id', group.id);

    // Header
    var header = mk('div', 'upstream-group-header');

    // Chevron icon
    var isCollapsed = collapsedGroups[group.id] === true;
    var chevron = mk('span', 'chevron-icon' + (isCollapsed ? '' : ' expanded'));
    chevron.innerHTML = SG.icon('chevronRight', 16);

    header.appendChild(chevron);

    // Upstream name
    var nameEl = mk('span', 'upstream-group-name');
    nameEl.textContent = group.name;
    header.appendChild(nameEl);

    // Tool count badge
    var countBadge = mk('span', 'badge badge-info');
    countBadge.textContent = group.tools.length + ' tool' + (group.tools.length !== 1 ? 's' : '');
    header.appendChild(countBadge);

    // Status dot
    var statusCls = resolveStatusClass(group.status);
    var statusDot = mk('span', 'status-dot ' + statusCls);
    header.appendChild(statusDot);

    // Actions area: refresh button + settings dropdown
    var actions = mk('div', 'upstream-group-actions');

    // -- Refresh button --
    var refreshBtn = mk('button', 'btn btn-icon btn-sm', { title: 'Refresh tools' });
    refreshBtn.innerHTML = SG.icon('refreshCw', 16);
    (function (gId, btn) {
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        btn.classList.add('btn-spinning');
        SG.api.post('/tools/refresh').then(function () {
          SG.toast.success('Tools refreshed');
          btn.classList.remove('btn-spinning');
          var contentContainer = document.querySelector('.tools-content');
          if (contentContainer) {
            var pageRoot = contentContainer.parentElement;
            if (pageRoot) loadData(pageRoot);
          }
        }).catch(function (err) {
          SG.toast.error('Refresh failed: ' + (err.message || 'Unknown error'));
          btn.classList.remove('btn-spinning');
        });
      });
    })(group.id, refreshBtn);
    actions.appendChild(refreshBtn);

    // -- Settings dropdown --
    var dropWrap = mk('div', 'dropdown-wrap');
    var settingsBtn = mk('button', 'btn btn-icon btn-sm', { title: 'Upstream settings' });
    settingsBtn.innerHTML = SG.icon('chevronDown', 16);
    var dropMenu = mk('div', 'dropdown-menu');

    // Edit item
    var editItem = mk('button', 'dropdown-item');
    editItem.innerHTML = SG.icon('wrench', 14) + ' ';
    editItem.appendChild(document.createTextNode('Edit'));
    (function (grp) {
      editItem.addEventListener('click', function (e) {
        e.stopPropagation();
        dropMenu.classList.remove('open');
        openAddUpstreamModal(grp.upstream || { id: grp.id, name: grp.name });
      });
    })(group);
    dropMenu.appendChild(editItem);

    // Divider
    dropMenu.appendChild(mk('div', 'dropdown-divider'));

    // Remove item
    var removeItem = mk('button', 'dropdown-item dropdown-item-danger');
    removeItem.innerHTML = SG.icon('xCircle', 14) + ' ';
    removeItem.appendChild(document.createTextNode('Remove'));
    (function (grp) {
      removeItem.addEventListener('click', function (e) {
        e.stopPropagation();
        dropMenu.classList.remove('open');
        SG.modal.confirm({
          title: 'Remove Upstream',
          message: 'Remove "' + grp.name + '" and all its tools? This cannot be undone.',
          confirmText: 'Remove',
          confirmClass: 'btn-danger',
          onConfirm: function () {
            var uid = grp.upstream ? grp.upstream.id : grp.id;
            SG.api.del('/upstreams/' + uid).then(function () {
              SG.toast.success('Upstream "' + grp.name + '" removed');
              var contentContainer = document.querySelector('.tools-content');
              if (contentContainer) {
                var pageRoot = contentContainer.parentElement;
                if (pageRoot) loadData(pageRoot);
              }
            }).catch(function (err) {
              SG.toast.error('Remove failed: ' + (err.message || 'Unknown error'));
            });
          }
        });
      });
    })(group);
    dropMenu.appendChild(removeItem);

    // Toggle dropdown on settings button click
    (function (menu) {
      settingsBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        var isOpen = menu.classList.contains('open');
        // Close any other open dropdowns
        var allMenus = document.querySelectorAll('.dropdown-menu.open');
        for (var m = 0; m < allMenus.length; m++) allMenus[m].classList.remove('open');
        if (!isOpen) {
          menu.classList.add('open');
          // Close on next outside click (delay to avoid this click closing it)
          setTimeout(function () {
            var closeHandler = function () {
              menu.classList.remove('open');
              document.removeEventListener('click', closeHandler);
            };
            document.addEventListener('click', closeHandler);
          }, 0);
        }
      });
    })(dropMenu);

    dropWrap.appendChild(settingsBtn);
    dropWrap.appendChild(dropMenu);
    actions.appendChild(dropWrap);

    header.appendChild(actions);

    // Expand/collapse handler
    (function (gId, chevronEl) {
      header.addEventListener('click', function () {
        collapsedGroups[gId] = !collapsedGroups[gId];
        var body = groupEl.querySelector('.upstream-group-body');
        if (body) {
          body.classList.toggle('collapsed');
        }
        chevronEl.classList.toggle('expanded');
      });
    })(group.id, chevron);

    groupEl.appendChild(header);

    // Body (tool rows)
    var body = mk('div', 'upstream-group-body' + (isCollapsed ? ' collapsed' : ''));

    for (var i = 0; i < group.tools.length; i++) {
      body.appendChild(renderToolRow(group.tools[i]));
    }

    groupEl.appendChild(body);
    return groupEl;
  }

  /**
   * Find the rule and policyId that match a given tool name.
   * Returns { rule, policyId } or null if no matching rule found.
   */
  function findRuleForTool(toolName) {
    for (var p = 0; p < policies.length; p++) {
      var pol = policies[p];
      var rules = pol.rules || [];
      for (var r = 0; r < rules.length; r++) {
        var rule = rules[r];
        var match = rule.tool_match || '';
        // Exact match
        if (match === toolName) {
          return { rule: rule, policyId: pol.id };
        }
        // Glob match (simple * patterns)
        if (match.indexOf('*') !== -1) {
          var regex = new RegExp('^' + globToRegex(match) + '$');
          if (regex.test(toolName)) {
            return { rule: rule, policyId: pol.id };
          }
        }
        // Check condition for tool_name == "xxx"
        if (rule.condition) {
          var eqMatch = rule.condition.match(/^tool_name\s*==\s*"([^"]*)"$/);
          if (eqMatch && eqMatch[1] === toolName) {
            return { rule: rule, policyId: pol.id };
          }
        }
      }
    }
    return null;
  }

  function renderToolRow(tool) {
    var row = mk('div', 'tool-row');

    // Tool name (clickable - opens rule modal)
    var nameEl = mk('span', 'tool-name', {
      style: 'cursor: pointer;',
      title: 'Click to edit rule for this tool'
    });
    nameEl.textContent = tool.name || 'unknown';
    (function (toolData) {
      nameEl.addEventListener('click', function (e) {
        e.stopPropagation();
        var found = findRuleForTool(toolData.name);
        if (found) {
          openRuleModal(found.rule, found.policyId);
        } else {
          openRuleModal(null, null, toolData.name);
        }
      });
    })(tool);
    row.appendChild(nameEl);

    // Description (truncated to 80 chars)
    var descEl = mk('span', 'tool-description');
    var desc = tool.description || '';
    descEl.textContent = desc.length > 80 ? desc.substring(0, 80) + '\u2026' : desc;
    row.appendChild(descEl);

    // Policy status badge
    var badgeWrap = mk('span', 'tool-badge');
    var status = (tool.policy_status || '').toLowerCase();
    var badge;

    if (status === 'allow' || status === 'allowed') {
      badge = mk('span', 'badge badge-success');
      badge.textContent = 'Allow';
      // Allow badge also clickable — open edit modal for matched rule
      badge.style.cursor = 'pointer';
      badge.setAttribute('title', 'Click to edit rule');
      (function (toolData) {
        badge.addEventListener('click', function (e) {
          e.stopPropagation();
          var found = findRuleForTool(toolData.name);
          if (found) {
            openRuleModal(found.rule, found.policyId);
          } else {
            openRuleModal(null, null, toolData.name);
          }
        });
      })(tool);
    } else if (status === 'deny' || status === 'denied') {
      badge = mk('span', 'badge badge-danger');
      badge.textContent = 'Deny';
      // Deny badge also clickable — open edit modal for matched rule
      badge.style.cursor = 'pointer';
      badge.setAttribute('title', 'Click to edit rule');
      (function (toolData) {
        badge.addEventListener('click', function (e) {
          e.stopPropagation();
          var found = findRuleForTool(toolData.name);
          if (found) {
            openRuleModal(found.rule, found.policyId);
          } else {
            openRuleModal(null, null, toolData.name);
          }
        });
      })(tool);
    } else {
      // No rule — clickable badge, opens rule modal pre-filled for this tool
      badge = mk('span', 'badge badge-neutral no-rule-badge');
      var defaultAction = getDefaultPolicyAction();
      if (defaultAction === 'deny') {
        badge.textContent = 'No rule (denied)';
      } else if (defaultAction === 'allow') {
        badge.textContent = 'No rule (allowed)';
      } else {
        badge.textContent = 'No rule';
      }
      badge.setAttribute('title', 'Click to create a rule for this tool');
      (function (toolData) {
        badge.addEventListener('click', function (e) {
          e.stopPropagation();
          openRuleModal(null, null, toolData.name);
        });
      })(tool);
    }

    badgeWrap.appendChild(badge);
    row.appendChild(badgeWrap);
    return row;
  }

  // -- Policy helpers -----------------------------------------------------------

  /**
   * Determine the default policy action from loaded policies data.
   * Looks for a policy whose name matches "Default RBAC Policy" (case-insensitive)
   * and returns the action of its lowest-priority (catch-all) rule.
   */
  function getDefaultPolicyAction() {
    for (var i = 0; i < policies.length; i++) {
      var p = policies[i];
      if (p.name && p.name.toLowerCase().indexOf('default') !== -1) {
        // Find the lowest priority rule (catch-all)
        var rules = p.rules || [];
        if (rules.length === 0) continue;
        var lowestRule = rules[0];
        for (var r = 1; r < rules.length; r++) {
          if (rules[r].priority < lowestRule.priority) {
            lowestRule = rules[r];
          }
        }
        return (lowestRule.action || '').toLowerCase();
      }
    }
    return null;
  }

  /**
   * Check if a rule is a default rule that should be protected from deletion.
   * A rule is considered "default" if:
   *   - It belongs to a policy named "Default RBAC Policy" (case-insensitive match on "default") AND
   *     the rule name contains "default-deny" or "default-allow"
   */
  function isDefaultRule(policyName, ruleName) {
    var pName = (policyName || '').toLowerCase();
    var rName = (ruleName || '').toLowerCase();
    if (pName.indexOf('default') === -1) return false;
    return rName.indexOf('default-deny') !== -1 || rName.indexOf('default-allow') !== -1;
  }

  // -- CEL helpers (visual-to-CEL and CEL-to-visual) -------------------------

  /**
   * Convert a glob pattern to a regex string.
   * Escapes regex special chars except *, then replaces * with .*
   */
  function globToRegex(pattern) {
    // Escape regex special chars except *
    var escaped = pattern.replace(/([.+?^${}()|[\]\\])/g, '\\$1');
    // Replace * with .*
    escaped = escaped.replace(/\*/g, '.*');
    return escaped;
  }

  /**
   * Build a CEL expression from simple form values.
   *
   * @param {string} appliesTo - Tool name or glob pattern
   * @returns {string} CEL expression
   */
  function buildCELFromSimple(appliesTo) {
    if (!appliesTo) return 'true';
    if (appliesTo.indexOf('*') !== -1) {
      return 'tool_name.matches("^' + globToRegex(appliesTo) + '$")';
    }
    return 'tool_name == "' + appliesTo + '"';
  }

  /**
   * Attempt to parse a CEL expression back into simple form values.
   * Returns { appliesTo: string } on success, or null if CEL is too complex.
   *
   * @param {string} cel - CEL expression string
   * @returns {Object|null}
   */
  function parseCELToSimple(cel) {
    if (!cel) return { appliesTo: '' };
    cel = cel.trim();

    // Match: true
    if (cel === 'true') {
      return { appliesTo: '' };
    }

    // Match: tool_name == "xxx"
    var eqMatch = cel.match(/^tool_name\s*==\s*"([^"]*)"$/);
    if (eqMatch) {
      return { appliesTo: eqMatch[1] };
    }

    // Match: tool_name.matches("^xxx$")
    var matchesMatch = cel.match(/^tool_name\.matches\("?\^(.+)\$"?\)$/);
    if (matchesMatch) {
      var regexBody = matchesMatch[1];
      // Attempt to convert regex back to glob: replace .* with *, un-escape chars
      var glob = regexBody.replace(/\.\*/g, '*');
      // Un-escape regex special chars
      glob = glob.replace(/\\([.+?^${}()|[\]\\])/g, '$1');
      return { appliesTo: glob };
    }

    // Cannot parse - too complex
    return null;
  }

  // -- Rule editor modal ----------------------------------------------------

  /**
   * Open the rule editor modal with Simple (visual builder) and Advanced
   * (CEL editor) tabs.
   *
   * @param {Object|null}  existingRule      - Rule object to edit, or null for new
   * @param {string|null}  policyId          - Policy ID containing the rule
   * @param {string|null}  prefilledToolName - Tool name to pre-fill (from "No rule" badge click)
   */
  function openRuleModal(existingRule, policyId, prefilledToolName) {
    var isEdit = existingRule != null;
    var activeRuleTab = 'simple';
    var lastAutoGeneratedCEL = '';

    // -- Build modal body via DOM -------------------------------------------
    var body = mk('div', 'rule-modal-form');

    // -- Tabs ---------------------------------------------------------------
    var tabs = mk('div', 'rule-tabs');
    var simpleTab = mk('button', 'rule-tab active');
    simpleTab.type = 'button';
    simpleTab.textContent = 'Simple';
    var advancedTab = mk('button', 'rule-tab');
    advancedTab.type = 'button';
    advancedTab.textContent = 'Advanced';
    tabs.appendChild(simpleTab);
    tabs.appendChild(advancedTab);
    body.appendChild(tabs);

    // -- Simple tab content -------------------------------------------------
    var simpleContent = mk('div', 'rule-tab-content active');

    // Rule Name
    var nameGroup = mk('div', 'form-group');
    var nameLabel = mk('label', 'form-label');
    nameLabel.textContent = 'Rule Name';
    nameLabel.setAttribute('for', 'rule-name');
    nameGroup.appendChild(nameLabel);
    var nameInput = mk('input', 'form-input', {
      type: 'text', id: 'rule-name', name: 'rule-name',
      placeholder: 'e.g. allow-file-read'
    });
    nameGroup.appendChild(nameInput);
    simpleContent.appendChild(nameGroup);

    // Applies To
    var appliesToGroup = mk('div', 'form-group');
    var appliesToLabel = mk('label', 'form-label');
    appliesToLabel.textContent = 'Applies To';
    appliesToLabel.setAttribute('for', 'rule-applies-to');
    appliesToGroup.appendChild(appliesToLabel);
    var appliesToInput = mk('input', 'form-input', {
      type: 'text', id: 'rule-applies-to', name: 'applies-to',
      placeholder: 'Tool name or glob pattern (e.g. read_* or file_read)'
    });
    appliesToGroup.appendChild(appliesToInput);
    var appliesToHelp = mk('div', 'form-help');
    appliesToHelp.textContent = 'Exact tool name or glob pattern with * wildcard';
    appliesToGroup.appendChild(appliesToHelp);
    simpleContent.appendChild(appliesToGroup);

    // Action
    var actionGroup = mk('div', 'form-group');
    var actionLabel = mk('label', 'form-label');
    actionLabel.textContent = 'Action';
    actionLabel.setAttribute('for', 'rule-action');
    actionGroup.appendChild(actionLabel);
    var actionSelect = mk('select', 'form-select', {
      id: 'rule-action', name: 'action'
    });
    var optAllow = mk('option');
    optAllow.value = 'allow';
    optAllow.textContent = 'Allow';
    actionSelect.appendChild(optAllow);
    var optDeny = mk('option');
    optDeny.value = 'deny';
    optDeny.textContent = 'Deny';
    actionSelect.appendChild(optDeny);
    actionGroup.appendChild(actionSelect);
    simpleContent.appendChild(actionGroup);

    // Priority
    var priorityGroup = mk('div', 'form-group');
    var priorityLabel = mk('label', 'form-label');
    priorityLabel.textContent = 'Priority';
    priorityLabel.setAttribute('for', 'rule-priority');
    priorityGroup.appendChild(priorityLabel);
    var priorityInput = mk('input', 'form-input', {
      type: 'number', id: 'rule-priority', name: 'priority',
      min: '1', max: '1000', value: '100'
    });
    priorityGroup.appendChild(priorityInput);
    var priorityHelp = mk('div', 'form-help');
    priorityHelp.textContent = 'Higher priority rules are evaluated first. Default deny is priority 0.';
    priorityGroup.appendChild(priorityHelp);
    simpleContent.appendChild(priorityGroup);

    body.appendChild(simpleContent);

    // -- Advanced tab content -----------------------------------------------
    var advancedContent = mk('div', 'rule-tab-content');

    // CEL Expression textarea
    var celGroup = mk('div', 'form-group');
    var celLabel = mk('label', 'form-label');
    celLabel.textContent = 'CEL Expression';
    celLabel.setAttribute('for', 'rule-cel');
    celGroup.appendChild(celLabel);
    var celTextarea = mk('textarea', 'cel-editor', {
      id: 'rule-cel', name: 'cel',
      placeholder: 'e.g. tool_name == "file_read" && "admin" in user_roles'
    });
    celGroup.appendChild(celTextarea);
    advancedContent.appendChild(celGroup);

    // Variable reference sidebar
    var celHelp = mk('div', 'cel-help');
    var celHelpTitle = mk('div', 'cel-help-title');
    celHelpTitle.textContent = 'Available Variables & Functions';
    celHelp.appendChild(celHelpTitle);

    var varSections = [
      { category: 'Action', vars: [
        { name: 'action_type', desc: '"tool_call", "file_access", "command_exec", "http_request"' },
        { name: 'action_name', desc: 'string \u2014 name of the action or tool' },
        { name: 'tool_name', desc: 'string \u2014 alias for action_name (MCP compat)' },
        { name: 'arguments', desc: 'map \u2014 arguments passed to the tool' },
        { name: 'tool_args', desc: 'map \u2014 alias for arguments (MCP compat)' }
      ]},
      { category: 'Identity', vars: [
        { name: 'identity_name', desc: 'string \u2014 name of the identity' },
        { name: 'identity_id', desc: 'string \u2014 unique identity ID' },
        { name: 'user_roles', desc: 'list \u2014 roles assigned to the identity' },
        { name: 'identity_roles', desc: 'list \u2014 alias for user_roles' }
      ]},
      { category: 'Context', vars: [
        { name: 'protocol', desc: '"mcp", "runtime", "http", "websocket"' },
        { name: 'framework', desc: '"crewai", "langchain", "autogen", "" ' },
        { name: 'gateway', desc: '"mcp-gateway", "runtime-python", "runtime-node"' },
        { name: 'session_id', desc: 'string \u2014 current session ID' },
        { name: 'request_time', desc: 'timestamp \u2014 time of the request' }
      ]},
      { category: 'Destination', vars: [
        { name: 'dest_url', desc: 'string \u2014 full destination URL' },
        { name: 'dest_domain', desc: 'string \u2014 destination domain' },
        { name: 'dest_ip', desc: 'string \u2014 resolved IP address' },
        { name: 'dest_port', desc: 'int \u2014 destination port' },
        { name: 'dest_path', desc: 'string \u2014 URL path or file path' },
        { name: 'dest_scheme', desc: 'string \u2014 http, https, ws, wss' },
        { name: 'dest_command', desc: 'string \u2014 command name (command_exec)' }
      ]},
      { category: 'Functions', vars: [
        { name: 'dest_ip_in_cidr(dest_ip, "10.0.0.0/8")', desc: 'check IP in CIDR range' },
        { name: 'dest_domain_matches(dest_domain, "*.evil.com")', desc: 'glob match on domain' },
        { name: 'action_arg(arguments, "key")', desc: 'get argument by key' },
        { name: 'action_arg_contains(arguments, "pat")', desc: 'search all arguments' }
      ]}
    ];
    for (var s = 0; s < varSections.length; s++) {
      var catDiv = mk('div', 'cel-help-category');
      catDiv.textContent = varSections[s].category;
      celHelp.appendChild(catDiv);
      var vars = varSections[s].vars;
      for (var v = 0; v < vars.length; v++) {
        var varLine = mk('div', '', { style: 'margin-bottom: var(--space-1);' });
        var varName = mk('span', 'cel-help-var');
        varName.textContent = vars[v].name;
        varLine.appendChild(varName);
        var varDesc = document.createTextNode(vars[v].desc);
        varLine.appendChild(varDesc);
        celHelp.appendChild(varLine);
      }
    }
    advancedContent.appendChild(celHelp);

    body.appendChild(advancedContent);

    // -- Pre-fill for edit mode ---------------------------------------------
    if (isEdit) {
      nameInput.value = existingRule.name || '';
      actionSelect.value = (existingRule.action || 'allow').toLowerCase();
      priorityInput.value = String(existingRule.priority || 100);

      // Pre-fill applies-to from tool_match (primary source)
      if (existingRule.tool_match) {
        appliesToInput.value = existingRule.tool_match;
      }

      // Pre-fill CEL condition
      if (existingRule.condition) {
        celTextarea.value = existingRule.condition;
        var parsed = parseCELToSimple(existingRule.condition);
        if (parsed) {
          if (parsed.appliesTo && !appliesToInput.value) {
            appliesToInput.value = parsed.appliesTo;
          }
        } else {
          // Complex expression - default to Advanced tab
          activeRuleTab = 'advanced';
          simpleTab.classList.remove('active');
          advancedTab.classList.add('active');
          simpleContent.classList.remove('active');
          advancedContent.classList.add('active');
        }
      }
    } else if (prefilledToolName) {
      appliesToInput.value = prefilledToolName;
    }

    // -- Tab switching logic ------------------------------------------------
    simpleTab.addEventListener('click', function () {
      if (activeRuleTab === 'simple') return;

      // Try to parse CEL back to simple
      var celVal = celTextarea.value.trim();
      if (celVal && celVal !== lastAutoGeneratedCEL) {
        var parsed = parseCELToSimple(celVal);
        if (!parsed) {
          SG.toast.info('Complex expression \u2014 use Advanced tab');
          return;
        }
        appliesToInput.value = parsed.appliesTo;
      }

      activeRuleTab = 'simple';
      simpleTab.classList.add('active');
      advancedTab.classList.remove('active');
      simpleContent.classList.add('active');
      advancedContent.classList.remove('active');
    });

    advancedTab.addEventListener('click', function () {
      if (activeRuleTab === 'advanced') return;

      // Auto-generate CEL from simple fields
      var celVal = celTextarea.value.trim();
      if (!celVal || celVal === lastAutoGeneratedCEL) {
        var generated = buildCELFromSimple(appliesToInput.value.trim());
        celTextarea.value = generated;
        lastAutoGeneratedCEL = generated;
      }

      activeRuleTab = 'advanced';
      advancedTab.classList.add('active');
      simpleTab.classList.remove('active');
      advancedContent.classList.add('active');
      simpleContent.classList.remove('active');
    });

    // -- Footer buttons -----------------------------------------------------
    var footerEl = mk('div', '', { style: 'display: contents;' });

    var cancelBtn = mk('button', 'btn btn-secondary');
    cancelBtn.type = 'button';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', function () {
      SG.modal.close();
    });
    footerEl.appendChild(cancelBtn);

    var saveBtn = mk('button', 'btn btn-primary');
    saveBtn.type = 'button';
    saveBtn.textContent = isEdit ? 'Update' : 'Save';
    footerEl.appendChild(saveBtn);

    // -- Save handler -------------------------------------------------------
    saveBtn.addEventListener('click', function () {
      var ruleName = nameInput.value.trim();
      var appliesToValue = appliesToInput.value.trim();
      var actionValue = actionSelect.value;
      var priorityValue = priorityInput.value;
      var celExpression = '';

      // Validate name
      if (!ruleName) {
        SG.toast.error('Rule name is required');
        nameInput.focus();
        return;
      }

      if (activeRuleTab === 'simple') {
        celExpression = buildCELFromSimple(appliesToValue);
      } else {
        celExpression = celTextarea.value.trim();
        if (!celExpression) {
          SG.toast.error('CEL expression is required');
          celTextarea.focus();
          return;
        }
      }

      var payload = {
        name: ruleName,
        description: 'Created from UI',
        priority: parseInt(priorityValue, 10) || 100,
        enabled: true,
        rules: [{
          name: ruleName,
          priority: parseInt(priorityValue, 10) || 100,
          tool_match: appliesToValue || '*',
          condition: celExpression,
          action: actionValue
        }]
      };

      // Disable save to prevent double-submit
      saveBtn.disabled = true;
      saveBtn.textContent = isEdit ? 'Updating\u2026' : 'Saving\u2026';

      var apiCall = (isEdit && policyId)
        ? SG.api.put('/policies/' + policyId, payload)
        : SG.api.post('/policies', payload);

      apiCall.then(function () {
        SG.modal.close();
        SG.toast.success('Rule saved');
        var contentContainer = document.querySelector('.tools-content');
        if (contentContainer) {
          var pageRoot = contentContainer.parentElement;
          if (pageRoot) loadData(pageRoot);
        }
      }).catch(function (err) {
        SG.toast.error(err.message || 'Failed to save rule');
      }).finally(function () {
        saveBtn.disabled = false;
        saveBtn.textContent = isEdit ? 'Update' : 'Save';
      });
    });

    // -- Open modal ---------------------------------------------------------
    SG.modal.open({
      title: isEdit ? 'Edit Rule' : 'Add Rule',
      body: body,
      footer: footerEl,
      width: '600px'
    });

    // Focus name input after modal opens
    setTimeout(function () {
      nameInput.focus();
    }, 100);
  }

  // -- Rule deletion ----------------------------------------------------------

  /**
   * Show a confirmation dialog to delete a rule, then call the API.
   *
   * @param {string} policyId  - The policy ID containing the rule
   * @param {string} ruleId    - The rule ID (for future per-rule delete)
   * @param {string} ruleName  - Display name for confirmation message
   */
  function confirmDeleteRule(policyId, ruleId, ruleName) {
    SG.modal.confirm({
      title: 'Delete Rule',
      message: 'Delete rule "' + ruleName + '"? This cannot be undone.',
      confirmText: 'Delete',
      confirmClass: 'btn-danger',
      onConfirm: function () {
        SG.api.del('/policies/' + policyId).then(function () {
          SG.toast.success('Rule deleted');
          var contentContainer = document.querySelector('.tools-content');
          if (contentContainer) {
            var pageRoot = contentContainer.parentElement;
            if (pageRoot) loadData(pageRoot);
          }
        }).catch(function (err) {
          SG.toast.error(err.message || 'Failed to delete rule');
        });
      }
    });
  }

  // -- Policy Rules section ---------------------------------------------------

  /**
   * Build the Policy Rules section DOM element.
   * Flattens all rules from all policies, sorts by priority descending,
   * and renders each as a row with priority, name, pattern, action badge,
   * and edit/delete buttons.
   */
  function buildRulesSection() {
    var section = mk('div', 'rules-section tools-enter');

    // Header
    var header = mk('div', 'rules-header');
    var h2 = mk('h2');
    h2.innerHTML = SG.icon('shield', 20) + ' ';
    h2.appendChild(document.createTextNode('Policy Rules'));
    header.appendChild(h2);

    var addRuleBtn = mk('button', 'btn btn-primary btn-sm');
    addRuleBtn.innerHTML = SG.icon('plus', 16) + ' ';
    addRuleBtn.appendChild(document.createTextNode('Add Rule'));
    addRuleBtn.addEventListener('click', function () {
      openRuleModal(null);
    });
    header.appendChild(addRuleBtn);
    section.appendChild(header);

    // Flatten all rules from all policies into a single array
    var allRules = [];
    for (var p = 0; p < policies.length; p++) {
      var pol = policies[p];
      var rules = pol.rules || [];
      for (var r = 0; r < rules.length; r++) {
        allRules.push({
          policyId: pol.id,
          policyName: pol.name,
          rule: rules[r]
        });
      }
    }

    // Sort by priority descending (highest priority first)
    allRules.sort(function (a, b) {
      return (b.rule.priority || 0) - (a.rule.priority || 0);
    });

    // Card container for rules
    var card = mk('div', '', {
      style: 'background: var(--bg-primary); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden;'
    });

    if (allRules.length === 0) {
      var emptyEl = mk('div', '', {
        style: 'padding: var(--space-6); text-align: center; color: var(--text-muted);'
      });
      emptyEl.textContent = 'No policy rules configured';
      card.appendChild(emptyEl);
    } else {
      for (var i = 0; i < allRules.length; i++) {
        card.appendChild(renderRuleRow(allRules[i]));
      }
    }

    section.appendChild(card);
    return section;
  }

  /**
   * Render a single rule row within the rules section.
   *
   * @param {Object} entry - {policyId, policyName, rule}
   * @returns {HTMLElement}
   */
  function renderRuleRow(entry) {
    var rule = entry.rule;
    var row = mk('div', 'rule-row');

    // Priority number
    var priorityEl = mk('span', 'rule-priority');
    priorityEl.textContent = String(rule.priority || 0);
    row.appendChild(priorityEl);

    // Rule info (name + pattern)
    var infoEl = mk('div', 'rule-info');
    var nameEl = mk('div', 'rule-name');
    nameEl.textContent = rule.name || 'Unnamed rule';
    infoEl.appendChild(nameEl);

    var patternEl = mk('div', 'rule-pattern');
    var patternText = rule.tool_match || rule.condition || '';
    if (patternText.length > 60) {
      patternText = patternText.substring(0, 60) + '\u2026';
    }
    patternEl.textContent = patternText;
    infoEl.appendChild(patternEl);
    row.appendChild(infoEl);

    // Action badge
    var action = (rule.action || '').toLowerCase();
    var actionBadge;
    if (action === 'allow') {
      actionBadge = mk('span', 'badge badge-success');
      actionBadge.textContent = 'Allow';
    } else {
      actionBadge = mk('span', 'badge badge-danger');
      actionBadge.textContent = 'Deny';
    }
    row.appendChild(actionBadge);

    // Actions: Edit + Delete
    var actionsEl = mk('div', 'rule-actions');

    // Edit button
    var editBtn = mk('button', 'btn btn-sm btn-secondary', { title: 'Edit rule' });
    editBtn.innerHTML = SG.icon('wrench', 14);
    (function (r, pid) {
      editBtn.addEventListener('click', function () {
        openRuleModal(r, pid);
      });
    })(rule, entry.policyId);
    actionsEl.appendChild(editBtn);

    // Delete button — protected for default rules
    var defaultRule = isDefaultRule(entry.policyName, rule.name);
    if (defaultRule) {
      var deleteBtn = mk('button', 'btn btn-sm btn-danger', {
        title: 'Default rule cannot be deleted',
        disabled: 'disabled'
      });
      deleteBtn.innerHTML = SG.icon('xCircle', 14);
      deleteBtn.style.opacity = '0.4';
      deleteBtn.style.cursor = 'not-allowed';
      actionsEl.appendChild(deleteBtn);

      // Default label
      var defaultLabel = mk('span', 'rule-default-label');
      defaultLabel.textContent = 'default';
      actionsEl.appendChild(defaultLabel);
    } else {
      var delBtn = mk('button', 'btn btn-sm btn-danger', { title: 'Delete rule' });
      delBtn.innerHTML = SG.icon('xCircle', 14);
      (function (pid, rid, rname) {
        delBtn.addEventListener('click', function () {
          confirmDeleteRule(pid, rid, rname);
        });
      })(entry.policyId, rule.id, rule.name);
      actionsEl.appendChild(delBtn);
    }

    row.appendChild(actionsEl);
    return row;
  }

  // -- Autocomplete helper ----------------------------------------------------

  /**
   * Build an autocomplete dropdown for an input element.
   *
   * @param {HTMLInputElement} inputEl - The input to attach autocomplete to
   * @param {Function} getItems - Returns array of { name, description } items
   * @param {Function} onSelect - Called with selected item
   * @returns {HTMLElement} The autocomplete list element (appended to inputEl.parentNode)
   */
  function buildAutocomplete(inputEl, getItems, onSelect) {
    var list = mk('div', 'autocomplete-list');
    var selectedIdx = -1;

    inputEl.parentNode.appendChild(list);

    function renderItems(filter) {
      list.innerHTML = '';
      selectedIdx = -1;
      var items = getItems();
      var matches = [];
      var lowerFilter = (filter || '').toLowerCase();

      for (var i = 0; i < items.length && matches.length < 10; i++) {
        if (!lowerFilter || items[i].name.toLowerCase().indexOf(lowerFilter) === 0) {
          matches.push(items[i]);
        }
      }

      if (matches.length === 0 || !filter) {
        list.classList.remove('open');
        return;
      }

      for (var m = 0; m < matches.length; m++) {
        (function (item, idx) {
          var el = mk('div', 'autocomplete-item');
          var nameSpan = mk('span', 'autocomplete-item-name');
          nameSpan.textContent = item.name;
          el.appendChild(nameSpan);
          if (item.description) {
            var descSpan = mk('span', 'autocomplete-item-desc');
            descSpan.textContent = item.description;
            el.appendChild(descSpan);
          }
          el.addEventListener('mousedown', function (e) {
            e.preventDefault(); // prevent blur before click registers
            onSelect(item);
            inputEl.value = item.name;
            list.classList.remove('open');
          });
          list.appendChild(el);
        })(matches[m], m);
      }

      list.classList.add('open');
    }

    function updateSelection() {
      var items = list.querySelectorAll('.autocomplete-item');
      for (var i = 0; i < items.length; i++) {
        items[i].classList.toggle('selected', i === selectedIdx);
      }
      // Scroll into view
      if (selectedIdx >= 0 && items[selectedIdx]) {
        items[selectedIdx].scrollIntoView({ block: 'nearest' });
      }
    }

    inputEl.addEventListener('input', function () {
      renderItems(inputEl.value);
    });

    inputEl.addEventListener('focus', function () {
      if (inputEl.value) {
        renderItems(inputEl.value);
      }
    });

    inputEl.addEventListener('blur', function () {
      // Delay to allow mousedown on item to register
      setTimeout(function () {
        list.classList.remove('open');
      }, 150);
    });

    inputEl.addEventListener('keydown', function (e) {
      var items = list.querySelectorAll('.autocomplete-item');
      if (!list.classList.contains('open') || items.length === 0) return;

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        selectedIdx = (selectedIdx + 1) % items.length;
        updateSelection();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        selectedIdx = selectedIdx <= 0 ? items.length - 1 : selectedIdx - 1;
        updateSelection();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (selectedIdx >= 0 && selectedIdx < items.length) {
          items[selectedIdx].dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
        }
      } else if (e.key === 'Escape') {
        list.classList.remove('open');
        selectedIdx = -1;
      }
    });

    return list;
  }

  // -- Policy Test section ----------------------------------------------------

  /**
   * Build the Policy Test playground section.
   * Allows users to test a tool call against the current policy ruleset
   * and see the result inline.
   */
  function buildTestSection() {
    var section = mk('div', 'test-section tools-enter');

    // Header
    var header = mk('div', 'rules-header');
    var h2 = mk('h2');
    h2.innerHTML = SG.icon('zap', 20) + ' ';
    h2.appendChild(document.createTextNode('Policy Test'));
    header.appendChild(h2);
    section.appendChild(header);

    // Card container
    var card = mk('div', '', {
      style: 'background: var(--bg-primary); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-4);'
    });

    // Form grid
    var formEl = mk('div', 'test-form');

    // -- Tool Name (with autocomplete) --
    var toolGroup = mk('div', 'form-group');
    var toolLabel = mk('label', 'form-label');
    toolLabel.textContent = 'Tool Name';
    toolLabel.setAttribute('for', 'test-tool-name');
    toolGroup.appendChild(toolLabel);
    var acWrap = mk('div', 'autocomplete-wrap');
    var toolInput = mk('input', 'form-input', {
      type: 'text', id: 'test-tool-name',
      placeholder: 'Type tool name...'
    });
    acWrap.appendChild(toolInput);
    toolGroup.appendChild(acWrap);
    formEl.appendChild(toolGroup);

    // Autocomplete for tool names
    buildAutocomplete(toolInput, function () {
      var items = [];
      for (var i = 0; i < tools.length; i++) {
        items.push({
          name: tools[i].name,
          description: tools[i].description || ''
        });
      }
      return items;
    }, function (item) {
      toolInput.value = item.name;
    });

    // -- Roles --
    var rolesGroup = mk('div', 'form-group');
    var rolesLabel = mk('label', 'form-label');
    rolesLabel.textContent = 'Roles';
    rolesLabel.setAttribute('for', 'test-roles');
    rolesGroup.appendChild(rolesLabel);
    var rolesInput = mk('input', 'form-input', {
      type: 'text', id: 'test-roles',
      placeholder: 'admin, user'
    });
    rolesGroup.appendChild(rolesInput);
    var rolesHelp = mk('div', 'form-help');
    rolesHelp.textContent = 'Comma-separated role list (optional)';
    rolesGroup.appendChild(rolesHelp);
    formEl.appendChild(rolesGroup);

    // -- Arguments (JSON) --
    var argsGroup = mk('div', 'form-group test-form-full');
    var argsLabel = mk('label', 'form-label');
    argsLabel.textContent = 'Arguments (JSON)';
    argsLabel.setAttribute('for', 'test-args');
    argsGroup.appendChild(argsLabel);
    var argsTextarea = mk('textarea', 'form-input', {
      id: 'test-args',
      placeholder: '{"key": "value"}',
      style: 'font-family: var(--font-mono); font-size: var(--text-xs); min-height: 60px; resize: vertical;'
    });
    argsGroup.appendChild(argsTextarea);
    var argsHelp = mk('div', 'form-help');
    argsHelp.textContent = 'JSON object with tool arguments (optional)';
    argsGroup.appendChild(argsHelp);
    formEl.appendChild(argsGroup);

    // -- Identity ID --
    var identityGroup = mk('div', 'form-group');
    var identityLabel = mk('label', 'form-label');
    identityLabel.textContent = 'Identity ID';
    identityLabel.setAttribute('for', 'test-identity');
    identityGroup.appendChild(identityLabel);
    var identityInput = mk('input', 'form-input', {
      type: 'text', id: 'test-identity',
      placeholder: 'test-user'
    });
    identityGroup.appendChild(identityInput);
    formEl.appendChild(identityGroup);

    // -- Test button --
    var btnGroup = mk('div', 'test-form-full');
    var testBtn = mk('button', 'btn btn-primary');
    testBtn.innerHTML = SG.icon('zap', 16) + ' ';
    testBtn.appendChild(document.createTextNode('Test Policy'));
    btnGroup.appendChild(testBtn);
    formEl.appendChild(btnGroup);

    card.appendChild(formEl);

    // -- Result area (hidden initially) --
    var resultArea = mk('div', 'test-result', { style: 'display: none;' });
    card.appendChild(resultArea);

    // -- Error display element --
    var toolError = mk('div', 'form-error-text', { style: 'display: none;' });
    toolGroup.appendChild(toolError);
    var argsError = mk('div', 'form-error-text', { style: 'display: none;' });
    argsGroup.appendChild(argsError);

    // -- Test button handler --
    testBtn.addEventListener('click', function () {
      // Clear previous errors
      toolError.style.display = 'none';
      toolError.textContent = '';
      argsError.style.display = 'none';
      argsError.textContent = '';
      toolGroup.classList.remove('form-error');
      argsGroup.classList.remove('form-error');

      var toolName = toolInput.value.trim();
      var argsText = argsTextarea.value.trim();
      var rolesText = rolesInput.value.trim();
      var identityId = identityInput.value.trim();

      // Validate tool name
      if (!toolName) {
        toolGroup.classList.add('form-error');
        toolError.textContent = 'Tool name is required';
        toolError.style.display = 'block';
        toolInput.focus();
        return;
      }

      // Validate JSON arguments
      var parsedArgs = {};
      if (argsText) {
        try {
          parsedArgs = JSON.parse(argsText);
        } catch (e) {
          argsGroup.classList.add('form-error');
          argsError.textContent = 'Invalid JSON';
          argsError.style.display = 'block';
          argsTextarea.focus();
          return;
        }
      }

      // Parse roles
      var rolesArray = rolesText
        ? rolesText.split(',').map(function (r) { return r.trim(); }).filter(Boolean)
        : [];

      var payload = {
        tool_name: toolName,
        arguments: parsedArgs,
        roles: rolesArray,
        identity_id: identityId || 'test-user'
      };

      // Disable button, show loading
      testBtn.disabled = true;
      var originalHTML = testBtn.innerHTML;
      testBtn.textContent = 'Testing\u2026';

      SG.api.post('/policies/test', payload).then(function (data) {
        // Render result
        resultArea.style.display = 'block';
        resultArea.innerHTML = '';
        resultArea.className = 'test-result';

        var allowed = data.allowed || data.decision === 'allow';
        resultArea.classList.add(allowed ? 'test-result-allow' : 'test-result-deny');

        // Decision row
        var decisionRow = mk('div', 'test-result-row');
        var decisionLabel = mk('span', 'test-result-label');
        decisionLabel.textContent = 'Decision';
        decisionRow.appendChild(decisionLabel);
        var decisionBadge = mk('span', 'badge ' + (allowed ? 'badge-success' : 'badge-danger'));
        decisionBadge.textContent = allowed ? 'Allow' : 'Deny';
        decisionRow.appendChild(decisionBadge);
        resultArea.appendChild(decisionRow);

        // Matched rule row
        var matchedName = data.rule_name || data.matched_rule || 'No specific rule';
        var ruleRow = mk('div', 'test-result-row');
        var ruleLabel = mk('span', 'test-result-label');
        ruleLabel.textContent = 'Matched';
        ruleRow.appendChild(ruleLabel);
        var ruleValue = mk('span', '');
        ruleValue.textContent = matchedName;
        ruleValue.style.fontFamily = 'var(--font-mono)';
        ruleValue.style.fontSize = 'var(--text-sm)';
        ruleRow.appendChild(ruleValue);
        resultArea.appendChild(ruleRow);

        // Reason row (if present)
        var reason = data.reason || '';
        if (reason) {
          var reasonRow = mk('div', 'test-result-row');
          var reasonLabel = mk('span', 'test-result-label');
          reasonLabel.textContent = 'Reason';
          reasonRow.appendChild(reasonLabel);
          var reasonValue = mk('span', '');
          reasonValue.textContent = reason;
          reasonValue.style.fontSize = 'var(--text-sm)';
          reasonRow.appendChild(reasonValue);
          resultArea.appendChild(reasonRow);
        }
      }).catch(function (err) {
        SG.toast.error(err.message || 'Policy test failed');
      }).finally(function () {
        testBtn.disabled = false;
        testBtn.innerHTML = originalHTML;
      });
    });

    section.appendChild(card);
    return section;
  }

  // -- Skeleton loading -------------------------------------------------------

  function renderSkeleton(container) {
    for (var i = 0; i < 3; i++) {
      var group = mk('div', 'tools-skeleton-group');
      group.appendChild(mk('div', 'skeleton tools-skeleton-header'));
      for (var r = 0; r < 3; r++) {
        group.appendChild(mk('div', 'skeleton tools-skeleton-row'));
      }
      container.appendChild(group);
    }
  }

  // -- Build full page DOM ----------------------------------------------------

  function buildPage(container) {
    var root = mk('div', '');

    // Header
    var header = mk('div', 'tools-header tools-enter');
    var h1 = mk('h1');
    h1.textContent = 'Tools & Rules';
    header.appendChild(h1);

    var actions = mk('div', 'tools-header-actions');
    // Add Upstream button
    var addBtn = mk('button', 'btn btn-primary btn-sm');
    addBtn.innerHTML = SG.icon('plus', 16) + ' ';
    addBtn.appendChild(document.createTextNode('Add Upstream'));
    addBtn.addEventListener('click', function () {
      openAddUpstreamModal();
    });
    actions.appendChild(addBtn);
    header.appendChild(actions);

    root.appendChild(header);

    // Content area (populated by renderContent after data loads)
    var contentArea = mk('div', 'tools-content');
    renderSkeleton(contentArea);
    root.appendChild(contentArea);

    container.appendChild(root);
  }

  // -- Lifecycle --------------------------------------------------------------

  function render(container) {
    cleanup();
    injectStyles();
    buildPage(container);
    loadData(container);
  }

  function cleanup() {
    tools = [];
    upstreams = [];
    policies = [];
    conflicts = [];
    activeFilter = 'all';
    collapsedGroups = {};
  }

  // -- Expose internal functions for testing (used by tools_test.html) --------

  SG.tools = SG.tools || {};
  SG.tools._internal = {
    buildCELFromSimple: buildCELFromSimple,
    globToRegex: globToRegex,
    parseCELToSimple: parseCELToSimple
  };
  SG.tools.openAddUpstreamModal = openAddUpstreamModal;

  // -- Registration -----------------------------------------------------------

  SG.router.register('tools', render);
  SG.router.registerCleanup('tools', cleanup);
})();
