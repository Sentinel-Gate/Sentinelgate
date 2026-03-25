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

  // -- Escape helpers ----------------------------------------------------------
  function esc(s) { var d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML; }
  function escAttr(s) { return esc(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;'); }

  // -- State ------------------------------------------------------------------

  var styleInjected = false;
  var tools = [];
  var upstreams = [];
  var policies = [];
  var conflicts = [];
  var transforms = [];
  var activeFilter = 'all';
  var collapsedGroups = {};
  var sessionContextEntries = [];
  var activeSectionTab = 'tools-rules';
  var _cachedPoliciesForPriority = null;
  var _cachedIdentities = [];
  var _initialTabHandled = false;

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

    /* -- Condition Builder (UX-F4) ---------------------------------------- */
    '.builder-meta { display: flex; gap: var(--space-3); margin-bottom: var(--space-4); }',
    '.builder-meta .form-group { flex: 1; margin-bottom: 0; }',
    '.builder-meta .form-group.meta-priority { flex: 0 0 80px; }',
    '.condition-builder {',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  padding: var(--space-3);',
    '  background: var(--bg-secondary);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.condition-builder-label {',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '  color: var(--text-muted);',
    '  margin-bottom: var(--space-2);',
    '}',
    '.condition-row {',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  align-items: center;',
    '  margin-bottom: var(--space-2);',
    '}',
    '.condition-row:last-child { margin-bottom: 0; }',
    '.condition-row select, .condition-row input {',
    '  padding: 6px 8px;',
    '  font-size: var(--text-sm);',
    '  font-family: inherit;',
    '  color: var(--text-primary);',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  outline: none;',
    '  box-sizing: border-box;',
    '}',
    '.condition-row select:focus, .condition-row input:focus {',
    '  border-color: var(--accent);',
    '}',
    '.condition-var { flex: 0 0 160px; }',
    '.condition-op { flex: 0 0 140px; }',
    '.condition-val { flex: 2; min-width: 140px; }',
    '.condition-remove {',
    '  flex: 0 0 28px;',
    '  height: 28px;',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  background: none;',
    '  border: 1px solid transparent;',
    '  border-radius: var(--radius-md);',
    '  color: var(--text-muted);',
    '  cursor: pointer;',
    '  padding: 0;',
    '  transition: all var(--transition-fast);',
    '}',
    '.condition-remove:hover { color: var(--danger); border-color: var(--danger); }',
    '.condition-combinator {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  gap: var(--space-2);',
    '  margin: var(--space-1) 0;',
    '}',
    '.condition-combinator::before, .condition-combinator::after {',
    '  content: "";',
    '  flex: 1;',
    '  height: 1px;',
    '  background: var(--border);',
    '}',
    '.condition-combinator select {',
    '  padding: 2px 8px;',
    '  font-size: 11px;',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-muted);',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-full);',
    '  outline: none;',
    '  cursor: pointer;',
    '}',
    '.condition-add-row {',
    '  margin-top: var(--space-2);',
    '}',
    '.condition-add-btn {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-1);',
    '  padding: 4px 10px;',
    '  font-size: var(--text-xs);',
    '  color: var(--accent-text);',
    '  background: none;',
    '  border: 1px dashed var(--accent);',
    '  border-radius: var(--radius-md);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '}',
    '.condition-add-btn:hover { background: var(--accent-subtle); }',
    '.cel-preview {',
    '  margin-bottom: var(--space-4);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  overflow: hidden;',
    '}',
    '.cel-preview-header {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  padding: var(--space-2) var(--space-3);',
    '  background: var(--bg-secondary);',
    '  border-bottom: 1px solid var(--border);',
    '}',
    '.cel-preview-title {',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '  color: var(--text-muted);',
    '}',
    '.cel-preview-edit-btn {',
    '  font-size: var(--text-xs);',
    '  color: var(--accent-text);',
    '  background: none;',
    '  border: none;',
    '  cursor: pointer;',
    '  text-decoration: underline;',
    '}',
    '.cel-preview-code {',
    '  padding: var(--space-3);',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  background: var(--bg-primary);',
    '  white-space: pre-wrap;',
    '  word-break: break-all;',
    '  min-height: 36px;',
    '  line-height: 1.5;',
    '}',
    '.lint-warnings { margin-bottom: var(--space-3); }',
    '.lint-warning {',
    '  display: flex;',
    '  align-items: flex-start;',
    '  gap: var(--space-2);',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-xs);',
    '  border-radius: var(--radius-md);',
    '  margin-bottom: var(--space-1);',
    '}',
    '.lint-warning.lint-error {',
    '  background: rgba(239,68,68,0.1);',
    '  color: var(--danger);',
    '  border: 1px solid rgba(239,68,68,0.2);',
    '}',
    '.lint-warning.lint-warn {',
    '  background: rgba(245,158,11,0.1);',
    '  color: #b45309;',
    '  border: 1px solid rgba(245,158,11,0.2);',
    '}',
    '.lint-warning.lint-info {',
    '  background: rgba(59,130,246,0.1);',
    '  color: #1d4ed8;',
    '  border: 1px solid rgba(59,130,246,0.2);',
    '}',
    '.suggestion-card {',
    '  display: flex;',
    '  align-items: flex-start;',
    '  gap: var(--space-2);',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-secondary);',
    '  background: var(--accent-subtle);',
    '  border: 1px solid var(--accent);',
    '  border-radius: var(--radius-md);',
    '  margin-bottom: var(--space-2);',
    '  cursor: pointer;',
    '  transition: background var(--transition-fast);',
    '}',
    '.suggestion-card:hover { background: rgba(99,102,241,0.15); }',

    /* -- Builder Step Sections ---------------------------------------------- */
    '.builder-step {',
    '  margin-bottom: var(--space-5);',
    '  position: relative;',
    '}',
    '.builder-step:not(:last-child)::before {',
    '  content: "";',
    '  position: absolute;',
    '  left: 11px;',
    '  top: 28px;',
    '  bottom: -4px;',
    '  width: 2px;',
    '  background: var(--border);',
    '}',
    '.builder-step.step-done:not(:last-child)::before {',
    '  background: rgba(34, 197, 94, 0.25);',
    '}',
    '.step-header {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  margin-bottom: var(--space-2);',
    '}',
    '.step-number {',
    '  width: 24px;',
    '  height: 24px;',
    '  border-radius: 50%;',
    '  background: rgba(45, 212, 191, 0.1);',
    '  color: var(--accent);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-bold);',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  flex-shrink: 0;',
    '  border: 1px solid rgba(45, 212, 191, 0.2);',
    '}',
    '.step-number.step-complete {',
    '  background: rgba(34, 197, 94, 0.15);',
    '  color: var(--success);',
    '  border-color: rgba(34, 197, 94, 0.25);',
    '}',
    '.step-number.step-error {',
    '  background: rgba(239, 68, 68, 0.15);',
    '  color: var(--danger);',
    '  border-color: rgba(239, 68, 68, 0.25);',
    '}',
    '.step-title {',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '}',
    '.step-optional {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  font-style: italic;',
    '  margin-left: var(--space-1);',
    '}',
    '.step-desc {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  margin-left: 34px;',
    '  margin-bottom: var(--space-2);',
    '  line-height: 1.4;',
    '}',
    '.step-content {',
    '  margin-left: 34px;',
    '}',

    /* -- Tool Chips --------------------------------------------------------- */
    '.tool-chips {',
    '  display: flex;',
    '  gap: 4px;',
    '  flex-wrap: wrap;',
    '  margin-top: var(--space-2);',
    '}',
    '.tool-chip {',
    '  font-size: var(--text-xs);',
    '  padding: 3px 8px;',
    '  border-radius: var(--radius-sm);',
    '  background: var(--bg-surface);',
    '  color: var(--text-secondary);',
    '  border: 1px solid var(--border);',
    '  font-family: var(--font-mono);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '}',
    '.tool-chip:hover {',
    '  border-color: var(--accent);',
    '  color: var(--accent-text);',
    '  background: rgba(45, 212, 191, 0.1);',
    '}',
    '.tool-chip.chip-active {',
    '  border-color: var(--accent);',
    '  color: var(--accent);',
    '  background: rgba(45, 212, 191, 0.1);',
    '  font-weight: var(--font-medium);',
    '}',
    '.tool-chip.chip-all {',
    '  font-family: var(--font-sans);',
    '  color: var(--text-muted);',
    '  font-style: italic;',
    '}',

    /* -- Quick Condition Chips ---------------------------------------------- */
    '.quick-conditions {',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  justify-content: center;',
    '  flex-wrap: wrap;',
    '  margin-top: var(--space-3);',
    '}',
    '.quick-chip {',
    '  font-size: var(--text-xs);',
    '  padding: 4px 10px;',
    '  border-radius: 20px;',
    '  background: var(--bg-surface);',
    '  color: var(--text-secondary);',
    '  border: 1px solid var(--border);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '}',
    '.quick-chip:hover {',
    '  border-color: var(--accent);',
    '  color: var(--accent-text);',
    '  background: rgba(45, 212, 191, 0.1);',
    '}',

    /* -- Validation Bar ----------------------------------------------------- */
    '.validation-bar {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  padding: var(--space-2) var(--space-3);',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-medium);',
    '  margin-top: var(--space-3);',
    '}',
    '.validation-bar.validation-valid {',
    '  background: rgba(34, 197, 94, 0.06);',
    '  border: 1px solid rgba(34, 197, 94, 0.15);',
    '  color: var(--success);',
    '}',
    '.validation-bar.validation-invalid {',
    '  background: rgba(239, 68, 68, 0.06);',
    '  border: 1px solid rgba(239, 68, 68, 0.15);',
    '  color: var(--danger);',
    '}',
    '.validation-checks {',
    '  display: flex;',
    '  gap: var(--space-3);',
    '  margin-left: auto;',
    '  font-size: var(--text-xs);',
    '}',
    '.v-check { display: flex; align-items: center; gap: 3px; }',
    '.v-check.v-pass { color: var(--success); }',
    '.v-check.v-fail { color: var(--danger); }',

    /* -- "What will happen" preview ----------------------------------------- */
    '.what-will-happen {',
    '  padding: var(--space-3) var(--space-3);',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  border-left: 3px solid var(--accent);',
    '  border-radius: 0 var(--radius-md) var(--radius-md) 0;',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  line-height: 1.5;',
    '  margin-top: var(--space-3);',
    '}',
    '.wwh-label {',
    '  font-size: 10px;',
    '  font-weight: var(--font-semibold);',
    '  color: var(--accent-text);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.05em;',
    '  margin-bottom: var(--space-1);',
    '}',
    '.wwh-action { font-weight: var(--font-semibold); }',
    '.wwh-deny { color: var(--danger); }',
    '.wwh-allow { color: var(--success); }',
    '.wwh-ask { color: var(--info); }',
    '.wwh-tool { color: var(--accent-text); font-family: var(--font-mono); }',
    '.wwh-identity { color: var(--warning); }',

    /* -- Auto-tag and field error ------------------------------------------- */
    '.auto-tag {',
    '  font-size: 10px;',
    '  font-weight: var(--font-medium);',
    '  color: var(--accent-text);',
    '  background: rgba(45, 212, 191, 0.1);',
    '  padding: 1px 6px;',
    '  border-radius: 3px;',
    '  margin-left: var(--space-2);',
    '  font-style: normal;',
    '}',
    '.field-error {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: 4px;',
    '  font-size: var(--text-xs);',
    '  color: var(--danger);',
    '  margin-top: var(--space-1);',
    '}',
    '.field-error a {',
    '  color: var(--accent-text);',
    '  text-decoration: underline;',
    '  cursor: pointer;',
    '}',

    '.builder-action-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.builder-action-row .form-group { flex: 1; margin-bottom: 0; }',
    '.variable-catalog-toggle {',
    '  font-size: var(--text-xs);',
    '  color: var(--accent-text);',
    '  background: none;',
    '  border: none;',
    '  cursor: pointer;',
    '  text-decoration: underline;',
    '  padding: 0;',
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
    '.test-result-ask {',
    '  border-color: var(--warning);',
    '  background: var(--warning-subtle, rgba(234,179,8,0.08));',
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
    '  background: rgba(59, 130, 246, 0.08);',
    '  border: 1px solid rgba(59, 130, 246, 0.25);',
    '  border-radius: var(--radius-md);',
    '  margin-bottom: var(--space-4);',
    '  color: var(--text-secondary);',
    '}',
    '.conflict-banner-icon {',
    '  flex-shrink: 0;',
    '  margin-top: 2px;',
    '  color: var(--info, #3b82f6);',
    '}',
    '.conflict-banner-close {',
    '  flex-shrink: 0;',
    '  background: none;',
    '  border: none;',
    '  color: var(--text-muted);',
    '  cursor: pointer;',
    '  padding: 2px;',
    '  line-height: 1;',
    '  font-size: 18px;',
    '}',
    '.conflict-banner-close:hover {',
    '  color: var(--text-primary);',
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
    '}',

    /* -- Template picker modal ---------------------------------------------- */
    '.template-grid {',
    '  display: grid;',
    '  grid-template-columns: repeat(2, 1fr);',
    '  gap: var(--space-3);',
    '}',
    '@media (max-width: 600px) {',
    '  .template-grid { grid-template-columns: 1fr; }',
    '}',
    '.template-card {',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  padding: var(--space-4);',
    '  cursor: pointer;',
    '  transition: border-color var(--transition-fast), background var(--transition-fast);',
    '}',
    '.template-card:hover {',
    '  border-color: var(--accent);',
    '}',
    '.template-card.selected {',
    '  border-color: var(--accent);',
    '  background: var(--accent-subtle);',
    '}',
    '.template-card-header {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  margin-bottom: var(--space-2);',
    '}',
    '.template-card-icon {',
    '  color: var(--accent);',
    '  flex-shrink: 0;',
    '  display: flex;',
    '  align-items: center;',
    '}',
    '.template-card-name {',
    '  font-weight: var(--font-semibold);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '}',
    '.template-card-desc {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  line-height: 1.4;',
    '}',
    '.template-card-meta {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  margin-top: var(--space-2);',
    '}',
    '.template-preview {',
    '  margin-top: var(--space-4);',
    '  display: none;',
    '}',
    '.template-preview.visible {',
    '  display: block;',
    '}',
    '.template-preview-title {',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '  margin-bottom: var(--space-2);',
    '}',
    '.template-rule-list {',
    '  list-style: none;',
    '  padding: 0;',
    '  margin: 0;',
    '}',
    '.template-rule-item {',
    '  padding: var(--space-2);',
    '  border-bottom: 1px solid var(--border);',
    '  font-size: var(--text-xs);',
    '  display: flex;',
    '  justify-content: space-between;',
    '  align-items: center;',
    '}',
    '.template-rule-item:last-child {',
    '  border-bottom: none;',
    '}',
    '.template-rule-action {',
    '  display: inline-flex;',
    '  padding: 2px 8px;',
    '  border-radius: var(--radius-sm);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '}',
    '.template-rule-action.allow {',
    '  background: var(--green-subtle, #e6f9e6);',
    '  color: var(--green, #16a34a);',
    '}',
    '.template-rule-action.deny {',
    '  background: var(--red-subtle, #fde8e8);',
    '  color: var(--red, #dc2626);',
    '}',

    /* -- Section tabs (Tools & Rules / Transforms / Policy Test) ------------ */
    '.section-tabs {',
    '  display: flex;',
    '  gap: var(--space-1);',
    '  margin-bottom: var(--space-6);',
    '  border-bottom: 2px solid var(--border);',
    '  padding-bottom: 0;',
    '}',
    '.section-tab {',
    '  padding: var(--space-2) var(--space-4);',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-secondary);',
    '  background: none;',
    '  border: none;',
    '  border-bottom: 2px solid transparent;',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '  margin-bottom: -2px;',
    '}',
    '.section-tab:hover {',
    '  color: var(--text-primary);',
    '  background: var(--bg-secondary);',
    '}',
    '.section-tab.active {',
    '  color: var(--accent-text);',
    '  border-bottom-color: var(--accent);',
    '}',


    /* -- Transform type badges ------------------------------------------------ */
    '.transform-type-badge {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  padding: 2px 8px;',
    '  border-radius: var(--radius-full);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-semibold);',
    '  letter-spacing: 0.02em;',
    '}',
    '.transform-type-badge.type-redact {',
    '  background: var(--danger-subtle, rgba(239,68,68,0.12));',
    '  color: var(--danger, #ef4444);',
    '}',
    '.transform-type-badge.type-truncate {',
    '  background: var(--warning-subtle, rgba(245,158,11,0.12));',
    '  color: var(--warning, #f59e0b);',
    '}',
    '.transform-type-badge.type-inject {',
    '  background: var(--info-subtle, rgba(59,130,246,0.12));',
    '  color: var(--info, #3b82f6);',
    '}',
    '.transform-type-badge.type-dry_run {',
    '  background: rgba(168,85,247,0.12);',
    '  color: #a855f7;',
    '}',
    '.transform-type-badge.type-mask {',
    '  background: rgba(234,179,8,0.12);',
    '  color: #ca8a04;',
    '}',

    /* -- Transform row -------------------------------------------------------- */
    '.transform-row {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3);',
    '  border-bottom: 1px solid var(--border);',
    '  transition: background var(--transition-fast);',
    '}',
    '.transform-row:last-child {',
    '  border-bottom: none;',
    '}',
    '.transform-row:hover {',
    '  background: var(--bg-secondary);',
    '}',
    '.transform-row-info {',
    '  flex: 1;',
    '  min-width: 0;',
    '}',
    '.transform-row-name {',
    '  font-weight: var(--font-medium);',
    '  color: var(--text-primary);',
    '  font-size: var(--text-sm);',
    '}',
    '.transform-row-meta {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  margin-top: 2px;',
    '}',
    '.transform-priority {',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-muted);',
    '  min-width: 40px;',
    '  text-align: center;',
    '}',
    '.transform-enabled-badge {',
    '  display: inline-flex;',
    '  padding: 2px 6px;',
    '  border-radius: var(--radius-sm);',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-medium);',
    '}',
    '.transform-enabled-badge.enabled {',
    '  background: var(--success-subtle, rgba(74,222,128,0.12));',
    '  color: var(--success, #22c55e);',
    '}',
    '.transform-enabled-badge.disabled {',
    '  background: var(--bg-elevated);',
    '  color: var(--text-muted);',
    '}',
    '.transform-actions {',
    '  display: flex;',
    '  gap: var(--space-2);',
    '  flex-shrink: 0;',
    '}',

    /* -- Transform config section (show/hide) --------------------------------- */
    '.transform-config-section {',
    '  display: none;',
    '}',
    '.transform-config-section.visible {',
    '  display: block;',
    '}',

    /* -- Transform test output ------------------------------------------------ */
    '.transform-test-output {',
    '  background: var(--bg-secondary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  padding: var(--space-3);',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-sm);',
    '  white-space: pre-wrap;',
    '  word-break: break-all;',
    '  max-height: 300px;',
    '  overflow-y: auto;',
    '  line-height: 1.5;',
    '}',
    '.transform-test-results {',
    '  margin-top: var(--space-3);',
    '}',
    '.transform-test-result-item {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  padding: var(--space-2) 0;',
    '  border-bottom: 1px solid var(--border);',
    '  font-size: var(--text-sm);',
    '}',
    '.transform-test-result-item:last-child {',
    '  border-bottom: none;',
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

  // -- Skeleton table helper --------------------------------------------------

  /**
   * Generate skeleton HTML for a table with header shimmer + N body rows.
   * CSS classes (.skeleton, .skeleton-text, etc.) are provided by components.css.
   *
   * @param {number} rows - Number of skeleton body rows
   * @param {number} cols - Number of columns per row
   * @returns {string} HTML string
   */
  function skeletonTable(rows, cols) {
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

  // -- Empty state helpers ----------------------------------------------------

  /**
   * Render an empty state for the Policy Rules section.
   * SVG illustration (shield + checkmark), title, description, and CTA button.
   *
   * @returns {string} HTML string
   */
  function renderRulesEmpty() {
    return '<div class="empty-state">' +
      '<div class="empty-state-illustration" style="width: 100px; height: 100px;">' +
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' +
          '<path d="M50 10 L85 25 L85 55 C85 72 68 85 50 92 C32 85 15 72 15 55 L15 25 Z" />' +
          '<path d="M38 50l8 8 16-16" />' +
        '</svg>' +
      '</div>' +
      '<h3 class="empty-state-title">No security rules defined</h3>' +
      '<p class="empty-state-description">Create rules to control which tools can be called, by whom, and under what conditions.</p>' +
      '<div style="display:flex;gap:var(--space-2);justify-content:center;flex-wrap:wrap">' +
      '<button class="btn btn-primary" data-action="add-rule">' +
        SG.icon('plus', 16) + ' Create First Rule' +
      '</button>' +
      '<button class="btn btn-secondary" data-action="use-template">' +
        SG.icon('filePlus', 16) + ' Use Template' +
      '</button>' +
      '</div>' +
    '</div>';
  }

  /**
   * Render an empty state for the Servers list (no upstreams connected).
   * SVG illustration (server), title, description, and CTA button.
   *
   * @returns {string} HTML string
   */
  function renderServersEmpty() {
    return '<div class="empty-state">' +
      '<div class="empty-state-illustration" style="width: 100px; height: 100px;">' +
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' +
          '<rect x="20" y="15" width="60" height="25" rx="4" />' +
          '<circle cx="35" cy="27.5" r="2" fill="currentColor" />' +
          '<circle cx="43" cy="27.5" r="2" fill="currentColor" />' +
          '<line x1="55" y1="27.5" x2="70" y2="27.5" />' +
          '<rect x="20" y="50" width="60" height="25" rx="4" />' +
          '<circle cx="35" cy="62.5" r="2" fill="currentColor" />' +
          '<circle cx="43" cy="62.5" r="2" fill="currentColor" />' +
          '<line x1="55" y1="62.5" x2="70" y2="62.5" />' +
          '<line x1="50" y1="40" x2="50" y2="50" />' +
          '<line x1="50" y1="75" x2="50" y2="85" />' +
        '</svg>' +
      '</div>' +
      '<h3 class="empty-state-title">No servers connected</h3>' +
      '<p class="empty-state-description">Add an MCP server to start discovering and managing tools.</p>' +
      '<button class="btn btn-primary" data-action="add-upstream">' +
        SG.icon('plus', 16) + ' Add First Server' +
      '</button>' +
    '</div>';
  }

  // -- Inline editing helper --------------------------------------------------

  /**
   * Make a table cell inline-editable on double-click.
   *
   * @param {HTMLElement} cell - The element to make editable
   * @param {Object} opts
   * @param {Function} opts.onSave - Called with (newValue, oldValue) when user saves
   * @param {Function} [opts.validate] - Returns true if value is valid
   */
  function makeInlineEditable(cell, opts) {
    cell.classList.add('inline-edit');
    cell.setAttribute('tabindex', '0');

    cell.addEventListener('dblclick', startEditing);
    cell.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !cell.isContentEditable) {
        e.preventDefault();
        startEditing();
      }
    });

    function startEditing() {
      var oldValue = cell.textContent;
      cell.setAttribute('contenteditable', 'true');
      cell.focus();

      // Select all text
      var range = document.createRange();
      range.selectNodeContents(cell);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);

      function finish() {
        cell.removeAttribute('contenteditable');
        var newValue = cell.textContent.trim();

        if (opts.validate && !opts.validate(newValue)) {
          cell.textContent = oldValue;
          SG.toast.error('Invalid value');
          return;
        }

        if (newValue !== oldValue) {
          opts.onSave(newValue, oldValue);
        }
      }

      cell.addEventListener('blur', finish, { once: true });
      cell.addEventListener('keydown', function handler(e) {
        if (e.key === 'Enter') {
          e.preventDefault();
          cell.removeEventListener('keydown', handler);
          cell.blur();
        }
        if (e.key === 'Escape') {
          e.preventDefault();
          cell.textContent = oldValue;
          cell.removeEventListener('keydown', handler);
          cell.removeAttribute('contenteditable');
        }
      });
    }
  }

  // -- Table sort helper ------------------------------------------------------

  /** Current sort state: { key, direction } */
  var _sortState = { key: null, direction: null };

  /**
   * Attach sortable behavior to a table header element.
   * Clicking toggles sort-asc / sort-desc on the column and re-sorts rows.
   *
   * @param {HTMLElement} th - The header element (.table-sortable)
   * @param {string} key - The sort key identifier
   * @param {HTMLElement} tbody - The parent container holding sortable rows
   * @param {Function} getSortValue - (rowEl) => comparable value for this column
   */
  function makeColumnSortable(th, key, tbody, getSortValue) {
    th.classList.add('table-sortable');
    // Add sort icon
    var sortIcon = mk('span', 'table-sort-icon');
    sortIcon.innerHTML = SG.icon('chevronDown', 12);
    th.appendChild(sortIcon);

    th.addEventListener('click', function () {
      // Toggle direction
      if (_sortState.key === key) {
        _sortState.direction = (_sortState.direction === 'asc') ? 'desc' : 'asc';
      } else {
        _sortState.key = key;
        _sortState.direction = 'asc';
      }

      // Update header classes
      var allHeaders = tbody.parentElement
        ? tbody.parentElement.querySelectorAll('.table-sortable')
        : [];
      for (var h = 0; h < allHeaders.length; h++) {
        allHeaders[h].classList.remove('sort-asc', 'sort-desc');
      }
      th.classList.add(_sortState.direction === 'asc' ? 'sort-asc' : 'sort-desc');

      // Re-sort rows
      var rows = [];
      var children = tbody.children;
      for (var r = 0; r < children.length; r++) {
        rows.push(children[r]);
      }
      rows.sort(function (a, b) {
        var va = getSortValue(a);
        var vb = getSortValue(b);
        if (typeof va === 'number' && typeof vb === 'number') {
          return _sortState.direction === 'asc' ? va - vb : vb - va;
        }
        var sa = String(va).toLowerCase();
        var sb = String(vb).toLowerCase();
        if (sa < sb) return _sortState.direction === 'asc' ? -1 : 1;
        if (sa > sb) return _sortState.direction === 'asc' ? 1 : -1;
        return 0;
      });
      for (var i = 0; i < rows.length; i++) {
        tbody.appendChild(rows[i]);
      }
    });
  }

  // -- Optimistic delete helpers ----------------------------------------------

  /**
   * Delete a policy rule with optimistic UI animation.
   * Uses SG.optimistic if available, otherwise implements the pattern inline.
   *
   * @param {string} policyId - The policy ID
   * @param {string} ruleId - The rule ID
   * @param {HTMLElement} rowEl - The row DOM element to animate out
   */
  function deleteRuleOptimistic(policyId, ruleId, rowEl) {
    var doOptimistic = typeof SG.optimistic === 'function' ? SG.optimistic : inlineOptimistic;
    doOptimistic({
      optimisticFn: function () {
        rowEl.style.transition = 'opacity 200ms ease, transform 200ms ease';
        rowEl.style.opacity = '0';
        rowEl.style.transform = 'translateX(-20px)';
        var previousDisplay = rowEl.style.display;
        setTimeout(function () { rowEl.style.display = 'none'; }, 200);
        return { rowEl: rowEl, previousDisplay: previousDisplay };
      },
      apiFn: function () {
        return SG.api.del('/policies/' + policyId + '/rules/' + ruleId);
      },
      successFn: function (result, data) {
        if (data.rowEl.parentNode) data.rowEl.parentNode.removeChild(data.rowEl);
        SG.toast.success('Rule deleted');
        // Always refresh data so policies array stays current (prevents ghost conflicts in template picker)
        _cachedPoliciesForPriority = null;
        var contentContainer = document.querySelector('.tools-content');
        if (contentContainer) {
          var pageRoot = contentContainer.parentElement;
          if (pageRoot) loadData(pageRoot);
        }
      },
      rollbackFn: function (err, data) {
        data.rowEl.style.display = data.previousDisplay || '';
        data.rowEl.style.opacity = '1';
        data.rowEl.style.transform = 'translateX(0)';
        SG.toast.error('Delete failed: ' + (err.message || 'Unknown error'));
      }
    });
  }

  /**
   * Delete an upstream server with optimistic UI animation.
   *
   * @param {string} upstreamId - The upstream ID
   * @param {HTMLElement} rowEl - The upstream group DOM element to animate out
   */
  function deleteUpstreamOptimistic(upstreamId, rowEl) {
    var doOptimistic = typeof SG.optimistic === 'function' ? SG.optimistic : inlineOptimistic;
    doOptimistic({
      optimisticFn: function () {
        rowEl.style.transition = 'opacity 200ms ease, transform 200ms ease';
        rowEl.style.opacity = '0';
        rowEl.style.transform = 'translateX(-20px)';
        var previousDisplay = rowEl.style.display;
        setTimeout(function () { rowEl.style.display = 'none'; }, 200);
        return { rowEl: rowEl, previousDisplay: previousDisplay };
      },
      apiFn: function () {
        return SG.api.del('/upstreams/' + upstreamId);
      },
      successFn: function (result, data) {
        if (data.rowEl.parentNode) data.rowEl.parentNode.removeChild(data.rowEl);
        SG.toast.success('Upstream removed');
        if (typeof SG.refreshSidebarUpstreams === 'function') SG.refreshSidebarUpstreams();
        // Refresh to update filter tabs and empty states
        var contentContainer = document.querySelector('.tools-content');
        if (contentContainer) {
          var pageRoot = contentContainer.parentElement;
          if (pageRoot) loadData(pageRoot);
        }
      },
      rollbackFn: function (err, data) {
        data.rowEl.style.display = data.previousDisplay || '';
        data.rowEl.style.opacity = '1';
        data.rowEl.style.transform = 'translateX(0)';
        SG.toast.error('Remove failed: ' + (err.message || 'Unknown error'));
      }
    });
  }

  /**
   * Inline optimistic helper — fallback when SG.optimistic is not available.
   */
  function inlineOptimistic(opts) {
    var rollbackData;
    try {
      rollbackData = opts.optimisticFn();
    } catch (e) {
      if (opts.rollbackFn) opts.rollbackFn(e, null);
      return;
    }
    opts.apiFn()
      .then(function (result) {
        if (opts.successFn) opts.successFn(result, rollbackData);
      })
      .catch(function (err) {
        if (opts.rollbackFn) opts.rollbackFn(err, rollbackData);
      });
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
      // Type is immutable — disable the selector to prevent accidental changes
      // that would cause the wrong fields to be sent in the payload.
      typeSelect.disabled = true;
      typeSelect.style.opacity = '0.6';
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
        } else if (isEdit) {
          payload.args = [];
        }
        var envObj = parseEnvVars(envTextarea.value);
        if (isEdit || Object.keys(envObj).length > 0) {
          // In edit mode, always send env (even empty) so the user can
          // intentionally clear all env vars. The backend treats nil as
          // "preserve existing" and {} as "clear all".
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
        if (typeof SG.refreshSidebarUpstreams === 'function') SG.refreshSidebarUpstreams();
        // Refresh the tool list or current page
        var contentContainer = document.querySelector('.tools-content');
        if (contentContainer) {
          var pageRoot = contentContainer.parentElement;
          if (pageRoot) {
            loadData(pageRoot);
          }
        } else if (SG.router && SG.router.reload) {
          // Modal was opened from another page (e.g., Connections) — reload to refresh
          SG.router.reload();
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
      title: isEdit ? 'Edit MCP Server' : 'Add MCP Server',
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
      SG.api.get('/policies'),
      SG.api.get('/v1/transforms').catch(function () { return []; }),
      SG.api.get('/identities').catch(function () { return []; })
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
      transforms = Array.isArray(results[3]) ? results[3] : [];
      _cachedIdentities = Array.isArray(results[4]) ? results[4] : [];
      if (!Array.isArray(tools)) tools = [];
      if (!Array.isArray(upstreams)) upstreams = [];
      if (!Array.isArray(policies)) policies = [];
      if (!Array.isArray(conflicts)) conflicts = [];
      renderContent(container);
      // Handle ?tab= parameter from URL only on first load (not on data refresh after actions)
      if (!_initialTabHandled) {
        _initialTabHandled = true;
        var tabParam = parseHashParam('tab');
        if (tabParam === 'templates') {
          openTemplatePickerModal();
        } else if (tabParam === 'transforms' || tabParam === 'policy-test') {
          activeSectionTab = tabParam;
          applySectionTab();
        }
      }
    }).catch(function (err) {
      SG.toast.error('Failed to load tools: ' + (err.message || 'Unknown error'));
    });
  }

  // -- Query string parsing ---------------------------------------------------

  function parseHashParam(name) {
      var hash = window.location.hash || '';
      var qIdx = hash.indexOf('?');
      if (qIdx === -1) return null;
      var query = hash.substring(qIdx + 1);
      var parts = query.split('&');
      for (var i = 0; i < parts.length; i++) {
        var pair = parts[i].split('=');
        if (pair[0] === name && pair[1]) {
          return decodeURIComponent(pair[1]);
        }
      }
      return null;
    }

    function parseUpstreamFilter() {
      return parseHashParam('upstream');
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
    // and add upstreams with 0 tools (shadowed) so they appear in the UI.
    for (var u = 0; u < upstreams.length; u++) {
      var up = upstreams[u];
      var key = up.id || up.name || '';
      if (groups[key]) {
        groups[key].status = up.status;
        groups[key].name = up.name || key;
        groups[key].upstream = up;
      } else {
        // Upstream has 0 registered tools (shadowed) — include it anyway
        groups[key] = {
          id: key,
          name: up.name || key,
          tools: [],
          status: up.status,
          upstream: up,
          shadowed: true
        };
        order.push(key);
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

    // Section tabs
    renderSectionTabs(contentArea);

    // Section containers
    var toolsRulesSection = mk('div', 'section-content');
    toolsRulesSection.setAttribute('data-section', 'tools-rules');
    var transformsSection = mk('div', 'section-content');
    transformsSection.setAttribute('data-section', 'transforms');
    var policyTestSection = mk('div', 'section-content');
    policyTestSection.setAttribute('data-section', 'policy-test');

    // Tools & Rules content
    var preFilter = parseUpstreamFilter();
    if (preFilter) {
      activeFilter = preFilter;
    }
    var groups = groupToolsByUpstream();
    if (tools.length === 0 && groups.length === 0) {
      renderEmptyState(toolsRulesSection);
    } else if (groups.length > 0) {
      renderFilterTabs(toolsRulesSection, groups);
      renderConflictBanner(toolsRulesSection);
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
      toolsRulesSection.appendChild(groupsContainer);
    }

    // Policy Rules section (always shown, even without upstream tools)
    toolsRulesSection.appendChild(buildRulesSection());

    // Transforms content
    renderTransforms(transformsSection);

    // Policy Test content
    policyTestSection.appendChild(buildTestSection());

    // Simulation section (UX-F1)
    var simulationSection = mk('div', 'section-content');
    simulationSection.setAttribute('data-section', 'simulation');
    renderSimulationSection(simulationSection);

    contentArea.appendChild(toolsRulesSection);
    contentArea.appendChild(transformsSection);
    contentArea.appendChild(policyTestSection);
    contentArea.appendChild(simulationSection);

    // Apply section visibility
    applySectionTab();
  }

  function renderSectionTabs(container) {
    var tabs = mk('div', 'section-tabs');
    var tabDefs = [
      { id: 'tools-rules', label: 'Tools & Rules' },
      { id: 'transforms', label: 'Transforms' },
      { id: 'policy-test', label: 'Policy Test' },
      { id: 'simulation', label: 'Simulation' }
    ];
    for (var i = 0; i < tabDefs.length; i++) {
      (function (def) {
        var btn = mk('button', 'section-tab' + (activeSectionTab === def.id ? ' active' : ''));
        btn.textContent = def.label;
        btn.setAttribute('data-section-id', def.id);
        btn.addEventListener('click', function () {
          activeSectionTab = def.id;
          applySectionTab();
        });
        tabs.appendChild(btn);
      })(tabDefs[i]);
    }
    container.appendChild(tabs);
  }

  function applySectionTab() {
    // Update tab active states
    var tabBtns = document.querySelectorAll('.section-tab');
    for (var i = 0; i < tabBtns.length; i++) {
      var id = tabBtns[i].getAttribute('data-section-id');
      if (id === activeSectionTab) {
        tabBtns[i].classList.add('active');
      } else {
        tabBtns[i].classList.remove('active');
      }
    }
    // Show/hide sections
    var sections = document.querySelectorAll('.section-content');
    for (var j = 0; j < sections.length; j++) {
      var sid = sections[j].getAttribute('data-section');
      sections[j].style.display = (sid === activeSectionTab) ? '' : 'none';
    }
  }

  var conflictBannerDismissed = false;

  function renderConflictBanner(container) {
    if (!conflicts || conflicts.length === 0 || conflictBannerDismissed) return;

    var banner = mk('div', 'conflict-banner');

    var icon = mk('span', 'conflict-banner-icon');
    icon.innerHTML = SG.icon('info', 18);
    banner.appendChild(icon);

    var textWrap = mk('div', 'conflict-banner-text');
    var title = mk('strong', '');
    title.textContent = 'Namespaced Tools';
    textWrap.appendChild(title);

    var desc = mk('p', '');
    desc.textContent = 'Some tools exist in multiple servers and are accessible via namespaced names (e.g. server-name/tool-name). No action required.';
    textWrap.appendChild(desc);

    var closeBtn = mk('button', 'conflict-banner-close', { 'aria-label': 'Dismiss', type: 'button' });
    closeBtn.innerHTML = '\u00d7';
    closeBtn.addEventListener('click', function () {
      conflictBannerDismissed = true;
      if (banner.parentNode) banner.parentNode.removeChild(banner);
    });

    banner.appendChild(textWrap);
    banner.appendChild(closeBtn);
    container.appendChild(banner);
  }

  function renderEmptyState(container) {
    var wrapper = mk('div', '');
    wrapper.innerHTML = renderServersEmpty();
    container.appendChild(wrapper);
    // Wire up CTA button
    var ctaBtn = wrapper.querySelector('[data-action="add-upstream"]');
    if (ctaBtn) {
      ctaBtn.addEventListener('click', function () {
        openAddUpstreamModal(null);
      });
    }
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

    // Shadowed badge for upstreams with 0 registered tools
    if (group.shadowed) {
      var shadowBadge = mk('span', 'badge badge-warning', {
        style: 'font-size: var(--text-xs);',
        title: 'This upstream shares tool names with other upstreams — all accessible via namespaced names'
      });
      shadowBadge.textContent = 'shadowed';
      header.appendChild(shadowBadge);
    }

    // Status dot
    var statusCls = resolveStatusClass(group.status);
    var statusDot = mk('span', 'status-dot ' + statusCls);
    header.appendChild(statusDot);

    // Actions area: refresh button + settings dropdown
    var actions = mk('div', 'upstream-group-actions');

    // -- Refresh button --
    var refreshBtn = mk('button', 'btn btn-icon btn-sm', {
      title: 'Refresh tools',
      'aria-label': 'Refresh tools for ' + group.name
    });
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
    var settingsBtn = mk('button', 'btn btn-icon btn-sm', {
      title: 'Upstream settings',
      'aria-label': 'Settings for ' + group.name,
      'aria-expanded': 'false'
    });
    settingsBtn.innerHTML = SG.icon('chevronDown', 16);
    var dropMenu = mk('div', 'dropdown-menu');

    // Edit item
    var editItem = mk('button', 'dropdown-item', {
      'aria-label': 'Edit upstream ' + group.name
    });
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
    var removeItem = mk('button', 'dropdown-item dropdown-item-danger', {
      'aria-label': 'Remove upstream ' + group.name
    });
    removeItem.innerHTML = SG.icon('xCircle', 14) + ' ';
    removeItem.appendChild(document.createTextNode('Remove'));
    (function (grp, gEl) {
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
            deleteUpstreamOptimistic(uid, gEl);
          }
        });
      });
    })(group, groupEl);
    dropMenu.appendChild(removeItem);

    // Toggle dropdown on settings button click
    (function (menu, sBtn) {
      sBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        var isOpen = menu.classList.contains('open');
        // Close any other open dropdowns
        var allMenus = document.querySelectorAll('.dropdown-menu.open');
        for (var m = 0; m < allMenus.length; m++) allMenus[m].classList.remove('open');
        // Reset all aria-expanded
        var allToggleBtns = document.querySelectorAll('[aria-expanded]');
        for (var ab = 0; ab < allToggleBtns.length; ab++) allToggleBtns[ab].setAttribute('aria-expanded', 'false');
        if (!isOpen) {
          menu.classList.add('open');
          sBtn.setAttribute('aria-expanded', 'true');
          // Close on next outside click (delay to avoid this click closing it)
          setTimeout(function () {
            var closeHandler = function () {
              menu.classList.remove('open');
              sBtn.setAttribute('aria-expanded', 'false');
              document.removeEventListener('click', closeHandler);
            };
            document.addEventListener('click', closeHandler);
          }, 0);
        }
      });
    })(dropMenu, settingsBtn);

    dropWrap.appendChild(settingsBtn);
    dropWrap.appendChild(dropMenu);
    actions.appendChild(dropWrap);

    header.appendChild(actions);

    // Expand/collapse handler
    header.setAttribute('role', 'button');
    header.setAttribute('aria-expanded', isCollapsed ? 'false' : 'true');
    header.setAttribute('aria-label', (isCollapsed ? 'Expand ' : 'Collapse ') + group.name);
    (function (gId, chevronEl, headerEl) {
      headerEl.addEventListener('click', function () {
        collapsedGroups[gId] = !collapsedGroups[gId];
        var body = groupEl.querySelector('.upstream-group-body');
        if (body) {
          body.classList.toggle('collapsed');
        }
        chevronEl.classList.toggle('expanded');
        var expanded = !collapsedGroups[gId];
        headerEl.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        headerEl.setAttribute('aria-label', (expanded ? 'Collapse ' : 'Expand ') + gId);
      });
    })(group.id, chevron, header);

    groupEl.appendChild(header);

    // Body (tool rows)
    var body = mk('div', 'upstream-group-body' + (isCollapsed ? ' collapsed' : ''));

    if (group.shadowed && group.tools.length === 0) {
      // Show explanation for shadowed upstream
      var shadowMsg = mk('div', '', {
        style: 'padding: var(--space-4); color: var(--text-muted); font-size: var(--text-sm); text-align: center;'
      });
      shadowMsg.textContent = 'This upstream shares tool names with other upstreams. All tools are accessible via namespaced names (e.g., server-name/tool-name).';
      body.appendChild(shadowMsg);
    }

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
    // Extract bare name for backward-compat matching with namespaced tools
    var bareName = toolName.indexOf('/') >= 0 ? toolName.split('/').slice(1).join('/') : toolName;
    for (var p = 0; p < policies.length; p++) {
      var pol = policies[p];
      var rules = pol.rules || [];
      for (var r = 0; r < rules.length; r++) {
        var rule = rules[r];
        var match = rule.tool_match || rule.tool_pattern || '*';
        // Exact match (full name or bare name backward compat)
        if (match === toolName || match === '*' || (match.indexOf('/') < 0 && match === bareName)) {
          return { rule: rule, policyId: pol.id };
        }
        // Glob match (simple * patterns) — use globMatch for filepath.Match parity
        if (match.indexOf('*') !== -1 || match.indexOf('?') !== -1) {
          if (globMatch(match, toolName)) {
            return { rule: rule, policyId: pol.id };
          }
          // Bare pattern also tested against bare tool name
          if (match.indexOf('/') < 0 && bareName !== toolName && globMatch(match, bareName)) {
            return { rule: rule, policyId: pol.id };
          }
        }
        // Check condition for tool_name == "xxx"
        if (rule.condition) {
          var eqMatch = rule.condition.match(/^tool_name\s*==\s*"([^"]*)"$/);
          if (eqMatch && (eqMatch[1] === toolName || eqMatch[1] === bareName)) {
            return { rule: rule, policyId: pol.id };
          }
        }
      }
    }
    return null;
  }

  function showToolDetail(tool) {
    var body = mk('div', '');

    // Upstream
    var upstreamRow = mk('div', '', { style: 'margin-bottom:var(--space-3)' });
    upstreamRow.innerHTML = '<strong>MCP Server:</strong> ' + esc(tool.upstream_name || tool.upstream || '-');
    body.appendChild(upstreamRow);

    // Description
    if (tool.description) {
      var descRow = mk('div', '', { style: 'margin-bottom:var(--space-3);color:var(--text-secondary)' });
      descRow.textContent = tool.description;
      body.appendChild(descRow);
    }

    // Input schema
    if (tool.input_schema || tool.inputSchema) {
      var schema = tool.input_schema || tool.inputSchema;
      var schemaLabel = mk('div', '', { style: 'font-weight:var(--font-medium);margin-bottom:var(--space-1)' });
      schemaLabel.textContent = 'Parameters:';
      body.appendChild(schemaLabel);
      var props = schema.properties || {};
      var required = schema.required || [];
      var propNames = Object.keys(props);
      if (propNames.length > 0) {
        var table = mk('table', '', { style: 'width:100%;font-size:var(--text-sm);border-collapse:collapse' });
        table.innerHTML = '<thead><tr style="text-align:left;border-bottom:1px solid var(--border)"><th style="padding:var(--space-1) var(--space-2)">Name</th><th style="padding:var(--space-1) var(--space-2)">Type</th><th style="padding:var(--space-1) var(--space-2)">Required</th><th style="padding:var(--space-1) var(--space-2)">Description</th></tr></thead>';
        var tbody = mk('tbody');
        for (var pi = 0; pi < propNames.length; pi++) {
          var pName = propNames[pi];
          var prop = props[pName];
          var tr = mk('tr', '', { style: 'border-bottom:1px solid var(--border)' });
          tr.innerHTML = '<td style="padding:var(--space-1) var(--space-2)"><code>' + esc(pName) + '</code></td>' +
            '<td style="padding:var(--space-1) var(--space-2);color:var(--text-muted)">' + esc(prop.type || '-') + '</td>' +
            '<td style="padding:var(--space-1) var(--space-2)">' + (required.indexOf(pName) >= 0 ? '<span style="color:var(--success)">yes</span>' : 'no') + '</td>' +
            '<td style="padding:var(--space-1) var(--space-2);color:var(--text-secondary)">' + esc(prop.description || '-') + '</td>';
          tbody.appendChild(tr);
        }
        table.appendChild(tbody);
        body.appendChild(table);
      } else {
        var noParams = mk('div', '', { style: 'color:var(--text-muted);font-style:italic' });
        noParams.textContent = 'No parameters';
        body.appendChild(noParams);
      }
    }

    // Matching rules
    var matchingRules = [];
    for (var p = 0; p < policies.length; p++) {
      var pol = policies[p];
      if (!pol.rules) continue;
      for (var ri = 0; ri < pol.rules.length; ri++) {
        var rule = pol.rules[ri];
        var tm = rule.tool_match || rule.tool_pattern || '*';
        // Backward compat: bare patterns (no "/") also match namespaced tool names.
        var bareName = tool.name.indexOf('/') >= 0 ? tool.name.split('/').slice(1).join('/') : tool.name;
        if (tm === '*' || tm === tool.name || tm === bareName ||
            globMatch(tm, tool.name) ||
            (tm.indexOf('/') < 0 && globMatch(tm, bareName))) {
          matchingRules.push({ rule: rule, policyId: pol.id });
        }
      }
    }
    if (matchingRules.length > 0) {
      var rulesLabel = mk('div', '', { style: 'font-weight:var(--font-medium);margin-top:var(--space-3);margin-bottom:var(--space-1)' });
      rulesLabel.textContent = 'Matching Policy Rules (' + matchingRules.length + '):';
      body.appendChild(rulesLabel);
      for (var mi = 0; mi < matchingRules.length; mi++) {
        var mr = matchingRules[mi].rule;
        var ruleDiv = mk('div', '', { style: 'padding:var(--space-1) var(--space-2);margin-bottom:var(--space-1);border-left:3px solid ' + (mr.action === 'deny' ? 'var(--danger)' : mr.action === 'allow' ? 'var(--success)' : 'var(--warning)') + ';background:var(--bg-secondary);border-radius:var(--radius-sm);font-size:var(--text-sm)' });
        ruleDiv.innerHTML = '<strong>' + esc(mr.name || 'Unnamed') + '</strong> &mdash; ' + esc(mr.action || '-') + ' <span style="color:var(--text-muted)">(match: ' + esc(mr.tool_match || '*') + ')</span>';
        body.appendChild(ruleDiv);
      }
    }

    // Footer with "Create Rule" button
    var footer = mk('div', '', { style: 'display:flex;justify-content:flex-end;gap:var(--space-2)' });
    var createBtn = mk('button', 'btn btn-primary btn-sm');
    createBtn.textContent = '+ Create Rule for ' + tool.name;
    createBtn.addEventListener('click', function () {
      SG.modal.close();
      openRuleModal(null, null, tool.name);
    });
    footer.appendChild(createBtn);

    SG.modal.open({
      title: tool.name,
      body: body,
      footer: footer
    });
  }

  function renderToolRow(tool) {
    var row = mk('div', 'tool-row');

    // Tool name (clickable - shows tool detail)
    var nameEl = mk('span', 'tool-name', {
      style: 'cursor: pointer;',
      title: 'Click to view tool details'
    });
    // If tool name is namespaced (contains "/"), show bare name + upstream badge
    var displayName = tool.name || 'unknown';
    var nsBadge = null;
    if (displayName.indexOf('/') >= 0) {
      var parts = displayName.split('/');
      var nsPrefix = parts[0];
      displayName = parts.slice(1).join('/');
      nsBadge = mk('span', '', {
        style: 'display:inline-block;font-size:var(--text-xs);background:var(--bg-secondary);color:var(--text-secondary);' +
          'padding:1px 6px;border-radius:var(--radius);margin-right:var(--space-1);font-weight:500;vertical-align:middle'
      });
      nsBadge.textContent = nsPrefix;
    }
    nameEl.textContent = displayName;
    (function (toolData) {
      nameEl.addEventListener('click', function (e) {
        e.stopPropagation();
        showToolDetail(toolData);
      });
    })(tool);
    if (nsBadge) row.appendChild(nsBadge);
    row.appendChild(nameEl);

    // Copy icon for tool name (separate from click-to-detail)
    if (SG.clipboard) {
      var copyBtn = mk('span', 'copy-icon', {
        title: 'Copy tool name',
        'aria-label': 'Copy tool name ' + (tool.name || ''),
        role: 'button',
        tabindex: '0',
        style: 'cursor:pointer;opacity:0;transition:opacity 0.15s;width:14px;height:14px;flex-shrink:0;color:var(--text-muted);margin-left:var(--space-1);'
      });
      if (typeof SG.icon === 'function') copyBtn.innerHTML = SG.icon('copy', 14);
      (function (name, btn) {
        btn.addEventListener('click', function (e) {
          e.stopPropagation();
          SG.clipboard.copy(name, btn);
        });
      })(tool.name || 'unknown', copyBtn);
      row.appendChild(copyBtn);
      // Show on row hover
      row.addEventListener('mouseenter', function () { copyBtn.style.opacity = '1'; });
      row.addEventListener('mouseleave', function () { copyBtn.style.opacity = '0'; });
    }

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
      (function (toolData, badgeEl) {
        badge.addEventListener('click', function (e) {
          e.stopPropagation();
          var found = findRuleForTool(toolData.name);
          if (found) {
            openRuleModal(found.rule, found.policyId);
          } else {
            // No explicit rule — show quick popover instead of full modal
            showQuickRulePopover(toolData.name, badgeEl);
          }
        });
      })(tool, badge);
    } else if (status === 'deny' || status === 'denied') {
      badge = mk('span', 'badge badge-danger');
      badge.textContent = 'Deny';
      // Deny badge also clickable — open edit modal for matched rule
      badge.style.cursor = 'pointer';
      badge.setAttribute('title', 'Click to edit rule');
      (function (toolData, badgeEl) {
        badge.addEventListener('click', function (e) {
          e.stopPropagation();
          var found = findRuleForTool(toolData.name);
          if (found) {
            openRuleModal(found.rule, found.policyId);
          } else {
            // No explicit rule — show quick popover instead of full modal
            showQuickRulePopover(toolData.name, badgeEl);
          }
        });
      })(tool, badge);
    } else if (status === 'conditional') {
      badge = mk('span', 'badge badge-info');
      badge.textContent = 'Conditional';
      badge.style.cursor = 'pointer';
      badge.setAttribute('title', 'Multiple rules with different actions match this tool. Click for details.');
      (function (toolData) {
        badge.addEventListener('click', function (e) {
          e.stopPropagation();
          var rules = toolData.matching_rules || [];
          var bodyEl = document.createElement('div');
          bodyEl.style.cssText = 'font-size: var(--text-sm);';
          var desc = document.createElement('p');
          desc.style.cssText = 'margin: 0 0 var(--space-3) 0; color: var(--text-secondary);';
          desc.textContent = 'The outcome for this tool depends on the call arguments. Rules are evaluated in priority order (highest first):';
          bodyEl.appendChild(desc);
          for (var ri = 0; ri < rules.length; ri++) {
            var r = rules[ri];
            var ruleDiv = document.createElement('div');
            ruleDiv.style.cssText = 'padding: var(--space-2); background: var(--bg-secondary); border-radius: var(--radius); margin-bottom: var(--space-1); font-family: var(--font-mono); font-size: var(--text-xs);';
            var actionColor = r.action === 'deny' ? 'var(--danger)' : r.action === 'allow' ? 'var(--success)' : 'var(--warning)';
            var actionLabels = { allow: 'ALLOW', deny: 'DENY', approval_required: 'ASK' };
            var actionLabel = actionLabels[r.action] || r.action.toUpperCase();
            ruleDiv.innerHTML = '<span style="color:' + actionColor + ';font-weight:600">' + esc(actionLabel) + '</span> ' +
              '"' + esc(r.tool_match) + '"' +
              (r.condition ? ' <span style="color:var(--text-muted)">when</span> ' + esc(r.condition) : '') +
              ' <span style="color:var(--text-muted)">(priority ' + esc(String(r.priority)) + ')</span>' +
              ' <span style="color:var(--text-secondary)">\u2014 ' + esc(r.name) + '</span>';
            bodyEl.appendChild(ruleDiv);
          }
          SG.modal.open({ title: 'Rule Chain for \u201c' + toolData.name + '\u201d', body: bodyEl, width: '560px' });
        });
      })(tool);
    } else if (status === 'approval_required') {
      badge = mk('span', 'badge badge-warning');
      badge.textContent = 'Ask';
      badge.style.cursor = 'pointer';
      badge.setAttribute('title', 'Requires human approval. Click to edit rule.');
      (function (toolData, badgeEl) {
        badge.addEventListener('click', function (e) {
          e.stopPropagation();
          var found = findRuleForTool(toolData.name);
          if (found) {
            openRuleModal(found.rule, found.policyId);
          } else {
            showQuickRulePopover(toolData.name, badgeEl);
          }
        });
      })(tool, badge);
    } else if (status === 'unknown') {
      badge = mk('span', 'badge badge-neutral');
      badge.textContent = 'Unavailable';
      badge.setAttribute('title', 'Policy engine is not available');
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
      (function (toolData, badgeEl) {
        badgeEl.addEventListener('click', function (e) {
          e.stopPropagation();
          showQuickRulePopover(toolData.name, badgeEl);
        });
      })(tool, badge);
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
    // Escape regex special chars except * and ?
    var escaped = pattern.replace(/([.+?^${}()|[\]\\])/g, '\\$1');
    // Replace * with .* for CEL regex expressions (used by buildCELFromSimple)
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

  // -- Visual Policy Builder (UX-F4) ----------------------------------------

  // Variable catalog: all CEL variables grouped by category with type info.
  var VARIABLE_CATALOG = [
    { category: 'Action', variables: [
      { name: 'tool_name', type: 'string', label: 'Tool Name', example: 'read_file' },
      { name: 'action_type', type: 'string', label: 'Action Type', example: 'tool_call', suggestions: ['tool_call', 'file_access', 'command_exec', 'http_request'] },
      { name: 'action_name', type: 'string', label: 'Action Name', example: 'read_file' }
    ]},
    { category: 'Identity', variables: [
      { name: 'identity_name', type: 'string', label: 'Identity', example: 'claude-prod' },
      { name: 'identity_id', type: 'string', label: 'Identity ID', example: 'id-abc123' },
      { name: 'identity_roles', type: 'list', label: 'Roles', example: 'admin' }
    ]},
    { category: 'Context', variables: [
      { name: 'protocol', type: 'string', label: 'Protocol', example: 'mcp', suggestions: ['mcp', 'http', 'websocket'] },
      { name: 'framework', type: 'string', label: 'Framework', example: 'langchain', suggestions: ['crewai', 'langchain', 'autogen'] },
      { name: 'gateway', type: 'string', label: 'Gateway', example: 'mcp-gateway' },
      { name: 'session_id', type: 'string', label: 'Session ID', example: 'sess_abc123' },
      { name: 'request_time', type: 'string', label: 'Request Time', example: 'timestamp()' }
    ]},
    { category: 'Destination', variables: [
      { name: 'dest_domain', type: 'string', label: 'Domain', example: 'api.example.com' },
      { name: 'dest_ip', type: 'string', label: 'IP Address', example: '10.0.1.5' },
      { name: 'dest_port', type: 'int', label: 'Port', example: '443' },
      { name: 'dest_url', type: 'string', label: 'URL', example: 'https://api.example.com' },
      { name: 'dest_path', type: 'string', label: 'Path', example: '/data/secrets' },
      { name: 'dest_scheme', type: 'string', label: 'Scheme', example: 'https', suggestions: ['http', 'https', 'ws', 'wss'] },
      { name: 'dest_command', type: 'string', label: 'Command', example: 'rm' }
    ]},
    { category: 'Arguments', variables: [
      { name: 'arguments', type: 'map', label: 'Tool Arguments', example: '{"path": "/data"}' }
    ]},
    { category: 'Session', variables: [
      { name: 'session_call_count', type: 'int', label: 'Call Count', example: '50' },
      { name: 'session_write_count', type: 'int', label: 'Write Count', example: '10' },
      { name: 'session_delete_count', type: 'int', label: 'Delete Count', example: '2' },
      { name: 'session_duration_seconds', type: 'int', label: 'Duration (sec)', example: '3600' },
      { name: 'session_cumulative_cost', type: 'double', label: 'Cumulative Cost ($)', example: '12.50' }
    ]},
    { category: 'Session History', variables: [
      { name: 'session_action_history', type: 'list', label: 'Action History', example: '[{tool_name, call_type, timestamp}]' },
      { name: 'session_action_set', type: 'map', label: 'Action Set', example: '{"read_file": true}' },
      { name: 'session_arg_key_set', type: 'map', label: 'Arg Key Set', example: '{"path": true}' }
    ]},
    { category: 'Agent Health', variables: [
      { name: 'user_deny_rate', type: 'double', label: 'Deny Rate', example: '0.15' },
      { name: 'user_drift_score', type: 'double', label: 'Drift Score', example: '0.25' },
      { name: 'user_violation_count', type: 'int', label: 'Violation Count', example: '3' },
      { name: 'user_total_calls', type: 'int', label: 'Total Calls (24h)', example: '500' },
      { name: 'user_error_rate', type: 'double', label: 'Error Rate', example: '0.02' }
    ]}
  ];

  // Operators grouped by variable type.
  var OPERATORS_BY_TYPE = {
    string: [
      { value: 'equals', label: 'equals' },
      { value: 'not_equals', label: 'does not equal' },
      { value: 'contains', label: 'contains' },
      { value: 'not_contains', label: 'does not contain' },
      { value: 'starts_with', label: 'starts with' },
      { value: 'ends_with', label: 'ends with' },
      { value: 'matches', label: 'matches regex' }
    ],
    list: [
      { value: 'in', label: 'contains' },
      { value: 'not_in', label: 'does not contain' }
    ],
    int: [
      { value: 'eq', label: 'equals' },
      { value: 'neq', label: 'does not equal' },
      { value: 'gt', label: 'greater than' },
      { value: 'lt', label: 'less than' },
      { value: 'gte', label: 'at least' },
      { value: 'lte', label: 'at most' }
    ],
    double: [
      { value: 'eq', label: 'equals' },
      { value: 'neq', label: 'does not equal' },
      { value: 'gt', label: 'greater than' },
      { value: 'lt', label: 'less than' },
      { value: 'gte', label: 'at least' },
      { value: 'lte', label: 'at most' }
    ],
    map: [
      { value: 'has_key', label: 'has key' },
      { value: 'value_contains', label: 'any value contains' }
    ]
  };

  // Flat variable lookup by name.
  var _varInfoCache = null;
  function getVariableInfo(name) {
    if (!_varInfoCache) {
      _varInfoCache = {};
      for (var c = 0; c < VARIABLE_CATALOG.length; c++) {
        var vars = VARIABLE_CATALOG[c].variables;
        for (var v = 0; v < vars.length; v++) {
          _varInfoCache[vars[v].name] = vars[v];
        }
      }
    }
    return _varInfoCache[name] || null;
  }

  // Get operators available for a variable.
  function getOperatorsForVariable(varName) {
    var info = getVariableInfo(varName);
    if (!info) return OPERATORS_BY_TYPE.string;
    return OPERATORS_BY_TYPE[info.type] || OPERATORS_BY_TYPE.string;
  }

  // Escape a string value for use inside CEL double-quoted strings.
  function escCEL(s) {
    if (!s) return '';
    return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  }

  // Convert a single condition object to a CEL expression fragment.
  function conditionToCEL(cond) {
    var v = cond.variable;
    var val = cond.value;
    if (!v || !cond.operator) return '';
    switch (cond.operator) {
      case 'equals':       return v + ' == "' + escCEL(val) + '"';
      case 'not_equals':   return v + ' != "' + escCEL(val) + '"';
      case 'contains':     return v + '.contains("' + escCEL(val) + '")';
      case 'not_contains': return '!' + v + '.contains("' + escCEL(val) + '")';
      case 'starts_with':  return v + '.startsWith("' + escCEL(val) + '")';
      case 'ends_with':    return v + '.endsWith("' + escCEL(val) + '")';
      case 'matches':      return v + '.matches("' + escCEL(val) + '")';
      case 'in':           return '"' + escCEL(val) + '" in ' + v;
      case 'not_in':       return '!("' + escCEL(val) + '" in ' + v + ')';
      case 'eq':           return v + ' == ' + val;
      case 'neq':          return v + ' != ' + val;
      case 'gt':           return v + ' > ' + val;
      case 'lt':           return v + ' < ' + val;
      case 'gte':          return v + ' >= ' + val;
      case 'lte':          return v + ' <= ' + val;
      case 'has_key':      return '"' + escCEL(val) + '" in ' + v;
      case 'value_contains': return 'action_arg_contains(' + v + ', "' + escCEL(val) + '")';
      default:             return 'true';
    }
  }

  // Generate a CEL expression from an array of conditions + combinator.
  function generateCELFromConditions(conditions, combinator) {
    var parts = [];
    for (var i = 0; i < conditions.length; i++) {
      var c = conditions[i];
      if (c.variable && c.operator) {
        var fragment = conditionToCEL(c);
        if (fragment && fragment !== 'true') {
          parts.push(fragment);
        }
      }
    }
    if (parts.length === 0) return 'true';
    if (parts.length === 1) return parts[0];
    var joiner = combinator === 'OR' ? ' || ' : ' && ';
    return parts.join(joiner);
  }

  // Split a CEL expression by a top-level separator (not inside parens).
  function splitTopLevel(expr, separator) {
    var parts = [];
    var depth = 0;
    var current = '';
    var sepLen = separator.length;
    for (var i = 0; i < expr.length; i++) {
      var ch = expr[i];
      if (ch === '(' || ch === '[') depth++;
      else if (ch === ')' || ch === ']') depth--;
      if (depth === 0 && expr.substring(i, i + sepLen) === separator) {
        parts.push(current);
        current = '';
        i += sepLen - 1;
      } else {
        current += ch;
      }
    }
    if (current) parts.push(current);
    return parts;
  }

  // Parse a single CEL condition fragment back into a condition object.
  function parseSingleCondition(expr) {
    expr = expr.trim();
    var m;
    // var == "value"
    m = expr.match(/^(\w+)\s*==\s*"([^"]*)"$/);
    if (m) return { variable: m[1], operator: 'equals', value: m[2] };
    // var != "value"
    m = expr.match(/^(\w+)\s*!=\s*"([^"]*)"$/);
    if (m) return { variable: m[1], operator: 'not_equals', value: m[2] };
    // var.contains("value")
    m = expr.match(/^(\w+)\.contains\("([^"]*)"\)$/);
    if (m) return { variable: m[1], operator: 'contains', value: m[2] };
    // !var.contains("value")
    m = expr.match(/^!(\w+)\.contains\("([^"]*)"\)$/);
    if (m) return { variable: m[1], operator: 'not_contains', value: m[2] };
    // var.startsWith("value")
    m = expr.match(/^(\w+)\.startsWith\("([^"]*)"\)$/);
    if (m) return { variable: m[1], operator: 'starts_with', value: m[2] };
    // var.endsWith("value")
    m = expr.match(/^(\w+)\.endsWith\("([^"]*)"\)$/);
    if (m) return { variable: m[1], operator: 'ends_with', value: m[2] };
    // var.matches("pattern")
    m = expr.match(/^(\w+)\.matches\("([^"]*)"\)$/);
    if (m) return { variable: m[1], operator: 'matches', value: m[2] };
    // "value" in var
    m = expr.match(/^"([^"]*)"\s+in\s+(\w+)$/);
    if (m) return { variable: m[2], operator: 'in', value: m[1] };
    // !("value" in var)
    m = expr.match(/^!\("([^"]*)"\s+in\s+(\w+)\)$/);
    if (m) return { variable: m[2], operator: 'not_in', value: m[1] };
    // var == N
    m = expr.match(/^(\w+)\s*==\s*(\d+)$/);
    if (m) return { variable: m[1], operator: 'eq', value: m[2] };
    // var != N
    m = expr.match(/^(\w+)\s*!=\s*(\d+)$/);
    if (m) return { variable: m[1], operator: 'neq', value: m[2] };
    // var >= N
    m = expr.match(/^(\w+)\s*>=\s*(\d+)$/);
    if (m) return { variable: m[1], operator: 'gte', value: m[2] };
    // var <= N
    m = expr.match(/^(\w+)\s*<=\s*(\d+)$/);
    if (m) return { variable: m[1], operator: 'lte', value: m[2] };
    // var > N
    m = expr.match(/^(\w+)\s*>\s*(\d+)$/);
    if (m) return { variable: m[1], operator: 'gt', value: m[2] };
    // var < N
    m = expr.match(/^(\w+)\s*<\s*(\d+)$/);
    if (m) return { variable: m[1], operator: 'lt', value: m[2] };
    // action_arg_contains(var, "value")
    m = expr.match(/^action_arg_contains\((\w+),\s*"([^"]*)"\)$/);
    if (m) return { variable: m[1], operator: 'value_contains', value: m[2] };
    // "value" in var (map key check)
    // already handled above for lists — works for maps too
    return null;
  }

  // Parse a full CEL expression into conditions + combinator (best effort).
  // Returns { conditions: [...], combinator: 'AND'|'OR' } or null if too complex.
  function parseCELToConditions(cel) {
    if (!cel || cel.trim() === 'true' || cel.trim() === '') {
      return { conditions: [], combinator: 'AND' };
    }
    cel = cel.trim();
    var combinator = 'AND';
    var parts;
    // Detect top-level combinator
    var hasOr = splitTopLevel(cel, ' || ').length > 1;
    var hasAnd = splitTopLevel(cel, ' && ').length > 1;
    if (hasOr && !hasAnd) {
      combinator = 'OR';
      parts = splitTopLevel(cel, ' || ');
    } else if (hasAnd) {
      combinator = 'AND';
      parts = splitTopLevel(cel, ' && ');
    } else {
      parts = [cel];
    }
    var conditions = [];
    for (var i = 0; i < parts.length; i++) {
      var parsed = parseSingleCondition(parts[i].trim());
      if (parsed) {
        conditions.push(parsed);
      } else {
        return null; // too complex for builder
      }
    }
    return { conditions: conditions, combinator: combinator };
  }

  // Levenshtein distance for typo suggestions in tool names.
  function levenshtein(a, b) {
    var m = a.length, n = b.length;
    var dp = [];
    for (var i = 0; i <= m; i++) {
      dp[i] = [i];
      for (var j = 1; j <= n; j++) {
        dp[i][j] = i === 0 ? j : 0;
      }
    }
    for (var i2 = 1; i2 <= m; i2++) {
      for (var j2 = 1; j2 <= n; j2++) {
        dp[i2][j2] = a[i2 - 1] === b[j2 - 1]
          ? dp[i2 - 1][j2 - 1]
          : 1 + Math.min(dp[i2 - 1][j2], dp[i2][j2 - 1], dp[i2 - 1][j2 - 1]);
      }
    }
    return dp[m][n];
  }

  // Find closest tool name for typo suggestions (max distance 3).
  function findClosestTool(input) {
    if (!input || tools.length === 0) return null;
    var best = null, bestDist = 4;
    for (var i = 0; i < tools.length; i++) {
      var name = tools[i].name || '';
      var d = levenshtein(input.toLowerCase(), name.toLowerCase());
      if (d > 0 && d < bestDist) {
        bestDist = d;
        best = name;
      }
    }
    return best;
  }

  // Check if a tool match value is a glob pattern (contains * or ?).
  function isGlobPattern(val) {
    return val && (val.indexOf('*') !== -1 || val.indexOf('?') !== -1);
  }

  // Check if a tool match value matches any registered tool.
  function toolMatchExists(val) {
    if (!val || val === '*') return true;
    if (isGlobPattern(val)) {
      // Verify the glob actually matches at least one registered tool
      for (var gi = 0; gi < tools.length; gi++) {
        if (globMatch(val, tools[gi].name || '')) return true;
      }
      return tools.length === 0; // no tools loaded yet → assume valid
    }
    for (var i = 0; i < tools.length; i++) {
      if ((tools[i].name || '') === val) return true;
    }
    return false;
  }

  // Smart suggestions based on current conditions.
  function getSmartSuggestions(conditions, toolMatch, action) {
    var suggestions = [];
    var hasToolCondition = false;
    var hasRoleCondition = false;
    for (var i = 0; i < conditions.length; i++) {
      if (conditions[i].variable === 'tool_name') hasToolCondition = true;
      if (conditions[i].variable === 'identity_roles' || conditions[i].variable === 'user_roles') hasRoleCondition = true;
    }
    // If blocking a specific tool but no role check
    if (action === 'deny' && (toolMatch || hasToolCondition) && !hasRoleCondition) {
      suggestions.push({
        text: 'Add a role condition? Most deny rules restrict by role (e.g., non-admin users only).',
        condition: { variable: 'identity_roles', operator: 'not_in', value: 'admin' }
      });
    }
    // If allowing all with no conditions
    if (action === 'allow' && (!toolMatch || toolMatch === '*') && conditions.length === 0) {
      suggestions.push({
        text: 'Consider restricting to a specific tool or role. Unrestricted allow rules are rarely needed.',
        condition: null
      });
    }
    // If using dest_domain, suggest dest_port too
    var hasDomain = false;
    var hasPort = false;
    for (var j = 0; j < conditions.length; j++) {
      if (conditions[j].variable === 'dest_domain') hasDomain = true;
      if (conditions[j].variable === 'dest_port') hasPort = true;
    }
    if (hasDomain && !hasPort) {
      suggestions.push({
        text: 'Also restrict by port? Outbound rules are more effective with port restrictions.',
        condition: { variable: 'dest_port', operator: 'eq', value: '443' }
      });
    }
    return suggestions;
  }

  // Debounced linter API call.
  var _lintTimer = null;
  function lintRule(condition, toolMatch, action, priority, ruleId, callback) {
    if (_lintTimer) clearTimeout(_lintTimer);
    _lintTimer = setTimeout(function () {
      SG.api.post('/policies/lint', {
        condition: condition,
        tool_match: toolMatch || '*',
        action: action || 'deny',
        priority: priority || 100,
        rule_id: ruleId || ''
      }).then(function (result) {
        callback(result.warnings || [], result.valid);
      }).catch(function () {
        callback([], true); // fail silently
      });
    }, 500);
  }

  // -- Rule editor modal (Visual Policy Builder) --------------------------------

  /**
   * Show a quick-rule popover when clicking a "No rule" badge.
   * Allows creating a simple allow/deny rule without opening the full modal.
   *
   * @param {string}      toolName     - Tool name to create a rule for
   * @param {HTMLElement}  badgeElement - The badge element for positioning
   */
  function showQuickRulePopover(toolName, badgeElement) {
    var existing = document.getElementById('quick-rule-popover');
    if (existing) existing.remove();

    var popover = mk('div', '', {
      id: 'quick-rule-popover',
      style: 'position: absolute; z-index: 1000; background: var(--bg-surface); ' +
        'border: 1px solid var(--border); border-radius: var(--radius-lg); ' +
        'padding: var(--space-4); width: 280px; box-shadow: var(--shadow-lg);'
    });

    // Tool name header
    var header = mk('div', '', {
      style: 'font-family: var(--font-mono); font-size: var(--text-sm); font-weight: var(--font-semibold); ' +
        'color: var(--text-primary); margin-bottom: var(--space-3); padding-bottom: var(--space-2); ' +
        'border-bottom: 1px solid var(--border);'
    });
    header.textContent = toolName;
    popover.appendChild(header);

    // Action label
    var actionLabel = mk('div', '', {
      style: 'font-size: var(--text-xs); color: var(--text-muted); text-transform: uppercase; ' +
        'letter-spacing: 0.05em; margin-bottom: var(--space-2);'
    });
    actionLabel.textContent = 'Quick Action';
    popover.appendChild(actionLabel);

    var selectedAction = 'deny';
    var actions = [
      { value: 'allow', label: 'Allow' },
      { value: 'deny', label: 'Deny' },
      { value: 'approval_required', label: 'Ask' }
    ];

    var radioGroup = mk('div', '', { style: 'display: flex; gap: var(--space-4); margin-bottom: var(--space-4);' });
    actions.forEach(function (a) {
      var label = mk('label', '', {
        style: 'display: flex; align-items: center; gap: var(--space-2); font-size: var(--text-sm); ' +
          'color: var(--text-secondary); cursor: pointer;'
      });
      var radio = mk('input', '');
      radio.type = 'radio';
      radio.name = 'quick-action';
      radio.value = a.value;
      if (a.value === 'deny') radio.checked = true;
      radio.addEventListener('change', function () { selectedAction = this.value; });
      label.appendChild(radio);
      label.appendChild(document.createTextNode(' ' + a.label));
      radioGroup.appendChild(label);
    });
    popover.appendChild(radioGroup);

    // Buttons
    var btnGroup = mk('div', '', { style: 'display: flex; gap: var(--space-2);' });

    var applyBtn = mk('button', 'btn btn-primary btn-sm');
    applyBtn.textContent = 'Apply';
    applyBtn.style.flex = '1';
    applyBtn.addEventListener('click', function () {
      applyBtn.disabled = true;
      applyBtn.textContent = 'Saving...';
      var ruleName = selectedAction.toLowerCase().replace('approval_required', 'ask') + '-' + toolName;
      var policyPayload = {
        name: ruleName,
        description: 'Quick rule for ' + toolName,
        enabled: true,
        rules: [{
          name: ruleName,
          tool_match: toolName,
          action: selectedAction,
          priority: 100,
          condition: 'true'
        }]
      };
      SG.api.post('/policies', policyPayload).then(function () {
        popover.remove();
        SG.toast.success('Rule created: ' + ruleName);
        var toolsContent = document.querySelector('.tools-content');
        if (toolsContent && toolsContent.parentElement) loadData(toolsContent.parentElement);
      }).catch(function (err) {
        applyBtn.disabled = false;
        applyBtn.textContent = 'Apply';
        SG.toast.error('Failed: ' + (err.message || 'Unknown error'));
      });
    });
    btnGroup.appendChild(applyBtn);

    var moreBtn = mk('button', 'btn btn-secondary btn-sm');
    moreBtn.textContent = 'More options\u2026';
    moreBtn.style.flex = '1';
    moreBtn.addEventListener('click', function () {
      popover.remove();
      openRuleModal(null, null, toolName);
    });
    btnGroup.appendChild(moreBtn);
    popover.appendChild(btnGroup);

    // Position: anchor to the right edge of the badge, below it
    var rect = badgeElement.getBoundingClientRect();
    popover.style.top = (rect.bottom + window.scrollY + 4) + 'px';
    // Align right edge of popover with right edge of badge
    popover.style.right = (document.documentElement.clientWidth - rect.right - window.scrollX) + 'px';
    document.body.appendChild(popover);

    setTimeout(function () {
      document.addEventListener('click', function dismiss(e) {
        if (!popover.contains(e.target) && e.target !== badgeElement) {
          popover.remove();
          document.removeEventListener('click', dismiss);
        }
      });
    }, 0);
  }

  /**
   * Open the Visual Policy Builder modal.
   * Replaces the old Simple/Advanced rule editor with a condition-based builder
   * plus a CEL editor tab for power users.
   *
   * @param {Object|null}  existingRule      - Rule object to edit, or null for new
   * @param {string|null}  policyId          - Policy ID containing the rule
   * @param {string|null}  prefilledToolName - Tool name to pre-fill (from "No rule" badge click)
   */
  function openRuleModal(existingRule, policyId, prefilledToolName) {
    var isEdit = existingRule != null;
    var activeRuleTab = 'builder';

    // -- Builder state ------------------------------------------------------
    var conditions = [];
    var combinator = 'AND';

    // -- Build modal body ---------------------------------------------------
    var body = mk('div', 'rule-modal-form');

    // -- Tabs ---------------------------------------------------------------
    var tabs = mk('div', 'rule-tabs');
    var builderTab = mk('button', 'rule-tab active');
    builderTab.type = 'button';
    builderTab.textContent = 'Builder';
    var celTab = mk('button', 'rule-tab');
    celTab.type = 'button';
    celTab.textContent = 'CEL';
    var helpBtn = mk('button', 'rule-tab', {
      style: 'margin-left: auto; font-size: var(--text-sm); min-width: 28px;',
      'aria-label': 'Rule builder help'
    });
    helpBtn.type = 'button';
    helpBtn.textContent = '?';
    helpBtn.addEventListener('click', function () {
      var helpPanel = body.querySelector('.builder-help-panel');
      if (helpPanel) {
        helpPanel.style.display = helpPanel.style.display === 'none' ? 'block' : 'none';
      }
    });
    tabs.appendChild(builderTab);
    tabs.appendChild(celTab);
    tabs.appendChild(helpBtn);
    body.appendChild(tabs);

    // Help panel (hidden by default) — full guide matching 3-step flow
    var helpPanel = mk('div', 'builder-help-panel', {
      style: 'display: none; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: var(--radius-md); padding: var(--space-3); margin-bottom: var(--space-3); font-size: var(--text-sm); line-height: 1.6; max-height: 400px; overflow-y: auto;'
    });
    helpPanel.innerHTML =
      '<h4 style="margin: 0 0 var(--space-3) 0;">How to create a security rule</h4>' +
      '<p style="margin: 0 0 var(--space-3) 0; color: var(--text-muted);">The form below walks you through 3 steps. Follow them top to bottom and you\u2019ll have a working rule in seconds.</p>' +

      '<div style="margin-bottom: var(--space-3);">' +
      '<strong>Step 1 \u2014 What should happen?</strong>' +
      '<p style="margin: var(--space-1) 0;">Choose the action from the dropdown:</p>' +
      '<ul style="margin: var(--space-1) 0; padding-left: var(--space-4);">' +
      '<li><strong>Deny</strong> \u2014 block the tool call. The agent gets an error and cannot proceed.</li>' +
      '<li><strong>Allow</strong> \u2014 explicitly permit the tool call. Useful to create exceptions to broader deny rules.</li>' +
      '<li><strong>Ask</strong> \u2014 pause the tool call and send you a notification. You approve or reject it from the Notifications page. The agent waits until you decide.</li>' +
      '</ul>' +
      '</div>' +

      '<div style="margin-bottom: var(--space-3);">' +
      '<strong>Step 2 \u2014 Which tool?</strong>' +
      '<p style="margin: var(--space-1) 0;">Click one of the tool chips below the input \u2014 they are the real tools from your connected servers. You can also type a name directly.</p>' +
      '<ul style="margin: var(--space-1) 0; padding-left: var(--space-4);">' +
      '<li><strong>Single tool:</strong> click the chip or type the name, e.g. <code>write_file</code></li>' +
      '<li><strong>Group of tools:</strong> type a pattern with <code>*</code>, e.g. <code>read_*</code> matches all tools starting with "read_"</li>' +
      '<li><strong>All tools:</strong> click the <em>* (all tools)</em> chip or type <code>*</code></li>' +
      '</ul>' +
      '<div style="border-left: 3px solid var(--accent); padding-left: var(--space-2); margin: var(--space-2) 0; color: var(--text-muted);">' +
      '<strong>Tip:</strong> start with a single tool \u2014 it\u2019s easier to expand later than to fix a rule that blocks everything.' +
      '</div>' +
      '</div>' +

      '<div style="margin-bottom: var(--space-3);">' +
      '<strong>Step 3 \u2014 For whom? (optional)</strong>' +
      '<p style="margin: var(--space-1) 0;">Without conditions, the rule applies to <strong>every agent and every call</strong> to the matched tool. Add conditions to restrict when it applies.</p>' +
      '<p style="margin: var(--space-1) 0;">The quick suggestions below the button use your real identities \u2014 click one to add it instantly. Or click "+ Add Condition" to build your own:</p>' +
      '<ul style="margin: var(--space-1) 0; padding-left: var(--space-4);">' +
      '<li><strong>Variable</strong> \u2014 what to check (identity, role, file path, arguments...)</li>' +
      '<li><strong>Operator</strong> \u2014 how to compare (equals, not equals, contains, starts with, ends with, matches regex)</li>' +
      '<li><strong>Value</strong> \u2014 the value to match against</li>' +
      '</ul>' +
      '<div style="border-left: 3px solid var(--accent); padding-left: var(--space-2); margin: var(--space-2) 0; color: var(--text-muted);">' +
      '<strong>Example:</strong> to deny <code>write_file</code> only for non-admin users, click "Only for non-admins" or add: Variable = <code>identity_roles</code>, Operator = <code>does not contain</code>, Value = <code>admin</code>.' +
      '</div>' +
      '</div>' +

      '<div style="margin-bottom: var(--space-3);">' +
      '<strong>Name, Priority & Review</strong>' +
      '<p style="margin: var(--space-1) 0;">The <strong>Rule Name</strong> is auto-generated from your choices (e.g. <code>deny-write_file</code>). You can edit it freely if you want a custom name.</p>' +
      '<p style="margin: var(--space-1) 0;"><strong>Priority</strong> decides which rule wins when multiple rules match the same tool. Higher number = higher priority. The default (100) is fine for most cases.</p>' +
      '<ul style="margin: var(--space-1) 0; padding-left: var(--space-4);">' +
      '<li>A common pattern: broad allow/deny at priority 50, specific exceptions at priority 100+</li>' +
      '<li>The priority context below the field shows where your rule stands relative to existing rules</li>' +
      '</ul>' +
      '<p style="margin: var(--space-1) 0;">The <strong>"What will happen"</strong> box shows a plain-English summary of your rule \u2014 read it to make sure it matches your intent.</p>' +
      '<p style="margin: var(--space-1) 0;">The <strong>green bar</strong> at the bottom confirms your rule is valid. If there\u2019s an issue, it turns red and tells you what to fix.</p>' +
      '</div>' +

      '<p style="margin: 0; color: var(--text-muted);">For advanced expressions with full control over the condition logic, switch to the <strong>CEL</strong> tab.</p>';
    body.appendChild(helpPanel);

    // =====================================================================
    //  BUILDER TAB — Stepped layout (1: Action, 2: Tool, 3: For whom)
    // =====================================================================
    var builderContent = mk('div', 'rule-tab-content active');

    // ── STEP 1: What should happen? ─────────────────────────────────────
    var step1 = mk('div', 'builder-step step-done');
    var step1Header = mk('div', 'step-header');
    var step1Num = mk('div', 'step-number step-complete');
    step1Num.textContent = '1';
    step1Header.appendChild(step1Num);
    var step1Title = mk('div', 'step-title');
    step1Title.textContent = 'What should happen?';
    step1Header.appendChild(step1Title);
    step1.appendChild(step1Header);
    var step1Desc = mk('div', 'step-desc');
    step1Desc.textContent = 'Choose the action for matching tool calls';
    step1.appendChild(step1Desc);
    var step1Content = mk('div', 'step-content');
    var actionSelect = mk('select', 'form-select', { style: 'width: auto; min-width: 200px;' });
    var optDeny = mk('option');
    optDeny.value = 'deny'; optDeny.textContent = 'Deny \u2014 block the call';
    actionSelect.appendChild(optDeny);
    var optAllow = mk('option');
    optAllow.value = 'allow'; optAllow.textContent = 'Allow \u2014 permit the call';
    actionSelect.appendChild(optAllow);
    var optAsk = mk('option');
    optAsk.value = 'approval_required'; optAsk.textContent = 'Ask \u2014 require approval';
    actionSelect.appendChild(optAsk);
    actionSelect.value = 'deny';
    actionSelect.addEventListener('change', function () { triggerUpdate(); });
    step1Content.appendChild(actionSelect);
    step1.appendChild(step1Content);
    builderContent.appendChild(step1);

    // ── STEP 2: Which tool? ─────────────────────────────────────────────
    var step2 = mk('div', 'builder-step');
    var step2Header = mk('div', 'step-header');
    var step2Num = mk('div', 'step-number');
    step2Num.textContent = '2';
    step2Header.appendChild(step2Num);
    var step2Title = mk('div', 'step-title');
    step2Title.textContent = 'Which tool?';
    step2Header.appendChild(step2Title);
    step2.appendChild(step2Header);
    var step2Desc = mk('div', 'step-desc');
    step2Desc.textContent = 'Click a tool below or type a name';
    step2.appendChild(step2Desc);
    var step2Content = mk('div', 'step-content');
    var matchInput = mk('input', 'form-input', {
      type: 'text', placeholder: 'Click a tool below or type a name...'
    });
    // Tool name autocomplete datalist
    var matchDlId = 'dl-toolmatch-' + Math.random().toString(36).substr(2, 5);
    var matchDatalist = mk('datalist');
    matchDatalist.id = matchDlId;
    for (var tmi = 0; tmi < tools.length; tmi++) {
      var tmOpt = mk('option');
      tmOpt.value = tools[tmi].name || '';
      matchDatalist.appendChild(tmOpt);
    }
    matchInput.setAttribute('list', matchDlId);
    step2Content.appendChild(matchInput);
    step2Content.appendChild(matchDatalist);
    // Tool chips — real tools from connected servers
    // Field error for typo detection (before chips, for visual proximity to input)
    var toolFieldError = mk('div', 'field-error', { style: 'display: none;' });
    step2Content.appendChild(toolFieldError);
    // Tool chips — real tools from connected servers
    var toolChipsContainer = mk('div', 'tool-chips');
    step2Content.appendChild(toolChipsContainer);
    step2.appendChild(step2Content);
    builderContent.appendChild(step2);

    // ── STEP 3: For whom? ───────────────────────────────────────────────
    var step3 = mk('div', 'builder-step');
    var step3Header = mk('div', 'step-header');
    var step3Num = mk('div', 'step-number');
    step3Num.textContent = '3';
    step3Header.appendChild(step3Num);
    var step3Title = mk('div', 'step-title');
    step3Title.textContent = 'For whom?';
    step3Header.appendChild(step3Title);
    var step3Optional = mk('span', 'step-optional');
    step3Optional.textContent = '\u2014 optional';
    step3Header.appendChild(step3Optional);
    step3.appendChild(step3Header);
    var step3Desc = mk('div', 'step-desc');
    step3Desc.textContent = 'Add conditions to restrict when this rule applies. Skip to apply to everyone.';
    step3.appendChild(step3Desc);
    var step3Content = mk('div', 'step-content');

    // Condition builder (same vars as before — conditions, condRowsContainer, etc.)
    var prioGroup = mk('div', 'form-group meta-priority');
    var prioLabel = mk('label', 'form-label');
    prioLabel.textContent = 'Priority';
    prioGroup.appendChild(prioLabel);
    var prioInput = mk('input', 'form-input', {
      type: 'number', min: '1', max: '1000', value: '100'
    });
    prioGroup.appendChild(prioInput);

    // -- Priority context visualization ------------------------------------
    var prioHint = mk('div', 'form-help', { style: 'color: var(--accent-text); margin-top: 3px;' });
    prioHint.textContent = 'Higher = wins';
    prioGroup.appendChild(prioHint);
    var priorityContext = mk('div', '', {
      style: 'margin-top: var(--space-1); font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); line-height: 1.4;'
    });
    priorityContext.id = 'priority-context';
    prioGroup.appendChild(priorityContext);

    // -- Condition Builder (inside step 3) ---------------------------------
    var condBuilder = mk('div', 'condition-builder');
    var condRowsContainer = mk('div', 'condition-rows');
    condBuilder.appendChild(condRowsContainer);

    // Add condition button row
    var addRow = mk('div', 'condition-add-row', { style: 'text-align: center;' });
    var addBtn = mk('button', 'condition-add-btn');
    addBtn.type = 'button';
    addBtn.textContent = '+ Add Condition';
    addBtn.addEventListener('click', function () {
      conditions.push({ variable: '', operator: '', value: '' });
      renderConditions();
      triggerUpdate();
    });
    addRow.appendChild(addBtn);

    // Variable catalog toggle
    var catToggle = mk('button', 'variable-catalog-toggle');
    catToggle.type = 'button';
    catToggle.textContent = 'Variable Catalog';
    catToggle.style.marginLeft = 'var(--space-3)';
    catToggle.addEventListener('click', function () {
      var cat = condBuilder.querySelector('.cel-help');
      if (cat) {
        cat.style.display = cat.style.display === 'none' ? 'block' : 'none';
      }
    });
    addRow.appendChild(catToggle);

    // CEL Examples toggle
    var exToggle = mk('button', 'variable-catalog-toggle');
    exToggle.type = 'button';
    exToggle.textContent = 'Examples';
    exToggle.style.marginLeft = 'var(--space-3)';
    exToggle.addEventListener('click', function () {
      var panel = condBuilder.querySelector('.cel-examples-panel');
      if (panel) {
        panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
      }
    });
    addRow.appendChild(exToggle);
    condBuilder.appendChild(addRow);

    // Condition hint (shown when no conditions)
    var conditionHint = mk('div', '', {
      style: 'text-align: center; font-size: var(--text-xs); color: var(--text-muted); margin-top: var(--space-2); line-height: 1.5;'
    });
    conditionHint.innerHTML = 'Without conditions, this rule <strong style="color: var(--text-primary);">applies to every call</strong> to the matched tool.';
    condBuilder.appendChild(conditionHint);

    // Quick condition chips
    var quickChipsContainer = mk('div', 'quick-conditions');
    condBuilder.appendChild(quickChipsContainer);

    // Variable catalog panel (hidden by default)
    var catalogPanel = mk('div', 'cel-help', { style: 'display: none; margin-top: var(--space-2);' });
    var catTitle = mk('div', 'cel-help-title');
    catTitle.textContent = 'Available Variables';
    catalogPanel.appendChild(catTitle);
    for (var ci = 0; ci < VARIABLE_CATALOG.length; ci++) {
      var cat = VARIABLE_CATALOG[ci];
      // All variable categories shown (aligned with dropdown and CEL tab)
      var catHead = mk('div', 'cel-help-category');
      catHead.textContent = cat.category;
      catalogPanel.appendChild(catHead);
      for (var vi = 0; vi < cat.variables.length; vi++) {
        var vInfo = cat.variables[vi];
        var vLine = mk('div', '', { style: 'margin-bottom: 2px; cursor: pointer;' });
        var vName = mk('span', 'cel-help-var');
        vName.textContent = vInfo.name;
        vLine.appendChild(vName);
        var vType = document.createTextNode(vInfo.type + ' \u2014 ' + vInfo.label);
        vLine.appendChild(vType);
        (function (varName) {
          vLine.addEventListener('click', function () {
            conditions.push({ variable: varName, operator: '', value: '' });
            renderConditions();
            triggerUpdate();
          });
        })(vInfo.name);
        catalogPanel.appendChild(vLine);
      }
    }
    condBuilder.appendChild(catalogPanel);

    // CEL Examples panel (hidden by default)
    var examplesPanel = mk('div', 'cel-examples-panel cel-help', { style: 'display: none; margin-top: var(--space-2);' });
    var exTitle = mk('div', 'cel-help-title');
    exTitle.textContent = 'Common Rule Examples';
    examplesPanel.appendChild(exTitle);

    var CEL_EXAMPLES = [
      { desc: 'Block a specific tool for non-admins', cel: 'tool_name == "execute_command" && !("admin" in identity_roles)' },
      { desc: 'Allow read-only tools for readers', cel: 'tool_name.startsWith("read_") && "reader" in identity_roles' },
      { desc: 'Block access to secret paths', cel: '"path" in arguments && (arguments["path"].contains("secret") || arguments["path"].contains(".env"))' },
      { desc: 'Rate limit by session call count', cel: 'session_call_count > 100' },
      { desc: 'Block expensive operations by cost', cel: 'session_cumulative_cost > 5.0' },
      { desc: 'Allow only during work hours', cel: 'request_time.getHours() >= 9 && request_time.getHours() < 18' },
      { desc: 'Block tool if used with specific arg', cel: '"password" in arguments || "secret" in arguments' },
      { desc: 'Restrict tool to specific identity', cel: 'identity_name == "production-bot"' }
    ];

    for (var exi = 0; exi < CEL_EXAMPLES.length; exi++) {
      (function (ex) {
        var exLine = mk('div', '', { style: 'margin-bottom: var(--space-2); cursor: pointer; padding: var(--space-1); border-radius: var(--radius-sm);' });
        exLine.addEventListener('mouseenter', function () { exLine.style.background = 'var(--bg-secondary)'; });
        exLine.addEventListener('mouseleave', function () { exLine.style.background = ''; });
        var exDesc = mk('div', '', { style: 'font-size: var(--text-xs); color: var(--text-muted); margin-bottom: 2px;' });
        exDesc.textContent = ex.desc;
        exLine.appendChild(exDesc);
        var exCode = mk('code', '', { style: 'font-size: var(--text-xs); color: var(--accent);' });
        exCode.textContent = ex.cel;
        exLine.appendChild(exCode);
        exLine.addEventListener('click', function () {
          celTextarea.value = ex.cel;
          switchTab('cel');
          SG.toast.info('Example loaded in CEL editor');
        });
        examplesPanel.appendChild(exLine);
      })(CEL_EXAMPLES[exi]);
    }
    condBuilder.appendChild(examplesPanel);

    step3Content.appendChild(condBuilder);
    step3.appendChild(step3Content);
    builderContent.appendChild(step3);

    // ── Name + Priority row (below step 3) ──────────────────────────────
    var nameMetaRow = mk('div', '', {
      style: 'display: flex; gap: var(--space-3); margin-bottom: var(--space-3); padding-left: 34px;'
    });
    var nameGroup = mk('div', 'form-group', { style: 'flex: 1;' });
    var nameLabel = mk('label', 'form-label');
    nameLabel.textContent = 'Rule Name ';
    var autoTag = mk('span', 'auto-tag');
    autoTag.textContent = 'auto';
    nameLabel.appendChild(autoTag);
    nameGroup.appendChild(nameLabel);
    var nameInput = mk('input', 'form-input', {
      type: 'text', placeholder: 'Auto-generated from your choices'
    });
    nameInput.style.fontStyle = 'italic';
    nameInput.style.color = 'var(--text-muted)';
    nameGroup.appendChild(nameInput);
    var nameHelp = mk('div', 'form-help');
    nameHelp.textContent = 'Auto-generated. Edit freely to customize.';
    nameGroup.appendChild(nameHelp);
    nameMetaRow.appendChild(nameGroup);
    nameMetaRow.appendChild(prioGroup);
    builderContent.appendChild(nameMetaRow);

    // ── "What will happen" preview ──────────────────────────────────────
    var whatWillHappen = mk('div', 'what-will-happen');
    var wwhLabel = mk('div', 'wwh-label');
    wwhLabel.textContent = 'What will happen';
    whatWillHappen.appendChild(wwhLabel);
    var wwhText = mk('div');
    wwhText.innerHTML = 'Configure the rule above to see a preview.';
    whatWillHappen.appendChild(wwhText);
    builderContent.appendChild(whatWillHappen);

    // -- CEL Preview --------------------------------------------------------
    var celPreview = mk('div', 'cel-preview');
    var prevHeader = mk('div', 'cel-preview-header');
    var prevTitle = mk('div', 'cel-preview-title');
    prevTitle.textContent = 'CEL GENERATED';
    prevHeader.appendChild(prevTitle);
    var prevEditBtn = mk('button', 'cel-preview-edit-btn');
    prevEditBtn.type = 'button';
    prevEditBtn.textContent = 'Edit CEL';
    prevEditBtn.addEventListener('click', function () {
      celTextarea.value = celPreviewCode.textContent || 'true';
      switchTab('cel');
    });
    prevHeader.appendChild(prevEditBtn);
    celPreview.appendChild(prevHeader);
    var celPreviewCode = mk('div', 'cel-preview-code');
    celPreviewCode.textContent = 'true';
    celPreview.appendChild(celPreviewCode);
    builderContent.appendChild(celPreview);

    // -- Validation bar (replaces lint container for Builder tab) ----------
    var validationBar = mk('div', 'validation-bar');
    builderContent.appendChild(validationBar);

    // -- Lint warnings container (kept for internal tracking) ---------------
    var lintContainer = mk('div', 'lint-warnings', { style: 'display: none;' });
    builderContent.appendChild(lintContainer);

    // -- Suggestions container ----------------------------------------------
    var suggestContainer = mk('div', 'builder-suggestions');
    builderContent.appendChild(suggestContainer);

    body.appendChild(builderContent);

    // =====================================================================
    //  CEL TAB
    // =====================================================================
    var celContent = mk('div', 'rule-tab-content');

    // CEL meta fields (name, tool_match, priority, action) replicated
    var celMetaNote = mk('div', 'form-help', {
      style: 'margin-bottom: var(--space-3);'
    });
    celMetaNote.textContent = 'Write your condition as a CEL expression. This gives you full control over the evaluation logic. Rule name, tool match, priority, and action are shared with the Builder tab.';
    celContent.appendChild(celMetaNote);

    var celGroup = mk('div', 'form-group');
    var celLabel2 = mk('label', 'form-label');
    celLabel2.textContent = 'CEL Expression';
    celGroup.appendChild(celLabel2);
    var celTextarea = mk('textarea', 'cel-editor', {
      placeholder: 'e.g. tool_name == "file_read" && "admin" in identity_roles'
    });
    celGroup.appendChild(celTextarea);
    celContent.appendChild(celGroup);

    // Variable reference (enhanced from catalog)
    var celHelp = mk('div', 'cel-help');
    var celHelpTitle = mk('div', 'cel-help-title');
    celHelpTitle.textContent = 'Variables & Functions Reference';
    celHelp.appendChild(celHelpTitle);
    for (var si = 0; si < VARIABLE_CATALOG.length; si++) {
      var sect = VARIABLE_CATALOG[si];
      var sectHead = mk('div', 'cel-help-category');
      sectHead.textContent = sect.category;
      celHelp.appendChild(sectHead);
      for (var svi = 0; svi < sect.variables.length; svi++) {
        var sv = sect.variables[svi];
        var svLine = mk('div', '', { style: 'margin-bottom: 2px;' });
        var svName = mk('span', 'cel-help-var');
        svName.textContent = sv.name;
        svLine.appendChild(svName);
        svLine.appendChild(document.createTextNode(sv.type + ' \u2014 e.g. ' + sv.example));
        celHelp.appendChild(svLine);
        // Extended description for arguments (map type)
        if (sv.name === 'arguments') {
          var argDesc = mk('div', '', { style: 'margin-left: var(--space-4); font-size: var(--text-xs); color: var(--text-muted); margin-bottom: var(--space-1);' });
          argDesc.textContent = 'arguments is a map of all tool call parameters. Access keys with arguments["key"]. Examples: arguments["path"].contains("secret"), "path" in arguments, arguments["command"] == "rm"';
          celHelp.appendChild(argDesc);
        }
      }
    }
    // Functions section
    var fnHead = mk('div', 'cel-help-category');
    fnHead.textContent = 'Functions';
    celHelp.appendChild(fnHead);
    var fnList = [
      ['glob("pattern", name)', 'filepath-style glob match'],
      ['dest_ip_in_cidr(ip, "10.0.0.0/8")', 'IP in CIDR range'],
      ['dest_domain_matches(domain, "*.evil.com")', 'domain wildcard match'],
      ['action_arg(arguments, "key")', 'get argument by key'],
      ['action_arg_contains(arguments, "pat")', 'search all argument values'],
      ['session_count(history, "read")', 'count by call type'],
      ['session_count_for(history, "tool")', 'count by tool name'],
      ['session_count_window(history, "tool", 60)', 'count in last N seconds'],
      ['session_has_action(action_set, "tool")', 'tool used in session?'],
      ['session_has_arg(arg_key_set, "key")', 'arg key used in session?'],
      ['session_has_arg_in(history, "key", "tool")', 'arg key used with tool?'],
      ['session_sequence(history, "a", "b")', 'check A before B'],
      ['session_time_since_action(history, "tool")', 'seconds since last call']
    ];
    for (var fi = 0; fi < fnList.length; fi++) {
      var fLine = mk('div', '', { style: 'margin-bottom: 2px;' });
      var fName = mk('span', 'cel-help-var');
      fName.textContent = fnList[fi][0];
      fLine.appendChild(fName);
      fLine.appendChild(document.createTextNode(fnList[fi][1]));
      celHelp.appendChild(fLine);
    }
    celContent.appendChild(celHelp);

    // CEL Examples section (duplicated from builder for convenience)
    var celExamplesSection = mk('div', 'cel-help', { style: 'margin-top: var(--space-3); border-top: 2px solid var(--border); padding-top: var(--space-3);' });
    var celExTitle = mk('div', 'cel-help-title');
    celExTitle.textContent = 'Examples';
    celExamplesSection.appendChild(celExTitle);

    var CEL_TAB_EXAMPLES = [
      { desc: 'Block a specific tool for non-admins', cel: 'tool_name == "execute_command" && !("admin" in identity_roles)' },
      { desc: 'Allow read-only tools for readers', cel: 'tool_name.startsWith("read_") && "reader" in identity_roles' },
      { desc: 'Block access to secret paths', cel: '"path" in arguments && (arguments["path"].contains("secret") || arguments["path"].contains(".env"))' },
      { desc: 'Rate limit by session call count', cel: 'session_call_count > 100' },
      { desc: 'Block expensive operations by cost', cel: 'session_cumulative_cost > 5.0' },
      { desc: 'Allow only during work hours', cel: 'request_time.getHours() >= 9 && request_time.getHours() < 18' },
      { desc: 'Block tool if used with specific arg', cel: '"password" in arguments || "secret" in arguments' },
      { desc: 'Restrict tool to specific identity', cel: 'identity_name == "production-bot"' }
    ];

    for (var cei = 0; cei < CEL_TAB_EXAMPLES.length; cei++) {
      (function (ex) {
        var exLine = mk('div', '', { style: 'margin-bottom: var(--space-2); cursor: pointer; padding: var(--space-1); border-radius: var(--radius-sm);' });
        exLine.addEventListener('mouseenter', function () { exLine.style.background = 'var(--bg-secondary)'; });
        exLine.addEventListener('mouseleave', function () { exLine.style.background = ''; });
        var exDesc = mk('div', '', { style: 'font-size: var(--text-xs); color: var(--text-muted); margin-bottom: 2px;' });
        exDesc.textContent = ex.desc;
        exLine.appendChild(exDesc);
        var exCode = mk('code', '', { style: 'font-size: var(--text-xs); color: var(--accent);' });
        exCode.textContent = ex.cel;
        exLine.appendChild(exCode);
        exLine.addEventListener('click', function () {
          celTextarea.value = ex.cel;
          SG.toast.info('Example loaded');
        });
        celExamplesSection.appendChild(exLine);
      })(CEL_TAB_EXAMPLES[cei]);
    }
    celContent.appendChild(celExamplesSection);

    // Lint warnings for CEL tab
    var celLintContainer = mk('div', 'lint-warnings');
    celContent.appendChild(celLintContainer);

    body.appendChild(celContent);

    // =====================================================================
    //  ESTIMATED IMPACT (Inline Simulation)
    // =====================================================================
    var impactSection = mk('div', 'impact-estimate-section', {
      style: 'border-top: 1px solid var(--border); padding-top: var(--space-3); margin-top: var(--space-3);'
    });

    var impactHeader = mk('div', '', {
      style: 'display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-2);'
    });
    var impactTitle = mk('div', 'condition-builder-label');
    impactTitle.textContent = 'ESTIMATED IMPACT';
    impactTitle.style.marginBottom = '0';
    impactHeader.appendChild(impactTitle);

    var impactBtn = mk('button', 'btn btn-secondary btn-sm');
    impactBtn.type = 'button';
    impactBtn.textContent = 'Preview Impact';
    impactHeader.appendChild(impactBtn);
    impactSection.appendChild(impactHeader);

    var impactHelp = mk('div', 'form-help', {
      style: 'margin-bottom: var(--space-2);'
    });
    impactHelp.textContent = 'Replay recent audit traffic against this rule to estimate the impact on real decisions.';
    impactSection.appendChild(impactHelp);

    var impactResultContainer = mk('div', 'impact-result');
    impactSection.appendChild(impactResultContainer);

    impactBtn.addEventListener('click', function () {
      impactBtn.disabled = true;
      impactBtn.textContent = 'Analyzing\u2026';
      impactResultContainer.innerHTML = '';

      var loadingMsg = mk('div', '', {
        style: 'font-size: var(--text-sm); color: var(--text-muted);'
      });
      loadingMsg.textContent = 'Analyzing audit traffic\u2026';
      impactResultContainer.appendChild(loadingMsg);

      // Include the rule being built as a candidate rule for accurate impact preview.
      // The CEL condition is sent so the backend can evaluate it against each audit record.
      var candidateRules = [];
      var candidateToolMatch = matchInput.value.trim() || '*';
      var candidateAction = actionSelect.value || 'deny';
      var candidatePriority = parseInt(prioInput.value, 10) || 100;
      var candidateCondition = '';
      if (activeRuleTab === 'cel') {
        candidateCondition = celTextarea.value.trim();
      } else {
        candidateCondition = generateCELFromConditions(conditions, combinator);
      }
      if (candidateToolMatch) {
        candidateRules.push({
          tool_match: candidateToolMatch,
          action: candidateAction,
          priority: candidatePriority,
          condition: candidateCondition || ''
        });
      }
      SG.api.post('/v1/simulation/run', { max_records: 100, tool_match: candidateToolMatch, candidate_rules: candidateRules }).then(function (result) {
        impactBtn.disabled = false;
        impactBtn.textContent = 'Preview Impact';
        impactResultContainer.innerHTML = '';

        if (result.total_analyzed === 0) {
          var noData = mk('div', '', {
            style: 'font-size: var(--text-sm); color: var(--text-muted);'
          });
          noData.textContent = 'No audit records found. Connect an agent and make some tool calls first.';
          impactResultContainer.appendChild(noData);
          return;
        }

        // Stats grid
        var statsGrid = mk('div', '', {
          style: 'display: grid; grid-template-columns: repeat(4, 1fr); gap: var(--space-2); margin-bottom: var(--space-2);'
        });

        // Analyzed
        var analyzedCell = mk('div', '', {
          style: 'background: var(--bg-secondary); border-radius: var(--radius-md); padding: var(--space-2); text-align: center;'
        });
        var analyzedNum = mk('div', '', {
          style: 'font-size: var(--text-lg); font-weight: var(--font-bold);'
        });
        analyzedNum.textContent = String(result.total_analyzed);
        analyzedCell.appendChild(analyzedNum);
        var analyzedLabel = mk('div', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted); text-transform: uppercase;'
        });
        analyzedLabel.textContent = 'Analyzed';
        analyzedCell.appendChild(analyzedLabel);
        statsGrid.appendChild(analyzedCell);

        // Would block (allow_to_deny)
        var blockCell = mk('div', '', {
          style: 'background: var(--bg-secondary); border-radius: var(--radius-md); padding: var(--space-2); text-align: center;'
        });
        var blockNum = mk('div', '', {
          style: 'font-size: var(--text-lg); font-weight: var(--font-bold); color: var(--danger);'
        });
        blockNum.textContent = String(result.allow_to_deny || 0);
        blockCell.appendChild(blockNum);
        var blockLabel = mk('div', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted); text-transform: uppercase;'
        });
        blockLabel.textContent = 'Would Block';
        blockCell.appendChild(blockLabel);
        statsGrid.appendChild(blockCell);

        // Would allow (deny_to_allow)
        var allowCell = mk('div', '', {
          style: 'background: var(--bg-secondary); border-radius: var(--radius-md); padding: var(--space-2); text-align: center;'
        });
        var allowNum = mk('div', '', {
          style: 'font-size: var(--text-lg); font-weight: var(--font-bold); color: var(--success);'
        });
        allowNum.textContent = String(result.deny_to_allow || 0);
        allowCell.appendChild(allowNum);
        var allowLabel = mk('div', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted); text-transform: uppercase;'
        });
        allowLabel.textContent = 'Would Allow';
        allowCell.appendChild(allowLabel);
        statsGrid.appendChild(allowCell);

        // Not affected (unchanged)
        var unchangedCount = result.unchanged || 0;
        var unchangedCell = mk('div', '', {
          style: 'background: var(--bg-secondary); border-radius: var(--radius-md); padding: var(--space-2); text-align: center;'
        });
        var unchangedNum = mk('div', '', {
          style: 'font-size: var(--text-lg); font-weight: var(--font-bold); color: var(--text-muted);'
        });
        unchangedNum.textContent = String(unchangedCount);
        unchangedCell.appendChild(unchangedNum);
        var unchangedLabel = mk('div', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted); text-transform: uppercase;'
        });
        unchangedLabel.textContent = 'Unchanged';
        unchangedCell.appendChild(unchangedLabel);
        statsGrid.appendChild(unchangedCell);

        impactResultContainer.appendChild(statsGrid);

        // Impacted agents and tools
        var impactedAgents = result.impacted_agents || [];
        var impactedTools = result.impacted_tools || [];
        if (impactedAgents.length > 0 || impactedTools.length > 0) {
          var impactDetails = mk('div', '', {
            style: 'font-size: var(--text-sm); margin-top: var(--space-1);'
          });
          if (impactedAgents.length > 0) {
            var agentLine = mk('div', '', { style: 'margin-bottom: 2px;' });
            var agentBold = mk('strong');
            agentBold.textContent = 'Impacted identities: ';
            agentLine.appendChild(agentBold);
            for (var ai = 0; ai < impactedAgents.length; ai++) {
              if (ai > 0) agentLine.appendChild(document.createTextNode(', '));
              var agentCode = mk('code');
              // Resolve UUID to identity name
              var agentDisplay = impactedAgents[ai];
              for (var ci = 0; ci < _cachedIdentities.length; ci++) {
                if (_cachedIdentities[ci].id === impactedAgents[ai]) {
                  agentDisplay = _cachedIdentities[ci].name || impactedAgents[ai];
                  break;
                }
              }
              agentCode.textContent = agentDisplay;
              agentLine.appendChild(agentCode);
            }
            impactDetails.appendChild(agentLine);
          }
          if (impactedTools.length > 0) {
            var toolLine = mk('div');
            var toolBold = mk('strong');
            toolBold.textContent = 'Impacted tools: ';
            toolLine.appendChild(toolBold);
            for (var ti2 = 0; ti2 < impactedTools.length; ti2++) {
              if (ti2 > 0) toolLine.appendChild(document.createTextNode(', '));
              var toolCode = mk('code');
              toolCode.textContent = impactedTools[ti2];
              toolLine.appendChild(toolCode);
            }
            impactDetails.appendChild(toolLine);
          }
          impactResultContainer.appendChild(impactDetails);
        }

        // Duration
        var durationLine = mk('div', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted); margin-top: var(--space-1);'
        });
        durationLine.textContent = 'Completed in ' + (result.duration_ms || 0) + 'ms';
        impactResultContainer.appendChild(durationLine);

      }).catch(function (err) {
        impactBtn.disabled = false;
        impactBtn.textContent = 'Preview Impact';
        impactResultContainer.innerHTML = '';
        var errMsg = mk('div', '', {
          style: 'font-size: var(--text-sm); color: var(--danger);'
        });
        errMsg.textContent = 'Simulation failed: ' + (err.message || 'Unknown error');
        impactResultContainer.appendChild(errMsg);
      });
    });

    body.appendChild(impactSection);

    // =====================================================================
    //  RENDER & UPDATE HELPERS
    // =====================================================================

    // Build a variable dropdown with optgroups by category.
    function buildVariableSelect(selectedVar) {
      var sel = mk('select', 'condition-var');
      var emptyOpt = mk('option');
      emptyOpt.value = '';
      emptyOpt.textContent = 'Select variable...';
      sel.appendChild(emptyOpt);
      for (var ci2 = 0; ci2 < VARIABLE_CATALOG.length; ci2++) {
        // All variable categories are available in both Builder and CEL tab
        var grp = mk('optgroup');
        grp.label = VARIABLE_CATALOG[ci2].category;
        var gvars = VARIABLE_CATALOG[ci2].variables;
        for (var gv = 0; gv < gvars.length; gv++) {
          var opt = mk('option');
          opt.value = gvars[gv].name;
          opt.textContent = gvars[gv].label + ' (' + gvars[gv].name + ')';
          if (gvars[gv].name === selectedVar) opt.selected = true;
          grp.appendChild(opt);
        }
        sel.appendChild(grp);
      }
      return sel;
    }

    // Build an operator dropdown for a given variable.
    function buildOperatorSelect(varName, selectedOp) {
      var sel = mk('select', 'condition-op');
      var ops = getOperatorsForVariable(varName);
      for (var oi = 0; oi < ops.length; oi++) {
        var opt = mk('option');
        opt.value = ops[oi].value;
        opt.textContent = ops[oi].label;
        if (ops[oi].value === selectedOp) opt.selected = true;
        sel.appendChild(opt);
      }
      return sel;
    }

    // Build a value input with optional suggestions.
    function buildValueInput(varName, currentVal, operator) {
      var info = getVariableInfo(varName);
      var input = mk('input', 'condition-val', {
        type: (info && info.type === 'int') ? 'number' : 'text',
        placeholder: (info && info.example) ? 'e.g. ' + info.example : 'value'
      });
      input.value = currentVal || '';
      // Only show datalist/autocomplete for exact-match operators, not partial-match
      var isExactOp = operator === 'equals' || operator === 'not_equals' || operator === 'matches';
      // Add datalist for suggestions
      if (isExactOp && info && info.suggestions && info.suggestions.length > 0) {
        var dlId = 'dl-' + varName + '-' + Math.random().toString(36).substr(2, 5);
        var dl = mk('datalist');
        dl.id = dlId;
        for (var di = 0; di < info.suggestions.length; di++) {
          var dlOpt = mk('option');
          dlOpt.value = info.suggestions[di];
          dl.appendChild(dlOpt);
        }
        input.setAttribute('list', dlId);
        input.parentNode && input.parentNode.appendChild(dl);
        // We'll append the datalist after the input is in the DOM
        input._pendingDatalist = dl;
      }
      // Also add tool name autocomplete (only for exact-match operators)
      if (isExactOp && (varName === 'tool_name' || varName === 'action_name')) {
        var tdlId = 'dl-tools-' + Math.random().toString(36).substr(2, 5);
        var tdl = mk('datalist');
        tdl.id = tdlId;
        for (var ti = 0; ti < tools.length; ti++) {
          var tOpt = mk('option');
          tOpt.value = tools[ti].name || '';
          tdl.appendChild(tOpt);
        }
        input.setAttribute('list', tdlId);
        input._pendingDatalist = tdl;
      }
      // Identity name autocomplete from cached identities
      if (varName === 'identity_name' && _cachedIdentities.length > 0) {
        var idlId = 'dl-identity-' + Math.random().toString(36).substr(2, 5);
        var idl = mk('datalist');
        idl.id = idlId;
        for (var ii = 0; ii < _cachedIdentities.length; ii++) {
          var iOpt = mk('option');
          iOpt.value = _cachedIdentities[ii].name || '';
          idl.appendChild(iOpt);
        }
        input.setAttribute('list', idlId);
        input._pendingDatalist = idl;
      }
      // Identity roles autocomplete from known roles
      if (varName === 'identity_roles') {
        var knownRoles = ['admin', 'reader', 'developer', 'auditor'];
        // Also collect roles from cached identities
        for (var ri = 0; ri < _cachedIdentities.length; ri++) {
          var iRoles = _cachedIdentities[ri].roles || [];
          for (var rj = 0; rj < iRoles.length; rj++) {
            if (knownRoles.indexOf(iRoles[rj]) === -1) knownRoles.push(iRoles[rj]);
          }
        }
        var rdlId = 'dl-roles-' + Math.random().toString(36).substr(2, 5);
        var rdl = mk('datalist');
        rdl.id = rdlId;
        for (var rk = 0; rk < knownRoles.length; rk++) {
          var rOpt = mk('option');
          rOpt.value = knownRoles[rk];
          rdl.appendChild(rOpt);
        }
        input.setAttribute('list', rdlId);
        input._pendingDatalist = rdl;
      }
      return input;
    }

    // Render all condition rows.
    function renderConditions() {
      condRowsContainer.innerHTML = '';
      for (var idx = 0; idx < conditions.length; idx++) {
        // Combinator between rows
        if (idx > 0) {
          var combRow = mk('div', 'condition-combinator');
          var combSelect = mk('select');
          var andOpt = mk('option');
          andOpt.value = 'AND'; andOpt.textContent = 'AND';
          combSelect.appendChild(andOpt);
          var orOpt = mk('option');
          orOpt.value = 'OR'; orOpt.textContent = 'OR';
          combSelect.appendChild(orOpt);
          combSelect.value = combinator;
          (function () {
            combSelect.addEventListener('change', function () {
              combinator = this.value;
              triggerUpdate();
            });
          })();
          combRow.appendChild(combSelect);
          condRowsContainer.appendChild(combRow);
        }

        // Condition row
        var row = mk('div', 'condition-row');
        var cond = conditions[idx];

        // Variable select
        var varSel = buildVariableSelect(cond.variable);
        (function (i) {
          varSel.addEventListener('change', function () {
            conditions[i].variable = this.value;
            // Reset operator when variable changes (different type)
            var ops = getOperatorsForVariable(this.value);
            conditions[i].operator = ops.length > 0 ? ops[0].value : '';
            conditions[i].value = '';
            renderConditions();
            triggerUpdate();
          });
        })(idx);
        row.appendChild(varSel);

        // Operator select
        var opSel = buildOperatorSelect(cond.variable, cond.operator);
        (function (i) {
          opSel.addEventListener('change', function () {
            conditions[i].operator = this.value;
            renderConditions();
            triggerUpdate();
          });
        })(idx);
        row.appendChild(opSel);

        // Value input
        var valInput = buildValueInput(cond.variable, cond.value, cond.operator);
        (function (i) {
          valInput.addEventListener('input', function () {
            conditions[i].value = this.value;
            triggerUpdate();
          });
        })(idx);
        row.appendChild(valInput);
        // Append pending datalist
        if (valInput._pendingDatalist) {
          row.appendChild(valInput._pendingDatalist);
        }

        // Remove button
        var removeBtn = mk('button', 'condition-remove', {
          'aria-label': 'Remove condition'
        });
        removeBtn.type = 'button';
        removeBtn.innerHTML = '\u00d7';
        removeBtn.title = 'Remove condition';
        (function (i) {
          removeBtn.addEventListener('click', function () {
            conditions.splice(i, 1);
            renderConditions();
            triggerUpdate();
          });
        })(idx);
        row.appendChild(removeBtn);

        condRowsContainer.appendChild(row);
      }
    }

    // Update CEL preview, lint, and suggestions.
    function triggerUpdate() {
      var cel = generateCELFromConditions(conditions, combinator);
      celPreviewCode.textContent = cel;

      // Run linter
      var ruleId = isEdit && existingRule ? existingRule.id : '';
      lintRule(cel, matchInput.value.trim(), actionSelect.value,
        parseInt(prioInput.value, 10) || 100, ruleId,
        function (warnings, valid) {
          renderLintWarnings(lintContainer, warnings);
          renderValidationBar(warnings, valid);
        });

      // Smart suggestions
      renderSuggestions();

      // Update new Builder components
      updateWhatWillHappen();
      renderQuickConditions();
      updateStepStates();
      autoGenerateName();
    }

    // Render lint warnings into a container.
    function renderLintWarnings(container, warnings) {
      container.innerHTML = '';
      if (!warnings || warnings.length === 0) return;
      for (var wi = 0; wi < warnings.length; wi++) {
        var w = warnings[wi];
        var cls = 'lint-warning';
        if (w.severity === 'error') cls += ' lint-error';
        else if (w.severity === 'warning') cls += ' lint-warn';
        else cls += ' lint-info';
        var wEl = mk('div', cls);
        var icon = w.severity === 'error' ? '\u2716' : w.severity === 'warning' ? '\u26a0' : '\u2139';
        wEl.textContent = icon + ' ' + w.message;
        container.appendChild(wEl);
      }
    }

    // Render smart suggestions.
    function renderSuggestions() {
      suggestContainer.innerHTML = '';
      var suggs = getSmartSuggestions(conditions, matchInput.value.trim(), actionSelect.value);
      for (var si2 = 0; si2 < suggs.length; si2++) {
        var s = suggs[si2];
        var card = mk('div', 'suggestion-card');
        card.textContent = '\ud83d\udca1 ' + s.text;
        if (s.condition) {
          (function (cond) {
            card.addEventListener('click', function () {
              conditions.push({
                variable: cond.variable,
                operator: cond.operator,
                value: cond.value
              });
              renderConditions();
              triggerUpdate();
            });
          })(s.condition);
        }
        suggestContainer.appendChild(card);
      }
    }

    // -- Render tool chips from connected servers ----------------------------
    var _toolChipMaxShow = 12;
    function renderToolChips() {
      toolChipsContainer.innerHTML = '';
      var currentVal = matchInput.value.trim();
      var shown = 0;
      for (var tc = 0; tc < tools.length && shown < _toolChipMaxShow; tc++) {
        var tName = tools[tc].name || '';
        if (!tName) continue;
        var chip = mk('span', 'tool-chip');
        if (tName === currentVal) chip.className = 'tool-chip chip-active';
        chip.textContent = tName;
        (function (name) {
          chip.addEventListener('click', function () {
            matchInput.value = name;
            matchInput.style.fontStyle = '';
            matchInput.style.color = '';
            renderToolChips();
            triggerUpdate();
          });
        })(tName);
        toolChipsContainer.appendChild(chip);
        shown++;
      }
      if (tools.length > _toolChipMaxShow) {
        var moreChip = mk('span', 'tool-chip chip-all');
        moreChip.textContent = '+ ' + (tools.length - _toolChipMaxShow) + ' more';
        moreChip.addEventListener('click', function () {
          _toolChipMaxShow = tools.length;
          renderToolChips();
        });
        toolChipsContainer.appendChild(moreChip);
      }
      // "All tools" chip always at end
      var allChip = mk('span', 'tool-chip chip-all');
      if (currentVal === '*') allChip.className = 'tool-chip chip-active chip-all';
      allChip.textContent = '* (all tools)';
      allChip.addEventListener('click', function () {
        matchInput.value = '*';
        matchInput.style.fontStyle = '';
        matchInput.style.color = '';
        renderToolChips();
        triggerUpdate();
      });
      toolChipsContainer.appendChild(allChip);
    }

    // -- Render quick-condition suggestions ----------------------------------
    function renderQuickConditions() {
      quickChipsContainer.innerHTML = '';
      // Only show when no conditions exist
      if (conditions.length > 0) {
        conditionHint.style.display = 'none';
        quickChipsContainer.style.display = 'none';
        return;
      }
      conditionHint.style.display = '';
      quickChipsContainer.style.display = '';
      // Update hint text dynamically (XSS-safe via textContent)
      var actionVerbs = { deny: 'denies', allow: 'allows', approval_required: 'asks approval for' };
      var actionVerb = actionVerbs[actionSelect.value] || 'applies to';
      var tool = matchInput.value.trim() || 'the matched tool';
      conditionHint.innerHTML = '';
      conditionHint.appendChild(document.createTextNode('Without conditions, this rule '));
      var hintBold = mk('strong', '', { style: 'color: var(--text-primary);' });
      hintBold.textContent = actionVerb + ' every call';
      conditionHint.appendChild(hintBold);
      conditionHint.appendChild(document.createTextNode(' to '));
      var hintTool = mk('strong', '', { style: 'color: var(--accent-text);' });
      hintTool.textContent = tool;
      conditionHint.appendChild(hintTool);
      conditionHint.appendChild(document.createTextNode('.'));

      // Build suggestions from cached identities
      var chips = [];
      for (var qi = 0; qi < _cachedIdentities.length && chips.length < 3; qi++) {
        var idName = _cachedIdentities[qi].name;
        if (idName) {
          chips.push({
            label: 'Only for ' + idName,
            cond: { variable: 'identity_name', operator: 'equals', value: idName }
          });
        }
      }
      // "Only for non-admins" if any identity has admin role
      var hasAdmin = false;
      for (var ai = 0; ai < _cachedIdentities.length; ai++) {
        var roles = _cachedIdentities[ai].roles || [];
        for (var ri = 0; ri < roles.length; ri++) {
          if (roles[ri] === 'admin') { hasAdmin = true; break; }
        }
        if (hasAdmin) break;
      }
      if (hasAdmin) {
        chips.push({
          label: 'Only for non-admins',
          cond: { variable: 'identity_roles', operator: 'not_in', value: 'admin' }
        });
      }
      // Generic suggestion
      chips.push({
        label: 'When path contains...',
        cond: { variable: 'arguments', operator: 'contains', value: '' }
      });

      for (var ci2 = 0; ci2 < chips.length; ci2++) {
        var qchip = mk('span', 'quick-chip');
        qchip.textContent = chips[ci2].label;
        (function (cond) {
          qchip.addEventListener('click', function () {
            conditions.push({ variable: cond.variable, operator: cond.operator, value: cond.value });
            renderConditions();
            triggerUpdate();
          });
        })(chips[ci2].cond);
        quickChipsContainer.appendChild(qchip);
      }
    }

    // -- Generate "What will happen" preview ---------------------------------
    function updateWhatWillHappen() {
      // Build the preview using DOM elements (safe against XSS)
      wwhText.innerHTML = '';
      var action = actionSelect.value;
      var actionLabel, actionClass;
      if (action === 'deny') { actionLabel = 'DENY'; actionClass = 'wwh-deny'; }
      else if (action === 'allow') { actionLabel = 'ALLOW'; actionClass = 'wwh-allow'; }
      else { actionLabel = 'ASK APPROVAL FOR'; actionClass = 'wwh-ask'; }

      var tool = matchInput.value.trim() || '*';

      // "This rule will "
      wwhText.appendChild(document.createTextNode('This rule will '));
      // ACTION
      var actionSpan = mk('span', 'wwh-action ' + actionClass);
      actionSpan.textContent = actionLabel;
      wwhText.appendChild(actionSpan);
      wwhText.appendChild(document.createTextNode(' '));

      // "calls to TOOL" or "all tools"
      if (tool === '*') {
        wwhText.appendChild(document.createTextNode('all tool calls'));
      } else {
        wwhText.appendChild(document.createTextNode('calls to '));
        var toolSpan = mk('span', 'wwh-tool');
        toolSpan.textContent = tool;
        wwhText.appendChild(toolSpan);
      }

      // Conditions
      if (conditions.length > 0) {
        var parts = [];
        for (var wi = 0; wi < conditions.length; wi++) {
          var c = conditions[wi];
          if (!c.variable) continue;
          var varLabel = c.variable.replace(/_/g, ' ');
          var opLabel = c.operator || '';
          var valDisplay = c.value || '...';
          if (opLabel === 'equals') parts.push({ text: varLabel + ' is ', val: valDisplay });
          else if (opLabel === 'not_equals') parts.push({ text: varLabel + ' is not ', val: valDisplay });
          else if (opLabel === 'contains') parts.push({ text: varLabel + ' contains ', val: valDisplay });
          else if (opLabel === 'not_contains') parts.push({ text: varLabel + ' does not contain ', val: valDisplay });
          else if (opLabel === 'in') parts.push({ val: valDisplay, text: ' is in ' + varLabel, valFirst: true });
          else if (opLabel === 'not_in') parts.push({ val: valDisplay, text: ' is not in ' + varLabel, valFirst: true });
          else if (opLabel === 'starts_with') parts.push({ text: varLabel + ' starts with ', val: valDisplay });
          else parts.push({ text: varLabel + ' ' + opLabel + ' ', val: valDisplay });
        }
        if (parts.length > 0) {
          var joiner = combinator === 'OR' ? ' or ' : ' and ';
          wwhText.appendChild(document.createTextNode(' when '));
          for (var pi = 0; pi < parts.length; pi++) {
            if (pi > 0) wwhText.appendChild(document.createTextNode(joiner));
            var part = parts[pi];
            if (part.valFirst) {
              var vs = mk('span', 'wwh-identity');
              vs.textContent = part.val;
              wwhText.appendChild(vs);
              wwhText.appendChild(document.createTextNode(part.text));
            } else {
              wwhText.appendChild(document.createTextNode(part.text));
              var vs2 = mk('span', 'wwh-identity');
              vs2.textContent = part.val;
              wwhText.appendChild(vs2);
            }
          }
        }
      } else {
        wwhText.appendChild(document.createTextNode(' for '));
        var everyoneSpan = mk('strong');
        everyoneSpan.textContent = 'everyone';
        wwhText.appendChild(everyoneSpan);
      }

      var priority = parseInt(prioInput.value, 10) || 100;
      wwhText.appendChild(document.createTextNode(', at priority ' + priority + '.'));
    }

    // -- Render validation bar -----------------------------------------------
    var lastLintWarnings = [];
    var lastLintValid = true;

    function renderValidationBar(warnings, valid) {
      lastLintWarnings = warnings || [];
      lastLintValid = valid !== false;
      validationBar.innerHTML = '';

      // Client-side checks
      var toolVal = matchInput.value.trim();
      var toolExists = toolVal ? toolMatchExists(toolVal) : false;
      var hasConflict = false;
      for (var vbi = 0; vbi < lastLintWarnings.length; vbi++) {
        if (lastLintWarnings[vbi].type === 'shadow' || lastLintWarnings[vbi].type === 'conflict') {
          hasConflict = true;
          break;
        }
      }

      var syntaxOk = lastLintValid;
      var allOk = syntaxOk && toolExists && !hasConflict;

      validationBar.className = 'validation-bar ' + (allOk ? 'validation-valid' : 'validation-invalid');

      var icon = mk('span', '', { style: 'font-size: var(--text-sm);' });
      icon.textContent = allOk ? '\u2713' : '\u2717';
      validationBar.appendChild(icon);

      var msg = mk('span');
      if (allOk) {
        msg.textContent = 'Ready to save';
      } else {
        var issues = 0;
        if (!syntaxOk) issues++;
        if (!toolExists) issues++;
        if (hasConflict) issues++;
        msg.textContent = issues + ' issue' + (issues > 1 ? 's' : '') + ' to fix';
      }
      validationBar.appendChild(msg);

      var checks = mk('div', 'validation-checks');
      var c1 = mk('span', 'v-check ' + (syntaxOk ? 'v-pass' : 'v-fail'));
      c1.textContent = (syntaxOk ? '\u2713' : '\u2717') + ' Syntax';
      checks.appendChild(c1);
      var c2 = mk('span', 'v-check ' + (toolExists ? 'v-pass' : 'v-fail'));
      c2.textContent = (toolExists ? '\u2713' : '\u2717') + (!toolVal ? ' Tool required' : (toolExists ? ' Tool exists' : ' Tool not found'));
      checks.appendChild(c2);
      var c3 = mk('span', 'v-check ' + (!hasConflict ? 'v-pass' : 'v-fail'));
      c3.textContent = !hasConflict ? '\u2713 No conflicts' : '\u26a0 Conflicts';
      checks.appendChild(c3);
      validationBar.appendChild(checks);

      // Save button state — disabled unless syntax is valid AND tool is specified
      var canSave = syntaxOk && toolExists;
      saveBtn.disabled = !canSave;
      saveBtn.style.opacity = canSave ? '' : '0.5';
      saveBtn.style.cursor = canSave ? '' : 'not-allowed';

      // Update tool field error (typo detection — XSS-safe via textContent)
      if (toolVal && !toolExists && !isGlobPattern(toolVal)) {
        var closest = findClosestTool(toolVal);
        toolFieldError.style.display = '';
        toolFieldError.innerHTML = '';
        matchInput.classList.add('is-error');
        if (closest) {
          toolFieldError.appendChild(document.createTextNode('\u2717 "' + toolVal + '" not found \u2014 did you mean '));
          var fixLink = mk('a');
          fixLink.textContent = closest;
          fixLink.style.color = 'var(--accent-text)';
          fixLink.style.textDecoration = 'underline';
          fixLink.style.cursor = 'pointer';
          (function (fix) {
            fixLink.addEventListener('click', function () {
              matchInput.value = fix;
              matchInput.style.fontStyle = '';
              matchInput.style.color = '';
              renderToolChips();
              triggerUpdate();
            });
          })(closest);
          toolFieldError.appendChild(fixLink);
          toolFieldError.appendChild(document.createTextNode('?'));
        } else {
          toolFieldError.textContent = '\u2717 "' + toolVal + '" does not match any tool on your servers';
        }
        // Step 2 error state
        step2Num.className = 'step-number step-error';
      } else {
        toolFieldError.style.display = 'none';
        matchInput.classList.remove('is-error');
        if (toolVal) {
          step2Num.className = 'step-number step-complete';
          step2.className = 'builder-step step-done';
        } else {
          step2Num.className = 'step-number';
          step2.className = 'builder-step';
        }
      }

      // Step 3 state (always "done" since conditions are optional)
      step3Num.className = 'step-number step-complete';
      step3.className = 'builder-step step-done';
    }

    // -- Update step completion states ---------------------------------------
    function updateStepStates() {
      // Step 1: always done (action has default)
      step1Num.className = 'step-number step-complete';
      step1.className = 'builder-step step-done';
      // Step 2: done when tool match has value and is valid
      var toolVal = matchInput.value.trim();
      if (toolVal && toolMatchExists(toolVal)) {
        step2Num.className = 'step-number step-complete';
        step2.className = 'builder-step step-done';
      } else if (toolVal && !isGlobPattern(toolVal) && !toolMatchExists(toolVal)) {
        step2Num.className = 'step-number step-error';
        step2.className = 'builder-step';
      } else {
        step2Num.className = 'step-number';
        step2.className = 'builder-step';
      }
      // Step 3: always done (optional)
      step3Num.className = 'step-number step-complete';
      step3.className = 'builder-step step-done';
    }

    // -- Tab switching -------------------------------------------------------
    function switchTab(tab) {
      activeRuleTab = tab;
      if (tab === 'builder') {
        builderTab.classList.add('active');
        celTab.classList.remove('active');
        builderContent.classList.add('active');
        celContent.classList.remove('active');
      } else {
        celTab.classList.add('active');
        builderTab.classList.remove('active');
        celContent.classList.add('active');
        builderContent.classList.remove('active');
      }
    }

    builderTab.addEventListener('click', function () {
      if (activeRuleTab === 'builder') return;
      // Try to parse CEL back to conditions
      var celVal = celTextarea.value.trim();
      if (celVal) {
        var parsed = parseCELToConditions(celVal);
        if (parsed) {
          conditions = parsed.conditions;
          combinator = parsed.combinator;
          renderConditions();
          triggerUpdate();
        } else {
          SG.toast.info('Expression too complex for builder \u2014 use CEL tab');
          return;
        }
      }
      switchTab('builder');
    });

    celTab.addEventListener('click', function () {
      if (activeRuleTab === 'cel') return;
      // Sync current builder state to CEL textarea
      var cel = generateCELFromConditions(conditions, combinator);
      celTextarea.value = cel;
      switchTab('cel');
      // Lint the CEL
      var ruleId = isEdit && existingRule ? existingRule.id : '';
      lintRule(cel, matchInput.value.trim(), actionSelect.value,
        parseInt(prioInput.value, 10) || 100, ruleId,
        function (warnings) {
          renderLintWarnings(celLintContainer, warnings);
        });
    });

    // Lint on CEL textarea change
    celTextarea.addEventListener('input', function () {
      var cel = celTextarea.value.trim();
      var ruleId = isEdit && existingRule ? existingRule.id : '';
      lintRule(cel, matchInput.value.trim(), actionSelect.value,
        parseInt(prioInput.value, 10) || 100, ruleId,
        function (warnings) {
          renderLintWarnings(celLintContainer, warnings);
        });
    });

    // -- Pre-fill for edit mode ---------------------------------------------
    if (isEdit) {
      nameInput.value = existingRule.name || '';
      matchInput.value = existingRule.tool_match || '*';
      prioInput.value = String(existingRule.priority || 100);
      actionSelect.value = (existingRule.action || 'deny').toLowerCase();

      if (existingRule.condition && existingRule.condition !== 'true') {
        var parsed = parseCELToConditions(existingRule.condition);
        if (parsed && parsed.conditions.length > 0) {
          conditions = parsed.conditions;
          combinator = parsed.combinator;
        } else {
          // Complex expression — switch to CEL tab
          celTextarea.value = existingRule.condition;
          activeRuleTab = 'cel';
          builderTab.classList.remove('active');
          celTab.classList.add('active');
          builderContent.classList.remove('active');
          celContent.classList.add('active');
        }
      }
    } else if (prefilledToolName) {
      matchInput.value = prefilledToolName;
    }

    // -- Auto-generate rule name (5.1) ------------------------------------
    var nameManuallyEdited = !!existingRule; // true in edit mode

    nameInput.addEventListener('input', function () {
      nameManuallyEdited = true;
      nameInput.style.fontStyle = '';
      nameInput.style.color = '';
      if (autoTag) autoTag.style.display = 'none';
    });

    function autoGenerateName() {
      if (nameManuallyEdited) return;
      var action = actionSelect.value || 'deny';
      var prefix = action === 'approval_required' ? 'ask' : action.toLowerCase();
      var pattern = matchInput.value || '*';
      var name = prefix + '-' + pattern;
      // Add condition summary if present
      if (conditions.length > 0) {
        for (var ani = 0; ani < conditions.length; ani++) {
          var c = conditions[ani];
          if (!c.variable || !c.value) continue;
          if (c.variable === 'identity_name' && c.operator === 'not_equals') {
            name += '-not-' + c.value;
          } else if (c.variable === 'identity_name' && c.operator === 'equals') {
            name += '-' + c.value;
          } else if ((c.variable === 'identity_roles') && (c.operator === 'not_in' || c.operator === 'not_contains')) {
            name += '-not-' + c.value;
          } else if ((c.variable === 'identity_roles') && (c.operator === 'in' || c.operator === 'contains')) {
            name += '-' + c.value;
          }
          break; // only first condition in name
        }
      }
      // Truncate to 40 chars
      if (name.length > 40) name = name.substring(0, 40).replace(/-$/, '');
      nameInput.value = name;
      // Keep auto-generated styling
      nameInput.style.fontStyle = 'italic';
      nameInput.style.color = 'var(--text-muted)';
    }

    actionSelect.addEventListener('change', autoGenerateName);
    matchInput.addEventListener('input', function () {
      renderToolChips();
      triggerUpdate();
    });

    // Trigger initial auto-generate for new rules
    if (!existingRule) autoGenerateName();

    // -- Priority context visualization (5.2) -----------------------------
    function updatePriorityContext() {
      var currentPriority = parseInt(prioInput.value) || 100;
      var currentName = nameInput.value || '(this rule)';

      var allRules = [];
      if (_cachedPoliciesForPriority) {
        for (var p = 0; p < _cachedPoliciesForPriority.length; p++) {
          var rules = _cachedPoliciesForPriority[p].rules || [];
          for (var r = 0; r < rules.length; r++) {
            if (existingRule && rules[r].name === existingRule.name) continue;
            allRules.push({ name: rules[r].name, priority: rules[r].priority || 0 });
          }
        }
      }

      allRules.push({ name: currentName, priority: currentPriority, isCurrent: true });
      allRules.sort(function (a, b) { return b.priority - a.priority; });

      // XSS-safe: use textContent instead of innerHTML for user/server-provided names
      priorityContext.innerHTML = '';
      var pcHeader = mk('div', '', { style: 'margin-bottom: var(--space-1); color: var(--text-secondary);' });
      pcHeader.textContent = 'Evaluation order:';
      priorityContext.appendChild(pcHeader);
      for (var i = 0; i < allRules.length; i++) {
        var rule = allRules[i];
        var ruleDiv = mk('div');
        if (rule.isCurrent) {
          ruleDiv.style.color = 'var(--accent)';
          ruleDiv.style.fontWeight = 'var(--font-semibold)';
          ruleDiv.textContent = '  \u2192 ' + rule.name + ' (' + rule.priority + ') \u2190 this rule';
        } else {
          ruleDiv.textContent = '  ' + rule.name + ' (' + rule.priority + ')';
        }
        priorityContext.appendChild(ruleDiv);
      }
    }

    prioInput.addEventListener('input', function () {
      updatePriorityContext();
      updateWhatWillHappen();
    });
    nameInput.addEventListener('input', updatePriorityContext);
    updatePriorityContext();

    // Fetch policies for priority context
    SG.api.get('/policies').then(function (data) {
      _cachedPoliciesForPriority = data;
      updatePriorityContext();
    }).catch(function () {});

    renderConditions();
    renderToolChips();
    triggerUpdate();

    // -- Footer buttons -----------------------------------------------------
    var footerEl = mk('div', '', { style: 'display: contents;' });

    var cancelBtn = mk('button', 'btn btn-secondary');
    cancelBtn.type = 'button';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', function () { SG.modal.close(); });
    footerEl.appendChild(cancelBtn);

    var saveBtn = mk('button', 'btn btn-primary');
    saveBtn.type = 'button';
    saveBtn.textContent = isEdit ? 'Update Rule' : 'Save Rule';
    footerEl.appendChild(saveBtn);

    // -- Save handler -------------------------------------------------------
    saveBtn.addEventListener('click', function () {
      var ruleName = nameInput.value.trim();
      if (!ruleName) {
        SG.toast.error('Rule name is required');
        nameInput.focus();
        return;
      }

      var toolMatchValue = matchInput.value.trim();
      if (!toolMatchValue) {
        SG.toast.error('Tool match is required');
        matchInput.focus();
        return;
      }
      var actionValue = actionSelect.value;
      var priorityValue = parseInt(prioInput.value, 10) || 100;
      var celExpression;

      if (activeRuleTab === 'builder') {
        celExpression = generateCELFromConditions(conditions, combinator);
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
        description: 'Created from Policy Builder',
        priority: priorityValue,
        enabled: true,
        rules: [{
          name: ruleName,
          priority: priorityValue,
          tool_match: toolMatchValue,
          condition: celExpression,
          action: actionValue
        }]
      };

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
        saveBtn.textContent = isEdit ? 'Update Rule' : 'Save Rule';
      });
    });

    // -- Open modal ---------------------------------------------------------
    SG.modal.open({
      title: isEdit ? 'Edit Rule' : 'New Rule',
      body: body,
      footer: footerEl,
      width: '860px'
    });

    setTimeout(function () { matchInput.focus(); }, 100);
  }

  // -- Rule deletion ----------------------------------------------------------

  /**
   * Show a confirmation dialog to delete a rule, then use optimistic UI.
   *
   * @param {string} policyId  - The policy ID containing the rule
   * @param {string} ruleId    - The rule ID (for future per-rule delete)
   * @param {string} ruleName  - Display name for confirmation message
   * @param {HTMLElement} [rowEl] - The row DOM element (for optimistic animation)
   */
  function confirmDeleteRule(policyId, ruleId, ruleName, rowEl) {
    SG.modal.confirm({
      title: 'Delete Rule',
      message: 'Delete rule "' + ruleName + '"? This cannot be undone.',
      confirmText: 'Delete',
      confirmClass: 'btn-danger',
      onConfirm: function () {
        if (rowEl) {
          deleteRuleOptimistic(policyId, ruleId, rowEl);
        } else {
          SG.api.del('/policies/' + policyId + '/rules/' + ruleId).then(function () {
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

    var headerActions = mk('div', '', { style: 'display:flex;gap:var(--space-2);align-items:center;flex-wrap:wrap' });
    var addRuleBtn = mk('button', 'btn btn-primary btn-sm');
    addRuleBtn.setAttribute('data-action', 'add-rule');
    addRuleBtn.innerHTML = SG.icon('plus', 16) + ' ';
    addRuleBtn.appendChild(document.createTextNode('Add Rule'));
    addRuleBtn.addEventListener('click', function () {
      openRuleModal(null);
    });
    headerActions.appendChild(addRuleBtn);

    var useTemplateBtn = mk('button', 'btn btn-secondary btn-sm');
    useTemplateBtn.innerHTML = SG.icon('filePlus', 16) + ' ';
    useTemplateBtn.appendChild(document.createTextNode('Use Template'));
    useTemplateBtn.addEventListener('click', function () {
      openTemplatePickerModal();
    });
    headerActions.appendChild(useTemplateBtn);

    var clearAllBtn = mk('button', 'btn btn-danger btn-sm');
    clearAllBtn.innerHTML = SG.icon('trash', 14) + ' ';
    clearAllBtn.appendChild(document.createTextNode('Clear All Rules'));
    clearAllBtn.addEventListener('click', function () {
      SG.modal.confirm({
        title: 'Clear All Rules',
        message: 'This will remove all custom rules. The built-in default rule (which allows all tool calls when no other rules match) is preserved to keep agents working. This cannot be undone.',
        confirmText: 'Clear All',
        confirmClass: 'btn-danger',
        onConfirm: function () {
          var nonDefault = allRules.filter(function (r) {
            return !isDefaultRule(r.policyName, r.rule.name);
          });
          if (nonDefault.length === 0) {
            SG.toast.info('No rules to clear');
            return;
          }
          // Group by policyId to delete entire policies atomically
          var byPolicy = {};
          nonDefault.forEach(function (r) {
            if (!byPolicy[r.policyId]) byPolicy[r.policyId] = [];
            byPolicy[r.policyId].push(r);
          });
          var policyIds = Object.keys(byPolicy);
          var chain = Promise.resolve();
          policyIds.forEach(function (pid) {
            chain = chain.then(function () {
              return SG.api.del('/policies/' + pid).catch(function (err) {
                // Ignore 404 — policy may have been deleted already
                if (err && err.status === 404) return;
                throw err;
              });
            });
          });
          chain.then(function () {
            SG.toast.success('All rules cleared');
            var contentArea = document.querySelector('.tools-content');
            if (contentArea && contentArea.parentElement) loadData(contentArea.parentElement);
          }).catch(function (err) {
            SG.toast.error('Failed: ' + (err.message || 'Unknown error'));
            var contentArea = document.querySelector('.tools-content');
            if (contentArea && contentArea.parentElement) loadData(contentArea.parentElement);
          });
        }
      });
    });
    headerActions.appendChild(clearAllBtn);

    var groupByPolicy = false;

    header.appendChild(headerActions);
    section.appendChild(header);

    // Filter bar: identity filter
    var filterBar = mk('div', '', {
      style: 'display: flex; align-items: center; gap: var(--space-3); margin-bottom: var(--space-3); flex-wrap: wrap;'
    });

    // Identity filter dropdown
    var filterLabel = mk('label', '', {
      style: 'font-size: var(--text-xs); color: var(--text-muted); white-space: nowrap;'
    });
    filterLabel.textContent = 'Show rules for:';
    filterBar.appendChild(filterLabel);
    var identityFilter = mk('select', 'form-select', {
      style: 'font-size: var(--text-sm); padding: var(--space-1) var(--space-2); max-width: 200px;'
    });
    var allOpt = mk('option');
    allOpt.value = ''; allOpt.textContent = 'All identities';
    identityFilter.appendChild(allOpt);
    for (var ci = 0; ci < _cachedIdentities.length; ci++) {
      var iOpt = mk('option');
      iOpt.value = _cachedIdentities[ci].name || '';
      iOpt.textContent = _cachedIdentities[ci].name || _cachedIdentities[ci].id;
      identityFilter.appendChild(iOpt);
    }
    filterBar.appendChild(identityFilter);

    // Group mode selector
    var groupSelect = mk('select', 'form-select', {
      style: 'font-size: var(--text-sm); padding: var(--space-1) var(--space-2); max-width: 200px;'
    });
    var optPriority = mk('option');
    optPriority.value = 'priority';
    optPriority.textContent = 'Sort by priority';
    groupSelect.appendChild(optPriority);
    var optPolicy = mk('option');
    optPolicy.value = 'policy';
    optPolicy.textContent = 'Group by policy';
    groupSelect.appendChild(optPolicy);
    filterBar.appendChild(groupSelect);

    section.appendChild(filterBar);

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
      var emptyWrapper = mk('div', '');
      emptyWrapper.innerHTML = renderRulesEmpty();
      card.appendChild(emptyWrapper);
      // Wire up CTA buttons
      var rulesCta = emptyWrapper.querySelector('[data-action="add-rule"]');
      if (rulesCta) {
        rulesCta.addEventListener('click', function () {
          openRuleModal(null);
        });
      }
      var templateCta = emptyWrapper.querySelector('[data-action="use-template"]');
      if (templateCta) {
        templateCta.addEventListener('click', function () {
          openTemplatePickerModal();
        });
      }
    } else {
      // Sortable header row
      var headerRow = mk('div', 'rule-row', {
        style: 'font-size: var(--text-xs); font-weight: var(--font-semibold); text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); background: var(--bg-secondary); cursor: default;'
      });
      var thPriority = mk('span', 'rule-priority', { style: 'cursor: pointer;' });
      thPriority.textContent = '#';
      headerRow.appendChild(thPriority);
      var thName = mk('div', 'rule-info', { style: 'cursor: pointer;' });
      thName.textContent = 'Rule';
      headerRow.appendChild(thName);
      var thAction = mk('span', '', { style: 'cursor: pointer; min-width: 60px;' });
      thAction.textContent = 'Action';
      headerRow.appendChild(thAction);
      var thActions = mk('div', 'rule-actions');
      thActions.textContent = '';
      headerRow.appendChild(thActions);
      card.appendChild(headerRow);

      // Rules body container (for sorting)
      var rulesBody = mk('div', 'rules-body');
      for (var i = 0; i < allRules.length; i++) {
        rulesBody.appendChild(renderRuleRow(allRules[i]));
      }
      card.appendChild(rulesBody);

      // Wire up sortable columns
      makeColumnSortable(thPriority, 'priority', rulesBody, function (row) {
        var el = row.querySelector('.rule-priority');
        return el ? parseInt(el.getAttribute('data-sort-priority') || el.textContent, 10) || 0 : 0;
      });
      makeColumnSortable(thName, 'name', rulesBody, function (row) {
        var el = row.querySelector('.rule-name');
        return el ? (el.getAttribute('data-sort-name') || el.textContent) : '';
      });
      makeColumnSortable(thAction, 'action', rulesBody, function (row) {
        var el = row.querySelector('[data-sort-action]');
        return el ? el.getAttribute('data-sort-action') : '';
      });
    }

    section.appendChild(card);

    // Wire identity filter
    identityFilter.addEventListener('change', function () {
      var filterName = identityFilter.value;
      var rows = card.querySelectorAll('.rule-row[data-rule-id]');
      for (var fi = 0; fi < rows.length; fi++) {
        if (!filterName) {
          rows[fi].style.display = '';
        } else {
          // Show rules that apply to this identity:
          // - Rules with no condition (apply to all)
          // - Rules whose condition doesn't reference any identity fields (global/tool-based)
          // - Rules whose condition mentions the selected identity name
          var ruleCondition = rows[fi].getAttribute('data-condition') || '';
          var appliesToAll = !ruleCondition || ruleCondition === 'true';
          var isIdentityScoped = ruleCondition.indexOf('identity_name') !== -1 ||
            ruleCondition.indexOf('identity_id') !== -1 ||
            ruleCondition.indexOf('identity_roles') !== -1;
          // Use quote-wrapped search to avoid substring false positives
          // (e.g., role "admin" matching "administrator" in the condition)
          var mentionsIdentity = ruleCondition.indexOf('"' + filterName + '"') !== -1 ||
            ruleCondition.indexOf("'" + filterName + "'") !== -1;
          // Also check if the identity's roles appear in role-based conditions
          if (!mentionsIdentity && isIdentityScoped) {
            for (var ri = 0; ri < _cachedIdentities.length; ri++) {
              if (_cachedIdentities[ri].name === filterName) {
                var idRoles = _cachedIdentities[ri].roles || [];
                for (var rj = 0; rj < idRoles.length; rj++) {
                  if (ruleCondition.indexOf('"' + idRoles[rj] + '"') !== -1 ||
                      ruleCondition.indexOf("'" + idRoles[rj] + "'") !== -1) {
                    mentionsIdentity = true;
                    break;
                  }
                }
                break;
              }
            }
          }
          // Global rules (no identity in condition) apply to everyone
          var showRule = appliesToAll || !isIdentityScoped || mentionsIdentity;
          rows[fi].style.display = showRule ? '' : 'none';
        }
      }
    });

    // Wire group selector
    groupSelect.addEventListener('change', function () {
      groupByPolicy = groupSelect.value === 'policy';
      var rulesBodyEl = card.querySelector('.rules-body');
      if (!rulesBodyEl) return;

      if (groupByPolicy) {
        // Group by policy name
        rulesBodyEl.innerHTML = '';
        var byPol = {};
        for (var gi = 0; gi < allRules.length; gi++) {
          var pn = allRules[gi].policyName || 'Default';
          if (!byPol[pn]) byPol[pn] = [];
          byPol[pn].push(allRules[gi]);
        }
        var polNames = Object.keys(byPol);
        for (var gk = 0; gk < polNames.length; gk++) {
          var groupHeader = mk('div', '', {
            style: 'font-size: var(--text-xs); font-weight: var(--font-semibold); color: var(--text-muted); padding: var(--space-2) var(--space-3); background: var(--bg-secondary); border-bottom: 1px solid var(--border);'
          });
          groupHeader.textContent = polNames[gk];
          rulesBodyEl.appendChild(groupHeader);
          for (var gj = 0; gj < byPol[polNames[gk]].length; gj++) {
            rulesBodyEl.appendChild(renderRuleRow(byPol[polNames[gk]][gj]));
          }
        }
      } else {
        // Sort by priority
        rulesBodyEl.innerHTML = '';
        allRules.sort(function (a, b) {
          return (b.rule.priority || 0) - (a.rule.priority || 0);
        });
        for (var gi2 = 0; gi2 < allRules.length; gi2++) {
          rulesBodyEl.appendChild(renderRuleRow(allRules[gi2]));
        }
      }
      // Re-apply identity filter after re-rendering rows
      identityFilter.dispatchEvent(new Event('change'));
    });

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
    row.setAttribute('data-rule-id', rule.id || '');
    row.setAttribute('data-policy-id', entry.policyId || '');
    row.setAttribute('data-condition', rule.condition || '');
    row.setAttribute('data-tool-match', rule.tool_match || '*');

    // Priority number
    var priorityEl = mk('span', 'rule-priority');
    priorityEl.textContent = String(rule.priority || 0);
    priorityEl.setAttribute('data-sort-priority', String(rule.priority || 0));
    row.appendChild(priorityEl);

    // Rule info (name + pattern)
    var infoEl = mk('div', 'rule-info');
    var nameEl = mk('div', 'rule-name');
    nameEl.textContent = rule.name || 'Unnamed rule';
    nameEl.setAttribute('data-sort-name', rule.name || '');
    infoEl.appendChild(nameEl);

    // Make rule name inline-editable (description-like field)
    makeInlineEditable(nameEl, {
      onSave: function (newValue, oldValue) {
        // Persist name change via API (best-effort)
        var payload = {
          name: newValue,
          description: 'Updated from inline edit',
          priority: rule.priority || 100,
          enabled: true,
          rules: [{
            name: newValue,
            priority: rule.priority || 100,
            tool_match: rule.tool_match || '*',
            condition: rule.condition || 'true',
            action: rule.action || 'deny'
          }]
        };
        if (entry.policyId) {
          SG.api.put('/policies/' + entry.policyId, payload).then(function () {
            SG.toast.success('Rule name updated');
          }).catch(function (err) {
            nameEl.textContent = oldValue;
            SG.toast.error('Update failed: ' + (err.message || 'Unknown error'));
          });
        }
      },
      validate: function (value) {
        return value.length > 0;
      }
    });

    // Source badge (template, redteam, etc.)
    if (rule.source) {
      var sourceBadge = mk('span', 'badge badge-neutral', { style: 'font-size:var(--text-xs);margin-left:var(--space-1);vertical-align:middle' });
      var sourceLabel = rule.source.replace('template:', '');
      sourceBadge.textContent = sourceLabel;
      infoEl.appendChild(sourceBadge);
    }

    var patternEl = mk('div', 'rule-pattern');
    var toolMatch = rule.tool_match || '*';
    var condition = rule.condition || '';
    var patternText = 'match: ' + toolMatch;
    if (condition && condition.trim() !== 'true' && condition.trim() !== '') {
      var condShort = condition.length > 50 ? condition.substring(0, 50) + '\u2026' : condition;
      patternText += ' \u2502 ' + condShort;
    }
    patternEl.textContent = patternText;
    patternEl.title = condition || '';
    infoEl.appendChild(patternEl);
    row.appendChild(infoEl);

    // Action badge
    var action = (rule.action || '').toLowerCase();
    var actionBadge;
    if (action === 'allow') {
      actionBadge = mk('span', 'badge badge-success');
      actionBadge.textContent = 'Allow';
    } else if (action === 'approval_required') {
      actionBadge = mk('span', 'badge badge-warning');
      actionBadge.textContent = 'Ask';
    } else {
      actionBadge = mk('span', 'badge badge-danger');
      actionBadge.textContent = 'Deny';
    }
    actionBadge.setAttribute('data-sort-action', action);
    row.appendChild(actionBadge);

    // Actions: Edit + Delete
    var actionsEl = mk('div', 'rule-actions');

    // Edit button (with aria-label)
    var editBtn = mk('button', 'btn btn-sm btn-secondary', {
      title: 'Edit rule',
      'aria-label': 'Edit rule ' + (rule.name || '')
    });
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
        'aria-label': 'Delete rule (disabled, default rule)',
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
      var delBtn = mk('button', 'btn btn-sm btn-danger', {
        title: 'Delete rule',
        'aria-label': 'Delete rule ' + (rule.name || '')
      });
      delBtn.innerHTML = SG.icon('xCircle', 14);
      (function (pid, rid, rname, rowRef) {
        delBtn.addEventListener('click', function () {
          confirmDeleteRule(pid, rid, rname, rowRef);
        });
      })(entry.policyId, rule.id, rule.name, row);
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
  function buildAutocomplete(inputEl, getItems, onSelect, opts) {
    var options = opts || {};
    var list = mk('div', 'autocomplete-list');
    var selectedIdx = -1;

    inputEl.parentNode.appendChild(list);

    // For comma-separated fields, extract the segment being typed after the last comma.
    function currentSegment(val) {
      if (!options.commaSeparated) return val;
      var parts = val.split(',');
      return parts[parts.length - 1].trimStart();
    }

    // For comma-separated fields, replace only the last segment with the selected value.
    function replaceSegment(val, selected) {
      if (!options.commaSeparated) return selected;
      var parts = val.split(',');
      parts[parts.length - 1] = ' ' + selected;
      return parts.join(',').replace(/^,?\s*/, '');
    }

    function renderItems(filter, showAll) {
      list.innerHTML = '';
      selectedIdx = -1;
      var items = getItems();
      var matches = [];
      var segment = currentSegment(filter || '');
      var lowerFilter = segment.toLowerCase();

      for (var i = 0; i < items.length && matches.length < 10; i++) {
        if (!lowerFilter || items[i].name.toLowerCase().indexOf(lowerFilter) === 0) {
          matches.push(items[i]);
        }
      }

      if (matches.length === 0 || (!segment && !showAll)) {
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
            inputEl.value = replaceSegment(inputEl.value, item.name);
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
      renderItems(inputEl.value, !!options.showAllOnFocus);
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

    // UX-4 FIX: Explanation of Policy Test purpose
    var desc = mk('p', '', { style: 'font-size:var(--text-sm);color:var(--text-secondary);margin-bottom:var(--space-4)' });
    desc.textContent = 'Simulate a tool call against your active policies without executing it. ' +
      'Enter a tool name, arguments, and identity to see whether the call would be allowed, denied, or require approval \u2014 and which rule matched.';
    section.appendChild(desc);

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
      placeholder: 'Type tool name...',
      autocomplete: 'off'
    });
    acWrap.appendChild(toolInput);
    toolGroup.appendChild(acWrap);
    formEl.appendChild(toolGroup);

    // Autocomplete for tool names — tools with rules are shown first
    buildAutocomplete(toolInput, function () {
      // Build set of tools that have rules
      var toolsWithRules = {};
      for (var pi = 0; pi < policies.length; pi++) {
        var pRules = policies[pi].rules || [];
        for (var ri = 0; ri < pRules.length; ri++) {
          var tm = pRules[ri].tool_match || '';
          if (tm && tm !== '*') toolsWithRules[tm] = true;
        }
      }
      var items = [];
      for (var i = 0; i < tools.length; i++) {
        var hasRule = toolsWithRules[tools[i].name] || false;
        items.push({
          name: tools[i].name,
          description: (hasRule ? '\u2713 has rules' : '') + (tools[i].description ? (hasRule ? ' \u2014 ' : '') + tools[i].description : '')
        });
      }
      // Sort: tools with rules first
      items.sort(function (a, b) {
        var aHas = a.description.indexOf('\u2713') === 0 ? 0 : 1;
        var bHas = b.description.indexOf('\u2713') === 0 ? 0 : 1;
        return aHas - bHas || a.name.localeCompare(b.name);
      });
      return items;
    }, function (item) {
      toolInput.value = item.name;
    }, { showAllOnFocus: true });

    // -- Roles --
    var rolesGroup = mk('div', 'form-group');
    var rolesLabel = mk('label', 'form-label');
    rolesLabel.textContent = 'Roles';
    rolesLabel.setAttribute('for', 'test-roles');
    rolesGroup.appendChild(rolesLabel);
    var acWrapRoles = mk('div', 'autocomplete-wrap');
    var rolesInput = mk('input', 'form-input', {
      type: 'text', id: 'test-roles',
      placeholder: 'admin, user, read-only, developer, auditor',
      autocomplete: 'off'
    });
    rolesInput.addEventListener('input', function () {
      // Visual feedback: border and background change when a role is entered
      if (rolesInput.value.trim()) {
        rolesInput.style.borderColor = 'var(--accent)';
        rolesInput.style.background = 'var(--bg-elevated)';
        rolesInput.style.fontWeight = '500';
      } else {
        rolesInput.style.borderColor = '';
        rolesInput.style.background = '';
        rolesInput.style.fontWeight = '';
      }
    });
    acWrapRoles.appendChild(rolesInput);
    rolesGroup.appendChild(acWrapRoles);
    var knownRoles = ['admin', 'user', 'read-only', 'developer', 'auditor'];
    buildAutocomplete(rolesInput, function () {
      // Filter out roles already entered
      var current = rolesInput.value.split(',').map(function (s) { return s.trim().toLowerCase(); });
      var items = [];
      for (var i = 0; i < knownRoles.length; i++) {
        if (current.indexOf(knownRoles[i].toLowerCase()) === -1) {
          items.push({ name: knownRoles[i] });
        }
      }
      return items;
    }, function (item) {
      // commaSeparated handled by buildAutocomplete opts
    }, { commaSeparated: true, showAllOnFocus: true });
    var rolesHelp = mk('div', 'form-help');
    rolesHelp.textContent = 'Comma-separated role list (optional). Valid roles: admin, user, read-only, developer, auditor';
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
    argsHelp.textContent = 'JSON object with tool arguments (optional). Example: {"path": "/etc/passwd"} or {"query": "SELECT * FROM users"}';
    argsGroup.appendChild(argsHelp);
    formEl.appendChild(argsGroup);

    // -- Identity --
    var identityGroup = mk('div', 'form-group');
    var identityLabel = mk('label', 'form-label');
    identityLabel.textContent = 'Identity';
    identityLabel.setAttribute('for', 'test-identity');
    identityGroup.appendChild(identityLabel);
    var identityInput = mk('select', 'form-select', { id: 'test-identity' });
    var idNoneOpt = mk('option');
    idNoneOpt.value = ''; idNoneOpt.textContent = '(none)';
    identityInput.appendChild(idNoneOpt);
    for (var idi = 0; idi < _cachedIdentities.length; idi++) {
      var idOpt = mk('option');
      idOpt.value = _cachedIdentities[idi].id;
      idOpt.textContent = _cachedIdentities[idi].name || _cachedIdentities[idi].id;
      identityInput.appendChild(idOpt);
    }
    identityGroup.appendChild(identityInput);
    formEl.appendChild(identityGroup);

    // -- Session Context (collapsible) --
    var sessionGroup = mk('div', 'form-group test-form-full');

    var sessionToggle = mk('div', '', {
      style: 'display: flex; align-items: center; gap: var(--space-2); cursor: pointer; user-select: none; padding: var(--space-2) 0;'
    });
    var sessionArrow = mk('span', '', {
      style: 'font-size: var(--text-sm); color: var(--text-muted); transition: transform 0.2s;'
    });
    sessionArrow.textContent = '\u25B6';
    sessionToggle.appendChild(sessionArrow);
    var sessionToggleLabel = mk('span', 'form-label', {
      style: 'margin: 0; cursor: pointer;'
    });
    sessionToggleLabel.textContent = 'Session Context (optional — simulate session history)';
    sessionToggle.appendChild(sessionToggleLabel);
    sessionGroup.appendChild(sessionToggle);

    var sessionPanel = mk('div', '', { style: 'display: none; margin-top: var(--space-2);' });

    var sessionHelpText = mk('div', 'form-help', { style: 'margin-bottom: var(--space-3);' });
    sessionHelpText.textContent = 'Add simulated prior tool calls to test session-aware rules. Each entry represents a previous call in the session before the one being tested. The tool call you are testing is automatically appended as the last entry.';
    var sessionHelpDetails = mk('div', 'form-help', { style: 'margin-bottom: var(--space-2); font-size: var(--text-xs); color: var(--text-muted);' });
    sessionHelpDetails.innerHTML =
      '<strong>Call Type</strong>: read, write, delete, or other (determines how the call is classified).<br>' +
      '<strong>Seconds Ago</strong>: sets the timestamp of the entry relative to now (0 = current time).<br>' +
      '<strong>CEL variables populated</strong>: <code>session_call_count</code>, <code>session_action_history</code>, <code>session_action_set</code>, <code>session_arg_key_set</code>.';
    sessionPanel.appendChild(sessionHelpDetails);
    sessionPanel.appendChild(sessionHelpText);

    var sessionEntriesContainer = mk('div', '', { id: 'session-context-entries' });
    sessionPanel.appendChild(sessionEntriesContainer);

    var addActionBtn = mk('button', 'btn btn-secondary', {
      type: 'button',
      style: 'font-size: var(--text-sm); padding: var(--space-1) var(--space-3); margin-top: var(--space-2);'
    });
    addActionBtn.textContent = '+ Add Action';
    sessionPanel.appendChild(addActionBtn);

    sessionGroup.appendChild(sessionPanel);
    formEl.appendChild(sessionGroup);

    // Toggle session context panel visibility
    sessionToggle.addEventListener('click', function () {
      var isHidden = sessionPanel.style.display === 'none';
      sessionPanel.style.display = isHidden ? 'block' : 'none';
      sessionArrow.textContent = isHidden ? '\u25BC' : '\u25B6';
    });

    // Render session context entries
    function renderSessionEntries() {
      sessionEntriesContainer.innerHTML = '';
      for (var i = 0; i < sessionContextEntries.length; i++) {
        (function (idx) {
          var entry = sessionContextEntries[idx];
          var row = mk('div', '', {
            style: 'display: flex; gap: var(--space-2); align-items: flex-start; margin-bottom: var(--space-2); flex-wrap: wrap;'
          });

          // Tool Name input
          var toolNameWrap = mk('div', '', { style: 'flex: 1; min-width: 120px;' });
          if (idx === 0) {
            var tnLabel = mk('div', '', {
              style: 'font-size: var(--text-xs); color: var(--text-muted); margin-bottom: 2px;'
            });
            tnLabel.textContent = 'Tool Name';
            toolNameWrap.appendChild(tnLabel);
          }
          var tnInput = mk('input', 'form-input', {
            type: 'text',
            placeholder: 'read_file',
            value: entry.tool_name || '',
            style: 'font-size: var(--text-sm); padding: var(--space-1) var(--space-2);'
          });
          tnInput.addEventListener('input', function () {
            entry.tool_name = tnInput.value;
          });
          toolNameWrap.appendChild(tnInput);
          row.appendChild(toolNameWrap);

          // Call Type select
          var typeWrap = mk('div', '', { style: 'min-width: 90px;' });
          if (idx === 0) {
            var typeLabel = mk('div', '', {
              style: 'font-size: var(--text-xs); color: var(--text-muted); margin-bottom: 2px;'
            });
            typeLabel.textContent = 'Type';
            typeWrap.appendChild(typeLabel);
          }
          var typeSelect = mk('select', 'form-input', {
            style: 'font-size: var(--text-sm); padding: var(--space-1) var(--space-2);'
          });
          var typeOptions = ['other', 'read', 'write', 'delete'];
          for (var ti = 0; ti < typeOptions.length; ti++) {
            var opt = mk('option', '', { value: typeOptions[ti] });
            opt.textContent = typeOptions[ti];
            if (typeOptions[ti] === (entry.call_type || 'other')) {
              opt.selected = true;
            }
            typeSelect.appendChild(opt);
          }
          typeSelect.addEventListener('change', function () {
            entry.call_type = typeSelect.value;
          });
          typeWrap.appendChild(typeSelect);
          row.appendChild(typeWrap);

          // Seconds Ago input
          var secWrap = mk('div', '', { style: 'min-width: 80px;' });
          if (idx === 0) {
            var secLabel = mk('div', '', {
              style: 'font-size: var(--text-xs); color: var(--text-muted); margin-bottom: 2px;'
            });
            secLabel.textContent = 'Secs Ago';
            secWrap.appendChild(secLabel);
          }
          var secInput = mk('input', 'form-input', {
            type: 'number',
            min: '0',
            value: String(entry.seconds_ago || 0),
            style: 'font-size: var(--text-sm); padding: var(--space-1) var(--space-2); width: 80px;'
          });
          secInput.addEventListener('input', function () {
            entry.seconds_ago = parseInt(secInput.value, 10) || 0;
          });
          secWrap.appendChild(secInput);
          row.appendChild(secWrap);

          // Arg Keys input
          var argWrap = mk('div', '', { style: 'flex: 1; min-width: 100px;' });
          if (idx === 0) {
            var argLabel = mk('div', '', {
              style: 'font-size: var(--text-xs); color: var(--text-muted); margin-bottom: 2px;'
            });
            argLabel.textContent = 'Arg Keys';
            argWrap.appendChild(argLabel);
          }
          var argInput = mk('input', 'form-input', {
            type: 'text',
            placeholder: 'path,content',
            value: entry.arg_keys || '',
            style: 'font-size: var(--text-sm); padding: var(--space-1) var(--space-2);'
          });
          argInput.addEventListener('input', function () {
            entry.arg_keys = argInput.value;
          });
          argWrap.appendChild(argInput);
          row.appendChild(argWrap);

          // Remove button
          var removeWrap = mk('div', '', { style: 'display: flex; align-items: flex-end;' });
          if (idx === 0) {
            var removeLabel = mk('div', '', {
              style: 'font-size: var(--text-xs); color: transparent; margin-bottom: 2px;'
            });
            removeLabel.textContent = '\u00A0';
            removeWrap.appendChild(removeLabel);
          }
          var removeBtn = mk('button', 'btn', {
            type: 'button',
            style: 'font-size: var(--text-sm); padding: var(--space-1) var(--space-2); color: var(--danger); background: transparent; border: 1px solid var(--danger); min-width: auto;'
          });
          removeBtn.textContent = '\u00D7';
          removeBtn.addEventListener('click', function () {
            sessionContextEntries.splice(idx, 1);
            renderSessionEntries();
          });
          removeWrap.appendChild(removeBtn);
          row.appendChild(removeWrap);

          sessionEntriesContainer.appendChild(row);
        })(i);
      }
    }

    // Add Action button handler
    addActionBtn.addEventListener('click', function () {
      sessionContextEntries.push({ tool_name: '', call_type: 'other', seconds_ago: 0, arg_keys: '' });
      renderSessionEntries();
    });

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

      // Include session context entries if any have a tool_name
      if (sessionContextEntries.length > 0) {
        var sc = sessionContextEntries.map(function (e) {
          var entry = { tool_name: e.tool_name };
          if (e.call_type) entry.call_type = e.call_type;
          if (e.seconds_ago > 0) entry.seconds_ago = parseInt(e.seconds_ago, 10);
          if (e.arg_keys) {
            entry.arg_keys = e.arg_keys.split(',').map(function (k) { return k.trim(); }).filter(Boolean);
          }
          return entry;
        }).filter(function (e) { return e.tool_name; });
        if (sc.length > 0) {
          payload.session_context = sc;
        }
      }

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
        var requiresApproval = data.decision === 'approval_required';
        if (requiresApproval) {
          resultArea.classList.add('test-result-ask');
        } else {
          resultArea.classList.add(allowed ? 'test-result-allow' : 'test-result-deny');
        }

        // Decision row
        var decisionRow = mk('div', 'test-result-row');
        var decisionLabel = mk('span', 'test-result-label');
        decisionLabel.textContent = 'Decision';
        decisionRow.appendChild(decisionLabel);
        var decisionBadge;
        if (requiresApproval) {
          decisionBadge = mk('span', 'badge badge-warning');
          decisionBadge.textContent = 'Ask';
        } else {
          decisionBadge = mk('span', 'badge ' + (allowed ? 'badge-success' : 'badge-danger'));
          decisionBadge.textContent = allowed ? 'Allow' : 'Deny';
        }
        decisionRow.appendChild(decisionBadge);
        resultArea.appendChild(decisionRow);

        // Matched rule row
        var matchedName = data.rule_name || (data.matched_rule && data.matched_rule.name) || 'No specific rule';
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

  // -- Simulation section (UX-F1) -----------------------------------------------

  function renderSimulationSection(container) {
    container.innerHTML =
      '<div class="card" style="margin-bottom: var(--space-4);">' +
        '<div class="card-header"><h3 class="card-title">Policy Simulation</h3></div>' +
        '<div class="card-body" style="padding: var(--space-6);">' +
          '<p style="font-size: var(--text-sm); color: var(--text-secondary); margin-bottom: var(--space-4);">' +
            'Replay recent audit traffic against your current policy rules to see the impact. ' +
            'Shows how many calls would change decision (allow/deny) if policies were applied to historical traffic.' +
          '</p>' +
          '<div style="display: flex; align-items: center; gap: var(--space-3); margin-bottom: var(--space-4);">' +
            '<label style="font-size: var(--text-sm); color: var(--text-secondary);">Max records:</label>' +
            '<select id="sim-max-records" class="form-select" style="width: auto;">' +
              '<option value="100">100</option>' +
              '<option value="500">500</option>' +
              '<option value="1000" selected>1,000</option>' +
            '</select>' +
            '<button class="btn btn-primary" id="run-simulation-btn">Run Simulation</button>' +
          '</div>' +
          '<div id="simulation-result"></div>' +
        '</div>' +
      '</div>';

    var runBtn = container.querySelector('#run-simulation-btn');
    if (runBtn) {
      runBtn.addEventListener('click', function () {
        var maxRecords = parseInt(container.querySelector('#sim-max-records').value) || 1000;
        runBtn.disabled = true;
        runBtn.textContent = 'Running...';
        container.querySelector('#simulation-result').innerHTML =
          '<p style="color: var(--text-muted);">Analyzing audit traffic...</p>';

        SG.api.post('/v1/simulation/run', { max_records: maxRecords }).then(function (result) {
          runBtn.disabled = false;
          runBtn.textContent = 'Run Simulation';
          renderSimulationResult(result);
        }).catch(function (err) {
          runBtn.disabled = false;
          runBtn.textContent = 'Run Simulation';
          container.querySelector('#simulation-result').innerHTML =
            '<p style="color: var(--danger);">Simulation failed: ' + esc(err.message || 'Unknown error') + '</p>';
        });
      });
    }
  }

  function renderSimulationResult(result) {
    var el = document.getElementById('simulation-result');
    if (!el) return;

    if (result.total_analyzed === 0) {
      el.innerHTML = '<p style="color: var(--text-muted);">No audit records found to analyze. Connect an agent and make some tool calls first.</p>';
      return;
    }

    var html =
      '<div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: var(--space-3); margin-bottom: var(--space-4);">' +
        '<div style="background: var(--bg-secondary); border-radius: var(--radius-lg); padding: var(--space-3); text-align: center;">' +
          '<div style="font-size: var(--text-2xl); font-weight: var(--font-bold);">' + esc(String(result.total_analyzed)) + '</div>' +
          '<div style="font-size: var(--text-xs); color: var(--text-muted); text-transform: uppercase;">Analyzed</div>' +
        '</div>' +
        '<div style="background: var(--bg-secondary); border-radius: var(--radius-lg); padding: var(--space-3); text-align: center;">' +
          '<div style="font-size: var(--text-2xl); font-weight: var(--font-bold); color: var(--success);">' + esc(String(result.unchanged)) + '</div>' +
          '<div style="font-size: var(--text-xs); color: var(--text-muted); text-transform: uppercase;">Unchanged</div>' +
        '</div>' +
        '<div style="background: var(--bg-secondary); border-radius: var(--radius-lg); padding: var(--space-3); text-align: center;">' +
          '<div style="font-size: var(--text-2xl); font-weight: var(--font-bold); color: var(--danger);">' + esc(String(result.allow_to_deny || 0)) + '</div>' +
          '<div style="font-size: var(--text-xs); color: var(--text-muted); text-transform: uppercase;">Would Block</div>' +
        '</div>' +
        '<div style="background: var(--bg-secondary); border-radius: var(--radius-lg); padding: var(--space-3); text-align: center;">' +
          '<div style="font-size: var(--text-2xl); font-weight: var(--font-bold); color: var(--warning, #f59e0b);">' + esc(String(result.deny_to_allow || 0)) + '</div>' +
          '<div style="font-size: var(--text-xs); color: var(--text-muted); text-transform: uppercase;">Would Allow</div>' +
        '</div>' +
      '</div>' +
      '<p style="font-size: var(--text-xs); color: var(--text-muted); margin-bottom: var(--space-3);">Changes reflect records where the current policy rules would produce a different decision than was recorded at the time of the original call.</p>';

    if (result.changed > 0) {
      // Impacted summary
      html += '<div style="margin-bottom: var(--space-3); font-size: var(--text-sm);">';
      if (result.impacted_agents && result.impacted_agents.length > 0) {
        // Resolve UUIDs to identity names where possible
        var resolvedAgents = result.impacted_agents.map(function(a) {
          for (var ci = 0; ci < _cachedIdentities.length; ci++) {
            if (_cachedIdentities[ci].id === a) return _cachedIdentities[ci].name || a;
          }
          return a;
        });
        html += '<strong>Impacted identities:</strong> ' + resolvedAgents.map(function(a) { return '<code>' + esc(a) + '</code>'; }).join(', ') + '<br>';
      }
      if (result.impacted_tools && result.impacted_tools.length > 0) {
        html += '<strong>Impacted tools:</strong> ' + result.impacted_tools.map(function(t) { return '<code>' + esc(t) + '</code>'; }).join(', ');
      }
      html += '</div>';

      // Detail table
      if (result.details && result.details.length > 0) {
        html += '<div class="table-responsive"><table class="data-table"><thead><tr>' +
          '<th>Tool</th><th>Identity</th><th>Original</th><th>New</th><th>Rule</th>' +
          '</tr></thead><tbody>';

        for (var i = 0; i < Math.min(result.details.length, 50); i++) {
          var d = result.details[i];
          // Resolve identity_id to name
          var idName = d.identity_id || '-';
          for (var ri = 0; ri < _cachedIdentities.length; ri++) {
            if (_cachedIdentities[ri].id === d.identity_id) {
              idName = _cachedIdentities[ri].name || d.identity_id;
              break;
            }
          }
          html += '<tr>' +
            '<td><code>' + esc(d.tool_name || '-') + '</code></td>' +
            '<td>' + esc(idName) + '</td>' +
            '<td><span class="badge badge-' + (d.original_decision === 'allow' ? 'success' : d.original_decision === 'approval_required' ? 'warning' : 'danger') + '">' + esc(d.original_decision === 'approval_required' ? 'Ask' : d.original_decision) + '</span></td>' +
            '<td><span class="badge badge-' + (d.new_decision === 'allow' ? 'success' : d.new_decision === 'approval_required' ? 'warning' : 'danger') + '">' + esc(d.new_decision === 'approval_required' ? 'Ask' : d.new_decision) + '</span></td>' +
            '<td>' + esc(d.new_rule_name || d.new_rule_id || '-') + '</td>' +
            '</tr>';
        }
        html += '</tbody></table></div>';
        if (result.details.length > 50) {
          html += '<p style="font-size: var(--text-xs); color: var(--text-muted);">Showing 50 of ' + esc(String(result.details.length)) + ' changed records.</p>';
        }
      }
    }

    html += '<p style="font-size: var(--text-xs); color: var(--text-muted); margin-top: var(--space-2);">Simulation completed in ' + esc(String(result.duration_ms || 0)) + 'ms</p>';

    el.innerHTML = html;
  }

  // -- Transforms section -------------------------------------------------------

  /**
   * Map transform type to its CSS badge class suffix.
   */
  function transformTypeBadgeClass(type) {
    var typeMap = {
      'redact': 'type-redact',
      'truncate': 'type-truncate',
      'inject': 'type-inject',
      'dry_run': 'type-dry_run',
      'mask': 'type-mask'
    };
    return typeMap[type] || '';
  }

  /**
   * Build a transform request body from form values.
   */
  function buildTransformRequestFromForm(form) {
    var name = form.querySelector('[name="tf-name"]').value.trim();
    var type = form.querySelector('[name="tf-type"]').value;
    var toolMatch = form.querySelector('[name="tf-tool-match"]').value.trim();
    var priority = parseInt(form.querySelector('[name="tf-priority"]').value, 10) || 100;
    var enabledEl = form.querySelector('[name="tf-enabled"]');
    var enabled = enabledEl ? enabledEl.checked : true;

    var config = {};

    if (type === 'redact') {
      var patternsText = form.querySelector('[name="tf-redact-patterns"]').value;
      config.patterns = patternsText.split('\n').map(function (l) { return l.trim(); }).filter(Boolean);
      var replacement = form.querySelector('[name="tf-redact-replacement"]').value;
      if (replacement) config.replacement = replacement;
    } else if (type === 'truncate') {
      var maxBytes = form.querySelector('[name="tf-truncate-max-bytes"]').value;
      var maxLines = form.querySelector('[name="tf-truncate-max-lines"]').value;
      var suffix = form.querySelector('[name="tf-truncate-suffix"]').value;
      if (maxBytes) config.max_bytes = parseInt(maxBytes, 10);
      if (maxLines) config.max_lines = parseInt(maxLines, 10);
      if (suffix) config.suffix = suffix;
    } else if (type === 'inject') {
      var prepend = form.querySelector('[name="tf-inject-prepend"]').value;
      var append = form.querySelector('[name="tf-inject-append"]').value;
      if (prepend) config.prepend = prepend;
      if (append) config.append = append;
    } else if (type === 'dry_run') {
      var response = form.querySelector('[name="tf-dryrun-response"]').value;
      if (response) config.response = response;
    } else if (type === 'mask') {
      var maskPatterns = form.querySelector('[name="tf-mask-patterns"]').value;
      config.mask_patterns = maskPatterns.split('\n').map(function (l) { return l.trim(); }).filter(Boolean);
      var vp = form.querySelector('[name="tf-mask-visible-prefix"]').value;
      var vs = form.querySelector('[name="tf-mask-visible-suffix"]').value;
      var mc = form.querySelector('[name="tf-mask-char"]').value;
      if (vp !== '') config.visible_prefix = parseInt(vp, 10);
      if (vs !== '') config.visible_suffix = parseInt(vs, 10);
      if (mc) config.mask_char = mc;
    }

    return {
      name: name,
      type: type,
      tool_match: toolMatch || '*',
      priority: priority,
      enabled: enabled,
      config: config
    };
  }

  /**
   * Render the Transforms section: rule list + add button + test sandbox.
   */
  function renderTransforms(container) {
    // Header
    var header = mk('div', 'rules-header');
    var h2 = mk('h2');
    h2.innerHTML = SG.icon('eye', 20) + ' ';
    h2.appendChild(document.createTextNode('Response Transforms'));
    header.appendChild(h2);

    var addBtn = mk('button', 'btn btn-primary btn-sm');
    addBtn.innerHTML = SG.icon('plus', 16) + ' ';
    addBtn.appendChild(document.createTextNode('Add Transform'));
    addBtn.addEventListener('click', function () {
      openTransformModal(null);
    });
    header.appendChild(addBtn);
    container.appendChild(header);

    // Rule list card
    var card = mk('div', '', {
      style: 'background: var(--bg-primary); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden;'
    });

    // Sort by priority descending (higher = first)
    var sorted = transforms.slice().sort(function (a, b) {
      return (b.priority || 0) - (a.priority || 0);
    });

    if (sorted.length === 0) {
      var emptyEl = mk('div', '', {
        style: 'padding: var(--space-6); text-align: center; color: var(--text-muted);'
      });
      emptyEl.textContent = 'No transform rules configured. Add one to start redacting, masking, or modifying tool responses.';
      card.appendChild(emptyEl);
    } else {
      for (var i = 0; i < sorted.length; i++) {
        card.appendChild(renderTransformRow(sorted[i]));
      }
    }

    container.appendChild(card);

    // Test sandbox section
    container.appendChild(buildTransformTestSection());
  }

  /**
   * Render a single transform rule row.
   */
  function renderTransformRow(rule) {
    var row = mk('div', 'transform-row');

    // Priority
    var priorityEl = mk('span', 'transform-priority');
    priorityEl.textContent = String(rule.priority || 0);
    row.appendChild(priorityEl);

    // Type badge
    var typeBadge = mk('span', 'transform-type-badge ' + transformTypeBadgeClass(rule.type));
    typeBadge.textContent = rule.type || 'unknown';
    row.appendChild(typeBadge);

    // Info (name + tool match)
    var info = mk('div', 'transform-row-info');
    var nameEl = mk('div', 'transform-row-name');
    nameEl.textContent = rule.name || 'Unnamed';
    info.appendChild(nameEl);
    var meta = mk('div', 'transform-row-meta');
    var toolMatchEl = mk('span', '');
    toolMatchEl.textContent = 'tool: ' + (rule.tool_match || '*');
    toolMatchEl.style.fontFamily = 'var(--font-mono)';
    meta.appendChild(toolMatchEl);
    info.appendChild(meta);
    row.appendChild(info);

    // Enabled badge
    var enabledBadge = mk('span', 'transform-enabled-badge ' + (rule.enabled ? 'enabled' : 'disabled'));
    enabledBadge.textContent = rule.enabled ? 'Enabled' : 'Disabled';
    row.appendChild(enabledBadge);

    // Actions
    var actions = mk('div', 'transform-actions');

    // Edit button
    var editBtn = mk('button', 'btn btn-sm btn-secondary', {
      title: 'Edit transform',
      'aria-label': 'Edit transform ' + (rule.name || '')
    });
    editBtn.innerHTML = SG.icon('wrench', 14);
    (function (r) {
      editBtn.addEventListener('click', function () {
        openTransformModal(r);
      });
    })(rule);
    actions.appendChild(editBtn);

    // Delete button
    var delBtn = mk('button', 'btn btn-sm btn-danger', {
      title: 'Delete transform',
      'aria-label': 'Delete transform ' + (rule.name || '')
    });
    delBtn.innerHTML = SG.icon('xCircle', 14);
    (function (r) {
      delBtn.addEventListener('click', function () {
        confirmDeleteTransform(r.id, r.name);
      });
    })(rule);
    actions.appendChild(delBtn);

    row.appendChild(actions);
    return row;
  }

  /**
   * Confirm and delete a transform rule.
   */
  function confirmDeleteTransform(id, name) {
    SG.modal.confirm({
      title: 'Delete Transform',
      message: 'Delete transform rule "' + name + '"? This cannot be undone.',
      confirmText: 'Delete',
      confirmClass: 'btn-danger',
      onConfirm: function () {
        SG.api.del('/v1/transforms/' + encodeURIComponent(id)).then(function () {
          SG.toast.success('Transform "' + name + '" deleted');
          var contentArea = document.querySelector('.tools-content');
          if (contentArea) {
            var pageRoot = contentArea.parentElement;
            if (pageRoot) loadData(pageRoot);
          }
        }).catch(function (err) {
          SG.toast.error(err.message || 'Failed to delete transform');
        });
      }
    });
  }

  /**
   * Open modal for adding or editing a transform rule.
   */
  function openTransformModal(existing) {
    var isEdit = existing != null;

    var form = mk('form', 'add-upstream-form');
    form.setAttribute('autocomplete', 'off');

    // Help toggle button
    var tfHelpRow = mk('div', '', { style: 'display: flex; justify-content: flex-end; margin-bottom: var(--space-2);' });
    var tfHelpBtn = mk('button', 'rule-tab', { type: 'button', title: 'Show guide' });
    tfHelpBtn.textContent = '?';
    tfHelpRow.appendChild(tfHelpBtn);
    form.appendChild(tfHelpRow);

    // Help panel (hidden by default) — full guide from user feedback
    var tfHelpPanel = mk('div', 'transform-help-panel', {
      style: 'display: none; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: var(--radius-md); padding: var(--space-3); margin-bottom: var(--space-3); font-size: var(--text-sm); line-height: 1.6; max-height: 350px; overflow-y: auto;'
    });
    tfHelpPanel.innerHTML =
      '<h4 style="margin: 0 0 var(--space-3) 0;">How to create a response transform</h4>' +
      '<p style="margin: var(--space-1) 0;">Response transforms modify what comes back from a tool before the agent sees it. Use them to hide sensitive data, limit response size, or add warnings.</p>' +

      '<div style="margin-bottom: var(--space-3);">' +
      '<strong>1. Choose what the transform does (Type)</strong>' +
      '<p style="margin: var(--space-1) 0;">Pick the type that matches your goal:</p>' +
      '<ul style="margin: var(--space-1) 0; padding-left: var(--space-4);">' +
      '<li><strong>redact</strong> \u2014 removes sensitive text completely. Matched text is replaced with <code>[REDACTED]</code>. Use for: API keys, passwords, tokens.</li>' +
      '<li><strong>mask</strong> \u2014 hides text partially, showing only the first and last characters. Use for: emails, phone numbers.</li>' +
      '<li><strong>truncate</strong> \u2014 cuts the response if it\u2019s too long. Use for: preventing huge responses from overloading the agent.</li>' +
      '<li><strong>inject</strong> \u2014 adds a message before or after the response. Use for: warnings, disclaimers, context.</li>' +
      '<li><strong>dry_run</strong> \u2014 returns a fake response without actually calling the tool. Use for: testing what an agent would do without real effects.</li>' +
      '</ul>' +
      '</div>' +

      '<div style="margin-bottom: var(--space-3);">' +
      '<strong>2. Name your transform</strong>' +
      '<p style="margin: var(--space-1) 0;">Give it a short name that tells you what it does, e.g. <code>redact-api-keys</code>, <code>mask-emails</code>, <code>truncate-large-files</code>.</p>' +
      '</div>' +

      '<div style="margin-bottom: var(--space-3);">' +
      '<strong>3. Choose which tools it applies to (Tool Match)</strong>' +
      '<p style="margin: var(--space-1) 0;">Same as in Rules: type the tool name or use <code>*</code> for all tools. For example, <code>read_file</code> applies the transform only to file reads.</p>' +
      '</div>' +

      '<div style="margin-bottom: var(--space-3);">' +
      '<strong>4. Set the priority</strong>' +
      '<p style="margin: var(--space-1) 0;">Priority decides the order when multiple transforms apply to the same tool response. Higher number = higher priority.</p>' +
      '<p style="margin: var(--space-1) 0;">If this is your only transform, the default value (100) is fine.</p>' +
      '<div style="border-left: 3px solid var(--accent); padding-left: var(--space-2); margin: var(--space-2) 0; color: var(--text-muted);">' +
      '<strong>Tip:</strong> transforms can be edited at any time \u2014 including their priority \u2014 so don\u2019t worry about getting it perfect on the first try.' +
      '</div>' +
      '</div>' +

      '<div style="margin-bottom: var(--space-3);">' +
      '<strong>5. Configure the settings</strong>' +
      '<p style="margin: var(--space-1) 0;">After choosing the type, fill in the settings that appear at the bottom of the form:</p>' +
      '<ul style="margin: var(--space-1) 0; padding-left: var(--space-4);">' +
      '<li><strong>redact / mask</strong> \u2014 add one regex pattern per line. The form pre-fills common patterns. Click the pattern chips to add more.</li>' +
      '<li><strong>truncate</strong> \u2014 set Max Bytes (default 10000) and/or Max Lines (default 100). The response is cut at whichever limit is hit first.</li>' +
      '<li><strong>inject</strong> \u2014 write the text to add in Prepend (before the response) and/or Append (after it).</li>' +
      '<li><strong>dry_run</strong> \u2014 write the fake response in Response Template. The tool will not actually be executed.</li>' +
      '</ul>' +
      '<p style="margin: var(--space-1) 0;">Click <strong>Save</strong> to activate the transform. You can test it in the "Test Transform" section below by pasting sample text.</p>' +
      '<div style="border-left: 3px solid var(--accent); padding-left: var(--space-2); margin: var(--space-2) 0; color: var(--text-muted);">' +
      '<strong>Tip:</strong> you can disable a transform without deleting it by unchecking "Enabled" \u2014 useful for temporary debugging.' +
      '</div>' +
      '</div>';
    form.appendChild(tfHelpPanel);

    tfHelpBtn.addEventListener('click', function (e) {
      e.preventDefault();
      tfHelpPanel.style.display = tfHelpPanel.style.display === 'none' ? 'block' : 'none';
      tfHelpBtn.classList.toggle('active');
    });

    // Type selector (first — determines name placeholder)
    var typeGroup = mk('div', 'form-group');
    var typeLabel = mk('label', 'form-label');
    typeLabel.textContent = 'Type';
    typeGroup.appendChild(typeLabel);
    var typeSelect = mk('select', 'form-select', { name: 'tf-type' });
    var types = ['redact', 'truncate', 'inject', 'dry_run', 'mask'];
    for (var ti = 0; ti < types.length; ti++) {
      var opt = mk('option');
      opt.value = types[ti];
      opt.textContent = types[ti];
      typeSelect.appendChild(opt);
    }
    typeGroup.appendChild(typeSelect);

    // UX-3 FIX: Description for each transform type
    var typeDescriptions = {
      redact: 'Replaces text matching a regex pattern with a placeholder (e.g. API_KEY=sk_live_xxx \u2192 API_KEY=[REDACTED]).',
      truncate: 'Cuts the response to N bytes/lines and appends a suffix (e.g. [TRUNCATED]). Use to limit large responses.',
      inject: 'Adds text before (prepend) and/or after (append) the response. Use for disclaimers or watermarks.',
      dry_run: 'Short-circuits the tool call and returns synthetic text instead. The upstream call is never executed. Use to test pipelines safely.',
      mask: 'Obscures the middle of matched text, preserving first/last N chars (e.g. 4532********0366).'
    };
    var typeDesc = mk('p', '', { style: 'font-size:var(--text-xs);color:var(--text-muted);margin-top:4px;line-height:1.4' });
    typeDesc.textContent = typeDescriptions.redact;
    typeGroup.appendChild(typeDesc);

    // Update description when type changes
    typeSelect.addEventListener('change', function () {
      typeDesc.textContent = typeDescriptions[typeSelect.value] || '';
    });

    form.appendChild(typeGroup);

    // Name (after type — placeholder adapts)
    var namePlaceholders = {
      redact: 'e.g. redact-api-keys',
      truncate: 'e.g. truncate-large-responses',
      inject: 'e.g. inject-disclaimer',
      dry_run: 'e.g. dry-run-all-tools',
      mask: 'e.g. mask-emails'
    };
    var nameGroup = mk('div', 'form-group');
    var nameLabel = mk('label', 'form-label');
    nameLabel.textContent = 'Name';
    nameGroup.appendChild(nameLabel);
    var nameInput = mk('input', 'form-input', {
      type: 'text', name: 'tf-name', placeholder: namePlaceholders.redact
    });
    nameGroup.appendChild(nameInput);
    form.appendChild(nameGroup);

    // Update placeholder when type changes
    typeSelect.addEventListener('change', function () {
      nameInput.placeholder = namePlaceholders[typeSelect.value] || 'e.g. my-transform';
    });

    // Tool Match
    var toolGroup = mk('div', 'form-group');
    var toolLabel = mk('label', 'form-label');
    toolLabel.textContent = 'Tool Match';
    toolGroup.appendChild(toolLabel);
    var toolInput = mk('input', 'form-input', {
      type: 'text', name: 'tf-tool-match', placeholder: 'e.g. read_file, file_*, *'
    });
    // Tool match autocomplete datalist
    var tfDlId = 'dl-tf-toolmatch-' + Math.random().toString(36).substr(2, 5);
    var tfDatalist = mk('datalist');
    tfDatalist.id = tfDlId;
    for (var tfi = 0; tfi < tools.length; tfi++) {
      var tfOpt = mk('option');
      tfOpt.value = tools[tfi].name || '';
      tfDatalist.appendChild(tfOpt);
    }
    toolInput.setAttribute('list', tfDlId);
    toolGroup.appendChild(toolInput);
    toolGroup.appendChild(tfDatalist);
    var toolHelp = mk('div', 'form-help');
    toolHelp.textContent = 'Tool name or glob pattern (* matches all)';
    toolGroup.appendChild(toolHelp);
    form.appendChild(toolGroup);

    // Priority
    var prioGroup = mk('div', 'form-group');
    var prioLabel = mk('label', 'form-label');
    prioLabel.textContent = 'Priority';
    prioGroup.appendChild(prioLabel);
    var prioInput = mk('input', 'form-input', {
      type: 'number', name: 'tf-priority', value: '100', min: '0', max: '10000'
    });
    prioGroup.appendChild(prioInput);
    var prioHelp = mk('div', 'form-help');
    prioHelp.textContent = 'Higher number = higher priority (applied first). Same as policy rules.';
    prioGroup.appendChild(prioHelp);
    form.appendChild(prioGroup);

    // Enabled
    var enabledGroup = mk('div', 'form-group');
    var enabledWrap = mk('label', '', { style: 'display: flex; align-items: center; gap: var(--space-2); cursor: pointer;' });
    var enabledCheckbox = mk('input', '', { type: 'checkbox', name: 'tf-enabled' });
    enabledCheckbox.checked = true;
    enabledWrap.appendChild(enabledCheckbox);
    var enabledText = mk('span', 'form-label', { style: 'margin: 0;' });
    enabledText.textContent = 'Enabled';
    enabledWrap.appendChild(enabledText);
    enabledGroup.appendChild(enabledWrap);
    var enabledHelp = mk('div', 'form-help');
    enabledHelp.textContent = 'Uncheck to save the rule without activating it';
    enabledGroup.appendChild(enabledHelp);
    form.appendChild(enabledGroup);

    // -- Type-specific config sections --

    // Pattern catalog chips helper
    var PATTERN_CATALOG = [
      { label: 'SSN', pattern: '\\d{3}-\\d{2}-\\d{4}' },
      { label: 'Credit Card', pattern: '\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b' },
      { label: 'Email', pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}' },
      { label: 'Phone (intl)', pattern: '\\+?\\d{1,4}[\\s-]?\\(?\\d{1,4}\\)?[\\s-]?\\d{2,4}[\\s-]?\\d{2,4}(?:[\\s-]?\\d{2,4})?' },
      { label: 'IBAN', pattern: '\\b[A-Z]{2}\\d{2}[\\s]?[\\dA-Z]{4}[\\s]?(?:[\\dA-Z]{4}[\\s]?){2,7}[\\dA-Z]{1,4}\\b' },
      { label: 'API Key', pattern: 'sk-[a-zA-Z0-9]{20,}' },
      { label: 'AWS Key', pattern: 'AKIA[0-9A-Z]{16}' },
      { label: 'IPv4', pattern: '\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b' }
    ];
    function buildPatternChips(targetTextarea) {
      var wrap = mk('div', '', { style: 'margin-top: var(--space-2);' });
      var chipLabel = mk('div', 'form-help', { style: 'margin-bottom: var(--space-2);' });
      chipLabel.textContent = 'Common patterns (click to add):';
      wrap.appendChild(chipLabel);
      var chipRow = mk('div', '', { style: 'display: flex; flex-wrap: wrap; gap: var(--space-1);' });
      for (var ci = 0; ci < PATTERN_CATALOG.length; ci++) {
        (function(cat) {
          var chip = mk('button', 'btn btn-sm', {
            type: 'button',
            style: 'border-radius: var(--radius-full); background: var(--bg-surface); color: var(--text-secondary); border: 1px solid var(--border); cursor: pointer; font-size: var(--text-xs); padding: var(--space-1) var(--space-2);'
          });
          chip.textContent = cat.label;
          chip.addEventListener('click', function() {
            var val = targetTextarea.value.trim();
            targetTextarea.value = val ? val + '\n' + cat.pattern : cat.pattern;
          });
          chipRow.appendChild(chip);
        })(PATTERN_CATALOG[ci]);
      }
      wrap.appendChild(chipRow);
      return wrap;
    }

    // Redact config
    var redactSection = mk('div', 'transform-config-section visible', { 'data-config-type': 'redact' });
    var rdPatGroup = mk('div', 'form-group');
    var rdPatLabel = mk('label', 'form-label');
    rdPatLabel.textContent = 'Patterns (one regex per line)';
    rdPatGroup.appendChild(rdPatLabel);
    var rdPatInput = mk('textarea', 'form-textarea', {
      name: 'tf-redact-patterns', rows: '3',
      placeholder: 'sk-[a-zA-Z0-9]{20,}\nAIza[0-9A-Za-z_-]{35}'
    });
    rdPatGroup.appendChild(rdPatInput);
    var rdPatHelp = mk('div', 'form-help');
    rdPatHelp.textContent = 'Regular expressions, one per line. Examples: \\d{3}-\\d{2}-\\d{4} (SSN), sk-[a-zA-Z0-9]{20,} (API key)';
    rdPatGroup.appendChild(rdPatHelp);
    redactSection.appendChild(rdPatGroup);
    redactSection.appendChild(buildPatternChips(rdPatInput));
    var rdReplGroup = mk('div', 'form-group');
    var rdReplLabel = mk('label', 'form-label');
    rdReplLabel.textContent = 'Replacement';
    rdReplGroup.appendChild(rdReplLabel);
    var rdReplInput = mk('input', 'form-input', {
      type: 'text', name: 'tf-redact-replacement', placeholder: '[REDACTED]'
    });
    rdReplGroup.appendChild(rdReplInput);
    redactSection.appendChild(rdReplGroup);
    form.appendChild(redactSection);

    // Truncate config
    var truncateSection = mk('div', 'transform-config-section', { 'data-config-type': 'truncate' });
    var trBytesGroup = mk('div', 'form-group');
    var trBytesLabel = mk('label', 'form-label');
    trBytesLabel.textContent = 'Max Bytes';
    trBytesGroup.appendChild(trBytesLabel);
    var trBytesInput = mk('input', 'form-input', {
      type: 'number', name: 'tf-truncate-max-bytes', placeholder: '10000'
    });
    trBytesGroup.appendChild(trBytesInput);
    truncateSection.appendChild(trBytesGroup);
    var trLinesGroup = mk('div', 'form-group');
    var trLinesLabel = mk('label', 'form-label');
    trLinesLabel.textContent = 'Max Lines';
    trLinesGroup.appendChild(trLinesLabel);
    var trLinesInput = mk('input', 'form-input', {
      type: 'number', name: 'tf-truncate-max-lines', placeholder: '100'
    });
    trLinesGroup.appendChild(trLinesInput);
    truncateSection.appendChild(trLinesGroup);
    var trSfxGroup = mk('div', 'form-group');
    var trSfxLabel = mk('label', 'form-label');
    trSfxLabel.textContent = 'Suffix';
    trSfxGroup.appendChild(trSfxLabel);
    var trSfxInput = mk('input', 'form-input', {
      type: 'text', name: 'tf-truncate-suffix', placeholder: '... [truncated]'
    });
    trSfxGroup.appendChild(trSfxInput);
    truncateSection.appendChild(trSfxGroup);
    form.appendChild(truncateSection);

    // Inject config
    var injectSection = mk('div', 'transform-config-section', { 'data-config-type': 'inject' });
    var inPrepGroup = mk('div', 'form-group');
    var inPrepLabel = mk('label', 'form-label');
    inPrepLabel.textContent = 'Prepend';
    inPrepGroup.appendChild(inPrepLabel);
    var inPrepInput = mk('textarea', 'form-textarea', {
      name: 'tf-inject-prepend', rows: '2',
      placeholder: 'WARNING: This response may contain sensitive data'
    });
    inPrepGroup.appendChild(inPrepInput);
    injectSection.appendChild(inPrepGroup);
    var inAppGroup = mk('div', 'form-group');
    var inAppLabel = mk('label', 'form-label');
    inAppLabel.textContent = 'Append';
    inAppGroup.appendChild(inAppLabel);
    var inAppInput = mk('textarea', 'form-textarea', {
      name: 'tf-inject-append', rows: '2', placeholder: ''
    });
    inAppGroup.appendChild(inAppInput);
    injectSection.appendChild(inAppGroup);
    form.appendChild(injectSection);

    // Dry Run config
    var dryRunSection = mk('div', 'transform-config-section', { 'data-config-type': 'dry_run' });
    var drRespGroup = mk('div', 'form-group');
    var drRespLabel = mk('label', 'form-label');
    drRespLabel.textContent = 'Response Template';
    drRespGroup.appendChild(drRespLabel);
    var drRespInput = mk('textarea', 'form-textarea', {
      name: 'tf-dryrun-response', rows: '3',
      placeholder: '{"success": true, "dry_run": true}'
    });
    drRespGroup.appendChild(drRespInput);
    dryRunSection.appendChild(drRespGroup);
    form.appendChild(dryRunSection);

    // Mask config
    var maskSection = mk('div', 'transform-config-section', { 'data-config-type': 'mask' });
    var mkPatGroup = mk('div', 'form-group');
    var mkPatLabel = mk('label', 'form-label');
    mkPatLabel.textContent = 'Patterns (one regex per line)';
    mkPatGroup.appendChild(mkPatLabel);
    var mkPatInput = mk('textarea', 'form-textarea', {
      name: 'tf-mask-patterns', rows: '3', placeholder: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'
    });
    mkPatGroup.appendChild(mkPatInput);
    var mkPatHelp = mk('div', 'form-help');
    mkPatHelp.textContent = 'Regular expressions, one per line. Matched text is partially hidden, showing only prefix/suffix characters. Example: [A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z]{2,} (email)';
    mkPatGroup.appendChild(mkPatHelp);
    maskSection.appendChild(mkPatGroup);
    maskSection.appendChild(buildPatternChips(mkPatInput));
    var mkVpGroup = mk('div', 'form-group');
    var mkVpLabel = mk('label', 'form-label');
    mkVpLabel.textContent = 'Visible Prefix';
    mkVpGroup.appendChild(mkVpLabel);
    var mkVpInput = mk('input', 'form-input', {
      type: 'number', name: 'tf-mask-visible-prefix', value: '3', min: '0'
    });
    mkVpGroup.appendChild(mkVpInput);
    maskSection.appendChild(mkVpGroup);
    var mkVsGroup = mk('div', 'form-group');
    var mkVsLabel = mk('label', 'form-label');
    mkVsLabel.textContent = 'Visible Suffix';
    mkVsGroup.appendChild(mkVsLabel);
    var mkVsInput = mk('input', 'form-input', {
      type: 'number', name: 'tf-mask-visible-suffix', value: '4', min: '0'
    });
    mkVsGroup.appendChild(mkVsInput);
    maskSection.appendChild(mkVsGroup);
    var mkCharGroup = mk('div', 'form-group');
    var mkCharLabel = mk('label', 'form-label');
    mkCharLabel.textContent = 'Mask Character';
    mkCharGroup.appendChild(mkCharLabel);
    var mkCharInput = mk('input', 'form-input', {
      type: 'text', name: 'tf-mask-char', value: '*', maxlength: '1'
    });
    mkCharGroup.appendChild(mkCharInput);
    maskSection.appendChild(mkCharGroup);
    form.appendChild(maskSection);

    // -- Error display area (for validation errors) --
    var errorArea = mk('div', 'form-error-text', { style: 'display: none;' });
    form.appendChild(errorArea);

    // -- Type toggle: show/hide config sections --
    function updateConfigVisibility() {
      var selected = typeSelect.value;
      var configSections = form.querySelectorAll('.transform-config-section');
      for (var cs = 0; cs < configSections.length; cs++) {
        var sType = configSections[cs].getAttribute('data-config-type');
        if (sType === selected) {
          configSections[cs].classList.add('visible');
        } else {
          configSections[cs].classList.remove('visible');
        }
      }
    }
    typeSelect.addEventListener('change', updateConfigVisibility);

    // -- Pre-fill for edit mode --
    if (isEdit) {
      nameInput.value = existing.name || '';
      typeSelect.value = existing.type || 'redact';
      nameInput.placeholder = namePlaceholders[typeSelect.value] || 'e.g. my-transform';
      typeDesc.textContent = typeDescriptions[typeSelect.value] || '';
      toolInput.value = existing.tool_match || '';
      prioInput.value = String(existing.priority || 100);
      enabledCheckbox.checked = existing.enabled !== false;

      var cfg = existing.config || {};
      if (existing.type === 'redact') {
        rdPatInput.value = (cfg.patterns || []).join('\n');
        rdReplInput.value = cfg.replacement || '';
      } else if (existing.type === 'truncate') {
        trBytesInput.value = cfg.max_bytes || '';
        trLinesInput.value = cfg.max_lines || '';
        trSfxInput.value = cfg.suffix || '';
      } else if (existing.type === 'inject') {
        inPrepInput.value = cfg.prepend || '';
        inAppInput.value = cfg.append || '';
      } else if (existing.type === 'dry_run') {
        drRespInput.value = cfg.response || '';
      } else if (existing.type === 'mask') {
        mkPatInput.value = (cfg.mask_patterns || []).join('\n');
        mkVpInput.value = cfg.visible_prefix != null ? String(cfg.visible_prefix) : '3';
        mkVsInput.value = cfg.visible_suffix != null ? String(cfg.visible_suffix) : '4';
        mkCharInput.value = cfg.mask_char || '*';
      }

      updateConfigVisibility();
    }

    // Prevent form submit
    form.addEventListener('submit', function (e) { e.preventDefault(); });

    // Footer buttons
    var footerEl = mk('div', '', { style: 'display: contents;' });
    var cancelBtn = mk('button', 'btn btn-secondary');
    cancelBtn.type = 'button';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', function () { SG.modal.close(); });
    footerEl.appendChild(cancelBtn);

    var saveBtn = mk('button', 'btn btn-primary');
    saveBtn.type = 'button';
    saveBtn.textContent = isEdit ? 'Update' : 'Save';
    footerEl.appendChild(saveBtn);

    // Save handler
    saveBtn.addEventListener('click', function () {
      errorArea.style.display = 'none';
      var payload = buildTransformRequestFromForm(form);

      if (!payload.name) {
        errorArea.textContent = 'Name is required';
        errorArea.style.display = 'block';
        nameInput.focus();
        return;
      }

      saveBtn.disabled = true;
      saveBtn.textContent = isEdit ? 'Updating\u2026' : 'Saving\u2026';

      var apiCall = isEdit
        ? SG.api.put('/v1/transforms/' + encodeURIComponent(existing.id), payload)
        : SG.api.post('/v1/transforms', payload);

      apiCall.then(function () {
        SG.modal.close();
        SG.toast.success('Transform "' + payload.name + '" ' + (isEdit ? 'updated' : 'created'));
        var contentArea = document.querySelector('.tools-content');
        if (contentArea) {
          var pageRoot = contentArea.parentElement;
          if (pageRoot) loadData(pageRoot);
        }
      }).catch(function (err) {
        errorArea.textContent = err.message || 'Failed to save transform';
        errorArea.style.display = 'block';
      }).finally(function () {
        saveBtn.disabled = false;
        saveBtn.textContent = isEdit ? 'Update' : 'Save';
      });
    });

    SG.modal.open({
      title: isEdit ? 'Edit Transform' : 'Add Transform',
      body: form,
      footer: footerEl,
      width: '600px'
    });

    setTimeout(function () { nameInput.focus(); }, 100);
  }

  /**
   * Build the Transform Test sandbox section.
   */
  function buildTransformTestSection() {
    var section = mk('div', '', { style: 'margin-top: var(--space-6);' });

    var header = mk('div', 'rules-header');
    var h3 = mk('h2');
    h3.innerHTML = SG.icon('zap', 20) + ' ';
    h3.appendChild(document.createTextNode('Test Transform'));
    header.appendChild(h3);
    section.appendChild(header);

    var card = mk('div', '', {
      style: 'background: var(--bg-primary); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-4);'
    });

    // Sample Text
    var textGroup = mk('div', 'form-group');
    var textLabel = mk('label', 'form-label');
    textLabel.textContent = 'Sample Text';
    textGroup.appendChild(textLabel);
    var textArea = mk('textarea', 'form-input', {
      id: 'tf-test-text', rows: '6',
      style: 'font-family: var(--font-mono); font-size: var(--text-xs); resize: vertical;',
      placeholder: 'Paste a sample tool response here...'
    });
    textGroup.appendChild(textArea);
    card.appendChild(textGroup);

    // Tool name input for matching saved rules
    var toolNameGroup = mk('div', 'form-group');
    var toolNameLabel = mk('label', 'form-label');
    toolNameLabel.textContent = 'Tool Name';
    toolNameGroup.appendChild(toolNameLabel);
    var toolNameInput = mk('input', 'form-input', {
      type: 'text', id: 'tf-test-tool', placeholder: 'e.g. read_file'
    });
    toolNameGroup.appendChild(toolNameInput);
    var toolNameHelp = mk('div', 'form-help');
    toolNameHelp.textContent = 'Used for matching saved transform rules by tool_match pattern';
    toolNameGroup.appendChild(toolNameHelp);
    card.appendChild(toolNameGroup);

    // Use saved rules checkbox
    var savedGroup = mk('div', 'form-group');
    var savedWrap = mk('label', '', { style: 'display: flex; align-items: center; gap: var(--space-2); cursor: pointer;' });
    var savedCheckbox = mk('input', '', { type: 'checkbox', id: 'tf-test-use-saved' });
    savedCheckbox.checked = true;
    savedWrap.appendChild(savedCheckbox);
    var savedText = mk('span', '', { style: 'font-size: var(--text-sm); color: var(--text-primary);' });
    savedText.textContent = 'Use saved rules';
    savedWrap.appendChild(savedText);
    savedGroup.appendChild(savedWrap);
    card.appendChild(savedGroup);

    // Custom rules JSON textarea (hidden when "use saved" is checked)
    var customGroup = mk('div', 'form-group', { style: 'display: none;' });
    var customLabel = mk('label', 'form-label');
    customLabel.textContent = 'Custom Rules (JSON)';
    customGroup.appendChild(customLabel);
    var customArea = mk('textarea', 'form-input', {
      id: 'tf-test-custom-rules', rows: '4',
      style: 'font-family: var(--font-mono); font-size: var(--text-xs); resize: vertical;',
      placeholder: '[{"name":"test","type":"redact","tool_match":"*","priority":100,"enabled":true,"config":{"patterns":["sk-.*"]}}]'
    });
    customGroup.appendChild(customArea);
    var customHelp = mk('div', 'form-help');
    customHelp.textContent = 'JSON array of transform rules. Each rule needs: name, type (redact|mask|truncate|inject|dry_run), tool_match (glob), priority (number), enabled (bool), config (type-specific object).';
    customGroup.appendChild(customHelp);
    card.appendChild(customGroup);

    // Toggle custom rules visibility
    savedCheckbox.addEventListener('change', function () {
      customGroup.style.display = savedCheckbox.checked ? 'none' : 'block';
    });

    // Run Test button
    var btnGroup = mk('div', 'form-group');
    var testBtn = mk('button', 'btn btn-primary');
    testBtn.innerHTML = SG.icon('zap', 16) + ' ';
    testBtn.appendChild(document.createTextNode('Run Test'));
    btnGroup.appendChild(testBtn);
    card.appendChild(btnGroup);

    // Result area
    var resultArea = mk('div', '', { style: 'display: none;' });
    card.appendChild(resultArea);

    // Test button handler
    testBtn.addEventListener('click', function () {
      var sampleText = textArea.value;
      if (!sampleText) {
        SG.toast.error('Please enter sample text to transform');
        textArea.focus();
        return;
      }

      var rules = [];
      if (savedCheckbox.checked) {
        // Build rules from saved transforms that match the tool name
        var toolName = toolNameInput.value.trim() || '*';
        for (var i = 0; i < transforms.length; i++) {
          var t = transforms[i];
          if (!t.enabled) continue;
          // Simple matching: * matches all, exact match, or glob
          var match = t.tool_match || '*';
          var matches = false;
          if (match === '*') {
            matches = true;
          } else if (match === toolName) {
            matches = true;
          } else if (match.indexOf('*') !== -1 || match.indexOf('?') !== -1) {
            matches = globMatch(match, toolName);
          }
          if (matches) {
            rules.push({
              name: t.name,
              type: t.type,
              tool_match: t.tool_match,
              priority: t.priority,
              enabled: t.enabled,
              config: t.config || {}
            });
          }
        }
      } else {
        // Parse custom rules JSON
        var customText = customArea.value.trim();
        if (customText) {
          try {
            rules = JSON.parse(customText);
            if (!Array.isArray(rules)) {
              SG.toast.error('Custom rules must be a JSON array');
              return;
            }
          } catch (e) {
            SG.toast.error('Invalid JSON in custom rules');
            return;
          }
        }
      }

      testBtn.disabled = true;
      var originalHTML = testBtn.innerHTML;
      testBtn.textContent = 'Testing\u2026';

      SG.api.post('/v1/transforms/test', { text: sampleText, rules: rules }).then(function (data) {
        resultArea.style.display = 'block';
        resultArea.innerHTML = '';

        // Output label
        var outputLabel = mk('div', 'form-label');
        outputLabel.textContent = 'Transformed Output';
        outputLabel.style.marginBottom = 'var(--space-2)';
        resultArea.appendChild(outputLabel);

        // Output pre block
        var outputPre = mk('div', 'transform-test-output');
        outputPre.textContent = data.output || '';
        resultArea.appendChild(outputPre);

        // Results list
        var results = data.results || [];
        if (results.length > 0) {
          var resultsDiv = mk('div', 'transform-test-results');
          var resultsLabel = mk('div', 'form-label');
          resultsLabel.textContent = 'Transform Results';
          resultsLabel.style.marginBottom = 'var(--space-2)';
          resultsLabel.style.marginTop = 'var(--space-3)';
          resultsDiv.appendChild(resultsLabel);

          for (var ri = 0; ri < results.length; ri++) {
            var r = results[ri];
            var item = mk('div', 'transform-test-result-item');

            var rName = mk('span', '');
            rName.textContent = r.rule_name || r.rule_id || 'Unknown';
            rName.style.fontWeight = 'var(--font-medium)';
            item.appendChild(rName);

            var rType = mk('span', 'transform-type-badge ' + transformTypeBadgeClass(r.type));
            rType.textContent = r.type || '';
            item.appendChild(rType);

            var rApplied = mk('span', 'badge ' + (r.applied ? 'badge-success' : 'badge-neutral'));
            rApplied.textContent = r.applied ? 'Applied' : 'Skipped';
            item.appendChild(rApplied);

            if (r.detail) {
              var rDetail = mk('span', '', { style: 'color: var(--text-muted); font-size: var(--text-xs);' });
              rDetail.textContent = r.detail;
              item.appendChild(rDetail);
            }

            resultsDiv.appendChild(item);
          }
          resultArea.appendChild(resultsDiv);
        }
      }).catch(function (err) {
        SG.toast.error(err.message || 'Transform test failed');
      }).finally(function () {
        testBtn.disabled = false;
        testBtn.innerHTML = originalHTML;
      });
    });

    section.appendChild(card);
    return section;
  }

  // -- Template picker modal --------------------------------------------------

  function openTemplatePickerModal() {
    var selectedId = null;
    var selectedDetail = null;
    var applyBtn = null;
    var previewDiv = null;

    SG.api.get('/v1/templates').then(function (templateList) {
      if (!templateList || !templateList.length) {
        SG.toast.error('No templates available');
        return;
      }

      // Build modal body
      var body = mk('div', '');

      // Explanation note
      var templateNote = mk('div', '', {
        style: 'font-size: var(--text-sm); color: var(--text-muted); margin-bottom: var(--space-3); line-height: 1.5;'
      });
      templateNote.textContent = 'Each template creates an independent set of rules. If you apply multiple templates, their rules are evaluated together by priority \u2014 conflicts may occur. Review the rules after applying.';
      body.appendChild(templateNote);

      // Template grid
      var grid = mk('div', 'template-grid');
      var cards = [];

      for (var i = 0; i < templateList.length; i++) {
        (function (tmpl) {
          var card = mk('div', 'template-card');
          card.setAttribute('data-template-id', tmpl.id);

          // Card header with icon and name
          var cardHeader = mk('div', 'template-card-header');
          var iconWrap = mk('span', 'template-card-icon');
          iconWrap.innerHTML = SG.icon(tmpl.icon, 20);
          cardHeader.appendChild(iconWrap);
          var nameEl = mk('span', 'template-card-name');
          nameEl.textContent = tmpl.name;
          cardHeader.appendChild(nameEl);
          card.appendChild(cardHeader);

          // Description
          var descEl = mk('div', 'template-card-desc');
          descEl.textContent = tmpl.description;
          card.appendChild(descEl);

          // Meta (rule count)
          var metaEl = mk('div', 'template-card-meta');
          metaEl.textContent = tmpl.rule_count + (tmpl.rule_count === 1 ? ' rule' : ' rules');
          card.appendChild(metaEl);

          // Click handler
          card.addEventListener('click', function () {
            // Deselect all cards
            for (var c = 0; c < cards.length; c++) {
              cards[c].classList.remove('selected');
            }
            // Select this card
            card.classList.add('selected');
            selectedId = tmpl.id;

            // Fetch full template detail for rule preview
            SG.api.get('/v1/templates/' + tmpl.id).then(function (detail) {
              selectedDetail = detail;
              showTemplatePreview(previewDiv, detail);
              if (applyBtn) {
                applyBtn.disabled = false;
                applyBtn.classList.remove('btn-disabled');
              }
            }).catch(function (err) {
              SG.toast.error('Failed to load template: ' + (err.message || 'Unknown error'));
            });
          });

          cards.push(card);
          grid.appendChild(card);
        })(templateList[i]);
      }

      body.appendChild(grid);

      // Preview section (initially hidden)
      previewDiv = mk('div', 'template-preview');
      body.appendChild(previewDiv);

      // Apply-to selector (target identity/role)
      var applyToDiv = mk('div', '', {
        style: 'margin-top: var(--space-3); border-top: 1px solid var(--border); padding-top: var(--space-3);'
      });
      var applyToLabel = mk('label', 'form-label');
      applyToLabel.textContent = 'Apply to';
      applyToDiv.appendChild(applyToLabel);
      var applyToSelect = mk('select', 'form-select', {
        style: 'margin-bottom: var(--space-2);'
      });
      var atAll = mk('option');
      atAll.value = 'all'; atAll.textContent = 'All identities';
      applyToSelect.appendChild(atAll);
      var atRole = mk('option');
      atRole.value = 'role'; atRole.textContent = 'Specific roles';
      applyToSelect.appendChild(atRole);
      var atIdentity = mk('option');
      atIdentity.value = 'identity'; atIdentity.textContent = 'Specific identities';
      applyToSelect.appendChild(atIdentity);
      applyToDiv.appendChild(applyToSelect);

      // Value select (invisible but space-reserving when "All" selected, to prevent footer height jumps)
      var applyToValueWrap = mk('div', '', { style: 'visibility: hidden; height: 0; overflow: hidden; transition: height 0.2s ease;' });
      var applyToValueSelect = mk('select', 'form-select');
      applyToValueWrap.appendChild(applyToValueSelect);
      var applyToHelp = mk('div', 'form-help');
      applyToHelp.textContent = 'Choose which role or identity to apply this template to';
      applyToValueWrap.appendChild(applyToHelp);
      applyToDiv.appendChild(applyToValueWrap);

      // Build role and identity option lists from cached data
      function populateApplyToOptions(mode) {
        applyToValueSelect.innerHTML = '';
        if (mode === 'role') {
          var allRoles = {};
          for (var ri = 0; ri < _cachedIdentities.length; ri++) {
            var roles = _cachedIdentities[ri].roles || [];
            for (var rj = 0; rj < roles.length; rj++) allRoles[roles[rj]] = true;
          }
          // Add known roles as fallback
          ['admin', 'user', 'read-only', 'developer', 'auditor'].forEach(function(r) { allRoles[r] = true; });
          Object.keys(allRoles).sort().forEach(function(r) {
            var opt = mk('option');
            opt.value = r; opt.textContent = r;
            applyToValueSelect.appendChild(opt);
          });
        } else {
          for (var ii = 0; ii < _cachedIdentities.length; ii++) {
            var opt = mk('option');
            opt.value = _cachedIdentities[ii].name || _cachedIdentities[ii].id;
            opt.textContent = _cachedIdentities[ii].name || _cachedIdentities[ii].id;
            applyToValueSelect.appendChild(opt);
          }
        }
      }

      applyToSelect.addEventListener('change', function () {
        if (applyToSelect.value === 'all') {
          applyToValueWrap.style.visibility = 'hidden';
          applyToValueWrap.style.height = '0';
          applyToValueWrap.style.overflow = 'hidden';
        } else {
          populateApplyToOptions(applyToSelect.value);
          applyToValueWrap.style.visibility = '';
          applyToValueWrap.style.height = '';
          applyToValueWrap.style.overflow = '';
        }
      });

      // Build footer — Apply-to selector is placed here so it's always visible
      // alongside the Cancel/Apply buttons without requiring scrolling
      var footerEl = mk('div', '', { style: 'display: contents;' });
      applyToDiv.style.marginTop = '0';
      applyToDiv.style.borderTop = 'none';
      applyToDiv.style.paddingTop = '0';
      applyToDiv.style.flex = '1';
      footerEl.appendChild(applyToDiv);

      var cancelBtn = mk('button', 'btn btn-secondary');
      cancelBtn.textContent = 'Cancel';
      cancelBtn.addEventListener('click', function () {
        SG.modal.close();
      });
      footerEl.appendChild(cancelBtn);

      applyBtn = mk('button', 'btn btn-primary');
      applyBtn.textContent = 'Apply Template';
      applyBtn.disabled = true;
      applyBtn.classList.add('btn-disabled');
      applyBtn.addEventListener('click', function () {
        if (!selectedId) return;

        // Detect specific conflicts between template rules and existing rules
        var tmplName = selectedDetail ? selectedDetail.name : selectedId;
        var conflictMsgs = [];
        var templateRules = selectedDetail ? (selectedDetail.rules || []) : [];

        // Flatten all existing rules
        var existingRules = [];
        for (var pi = 0; pi < policies.length; pi++) {
          var pRules = policies[pi].rules || [];
          for (var ri = 0; ri < pRules.length; ri++) {
            existingRules.push(pRules[ri]);
          }
        }

        for (var ti = 0; ti < templateRules.length; ti++) {
          var newRule = templateRules[ti];
          for (var ei = 0; ei < existingRules.length; ei++) {
            var er = existingRules[ei];
            // Check if tool_match patterns overlap
            var overlap = false;
            if (newRule.tool_match === er.tool_match) {
              overlap = true;
            } else if (newRule.tool_match === '*' || er.tool_match === '*') {
              overlap = true;
            } else {
              // Check glob overlap: does either match the other's pattern?
              overlap = globMatch(newRule.tool_match, er.tool_match) || globMatch(er.tool_match, newRule.tool_match);
            }
            if (!overlap) continue;

            // Overlapping tools found — check for conflicts
            var newAct = newRule.action || 'deny';
            var erAct = er.action || 'deny';

            // (b) Duplicate: same tool_match + same action
            if (newRule.tool_match === er.tool_match && newAct === erAct) {
              conflictMsgs.push('Duplicate: "' + newRule.name + '" is identical to existing "' + er.name + '" (both ' + erAct + ' on ' + er.tool_match + ')');
            }
            // (a)+(c) Contradicting: same/overlapping tools, opposite actions
            else if (newAct !== erAct) {
              var winner = (newRule.priority || 100) >= (er.priority || 100) ? newRule : er;
              var loser = winner === newRule ? er : newRule;
              conflictMsgs.push('Conflict: "' + winner.name + '" (' + (winner.action || 'deny') + ', priority ' + (winner.priority || 100) + ') overrides "' + loser.name + '" (' + (loser.action || 'deny') + ', priority ' + (loser.priority || 100) + ') on ' + (newRule.tool_match === er.tool_match ? er.tool_match : newRule.tool_match + ' / ' + er.tool_match));
            }
          }
        }

        // Deduplicate messages
        var uniqueMsgs = [];
        var seen = {};
        for (var mi = 0; mi < conflictMsgs.length; mi++) {
          if (!seen[conflictMsgs[mi]]) {
            seen[conflictMsgs[mi]] = true;
            uniqueMsgs.push(conflictMsgs[mi]);
          }
        }
        conflictMsgs = uniqueMsgs;
        // Build CEL condition for target
        var targetCondition = '';
        var atVal = applyToValueSelect.value.trim();
        if (applyToSelect.value === 'role' && atVal) {
          targetCondition = '"' + escCEL(atVal) + '" in identity_roles';
        } else if (applyToSelect.value === 'identity' && atVal) {
          targetCondition = 'identity_name == "' + escCEL(atVal) + '"';
        }

        if (conflictMsgs.length > 0) {
          var conflictSummary = conflictMsgs.length === 1
            ? conflictMsgs[0]
            : conflictMsgs.length + ' issues found:\n\n\u2022 ' + conflictMsgs.slice(0, 5).join('\n\u2022 ') + (conflictMsgs.length > 5 ? '\n\u2022 ...and ' + (conflictMsgs.length - 5) + ' more' : '');
          SG.modal.confirm({
            title: 'Potential Conflicts (' + conflictMsgs.length + ')',
            message: conflictSummary + '\n\nApply "' + tmplName + '" anyway?',
            confirmText: 'Apply Anyway',
            confirmClass: 'btn-primary',
            onConfirm: function () {
              applyTemplate(selectedId, targetCondition);
            }
          });
        } else {
          applyTemplate(selectedId, targetCondition);
        }
      });
      footerEl.appendChild(applyBtn);

      SG.modal.open({
        title: 'Choose a Policy Template',
        body: body,
        footer: footerEl,
        width: '640px'
      });
    }).catch(function (err) {
      SG.toast.error('Failed to load templates: ' + (err.message || 'Unknown error'));
    });
  }

  // Simple glob matcher for tool_match patterns (supports * and ? wildcards).
  function globMatch(pattern, name) {
    if (!pattern || pattern === '*') return true;
    var regex = '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]') + '$';
    try { return new RegExp(regex).test(name); } catch (e) { return false; }
  }

  function showTemplatePreview(previewDiv, detail) {
    previewDiv.innerHTML = '';
    previewDiv.classList.add('visible');

    var titleEl = mk('div', 'template-preview-title');
    titleEl.textContent = 'Rules in "' + detail.name + '"';
    previewDiv.appendChild(titleEl);

    var list = mk('ul', 'template-rule-list');
    var rules = detail.rules || [];
    for (var i = 0; i < rules.length; i++) {
      var rule = rules[i];
      var item = mk('li', 'template-rule-item');

      var ruleInfo = mk('span', '');
      ruleInfo.textContent = rule.name;
      if (rule.tool_match && rule.tool_match !== '*') {
        ruleInfo.textContent += ' (' + rule.tool_match + ')';
      }
      item.appendChild(ruleInfo);

      var actionBadge = mk('span', 'template-rule-action ' + rule.action);
      actionBadge.textContent = rule.action;
      item.appendChild(actionBadge);

      // Show matching tools from discovered tools
      var pattern = rule.tool_match || '*';
      var matchedTools = [];
      for (var t = 0; t < tools.length; t++) {
        if (globMatch(pattern, tools[t].name)) {
          matchedTools.push(tools[t].name);
        }
      }
      if (matchedTools.length > 0) {
        var matchLine = mk('div', '', {
          style: 'font-size: var(--text-xs); color: var(--text-muted); margin-top: 2px;'
        });
        var icon = rule.action === 'allow' ? '\u2713 ' : '\u2717 ';
        matchLine.textContent = icon + 'Matches: ' + matchedTools.slice(0, 8).join(', ') +
          (matchedTools.length > 8 ? ' (+' + (matchedTools.length - 8) + ' more)' : '');
        item.appendChild(matchLine);
      }

      list.appendChild(item);
    }
    previewDiv.appendChild(list);
  }

  function applyTemplate(templateId, targetCondition) {
    if (!targetCondition) {
      // No identity/role filter — use backend apply directly
      SG.api.post('/v1/templates/' + templateId + '/apply').then(function () {
        SG.toast.success('Template applied — policy created');
        SG.modal.close();
        var contentArea = document.querySelector('.tools-content');
        if (contentArea) {
          var pageRoot = contentArea.parentElement;
          if (pageRoot) loadData(pageRoot);
        }
      }).catch(function (err) {
        SG.toast.error('Failed to apply template: ' + (err.message || 'Unknown error'));
      });
    } else {
      // Fetch template, modify rules with target condition, create policy manually
      SG.api.get('/v1/templates/' + templateId).then(function (detail) {
        var rules = (detail.rules || []).map(function (r) {
          var cond = r.condition && r.condition !== 'true'
            ? '(' + r.condition + ') && ' + targetCondition
            : targetCondition;
          return {
            name: r.name,
            priority: r.priority || 100,
            tool_match: r.tool_match || '*',
            condition: cond,
            action: r.action || 'deny',
            source: 'template:' + detail.name
          };
        });
        var payload = {
          name: detail.name + ' (scoped)',
          description: 'Applied from template: ' + detail.name,
          priority: 100,
          enabled: true,
          rules: rules
        };
        return SG.api.post('/policies', payload);
      }).then(function () {
        SG.toast.success('Template applied with scope — policy created');
        SG.modal.close();
        var contentArea = document.querySelector('.tools-content');
        if (contentArea) {
          var pageRoot = contentArea.parentElement;
          if (pageRoot) loadData(pageRoot);
        }
      }).catch(function (err) {
        SG.toast.error('Failed to apply template: ' + (err.message || 'Unknown error'));
      });
    }
  }

  // -- Skeleton loading -------------------------------------------------------

  function renderSkeleton(container) {
    // Upstream groups skeleton (3 groups with header shimmer + tool rows)
    for (var i = 0; i < 3; i++) {
      var group = mk('div', 'tools-skeleton-group');
      group.appendChild(mk('div', 'skeleton tools-skeleton-header'));
      for (var r = 0; r < 3; r++) {
        group.appendChild(mk('div', 'skeleton tools-skeleton-row'));
      }
      container.appendChild(group);
    }
    // Rules section skeleton (table with header + 4 rows x 4 columns)
    var rulesSkeletonWrap = mk('div', '', {
      style: 'margin-top: var(--space-6);'
    });
    // Section title shimmer
    var titleShimmer = mk('div', '', {
      style: 'display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-4);'
    });
    titleShimmer.innerHTML = '<div class="skeleton skeleton-text" style="height: 20px; width: 140px;"></div>' +
      '<div class="skeleton skeleton-text" style="height: 32px; width: 100px; border-radius: var(--radius-md);"></div>';
    rulesSkeletonWrap.appendChild(titleShimmer);
    // Table skeleton
    var tableWrap = mk('div', '');
    tableWrap.innerHTML = skeletonTable(4, 4);
    rulesSkeletonWrap.appendChild(tableWrap);
    container.appendChild(rulesSkeletonWrap);
  }

  // -- Build full page DOM ----------------------------------------------------

  function buildPage(container) {
    var root = mk('div', '');

    // Header
    var header = mk('div', 'tools-header tools-enter');
    var headerLeft = mk('div', '');
    var h1 = mk('h1');
    h1.textContent = 'Tools & Rules';
    headerLeft.appendChild(h1);
    var subtitle = mk('p', 'page-subtitle');
    subtitle.textContent = 'Manage your security rules and response transforms.';
    headerLeft.appendChild(subtitle);
    header.appendChild(headerLeft);

    var actions = mk('div', 'tools-header-actions');
    // Add Server button
    var addServerBtn = mk('button', 'btn btn-primary btn-sm');
    addServerBtn.setAttribute('data-action', 'add-upstream');
    addServerBtn.innerHTML = SG.icon('plus', 16) + ' ';
    addServerBtn.appendChild(document.createTextNode('Add Server'));
    addServerBtn.addEventListener('click', function () { openAddUpstreamModal(null); });
    actions.appendChild(addServerBtn);
    // Use Template button
    var templateBtn = mk('button', 'btn btn-secondary btn-sm');
    templateBtn.innerHTML = SG.icon('filePlus', 16) + ' ';
    templateBtn.appendChild(document.createTextNode('Use Template'));
    templateBtn.addEventListener('click', function () {
      openTemplatePickerModal();
    });
    actions.appendChild(templateBtn);
    header.appendChild(actions);
    var helpBtn = mk('button', 'help-btn', {
      type: 'button',
      'aria-label': 'Help for Tools & Rules page'
    });
    helpBtn.textContent = '?';
    helpBtn.addEventListener('click', function() { if (SG.help) SG.help.toggle('tools'); });
    actions.appendChild(helpBtn);

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
    if (_lintTimer) { clearTimeout(_lintTimer); _lintTimer = null; }
    tools = [];
    upstreams = [];
    policies = [];
    conflicts = [];
    transforms = [];
    activeFilter = 'all';
    collapsedGroups = {};
    activeSectionTab = 'tools-rules';
    _sortState = { key: null, direction: null };
    _initialTabHandled = false;
    _cachedPoliciesForPriority = null;
  }

  // -- Expose internal functions for testing (used by tools_test.html) --------

  SG.tools = SG.tools || {};
  SG.tools._internal = {
    buildCELFromSimple: buildCELFromSimple,
    globToRegex: globToRegex,
    parseCELToSimple: parseCELToSimple,
    // UX-F4 Visual Policy Builder
    conditionToCEL: conditionToCEL,
    generateCELFromConditions: generateCELFromConditions,
    parseCELToConditions: parseCELToConditions,
    parseSingleCondition: parseSingleCondition,
    VARIABLE_CATALOG: VARIABLE_CATALOG,
    OPERATORS_BY_TYPE: OPERATORS_BY_TYPE,
    transformTypeBadgeClass: transformTypeBadgeClass,
    buildTransformRequestFromForm: buildTransformRequestFromForm,
    renderTransforms: renderTransforms,
    renderTransformRow: renderTransformRow,
    openTransformModal: openTransformModal,
    // Phase 2 polish
    skeletonTable: skeletonTable,
    renderRulesEmpty: renderRulesEmpty,
    renderServersEmpty: renderServersEmpty,
    makeInlineEditable: makeInlineEditable,
    makeColumnSortable: makeColumnSortable,
    deleteRuleOptimistic: deleteRuleOptimistic,
    deleteUpstreamOptimistic: deleteUpstreamOptimistic
  };
  SG.tools.openAddUpstreamModal = openAddUpstreamModal;
  SG.tools.openTemplatePickerModal = openTemplatePickerModal;
  SG.tools.openRuleModal = openRuleModal;
  SG.tools.buildAutocomplete = buildAutocomplete;

  // Allow external callers (e.g. Permissions page) to open the rule modal
  // with full tool chips, identity shortcuts, and CSS — even when the Tools
  // page has not been rendered yet.
  SG.tools.ensureDataForModal = function () {
    injectStyles();
    var promises = [];
    if (tools.length === 0) {
      promises.push(SG.api.get('/tools', { silent: true }).then(function (t) {
        // API returns {tools: [...], conflicts: [...]}
        var list = Array.isArray(t) ? t : (t && Array.isArray(t.tools) ? t.tools : []);
        if (list.length > 0) tools = list;
      }));
    }
    if (_cachedIdentities.length === 0) {
      promises.push(SG.api.get('/identities', { silent: true }).then(function (ids) {
        if (Array.isArray(ids)) _cachedIdentities = ids;
      }));
    }
    if (policies.length === 0) {
      promises.push(SG.api.get('/policies', { silent: true }).then(function (p) {
        if (Array.isArray(p)) policies = p;
      }));
    }
    return Promise.all(promises);
  };

  // -- Registration -----------------------------------------------------------

  SG.router.register('tools', render);
  SG.router.registerCleanup('tools', cleanup);
})();
