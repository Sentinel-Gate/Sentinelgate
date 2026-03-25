/**
 * dashboard.js -- Dashboard page for SentinelGate admin UI.
 *
 * The command center: live stat cards, upstream health, active sessions,
 * and real-time activity feed. Self-registers with SG.router and manages
 * its own polling intervals and SSE connection lifecycle.
 *
 * Data sources:
 *   GET /admin/api/stats              -> stat card values (polled every 2s)
 *   GET /admin/api/upstreams          -> upstream list + status (polled every 5s)
 *   GET /admin/api/v1/sessions/active -> active sessions with usage (polled every 2s)
 *   GET /admin/api/v1/quotas          -> quota configs for progress bar limits (once)
 *   SSE /admin/api/audit/stream       -> real-time activity entries
 *
 * Design features:
 *   - Staggered entrance animations on page load
 *   - Skeleton loading placeholders before first data arrives
 *   - Value-change pulse animation on stat card updates
 *   - Semantic icon tints (success for Allowed, danger for Denied, etc.)
 *   - Activity entries slide in from left on SSE arrival
 *   - Active sessions with progress bars (green/yellow/red/overflow)
 *   - Responsive grid: 4->3->2->1 cols for stat cards
 *   - All user data rendered via textContent (XSS-safe)
 *
 * Requirements:
 *   DASH-01  Four stat cards with live counts
 *   DASH-02  Recent activity feed via SSE (last 10 entries)
 *   DASH-03  Upstream status with connection dots
 *   DASH-04  Click upstream navigates to #/tools?upstream={id}
 *   DASH-05  Live indicator (pulsing green dot) for SSE state
 *   DASH-06  Polling intervals: stats 2s, upstreams 5s
 *   DASH-07  Active sessions widget with progress bars
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // -- State ------------------------------------------------------------------

  var statsInterval = null;
  var upstreamInterval = null;
  var eventSource = null;
  var activityEntries = [];
  var MAX_ACTIVITY = 10;
  var previousStats = {};
  var styleInjected = false;
  var cachedQuotas = {}; // keyed by identity_id
  var previousSessions = []; // for DOM diffing

  // -- Cached supplementary data (4.1, 4.2, 4.3) --
  var cachedPolicies = null;
  var cachedIdentities = null;
  var cachedKeys = null;
  var cachedTransforms = null;
  var cachedContentScan = null, cachedDriftConfig = null, cachedRecordingConfig = null;
  var cachedLastStats = null;
  var cachedUpstreams = null;
  var upstreamsLoaded = false; // true after first upstream poll resolves
  var postureExpanded = false; // preserve toggle state across re-renders
  var supplementaryInterval = null;
  var sessionsInterval = null; // BUG-4 FIX: polling for active sessions
  var statCardsBuilt = false; // tracks whether skeleton was replaced with real cards

  // -- Count-up animation for stat card values --------------------------------

  /**
   * Animate a number from its current displayed value to a new value.
   * Handles integers only. Duration adapts to delta size.
   *
   * @param {HTMLElement} el - Element whose textContent shows the number
   * @param {number} newVal - Target value
   * @param {number} [duration=400] - Animation duration in ms
   */
  function animateValue(el, newVal, duration) {
    duration = duration || 400;
    var startVal = parseInt(el.textContent.replace(/,/g, ''), 10) || 0;
    if (startVal === newVal) return;

    var delta = newVal - startVal;
    var startTime = null;

    // Visual flash
    el.classList.add('value-changed');
    setTimeout(function () { el.classList.remove('value-changed'); }, 400);

    function step(timestamp) {
      if (!startTime) startTime = timestamp;
      var progress = Math.min((timestamp - startTime) / duration, 1);
      // Ease out cubic
      var eased = 1 - Math.pow(1 - progress, 3);
      var current = Math.round(startVal + delta * eased);
      el.textContent = current.toLocaleString();
      if (progress < 1) {
        requestAnimationFrame(step);
      }
    }

    requestAnimationFrame(step);
  }

  // -- Dashboard-specific styles ----------------------------------------------
  // Injected once into <head> on first render; co-located here so
  // dashboard layout, animations, and micro-interactions live with the
  // code that uses them.

  var DASHBOARD_CSS = [
    /* -- Layout --------------------------------------------------------- */
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

    /* -- Health indicator ------------------------------------------------ */
    '.health-dot {',
    '  display: inline-block;',
    '  width: 10px;',
    '  height: 10px;',
    '  border-radius: 50%;',
    '  margin-left: var(--space-2);',
    '  vertical-align: middle;',
    '  transition: background 0.3s ease, box-shadow 0.3s ease;',
    '}',
    '.health-dot.health-green { background: var(--success); box-shadow: 0 0 6px var(--success); }',
    '.health-dot.health-yellow { background: var(--warning); box-shadow: 0 0 6px var(--warning); }',
    '.health-dot.health-red { background: var(--danger); box-shadow: 0 0 6px var(--danger); }',

    /* Stat cards grid -- responsive breakpoints */
    '.stat-cards-grid {',
    '  display: grid;',
    '  grid-template-columns: repeat(6, 1fr);',
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
    '  margin-top: var(--space-6);',
    '}',
    '@media (max-width: 768px) {',
    '  .dashboard-panels { grid-template-columns: 1fr; }',
    '}',

    /* -- Staggered entrance animation ----------------------------------- */
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
    '.dash-enter-8 { animation-delay: 0.38s; }',

    /* -- Stat value change pulse ---------------------------------------- */
    '@keyframes valuePulse {',
    '  0%   { transform: scale(1);    color: var(--text-primary); }',
    '  30%  { transform: scale(1.12); color: var(--accent-text); }',
    '  100% { transform: scale(1);    color: var(--text-primary); }',
    '}',
    '.stat-card-value.value-changed {',
    '  animation: valuePulse 0.5s ease;',
    '}',

    /* -- Semantic icon tints per stat card type -------------------------- */
    '.stat-icon-accent  .stat-card-icon { background: var(--accent-subtle); color: var(--accent); }',
    '.stat-icon-success .stat-card-icon { background: var(--success-subtle); color: var(--success); }',
    '.stat-icon-danger  .stat-card-icon { background: var(--danger-subtle); color: var(--danger); }',
    '.stat-icon-warning .stat-card-icon { background: var(--warning-subtle); color: var(--warning); }',
    '.stat-icon-blocked .stat-card-icon { background: rgba(139, 92, 246, 0.12); color: #7c3aed; }',

    /* -- Skeleton loading shimmer --------------------------------------- */
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

    /* -- Activity entry slide-in ---------------------------------------- */
    '@keyframes activitySlideIn {',
    '  from { opacity: 0; transform: translateX(-8px); }',
    '  to   { opacity: 1; transform: translateX(0); }',
    '}',
    '.activity-entry-new {',
    '  animation: activitySlideIn 0.3s ease both;',
    '}',
    '.badge-scan {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  padding: 1px var(--space-2);',
    '  font-size: 10px;',
    '  font-weight: var(--font-medium);',
    '  border-radius: var(--radius-full);',
    '  background: rgba(234, 179, 8, 0.15);',
    '  color: var(--warning);',
    '  border: 1px solid rgba(234, 179, 8, 0.25);',
    '  flex-shrink: 0;',
    '}',

    /* -- Scroll areas with styled scrollbars ----------------------------- */
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
    /* UX-13 FIX: Scroll fade indicator at bottom of scrollable cards */
    '.dash-scroll-wrap { position: relative; }',
    '.dash-scroll-wrap::after {',
    '  content: "";',
    '  position: absolute;',
    '  bottom: 0; left: 0; right: 0;',
    '  height: 32px;',
    '  background: linear-gradient(transparent, var(--bg-primary));',
    '  pointer-events: none;',
    '  opacity: 0;',
    '  transition: opacity 0.2s;',
    '}',
    '.dash-scroll-wrap.has-overflow::after { opacity: 1; }',

    /* -- Clickable upstream rows ---------------------------------------- */
    '.upstream-item-link { cursor: pointer; }',

    /* -- Delete button on upstream items -------------------------------- */
    '.upstream-delete-btn {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  width: 28px;',
    '  height: 28px;',
    '  border: 1px solid var(--border);',
    '  background: var(--bg-secondary);',
    '  color: var(--text-muted);',
    '  border-radius: var(--radius-sm);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '  flex-shrink: 0;',
    '}',
    '.upstream-delete-btn:hover {',
    '  color: var(--danger);',
    '  background: rgba(239, 68, 68, 0.1);',
    '  border-color: var(--danger);',
    '}',

    /* -- Live indicator inactive state ---------------------------------- */
    '.live-indicator.inactive {',
    '  color: var(--text-muted);',
    '}',
    '.live-indicator.inactive .live-dot {',
    '  background: var(--text-muted);',
    '}',
    '.live-indicator.inactive .live-dot::before {',
    '  display: none;',
    '}',

    /* -- Protocol/Framework distribution widgets (UI-01, UI-02) --------- */
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
    '}',

    /* -- Active Sessions widget ----------------------------------------- */
    '.sessions-grid {',
    '  display: grid;',
    '  grid-template-columns: 1fr 1fr;',
    '  gap: var(--space-3);',
    '}',
    '@media (max-width: 768px) {',
    '  .sessions-grid { grid-template-columns: 1fr; }',
    '}',
    '.session-card {',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  padding: var(--space-3);',
    '}',
    '.session-card-header {',
    '  display: flex;',
    '  justify-content: space-between;',
    '  align-items: center;',
    '  margin-bottom: var(--space-2);',
    '}',
    '.session-identity {',
    '  font-weight: 600;',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '}',
    '.session-id {',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '}',
    '.session-stats-row {',
    '  display: flex;',
    '  gap: var(--space-3);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-secondary);',
    '  margin-bottom: var(--space-2);',
    '}',
    '.session-stat-item {',
    '  white-space: nowrap;',
    '}',
    '.session-stat-item strong {',
    '  color: var(--text-primary);',
    '}',
    '.session-progress {',
    '  margin-bottom: var(--space-1);',
    '}',
    '.session-progress-label {',
    '  display: flex;',
    '  justify-content: space-between;',
    '  font-size: var(--text-xs);',
    '  color: var(--text-secondary);',
    '  margin-bottom: 2px;',
    '}',
    '.session-progress-track {',
    '  height: 6px;',
    '  background: var(--bg-primary);',
    '  border-radius: var(--radius-full);',
    '  overflow: hidden;',
    '}',
    '.session-progress-bar {',
    '  height: 100%;',
    '  border-radius: var(--radius-full);',
    '  transition: width 0.4s ease, background 0.3s ease;',
    '}',
    '.session-progress-green  { background: var(--success); }',
    '.session-progress-yellow { background: var(--warning); }',
    '.session-progress-red    { background: var(--danger); }',
    '@keyframes overflowPulse {',
    '  0%, 100% { opacity: 1; }',
    '  50%      { opacity: 0.7; }',
    '}',
    '.session-progress-overflow {',
    '  background: var(--danger);',
    '  animation: overflowPulse 1.5s ease infinite;',
    '}',
    '.session-meta {',
    '  display: flex;',
    '  gap: var(--space-3);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  margin-top: var(--space-2);',
    '}',
    '.session-count-badge {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  min-width: 20px;',
    '  height: 20px;',
    '  padding: 0 var(--space-1);',
    '  font-size: var(--text-xs);',
    '  font-weight: 600;',
    '  color: var(--text-secondary);',
    '  background: var(--bg-surface);',
    '  border-radius: var(--radius-full);',
    '  margin-left: var(--space-2);',
    '}',

    /* -- Next-steps banner (UX-07) -------------------------------------- */
    '@keyframes nextstepsFadeIn {',
    '  from { opacity: 0; transform: translateY(-8px); }',
    '  to   { opacity: 1; transform: translateY(0); }',
    '}',
    '.nextsteps-banner {',
    '  display: flex;',
    '  align-items: flex-start;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3) var(--space-4);',
    '  margin-bottom: var(--space-4);',
    '  background: var(--accent-subtle);',
    '  border: 1px solid var(--accent);',
    '  border-radius: var(--radius-lg);',
    '  animation: nextstepsFadeIn 0.4s ease both;',
    '}',
    '.nextsteps-banner-icon {',
    '  flex-shrink: 0;',
    '  color: var(--accent);',
    '  margin-top: 2px;',
    '}',
    '.nextsteps-banner-icon svg {',
    '  width: 20px;',
    '  height: 20px;',
    '}',
    '.nextsteps-banner-body {',
    '  flex: 1;',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  line-height: 1.5;',
    '}',
    '.nextsteps-banner-body a {',
    '  color: var(--accent-text);',
    '  font-weight: var(--font-semibold);',
    '  text-decoration: underline;',
    '  text-underline-offset: 2px;',
    '}',
    '.nextsteps-banner-body a:hover {',
    '  opacity: 0.85;',
    '}',
    '.nextsteps-banner-close {',
    '  flex-shrink: 0;',
    '  background: none;',
    '  border: none;',
    '  cursor: pointer;',
    '  color: var(--text-muted);',
    '  padding: 2px;',
    '  line-height: 1;',
    '  border-radius: var(--radius-sm);',
    '  transition: color var(--transition-fast), background var(--transition-fast);',
    '}',
    '.nextsteps-banner-close:hover {',
    '  color: var(--text-primary);',
    '  background: var(--bg-surface);',
    '}',

    /* -- Security Score widget (4.1) --------------------------------- */
    '.posture-card { margin-bottom: var(--space-4); }',
    '.posture-bar-track { width: 100%; height: 8px; background: var(--bg-elevated); border-radius: 4px; overflow: hidden; margin: var(--space-2) 0; }',
    '.posture-bar { height: 100%; border-radius: 4px; transition: width 0.5s ease, background 0.3s ease; }',
    '.posture-score { font-size: var(--text-lg); font-weight: 600; }',
    '.posture-toggle {',
    '  display: inline-flex; align-items: center; gap: var(--space-1);',
    '  background: none; border: none; color: var(--accent);',
    '  font-size: var(--text-sm); cursor: pointer; padding: var(--space-1) 0; margin-top: var(--space-2);',
    '}',
    '.posture-toggle:hover { text-decoration: underline; }',
    '.posture-suggestions.collapsed { display: none; }',
    '.posture-suggestions { margin-top: var(--space-3); }',
    '.posture-suggestion { font-size: var(--text-sm); color: var(--text-secondary); padding: var(--space-1) 0; display: flex; align-items: center; gap: var(--space-2); }',
    '.posture-suggestion::before { content: \'\\2192\'; color: var(--accent); }',

    /* -- Actionable Insights widget (4.3) ------------------------------- */
    '.insights-card { margin-bottom: var(--space-4); }',
    '.insight-item { font-size: var(--text-sm); color: var(--text-secondary); padding: var(--space-1) 0; display: flex; align-items: center; gap: var(--space-2); }',
    '.insight-item::before { content: \'\\2022\'; color: var(--accent); font-weight: bold; }',

    /* -- Next-step banner (4.2) ----------------------------------------- */
    '.nextstep-realtime-banner {',
    '  display: flex;',
    '  align-items: flex-start;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3) var(--space-4);',
    '  margin-bottom: var(--space-4);',
    '  background: var(--accent-subtle);',
    '  border: 1px solid var(--accent);',
    '  border-radius: var(--radius-lg);',
    '  animation: nextstepsFadeIn 0.4s ease both;',
    '}',
    '.nextstep-realtime-banner a {',
    '  color: var(--accent-text);',
    '  font-weight: var(--font-semibold);',
    '  text-decoration: underline;',
    '  text-underline-offset: 2px;',
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

  // -- Skeleton loading helpers (2.4) -----------------------------------------

  /**
   * Generate skeleton stat cards HTML for the dashboard grid.
   * @param {number} count - Number of skeleton cards to render
   * @returns {string} HTML string
   */
  function renderSkeletonStatCards(count) {
    var html = '';
    for (var i = 0; i < count; i++) {
      html +=
        '<div class="skeleton-card" style="display:flex;align-items:flex-start;justify-content:space-between;">' +
          '<div style="flex:1;">' +
            '<div class="skeleton skeleton-text" style="width:50%;height:12px;margin-bottom:12px;"></div>' +
            '<div class="skeleton skeleton-text" style="width:25%;height:28px;margin-bottom:8px;"></div>' +
            '<div class="skeleton skeleton-text" style="width:75%;height:12px;"></div>' +
          '</div>' +
          '<div class="skeleton skeleton-circle" style="width:40px;height:40px;flex-shrink:0;border-radius:50%;"></div>' +
        '</div>';
    }
    return html;
  }

  /**
   * Generate skeleton activity feed entries HTML.
   * @param {number} count - Number of skeleton entries to render
   * @returns {string} HTML string
   */
  function renderSkeletonActivityFeed(count) {
    var html = '';
    for (var i = 0; i < count; i++) {
      html +=
        '<div style="display:flex;gap:var(--space-3);padding:var(--space-2) 0;' +
          (i < count - 1 ? 'border-bottom:1px solid var(--border);margin-bottom:var(--space-2);' : '') + '">' +
          '<div class="skeleton skeleton-circle" style="width:32px;height:32px;flex-shrink:0;border-radius:50%;"></div>' +
          '<div style="flex:1;">' +
            '<div class="skeleton skeleton-text" style="width:75%;height:14px;margin-bottom:6px;"></div>' +
            '<div class="skeleton skeleton-text" style="width:50%;height:12px;"></div>' +
          '</div>' +
        '</div>';
    }
    return html;
  }

  // -- Onboarding banner for dashboard (shown when no servers connected) ------

  /**
   * Render a compact onboarding banner at the top of the dashboard.
   * The full dashboard remains visible below (counters at zero, widgets empty).
   * @param {HTMLElement} container - The banner container
   */
  function renderOnboardingBanner(container) {
    container.innerHTML = '';
    var banner = mk('div', '', {
      style: 'background: var(--info-subtle); border: 1px solid rgba(59, 130, 246, 0.2); ' +
        'border-radius: var(--radius-lg); padding: var(--space-4) var(--space-5); ' +
        'margin-bottom: var(--space-5); display: flex; align-items: center; gap: var(--space-4);'
    });
    banner.id = 'onboarding-banner';
    var iconWrap = mk('div', '', {
      style: 'flex-shrink: 0; width: 36px; height: 36px; border-radius: 50%; ' +
        'background: rgba(59, 130, 246, 0.15); display: flex; align-items: center; ' +
        'justify-content: center; color: var(--info);'
    });
    iconWrap.innerHTML = SG.icon('info', 18);
    banner.appendChild(iconWrap);
    var textWrap = mk('div', '', { style: 'flex: 1;' });
    var bannerTitle = mk('div', '', {
      style: 'font-weight: var(--font-semibold); color: var(--text-primary); margin-bottom: 2px;'
    });
    bannerTitle.textContent = 'No MCP servers connected yet';
    textWrap.appendChild(bannerTitle);
    var bannerDesc = mk('div', '', {
      style: 'font-size: var(--text-sm); color: var(--text-secondary);'
    });
    bannerDesc.textContent = 'Connect your first server to start proxying tools and see live activity.';
    textWrap.appendChild(bannerDesc);
    banner.appendChild(textWrap);
    var connectBtn = mk('button', 'btn btn-primary btn-sm', { type: 'button', 'aria-label': 'Connect a Server' });
    var btnIcon = mk('span', '', { 'aria-hidden': 'true' });
    btnIcon.innerHTML = SG.icon('plus', 14);
    connectBtn.appendChild(btnIcon);
    connectBtn.appendChild(document.createTextNode(' Connect a Server'));
    connectBtn.addEventListener('click', function () {
      window.location.hash = '#/tools';
    });
    banner.appendChild(connectBtn);
    container.appendChild(banner);
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

  // -- Build full dashboard DOM -----------------------------------------------

  function buildDashboard(container) {
    var root = mk('div', '');
    root.id = 'dashboard-root';

    // -- Next-step banner container (4.2, real state based) --
    var nextStepContainer = mk('div', '');
    nextStepContainer.id = 'nextstep-banner-container';
    root.appendChild(nextStepContainer);

    // -- Header row --
    var header = mk('div', 'dashboard-header dash-enter dash-enter-1');
    var headerLeft = mk('div', '');
    var h1 = mk('h1');
    h1.textContent = 'Dashboard';
    var healthDot = mk('span', 'health-dot health-green');
    healthDot.id = 'health-indicator';
    healthDot.title = 'All systems healthy';
    h1.appendChild(healthDot);
    headerLeft.appendChild(h1);
    var subtitle = mk('p', 'page-subtitle');
    subtitle.textContent = 'Real-time overview of all activity flowing through your proxy.';
    headerLeft.appendChild(subtitle);
    header.appendChild(headerLeft);

    var live = mk('div', 'live-indicator inactive');
    live.id = 'live-indicator';
    live.appendChild(mk('span', 'live-dot'));
    var liveLabel = mk('span');
    liveLabel.textContent = 'Live';
    live.appendChild(liveLabel);
    header.appendChild(live);
    var helpBtn = mk('button', 'help-btn', { type: 'button' });
    helpBtn.textContent = '?';
    helpBtn.setAttribute('aria-label', 'Show dashboard help');
    helpBtn.addEventListener('click', function() { if (SG.help) SG.help.toggle('dashboard'); });
    header.appendChild(helpBtn);
    root.appendChild(header);

    // -- Stat cards grid (skeleton shown first, replaced on data load) --
    var grid = mk('div', 'stat-cards-grid dash-enter dash-enter-2');
    grid.id = 'stat-cards';
    grid.innerHTML = renderSkeletonStatCards(5);
    root.appendChild(grid);

    // -- Security Score widget (4.1) --
    var postureCard = mk('div', 'card posture-card dash-enter dash-enter-3');
    postureCard.id = 'posture-widget';
    var postureHeader = mk('div', 'card-header');
    var postureTitle = mk('span', 'card-title');
    postureTitle.innerHTML = SG.icon('shield', 16) + ' ';
    postureTitle.appendChild(document.createTextNode('Security Score'));
    postureHeader.appendChild(postureTitle);
    postureCard.appendChild(postureHeader);
    var postureBody = mk('div', 'card-body');
    postureBody.id = 'posture-body';
    var postureLoading = mk('div', 'dist-empty-state');
    postureLoading.textContent = 'Calculating security score\u2026';
    postureBody.appendChild(postureLoading);
    postureCard.appendChild(postureBody);
    root.appendChild(postureCard);

    // -- Actionable Insights widget (4.3) --
    var insightsCard = mk('div', 'card insights-card dash-enter dash-enter-3');
    insightsCard.id = 'insights-widget';
    var insightsHeader = mk('div', 'card-header');
    var insightsTitle = mk('span', 'card-title');
    insightsTitle.innerHTML = SG.icon('zap', 16) + ' ';
    insightsTitle.appendChild(document.createTextNode('Insights'));
    insightsHeader.appendChild(insightsTitle);
    insightsCard.appendChild(insightsHeader);
    var insightsBody = mk('div', 'card-body');
    insightsBody.id = 'insights-body';
    insightsCard.appendChild(insightsBody);
    // insightsCard, widgets, sessCard removed from dashboard (moved to audit.js / sessions.js)

    // -- Two-column panels --
    var panels = mk('div', 'dashboard-panels');

    // Upstreams card
    var upCard = mk('div', 'card dash-enter dash-enter-6');
    var upHeader = mk('div', 'card-header');
    var upTitle = mk('span', 'card-title');
    upTitle.innerHTML = SG.icon('server', 16) + ' ';
    upTitle.appendChild(document.createTextNode('MCP Servers'));
    upHeader.appendChild(upTitle);
    upCard.appendChild(upHeader);

    var upWrap = mk('div', 'dash-scroll-wrap');
    var upBody = mk('div', 'card-body dash-scroll');
    upBody.id = 'upstream-list';
    // Skeleton loading state for upstream list
    for (var s = 0; s < 3; s++) {
      upBody.appendChild(mk('div', 'skeleton skeleton-item'));
    }
    upWrap.appendChild(upBody);
    upCard.appendChild(upWrap);
    panels.appendChild(upCard);

    // Activity card
    var actCard = mk('div', 'card dash-enter dash-enter-7');
    var actHeader = mk('div', 'card-header');
    var actTitle = mk('span', 'card-title');
    actTitle.innerHTML = SG.icon('activity', 16) + ' ';
    actTitle.appendChild(document.createTextNode('Recent Activity'));
    actHeader.appendChild(actTitle);
    actCard.appendChild(actHeader);

    var actWrap = mk('div', 'dash-scroll-wrap');
    var actBody = mk('div', 'card-body dash-scroll');
    actBody.id = 'activity-feed';
    // Skeleton loading state for activity feed (replaced once SSE connects)
    var actSkeleton = mk('div', '');
    actSkeleton.id = 'activity-skeleton';
    actSkeleton.innerHTML = renderSkeletonActivityFeed(5);
    actBody.appendChild(actSkeleton);
    var emptyAct = mk('div', 'empty-state');
    emptyAct.id = 'activity-empty';
    emptyAct.style.display = 'none';
    var emptyIcon = mk('div', 'empty-state-icon');
    emptyIcon.innerHTML = SG.icon('activity', 32);
    emptyAct.appendChild(emptyIcon);
    var emptyDesc = mk('p', 'empty-state-description');
    emptyDesc.textContent = 'Waiting for activity\u2026';
    emptyAct.appendChild(emptyDesc);
    actBody.appendChild(emptyAct);
    actWrap.appendChild(actBody);
    actCard.appendChild(actWrap);
    panels.appendChild(actCard);

    root.appendChild(panels);

    // BUG-4 FIX: Active Sessions card — container was never created in DOM,
    // so renderActiveSessions() could not find it and returned silently.
    var sessCard = mk('div', 'card dash-enter dash-enter-8', { style: 'margin-top: var(--space-6)' });
    var sessHeader = mk('div', 'card-header');
    var sessTitle = mk('span', 'card-title');
    sessTitle.innerHTML = SG.icon('users', 16) + ' ';
    sessTitle.appendChild(document.createTextNode('Active Sessions'));
    sessHeader.appendChild(sessTitle);
    var sessBadge = mk('span', 'badge badge-neutral');
    sessBadge.id = 'active-session-count';
    sessBadge.textContent = '0';
    sessHeader.appendChild(sessBadge);
    sessCard.appendChild(sessHeader);
    var sessWrap = mk('div', 'dash-scroll-wrap');
    var sessBody = mk('div', 'card-body dash-scroll');
    sessBody.id = 'active-sessions-container';
    sessWrap.appendChild(sessBody);
    sessCard.appendChild(sessWrap);
    root.appendChild(sessCard);

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
    value.setAttribute('data-animate', '');
    // Show skeleton shimmer until first data arrives
    value.appendChild(mk('div', 'skeleton skeleton-value'));
    content.appendChild(value);

    var iconWrap = mk('div', 'stat-card-icon');
    iconWrap.innerHTML = SG.icon(cfg.icon, 22);

    card.appendChild(content);
    card.appendChild(iconWrap);
    return card;
  }

  // -- Next-step banner (4.2, replaces UX-07 sessionStorage approach) ----------

  var lastBannerMsg = null; // Track last rendered message to avoid DOM thrashing

  /**
   * Renders the next-step banner based on real state from cached data.
   * Shows only ONE banner: the first missing step in sequence.
   * Skips re-render if the message hasn't changed (prevents flickering).
   */
  function updateNextStepBanner() {
    var container = document.getElementById('nextstep-banner-container');
    if (!container) return;
    // Yield to onboarding banner or wait for first upstream poll to resolve
    if (document.getElementById('onboarding-banner')) return;
    if (!upstreamsLoaded) return;

    var hasServers = cachedLastStats && cachedLastStats.upstreams > 0;
    var hasRules = cachedPolicies && cachedPolicies.length > 0;
    var hasIdentity = cachedIdentities && cachedIdentities.length > 0;
    var hasKey = cachedKeys && cachedKeys.length > 0;

    // If everything is truly done (all steps complete), hide the banner
    if (hasServers && hasRules && hasIdentity && hasKey) {
      if (lastBannerMsg !== null) {
        container.innerHTML = '';
        lastBannerMsg = null;
      }
      return;
    }

    var msg = null;
    var href = null;

    if (!hasServers) {
      msg = 'Connect an MCP server in Tools & Rules to get started.';
      href = '#/tools';
    } else if (!hasIdentity) {
      msg = 'Server connected! Next: create an identity and connect your agent.';
      href = '#/access';
    } else if (!hasKey) {
      msg = 'Identity ready! Next: generate an API key for this identity.';
      href = '#/access';
    } else if (!hasRules) {
      msg = 'Agent connected! Next: create security rules to control which tools are allowed.';
      href = '#/tools?tab=rules';
    }

    // Skip re-render if message hasn't changed
    if (msg === lastBannerMsg) return;
    lastBannerMsg = msg;

    // Build the banner
    container.innerHTML = '';
    var banner = mk('div', 'nextstep-realtime-banner info-box info-box-tip');

    var iconWrap = mk('span', '', { style: 'flex-shrink:0;color:var(--accent);margin-top:2px;' });
    iconWrap.innerHTML = SG.icon('compass', 20);
    banner.appendChild(iconWrap);

    var body = mk('span', '', { style: 'flex:1;font-size:var(--text-sm);color:var(--text-primary);line-height:1.5;' });
    body.appendChild(document.createTextNode(msg + ' '));
    if (href) {
      var link = mk('a', '', { href: href });
      link.textContent = 'Go \u2192';
      body.appendChild(link);
    }
    banner.appendChild(body);

    container.appendChild(banner);
  }

  // -- Data: Stats (DASH-01, DASH-06) -----------------------------------------

  function loadStats(opts) {
    SG.api.get('/stats', opts).then(function (data) {
      if (!data) return;
      cachedLastStats = data;

      // First load: replace skeleton grid with real stat cards
      if (!statCardsBuilt) {
        var grid = document.getElementById('stat-cards');
        if (grid) {
          grid.innerHTML = '';
          var cardDefs = [
            { icon: 'activity',    label: 'Requests',  id: 'stat-requests',  tint: 'stat-icon-accent' },
            { icon: 'checkCircle', label: 'Allowed',   id: 'stat-allowed',   tint: 'stat-icon-success' },
            { icon: 'xCircle',     label: 'Denied',    id: 'stat-denied',    tint: 'stat-icon-danger' },
            { icon: 'shield',      label: 'Blocked',   id: 'stat-blocked',   tint: 'stat-icon-blocked' },
            { icon: 'alertTriangle', label: 'Warned',    id: 'stat-warned',    tint: 'stat-icon-warning' },
            { icon: 'alertTriangle', label: 'Errors',    id: 'stat-errors',    tint: 'stat-icon-warning' }
          ];
          for (var c = 0; c < cardDefs.length; c++) {
            grid.appendChild(buildStatCard(cardDefs[c]));
          }
        }
        statCardsBuilt = true;
      }

      var totalRequests = (data.allowed || 0) + (data.denied || 0) + (data.blocked || 0) + (data.warned || 0) + (data.errors || 0);
      updateStatValue('stat-requests', totalRequests);
      updateStatValue('stat-allowed', data.allowed);
      updateStatValue('stat-denied', data.denied);
      updateStatValue('stat-blocked', data.blocked || 0);
      updateStatValue('stat-warned', data.warned || 0);
      updateStatValue('stat-errors', data.errors || 0);

      // Sidebar upstream count sync
      var countEl = document.getElementById('upstream-count');
      if (countEl && data.upstreams != null) {
        var n = Number(data.upstreams) || 0;
        countEl.textContent = n + ' server' + (n !== 1 ? 's' : '');
      }

      // Refresh dependent widgets (4.1, 4.2) on each stats poll
      renderPostureWidget();
      updateNextStepBanner();
      updateHealthIndicator();
    }).catch(function () {
      // Non-fatal -- cards retain last values, next poll retries
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
      // Count-up animation when value actually changes (not on first load)
      var numVal = parseInt(strVal.replace(/,/g, ''), 10);
      if (prevVal !== undefined && prevVal !== strVal && !isNaN(numVal)) {
        animateValue(node, numVal);
      } else {
        node.textContent = strVal;
      }
      previousStats[id] = strVal;
    }
  }

  // -- Health Indicator (3.1) ---------------------------------------------------

  function updateHealthIndicator() {
    var dot = document.getElementById('health-indicator');
    if (!dot || !cachedLastStats) return;
    var stats = cachedLastStats;
    var total = (stats.allowed || 0) + (stats.denied || 0) + (stats.warned || 0) + (stats.errors || 0);
    var errorRate = total > 0 ? ((stats.errors || 0) / total) * 100 : 0;
    var allDisconnected = false, anyDisconnected = false;
    if (cachedUpstreams && cachedUpstreams.length > 0) {
      var connected = cachedUpstreams.filter(function(u) {
        var s = String(u.status || '').toLowerCase();
        return s === 'connected' || s === 'running';
      }).length;
      allDisconnected = connected === 0;
      anyDisconnected = connected < cachedUpstreams.length;
    }
    var level, title;
    if (allDisconnected || errorRate > 20) {
      level = 'health-red';
      title = allDisconnected ? 'All servers disconnected' : 'Error rate: ' + errorRate.toFixed(0) + '%';
    } else if (anyDisconnected || errorRate >= 5) {
      level = 'health-yellow';
      title = anyDisconnected ? 'Some servers disconnected' : 'Error rate: ' + errorRate.toFixed(0) + '%';
    } else {
      level = 'health-green';
      title = 'All systems healthy';
    }
    dot.className = 'health-dot ' + level;
    dot.title = title;
  }

  // -- Data: Protocol/Framework Distribution (UI-01, UI-02) -------------------

  var PROTOCOL_COLORS = {
    mcp: 'dist-bar-mcp',
    http: 'dist-bar-http',
    websocket: 'dist-bar-websocket'
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
    var fwColors = ['dist-bar-mcp', 'dist-bar-http', 'dist-bar-websocket', 'dist-bar-default'];

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

  // -- Data: Active Sessions (DASH-07) ----------------------------------------

  function loadActiveSessions(opts) {
    SG.api.get('/v1/sessions/active', opts).then(function (sessions) {
      if (!sessions) sessions = [];
      renderActiveSessions(sessions);
      previousSessions = sessions;
    }).catch(function () {
      // Non-fatal -- sessions widget retains last state
    });
  }

  function loadQuotaConfigs() {
    SG.api.get('/v1/quotas').then(function (quotas) {
      cachedQuotas = {};
      if (quotas && Array.isArray(quotas)) {
        for (var i = 0; i < quotas.length; i++) {
          if (quotas[i].identity_id) {
            cachedQuotas[quotas[i].identity_id] = quotas[i];
          }
        }
      }
    }).catch(function () {
      // Non-fatal
    });
  }

  function renderActiveSessions(sessions) {
    var container = document.getElementById('active-sessions-container');
    if (!container) return;

    // Update count badge
    var countBadge = document.getElementById('active-session-count');
    if (countBadge) {
      countBadge.textContent = String(sessions.length);
    }

    // Empty state
    var emptyEl = document.getElementById('sessions-empty');
    if (sessions.length === 0) {
      container.innerHTML = '';
      var empty = mk('div', 'dist-empty-state');
      empty.id = 'sessions-empty';
      empty.textContent = 'No active sessions';
      container.appendChild(empty);
      return;
    }

    // Remove empty state if present
    if (emptyEl) {
      emptyEl.style.display = 'none';
    }

    // Build session cards
    container.innerHTML = '';
    var grid = mk('div', 'sessions-grid');

    for (var i = 0; i < sessions.length; i++) {
      var sess = sessions[i];
      grid.appendChild(buildSessionCard(sess));
    }

    container.appendChild(grid);
  }

  function buildSessionCard(sess) {
    var card = mk('div', 'session-card');

    // Header: identity name + session ID
    var header = mk('div', 'session-card-header');
    var identityName = mk('span', 'session-identity');
    identityName.textContent = sess.identity_name || 'Anonymous';
    header.appendChild(identityName);

    var sessIdSpan = mk('span', 'session-id', {
      title: sess.session_id || ''
    });
    sessIdSpan.textContent = (sess.session_id || '').substring(0, 8);
    header.appendChild(sessIdSpan);
    card.appendChild(header);

    // Stats row
    var statsRow = mk('div', 'session-stats-row');

    var statItems = [
      { label: 'Total', value: sess.total_calls },
      { label: 'Reads', value: sess.read_calls },
      { label: 'Writes', value: sess.write_calls },
      { label: 'Deletes', value: sess.delete_calls }
    ];

    for (var s = 0; s < statItems.length; s++) {
      var statItem = mk('span', 'session-stat-item');
      statItem.innerHTML = statItems[s].label + ': <strong>' + (statItems[s].value || 0) + '</strong>';
      statsRow.appendChild(statItem);
    }
    card.appendChild(statsRow);

    // Progress bars (only if quota is configured for this identity)
    var quota = cachedQuotas[sess.identity_id];
    if (quota && quota.enabled) {
      if (quota.max_calls_per_session > 0) {
        card.appendChild(buildProgressBar('Calls', sess.total_calls || 0, quota.max_calls_per_session));
      }
      if (quota.max_writes_per_session > 0) {
        card.appendChild(buildProgressBar('Writes', sess.write_calls || 0, quota.max_writes_per_session));
      }
      if (quota.max_deletes_per_session > 0) {
        card.appendChild(buildProgressBar('Deletes', sess.delete_calls || 0, quota.max_deletes_per_session));
      }
      if (quota.max_calls_per_minute > 0) {
        card.appendChild(buildProgressBar('Rate', sess.window_calls || 0, quota.max_calls_per_minute, '/min'));
      }
    }

    // Meta: duration + last activity
    var meta = mk('div', 'session-meta');

    if (sess.started_at) {
      var durationSpan = mk('span', '');
      var startedTime = new Date(sess.started_at).getTime();
      var durationMs = Date.now() - startedTime;
      var durationMin = Math.max(0, Math.floor(durationMs / 60000));
      durationSpan.textContent = 'Active for ' + formatDuration(durationMin);
      meta.appendChild(durationSpan);
    }

    if (sess.last_call_at) {
      var lastSpan = mk('span', '');
      lastSpan.textContent = formatRelativeTime(sess.last_call_at);
      meta.appendChild(lastSpan);
    }

    card.appendChild(meta);

    return card;
  }

  function buildProgressBar(label, current, max, suffix) {
    var wrapper = mk('div', 'session-progress');

    var labelRow = mk('div', 'session-progress-label');
    var labelText = mk('span', '');
    labelText.textContent = label;
    labelRow.appendChild(labelText);
    var valueText = mk('span', '');
    valueText.textContent = current + '/' + max + (suffix || '');
    labelRow.appendChild(valueText);
    wrapper.appendChild(labelRow);

    var track = mk('div', 'session-progress-track');
    var pct = max > 0 ? (current / max) * 100 : 0;
    var barPct = Math.min(pct, 100);

    var barCls = 'session-progress-bar ';
    if (pct > 100) {
      barCls += 'session-progress-overflow';
    } else if (pct > 80) {
      barCls += 'session-progress-red';
    } else if (pct > 60) {
      barCls += 'session-progress-yellow';
    } else {
      barCls += 'session-progress-green';
    }

    var bar = mk('div', barCls);
    bar.style.width = barPct + '%';
    track.appendChild(bar);
    wrapper.appendChild(track);

    return wrapper;
  }

  // -- Data: Upstreams (DASH-03, DASH-04) -------------------------------------

  function loadUpstreams(opts) {
    SG.api.get('/upstreams', opts).then(function (data) {
      cachedUpstreams = data;
      upstreamsLoaded = true;

      // Onboarding banner: show when no servers, hide when servers exist
      var bannerContainer = document.getElementById('nextstep-banner-container');
      if (!data || !Array.isArray(data) || data.length === 0) {
        // Show onboarding banner — dashboard stays visible with counters at zero
        if (bannerContainer && !document.getElementById('onboarding-banner')) {
          renderOnboardingBanner(bannerContainer);
        }
      } else {
        // Servers exist — remove onboarding banner
        if (bannerContainer) {
          var existingBanner = document.getElementById('onboarding-banner');
          if (existingBanner) existingBanner.remove();
        }
      }

      var container = document.getElementById('upstream-list');
      if (!container) return;

      // Diff-based update: only touch DOM elements that changed.
      // On first render (no existing list), build from scratch.
      var existingList = container.querySelector('.upstream-list');
      if (!existingList) {
        // First render — build everything
        container.innerHTML = '';
        var list = mk('div', 'upstream-list');
        for (var i = 0; i < data.length; i++) {
          list.appendChild(buildUpstreamItem(data[i]));
        }
        container.appendChild(list);
      } else {
        // Subsequent renders — diff in place
        var newIds = {};
        for (var j = 0; j < data.length; j++) {
          var u = data[j];
          var uid = u.id || u.name || '';
          newIds[uid] = true;
          var existing = existingList.querySelector('[data-upstream-id="' + uid + '"]');
          if (existing) {
            // Update status and tool count in place (no DOM rebuild)
            var statusCls = resolveStatusClass(u.status);
            var statusEl = existing.querySelector('.upstream-status');
            if (statusEl) {
              var prevCls = statusEl.getAttribute('data-status-cls');
              if (prevCls !== statusCls) {
                statusEl.className = 'upstream-status ' + statusCls;
                statusEl.setAttribute('data-status-cls', statusCls);
                var dot = statusEl.querySelector('.status-dot');
                if (dot) dot.className = 'status-dot ' + statusCls;
                var label = statusEl.querySelector('.text-xs');
                if (label) label.textContent = statusText(statusCls);
              }
            }
            var metaEl = existing.querySelector('[data-upstream-meta]');
            if (metaEl) {
              var tc = (u.tool_count != null) ? u.tool_count : 0;
              var newText = tc + ' tool' + (tc !== 1 ? 's' : '');
              if (metaEl.textContent !== newText) metaEl.textContent = newText;
            }
          } else {
            // New upstream — append
            existingList.appendChild(buildUpstreamItem(u));
          }
        }
        // Remove upstreams no longer in data
        var items = existingList.querySelectorAll('[data-upstream-id]');
        for (var k = 0; k < items.length; k++) {
          if (!newIds[items[k].getAttribute('data-upstream-id')]) {
            items[k].remove();
          }
        }
      }
      updateHealthIndicator();
    }).catch(function () {
      // Non-fatal -- upstream list retains last state
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

  // Build a single upstream item DOM element (used by both first render and diff).
  function buildUpstreamItem(u) {
    var uid = u.id || u.name || '';
    var item = mk('div', 'upstream-item upstream-item-link');
    item.setAttribute('data-upstream-id', uid);

    (function (upstreamId) {
      item.addEventListener('click', function () {
        window.location.hash = '#/tools?upstream=' + encodeURIComponent(upstreamId);
      });
    })(uid);

    var info = mk('div', '', { style: 'flex:1;min-width:0;' });
    var name = mk('div', 'upstream-name');
    name.textContent = u.name || u.id || 'Unknown';
    info.appendChild(name);

    var meta = mk('div', '', { style: 'font-size:var(--text-xs);color:var(--text-muted);' });
    meta.setAttribute('data-upstream-meta', '');
    var toolCount = (u.tool_count != null) ? u.tool_count : 0;
    meta.textContent = toolCount + ' tool' + (toolCount !== 1 ? 's' : '');
    info.appendChild(meta);

    var statusCls = resolveStatusClass(u.status);
    var status = mk('div', 'upstream-status ' + statusCls);
    status.setAttribute('data-status-cls', statusCls);
    status.appendChild(mk('span', 'status-dot ' + statusCls));
    var statusLabel = mk('span', 'text-xs');
    statusLabel.textContent = statusText(statusCls);
    status.appendChild(statusLabel);

    item.appendChild(info);
    item.appendChild(status);

    var delBtn = mk('button', 'upstream-delete-btn', { title: 'Remove upstream' });
    delBtn.setAttribute('aria-label', 'Remove upstream ' + (u.name || u.id || 'server'));
    delBtn.innerHTML = SG.icon('xCircle', 16);
    (function (upstream) {
      delBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        var uName = upstream.name || upstream.id || 'Unknown';
        var uId = upstream.id || upstream.name || '';
        SG.modal.confirm({
          title: 'Remove Upstream',
          message: 'Remove "' + uName + '" and all its tools? This cannot be undone.',
          confirmText: 'Remove',
          confirmClass: 'btn-danger',
          onConfirm: function () {
            SG.api.del('/upstreams/' + uId).then(function () {
              SG.toast.success('Upstream "' + uName + '" removed');
              loadUpstreams();
            }).catch(function (err) {
              SG.toast.error('Remove failed: ' + (err.message || 'Unknown error'));
            });
          }
        });
      });
    })(u);
    item.appendChild(delBtn);

    return item;
  }

  // -- SSE: Activity Feed (DASH-02, DASH-05) ----------------------------------

  function startSSE() {
    if (typeof EventSource === 'undefined') return;

    eventSource = new EventSource(SG.api.BASE + '/audit/stream');

    eventSource.onopen = function () {
      var indicator = document.getElementById('live-indicator');
      if (indicator) indicator.classList.remove('inactive');
      // Remove activity skeleton on SSE connect, show empty state if no entries
      var actSkeleton = document.getElementById('activity-skeleton');
      if (actSkeleton) actSkeleton.remove();
      var emptyEl = document.getElementById('activity-empty');
      if (emptyEl && activityEntries.length === 0) {
        emptyEl.style.display = '';
      }
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

    // Remove activity skeleton if still present
    var actSkeleton = document.getElementById('activity-skeleton');
    if (actSkeleton) actSkeleton.remove();

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

    // Build entries via DOM (XSS-safe -- all user text via textContent)
    var list = mk('div', 'upstream-list');

    for (var i = 0; i < activityEntries.length; i++) {
      var entry = activityEntries[i];

      var item = mk('div', 'upstream-item');
      // Slide-in animation on the newest entry
      if (hasNewEntry && i === 0) {
        item.classList.add('activity-entry-new');
      }

      var info = mk('div', '', { style: 'flex:1;min-width:0;' });

      // Plain English description (4.4)
      var descDiv = mk('div', 'upstream-name');
      descDiv.appendChild(formatActivityPlainEnglish(entry));
      info.appendChild(descDiv);

      var meta = mk('div', '', { style: 'font-size:var(--text-xs);color:var(--text-muted);' });
      meta.textContent = formatRelativeTime(entry.timestamp);
      info.appendChild(meta);

      // Decision badge
      var decision = String(entry.decision || '').toLowerCase();
      var badgeCls = 'badge-neutral';
      var badgeText = decision || 'unknown';
      if (decision === 'allow' || decision === 'allowed') {
        badgeCls = 'badge-success'; badgeText = 'Allow';
      } else if (decision === 'blocked') {
        badgeCls = 'badge-danger'; badgeText = 'Blocked';
      } else if (decision === 'deny' || decision === 'denied') {
        badgeCls = 'badge-danger'; badgeText = 'Deny';
      } else if (decision === 'warn') {
        badgeCls = 'badge-warning'; badgeText = 'Warn';
      } else if (decision === 'rate_limited' || decision === 'ratelimited') {
        badgeCls = 'badge-warning'; badgeText = 'Rate Limited';
      }

      var badgeWrap = mk('div', '', { style: 'display:flex;gap:var(--space-1);align-items:center;flex-shrink:0;' });
      var badge = mk('span', 'badge ' + badgeCls);
      badge.textContent = badgeText;
      badgeWrap.appendChild(badge);

      // Transform badge (2.6)
      if (entry.transform_count && entry.transform_count > 0) {
        var tfBadge = mk('span', 'badge badge-info');
        tfBadge.textContent = 'Transformed';
        badgeWrap.appendChild(tfBadge);
      }

      // Scan detections badge — distinguish Allow-with-detection from clean Allow
      if (entry.scan_detections && entry.scan_detections > 0) {
        var scanBadge = mk('span', 'badge badge-scan');
        scanBadge.textContent = entry.scan_detections + ' detection' + (entry.scan_detections > 1 ? 's' : '');
        scanBadge.title = entry.scan_types || '';
        badgeWrap.appendChild(scanBadge);
      }

      item.appendChild(info);
      item.appendChild(badgeWrap);
      list.appendChild(item);
    }

    feedEl.insertBefore(list, feedEl.firstChild);
  }

  // -- Plain English activity formatter (4.4) ---------------------------------

  /**
   * Returns a DocumentFragment describing an activity entry in plain English.
   * L-8: Uses DOM APIs instead of innerHTML for defense in depth.
   */
  function formatActivityPlainEnglish(entry) {
    var identity = entry.identity_name || entry.identity_id || entry.identity || 'anonymous';
    var tool = entry.tool_name || entry.tool || 'unknown';
    var decision = String(entry.decision || '').toLowerCase();

    var frag = document.createDocumentFragment();
    function addStrong(text) {
      var s = document.createElement('strong');
      s.textContent = text;
      frag.appendChild(s);
    }
    function addText(text) {
      frag.appendChild(document.createTextNode(text));
    }

    if (decision === 'allow' || decision === 'allowed') {
      addStrong(identity); addText(' used '); addStrong(tool); addText(' \u2014 allowed');
    } else if (decision === 'blocked') {
      addStrong(identity); addText(' tried '); addStrong(tool); addText(' \u2014 quota blocked');
    } else if (decision === 'deny' || decision === 'denied') {
      addStrong(identity); addText(' tried '); addStrong(tool); addText(' \u2014 denied by policy');
      if (entry.rule_id) {
        addText(' by rule \u2018'); addStrong(entry.rule_id); addText('\u2019');
      }
    } else if (decision === 'warn') {
      addStrong(identity); addText(' used '); addStrong(tool); addText(' \u2014 quota warning');
    } else if (decision === 'rate_limited' || decision === 'ratelimited') {
      addStrong(identity); addText(' tried '); addStrong(tool); addText(' \u2014 rate limited');
    } else {
      addStrong(identity); addText(' called '); addStrong(tool);
    }

    if (entry.transform_count && entry.transform_count > 0) {
      addText(' (' + entry.transform_count + ' transform' + (entry.transform_count > 1 ? 's' : '') + ' applied)');
    }

    return frag;
  }

  // -- Duration formatter ------------------------------------------------------

  function formatDuration(minutes) {
    if (minutes < 60) return minutes + 'm';
    var h = Math.floor(minutes / 60);
    var m = minutes % 60;
    if (h < 24) return h + 'h ' + m + 'm';
    var d = Math.floor(h / 24);
    var rh = h % 24;
    return d + 'd ' + rh + 'h';
  }

  // -- Relative time formatter ------------------------------------------------

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

  // -- Supplementary data (4.1, 4.2, 4.3) ------------------------------------

  /**
   * Fetches policies, identities, keys, and transforms for the posture widget,
   * next-step banners, and insights. Called once on page load and every 30s.
   */
  function loadSupplementaryData(opts) {
    Promise.all([
      SG.api.get('/policies', opts).catch(function () { return []; }),
      SG.api.get('/identities', opts).catch(function () { return []; }),
      SG.api.get('/keys', opts).catch(function () { return []; }),
      SG.api.get('/v1/transforms', opts).catch(function () { return []; }),
      SG.api.get('/v1/security/content-scanning', opts).catch(function() { return null; }),
      SG.api.get('/v1/drift/config', opts).catch(function() { return null; }),
      SG.api.get('/v1/recordings/config').catch(function() { return null; })
    ]).then(function (results) {
      cachedPolicies = results[0] || [];
      cachedIdentities = results[1] || [];
      cachedKeys = results[2] || [];
      cachedTransforms = results[3] || [];
      cachedContentScan = results[4] || null;
      cachedDriftConfig = results[5] || null;
      cachedRecordingConfig = results[6] || null;
      // Re-render dependent widgets
      renderPostureWidget();
      updateNextStepBanner();
    });
  }

  // -- Security Score widget (4.1) ------------------------------------------

  function renderPostureWidget() {
    var body = document.getElementById('posture-body');
    if (!body) return;

    var stats = cachedLastStats;
    if (!stats) return;

    // === Zero state: no upstreams, no policies, no identities → score is 0 ===
    var hasUpstreams = stats.upstreams > 0;
    var hasAnyPolicies = cachedPolicies && cachedPolicies.length > 0;
    var hasAnyIdentities = cachedIdentities && cachedIdentities.length > 0;
    if (!hasUpstreams && !hasAnyPolicies && !hasAnyIdentities) {
      body.innerHTML = '';
      var scoreRow = mk('div', '', { style: 'display:flex;align-items:center;gap:var(--space-3);' });
      var scoreLabel = mk('span', 'posture-score');
      scoreLabel.textContent = '0/100';
      scoreLabel.style.color = 'var(--danger)';
      scoreRow.appendChild(scoreLabel);
      var trackWrap = mk('div', '', { style: 'flex:1;' });
      var track = mk('div', 'posture-bar-track');
      var bar = mk('div', 'posture-bar');
      bar.style.width = '0%';
      bar.style.background = 'var(--danger)';
      track.appendChild(bar);
      trackWrap.appendChild(track);
      scoreRow.appendChild(trackWrap);
      body.appendChild(scoreRow);

      var hint = mk('div', '', { style: 'font-size:var(--text-sm);color:var(--text-muted);margin-top:var(--space-2);' });
      hint.textContent = 'Connect a server and configure policies to improve your security score.';
      body.appendChild(hint);
      return;
    }

    // === A. Tool Coverage (max 30 points) ===
    var totalTools = stats.tools || 0;
    var toolsWithRule = 0;
    if (totalTools > 0 && cachedPolicies) {
      var patterns = [];
      for (var p = 0; p < cachedPolicies.length; p++) {
        var pRules = cachedPolicies[p].rules || [];
        for (var r = 0; r < pRules.length; r++) {
          patterns.push(pRules[r].tool_match || '');
        }
      }
      var hasWildcardRule = patterns.indexOf('*') >= 0;
      if (hasWildcardRule) {
        toolsWithRule = totalTools;
      } else {
        var uniquePatterns = {};
        for (var i = 0; i < patterns.length; i++) {
          if (patterns[i] && patterns[i] !== '*') uniquePatterns[patterns[i]] = true;
        }
        toolsWithRule = Math.min(Object.keys(uniquePatterns).length, totalTools);
      }
    }
    var toolCoverage = totalTools > 0 ? Math.round((toolsWithRule / totalTools) * 30) : 0;
    var uncoveredTools = totalTools - toolsWithRule;

    // === B. Policy Quality (max 25 points) ===
    // Note: hasAnyPolicies is defined above (line ~1714) and reused here.
    var hasWildcardAllow = false;
    var hasDefaultDeny = false;
    var hasIdentityAware = false;
    var lowestPriority = Infinity;

    if (hasAnyPolicies) {
      for (var p = 0; p < cachedPolicies.length; p++) {
        var pRules = cachedPolicies[p].rules || [];
        for (var r = 0; r < pRules.length; r++) {
          var rule = pRules[r];
          var tm = rule.tool_match || '';
          var action = (rule.action || '').toLowerCase();
          var prio = rule.priority || 0;

          if (tm === '*' && action === 'allow') {
            if (!rule.condition || rule.condition.trim() === '') {
              hasWildcardAllow = true;
            }
          }
          if (tm === '*' && action === 'deny' && prio <= lowestPriority) {
            hasDefaultDeny = true;
            lowestPriority = prio;
          }
          if (rule.condition && (rule.condition.indexOf('identity_name') >= 0 || rule.condition.indexOf('identity_id') >= 0 || rule.condition.indexOf('identity_roles') >= 0)) {
            hasIdentityAware = true;
          }
        }
      }
    }

    var policyQuality = 0;
    if (hasAnyPolicies && !hasWildcardAllow) policyQuality += 10;
    if (hasDefaultDeny) policyQuality += 10;
    if (hasIdentityAware) policyQuality += 5;

    // === C. Content Protection (max 20 points) ===
    var hasContentScan = cachedContentScan && cachedContentScan.enabled === true && hasUpstreams;
    var hasTransformsActive = cachedTransforms && cachedTransforms.length > 0;
    var hasRateLimiting = false;
    if (cachedIdentities) {
      for (var i = 0; i < cachedIdentities.length; i++) {
        if (cachedIdentities[i].rate_limit && cachedIdentities[i].rate_limit > 0) {
          hasRateLimiting = true;
          break;
        }
      }
    }

    var contentProtection = 0;
    if (hasContentScan) contentProtection += 10;
    if (hasTransformsActive) contentProtection += 5;
    if (hasRateLimiting) contentProtection += 5;

    // === D. Monitoring (max 15 points) ===
    // Drift detection: backend returns { configured: true/false, config: {...} }.
    // Only award points when the service is actively running (configured=true) and there are upstreams.
    var hasDriftDetection = cachedDriftConfig && cachedDriftConfig.configured === true && hasUpstreams;
    // Recording: has explicit 'enabled' field.
    var hasRecording = cachedRecordingConfig && cachedRecordingConfig.enabled === true;
    var monitoring = 0;
    if (hasDriftDetection) monitoring += 8;
    if (hasRecording) monitoring += 7;

    // === E. Risk Penalties ===
    // Only penalize uncovered tools when policies exist (no penalty if user hasn't created rules yet).
    var penalties = 0;
    if (hasAnyPolicies && uncoveredTools > 0) penalties -= Math.min(uncoveredTools * 2, 10);
    if (hasWildcardAllow) penalties -= 15;

    // === Final score ===
    var rawScore = Math.max(0, Math.min(100, toolCoverage + policyQuality + contentProtection + monitoring + penalties));

    // Policies and identities are prerequisites — without them, features like
    // content scanning or drift detection don't provide meaningful security.
    var score;
    if (!hasAnyPolicies && !hasAnyIdentities) {
      score = hasUpstreams ? 5 : 0;
    } else {
      score = rawScore;
    }

    // === Suggestions ===
    var suggestions = [];
    // Prerequisite suggestions — these explain why the score is capped
    if (!hasAnyPolicies) {
      suggestions.push({ text: 'Create access policies to enforce which tools identities can call', link: '#/tools' });
    }
    if (!hasAnyIdentities) {
      suggestions.push({ text: 'Create identities to authenticate and authorize MCP clients', link: '#/access' });
    }
    if (toolCoverage < 30) {
      suggestions.push({ text: 'Cover more tools with rules (' + uncoveredTools + ' of ' + totalTools + ' unprotected)', link: '#/tools' });
    }
    if (!hasDefaultDeny) {
      suggestions.push({ text: 'Add a default-deny rule to block unprotected tools', link: '#/tools' });
    }
    if (hasWildcardAllow) {
      suggestions.push({ text: 'Your wildcard Allow rule permits all tools \u2014 add identity conditions or remove it', link: '#/tools' });
    }
    if (!hasContentScan) {
      suggestions.push({ text: 'Enable content scanning to detect sensitive data in tool responses', link: '#/security' });
    }
    if (!hasRateLimiting) {
      suggestions.push({ text: 'Enable rate limiting to prevent abuse', link: '#/access' });
    }
    if (!hasDriftDetection) {
      suggestions.push({ text: 'Enable tool integrity checking to detect tool poisoning', link: '#/security' });
    }
    if (!hasRecording) {
      suggestions.push({ text: 'Enable session recording for audit trail', link: '#/sessions' });
    }

    // Render
    body.innerHTML = '';

    // Score + bar row
    var scoreRow = mk('div', '', { style: 'display:flex;align-items:center;gap:var(--space-3);' });
    var scoreLabel = mk('span', 'posture-score');
    scoreLabel.textContent = score + '/100';

    var barColor;
    if (score < 30) { barColor = 'var(--danger)'; }
    else if (score <= 60) { barColor = 'var(--warning)'; }
    else { barColor = 'var(--success)'; }

    scoreLabel.style.color = barColor;
    scoreRow.appendChild(scoreLabel);

    var trackWrap = mk('div', '', { style: 'flex:1;' });
    var track = mk('div', 'posture-bar-track');
    var bar = mk('div', 'posture-bar');
    bar.style.width = score + '%';
    bar.style.background = barColor;
    track.appendChild(bar);
    trackWrap.appendChild(track);
    scoreRow.appendChild(trackWrap);
    body.appendChild(scoreRow);

    // Suggestions (collapsible)
    if (suggestions.length > 0) {
      var toggleBtn = mk('button', 'posture-toggle');
      toggleBtn.setAttribute('aria-label', 'Toggle security suggestions');
      toggleBtn.setAttribute('aria-expanded', String(postureExpanded));
      toggleBtn.innerHTML = SG.icon(postureExpanded ? 'chevronUp' : 'chevronDown', 14) + ' ';
      toggleBtn.appendChild(document.createTextNode(suggestions.length + ' suggestion' + (suggestions.length > 1 ? 's' : '')));
      body.appendChild(toggleBtn);

      var sugList = mk('div', 'posture-suggestions' + (postureExpanded ? '' : ' collapsed'));
      for (var s = 0; s < suggestions.length; s++) {
        var sug = mk('a', 'posture-suggestion', { href: suggestions[s].link, style: 'display:block;text-decoration:none;color:inherit;cursor:pointer;' });
        sug.textContent = suggestions[s].text;
        sugList.appendChild(sug);
      }
      body.appendChild(sugList);

      toggleBtn.addEventListener('click', function () {
        postureExpanded = !postureExpanded;
        sugList.classList.toggle('collapsed');
        toggleBtn.setAttribute('aria-expanded', String(postureExpanded));
        toggleBtn.innerHTML = SG.icon(postureExpanded ? 'chevronUp' : 'chevronDown', 14) + ' ';
        toggleBtn.appendChild(document.createTextNode(suggestions.length + ' suggestion' + (suggestions.length > 1 ? 's' : '')));
      });
    }
  }

  // -- Actionable Insights widget (4.3) ---------------------------------------

  function renderInsightsWidget() {
    var body = document.getElementById('insights-body');
    if (!body) return;

    var stats = cachedLastStats;
    if (!stats) {
      body.innerHTML = '';
      var loading = mk('div', 'dist-empty-state');
      loading.textContent = 'Waiting for data\u2026';
      body.appendChild(loading);
      return;
    }

    body.innerHTML = '';
    var messages = [];

    // Denied count
    if (stats.denied > 0) {
      messages.push(stats.denied + ' tool call' + (stats.denied > 1 ? 's' : '') + ' blocked today.');
    }

    // Warned count
    if (stats.warned > 0) {
      messages.push(stats.warned + ' quota warning' + (stats.warned > 1 ? 's' : '') + ' today.');
    }

    // No rules configured
    var policies = cachedPolicies || [];
    if (policies.length === 0) {
      messages.push('No custom rules configured. The default policy allows all tool calls. Add rules in Tools & Rules to restrict access.');
    }

    // Servers and tools
    var servers = stats.upstreams || 0;
    var tools = stats.tools || 0;
    messages.push(servers + ' MCP server' + (servers !== 1 ? 's' : '') + ' connected, ' + tools + ' tool' + (tools !== 1 ? 's' : '') + ' available.');

    // Rate limiting
    if (stats.rate_limited > 0) {
      messages.push('Rate limiting triggered ' + stats.rate_limited + ' time' + (stats.rate_limited > 1 ? 's' : '') + ' today.');
    }

    if (messages.length === 0) {
      var empty = mk('div', 'dist-empty-state');
      empty.textContent = 'No insights yet';
      body.appendChild(empty);
      return;
    }

    for (var i = 0; i < messages.length; i++) {
      var item = mk('div', 'insight-item');
      item.textContent = messages[i];
      body.appendChild(item);
    }
  }

  // -- Lifecycle --------------------------------------------------------------

  function render(container) {
    cleanup();
    injectStyles();
    buildDashboard(container);

    // Kick off data loading
    loadStats();
    loadUpstreams();
    loadQuotaConfigs();
    loadSupplementaryData();
    loadActiveSessions(); // BUG-4 FIX: initial load for active sessions widget
    startSSE();

    // UX-13: check scroll overflow after initial data loads
    setTimeout(checkScrollOverflow, 1000);

    // Start polling (DASH-06) — silent to avoid progress bar flicker
    var bg = { silent: true };
    statsInterval = setInterval(function () {
      loadStats(bg);
      checkScrollOverflow();
    }, 2000);
    upstreamInterval = setInterval(function () {
      loadUpstreams(bg);
    }, 5000);
    // BUG-4 FIX: poll active sessions every 2s (matches stats frequency)
    sessionsInterval = setInterval(function () {
      loadActiveSessions(bg);
    }, 2000);
    // Refresh supplementary data every 30s (not on every 2s stats poll)
    supplementaryInterval = setInterval(function () {
      loadSupplementaryData(bg);
    }, 30000);
  }

  function cleanup() {
    if (statsInterval) { clearInterval(statsInterval); statsInterval = null; }
    if (upstreamInterval) { clearInterval(upstreamInterval); upstreamInterval = null; }
    if (sessionsInterval) { clearInterval(sessionsInterval); sessionsInterval = null; }
    if (supplementaryInterval) { clearInterval(supplementaryInterval); supplementaryInterval = null; }
    if (eventSource) { eventSource.close(); eventSource = null; }
    activityEntries = [];
    previousStats = {};
    cachedQuotas = {};
    previousSessions = [];
    cachedPolicies = null;
    cachedIdentities = null;
    cachedKeys = null;
    cachedTransforms = null;
    cachedContentScan = null;
    cachedDriftConfig = null;
    cachedRecordingConfig = null;
    cachedLastStats = null;
    cachedUpstreams = null;
    postureExpanded = false;
    statCardsBuilt = false;
    upstreamsLoaded = false;
    // Remove onboarding banner if present
    var onboardBanner = document.getElementById('onboarding-banner');
    if (onboardBanner) onboardBanner.remove();
    lastBannerMsg = null;
  }

  // UX-13 FIX: detect scroll overflow and toggle fade indicator
  function checkScrollOverflow() {
    var scrollEls = document.querySelectorAll('.dash-scroll');
    scrollEls.forEach(function(el) {
      var wrap = el.closest('.dash-scroll-wrap');
      if (!wrap) return;
      if (el.scrollHeight > el.clientHeight + 8) {
        wrap.classList.add('has-overflow');
      } else {
        wrap.classList.remove('has-overflow');
      }
    });
  }

  // -- Registration -----------------------------------------------------------

  SG.router.register('dashboard', render);
  SG.router.registerCleanup('dashboard', cleanup);
})();
