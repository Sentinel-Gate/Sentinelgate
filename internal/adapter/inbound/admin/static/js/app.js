/**
 * app.js — Application entry point for SentinelGate admin UI.
 *
 * Loaded last (after icons.js, api.js, toast.js, modal.js, router.js,
 * and all page scripts). Registers placeholder pages for features not
 * yet implemented, then initializes the router.
 *
 * Architecture:
 *   - No ES modules — global SG namespace via classic script tags
 *   - Pages self-register via SG.router.register() in their own files
 *   - This file registers placeholders for pages without dedicated files yet
 *   - Router restores hash from sessionStorage on init (if set)
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // ── Sidebar search trigger (moved from inline script for CSP compliance)
  var trigger = document.getElementById('sidebar-search-trigger');
  if (trigger) trigger.addEventListener('click', function() {
    if (SG.commandPalette) SG.commandPalette.open();
  });

  // ── Placeholder page renderer ────────────────────────────────────

  /**
   * Create a placeholder renderer for a page coming in a future phase.
   *
   * @param {string} title    - Page title
   * @param {string} iconName - SG.icons key
   * @param {string} phase    - Which phase will implement this
   * @returns {Function} Render function for SG.router.register
   */
  function placeholder(title, iconName, phase) {
    return function (container) {
      container.innerHTML = '';
      var wrap = document.createElement('div');
      wrap.style.cssText = 'display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:60vh;color:var(--text-muted)';
      var iconDiv = document.createElement('div');
      iconDiv.style.cssText = 'opacity:0.4;margin-bottom:var(--space-4)';
      if (SG.icon) iconDiv.innerHTML = SG.icon(iconName, 48);
      wrap.appendChild(iconDiv);
      var h2 = document.createElement('h2');
      h2.style.cssText = 'font-size:var(--text-xl);color:var(--text-secondary);margin-bottom:var(--space-2)';
      h2.textContent = title;
      wrap.appendChild(h2);
      var p = document.createElement('p');
      p.style.cssText = 'font-size:var(--text-sm)';
      p.textContent = 'Coming in ' + phase;
      wrap.appendChild(p);
      container.appendChild(wrap);
    };
  }

  // ── Register placeholder pages ───────────────────────────────────
  // Pages with dedicated JS files (e.g. dashboard.js) register themselves.
  // These placeholders cover pages not yet built.

  if (!SG.router.routes['tools']) {
    SG.router.register('tools', placeholder('Tools & Rules', 'wrench', 'a future release'));
  }

  if (!SG.router.routes['access']) {
    SG.router.register('access', placeholder('Connections', 'key', 'a future release'));
  }

  if (!SG.router.routes['audit']) {
    SG.router.register('audit', placeholder('Activity', 'scrollText', 'a future release'));
  }

  // ── Initialize on DOM ready ──────────────────────────────────────

  document.addEventListener('DOMContentLoaded', function () {
    // Start the router (handles initial navigation + hashchange)
    SG.router.init();

    // Check for first-boot onboarding (no upstreams configured)
    // L-30: capture page at fetch time to avoid stale redirect
    var onboardingCheckPage = SG.router.currentPage;
    SG.api.get('/upstreams').then(function (upstreams) {
      if (upstreams && upstreams.length === 0) {
        var currentPage = SG.router.currentPage;
        // Only redirect if user hasn't navigated away since the check started
        if ((currentPage === onboardingCheckPage) && (currentPage === 'dashboard' || !currentPage)) {
          window.location.hash = '#/onboarding';
        }
      }
    }).catch(function () { /* ignore — upstreams may not be reachable yet */ });

    // Fetch system info for sidebar version display (non-fatal)
    SG.api.get('/system').then(function (data) {
      if (data && data.version) {
        var versionEl = document.querySelector('.sidebar-version');
        if (versionEl) {
          versionEl.textContent = 'v' + data.version;
        }
      }
    }).catch(function () {
      // Non-fatal — sidebar keeps showing server-rendered version
    });

    // Fetch upstreams for sidebar count display (non-fatal)
    function refreshSidebarUpstreams() {
      SG.api.get('/upstreams').then(function (data) {
        if (data && Array.isArray(data)) {
          var countEl = document.getElementById('upstream-count');
          if (countEl) {
            var n = data.length;
            countEl.textContent = n + ' server' + (n !== 1 ? 's' : '');
          }
        }
      }).catch(function () {});
    }
    refreshSidebarUpstreams();
    SG.refreshSidebarUpstreams = refreshSidebarUpstreams;

    // M-33: named function so it can be removed if needed
    var onHashChangeRefresh = function () {
      refreshSidebarUpstreams();
    };
    window.addEventListener('hashchange', onHashChangeRefresh);
  });
})();
