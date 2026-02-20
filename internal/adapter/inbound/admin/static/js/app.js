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
      var iconSvg = SG.icon ? SG.icon(iconName, 48) : '';
      container.innerHTML =
        '<div style="display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 60vh; color: var(--text-muted);">' +
          '<div style="opacity: 0.4; margin-bottom: var(--space-4);">' + iconSvg + '</div>' +
          '<h2 style="font-size: var(--text-xl); color: var(--text-secondary); margin-bottom: var(--space-2);">' + title + '</h2>' +
          '<p style="font-size: var(--text-sm);">Coming in ' + phase + '</p>' +
        '</div>';
    };
  }

  // ── Register placeholder pages ───────────────────────────────────
  // Pages with dedicated JS files (e.g. dashboard.js) register themselves.
  // These placeholders cover pages not yet built.

  if (!SG.router.routes['tools']) {
    SG.router.register('tools', placeholder('Tools & Rules', 'wrench', 'Phase 4'));
  }

  if (!SG.router.routes['access']) {
    SG.router.register('access', placeholder('Access Management', 'key', 'Phase 5'));
  }

  if (!SG.router.routes['audit']) {
    SG.router.register('audit', placeholder('Audit Log', 'scrollText', 'Phase 6'));
  }

  // ── Initialize on DOM ready ──────────────────────────────────────

  document.addEventListener('DOMContentLoaded', function () {
    // Start the router (handles initial navigation + hashchange)
    SG.router.init();

    // Check for first-boot onboarding (no upstreams configured)
    if (SG.onboarding && SG.onboarding.checkAndShow) {
      SG.api.get('/upstreams').then(function (upstreams) {
        if (upstreams && upstreams.length === 0) {
          // If on dashboard (or no page), show onboarding instead
          var page = SG.router.currentPage;
          if (page === 'dashboard' || !page) {
            var container = document.getElementById('page-content');
            if (container) {
              container.innerHTML = '';
              SG.onboarding.render(container);
            }
          }
        }
      }).catch(function () { /* ignore — upstreams may not be reachable yet */ });
    }

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
    SG.api.get('/upstreams').then(function (data) {
      if (data && Array.isArray(data)) {
        var countEl = document.getElementById('upstream-count');
        if (countEl) {
          var n = data.length;
          countEl.textContent = n + ' upstream' + (n !== 1 ? 's' : '');
        }
      }
    }).catch(function () {
      // Non-fatal — sidebar keeps showing "0 upstreams"
    });
  });
})();
