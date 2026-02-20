/**
 * router.js — Hash-based SPA router for SentinelGate admin UI.
 *
 * Pages register themselves via SG.router.register(hash, renderFn).
 * The router listens for hashchange events, calls cleanup for the
 * leaving page, clears the content area, and calls the new page's
 * render function.
 *
 * Navigation is instant — no page reload, no network request.
 *
 * Usage:
 *   SG.router.register('dashboard', function(container) { ... });
 *   SG.router.registerCleanup('dashboard', function() { ... });
 *   SG.router.init(); // called once on DOMContentLoaded
 */
'use strict';

window.SG = window.SG || {};

(function () {
  SG.router = {
    /** Registered page renderers: { pageName: renderFn } */
    routes: {},

    /** Registered cleanup functions: { pageName: cleanupFn } */
    cleanups: {},

    /** Currently active page name (null before first navigation) */
    currentPage: null,

    /** Cached reference to #page-content element */
    contentEl: null,

    /**
     * Register a page renderer.
     *
     * @param {string} page       - Page name matching data-page attribute (e.g. 'dashboard')
     * @param {Function} renderFn - Called with (containerElement) when navigating to this page
     */
    register: function (page, renderFn) {
      this.routes[page] = renderFn;
    },

    /**
     * Register a cleanup function called when navigating AWAY from a page.
     * Use this to clear intervals, remove event listeners, abort fetches, etc.
     *
     * @param {string} page     - Page name
     * @param {Function} cleanupFn - Called with no arguments when leaving the page
     */
    registerCleanup: function (page, cleanupFn) {
      this.cleanups[page] = cleanupFn;
    },

    /**
     * Initialize the router. Call once on DOMContentLoaded.
     *
     * 1. Cache the content element
     * 2. Listen for hashchange
     * 3. Navigate to initial hash (or default to #/dashboard)
     */
    init: function () {
      this.contentEl = document.getElementById('page-content');
      if (!this.contentEl) {
        return;
      }

      var self = this;
      window.addEventListener('hashchange', function () {
        self.navigate(window.location.hash);
      });

      // Navigate to current hash or default
      var initialHash = window.location.hash || '#/dashboard';
      if (!initialHash || initialHash === '#' || initialHash === '#/') {
        initialHash = '#/dashboard';
      }

      // Set hash without triggering a double navigation
      if (window.location.hash !== initialHash) {
        window.location.hash = initialHash;
      } else {
        this.navigate(initialHash);
      }
    },

    /**
     * Navigate to a hash route.
     *
     * @param {string} hash - Full hash string (e.g. '#/dashboard')
     */
    navigate: function (hash) {
      // Parse page name from hash: '#/dashboard' -> 'dashboard', '#/tools' -> 'tools'
      var raw = (hash || '').replace(/^#\/?/, '');
      var page = raw.split(/[?\/]/)[0] || 'dashboard';

      // Skip if already on this page
      if (page === this.currentPage) {
        return;
      }

      // Run cleanup for the page we're leaving
      if (this.currentPage && this.cleanups[this.currentPage]) {
        try {
          this.cleanups[this.currentPage]();
        } catch (e) {
          // Cleanup errors should not block navigation
        }
      }

      // Update sidebar active state
      this.updateNav(page);

      // Clear content area
      this.contentEl.innerHTML = '';

      // Track current page
      this.currentPage = page;

      // Call page renderer if registered
      var renderFn = this.routes[page];
      if (renderFn) {
        try {
          renderFn(this.contentEl);
        } catch (e) {
          this.contentEl.innerHTML =
            '<div style="padding: 2rem; color: var(--danger);">' +
            '<h2>Page Error</h2>' +
            '<p>' + (e.message || 'Unknown error') + '</p>' +
            '</div>';
        }
      } else {
        // No renderer registered — show 404-style message
        this.contentEl.innerHTML =
          '<div style="padding: 4rem; text-align: center; color: var(--text-muted);">' +
          '<p style="font-size: var(--text-lg);">Page not found</p>' +
          '<p style="margin-top: var(--space-2);">No handler registered for "' + page + '"</p>' +
          '</div>';
      }
    },

    /**
     * Update sidebar navigation active state.
     *
     * @param {string} activePage - Page name to mark as active
     */
    updateNav: function (activePage) {
      var items = document.querySelectorAll('.nav-item[data-page]');
      for (var i = 0; i < items.length; i++) {
        var item = items[i];
        if (item.getAttribute('data-page') === activePage) {
          item.classList.add('active');
        } else {
          item.classList.remove('active');
        }
      }
    }
  };
})();
