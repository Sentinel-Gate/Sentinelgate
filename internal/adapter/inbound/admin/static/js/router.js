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

    /** Pending transition timer ID (M-8: cleared on rapid navigation) */
    _transitionTimer: null,

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
     * Navigate to a hash route with smooth page transition.
     *
     * @param {string} hash - Full hash string (e.g. '#/dashboard')
     */
    reload: function () {
      var page = this.currentPage;
      this.currentPage = null;
      this.navigate('#/' + (page || 'dashboard'));
    },

    navigate: function (hash) {
      // Parse page name from hash: '#/dashboard' -> 'dashboard', '#/tools' -> 'tools'
      var raw = (hash || '').replace(/^#\/?/, '');
      var page = raw.split(/[?\/]/)[0] || 'dashboard';

      // Always update sidebar active state (even if only query params changed)
      this.updateNav(page);

      // Skip re-rendering if already on this page
      if (page === this.currentPage) {
        return;
      }

      // M-8: Cancel any pending transition timeout from a previous rapid navigation
      // to prevent resource leaks (stale page render) and double-cleanup.
      if (this._transitionTimer) {
        clearTimeout(this._transitionTimer);
        this._transitionTimer = null;
        // Clean up exit animation class left by the cancelled transition
        this.contentEl.classList.remove('page-transition-exit');
      }

      // Run cleanup for the page we're leaving
      if (this.currentPage && this.cleanups[this.currentPage]) {
        try {
          this.cleanups[this.currentPage]();
        } catch (e) {
          // Cleanup errors should not block navigation
        }
      }

      // M-8: Update currentPage synchronously so the same-page guard works
      // during rapid navigation (A -> B -> C within 120ms).
      this.currentPage = page;

      var self = this;
      var contentEl = this.contentEl;

      // If there's existing content, fade it out first
      if (contentEl.children.length > 0) {
        contentEl.classList.add('page-transition-exit');

        this._transitionTimer = setTimeout(function () {
          self._transitionTimer = null;
          contentEl.classList.remove('page-transition-exit');
          // M1: Guard against stale render — if another navigation occurred
          // during the 120ms exit animation, skip this render.
          if (self.currentPage !== page) return;
          contentEl.innerHTML = '';
          self._renderPage(page, contentEl);
        }, 120); // match exit animation duration
      } else {
        // First load — no exit animation needed
        contentEl.innerHTML = '';
        this._renderPage(page, contentEl);
      }
    },

    /**
     * Render a page and trigger entrance animation.
     * @private
     */
    _renderPage: function (page, contentEl) {
      var renderFn = this.routes[page];
      if (renderFn) {
        try {
          renderFn(contentEl);
        } catch (e) {
          var errDiv = document.createElement('div');
          errDiv.style.cssText = 'padding: 2rem; color: var(--danger);';
          var errH2 = document.createElement('h2');
          errH2.textContent = 'Page Error';
          var errP = document.createElement('p');
          errP.textContent = e.message || 'Unknown error';
          errDiv.appendChild(errH2);
          errDiv.appendChild(errP);
          contentEl.innerHTML = '';
          contentEl.appendChild(errDiv);
        }
      } else {
        var notFoundDiv = document.createElement('div');
        notFoundDiv.style.cssText = 'padding: 4rem; text-align: center; color: var(--text-muted);';
        var p1 = document.createElement('p');
        p1.style.fontSize = 'var(--text-lg)';
        p1.textContent = 'Page not found';
        var p2 = document.createElement('p');
        p2.style.marginTop = 'var(--space-2)';
        p2.textContent = 'No handler registered for "' + page + '"';
        notFoundDiv.appendChild(p1);
        notFoundDiv.appendChild(p2);
        contentEl.innerHTML = '';
        contentEl.appendChild(notFoundDiv);
      }

      // Trigger entrance animation
      // L-29: Skip animation if user prefers reduced motion
      if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        // No animation — don't add the class at all
      } else {
        contentEl.classList.add('page-transition-enter');
        contentEl.addEventListener('animationend', function handler() {
          contentEl.classList.remove('page-transition-enter');
          contentEl.removeEventListener('animationend', handler);
        });
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
