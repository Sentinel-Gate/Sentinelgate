/**
 * toast.js -- Toast notification system for SentinelGate admin UI.
 *
 * Provides slide-in toast notifications anchored to the top-right corner.
 * Maximum 3 visible at once, auto-dismiss after 4 seconds, 4 types.
 *
 * Usage:
 *   SG.toast.success('Upstream created');
 *   SG.toast.error('Failed to save policy');
 *   SG.toast.warning('Rate limit approaching');
 *   SG.toast.info('Discovery in progress');
 *   SG.toast.show('Custom message', 'success');
 *
 * Security: All user-provided text is set via textContent (XSS-safe).
 * Animation: Double requestAnimationFrame ensures CSS transitions trigger
 *            reliably after DOM insertion.
 */
window.SG = window.SG || {};

SG.toast = {
  /** Maximum number of toasts visible simultaneously. */
  MAX_VISIBLE: 3,

  /** Time in ms before a toast auto-dismisses. */
  AUTO_DISMISS_MS: 4000,

  /** Duration in ms for the slide-in / slide-out CSS transition. */
  ANIMATION_MS: 300,

  /** Cached reference to the toast container element. */
  _container: null,

  /**
   * Lazy-initialise: find (or warn about) the toast container.
   * The container is expected in the HTML as:
   *   <div id="toast-container" class="toast-container"></div>
   */
  init: function () {
    if (!this._container) {
      this._container = document.getElementById('toast-container');
    }
    return this._container;
  },

  /**
   * Show a toast notification.
   *
   * @param {string} message  Text to display (set via textContent, XSS-safe).
   * @param {string} type     One of 'success', 'error', 'warning', 'info'.
   */
  show: function (message, type) {
    var container = this.init();
    if (!container) return;

    type = type || 'info';

    // ── Enforce MAX_VISIBLE: remove oldest when at capacity ──────────
    var existing = container.querySelectorAll('.toast');
    while (existing.length >= this.MAX_VISIBLE) {
      var oldest = existing[0];
      if (oldest._sgTimer) {
        clearTimeout(oldest._sgTimer);
        oldest._sgTimer = null;
      }
      if (oldest.parentNode) {
        oldest.parentNode.removeChild(oldest);
      }
      existing = container.querySelectorAll('.toast');
    }

    // ── Build toast DOM ──────────────────────────────────────────────
    var toast = document.createElement('div');
    toast.className = 'toast toast-' + type;

    // Icon
    var iconEl = document.createElement('span');
    iconEl.className = 'toast-icon';
    var iconName = this._iconFor(type);
    if (typeof SG.icon === 'function') {
      iconEl.innerHTML = SG.icon(iconName, 18);
    }
    toast.appendChild(iconEl);

    // Message (XSS-safe: textContent, never innerHTML)
    var msgEl = document.createElement('span');
    msgEl.className = 'toast-message';
    msgEl.textContent = message;
    toast.appendChild(msgEl);

    // Close button
    var closeBtn = document.createElement('button');
    closeBtn.className = 'toast-close';
    closeBtn.setAttribute('aria-label', 'Close notification');
    if (typeof SG.icon === 'function') {
      closeBtn.innerHTML = SG.icon('x', 14);
    } else {
      closeBtn.textContent = '\u00D7';
    }
    var self = this;
    closeBtn.addEventListener('click', function () {
      self._dismiss(toast);
    });
    toast.appendChild(closeBtn);

    // ── Insert into DOM ──────────────────────────────────────────────
    container.appendChild(toast);

    // ── Double rAF: ensures the browser has rendered the element at
    //    its initial state (translateX(120%), opacity 0) before we add
    //    the visible class, so the CSS transition actually fires. ─────
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        toast.classList.add('toast-visible');
      });
    });

    // ── Auto-dismiss after AUTO_DISMISS_MS ───────────────────────────
    var timerId = setTimeout(function () {
      self._dismiss(toast);
    }, this.AUTO_DISMISS_MS);

    // Store timer so manual close can cancel it
    toast._sgTimer = timerId;
  },

  /**
   * Dismiss a toast with slide-out animation, then remove from DOM.
   *
   * @param {HTMLElement} toast  The toast element to remove.
   */
  _dismiss: function (toast) {
    if (!toast || !toast.parentNode) return;

    // Cancel any pending auto-dismiss timer
    if (toast._sgTimer) {
      clearTimeout(toast._sgTimer);
      toast._sgTimer = null;
    }

    // Trigger slide-out by removing the visible class
    toast.classList.remove('toast-visible');

    // Remove from DOM after the CSS transition completes
    var animMs = this.ANIMATION_MS;
    setTimeout(function () {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, animMs);
  },

  /**
   * Map toast type to an icon name from SG.icons.
   *
   * @param {string} type  One of 'success', 'error', 'warning', 'info'.
   * @returns {string}     Icon name for SG.icon().
   */
  _iconFor: function (type) {
    switch (type) {
      case 'success': return 'checkCircle';
      case 'error':   return 'xCircle';
      case 'warning': return 'alertTriangle';
      case 'info':    return 'info';
      default:        return 'info';
    }
  },

  // ── Convenience methods ──────────────────────────────────────────────

  /** Show a success toast (green). */
  success: function (msg) { this.show(msg, 'success'); },

  /** Show an error toast (red). */
  error: function (msg) { this.show(msg, 'error'); },

  /** Show a warning toast (yellow). */
  warning: function (msg) { this.show(msg, 'warning'); },

  /** Show an info toast (blue). */
  info: function (msg) { this.show(msg, 'info'); },
};
