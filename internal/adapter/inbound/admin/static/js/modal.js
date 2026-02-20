/**
 * modal.js -- Modal dialog system for SentinelGate admin UI.
 *
 * Provides modals with backdrop blur overlay, scale-up animation,
 * and multiple close triggers (ESC key, backdrop click, X button).
 * Only one modal can be open at a time.
 *
 * Usage:
 *   // General modal
 *   var body = SG.modal.open({
 *     title: 'Add Upstream',
 *     body: formElement,       // string or HTMLElement
 *     footer: buttonsElement,  // string or HTMLElement
 *     width: '600px',          // optional, default 520px via CSS
 *     onClose: function() {}   // optional callback
 *   });
 *
 *   // Confirmation dialog
 *   SG.modal.confirm({
 *     title: 'Delete upstream?',
 *     message: 'This action cannot be undone.',
 *     confirmText: 'Delete',
 *     confirmClass: 'btn-danger',
 *     onConfirm: function() { ... },
 *     onCancel: function() { ... }
 *   });
 *
 *   SG.modal.close();
 *   SG.modal.isOpen();
 *
 * Security: Title text is set via textContent (XSS-safe).
 * Animation: Double requestAnimationFrame ensures scale-up transition
 *            fires reliably after DOM insertion.
 */
window.SG = window.SG || {};

SG.modal = {
  /** Reference to the active backdrop element, or null. */
  backdrop: null,

  /** Reference to the active modal element, or null. */
  currentModal: null,

  /** Stored ESC key handler so it can be removed on close. */
  _escHandler: null,

  /** Stored onClose callback for the current modal. */
  _onClose: null,

  /**
   * Open a modal dialog.
   *
   * @param {Object} options
   * @param {string}              options.title   Modal heading (set via textContent).
   * @param {string|HTMLElement}  options.body    Content for the modal body.
   * @param {string|HTMLElement}  [options.footer] Content for the modal footer.
   * @param {Function}            [options.onClose] Called after the modal closes.
   * @param {string}              [options.width]  CSS max-width override.
   * @returns {HTMLElement}       The modal body element for programmatic updates.
   */
  open: function (options) {
    options = options || {};

    // Single modal: close any existing modal first
    if (this.backdrop) {
      this.close();
    }

    var self = this;
    this._onClose = options.onClose || null;

    // ── Build backdrop ───────────────────────────────────────────────
    var backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop';

    // Close on backdrop click (not on modal content click)
    backdrop.addEventListener('click', function (e) {
      if (e.target === backdrop) {
        self.close();
      }
    });

    // ── Build modal container ────────────────────────────────────────
    var modal = document.createElement('div');
    modal.className = 'modal';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');

    if (options.width) {
      modal.style.maxWidth = options.width;
    }

    // ── Header ───────────────────────────────────────────────────────
    var header = document.createElement('div');
    header.className = 'modal-header';

    var title = document.createElement('h3');
    title.className = 'modal-title';
    // XSS-safe: use textContent for user-provided title
    title.textContent = options.title || '';
    header.appendChild(title);

    var closeBtn = document.createElement('button');
    closeBtn.className = 'modal-close';
    closeBtn.setAttribute('aria-label', 'Close dialog');
    if (typeof SG.icon === 'function') {
      closeBtn.innerHTML = SG.icon('x', 18);
    } else {
      closeBtn.textContent = '\u00D7';
    }
    closeBtn.addEventListener('click', function () {
      self.close();
    });
    header.appendChild(closeBtn);

    modal.appendChild(header);

    // ── Body ─────────────────────────────────────────────────────────
    var body = document.createElement('div');
    body.className = 'modal-body';

    if (options.body) {
      if (typeof options.body === 'string') {
        body.innerHTML = options.body;
      } else if (options.body instanceof HTMLElement) {
        body.appendChild(options.body);
      }
    }

    modal.appendChild(body);

    // ── Footer (optional) ────────────────────────────────────────────
    if (options.footer) {
      var footer = document.createElement('div');
      footer.className = 'modal-footer';

      if (typeof options.footer === 'string') {
        footer.innerHTML = options.footer;
      } else if (options.footer instanceof HTMLElement) {
        footer.appendChild(options.footer);
      }

      modal.appendChild(footer);
    }

    // ── Assemble and insert ──────────────────────────────────────────
    backdrop.appendChild(modal);
    document.body.appendChild(backdrop);

    // Store references
    this.backdrop = backdrop;
    this.currentModal = modal;

    // ── Lock body scroll ─────────────────────────────────────────────
    document.body.style.overflow = 'hidden';

    // ── ESC key handler ──────────────────────────────────────────────
    this._escHandler = function (e) {
      if (e.key === 'Escape') {
        self.close();
      }
    };
    document.addEventListener('keydown', this._escHandler);

    // ── Animate in: double rAF ensures the browser has rendered the
    //    element at its initial state (opacity 0, scale 0.95) before
    //    adding the active class, so the CSS transition fires. ────────
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        backdrop.classList.add('active');
      });
    });

    // ── Focus the modal for accessibility ────────────────────────────
    modal.setAttribute('tabindex', '-1');
    modal.focus();

    // Return body element so callers can append or update content
    return body;
  },

  /**
   * Close the currently open modal with animation.
   */
  close: function () {
    if (!this.backdrop) return;

    var backdrop = this.backdrop;
    var onClose = this._onClose;

    // Remove ESC handler
    if (this._escHandler) {
      document.removeEventListener('keydown', this._escHandler);
      this._escHandler = null;
    }

    // Animate out
    backdrop.classList.remove('active');

    // Clear references before timeout fires
    this.backdrop = null;
    this.currentModal = null;
    this._onClose = null;

    // Restore body scroll
    document.body.style.overflow = '';

    // Remove from DOM after CSS transition completes (200ms base)
    setTimeout(function () {
      if (backdrop.parentNode) {
        backdrop.parentNode.removeChild(backdrop);
      }
    }, 200);

    // Call onClose callback
    if (typeof onClose === 'function') {
      onClose();
    }
  },

  /**
   * Show a confirmation dialog with Cancel and Confirm buttons.
   *
   * @param {Object} options
   * @param {string}   options.title        Dialog heading.
   * @param {string}   options.message      Confirmation message.
   * @param {string}   [options.confirmText] Button label (default: 'Confirm').
   * @param {string}   [options.confirmClass] Button CSS class (default: 'btn-primary').
   * @param {Function} [options.onConfirm]  Called when user confirms.
   * @param {Function} [options.onCancel]   Called when user cancels.
   */
  confirm: function (options) {
    options = options || {};

    var self = this;
    var confirmText = options.confirmText || 'Confirm';
    var confirmClass = options.confirmClass || 'btn-primary';

    // Build message element
    var msgEl = document.createElement('p');
    msgEl.textContent = options.message || '';
    msgEl.style.color = 'var(--text-secondary)';
    msgEl.style.lineHeight = '1.6';

    // Build footer with Cancel + Confirm buttons
    var footerEl = document.createElement('div');
    footerEl.style.display = 'contents';

    var cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-secondary';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', function () {
      self.close();
      if (typeof options.onCancel === 'function') {
        options.onCancel();
      }
    });

    var confirmBtn = document.createElement('button');
    confirmBtn.className = 'btn ' + confirmClass;
    confirmBtn.textContent = confirmText;
    confirmBtn.addEventListener('click', function () {
      self.close();
      if (typeof options.onConfirm === 'function') {
        options.onConfirm();
      }
    });

    footerEl.appendChild(cancelBtn);
    footerEl.appendChild(confirmBtn);

    this.open({
      title: options.title || 'Confirm',
      body: msgEl,
      footer: footerEl,
      onClose: options.onCancel || null,
    });
  },

  /**
   * Check whether a modal is currently open.
   *
   * @returns {boolean}
   */
  isOpen: function () {
    return this.backdrop !== null;
  },
};
