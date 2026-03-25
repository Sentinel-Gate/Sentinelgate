/**
 * keyboard.js — Global keyboard shortcuts for SentinelGate admin UI.
 *
 * Two-key combos (g then d = go to dashboard) and single-key actions.
 * Automatically disabled when focus is in an input/textarea/contenteditable.
 */
'use strict';

window.SG = window.SG || {};

(function () {
  var pendingPrefix = null;
  var prefixTimer = null;
  var COMBO_TIMEOUT = 800;

  // -- Shortcut definitions ---------------------------------------------------

  var GO_COMBOS = {
    'd': '#/dashboard',
    't': '#/tools',
    'a': '#/access',
    'l': '#/audit',
    's': '#/sessions',
    'n': '#/notifications',
    'c': '#/compliance',
    'p': '#/permissions',
    'x': '#/security',
    'r': '#/redteam',
    'f': '#/finops',
    'i': '#/agents',
  };

  var NEW_ACTIONS = {
    'tools':  '[data-action="add-upstream"]',
    'access': '[data-action="add-identity"]',
  };

  // -- Helpers ----------------------------------------------------------------

  function isInputFocused() {
    var el = document.activeElement;
    if (!el) return false;
    var tag = el.tagName.toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select') return true;
    if (el.isContentEditable) return true;
    if (el.closest('.modal') || el.closest('.cmd-palette')) return true;
    return false;
  }

  function clearPrefix() {
    pendingPrefix = null;
    if (prefixTimer) {
      clearTimeout(prefixTimer);
      prefixTimer = null;
    }
  }

  // -- Shortcut overlay (? key) -----------------------------------------------

  var overlayEl = null;

  var SHORTCUT_CSS = [
    '.shortcuts-overlay-backdrop{position:fixed;inset:0;z-index:9400;background:rgba(0,0,0,.5);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;opacity:0;transition:opacity 150ms ease}',
    '.shortcuts-overlay-backdrop.active{opacity:1}',
    '.shortcuts-overlay{background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius-xl);padding:var(--space-6);width:480px;max-height:80vh;overflow-y:auto;box-shadow:0 24px 48px rgba(0,0,0,.4)}',
    '.shortcuts-overlay h2{font-size:var(--text-lg);font-weight:var(--font-semibold);color:var(--text-primary);margin:0 0 var(--space-4)}',
    '.shortcuts-section{margin-bottom:var(--space-5)}',
    '.shortcuts-section h3{font-size:var(--text-xs);font-weight:var(--font-semibold);color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin:0 0 var(--space-2)}',
    '.shortcut-row{display:flex;align-items:center;justify-content:space-between;padding:var(--space-1) 0}',
    '.shortcut-row span:first-child{font-size:var(--text-sm);color:var(--text-secondary)}',
    '.shortcut-keys{display:flex;gap:var(--space-1)}',
    '.shortcut-keys kbd{background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:2px 8px;font-size:var(--text-xs);font-family:var(--font-mono);color:var(--text-primary);min-width:24px;text-align:center}'
  ].join('\n');

  function showShortcutsOverlay() {
    if (overlayEl) {
      closeShortcutsOverlay();
      return;
    }

    if (!document.querySelector('style[data-shortcuts]')) {
      var s = document.createElement('style');
      s.setAttribute('data-shortcuts', '');
      s.textContent = SHORTCUT_CSS;
      document.head.appendChild(s);
    }

    overlayEl = document.createElement('div');
    overlayEl.className = 'shortcuts-overlay-backdrop';
    overlayEl.addEventListener('click', function (e) {
      if (e.target === overlayEl) closeShortcutsOverlay();
    });

    var content = document.createElement('div');
    content.className = 'shortcuts-overlay';

    // L-34: Build overlay with DOM methods to avoid innerHTML with shortcutRow
    var h2 = document.createElement('h2');
    h2.textContent = 'Keyboard Shortcuts';
    content.appendChild(h2);

    function makeSection(title, rows) {
      var sec = document.createElement('div');
      sec.className = 'shortcuts-section';
      var h3 = document.createElement('h3');
      h3.textContent = title;
      sec.appendChild(h3);
      rows.forEach(function (r) { sec.appendChild(r); });
      return sec;
    }

    content.appendChild(makeSection('Navigation', [
      shortcutRow('Go to Dashboard', ['G', 'D']),
      shortcutRow('Go to Servers & Rules', ['G', 'T']),
      shortcutRow('Go to Connections', ['G', 'A']),
      shortcutRow('Go to Activity', ['G', 'L']),
      shortcutRow('Go to Sessions', ['G', 'S']),
      shortcutRow('Go to Notifications', ['G', 'N'])
    ]));

    content.appendChild(makeSection('Actions', [
      shortcutRow('Command palette', ['\u2318', 'K']),
      shortcutRow('New item (context-aware)', ['N']),
      shortcutRow('Focus search', ['/']),
      shortcutRow('Show shortcuts', ['?'])
    ]));

    content.appendChild(makeSection('General', [
      shortcutRow('Close modal/overlay', ['Esc'])
    ]));

    overlayEl.appendChild(content);
    document.body.appendChild(overlayEl);

    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        overlayEl.classList.add('active');
      });
    });
  }

  function shortcutRow(label, keys) {
    // L-34: Build DOM elements instead of innerHTML to avoid latent XSS
    var row = document.createElement('div');
    row.className = 'shortcut-row';
    var labelSpan = document.createElement('span');
    labelSpan.textContent = label;
    row.appendChild(labelSpan);
    var keysDiv = document.createElement('div');
    keysDiv.className = 'shortcut-keys';
    keys.forEach(function (k) {
      var kbd = document.createElement('kbd');
      kbd.textContent = k;
      keysDiv.appendChild(kbd);
    });
    row.appendChild(keysDiv);
    return row;
  }

  function closeShortcutsOverlay() {
    if (!overlayEl) return;
    overlayEl.classList.remove('active');
    var el = overlayEl;
    overlayEl = null;
    setTimeout(function () {
      if (el.parentNode) el.parentNode.removeChild(el);
    }, 150);
  }

  // -- Main handler -----------------------------------------------------------

  document.addEventListener('keydown', function (e) {
    if (isInputFocused()) return;
    if (e.ctrlKey || e.metaKey || e.altKey) return;

    var key = e.key.toLowerCase();

    // Handle pending two-key combo
    if (pendingPrefix === 'g') {
      clearPrefix();
      if (GO_COMBOS[key]) {
        e.preventDefault();
        window.location.hash = GO_COMBOS[key];
        return;
      }
    }

    // Start "g" combo
    if (key === 'g') {
      e.preventDefault();
      pendingPrefix = 'g';
      prefixTimer = setTimeout(clearPrefix, COMBO_TIMEOUT);
      return;
    }

    // ? — show shortcut overlay
    if (e.key === '?' || (e.shiftKey && key === '/')) {
      e.preventDefault();
      showShortcutsOverlay();
      return;
    }

    // / — focus search
    if (key === '/') {
      var searchInput = document.querySelector('.search-input, [data-search], input[type="search"]');
      if (searchInput) {
        e.preventDefault();
        searchInput.focus();
      }
      return;
    }

    // n — context-aware "new"
    if (key === 'n') {
      var page = SG.router.currentPage;
      var selector = NEW_ACTIONS[page];
      if (selector) {
        var btn = document.querySelector(selector);
        if (btn) {
          e.preventDefault();
          btn.click();
        }
      }
      return;
    }

    // Esc — close shortcuts overlay
    if (key === 'escape') {
      if (overlayEl) {
        closeShortcutsOverlay();
      }
    }
  });
})();
