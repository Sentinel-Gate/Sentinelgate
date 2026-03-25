/**
 * command-palette.js — Cmd+K command palette for SentinelGate admin UI.
 *
 * Fuzzy search across pages, servers, tools, rules, and quick actions.
 * Keyboard-driven: arrows to navigate, Enter to select, Esc to close.
 */
'use strict';

window.SG = window.SG || {};

(function () {
  var styleInjected = false;
  var backdropEl = null;
  var inputEl = null;
  var resultsEl = null;
  var selectedIndex = 0;
  var flatItems = [];
  var isTransitioning = false;

  // -- Static commands --------------------------------------------------------

  var PAGES = [
    { label: 'Dashboard',      icon: 'dashboard',     action: function () { window.location.hash = '#/dashboard'; },     shortcut: 'G D', keywords: '' },
    { label: 'Servers & Rules', icon: 'wrench',        action: function () { window.location.hash = '#/tools'; },         shortcut: 'G T', keywords: 'tools rules policies' },
    { label: 'Connections',     icon: 'key',           action: function () { window.location.hash = '#/access'; },        shortcut: 'G A', keywords: 'access identities keys api upstream' },
    { label: 'Activity',        icon: 'scrollText',    action: function () { window.location.hash = '#/audit'; },         shortcut: 'G L', keywords: 'audit log' },
    { label: 'Sessions',       icon: 'target',         action: function () { window.location.hash = '#/sessions'; },      shortcut: 'G S', keywords: 'recordings replay' },
    { label: 'Notifications',  icon: 'bell',           action: function () { window.location.hash = '#/notifications'; }, shortcut: 'G N', keywords: 'alerts approvals' },
    { label: 'Security',       icon: 'shield',         action: function () { window.location.hash = '#/security'; },      shortcut: '',    keywords: 'scanning quarantine drift' },
    { label: 'Compliance',     icon: 'checkSquare',    action: function () { window.location.hash = '#/compliance'; },    shortcut: '',    keywords: 'soc2 packs' },
    { label: 'Access Review',  icon: 'layoutGrid',     action: function () { window.location.hash = '#/permissions'; },   shortcut: '',    keywords: 'permissions health least privilege' },
    { label: 'Red Team',       icon: 'shieldAlert',    action: function () { window.location.hash = '#/redteam'; },       shortcut: '',    keywords: 'attack pentest' },
    { label: 'Cost Tracking',  icon: 'dollarSign',     action: function () { window.location.hash = '#/finops'; },        shortcut: '',    keywords: 'finops budget costs' },
    { label: 'Clients',        icon: 'users',          action: function () { window.location.hash = '#/agents'; },        shortcut: '',    keywords: 'agents connected' },
  ];

  var ACTIONS = [
    { label: 'Add MCP Server',  icon: 'plus',  keywords: 'upstream create', action: function () { if (SG.tools && SG.tools.openAddUpstreamModal) { SG.tools.openAddUpstreamModal(null); } else { window.location.hash = '#/access'; } } },
    { label: 'Create Rule',     icon: 'plus',  keywords: 'policy add', action: function () { window.location.hash = '#/tools'; setTimeout(function () { var btn = document.querySelector('[data-action="add-rule"]'); if (btn) btn.click(); }, 200); } },
    { label: 'Create Identity', icon: 'plus',  keywords: 'user agent add', action: function () { window.location.hash = '#/access'; setTimeout(function () { var btn = document.querySelector('[data-action="add-identity"]'); if (btn) btn.click(); }, 200); } },
    { label: 'Factory Reset',   icon: 'shieldAlert', keywords: 'reset clean wipe fresh virgin restart', action: factoryResetAction },
  ];

  function factoryResetAction() {
    if (!SG.modal) return;
    var content = document.createElement('div');
    content.style.cssText = 'display:flex;flex-direction:column;gap:var(--space-4)';

    var warn = document.createElement('p');
    warn.style.cssText = 'color:var(--danger);font-weight:var(--font-semibold)';
    warn.textContent = 'This will remove ALL data from the running system:';
    content.appendChild(warn);

    var list = document.createElement('ul');
    list.style.cssText = 'margin:0;padding-left:var(--space-5);color:var(--text-secondary);font-size:var(--text-sm);line-height:1.8';
    ['MCP Servers (upstream connections)', 'Policies and rules', 'Identities and API keys', 'Quotas and transforms', 'Active sessions', 'Tool baseline and quarantine', 'Stats and notifications'].forEach(function (t) {
      var li = document.createElement('li');
      li.textContent = t;
      list.appendChild(li);
    });
    content.appendChild(list);

    var note = document.createElement('p');
    note.style.cssText = 'font-size:var(--text-xs);color:var(--text-muted);margin-top:var(--space-2)';
    note.textContent = 'Read-only resources from YAML config will be preserved.';
    content.appendChild(note);

    var footer = document.createElement('div');
    footer.style.cssText = 'display:contents';

    var cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-secondary';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.addEventListener('click', function () { SG.modal.close(); });
    footer.appendChild(cancelBtn);

    var resetBtn = document.createElement('button');
    resetBtn.className = 'btn btn-danger';
    resetBtn.textContent = 'Reset Everything';
    resetBtn.addEventListener('click', function () {
      SG.modal.close();
      SG.api.post('/system/factory-reset', { confirm: true }).then(function (result) {
        var parts = [];
        if (result.upstreams_removed) parts.push(result.upstreams_removed + ' servers');
        if (result.policies_removed) parts.push(result.policies_removed + ' policies');
        if (result.identities_removed) parts.push(result.identities_removed + ' identities');
        if (result.keys_removed) parts.push(result.keys_removed + ' keys');
        if (result.quotas_removed) parts.push(result.quotas_removed + ' quotas');
        if (result.transforms_removed) parts.push(result.transforms_removed + ' transforms');
        if (result.sessions_cleared) parts.push(result.sessions_cleared + ' sessions');
        var msg = parts.length ? 'Removed: ' + parts.join(', ') : 'System is already clean';
        if (SG.toast) SG.toast.success('Factory reset complete. ' + msg);
        setTimeout(function () { window.location.hash = '#/dashboard'; window.location.reload(); }, 800);
      }).catch(function (err) {
        if (SG.toast) SG.toast.error('Factory reset failed: ' + (err.message || err));
      });
    });
    footer.appendChild(resetBtn);

    SG.modal.open({ title: 'Factory Reset', body: content, footer: footer });
  }

  // -- Fuzzy match ------------------------------------------------------------

  function fuzzyMatchText(query, text) {
    var q = query.toLowerCase();
    var t = text.toLowerCase();
    if (!q) return { match: true, score: 0 };
    var qi = 0;
    var score = 0;
    var lastMatchIndex = -1;
    for (var ti = 0; ti < t.length && qi < q.length; ti++) {
      if (t[ti] === q[qi]) {
        score += (ti === lastMatchIndex + 1) ? 2 : 1;
        if (ti === 0 || t[ti - 1] === ' ' || t[ti - 1] === '-') score += 3;
        lastMatchIndex = ti;
        qi++;
      }
    }
    return { match: qi === q.length, score: score };
  }

  function fuzzyMatch(query, text, keywords) {
    var labelResult = fuzzyMatchText(query, text);
    if (!keywords) return labelResult;
    var kwResult = fuzzyMatchText(query, keywords);
    if (labelResult.match && kwResult.match) {
      return labelResult.score >= kwResult.score ? labelResult : kwResult;
    }
    if (labelResult.match) return labelResult;
    if (kwResult.match) return kwResult;
    return labelResult;
  }

  // -- CSS injection ----------------------------------------------------------

  var CMD_PALETTE_CSS = [
    '.cmd-palette-backdrop{position:fixed;inset:0;z-index:9500;background:rgba(0,0,0,.5);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);opacity:0;transition:opacity 150ms ease;display:flex;align-items:flex-start;justify-content:center;padding-top:20vh}',
    '.cmd-palette-backdrop.active{opacity:1}',
    '.cmd-palette{width:560px;max-height:420px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:var(--radius-xl);box-shadow:0 24px 48px rgba(0,0,0,.4),0 0 0 1px rgba(255,255,255,.05);display:flex;flex-direction:column;overflow:hidden;transform:scale(.96) translateY(-8px);transition:transform 150ms ease,opacity 150ms ease;opacity:0}',
    '.cmd-palette-backdrop.active .cmd-palette{transform:scale(1) translateY(0);opacity:1}',
    '.cmd-palette-input-wrap{display:flex;align-items:center;gap:var(--space-3);padding:var(--space-4) var(--space-5);border-bottom:1px solid var(--border)}',
    '.cmd-palette-input-wrap svg{color:var(--text-muted);flex-shrink:0}',
    '.cmd-palette-input{flex:1;font-size:var(--text-base);color:var(--text-primary);background:transparent;border:none;outline:none;font-family:var(--font-sans)}',
    '.cmd-palette-input::placeholder{color:var(--text-muted)}',
    '.cmd-palette-results{flex:1;overflow-y:auto;padding:var(--space-2) 0}',
    '.cmd-palette-group-title{font-size:var(--text-xs);font-weight:var(--font-semibold);color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;padding:var(--space-2) var(--space-5);margin-top:var(--space-1)}',
    '.cmd-palette-item{display:flex;align-items:center;gap:var(--space-3);padding:var(--space-2) var(--space-5);cursor:pointer;transition:background-color 60ms ease}',
    '.cmd-palette-item:hover,.cmd-palette-item.selected{background:var(--bg-surface)}',
    '.cmd-palette-item.selected{background:var(--accent-subtle)}',
    '.cmd-palette-item-icon{width:18px;height:18px;color:var(--text-muted);flex-shrink:0}',
    '.cmd-palette-item.selected .cmd-palette-item-icon{color:var(--accent)}',
    '.cmd-palette-item-label{flex:1;font-size:var(--text-sm);color:var(--text-primary)}',
    '.cmd-palette-item-shortcut{font-size:var(--text-xs);font-family:var(--font-mono);color:var(--text-muted);display:flex;gap:var(--space-1)}',
    '.cmd-palette-item-shortcut kbd{background:var(--bg-surface);border:1px solid var(--border);border-radius:var(--radius-sm);padding:1px 6px;font-size:11px;font-family:var(--font-mono);line-height:1.6}',
    '.cmd-palette-footer{display:flex;align-items:center;justify-content:space-between;padding:var(--space-2) var(--space-5);border-top:1px solid var(--border);font-size:var(--text-xs);color:var(--text-muted)}',
    '.cmd-palette-footer-keys{display:flex;gap:var(--space-4)}',
    '.cmd-palette-footer-keys span{display:flex;align-items:center;gap:var(--space-1)}',
    '.cmd-palette-footer-keys kbd{background:var(--bg-surface);border:1px solid var(--border);border-radius:3px;padding:0 4px;font-size:10px;font-family:var(--font-mono)}',
    '.cmd-palette-empty{padding:var(--space-8) var(--space-5);text-align:center;color:var(--text-muted);font-size:var(--text-sm)}'
  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var css = document.createElement('style');
    css.setAttribute('data-cmd-palette', '');
    css.textContent = CMD_PALETTE_CSS;
    document.head.appendChild(css);
    styleInjected = true;
  }

  // -- DOM construction -------------------------------------------------------

  function buildPalette() {
    backdropEl = document.createElement('div');
    backdropEl.className = 'cmd-palette-backdrop';
    backdropEl.addEventListener('click', function (e) {
      if (e.target === backdropEl) closePalette();
    });

    var palette = document.createElement('div');
    palette.className = 'cmd-palette';

    // Input row
    var inputWrap = document.createElement('div');
    inputWrap.className = 'cmd-palette-input-wrap';
    inputWrap.innerHTML = SG.icon('search', 18);

    inputEl = document.createElement('input');
    inputEl.type = 'text';
    inputEl.className = 'cmd-palette-input';
    inputEl.placeholder = 'Type a command or search...';
    inputEl.setAttribute('autocomplete', 'off');
    inputEl.setAttribute('spellcheck', 'false');
    inputWrap.appendChild(inputEl);

    // Results
    resultsEl = document.createElement('div');
    resultsEl.className = 'cmd-palette-results';

    // Footer
    var footer = document.createElement('div');
    footer.className = 'cmd-palette-footer';
    footer.innerHTML =
      '<div class="cmd-palette-footer-keys">' +
        '<span><kbd>&uarr;</kbd><kbd>&darr;</kbd> navigate</span>' +
        '<span><kbd>&crarr;</kbd> select</span>' +
        '<span><kbd>esc</kbd> close</span>' +
      '</div>';

    palette.appendChild(inputWrap);
    palette.appendChild(resultsEl);
    palette.appendChild(footer);
    backdropEl.appendChild(palette);
    document.body.appendChild(backdropEl);

    // Events
    inputEl.addEventListener('input', function () {
      selectedIndex = 0;
      renderResults(inputEl.value);
    });

    inputEl.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        selectedIndex = Math.min(selectedIndex + 1, flatItems.length - 1);
        updateSelection();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        selectedIndex = Math.max(selectedIndex - 1, 0);
        updateSelection();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (flatItems[selectedIndex]) {
          flatItems[selectedIndex].action();
          closePalette();
        }
      } else if (e.key === 'Escape') {
        e.preventDefault();
        closePalette();
      }
    });
  }

  // -- Render -----------------------------------------------------------------

  function renderResults(query) {
    resultsEl.innerHTML = '';
    flatItems = [];
    query = (query || '').trim();

    var dynamicServers = [];
    var dynamicTools = [];

    if (SG._cachedUpstreams && Array.isArray(SG._cachedUpstreams)) {
      SG._cachedUpstreams.forEach(function (u) {
        dynamicServers.push({
          label: u.name || u.id,
          icon: 'server',
          action: function () { window.location.hash = '#/tools?upstream=' + encodeURIComponent(u.id); },
          shortcut: ''
        });
      });
    }

    if (SG._cachedTools && Array.isArray(SG._cachedTools)) {
      SG._cachedTools.forEach(function (t) {
        dynamicTools.push({
          label: t.name,
          icon: 'wrench',
          action: function () { window.location.hash = '#/tools?tool=' + encodeURIComponent(t.name); },
          shortcut: ''
        });
      });
    }

    var groups = [
      { title: 'Pages',   items: PAGES },
      { title: 'Actions', items: ACTIONS },
    ];
    if (dynamicServers.length) groups.push({ title: 'Servers', items: dynamicServers });
    if (dynamicTools.length)   groups.push({ title: 'Tools',   items: dynamicTools });

    var hasResults = false;

    groups.forEach(function (group) {
      var matched = group.items
        .map(function (item) {
          var result = fuzzyMatch(query, item.label, item.keywords);
          return { item: item, match: result.match, score: result.score };
        })
        .filter(function (r) { return r.match; })
        .sort(function (a, b) { return b.score - a.score; });

      if (!matched.length) return;
      hasResults = true;

      var titleEl = document.createElement('div');
      titleEl.className = 'cmd-palette-group-title';
      titleEl.textContent = group.title;
      resultsEl.appendChild(titleEl);

      matched.forEach(function (r) {
        var item = r.item;
        var row = document.createElement('div');
        row.className = 'cmd-palette-item';

        var iconSpan = document.createElement('span');
        iconSpan.className = 'cmd-palette-item-icon';
        if (typeof SG.icon === 'function') iconSpan.innerHTML = SG.icon(item.icon, 18);
        row.appendChild(iconSpan);

        var labelSpan = document.createElement('span');
        labelSpan.className = 'cmd-palette-item-label';
        labelSpan.textContent = item.label;
        row.appendChild(labelSpan);

        if (item.shortcut) {
          var shortcutSpan = document.createElement('span');
          shortcutSpan.className = 'cmd-palette-item-shortcut';
          item.shortcut.split(' ').forEach(function (k) {
            var kbd = document.createElement('kbd');
            kbd.textContent = k;
            shortcutSpan.appendChild(kbd);
          });
          row.appendChild(shortcutSpan);
        }

        var idx = flatItems.length;
        row.addEventListener('mouseenter', function () {
          selectedIndex = idx;
          updateSelection();
        });
        row.addEventListener('click', function () {
          item.action();
          closePalette();
        });

        resultsEl.appendChild(row);
        flatItems.push(item);
      });
    });

    if (!hasResults) {
      var empty = document.createElement('div');
      empty.className = 'cmd-palette-empty';
      empty.textContent = 'No results for "' + query + '"';
      resultsEl.appendChild(empty);
    }

    updateSelection();
  }

  function updateSelection() {
    var items = resultsEl.querySelectorAll('.cmd-palette-item');
    for (var i = 0; i < items.length; i++) {
      items[i].classList.toggle('selected', i === selectedIndex);
    }
    if (items[selectedIndex]) {
      items[selectedIndex].scrollIntoView({ block: 'nearest' });
    }
  }

  // -- Open / Close -----------------------------------------------------------

  function openPalette() {
    if (isTransitioning) return;
    injectStyles();
    if (!backdropEl) buildPalette();

    // L-31: Invalidate stale cache on every open so deleted servers/tools
    // don't linger. Fresh data is fetched each time the palette opens.
    SG._cachedUpstreams = null;
    SG._cachedTools = null;

    // Pre-fetch dynamic data; M-34: re-render when fetches resolve so
    // dynamic items are visible on first open
    SG.api.get('/upstreams').then(function (data) {
      SG._cachedUpstreams = data || [];
      if (backdropEl && backdropEl.classList.contains('active')) {
        renderResults(inputEl.value);
      }
    }).catch(function () {});
    SG.api.get('/tools').then(function (data) {
      SG._cachedTools = data || [];
      if (backdropEl && backdropEl.classList.contains('active')) {
        renderResults(inputEl.value);
      }
    }).catch(function () {});

    inputEl.value = '';
    selectedIndex = 0;
    renderResults('');

    if (!backdropEl.parentNode) {
      document.body.appendChild(backdropEl);
    }
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        backdropEl.classList.add('active');
        inputEl.focus();
      });
    });
  }

  function closePalette() {
    if (!backdropEl) return;
    isTransitioning = true;
    backdropEl.classList.remove('active');
    // M-28: hide backdrop from DOM after CSS transition completes
    var el = backdropEl;
    setTimeout(function () {
      if (el && el.parentNode) {
        el.parentNode.removeChild(el);
      }
      isTransitioning = false;
    }, 200);
  }

  // -- Global Cmd+K listener --------------------------------------------------

  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      if (backdropEl && backdropEl.classList && backdropEl.classList.contains('active')) {
        closePalette();
      } else {
        openPalette();
      }
    }
  });

  // -- Public API -------------------------------------------------------------

  SG.commandPalette = {
    open: openPalette,
    close: closePalette
  };
})();
