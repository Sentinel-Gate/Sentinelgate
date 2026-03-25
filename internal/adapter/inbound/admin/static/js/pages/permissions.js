// permissions.js — Access Review (Delta 2.2, Upgrade 6)
(function() {
  'use strict';

  const PAGE_NAME = 'permissions';
  const LP_TOOLTIP = 'Score = (permitted tools \u2212 gaps) \u00f7 permitted tools \u00d7 100.\nA \u201cgap\u201d is a permitted tool that is never used, rarely used (<3 calls), or used only in a narrow time window.\nLower scores indicate over-privileged identities.';
  var _tipStyleInjected = false;
  var _tipEl = null;
  function injectTipStyles() {
    if (_tipStyleInjected) return;
    _tipStyleInjected = true;
    var s = document.createElement('style');
    s.textContent = '.lp-tip{cursor:help}' +
      '#lp-tip-box{position:fixed;z-index:99999;pointer-events:none;' +
      'background:var(--bg-elevated,#1e1e2e);color:var(--text-primary,#e0e0e0);' +
      'border:1px solid var(--border,#333);border-radius:6px;' +
      'padding:8px 12px;font-size:12px;line-height:1.5;max-width:340px;' +
      'box-shadow:0 4px 12px rgba(0,0,0,0.4);white-space:pre-line;' +
      'opacity:0;transition:opacity 0.12s}' +
      '#lp-tip-box.visible{opacity:1}';
    document.head.appendChild(s);
  }
  function showTip(e) {
    if (!_tipEl) { _tipEl = document.createElement('div'); _tipEl.id = 'lp-tip-box'; document.body.appendChild(_tipEl); }
    _tipEl.textContent = LP_TOOLTIP;
    var r = e.target.closest('.lp-tip').getBoundingClientRect();
    _tipEl.style.left = Math.max(8, r.left + r.width / 2 - 170) + 'px';
    _tipEl.style.top = (r.top - 8) + 'px';
    _tipEl.style.transform = 'translateY(-100%)';
    _tipEl.classList.add('visible');
  }
  function hideTip() { if (_tipEl) _tipEl.classList.remove('visible'); }
  let currentIdentity = null;
  // M-30: store container reference from router instead of using getElementById
  let _container = null;

  function init(container) {
    _container = container || document.getElementById('page-content');
    injectTipStyles();
    // BUG-7 FIX: Single delegated click handler replaces all inline onclick
    // attributes that were blocked by CSP script-src 'self'.
    _container.addEventListener('click', handleClick);
    _container.addEventListener('mouseenter', function(e) { if (e.target.closest('.lp-tip')) showTip(e); }, true);
    _container.addEventListener('mouseleave', function(e) { if (e.target.closest('.lp-tip')) hideTip(); }, true);
    loadHealthMap();
  }

  function destroy() {
    if (_container) {
      _container.removeEventListener('click', handleClick);
    }
    currentIdentity = null;
    _container = null;
  }

  // BUG-7 FIX: Delegated event handler for all interactive elements.
  function handleClick(e) {
    var target = e.target.closest('[data-action]');
    if (!target) return;
    var act = target.dataset.action;
    switch (act) {
      case 'save-config':
        saveConfig();
        break;
      case 'show-detail':
        showDetail(target.dataset.identityId);
        break;
      case 'back-to-map':
        backToMap();
        break;
      case 'apply-single':
        applySingle(target.dataset.identityId, target.dataset.suggestionId);
        break;
      case 'open-builder':
        openInPolicyBuilder(target.dataset.toolPattern, target.dataset.condition);
        break;
      case 'apply-all':
        applyAll(target.dataset.identityId);
        break;
    }
  }

  // ── Health Map (all agents overview) ────────────────────────────────

  async function loadHealthMap() {
    const container = _container || document.getElementById('page-content');
    container.innerHTML = '<div class="page-header" style="position: relative;"><h1>Access Review</h1><button type="button" class="help-btn" style="position: absolute; top: 0; right: 0;">?</button><p class="page-subtitle">Fine-grained access control for identities and roles.</p></div><div id="ph-config"></div><div id="ph-content"><div class="loading">Loading...</div></div>';
    container.querySelector('.help-btn').addEventListener('click', function() { if (SG.help) SG.help.toggle('permissions'); });
    await renderConfig();
    await renderOverview();
  }

  async function renderConfig() {
    try {
      const cfg = await SG.api.get('/v1/permissions/config');
      // L-FE-4: Validate cfg.mode against known values to prevent dropdown/badge mismatch.
      const validModes = ['disabled','shadow','suggest','auto'];
      const mode = validModes.includes(cfg.mode) ? cfg.mode : 'disabled';
      const el = document.getElementById('ph-config');
      el.innerHTML = `
        <div class="card" style="margin-bottom:var(--space-4);padding:var(--space-3)">
          <div style="display:flex;align-items:center;gap:var(--space-3);flex-wrap:wrap">
            <label style="font-weight:600">Shadow Mode:</label>
            <select id="ph-mode" class="form-select" style="width:auto">
              <option value="disabled" ${mode==='disabled'?'selected':''}>Disabled</option>
              <option value="shadow" ${mode==='shadow'?'selected':''}>Shadow (report only)</option>
              <option value="suggest" ${mode==='suggest'?'selected':''}>Suggest (report + notify)</option>
              <option value="auto" ${mode==='auto'?'selected':''}>Auto-Tighten</option>
            </select>
            <label>Learning window: <input type="number" id="ph-days" class="form-input" style="width:60px;color-scheme:dark" value="${escAttr(String(cfg.learning_days||14))}" min="1" max="90"> days</label>
            <button class="btn btn-sm btn-primary" data-action="save-config">Save</button>
            <span class="badge badge-${mode==='disabled'?'neutral':'info'}" style="margin-left:auto">${esc(mode.toUpperCase())}</span>
          </div>
        </div>`;
    } catch(e) {
      document.getElementById('ph-config').innerHTML = '';
    }
  }

  async function renderOverview() {
    const el = document.getElementById('ph-content');
    try {
      const reports = await SG.api.get('/v1/permissions/health');
      if (!reports || reports.length === 0) {
        el.innerHTML = '<div class="empty-state"><h3>No permission data</h3><p>Enable shadow mode and wait for agent activity to see access review analysis.</p></div>';
        return;
      }
      el.innerHTML = renderHeatMatrix(reports) + renderAgentCards(reports);
    } catch(e) {
      if (e.message && e.message.includes('disabled')) {
        el.innerHTML = '<div class="empty-state"><h3>Access Review Disabled</h3><p>Enable shadow mode above to start analyzing agent permissions.</p></div>';
      } else {
        el.innerHTML = '<div class="empty-state"><h3>Error loading data</h3><p>' + esc(e.message||String(e)) + '</p></div>';
      }
    }
  }

  function renderHeatMatrix(reports) {
    // Collect all tools across all agents
    const allTools = new Set();
    reports.forEach(r => {
      if (r.gaps) r.gaps.forEach(g => allTools.add(g.tool_name));
    });
    // Also add used tools from usage count
    // Build a summary table
    let html = '<div class="card" style="margin-bottom:var(--space-4);padding:var(--space-4)"><h3 style="margin-bottom:var(--space-3)">Least Privilege Scores</h3><div class="ph-scores">';
    reports.forEach(r => {
      const color = r.least_privilege_score >= 80 ? 'var(--green)' : r.least_privilege_score >= 50 ? 'var(--yellow)' : 'var(--red)';
      html += `
        <div class="ph-score-row" data-action="show-detail" data-identity-id="${escAttr(r.identity_id)}" style="cursor:pointer;display:flex;align-items:center;gap:var(--space-3);padding:var(--space-2) 0;border-bottom:1px solid var(--border)">
          <span style="min-width:140px;font-weight:500">${esc(r.identity_name||r.identity_id)}</span>
          <div style="flex:1;background:var(--bg-secondary);border-radius:4px;height:20px;position:relative;overflow:hidden">
            <div style="width:${esc(String(r.least_privilege_score))}%;height:100%;background:${color};border-radius:4px;transition:width 0.3s"></div>
          </div>
          <span class="lp-tip" style="min-width:40px;text-align:right;font-weight:600">${esc(String(Math.round(r.least_privilege_score)))}%</span>
          <span style="min-width:80px;font-size:var(--text-sm);color:var(--text-secondary)">${r.used_tools > r.permitted_tools ? esc(String(r.used_tools)) + ' used (' + esc(String(r.permitted_tools)) + ' permitted)' : esc(String(r.used_tools)) + '/' + esc(String(r.permitted_tools)) + ' tools'}</span>
          <span class="badge badge-${r.gaps&&r.gaps.length>0?'warning':'success'}">${r.gaps?r.gaps.length:0} gaps</span>
        </div>`;
    });
    html += '</div></div>';
    return html;
  }

  function renderAgentCards(reports) {
    let html = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:var(--space-3)">';
    reports.forEach(r => {
      const score = Math.round(r.least_privilege_score);
      const scoreClass = score >= 80 ? 'success' : score >= 50 ? 'warning' : 'danger';
      const gapCount = r.gaps ? r.gaps.length : 0;
      const suggCount = r.suggestions ? r.suggestions.length : 0;
      html += `
        <div class="card" style="padding:var(--space-3);cursor:pointer" data-action="show-detail" data-identity-id="${escAttr(r.identity_id)}">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--space-2)">
            <strong>${esc(r.identity_name||r.identity_id)}</strong>
            <span class="badge badge-${scoreClass} lp-tip">${score}%</span>
          </div>
          <div style="font-size:var(--text-sm);color:var(--text-secondary)">
            <div>Roles: ${(r.roles||[]).map(r=>'<span class="badge badge-neutral" style="font-size:10px">'+esc(r)+'</span>').join(' ')}</div>
            <div style="margin-top:var(--space-1)">${r.used_tools > r.permitted_tools ? r.used_tools + ' used (' + r.permitted_tools + ' permitted)' : r.used_tools + '/' + r.permitted_tools + ' tools'}</div>
            ${gapCount>0?'<div style="color:var(--yellow)">'+gapCount+' over-privileged tools</div>':''}
            ${suggCount>0?'<div style="color:var(--blue)">'+suggCount+' suggestions available</div>':''}
            ${(typeof r.drift_score === 'number' && r.drift_score>0)?'<div>Drift: <span class="badge badge-'+(r.drift_score>0.3?'danger':r.drift_score>0?'warning':'success')+'">'+(r.drift_score || 0).toFixed(2)+'</span></div>':''}
          </div>
        </div>`;
    });
    html += '</div>';
    return html;
  }

  // ── Detail View (single identity) ──────────────────────────────────

  async function showDetail(identityID) {
    currentIdentity = identityID;
    const container = _container || document.getElementById('page-content');
    container.innerHTML = '<div class="loading">Loading...</div>';

    try {
      const report = await SG.api.get('/v1/permissions/health/' + encodeURIComponent(identityID));
      container.innerHTML = renderDetailView(report);
    } catch(e) {
      container.innerHTML = '<div class="empty-state"><h3>Error</h3><p>' + esc(e.message||String(e)) + '</p></div>';
    }
  }

  function renderDetailView(r) {
    const score = Math.round(r.least_privilege_score);
    const scoreColor = score >= 80 ? 'var(--green)' : score >= 50 ? 'var(--yellow)' : 'var(--red)';
    let html = `
      <div class="page-header" style="display:flex;align-items:center;gap:var(--space-3)">
        <button class="btn btn-sm btn-secondary" data-action="back-to-map">&larr; Back</button>
        <div>
          <h1>${esc(r.identity_name||r.identity_id)}</h1>
          <p class="page-subtitle">Roles: ${(r.roles||[]).map(x => esc(x)).join(', ')} | ${r.used_tools > r.permitted_tools ? r.used_tools + ' used (' + r.permitted_tools + ' permitted)' : r.used_tools + '/' + r.permitted_tools + ' tools'}</p>
        </div>
        <div class="lp-tip" style="margin-left:auto;text-align:center">
          <div style="font-size:2rem;font-weight:700;color:${scoreColor}">${score}%</div>
          <div style="font-size:var(--text-sm);color:var(--text-secondary)">Least Privilege</div>
        </div>
      </div>`;

    // KPI strip
    html += `
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:var(--space-3);margin-bottom:var(--space-4)">
        <div class="card" style="padding:var(--space-3);text-align:center">
          <div style="font-size:1.5rem;font-weight:700">${r.permitted_tools}</div>
          <div style="font-size:var(--text-sm);color:var(--text-secondary)">Permitted</div>
          <div style="font-size:var(--text-xs);color:var(--text-muted)">tools this identity can call</div>
        </div>
        <div class="card" style="padding:var(--space-3);text-align:center">
          <div style="font-size:1.5rem;font-weight:700;color:var(--green)">${r.used_tools}</div>
          <div style="font-size:var(--text-sm);color:var(--text-secondary)">Used</div>
          <div style="font-size:var(--text-xs);color:var(--text-muted)">tools called in observation window</div>
        </div>
        <div class="card" style="padding:var(--space-3);text-align:center">
          <div style="font-size:1.5rem;font-weight:700;color:var(--yellow)">${r.gaps?r.gaps.length:0}</div>
          <div style="font-size:var(--text-sm);color:var(--text-secondary)">Gaps</div>
          <div style="font-size:var(--text-xs);color:var(--text-muted)">over-privileged tools</div>
        </div>
        <div class="card" style="padding:var(--space-3);text-align:center">
          <div style="font-size:1.5rem;font-weight:700;color:var(--blue)">${r.suggestions?r.suggestions.length:0}</div>
          <div style="font-size:var(--text-sm);color:var(--text-secondary)">Suggestions</div>
          <div style="font-size:var(--text-xs);color:var(--text-muted)">auto-tighten rules available</div>
        </div>
      </div>`;

    // Gaps table
    if (r.gaps && r.gaps.length > 0) {
      html += '<div class="card" style="margin-bottom:var(--space-4);padding:var(--space-3)"><h3 style="margin-bottom:var(--space-2)">Permission Gaps</h3><style>.ph-gaps-table tbody tr{cursor:default}.ph-gaps-table tbody tr:hover{box-shadow:none;transform:none}.ph-gaps-table tbody tr:active{transform:none}.ph-gaps-table code{color:var(--text-primary)}</style><table class="table ph-gaps-table"><thead><tr><th>Tool</th><th>Type</th><th>Details</th></tr></thead><tbody>';
      r.gaps.forEach(g => {
        const typeColor = g.gap_type === 'never_used' ? 'var(--red)' : g.gap_type === 'rarely_used' ? 'var(--yellow)' : 'var(--blue)';
        html += `<tr><td><code>${esc(g.tool_name)}</code></td><td><span class="badge" style="background:${typeColor};color:#fff">${g.gap_type.replace('_',' ')}</span></td><td>${esc(g.description)}</td></tr>`;
      });
      html += '</tbody></table></div>';
    }

    // Suggestions
    if (r.suggestions && r.suggestions.length > 0) {
      html += `<div class="card" style="padding:var(--space-3)"><h3 style="margin-bottom:var(--space-2)">Auto-Tighten Suggestions</h3><div id="ph-suggestions">`;
      r.suggestions.forEach(s => {
        html += `
          <div class="ph-suggestion" style="padding:var(--space-2);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:var(--space-2)">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <div>
                <strong>${esc(s.tool_name)}</strong>
                <span style="color:var(--text-secondary);font-size:var(--text-sm);margin-left:var(--space-2)">${esc(s.reason)}</span>
              </div>
              <div style="display:flex;gap:var(--space-2)">
                <button class="btn btn-sm" data-action="apply-single" data-identity-id="${escAttr(r.identity_id)}" data-suggestion-id="${escAttr(s.id)}">Apply</button>
                <button class="btn btn-sm btn-ghost" data-action="open-builder" data-tool-pattern="${escAttr(s.tool_name || s.tool_pattern)}" data-condition="${escAttr(s.condition)}">Edit in Builder</button>
              </div>
            </div>
            <div style="margin-top:var(--space-1)"><code style="font-size:var(--text-xs);color:var(--text-secondary)">${esc(s.tool_pattern)} | ${esc(s.condition)} → ${esc(s.action)}</code></div>
          </div>`;
      });
      html += `<button class="btn" style="margin-top:var(--space-2)" data-action="apply-all" data-identity-id="${escAttr(r.identity_id)}">Apply All Suggestions</button></div></div>`;
    }

    return html;
  }

  // ── Actions ────────────────────────────────────────────────────────

  async function saveConfig() {
    const mode = document.getElementById('ph-mode').value;
    const days = parseInt(document.getElementById('ph-days').value) || 14;
    try {
      await SG.api.put('/v1/permissions/config', {
        mode: mode,
        learning_days: days,
        grace_period_days: 7
      });
      // Immediately update badge before re-fetching (eliminates visual lag)
      const badge = document.querySelector('#ph-config .badge');
      if (badge) {
        badge.textContent = mode.toUpperCase();
        badge.className = 'badge badge-' + (mode === 'disabled' ? 'neutral' : 'info');
      }
      SG.toast.success('Configuration saved');
      loadHealthMap();
    } catch(e) {
      SG.toast.error('Failed to save: ' + (e.message||e));
    }
  }

  async function applySingle(identityID, suggestionID) {
    try {
      await SG.api.post('/v1/permissions/apply', {
        identity_id: identityID,
        suggestion_ids: [suggestionID]
      });
      SG.toast.success('Suggestion applied');
      // UX-11 FIX: Remove the applied suggestion from DOM immediately
      var suggestions = document.getElementById('ph-suggestions');
      if (suggestions) {
        var items = suggestions.querySelectorAll('.ph-suggestion');
        items.forEach(function(item) {
          var btn = item.querySelector('[data-action="apply-single"][data-suggestion-id="' + suggestionID + '"]');
          if (btn) {
            item.style.maxHeight = item.offsetHeight + 'px';
            item.style.overflow = 'hidden';
            item.style.transition = 'opacity 0.2s, max-height 0.3s, margin 0.3s, padding 0.3s';
            item.style.opacity = '0';
            setTimeout(function() { item.style.maxHeight = '0'; item.style.marginBottom = '0'; item.style.padding = '0'; }, 200);
            setTimeout(function() { item.remove(); updateSuggestionCount(suggestions); }, 500);
          }
        });
      }
    } catch(e) {
      SG.toast.error('Failed: ' + (e.message||e));
    }
  }

  async function applyAll(identityID) {
    try {
      const data = await SG.api.get('/v1/permissions/suggestions/' + encodeURIComponent(identityID));
      if (!data.suggestions || data.suggestions.length === 0) {
        SG.toast.info('No suggestions to apply');
        return;
      }
      const ids = data.suggestions.map(s => s.id);
      await SG.api.post('/v1/permissions/apply', {
        identity_id: identityID,
        suggestion_ids: ids
      });
      SG.toast.success(ids.length + ' suggestions applied');
      // UX-11 FIX: Remove all suggestions from DOM immediately
      var suggestions = document.getElementById('ph-suggestions');
      if (suggestions) {
        suggestions.innerHTML = '<div style="padding:var(--space-3);color:var(--text-secondary);text-align:center">All suggestions applied.</div>';
        // Disable the Apply All button
        var applyAllBtn = suggestions.parentElement.querySelector('[data-action="apply-all"]');
        if (applyAllBtn) { applyAllBtn.disabled = true; applyAllBtn.style.opacity = '0.5'; }
      }
    } catch(e) {
      SG.toast.error('Failed: ' + (e.message||e));
    }
  }

  function updateSuggestionCount(container) {
    if (!container) return;
    var remaining = container.querySelectorAll('.ph-suggestion');
    if (remaining.length === 0) {
      container.innerHTML = '<div style="padding:var(--space-3);color:var(--text-secondary);text-align:center">All suggestions applied.</div>';
      var applyAllBtn = container.parentElement.querySelector('[data-action="apply-all"]');
      if (applyAllBtn) { applyAllBtn.disabled = true; applyAllBtn.style.opacity = '0.5'; }
    }
  }

  function openInPolicyBuilder(toolPattern, condition) {
    if (typeof SG.tools !== 'undefined' && SG.tools.ensureDataForModal) {
      SG.tools.ensureDataForModal().then(function () {
        SG.tools.openRuleModal(null, null, toolPattern);
      });
    } else {
      window.location.hash = '#/tools';
    }
  }

  function backToMap() {
    currentIdentity = null;
    loadHealthMap();
  }

  function esc(s) { const d=document.createElement('div');d.textContent=s||'';return d.innerHTML.replace(/"/g,'&quot;'); }
  function escAttr(s) { return esc(s).replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }

  // Register page
  if (typeof SG === 'undefined') window.SG = {};
  SG.permissions = { init, destroy, showDetail, backToMap, saveConfig, applySingle, applyAll, openInPolicyBuilder };
  SG.router.register(PAGE_NAME, init);
  SG.router.registerCleanup(PAGE_NAME, destroy);
})();
