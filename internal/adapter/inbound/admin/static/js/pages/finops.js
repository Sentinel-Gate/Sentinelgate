(function() {
  'use strict';

  var styleInjected = false;
  var currentReport = null;
  var currentIdentity = null;

  function injectStyles() {
    if (styleInjected) return;
    styleInjected = true;
    var style = document.createElement('style');
    style.setAttribute('data-page', 'finops');
    style.textContent = [
      '.fo-page { max-width: 1200px; }',
      '.fo-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-4); }',
      '.fo-budget-bar { margin-bottom: var(--space-4); background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-3); }',
      '.fo-budget-info { display: flex; justify-content: space-between; margin-bottom: var(--space-2); font-size: var(--text-sm); }',
      '.fo-budget-track { height: 16px; background: var(--bg-secondary); border-radius: var(--radius-full); overflow: hidden; }',
      '.fo-budget-fill { height: 100%; border-radius: var(--radius-full); transition: width 0.3s; }',
      '.fo-budget-fill.ok { background: var(--success); }',
      '.fo-budget-fill.warn { background: var(--warning); }',
      '.fo-budget-fill.over { background: var(--danger); }',
      '.fo-summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: var(--space-3); margin-bottom: var(--space-4); }',
      '.fo-summary-card { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-3); text-align: center; }',
      '.fo-summary-value { font-size: 1.5rem; font-weight: 700; }',
      '.fo-summary-label { font-size: var(--text-sm); color: var(--text-secondary); }',
      '.fo-table { width: 100%; border-collapse: collapse; margin-bottom: var(--space-4); }',
      '.fo-table th, .fo-table td { padding: var(--space-2) var(--space-3); text-align: left; border-bottom: 1px solid var(--border); font-size: var(--text-sm); }',
      '.fo-table th { font-weight: var(--font-semibold); color: var(--text-secondary); font-size: var(--text-xs); text-transform: uppercase; }',
      '.fo-table tr:hover { background: var(--bg-secondary); }',
      '.fo-table tr.clickable { cursor: pointer; }',
      '.fo-cost { font-family: var(--font-mono); }',
      '.fo-config-panel { background: var(--bg-surface); border: 1px solid rgba(255,255,255,0.12); border-radius: var(--radius-lg); padding: var(--space-3); margin-top: var(--space-3); margin-bottom: var(--space-4); }',
      '.fo-config-row { display: flex; gap: var(--space-3); align-items: center; margin-bottom: var(--space-2); flex-wrap: wrap; }',
      '.fo-config-row label { font-size: var(--text-sm); min-width: 140px; }',
      '.fo-config-row input { padding: 4px 8px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--bg-surface); color: var(--text-primary); font-size: var(--text-sm); width: 120px; color-scheme: dark; }',
      '.fo-empty { text-align: center; padding: var(--space-6); color: var(--text-muted); }',
      '.fo-detail-header { display: flex; align-items: center; gap: var(--space-3); margin-bottom: var(--space-4); }',
      '.fo-back { cursor: pointer; padding: 4px 12px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--bg-surface); color: var(--text-primary); font-size: var(--text-sm); }',
      '.fo-back:hover { background: var(--bg-secondary); }',
      '.fo-bar-wrap { width: 100px; height: 8px; background: var(--bg-secondary); border-radius: var(--radius-full); overflow: hidden; display: inline-block; vertical-align: middle; }',
      '.fo-bar-inner { height: 100%; border-radius: var(--radius-full); background: var(--accent); }'
    ].join('\n');
    document.head.appendChild(style);
  }

  function esc(str) {
    if (!str) return '';
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function fmtCost(v) {
    if (v === undefined || v === null) return '$0.00';
    return '$' + v.toFixed(4);
  }

  function render(container) {
    injectStyles();
    currentIdentity = null;
    container.innerHTML = '<div class="fo-page">' +
      '<div class="fo-header" style="flex-wrap: wrap;">' +
        '<div style="flex:1;min-width:0"><h2 style="margin:0;">Cost Tracking</h2>' +
        '<p class="page-subtitle">Track and control AI tool usage costs. ' +
        '<span style="color:var(--text-muted)">' + new Date().getFullYear() + '-' + String(new Date().getMonth() + 1).padStart(2, '0') + '</span></p></div>' +
        '<div style="display: flex; align-items: center; gap: var(--space-2);">' +
        '<button class="btn btn-secondary" id="fo-config-toggle">Configure</button></div>' +
        '<button type="button" class="help-btn" id="fo-help-btn">?</button>' +
      '</div>' +
      '<div id="fo-config" style="display:none"></div>' +
      '<div id="fo-content"><div class="fo-empty"><p>Loading cost data...</p></div></div>' +
    '</div>';

    document.getElementById('fo-config-toggle').addEventListener('click', toggleConfig);
    document.getElementById('fo-help-btn').addEventListener('click', function() { if (SG.help) SG.help.toggle('finops'); });
    loadCostReport().catch(function(err) { console.error('Failed to load cost data:', err); });
  }

  async function toggleConfig() {
    var el = document.getElementById('fo-config');
    if (el.style.display === 'none') {
      el.style.display = 'block';
      await renderConfig(el);
    } else {
      el.style.display = 'none';
    }
  }

  async function renderConfig(el) {
    var cfg;
    try {
      cfg = await SG.api.get('/v1/finops/config');
    } catch(e) {
      cfg = { enabled: false, default_cost_per_call: 0.01 };
    }

    // Fetch identities to resolve UUID → name
    var identityNames = {};
    try {
      var ids = await SG.api.get('/identities');
      (ids || []).forEach(function(id) { identityNames[id.id] = id.name || id.id; });
    } catch(e) {}

    // Build budget rows HTML
    var budgets = cfg.budgets || {};
    var budgetActions = cfg.budget_actions || {};
    var budgetRowsHtml = '';
    var budgetIds = Object.keys(budgets);
    for (var bi = 0; bi < budgetIds.length; bi++) {
      var bid = budgetIds[bi];
      var bact = budgetActions[bid] || 'notify';
      var bidDisplay = identityNames[bid] || bid;
      budgetRowsHtml += '<tr data-budget-id="' + esc(bid) + '">' +
        '<td style="font-size:var(--text-sm)">' + esc(bidDisplay) + '</td>' +
        '<td><input type="number" step="0.01" min="1" class="fo-budget-amount" value="' + (budgets[bid] || 0) + '" style="width:100px;padding:4px 8px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-surface);color:var(--text-primary);font-size:var(--text-sm);color-scheme:dark"></td>' +
        '<td><select class="fo-budget-action" style="padding:4px 8px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-surface);color:var(--text-primary);font-size:var(--text-sm)">' +
          '<option value="notify"' + (budgetActions[bid] !== 'block' ? ' selected' : '') + '>Notify</option>' +
          '<option value="block"' + (budgetActions[bid] === 'block' ? ' selected' : '') + '>Block</option>' +
        '</select></td>' +
        '<td><button class="btn btn-secondary btn-sm fo-budget-remove" type="button" style="color:var(--danger)">Remove</button></td>' +
      '</tr>';
    }

    el.innerHTML = '<div class="fo-config-panel">' +
      '<h3 style="margin-bottom:var(--space-3)">Configuration</h3>' +
      '<div class="fo-config-row"><label style="display:flex;align-items:center;gap:var(--space-2);cursor:pointer">' +
        '<input type="checkbox" id="fo-cfg-enabled"' + (cfg.enabled ? ' checked' : '') + '> Enable Cost Tracking</label>' +
        '<p style="font-size:var(--text-xs);color:var(--text-muted);margin:2px 0 0">When enabled, all tool calls are tracked and costs estimated based on the per-call rate below.</p></div>' +
      '<div class="fo-config-row"><label>Default Cost/Call</label>' +
        '<input type="number" step="0.001" id="fo-cfg-cost" value="' + (cfg.default_cost_per_call || 0.01) + '"></div>' +
      '<div style="border-top:1px solid var(--border);margin:var(--space-3) 0;padding-top:var(--space-3)">' +
        '<h4 style="margin:0 0 var(--space-2)">Budget Guardrails</h4>' +
        '<p style="font-size:var(--text-xs);color:var(--text-muted);margin:0 0 var(--space-2)">Set monthly spending limits per identity. When exceeded, the configured action is triggered. For per-session cost limits, use the <code>session_cumulative_cost</code> variable in a policy rule (see Help).</p>' +
        '<table class="fo-table" id="fo-budget-table"><thead><tr><th>Identity</th><th>Monthly Budget ($)</th><th>Action</th><th></th></tr></thead>' +
          '<tbody id="fo-budget-rows">' + budgetRowsHtml + '</tbody></table>' +
        '<div style="margin-top:var(--space-2);display:flex;gap:var(--space-2);align-items:center">' +
          '<select id="fo-budget-new-id" style="flex:1;padding:4px 8px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-surface);color:var(--text-primary);font-size:var(--text-sm)">' +
            '<option value="">Select identity...</option></select>' +
          '<button class="btn btn-secondary btn-sm" id="fo-budget-add" type="button">+ Add Budget</button>' +
        '</div>' +
      '</div>' +
      '<div class="fo-config-row" style="margin-top:var(--space-3);display:flex;align-items:center;gap:var(--space-3)">' +
        '<label style="display:flex;align-items:center;gap:var(--space-1);font-size:var(--text-sm);cursor:pointer;margin-right:auto">' +
          '<input type="checkbox" id="fo-cfg-enabled-footer"' + (cfg.enabled ? ' checked' : '') + '> Enabled</label>' +
        '<button class="btn btn-primary btn-sm" id="fo-cfg-save">Save</button>' +
      '</div>' +
    '</div>';

    // Load identities for the dropdown
    try {
      var identities = await SG.api.get('/identities');
      var sel = document.getElementById('fo-budget-new-id');
      if (Array.isArray(identities)) {
        identities.forEach(function(ident) {
          var id = ident.id || ident.identity_id;
          if (id && !budgets[id]) {
            var opt = document.createElement('option');
            opt.value = id;
            opt.textContent = ident.name || ident.identity_name || id;
            sel.appendChild(opt);
          }
        });
      }
    } catch(e) { /* identities not available, user can still type */ }

    // Add budget row
    document.getElementById('fo-budget-add').addEventListener('click', function() {
      var sel = document.getElementById('fo-budget-new-id');
      var newId = sel.value;
      if (!newId) { SG.toast.error('Select an identity first'); return; }
      var tbody = document.getElementById('fo-budget-rows');
      var tr = document.createElement('tr');
      tr.setAttribute('data-budget-id', newId);
      var newDisplayName = sel.options[sel.selectedIndex] ? sel.options[sel.selectedIndex].textContent : newId;
      tr.innerHTML = '<td style="font-size:var(--text-sm)">' + esc(newDisplayName) + '</td>' +
        '<td><input type="number" step="0.01" min="1" class="fo-budget-amount" value="50" style="width:100px;padding:4px 8px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-surface);color:var(--text-primary);font-size:var(--text-sm);color-scheme:dark"></td>' +
        '<td><select class="fo-budget-action" style="padding:4px 8px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg-surface);color:var(--text-primary);font-size:var(--text-sm)">' +
          '<option value="notify" selected>Notify</option>' +
          '<option value="block">Block</option></select></td>' +
        '<td><button class="btn btn-secondary btn-sm fo-budget-remove" type="button" style="color:var(--danger)">Remove</button></td>';
      tbody.appendChild(tr);
      // Remove from dropdown
      for (var i = 0; i < sel.options.length; i++) {
        if (sel.options[i].value === newId) { sel.remove(i); break; }
      }
      sel.value = '';
    });

    // Remove budget rows (delegated) — restore identity to dropdown
    document.getElementById('fo-budget-rows').addEventListener('click', function(e) {
      if (e.target.classList.contains('fo-budget-remove')) {
        var tr = e.target.closest('tr');
        if (tr) {
          var restoredId = tr.getAttribute('data-budget-id');
          var restoredName = tr.cells[0] ? tr.cells[0].textContent : restoredId;
          tr.remove();
          var sel = document.getElementById('fo-budget-new-id');
          if (sel && restoredId) {
            var opt = document.createElement('option');
            opt.value = restoredId;
            opt.textContent = restoredName;
            sel.appendChild(opt);
          }
        }
      }
    });

    // Sync the two enable checkboxes
    var foEnabledTop = document.getElementById('fo-cfg-enabled');
    var foEnabledFooter = document.getElementById('fo-cfg-enabled-footer');
    if (foEnabledTop && foEnabledFooter) {
      foEnabledTop.addEventListener('change', function () { foEnabledFooter.checked = foEnabledTop.checked; });
      foEnabledFooter.addEventListener('change', function () { foEnabledTop.checked = foEnabledFooter.checked; });
    }

    // Show warning when "Block" action is selected
    var budgetRows = document.getElementById('fo-budget-rows');
    if (budgetRows) {
      budgetRows.addEventListener('change', function (e) {
        if (e.target.classList.contains('fo-budget-action')) {
          var tr = e.target.closest('tr');
          if (!tr) return;
          var existingWarn = tr.querySelector('.fo-block-warning');
          if (e.target.value === 'block') {
            if (!existingWarn) {
              var warn = document.createElement('div');
              warn.className = 'fo-block-warning';
              warn.style.cssText = 'font-size:var(--text-xs);color:var(--warning);margin-top:4px;';
              warn.textContent = 'All tool calls will be denied for this identity once the budget is exceeded.';
              e.target.parentElement.appendChild(warn);
            }
          } else if (existingWarn) {
            existingWarn.remove();
          }
        }
      });
    }

    // Save
    document.getElementById('fo-cfg-save').addEventListener('click', async function() {
      // Collect budgets from table
      var newBudgets = {};
      var newBudgetActions = {};
      var rows = document.querySelectorAll('#fo-budget-rows tr[data-budget-id]');
      for (var ri = 0; ri < rows.length; ri++) {
        var row = rows[ri];
        var rid = row.getAttribute('data-budget-id');
        var amt = parseFloat(row.querySelector('.fo-budget-amount').value) || 0;
        var act = row.querySelector('.fo-budget-action').value || 'notify';
        if (amt > 0) {
          newBudgets[rid] = amt;
          newBudgetActions[rid] = act;
        }
      }
      var newCfg = {
        enabled: document.getElementById('fo-cfg-enabled').checked,
        default_cost_per_call: parseFloat(document.getElementById('fo-cfg-cost').value) || 0.01,
        tool_costs: cfg.tool_costs || {},
        budgets: newBudgets,
        budget_actions: newBudgetActions,
        alert_thresholds: cfg.alert_thresholds || [0.7, 0.85, 1.0]
      };
      try {
        await SG.api.put('/v1/finops/config', newCfg);
        SG.toast.success('Cost tracking config saved');
        await loadCostReport();
      } catch(err) {
        SG.toast.error(err.message || 'Failed to save config');
      }
    });
  }

  async function loadCostReport() {
    var content = document.getElementById('fo-content');
    try {
      currentReport = await SG.api.get('/v1/finops/costs');
      renderCostReport(content);
    } catch(err) {
      content.innerHTML = '<div class="fo-empty"><h3>Cost Tracking Not Available</h3><p>' + esc(err.message) + '</p></div>';
    }
  }

  function renderCostReport(el) {
    var r = currentReport;
    if (!r || r.total_calls === 0) {
      el.innerHTML = '<div class="fo-empty"><h3>No Cost Data</h3><p>Enable cost tracking and run some tool calls to see cost data.</p></div>';
      return;
    }

    var html = '';

    // Summary KPIs
    html += '<div class="fo-summary">';
    html += '<div class="fo-summary-card"><div class="fo-summary-value fo-cost">' + fmtCost(r.total_cost) + '</div><div class="fo-summary-label">Total Cost</div></div>';
    html += '<div class="fo-summary-card"><div class="fo-summary-value">' + r.total_calls + '</div><div class="fo-summary-label">Total Calls</div></div>';
    html += '<div class="fo-summary-card"><div class="fo-summary-value fo-cost">' + fmtCost(r.total_calls > 0 ? r.total_cost / r.total_calls : 0) + '</div><div class="fo-summary-label">Avg Cost/Call</div></div>';
    var daysElapsed = new Date().getDate();
    html += '<div class="fo-summary-card"><div class="fo-summary-value fo-cost">' + fmtCost(r.projection) + '</div><div class="fo-summary-label">Projection</div>';
    html += '<div style="font-size:var(--text-xs);color:var(--text-muted);margin-top:2px">Based on ' + r.total_calls + ' calls over ' + daysElapsed + ' days</div></div>';
    html += '</div>';

    // Budget status
    if (r.budget_status && r.budget_status.length > 0) {
      r.budget_status.forEach(function(bs) {
        var pct = Math.min(bs.percentage, 100);
        var cls = pct >= 100 ? 'over' : (pct >= 85 ? 'warn' : 'ok');
        html += '<div class="fo-budget-bar">';
        html += '<div class="fo-budget-info"><span>' + esc(bs.identity_name || bs.identity_id) + '</span><span>' + fmtCost(bs.spent) + ' / ' + fmtCost(bs.budget) + ' (' + (bs.percentage || 0).toFixed(1) + '%)</span></div>';
        html += '<div class="fo-budget-track"><div class="fo-budget-fill ' + cls + '" style="width:' + pct + '%"></div></div>';
        html += '</div>';
      });
    }

    // By Identity table
    if (r.by_identity && r.by_identity.length > 0) {
      html += '<h3 style="margin-bottom:var(--space-2)">Cost by Identity</h3>';
      html += '<table class="fo-table"><thead><tr><th>Identity</th><th>Calls</th><th>Total Cost</th><th>Avg Cost</th><th>Share</th></tr></thead><tbody>';
      r.by_identity.forEach(function(id) {
        var share = r.total_cost > 0 ? (id.total_cost / r.total_cost * 100) : 0;
        html += '<tr class="clickable" data-identity="' + esc(id.identity_id) + '" data-identity-name="' + esc(id.identity_name || '') + '" style="cursor:pointer">';
        html += '<td>' + esc(id.identity_name || id.identity_id) + '</td>';
        html += '<td>' + id.call_count + '</td>';
        html += '<td class="fo-cost">' + fmtCost(id.total_cost) + '</td>';
        html += '<td class="fo-cost">' + fmtCost(id.avg_cost) + '</td>';
        html += '<td><div class="fo-bar-wrap"><div class="fo-bar-inner" style="width:' + share + '%"></div></div> ' + share.toFixed(1) + '%</td>';
        html += '</tr>';
      });
      html += '</tbody></table>';
    }

    // By Tool table
    if (r.by_tool && r.by_tool.length > 0) {
      html += '<h3 style="margin-bottom:var(--space-2)">Cost by Tool</h3>';
      html += '<table class="fo-table"><thead><tr><th>Tool</th><th>Calls</th><th>Total Cost</th><th>Avg Cost</th></tr></thead><tbody>';
      r.by_tool.forEach(function(t) {
        html += '<tr>';
        html += '<td>' + esc(t.tool_name) + '</td>';
        html += '<td>' + t.call_count + '</td>';
        html += '<td class="fo-cost">' + fmtCost(t.total_cost) + '</td>';
        html += '<td class="fo-cost">' + fmtCost(t.avg_cost) + '</td>';
        html += '</tr>';
      });
      html += '</tbody></table>';
    }

    el.innerHTML = html;

    // Wire identity drill-down
    el.querySelectorAll('[data-identity]').forEach(function(row) {
      row.addEventListener('click', function() {
        var id = this.getAttribute('data-identity');
        var name = this.getAttribute('data-identity-name');
        showIdentityDetail(id, name);
      });
    });
  }

  async function showIdentityDetail(identityId, identityName) {
    currentIdentity = identityId;
    var content = document.getElementById('fo-content');
    content.innerHTML = '<div class="fo-empty"><p>Loading cost detail...</p></div>';

    try {
      var detail = await SG.api.get('/v1/finops/costs/' + encodeURIComponent(identityId));
      detail._displayName = identityName || detail.identity_name || identityId;
      renderIdentityDetail(content, detail);
    } catch(err) {
      content.innerHTML = '<div class="fo-empty"><p>Error: ' + esc(err.message) + '</p></div>';
    }
  }

  function renderIdentityDetail(el, detail) {
    var html = '<div class="fo-detail-header">';
    html += '<button class="fo-back" id="fo-back-btn">Back</button>';
    html += '<div><h3>' + esc(detail._displayName) + '</h3>';
    html += '<div style="font-size:var(--text-xs);color:var(--text-muted);font-family:var(--font-mono)">' + esc(detail.identity_id) + '</div></div></div>';

    // KPI strip
    html += '<div class="fo-summary">';
    html += '<div class="fo-summary-card"><div class="fo-summary-value fo-cost">' + fmtCost(detail.total_cost) + '</div><div class="fo-summary-label">Total Cost</div></div>';
    html += '<div class="fo-summary-card"><div class="fo-summary-value">' + detail.call_count + '</div><div class="fo-summary-label">Calls</div></div>';
    html += '<div class="fo-summary-card"><div class="fo-summary-value fo-cost">' + fmtCost(detail.avg_cost) + '</div><div class="fo-summary-label">Avg Cost/Call</div></div>';
    html += '<div class="fo-summary-card"><div class="fo-summary-value">' + (detail.tools ? detail.tools.length : 0) + '</div><div class="fo-summary-label">Tools Used</div></div>';
    html += '</div>';

    // Tool breakdown
    if (detail.tools && detail.tools.length > 0) {
      html += '<h3 style="margin-bottom:var(--space-2)">Tool Breakdown</h3>';
      html += '<table class="fo-table"><thead><tr><th>Tool</th><th>Calls</th><th>Total Cost</th><th>Avg Cost</th></tr></thead><tbody>';
      detail.tools.forEach(function(t) {
        html += '<tr>';
        html += '<td>' + esc(t.tool_name) + '</td>';
        html += '<td>' + t.call_count + '</td>';
        html += '<td class="fo-cost">' + fmtCost(t.total_cost) + '</td>';
        html += '<td class="fo-cost">' + fmtCost(t.avg_cost) + '</td>';
        html += '</tr>';
      });
      html += '</tbody></table>';
    }

    el.innerHTML = html;

    document.getElementById('fo-back-btn').addEventListener('click', function() {
      currentIdentity = null;
      // L-FE-8: Trigger fresh data fetch when navigating back from detail to avoid stale data.
      loadCostReport();
    });

  }

  function cleanup() {
    currentReport = null;
    currentIdentity = null;
  }

  SG.router.register('finops', render);
  SG.router.registerCleanup('finops', cleanup);
})();
