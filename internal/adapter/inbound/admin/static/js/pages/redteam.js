(function() {
  'use strict';

  var styleInjected = false;
  var currentReport = null;

  function injectStyles() {
    if (styleInjected) return;
    styleInjected = true;
    var style = document.createElement('style');
    style.setAttribute('data-page', 'redteam');
    style.textContent = [
      '.rt-page { max-width: 1200px; }',
      '.rt-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-4); }',
      '.rt-config { display: flex; gap: var(--space-3); align-items: center; flex-wrap: wrap; }',
      '.rt-config select, .rt-config input { padding: 6px 10px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--bg-surface); color: var(--text-primary); font-size: var(--text-sm); }',
      '.rt-scorecard { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: var(--space-3); margin-bottom: var(--space-4); }',
      '.rt-score-card { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-3); }',
      '.rt-score-name { font-size: var(--text-sm); font-weight: var(--font-semibold); margin-bottom: var(--space-2); text-transform: capitalize; }',
      '.rt-score-bar { height: 10px; background: var(--bg-secondary); border-radius: var(--radius-full); overflow: hidden; margin-bottom: var(--space-1); }',
      '.rt-score-fill { height: 100%; border-radius: var(--radius-full); transition: width 0.3s; }',
      '.rt-score-fill.good { background: var(--success); }',
      '.rt-score-fill.warn { background: var(--warning); }',
      '.rt-score-fill.bad { background: var(--danger); }',
      '.rt-score-stats { font-size: var(--text-xs); color: var(--text-secondary); }',
      '.rt-summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: var(--space-3); margin-bottom: var(--space-4); }',
      '.rt-summary-card { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-3); text-align: center; }',
      '.rt-summary-value { font-size: 1.5rem; font-weight: 700; }',
      '.rt-summary-label { font-size: var(--text-sm); color: var(--text-secondary); }',
      '.rt-vuln-list { display: flex; flex-direction: column; gap: var(--space-3); }',
      '.rt-vuln { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); overflow: hidden; }',
      '.rt-vuln-header { display: flex; justify-content: space-between; align-items: center; padding: var(--space-3); cursor: pointer; }',
      '.rt-vuln-header:hover { background: var(--bg-secondary); }',
      '.rt-vuln-title { font-weight: var(--font-semibold); }',
      '.rt-vuln-badges { display: flex; gap: var(--space-2); align-items: center; }',
      '.rt-sev { padding: 2px 8px; border-radius: var(--radius-full); font-size: var(--text-xs); font-weight: var(--font-semibold); text-transform: uppercase; }',
      '.rt-sev.critical { background: #fecaca; color: #991b1b; }',
      '.rt-sev.high { background: #fed7aa; color: #9a3412; }',
      '.rt-sev.medium { background: #fef08a; color: #854d0e; }',
      '.rt-sev.low { background: #d1fae5; color: #065f46; }',
      '.rt-cat { padding: 2px 8px; border-radius: var(--radius); font-size: var(--text-xs); background: var(--bg-secondary); color: var(--text-secondary); }',
      '.rt-vuln-body { padding: 0 var(--space-3) var(--space-3); display: none; }',
      '.rt-vuln-body.open { display: block; }',
      '.rt-detail-section { margin-bottom: var(--space-3); }',
      '.rt-detail-title { font-size: var(--text-sm); font-weight: var(--font-semibold); color: var(--text-secondary); margin-bottom: var(--space-1); }',
      '.rt-detail-box { background: var(--bg-primary); border: 1px solid var(--border); border-radius: var(--radius); padding: var(--space-2); font-size: var(--text-sm); }',
      '.rt-rule-box { background: var(--bg-primary); border: 1px solid var(--border); border-radius: var(--radius); padding: var(--space-2); font-family: var(--font-mono); font-size: var(--text-xs); white-space: pre-wrap; word-break: break-all; }',
      '.rt-actions { display: flex; gap: var(--space-2); margin-top: var(--space-2); }',
      '.rt-empty { text-align: center; padding: var(--space-6); color: var(--text-muted); }',
      '.rt-blocked-badge { color: var(--success); font-weight: var(--font-semibold); }',
      '.rt-passed-badge { color: var(--danger); font-weight: var(--font-semibold); }',
      '.rt-retest-result { margin-top: var(--space-2); padding: var(--space-2); border-radius: var(--radius); font-size: var(--text-sm); }',
      '.rt-retest-result.pass { background: #d1fae5; color: #065f46; }',
      '.rt-retest-result.fail { background: #fecaca; color: #991b1b; }',
      '.autocomplete-wrap { position: relative; display: inline-block; }',
      '.autocomplete-list { position: absolute; top: 100%; left: 0; right: 0; max-height: 200px; overflow-y: auto; background: var(--bg-elevated); border: 1px solid var(--border); border-radius: var(--radius-md); box-shadow: var(--shadow-lg); z-index: 10; display: none; min-width: 180px; }',
      '.autocomplete-list.open { display: block; }',
      '.autocomplete-item { padding: var(--space-2) var(--space-3); font-size: var(--text-sm); cursor: pointer; transition: background var(--transition-fast); }',
      '.autocomplete-item:hover, .autocomplete-item.selected { background: var(--bg-secondary); }',
      '.autocomplete-item-name { color: var(--text-primary); }'
    ].join('\n');
    document.head.appendChild(style);
  }

  function esc(str) {
    if (!str) return '';
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function formatCategory(cat) {
    return cat.replace(/_/g, ' ');
  }

  function render(container) {
    injectStyles();
    container.innerHTML = '<div class="rt-page">' +
      '<div class="rt-header" style="flex-wrap: wrap;">' +
        '<div><h2 style="margin:0;">Red Team Testing</h2>' +
        '<p class="page-subtitle">Test your defenses with adversarial prompt patterns.</p></div>' +
        '<div class="rt-config">' +
          '<span class="autocomplete-wrap"><input type="text" id="rt-target" placeholder="Target identity (e.g. admin-tester)" style="width:180px" autocomplete="off" required></span>' +
          '<span class="autocomplete-wrap"><input type="text" id="rt-roles" placeholder="Roles (comma-sep)" style="width:160px" autocomplete="off"></span>' +
          '<select id="rt-category"><option value="">Full Suite (30 patterns)</option>' +
            '<option value="tool_misuse">Tool Misuse (7)</option>' +
            '<option value="argument_manipulation">Argument Manipulation (7)</option>' +
            '<option value="prompt_injection_direct">Prompt Injection Direct (5)</option>' +
            '<option value="prompt_injection_indirect">Prompt Injection Indirect (5)</option>' +
            '<option value="permission_escalation">Permission Escalation (4)</option>' +
            '<option value="multi_step">Multi-Step Attack (2)</option>' +
          '</select>' +
          '<button class="btn btn-primary" id="rt-run-btn">Run Scan</button>' +
        '</div>' +
        '<button type="button" class="help-btn" id="rt-help-btn">?</button>' +
      '</div>' +
      '<div id="rt-content"><div class="rt-empty"><h3>No scan results yet</h3><p>Configure target and run a red team scan to test your policies.</p></div></div>' +
    '</div>';

    document.getElementById('rt-run-btn').addEventListener('click', runScan);
    document.getElementById('rt-help-btn').addEventListener('click', function() { if (SG.help) SG.help.toggle('redteam'); });
    loadIdentities();
    loadRecentReports().catch(function(err) { console.error('Failed to load recent reports:', err); });
  }

  function loadIdentities() {
    SG.api.get('/identities', { silent: true }).then(function(ids) {
      if (!Array.isArray(ids) || ids.length === 0) return;
      // Build identity items for autocomplete
      var identityItems = [];
      var roleItems = [];
      var seenRoles = {};
      for (var i = 0; i < ids.length; i++) {
        identityItems.push({ name: ids[i].name || ids[i].id });
        var roles = ids[i].roles || [];
        for (var k = 0; k < roles.length; k++) {
          if (!seenRoles[roles[k]]) {
            seenRoles[roles[k]] = true;
            roleItems.push({ name: roles[k] });
          }
        }
      }
      // Wire autocomplete on target identity
      var targetEl = document.getElementById('rt-target');
      if (targetEl && SG.tools && SG.tools.buildAutocomplete) {
        SG.tools.buildAutocomplete(targetEl, function() { return identityItems; }, function() {}, { showAllOnFocus: true });
      }
      // Wire autocomplete on roles
      var rolesEl = document.getElementById('rt-roles');
      if (rolesEl && SG.tools && SG.tools.buildAutocomplete) {
        SG.tools.buildAutocomplete(rolesEl, function() { return roleItems; }, function() {}, { showAllOnFocus: true, commaSeparated: true });
      }
    }).catch(function() { /* ignore — autocomplete is optional */ });
  }

  async function runScan() {
    var btn = document.getElementById('rt-run-btn');
    btn.disabled = true;
    btn.textContent = 'Scanning...';

    var target = document.getElementById('rt-target').value.trim();
    var rolesStr = document.getElementById('rt-roles').value;
    var category = document.getElementById('rt-category').value;
    var roles = rolesStr ? rolesStr.split(',').map(function(r){ return r.trim(); }) : [];

    // BUG-8 FIX: Validate target identity before API call.
    if (!target) {
      btn.disabled = false;
      btn.textContent = 'Run Scan';
      SG.toast.error('Target identity is required. Enter an identity name (e.g. "admin-tester").');
      document.getElementById('rt-target').focus();
      return;
    }

    // Preserve input values — renderReport() doesn't touch the form, but
    // some browsers clear inputs on DOM reflow. Re-set them after scan.
    var savedTarget = target;
    var savedRoles = rolesStr;

    try {
      var body = { target_identity: target, roles: roles };
      if (category) body.category = category;
      var report = await SG.api.post('/v1/redteam/run', body);
      currentReport = report;
      renderReport(report);
    } catch(err) {
      SG.toast.error(err.message || 'Scan failed');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Run Scan';
      // Restore input values in case browser cleared them during DOM update
      var targetEl = document.getElementById('rt-target');
      var rolesEl = document.getElementById('rt-roles');
      if (targetEl && !targetEl.value) targetEl.value = savedTarget;
      if (rolesEl && !rolesEl.value) rolesEl.value = savedRoles;
    }
  }

  function renderReport(report) {
    var content = document.getElementById('rt-content');
    var html = '';

    // Summary KPI strip
    var blockPct = report.corpus_size > 0 ? (report.total_blocked / report.corpus_size * 100).toFixed(1) : 0;
    html += '<div class="rt-summary">';
    html += '<div class="rt-summary-card"><div class="rt-summary-value">' + esc(String(report.corpus_size)) + '</div><div class="rt-summary-label">Patterns Tested</div></div>';
    html += '<div class="rt-summary-card"><div class="rt-summary-value rt-blocked-badge">' + esc(String(report.total_blocked)) + '</div><div class="rt-summary-label">Blocked</div></div>';
    html += '<div class="rt-summary-card"><div class="rt-summary-value rt-passed-badge">' + esc(String(report.total_passed)) + '</div><div class="rt-summary-label">Vulnerabilities</div></div>';
    html += '<div class="rt-summary-card"><div class="rt-summary-value">' + esc(String(blockPct)) + '%</div><div class="rt-summary-label">Block Rate</div></div>';
    html += '</div>';

    // Category scorecard
    if (report.scores && report.scores.length > 0) {
      html += '<div class="rt-scorecard">';
      report.scores.forEach(function(s) {
        var pct = s.total > 0 ? (s.blocked / s.total * 100) : 0;
        var cls = pct >= 90 ? 'good' : (pct >= 50 ? 'warn' : 'bad');
        html += '<div class="rt-score-card">';
        html += '<div class="rt-score-name">' + esc(formatCategory(s.category)) + '</div>';
        html += '<div class="rt-score-bar"><div class="rt-score-fill ' + cls + '" style="width:' + pct + '%"></div></div>';
        html += '<div class="rt-score-stats">' + esc(String(s.blocked)) + '/' + esc(String(s.total)) + ' blocked (' + esc(String(pct.toFixed(0))) + '%)</div>';
        html += '</div>';
      });
      html += '</div>';
    }

    // Vulnerabilities
    if (report.vulnerabilities && report.vulnerabilities.length > 0) {
      html += '<h3 style="margin-bottom:var(--space-3)">Vulnerabilities (' + esc(String(report.vulnerabilities.length)) + ')</h3>';
      html += '<div class="rt-vuln-list">';
      report.vulnerabilities.forEach(function(v, idx) {
        html += renderVulnerability(v, idx);
      });
      html += '</div>';
    } else {
      html += '<div class="rt-empty" style="margin-top:var(--space-4)"><h3 style="color:var(--success)">All attacks blocked!</h3><p>Your policies are blocking all tested attack patterns.</p></div>';
    }

    content.innerHTML = html;
    wireVulnEvents();
  }

  function renderVulnerability(v, idx) {
    var html = '<div class="rt-vuln" data-idx="' + idx + '">';
    html += '<div class="rt-vuln-header" data-toggle="' + idx + '">';
    html += '<div><span class="rt-vuln-title">' + esc(v.pattern_name) + '</span></div>';
    html += '<div class="rt-vuln-badges">';
    var safeSev = ['critical','high','medium','low'].indexOf((v.severity || '').toLowerCase()) >= 0 ? v.severity.toLowerCase() : 'low';
    html += '<span class="rt-sev ' + safeSev + '">' + esc(v.severity) + '</span>';
    html += '<span class="rt-cat">' + esc(formatCategory(v.category)) + '</span>';
    html += '</div></div>';
    html += '<div class="rt-vuln-body" id="rt-vuln-body-' + idx + '">';

    // Explanation
    html += '<div class="rt-detail-section"><div class="rt-detail-title">What happened</div>';
    html += '<div class="rt-detail-box">' + esc(v.description) + '<br><br><strong>Result:</strong> ' + esc(v.reason) + '</div></div>';

    if (v.explanation) {
      html += '<div class="rt-detail-section"><div class="rt-detail-title">Analysis</div>';
      html += '<div class="rt-detail-box">' + esc(v.explanation) + '</div></div>';
    }

    // Remediation
    if (v.remediation) {
      var r = v.remediation;
      var ruleText = 'name: ' + r.name + '\ntool_match: ' + r.tool_match + '\ncondition: ' + r.condition + '\naction: ' + r.action + '\npriority: ' + r.priority;
      html += '<div class="rt-detail-section"><div class="rt-detail-title">Suggested Policy</div>';
      html += '<div class="rt-rule-box">' + esc(ruleText) + '</div>';
      html += '<div class="rt-actions">';
      html += '<button class="btn btn-primary btn-sm" data-apply="' + idx + '">Apply Policy</button>';
      html += '<button class="btn btn-secondary btn-sm" data-edit="' + idx + '">Edit in Builder</button>';
      html += '<button class="btn btn-secondary btn-sm" data-retest="' + idx + '">Re-test</button>';
      html += '</div>';
      html += '<div id="rt-retest-result-' + idx + '"></div>';
      html += '</div>';
    }

    html += '</div></div>';
    return html;
  }

  function wireVulnEvents() {
    // L-22: Use event delegation on the scoped container instead of
    // globally-queried individual listeners to prevent duplicates on re-render.
    var container = document.getElementById('rt-content');
    if (!container) return;

    // Prevent duplicate listeners: renderReport() may be called multiple times
    // (loadRecentReports on page load + each scan). Without this guard,
    // multiple listeners cause classList.toggle to fire N times, cancelling out.
    if (container._sgEventsWired) return;
    container._sgEventsWired = true;

    container.addEventListener('click', function(e) {
      var target = e.target.closest('[data-toggle]');
      if (target) {
        var idx = target.getAttribute('data-toggle');
        var body = document.getElementById('rt-vuln-body-' + idx);
        if (body) body.classList.toggle('open');
        return;
      }

      // Apply Policy (with before/after preview + duplicate prevention)
      var applyBtn = e.target.closest('[data-apply]');
      if (applyBtn) {
        if (applyBtn.disabled) return;
        var applyIdx = parseInt(applyBtn.getAttribute('data-apply'));
        var v = currentReport && currentReport.vulnerabilities[applyIdx];
        if (!v || !v.remediation) return;
        var r = v.remediation;

        // Fetch policies + tools BEFORE showing the dialog so user sees the impact
        applyBtn.textContent = 'Loading...';
        Promise.all([
          SG.api.get('/policies'),
          SG.api.get('/tools', { silent: true }).catch(function() { return { tools: [] }; })
        ]).then(function(results) {
          var policies = results[0];
          var toolsResp = results[1];
          var toolsList = Array.isArray(toolsResp) ? toolsResp : (toolsResp && toolsResp.tools ? toolsResp.tools : []);
          applyBtn.textContent = 'Apply Policy';

          // Check for duplicate
          var exists = (policies || []).some(function(p) {
            return p.rules && p.rules.some(function(rule) { return rule.name === r.name; });
          });
          if (exists) {
            SG.toast.info('Policy "' + r.name + '" already applied');
            applyBtn.textContent = 'Already Applied';
            applyBtn.disabled = true;
            return;
          }

          // Find existing rules that affect the same tool
          var relatedRules = [];
          (policies || []).forEach(function(p) {
            (p.rules || []).forEach(function(rule) {
              if (rule.tool_match === r.tool_match || rule.tool_match === '*' || r.tool_match === '*') {
                relatedRules.push({ policyName: p.name, rule: rule });
              }
            });
          });

          // Build preview body as HTMLElement
          var bodyEl = document.createElement('div');
          bodyEl.style.cssText = 'font-size: var(--text-sm);';

          // New rule section
          var newTitle = document.createElement('h4');
          newTitle.style.cssText = 'margin: 0 0 var(--space-2) 0; font-size: var(--text-sm);';
          newTitle.textContent = 'New Rule';
          bodyEl.appendChild(newTitle);

          var newRule = document.createElement('div');
          newRule.style.cssText = 'padding: var(--space-2); background: var(--bg-secondary); border-radius: var(--radius); margin-bottom: var(--space-3); font-family: var(--font-mono); font-size: var(--text-xs);';
          newRule.textContent = r.action.toUpperCase() + ' "' + r.tool_match + '" when ' + (r.condition || 'true') + ' (priority ' + r.priority + ')';
          bodyEl.appendChild(newRule);

          // Existing rules section
          if (relatedRules.length > 0) {
            var existTitle = document.createElement('h4');
            existTitle.style.cssText = 'margin: 0 0 var(--space-2) 0; font-size: var(--text-sm);';
            existTitle.textContent = 'Existing Rules on "' + r.tool_match + '"';
            bodyEl.appendChild(existTitle);

            for (var ri = 0; ri < relatedRules.length; ri++) {
              var rr = relatedRules[ri];
              var ruleDiv = document.createElement('div');
              ruleDiv.style.cssText = 'padding: var(--space-1) var(--space-2); background: var(--bg-tertiary); border-radius: var(--radius); margin-bottom: var(--space-1); font-family: var(--font-mono); font-size: var(--text-xs); color: var(--text-secondary);';
              ruleDiv.textContent = rr.rule.action.toUpperCase() + ' "' + rr.rule.tool_match + '" (priority ' + rr.rule.priority + ') \u2014 ' + rr.policyName;
              bodyEl.appendChild(ruleDiv);
            }
          } else {
            var noRules = document.createElement('p');
            noRules.style.cssText = 'color: var(--text-muted); margin-bottom: var(--space-3);';
            noRules.textContent = 'No existing rules affect this tool.';
            bodyEl.appendChild(noRules);
          }

          // Impact Preview — show affected tools with before/after status
          var affectedTools = toolsList.filter(function(t) {
            if (r.tool_match === '*') return true;
            if (t.name === r.tool_match) return true;
            if (r.tool_match.indexOf('*') !== -1 || r.tool_match.indexOf('?') !== -1) {
              try {
                var re = new RegExp('^' + r.tool_match.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]') + '$');
                return re.test(t.name);
              } catch(ex) { return false; }
            }
            return false;
          });

          if (affectedTools.length > 0) {
            // Build impact rows first, only show section if any tool actually changes
            var statusLabels = { allow: 'Allow', deny: 'Deny', no_rule: 'No rule', conditional: 'Conditional', approval_required: 'Ask' };
            var impactRows = [];
            for (var ti = 0; ti < affectedTools.length; ti++) {
              var at = affectedTools[ti];
              var before = at.policy_status || 'no_rule';
              // Predict after: if current status has a different action than the new rule → conditional
              var after = before;
              if (before === 'no_rule') {
                after = r.action;
              } else if (before === 'conditional') {
                after = 'conditional';
              } else if (before !== r.action) {
                after = 'conditional';
              }

              if (before === after) continue; // skip unchanged tools

              var impactRow = document.createElement('div');
              impactRow.style.cssText = 'display:flex;align-items:center;gap:var(--space-2);padding:var(--space-1) 0;font-size:var(--text-xs);';
              var toolCode = document.createElement('code');
              toolCode.textContent = at.name;
              impactRow.appendChild(toolCode);

              var arrow = document.createElement('span');
              arrow.style.cssText = 'color:var(--text-muted);';
              var beforeLabel = statusLabels[before] || before;
              var afterLabel = statusLabels[after] || after;
              arrow.innerHTML = '<span style="color:var(--text-secondary)">' + esc(beforeLabel) + '</span> \u2192 <strong style="color:var(--warning)">' + esc(afterLabel) + '</strong>';
              impactRow.appendChild(arrow);
              impactRows.push(impactRow);
            }

            if (impactRows.length > 0) {
              var impactTitle = document.createElement('h4');
              impactTitle.style.cssText = 'margin: var(--space-3) 0 var(--space-2) 0; font-size: var(--text-sm);';
              impactTitle.textContent = 'Impact Preview';
              bodyEl.appendChild(impactTitle);
              for (var ir = 0; ir < impactRows.length; ir++) {
                bodyEl.appendChild(impactRows[ir]);
              }
            }
          }

          // Priority note
          var note = document.createElement('p');
          note.style.cssText = 'margin-top: var(--space-3); font-size: var(--text-xs); color: var(--text-muted);';
          note.textContent = 'Higher priority rules are evaluated first. The new rule (priority ' + r.priority + ') will take precedence over rules with lower priority values.';
          bodyEl.appendChild(note);

          // Footer with buttons
          var footerEl = document.createElement('div');
          footerEl.style.cssText = 'display: flex; gap: var(--space-2); justify-content: flex-end;';

          var cancelBtn = document.createElement('button');
          cancelBtn.className = 'btn btn-secondary';
          cancelBtn.textContent = 'Cancel';
          cancelBtn.addEventListener('click', function() { SG.modal.close(); });
          footerEl.appendChild(cancelBtn);

          var confirmBtn = document.createElement('button');
          confirmBtn.className = 'btn btn-primary';
          confirmBtn.textContent = 'Apply Rule';
          confirmBtn.addEventListener('click', function() {
            confirmBtn.disabled = true;
            confirmBtn.textContent = 'Applying...';
            SG.api.post('/policies', {
              name: r.name,
              enabled: true,
              rules: [{ name: r.name, tool_match: r.tool_match, condition: r.condition, action: r.action, priority: r.priority, source: 'redteam' }]
            }).then(function() {
              SG.modal.close();
              SG.toast.success('Policy "' + r.name + '" applied');
              applyBtn.textContent = 'Applied';
              applyBtn.disabled = true;
            }).catch(function(err) {
              SG.modal.close();
              SG.toast.error(err.message || 'Failed to apply policy');
              applyBtn.disabled = false;
              applyBtn.textContent = 'Apply Policy';
            });
          });
          footerEl.appendChild(confirmBtn);

          // Open modal with full preview
          SG.modal.open({
            title: 'Apply Deny Rule?',
            body: bodyEl,
            footer: footerEl,
            width: '560px'
          });
        }).catch(function(err) {
          applyBtn.textContent = 'Apply Policy';
          SG.toast.error(err.message || 'Failed to load policies');
        });
        return;
      }

      // Edit in Builder
      var editBtn = e.target.closest('[data-edit]');
      if (editBtn) {
        var editIdx = parseInt(editBtn.getAttribute('data-edit'));
        var ev = currentReport && currentReport.vulnerabilities[editIdx];
        if (!ev || !ev.remediation) return;
        var er = ev.remediation;
        if (typeof SG.tools !== 'undefined' && SG.tools.openRuleModal) {
          SG.tools.openRuleModal({ tool_match: er.tool_match, condition: er.condition, action: er.action, name: er.name, priority: er.priority });
        } else {
          window.location.hash = '#/tools';
        }
        return;
      }

      // Re-test
      var retestBtn = e.target.closest('[data-retest]');
      if (retestBtn) {
        var retestIdx = parseInt(retestBtn.getAttribute('data-retest'));
        var rv = currentReport && currentReport.vulnerabilities[retestIdx];
        if (!rv) return;
        var resultEl = document.getElementById('rt-retest-result-' + retestIdx);
        if (!resultEl) return;
        resultEl.innerHTML = '<em>Testing...</em>';
        var rtTarget = document.getElementById('rt-target');
        var rtRoles = document.getElementById('rt-roles');
        var targetVal = rtTarget ? rtTarget.value || '' : '';
        var rolesStr = rtRoles ? rtRoles.value || '' : '';
        // Fallback: use identity/roles from the original scan report
        if (!targetVal && currentReport && currentReport.target_identity) {
          targetVal = currentReport.target_identity;
        }
        var roles = rolesStr ? rolesStr.split(',').map(function(r){ return r.trim(); }) : [];
        if (roles.length === 0 && currentReport && currentReport.roles && currentReport.roles.length > 0) {
          roles = currentReport.roles;
        }
        if (!targetVal) {
          resultEl.innerHTML = '<div class="rt-retest-result fail">Re-test failed: target identity is required. Fill in the identity field above.</div>';
          return;
        }
        SG.api.post('/v1/redteam/run/single', { pattern_id: rv.pattern_id, target_identity: targetVal, roles: roles }).then(function(result) {
          if (result.blocked) {
            resultEl.innerHTML = '<div class="rt-retest-result pass">BLOCKED - Vulnerability fixed!</div>';
          } else {
            resultEl.innerHTML = '<div class="rt-retest-result fail">STILL PASSING - Vulnerability persists</div>';
          }
        }).catch(function(err) {
          resultEl.innerHTML = '<div class="rt-retest-result fail">Re-test failed: ' + esc(err.message) + '</div>';
        });
        return;
      }
    });
  }

  async function loadRecentReports() {
    try {
      var resp = await SG.api.get('/v1/redteam/reports');
      if (resp.reports && resp.reports.length > 0) {
        currentReport = resp.reports[0];
        renderReport(currentReport);
        // Pre-fill form with the report's identity/roles so Re-test works
        var targetEl = document.getElementById('rt-target');
        var rolesEl = document.getElementById('rt-roles');
        if (targetEl && !targetEl.value && currentReport.target_identity) {
          targetEl.value = currentReport.target_identity;
        }
        if (rolesEl && !rolesEl.value && currentReport.roles && currentReport.roles.length > 0) {
          rolesEl.value = currentReport.roles.join(', ');
        }
      }
    } catch(e) { /* ignore */ }
  }

  function cleanup() {
    currentReport = null;
  }

  SG.router.register('redteam', render);
  SG.router.registerCleanup('redteam', cleanup);
})();
