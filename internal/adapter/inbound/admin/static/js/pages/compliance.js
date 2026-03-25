/**
 * compliance.js -- Compliance Coverage Map (Delta 1.1) for SentinelGate admin UI.
 *
 * Displays regulatory requirement coverage as a visual map with colored blocks.
 * Each requirement shows coverage status (covered/partial/gap) with drill-down
 * to individual evidence checks. Supports bundle generation.
 *
 * Data sources:
 *   GET  /admin/api/v1/compliance/packs               -> available policy packs
 *   POST /admin/api/v1/compliance/packs/{id}/coverage  -> coverage analysis
 *   POST /admin/api/v1/compliance/bundles              -> generate evidence bundle
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  var styleInjected = false;

  var CSS = [
    '.compliance-page { padding: var(--space-6); max-width: 1100px; }',
    '.compliance-header { margin-bottom: var(--space-6); }',
    '.compliance-header h1 { font-size: var(--text-2xl); font-weight: var(--font-bold); margin: 0 0 var(--space-1) 0; }',
    '.compliance-header p { font-size: var(--text-sm); color: var(--text-muted); margin: 0; }',

    /* Overall score */
    '.compliance-score-bar { display: flex; align-items: center; gap: var(--space-4); background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-4) var(--space-5); margin-bottom: var(--space-5); }',
    '.compliance-score-number { font-size: var(--text-3xl); font-weight: var(--font-bold); min-width: 80px; }',
    '.compliance-score-number.high { color: var(--success); }',
    '.compliance-score-number.mid { color: var(--warning, #f59e0b); }',
    '.compliance-score-number.low { color: var(--danger); }',
    '.compliance-score-label { font-size: var(--text-sm); color: var(--text-muted); }',
    '.compliance-score-track { flex: 1; height: 12px; background: var(--bg-secondary); border-radius: var(--radius-full); overflow: hidden; }',
    '.compliance-score-fill { height: 100%; border-radius: var(--radius-full); transition: width 0.5s ease; }',
    '.compliance-score-fill.high { background: var(--success); }',
    '.compliance-score-fill.mid { background: var(--warning, #f59e0b); }',
    '.compliance-score-fill.low { background: var(--danger); }',

    /* Requirement grid */
    '.compliance-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: var(--space-4); margin-bottom: var(--space-5); }',
    '.compliance-req { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-4); cursor: pointer; transition: box-shadow 0.15s; border-left: 4px solid transparent; }',
    '.compliance-req:hover { box-shadow: 0 2px 8px rgba(0,0,0,0.08); }',
    '.compliance-req.covered { border-left-color: var(--success); }',
    '.compliance-req.partial { border-left-color: var(--warning, #f59e0b); }',
    '.compliance-req.gap { border-left-color: var(--danger); }',
    '.compliance-req-article { font-size: var(--text-xs); color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: var(--space-1); }',
    '.compliance-req-title { font-size: var(--text-sm); font-weight: var(--font-semibold); margin-bottom: var(--space-2); }',
    '.compliance-req-score { font-size: var(--text-lg); font-weight: var(--font-bold); }',
    '.compliance-req-score.high { color: var(--success); }',
    '.compliance-req-score.mid { color: var(--warning, #f59e0b); }',
    '.compliance-req-score.low { color: var(--danger); }',
    '.compliance-req-bar { height: 6px; background: var(--bg-secondary); border-radius: var(--radius-full); margin-top: var(--space-2); overflow: hidden; }',
    '.compliance-req-bar-fill { height: 100%; border-radius: var(--radius-full); }',

    /* Detail panel */
    '.compliance-detail { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-5); margin-bottom: var(--space-5); }',
    '.compliance-detail h3 { margin: 0 0 var(--space-3) 0; font-size: var(--text-base); }',
    '.compliance-check { display: flex; align-items: flex-start; gap: var(--space-3); padding: var(--space-3) 0; border-bottom: 1px solid var(--border); }',
    '.compliance-check:last-child { border-bottom: none; }',
    '.compliance-check-icon { width: 20px; height: 20px; flex-shrink: 0; margin-top: 2px; }',
    '.compliance-check-icon.pass { color: var(--success); }',
    '.compliance-check-icon.fail { color: var(--danger); }',
    '.compliance-check-desc { font-size: var(--text-sm); font-weight: var(--font-medium); }',
    '.compliance-check-detail { font-size: var(--text-xs); color: var(--text-muted); margin-top: var(--space-1); }',
    '.compliance-check-source { font-size: var(--text-xs); color: var(--text-muted); background: var(--bg-secondary); padding: 1px 6px; border-radius: var(--radius); display: inline-block; margin-top: var(--space-1); }',

    /* Actions */
    '.compliance-actions { display: flex; gap: var(--space-3); margin-top: var(--space-4); }',

    /* Evidence config */
    '.compliance-evidence { background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-4) var(--space-5); margin-bottom: var(--space-5); }',
    '.compliance-evidence h3 { font-size: var(--text-base); font-weight: var(--font-semibold); margin: 0 0 var(--space-2) 0; }',
    '.compliance-evidence-desc { font-size: var(--text-sm); color: var(--text-muted); margin-bottom: var(--space-3); }',
    '.compliance-evidence-toggle { display: flex; align-items: center; gap: var(--space-3); }',
    '.compliance-evidence-toggle label { font-size: var(--text-sm); cursor: pointer; }',
    '.compliance-evidence-warning { font-size: var(--text-xs); color: var(--warning, #f59e0b); margin-top: var(--space-2); display: none; }',
    '.compliance-evidence-status { font-size: var(--text-xs); margin-top: var(--space-2); }',
    '.compliance-evidence-status.active { color: var(--success); }',
    '.compliance-evidence-status.inactive { color: var(--text-muted); }',

    /* Bundle date pickers */
    '.compliance-date-group { display: flex; flex-direction: column; gap: var(--space-1); }',
    '.compliance-date-group label { font-size: var(--text-xs); color: var(--text-muted); }',
    '.compliance-date-input { padding: 6px 8px; border: 1px solid var(--border); border-radius: var(--radius); background: var(--bg-surface); color: var(--text-primary); font-size: var(--text-sm); }',

    /* Disclaimer */
    '.compliance-disclaimer { font-size: var(--text-xs); color: var(--text-muted); background: var(--bg-secondary); padding: var(--space-3); border-radius: var(--radius); margin-top: var(--space-4); line-height: 1.5; }'
  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-compliance', '');
    s.textContent = CSS;
    document.head.appendChild(s);
    styleInjected = true;
  }

  function esc(str) {
    if (!str) return '';
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function scoreClass(score) {
    if (score >= 0.8) return 'high';
    if (score >= 0.4) return 'mid';
    return 'low';
  }

  // -- State --
  var currentReport = null;
  var selectedReqID = null;

  // -- Render --

  function render(container) {
    cleanup();
    injectStyles();
    container.innerHTML =
      '<div class="compliance-page">' +
        '<div class="compliance-header" style="position: relative;">' +
          '<h1>Compliance</h1>' +
          '<button type="button" class="help-btn" style="position: absolute; top: 0; right: 0;">?</button>' +
          '<p class="page-subtitle">Track your security coverage against industry frameworks.</p>' +
          '<p>EU AI Act evidence coverage map. Click a requirement to see evidence checks.</p>' +
        '</div>' +
        '<div id="compliance-content"><p style="color: var(--text-muted);">Loading coverage data...</p></div>' +
      '</div>';
    container.querySelector('.help-btn').addEventListener('click', function() { if (SG.help) SG.help.toggle('compliance'); });

    // Load coverage for the default pack.
    SG.api.post('/v1/compliance/packs/eu-ai-act-transparency/coverage', {}).then(function (report) {
      currentReport = report;
      renderReport(document.getElementById('compliance-content'), report);
    }).catch(function (err) {
      document.getElementById('compliance-content').innerHTML =
        '<p style="color: var(--danger);">Failed to load compliance data: ' + esc(err.message || 'Unknown error') + '</p>';
    });
  }

  function renderReport(el, report) {
    if (!el || !report) return;

    var pct = Math.round((report.overall_score || 0) * 100);
    var cls = scoreClass(report.overall_score || 0);

    var html =
      '<div class="compliance-score-bar">' +
        '<div>' +
          '<div class="compliance-score-number ' + cls + '">' + pct + '%</div>' +
          '<div class="compliance-score-label">Overall Coverage</div>' +
        '</div>' +
        '<div class="compliance-score-track">' +
          '<div class="compliance-score-fill ' + cls + '" style="width: ' + pct + '%;"></div>' +
        '</div>' +
        '<div class="compliance-score-label">' + esc(report.pack_name || '') + '</div>' +
      '</div>';

    // Requirement grid
    html += '<div class="compliance-grid">';
    var reqs = report.requirements || [];
    for (var i = 0; i < reqs.length; i++) {
      var req = reqs[i];
      var reqPct = Math.round((req.score || 0) * 100);
      var reqCls = scoreClass(req.score || 0);
      var statusCls = req.status || 'gap';

      html +=
        '<div class="compliance-req ' + statusCls + '" data-req-id="' + esc(req.requirement_id) + '">' +
          '<div class="compliance-req-article">' + esc(req.article) + '</div>' +
          '<div class="compliance-req-title">' + esc(req.title) + '</div>' +
          '<div class="compliance-req-score ' + reqCls + '">' + reqPct + '%</div>' +
          '<div class="compliance-req-bar"><div class="compliance-req-bar-fill ' + reqCls + '" style="width: ' + reqPct + '%;"></div></div>' +
        '</div>';
    }
    html += '</div>';

    // Detail panel
    html += '<div id="compliance-detail"></div>';

    // Actions: date pickers + bundle button
    html += '<div class="compliance-actions" style="flex-wrap: wrap; align-items: flex-end;">' +
      '<div class="compliance-date-group">' +
        '<label for="bundle-start-date">Start Date</label>' +
        '<input type="date" id="bundle-start-date" class="compliance-date-input">' +
      '</div>' +
      '<div class="compliance-date-group">' +
        '<label for="bundle-end-date">End Date</label>' +
        '<input type="date" id="bundle-end-date" class="compliance-date-input">' +
      '</div>' +
      '<button class="btn btn-primary" id="generate-bundle-btn">Generate Evidence Bundle</button>' +
    '</div>';

    // Evidence config section
    html += '<div class="compliance-evidence">' +
      '<h3>Cryptographic Evidence</h3>' +
      '<div class="compliance-evidence-desc">' +
        'When enabled, every audit record is digitally signed (ECDSA P-256) for tamper detection. ' +
        'Signed records form a hash chain that proves no record was altered or removed after creation.' +
      '</div>' +
      '<div class="compliance-evidence-toggle">' +
        '<input type="checkbox" id="evidence-enabled-toggle">' +
        '<label for="evidence-enabled-toggle">Enable Cryptographic Evidence</label>' +
        '<button class="btn btn-sm btn-primary" id="evidence-save-btn">Save</button>' +
      '</div>' +
      '<div class="compliance-evidence-warning" id="evidence-restart-warning">' +
        'Changes take effect after restart.' +
      '</div>' +
      '<div class="compliance-evidence-status" id="evidence-runtime-status"></div>' +
    '</div>';

    // Disclaimer
    html += '<div class="compliance-disclaimer">' +
      'This coverage map contains technical evidence produced automatically by SentinelGate. ' +
      'It does not constitute legal advice nor certification of compliance. ' +
      'Compliance assessment requires independent legal analysis.' +
    '</div>';

    el.innerHTML = html;

    // Wire evidence toggle.
    (function () {
      var toggle = document.getElementById('evidence-enabled-toggle');
      var saveBtn = document.getElementById('evidence-save-btn');
      var warning = document.getElementById('evidence-restart-warning');
      var statusEl = document.getElementById('evidence-runtime-status');
      if (!toggle || !saveBtn) return;

      // Load current state.
      SG.api.get('/v1/compliance/evidence').then(function (data) {
        toggle.checked = !!data.enabled;
        if (data.runtime_on) {
          statusEl.textContent = 'Currently active (signing audit records)';
          statusEl.className = 'compliance-evidence-status active';
        } else {
          statusEl.textContent = 'Currently inactive';
          statusEl.className = 'compliance-evidence-status inactive';
        }
        // Show warning if saved state differs from runtime.
        if (data.enabled !== data.runtime_on) {
          warning.style.display = 'block';
        }
      }).catch(function () { /* ignore load failure */ });

      saveBtn.addEventListener('click', function () {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving...';
        SG.api.put('/v1/compliance/evidence', { enabled: toggle.checked }).then(function (data) {
          saveBtn.disabled = false;
          saveBtn.textContent = 'Save';
          SG.toast.success('Evidence configuration saved');
          // Show restart warning if saved != runtime.
          if (data.enabled !== data.runtime_on) {
            warning.style.display = 'block';
          } else {
            warning.style.display = 'none';
          }
        }).catch(function (err) {
          saveBtn.disabled = false;
          saveBtn.textContent = 'Save';
          SG.toast.error('Failed to save: ' + (err.message || 'Unknown error'));
        });
      });
    })();

    // Wire requirement clicks.
    var reqCards = el.querySelectorAll('.compliance-req');
    for (var j = 0; j < reqCards.length; j++) {
      (function (card) {
        card.addEventListener('click', function () {
          var reqId = card.getAttribute('data-req-id');
          selectedReqID = reqId;
          renderDetail(reqId);
          // Highlight selected
          var all = el.querySelectorAll('.compliance-req');
          for (var k = 0; k < all.length; k++) {
            all[k].style.boxShadow = '';
          }
          card.style.boxShadow = '0 0 0 2px var(--primary)';
        });
      })(reqCards[j]);
    }

    // Set default date range (last 7 days).
    var startDateEl = document.getElementById('bundle-start-date');
    var endDateEl = document.getElementById('bundle-end-date');
    if (startDateEl && endDateEl) {
      var now = new Date();
      var sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      endDateEl.value = now.toISOString().slice(0, 10);
      startDateEl.value = sevenDaysAgo.toISOString().slice(0, 10);
    }

    // Wire bundle generation.
    var bundleBtn = document.getElementById('generate-bundle-btn');
    if (bundleBtn) {
      bundleBtn.addEventListener('click', function () {
        bundleBtn.disabled = true;
        bundleBtn.textContent = 'Generating...';
        var payload = { pack_id: report.pack_id };
        // Pass user-selected date range as RFC3339.
        if (startDateEl && startDateEl.value) {
          payload.start_time = new Date(startDateEl.value + 'T00:00:00Z').toISOString();
        }
        if (endDateEl && endDateEl.value) {
          payload.end_time = new Date(endDateEl.value + 'T23:59:59Z').toISOString();
        }
        SG.api.post('/v1/compliance/bundles', payload).then(function (bundle) {
          bundleBtn.disabled = false;
          bundleBtn.textContent = 'Generate Evidence Bundle';
          SG.toast.success('Bundle generated: ' + bundle.id);
          // Download as JSON.
          var blob = new Blob([JSON.stringify(bundle, null, 2)], {type: 'application/json'});
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          a.href = url;
          a.download = bundle.id + '.json';
          a.click();
          URL.revokeObjectURL(url);
        }).catch(function (err) {
          bundleBtn.disabled = false;
          bundleBtn.textContent = 'Generate Evidence Bundle';
          SG.toast.error('Bundle generation failed: ' + (err.message || 'Unknown error'));
        });
      });
    }

    // Auto-select first requirement.
    if (reqs.length > 0) {
      selectedReqID = reqs[0].requirement_id;
      renderDetail(selectedReqID);
      if (reqCards.length > 0) {
        reqCards[0].style.boxShadow = '0 0 0 2px var(--primary)';
      }
    }
  }

  function renderDetail(reqId) {
    var detailEl = document.getElementById('compliance-detail');
    if (!detailEl || !currentReport) return;

    var reqs = currentReport.requirements || [];
    var req = null;
    for (var i = 0; i < reqs.length; i++) {
      if (reqs[i].requirement_id === reqId) {
        req = reqs[i];
        break;
      }
    }
    if (!req) {
      detailEl.innerHTML = '';
      return;
    }

    var checkIcon = function (passed) {
      if (passed) {
        return '<svg class="compliance-check-icon pass" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
      }
      return '<svg class="compliance-check-icon fail" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
    };

    var html = '<div class="compliance-detail">' +
      '<h3>' + esc(req.article) + ' — ' + esc(req.title) + '</h3>';

    var checks = req.check_results || [];
    for (var j = 0; j < checks.length; j++) {
      var check = checks[j];
      html += '<div class="compliance-check">' +
        checkIcon(check.passed) +
        '<div>' +
          '<div class="compliance-check-desc">' + esc(check.description) + '</div>' +
          '<div class="compliance-check-detail">' + esc(check.detail) + '</div>' +
          (check.source ? '<span class="compliance-check-source">' + esc(check.source) + '</span>' : '') +
        '</div>' +
      '</div>';
    }

    html += '</div>';
    detailEl.innerHTML = html;
  }

  function cleanup() {
    currentReport = null;
    selectedReqID = null;
  }

  SG.router.register('compliance', render);
  SG.router.registerCleanup('compliance', cleanup);
})();
