/**
 * notifications.js -- Notification & Action Center (UX-F3) + Diff Viewer (Delta 1.3)
 *
 * Features:
 *   - Real-time notification feed via SSE
 *   - Action Queue: notifications requiring action shown first
 *   - Badge counter in sidebar (updated via SSE)
 *   - Dismiss single / dismiss all
 *   - Tool Integrity Diff Viewer modal (Delta 1.3)
 *   - Inline actions (accept change, quarantine, navigate)
 *
 * Data sources:
 *   GET  /admin/api/v1/notifications          -> notification list
 *   GET  /admin/api/v1/notifications/count     -> badge counter
 *   GET  /admin/api/v1/notifications/stream    -> SSE real-time
 *   POST /admin/api/v1/notifications/{id}/dismiss
 *   POST /admin/api/v1/notifications/dismiss-all
 *   GET  /admin/api/v1/tools/drift             -> tool diff data
 *   POST /admin/api/v1/tools/accept-change     -> accept tool change
 *   POST /admin/api/v1/tools/quarantine        -> quarantine tool
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  var styleInjected = false;
  var notifications = [];
  var eventSource = null;
  // L-14: AbortController to cancel in-flight fetch requests on page navigation
  var pageAbortController = null;

  // L-13: Allowlist of known routes for notification action targets
  var KNOWN_ROUTES = [
    '#/dashboard', '#/tools', '#/access', '#/audit', '#/notifications',
    '#/sessions', '#/agents', '#/security', '#/compliance', '#/finops',
    '#/redteam', '#/getting-started', '#/onboarding'
  ];

  /**
   * L-13: Validate a navigation target against known routes.
   * Accepts exact matches or known routes with query params (e.g. '#/security?tab=scanning').
   */
  function isKnownRoute(target) {
    if (!target || typeof target !== 'string') return false;
    // Extract the path portion before any query string
    var path = target.split('?')[0];
    for (var i = 0; i < KNOWN_ROUTES.length; i++) {
      if (path === KNOWN_ROUTES[i]) return true;
    }
    return false;
  }

  // -- Styles ---------------------------------------------------------------

  var NOTIF_CSS = [
    '.notif-page { max-width: 800px; }',
    '.notif-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-6); }',
    '.notif-header h1 { font-size: var(--text-2xl); font-weight: var(--font-bold); color: var(--text-primary); margin: 0; }',
    '.notif-section-title { font-size: var(--text-xs); font-weight: var(--font-semibold); text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: var(--space-2); margin-top: var(--space-4); }',
    '.notif-card { background: var(--bg-primary); border: 1px solid var(--border); border-radius: var(--radius-lg); padding: var(--space-3) var(--space-4); margin-bottom: var(--space-2); transition: border-color var(--transition-fast); }',
    '.notif-card:hover { border-color: var(--accent); }',
    '.notif-card.severity-critical { border-left: 3px solid var(--danger); }',
    '.notif-card.severity-warning { border-left: 3px solid #f59e0b; }',
    '.notif-card.severity-info { border-left: 3px solid var(--accent); }',
    '.notif-card-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-1); }',
    '.notif-card-source { font-size: var(--text-xs); font-weight: var(--font-semibold); text-transform: uppercase; color: var(--text-muted); }',
    '.notif-card-time { font-size: var(--text-xs); color: var(--text-muted); }',
    '.notif-card-title { font-size: var(--text-sm); font-weight: var(--font-semibold); color: var(--text-primary); margin-bottom: var(--space-1); }',
    '.notif-card-message { font-size: var(--text-sm); color: var(--text-secondary); margin-bottom: var(--space-2); }',
    '.notif-card-actions { display: flex; gap: var(--space-2); flex-wrap: wrap; }',
    '.notif-action-btn { padding: 4px 12px; font-size: var(--text-xs); font-weight: var(--font-medium); border-radius: var(--radius-md); cursor: pointer; transition: all var(--transition-fast); border: 1px solid var(--border); background: var(--bg-secondary); color: var(--text-primary); }',
    '.notif-action-btn:hover { border-color: var(--accent); background: var(--accent-subtle); }',
    '.notif-action-btn.primary { background: var(--accent); color: white; border-color: var(--accent); }',
    '.notif-action-btn.danger { background: var(--danger); color: white; border-color: var(--danger); }',
    '.notif-dismiss-btn { padding: 2px 8px; font-size: 11px; color: var(--text-muted); background: none; border: none; cursor: pointer; }',
    '.notif-dismiss-btn:hover { color: var(--text-primary); }',
    '.notif-empty { text-align: center; padding: var(--space-8); color: var(--text-muted); }',
    '.notif-live-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: #22c55e; margin-right: var(--space-2); animation: pulse 2s ease-in-out infinite; }',
    '.notif-live-dot.disconnected { background: var(--text-muted); animation: none; }',
    /* Badge in sidebar */
    '.nav-badge { display: inline-flex; align-items: center; justify-content: center; min-width: 18px; height: 18px; padding: 0 5px; font-size: 11px; font-weight: var(--font-bold); color: white; background: var(--danger); border-radius: var(--radius-full); margin-left: auto; }',
    '.nav-badge.empty { display: none; }',
    '.nav-badge.nav-badge-info { background: #3b82f6; font-size: 10px; }',
    /* Diff viewer */
    '.diff-container { display: grid; grid-template-columns: 1fr 1fr; gap: var(--space-3); }',
    '.diff-panel { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: var(--radius-md); padding: var(--space-3); font-family: var(--font-mono); font-size: var(--text-xs); white-space: pre-wrap; word-break: break-word; line-height: 1.6; max-height: 400px; overflow-y: auto; }',
    '.diff-panel-title { font-family: inherit; font-size: var(--text-xs); font-weight: var(--font-semibold); text-transform: uppercase; color: var(--text-muted); margin-bottom: var(--space-2); }',
    '.diff-added { background: rgba(34,197,94,0.15); color: #16a34a; }',
    '.diff-removed { background: rgba(239,68,68,0.15); color: var(--danger); }',
    '.diff-risk { margin-top: var(--space-3); padding: var(--space-3); border-radius: var(--radius-md); font-size: var(--text-sm); }',
    '.diff-risk.high { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: var(--danger); }',
    '.diff-risk.medium { background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); color: #b45309; }',
    '.diff-risk.low { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); color: #16a34a; }',
    /* Escrow Decision Context (Delta 2.3) */
    '.escrow-section { margin-bottom: var(--space-4); }',
    '.escrow-section-title { font-size: var(--text-xs); font-weight: var(--font-semibold); text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: var(--space-2); padding-bottom: var(--space-1); border-bottom: 1px solid var(--border); }',
    '.escrow-timeout { font-size: var(--text-sm); font-weight: var(--font-bold); color: var(--danger); float: right; }',
    '.escrow-detail-grid { display: grid; grid-template-columns: auto 1fr; gap: var(--space-1) var(--space-3); font-size: var(--text-sm); }',
    '.escrow-detail-label { color: var(--text-muted); font-weight: var(--font-medium); }',
    '.escrow-detail-value { color: var(--text-primary); word-break: break-word; }',
    '.escrow-args { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: var(--radius-md); padding: var(--space-2); font-family: var(--font-mono); font-size: var(--text-xs); white-space: pre-wrap; max-height: 120px; overflow-y: auto; margin-top: var(--space-1); }',
    '.escrow-trail { list-style: none; padding: 0; margin: 0; }',
    '.escrow-trail li { display: flex; align-items: center; gap: var(--space-2); padding: var(--space-1) 0; font-size: var(--text-sm); border-bottom: 1px solid var(--border-light, rgba(255,255,255,0.05)); }',
    '.escrow-trail li:last-child { border-bottom: none; }',
    '.escrow-trail-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }',
    '.escrow-trail-dot.allow { background: #22c55e; }',
    '.escrow-trail-dot.deny { background: var(--danger); }',
    '.escrow-trail-dot.hold { background: #f59e0b; }',
    '.escrow-trail-time { color: var(--text-muted); font-size: var(--text-xs); min-width: 50px; }',
    '.escrow-trail-tool { font-weight: var(--font-medium); color: var(--text-primary); }',
    '.escrow-trail-badge { font-size: 10px; padding: 1px 6px; border-radius: var(--radius-full); font-weight: var(--font-semibold); }',
    '.escrow-trail-badge.allow { background: rgba(34,197,94,0.15); color: #16a34a; }',
    '.escrow-trail-badge.deny { background: rgba(239,68,68,0.15); color: var(--danger); }',
    '.escrow-trail-badge.hold { background: rgba(245,158,11,0.15); color: #b45309; }',
    '.escrow-history-item { font-size: var(--text-sm); padding: var(--space-1) 0; color: var(--text-secondary); }',
    '.escrow-assessment { list-style: none; padding: 0; margin: 0; }',
    '.escrow-assessment li { padding: var(--space-1) 0; font-size: var(--text-sm); color: var(--text-secondary); }',
    '.escrow-assessment li::before { content: "\\2022 "; color: var(--text-muted); margin-right: var(--space-1); }',
    '.escrow-note-input { width: 100%; padding: var(--space-2); font-size: var(--text-sm); border: 1px solid var(--border); border-radius: var(--radius-md); background: var(--bg-secondary); color: var(--text-primary); resize: vertical; min-height: 48px; margin-top: var(--space-2); }',
    '.escrow-actions { display: flex; gap: var(--space-2); justify-content: flex-end; margin-top: var(--space-3); }',
    '.escrow-actions .btn-approve { background: #22c55e; color: white; border: none; }',
    '.escrow-actions .btn-approve:hover { background: #16a34a; }',
    '.escrow-actions .btn-deny { background: var(--danger); color: white; border: none; }',
    '.escrow-actions .btn-deny:hover { background: #b91c1c; }'
  ];

  function injectStyles() {
    if (styleInjected) return;
    styleInjected = true;
    var style = document.createElement('style');
    style.textContent = NOTIF_CSS.join('\n');
    document.head.appendChild(style);
  }

  function mk(tag, className, attrs) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (attrs) {
      var keys = Object.keys(attrs);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (k === 'style') node.style.cssText = attrs[k];
        else node.setAttribute(k, attrs[k]);
      }
    }
    return node;
  }

  // -- Badge ----------------------------------------------------------------

  function updateBadge() {
    SG.api.get('/v1/notifications/count').then(function (data) {
      var badge = document.getElementById('notif-badge');
      if (!badge) return;
      var total = data.total || 0;
      var actionCount = data.actions || 0;
      if (total <= 0) {
        badge.textContent = '';
        badge.className = 'nav-badge empty';
      } else if (actionCount > 0) {
        badge.textContent = String(total);
        badge.className = 'nav-badge';
      } else {
        badge.textContent = String(total);
        badge.className = 'nav-badge nav-badge-info';
      }
    }).catch(function () {});
  }

  // Inject badge into sidebar on first load.
  function ensureBadge() {
    if (document.getElementById('notif-badge')) return;
    var navItem = document.querySelector('a[data-page="notifications"]');
    if (!navItem) return;
    var badge = mk('span', 'nav-badge empty');
    badge.id = 'notif-badge';
    navItem.appendChild(badge);
  }

  // -- SSE ------------------------------------------------------------------

  function startSSE() {
    if (typeof EventSource === 'undefined') return;
    if (eventSource) { eventSource.close(); eventSource = null; }

    eventSource = new EventSource(SG.api.BASE + '/v1/notifications/stream');

    eventSource.onerror = function () {
      var dot = document.getElementById('notif-live-dot');
      if (dot) dot.className = 'notif-live-dot disconnected';
    };

    eventSource.onmessage = function (evt) {
      try {
        var notif = JSON.parse(evt.data);
        // Deduplicate by ID.
        var found = false;
        for (var i = 0; i < notifications.length; i++) {
          if (notifications[i].id === notif.id) { found = true; break; }
        }
        if (!found) {
          notifications.unshift(notif);
          if (notifications.length > 200) notifications = notifications.slice(0, 200);
        }
        renderPage();
        updateBadge();
      } catch (e) { /* ignore parse errors */ }
    };
  }

  function stopSSE() {
    if (eventSource) { eventSource.close(); eventSource = null; }
  }

  // -- Time formatting ------------------------------------------------------

  function timeAgo(ts) {
    var diff = (Date.now() - new Date(ts).getTime()) / 1000;
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  }

  // -- Rendering ------------------------------------------------------------

  var pageRoot = null;

  function renderPage() {
    if (!pageRoot) return;
    var container = pageRoot.querySelector('.notif-content');
    if (!container) return;
    container.innerHTML = '';

    var actionNotifs = notifications.filter(function (n) { return n.requires_action && !n.dismissed; });
    var infoNotifs = notifications.filter(function (n) { return !n.requires_action && !n.dismissed; });

    if (actionNotifs.length === 0 && infoNotifs.length === 0) {
      var empty = mk('div', 'notif-empty');
      empty.textContent = 'All clear! Alerts and approval requests will appear here when they need your attention.';
      container.appendChild(empty);
      return;
    }

    if (actionNotifs.length > 0) {
      var actionTitle = mk('div', 'notif-section-title');
      actionTitle.textContent = 'ACTIONS REQUIRED (' + actionNotifs.length + ')';
      container.appendChild(actionTitle);
      for (var a = 0; a < actionNotifs.length; a++) {
        container.appendChild(renderCard(actionNotifs[a]));
      }
    }

    if (infoNotifs.length > 0) {
      var infoTitle = mk('div', 'notif-section-title');
      infoTitle.textContent = 'INFORMATIONAL (' + infoNotifs.length + ')';
      container.appendChild(infoTitle);
      for (var b = 0; b < infoNotifs.length; b++) {
        container.appendChild(renderCard(infoNotifs[b]));
      }
    }
  }

  function renderCard(notif) {
    var card = mk('div', 'notif-card severity-' + notif.severity);

    var header = mk('div', 'notif-card-header');
    var source = mk('span', 'notif-card-source');
    var rawSource = (notif.source || notif.type || '').toUpperCase();
    // Display-friendly names for notification sources
    var sourceDisplayMap = { 'FINOPS': 'COST TRACKING' };
    source.textContent = sourceDisplayMap[rawSource] || rawSource;
    header.appendChild(source);
    if (notif.count > 1) {
      var countBadge = mk('span', 'badge badge-neutral', { style: 'font-size:var(--text-xs);margin-left:var(--space-1)' });
      countBadge.textContent = '\u00d7' + notif.count;
      header.appendChild(countBadge);
    }

    var timeEl = mk('span', 'notif-card-time');
    timeEl.textContent = timeAgo(notif.timestamp);
    header.appendChild(timeEl);
    card.appendChild(header);

    var title = mk('div', 'notif-card-title');
    title.textContent = notif.title || notif.type;
    card.appendChild(title);

    if (notif.message) {
      var msg = mk('div', 'notif-card-message');
      msg.textContent = notif.message;
      card.appendChild(msg);
    }

    // Action buttons.
    var actions = mk('div', 'notif-card-actions');
    if (notif.actions && notif.actions.length > 0) {
      for (var i = 0; i < notif.actions.length; i++) {
        var act = notif.actions[i];
        var btn = mk('button', 'notif-action-btn' + (i === 0 ? ' primary' : ''));
        btn.textContent = act.label;
        (function (action, target, nid) {
          btn.addEventListener('click', function () {
            handleAction(action, target, nid);
          });
        })(act.action, act.target, notif.id);
        actions.appendChild(btn);
      }
    }

    // Dismiss button.
    var dismissBtn = mk('button', 'notif-dismiss-btn');
    dismissBtn.textContent = 'Dismiss';
    dismissBtn.addEventListener('click', function () {
      // L-12: URI-encode notification ID to prevent malformed URL paths
      SG.api.post('/v1/notifications/' + encodeURIComponent(notif.id) + '/dismiss').then(function () {
        notif.dismissed = true;
        renderPage();
        updateBadge();
      }).catch(function () {});
    });
    actions.appendChild(dismissBtn);

    card.appendChild(actions);
    return card;
  }

  // -- Action handlers ------------------------------------------------------

  function handleAction(action, target, notifId) {
    switch (action) {
      case 'navigate':
        // L-13: Validate target against allowlist of known routes before navigating
        if (target && isKnownRoute(target)) {
          window.location.hash = target;
        }
        break;
      case 'accept_change':
        // Extract tool name from notification payload.
        var notif = notifications.find(function (n) { return n.id === notifId; });
        var toolName = notif && notif.payload && notif.payload.tool_name;
        if (toolName) {
          SG.api.post('/v1/tools/accept-change', { tool_name: toolName }).then(function () {
            SG.toast.success('Change accepted for ' + toolName);
            dismissNotif(notifId);
          }).catch(function (err) {
            SG.toast.error(err.message || 'Failed to accept change');
          });
        }
        break;
      case 'quarantine':
        var notif2 = notifications.find(function (n) { return n.id === notifId; });
        var tool = notif2 && notif2.payload && notif2.payload.tool_name;
        if (tool) {
          SG.api.post('/v1/tools/quarantine', { tool_name: tool }).then(function () {
            SG.toast.success(tool + ' quarantined');
            dismissNotif(notifId);
          }).catch(function (err) {
            SG.toast.error(err.message || 'Failed to quarantine');
          });
        }
        break;
      case 'view_diff':
        openDiffViewer(target);
        break;
      case 'approval_review':
        openApprovalContext(target, notifId);
        break;
      case 'approval_approve':
        quickApproval(target, notifId, true);
        break;
      case 'approval_deny':
        quickApproval(target, notifId, false);
        break;
      case 'content_whitelist':
        window.location.hash = '#/security?tab=scanning';
        break;
      case 'drift_policy':
        // "Crea Policy da Anomalia" — opens Policy Builder pre-filled
        // Navigate to tools page, then open rule modal with pre-compiled CEL
        window.location.hash = '#/tools';
        setTimeout(function () {
          if (SG.tools && SG.tools.openRuleModal) {
            // Pre-fill with a deny rule for the drifting identity
            SG.tools.openRuleModal(null, null, '*');
          }
        }, 500);
        break;
    }
  }

  function dismissNotif(id) {
    // L-12: URI-encode notification ID to prevent malformed URL paths
    SG.api.post('/v1/notifications/' + encodeURIComponent(id) + '/dismiss').then(function () {
      var n = notifications.find(function (x) { return x.id === id; });
      if (n) n.dismissed = true;
      renderPage();
      updateBadge();
    }).catch(function () {});
  }

  // -- Diff Viewer (Delta 1.3) ----------------------------------------------

  function openDiffViewer(toolName) {
    SG.api.get('/v1/tools/drift').then(function (data) {
      var drifts = data.drifts || data || [];
      var drift = null;
      for (var i = 0; i < drifts.length; i++) {
        if (drifts[i].tool_name === toolName) {
          drift = drifts[i];
          break;
        }
      }

      if (!drift) {
        SG.toast.info('No changes found for ' + toolName);
        return;
      }

      var body = mk('div');

      // Side-by-side diff.
      var diffContainer = mk('div', 'diff-container');

      var beforePanel = mk('div', 'diff-panel');
      var beforeTitle = mk('div', 'diff-panel-title');
      beforeTitle.textContent = 'BEFORE (baseline)';
      beforePanel.appendChild(beforeTitle);
      var beforeCode = mk('pre');
      beforeCode.textContent = formatToolDef(drift.baseline);
      beforePanel.appendChild(beforeCode);
      diffContainer.appendChild(beforePanel);

      var afterPanel = mk('div', 'diff-panel');
      var afterTitle = mk('div', 'diff-panel-title');
      afterTitle.textContent = 'AFTER (current)';
      afterPanel.appendChild(afterTitle);
      var afterCode = mk('pre');
      afterCode.textContent = formatToolDef(drift.current);
      afterPanel.appendChild(afterCode);
      diffContainer.appendChild(afterPanel);

      body.appendChild(diffContainer);

      // Risk assessment.
      var risk = assessRisk(drift);
      if (risk.level !== 'low') {
        var riskDiv = mk('div', 'diff-risk ' + risk.level);
        riskDiv.textContent = risk.icon + ' ' + risk.message;
        body.appendChild(riskDiv);
      }

      // Footer.
      var footer = mk('div', '', { style: 'display: contents;' });
      var closeBtn = mk('button', 'btn btn-secondary');
      closeBtn.type = 'button';
      closeBtn.textContent = 'Close';
      closeBtn.addEventListener('click', function () { SG.modal.close(); });
      footer.appendChild(closeBtn);

      var acceptBtn = mk('button', 'btn btn-primary');
      acceptBtn.textContent = 'Accept Change';
      acceptBtn.addEventListener('click', function () {
        SG.api.post('/v1/tools/accept-change', { tool_name: toolName }).then(function () {
          SG.toast.success('Change accepted');
          SG.modal.close();
        }).catch(function (err) { SG.toast.error(err.message); });
      });
      footer.appendChild(acceptBtn);

      var quarBtn = mk('button', 'btn btn-secondary');
      quarBtn.style.cssText = 'color: var(--danger); border-color: var(--danger);';
      quarBtn.textContent = 'Quarantine';
      quarBtn.addEventListener('click', function () {
        SG.api.post('/v1/tools/quarantine', { tool_name: toolName }).then(function () {
          SG.toast.success(toolName + ' quarantined');
          SG.modal.close();
        }).catch(function (err) { SG.toast.error(err.message); });
      });
      footer.appendChild(quarBtn);

      SG.modal.open({
        title: 'Tool Integrity — ' + toolName,
        body: body,
        footer: footer,
        width: '800px'
      });
    }).catch(function (err) {
      SG.toast.error(err.message || 'Failed to load drift data');
    });
  }

  function formatToolDef(def) {
    if (!def) return '(not available)';
    if (typeof def === 'string') return def;
    try {
      return JSON.stringify(def, null, 2);
    } catch (e) {
      return String(def);
    }
  }

  function assessRisk(drift) {
    if (!drift || !drift.current) return { level: 'low', icon: '', message: '' };

    var desc = '';
    if (typeof drift.current === 'object' && drift.current.description) {
      desc = drift.current.description.toLowerCase();
    } else if (typeof drift.current === 'string') {
      desc = drift.current.toLowerCase();
    }

    // Check for tool poisoning patterns.
    var poisonPatterns = ['read', 'include', 'file', 'exec', 'eval', 'ssh', 'password', 'secret', 'credential', 'token', 'curl', 'wget', 'base64'];
    var matches = 0;
    for (var i = 0; i < poisonPatterns.length; i++) {
      if (desc.indexOf(poisonPatterns[i]) !== -1) matches++;
    }

    if (matches >= 3) {
      return { level: 'high', icon: '!!', message: 'RISK HIGH — Tool Poisoning Pattern Detected. The new description contains suspicious operational instructions.' };
    }
    if (matches >= 1) {
      return { level: 'medium', icon: '!', message: 'RISK MEDIUM — Description contains potentially sensitive keywords. Review carefully.' };
    }
    return { level: 'low', icon: '', message: '' };
  }

  // -- Escrow Decision Context (Delta 2.3) ------------------------------------

  function quickApproval(approvalId, notifId, approve) {
    var endpoint = approve
      ? '/v1/approvals/' + encodeURIComponent(approvalId) + '/approve'
      : '/v1/approvals/' + encodeURIComponent(approvalId) + '/deny';
    var body = approve ? {} : { reason: 'denied by admin' };
    SG.api.post(endpoint, body).then(function () {
      SG.toast.success(approve ? 'Approved' : 'Denied');
      dismissNotif(notifId);
    }).catch(function (err) {
      SG.toast.error(err.message || 'Action failed');
    });
  }

  function openApprovalContext(approvalId, notifId) {
    // L-14: Pass AbortController signal to cancel fetch on page navigation
    var signal = pageAbortController ? pageAbortController.signal : undefined;
    SG.api.get('/v1/approvals/' + encodeURIComponent(approvalId) + '/context', { signal: signal }).then(function (data) {
      // M-32: if user navigated away during fetch, don't open modal on wrong page
      if (SG.router.currentPage !== 'notifications') return;
      renderApprovalContextModal(data, approvalId, notifId);
    }).catch(function (err) {
      if (err && err.name === 'AbortError') return; // L-14: silently ignore aborted requests
      if (SG.router.currentPage !== 'notifications') return;
      SG.toast.error(err.message || 'Failed to load approval context');
    });
  }

  function renderApprovalContextModal(data, approvalId, notifId) {
    var body = mk('div');
    var req = data.request || {};

    // --- Timeout countdown ---
    var timeoutDiv = mk('div', 'escrow-timeout');
    timeoutDiv.id = 'escrow-countdown';
    var remaining = (req.timeout_secs || 300) - Math.floor((Date.now() - new Date(req.created_at).getTime()) / 1000);
    if (remaining < 0) remaining = 0;
    timeoutDiv.textContent = 'Timeout: ' + formatCountdown(remaining);
    body.appendChild(timeoutDiv);

    // Start countdown
    var countdownInterval = setInterval(function () {
      remaining--;
      if (remaining <= 0) {
        clearInterval(countdownInterval);
        timeoutDiv.textContent = 'Timed out';
        return;
      }
      timeoutDiv.textContent = 'Timeout: ' + formatCountdown(remaining);
    }, 1000);

    // --- Request Detail ---
    var reqSection = mk('div', 'escrow-section');
    var reqTitle = mk('div', 'escrow-section-title');
    reqTitle.textContent = 'REQUEST';
    reqSection.appendChild(reqTitle);

    var grid = mk('div', 'escrow-detail-grid');
    addDetailRow(grid, 'Agent', (req.identity_name || req.identity_id || 'Unknown') + (req.identity_id ? ' (' + req.identity_id + ')' : ''));
    addDetailRow(grid, 'Tool', req.tool_name);
    addDetailRow(grid, 'Policy', (req.rule_name || req.rule_id || 'unknown'));
    if (req.condition) {
      addDetailRow(grid, 'Hold reason', req.condition);
    }
    reqSection.appendChild(grid);

    if (req.arguments && Object.keys(req.arguments).length > 0) {
      var argsDiv = mk('div', 'escrow-args');
      argsDiv.textContent = JSON.stringify(req.arguments, null, 2);
      reqSection.appendChild(argsDiv);
    }
    body.appendChild(reqSection);

    // --- Session Trail ---
    var trail = data.session_trail || [];
    if (trail.length > 0) {
      var trailSection = mk('div', 'escrow-section');
      var trailTitle = mk('div', 'escrow-section-title');
      trailTitle.textContent = 'SESSION TRAIL';
      trailSection.appendChild(trailTitle);

      var trailList = mk('ul', 'escrow-trail');
      for (var i = 0; i < trail.length; i++) {
        var item = trail[i];
        var li = mk('li');
        var trailStatus = item.status || item.decision || 'unknown';
        var dot = mk('span', 'escrow-trail-dot ' + trailStatus);
        li.appendChild(dot);
        var ts = mk('span', 'escrow-trail-time');
        ts.textContent = formatTime(item.timestamp);
        li.appendChild(ts);
        var toolSpan = mk('span', 'escrow-trail-tool');
        toolSpan.textContent = item.tool_name;
        li.appendChild(toolSpan);
        var badge = mk('span', 'escrow-trail-badge ' + trailStatus);
        badge.textContent = trailStatus.toUpperCase();
        li.appendChild(badge);
        trailList.appendChild(li);
      }
      trailSection.appendChild(trailList);
      body.appendChild(trailSection);
    }

    // --- Agent History ---
    var hist = data.agent_history || {};
    var histSection = mk('div', 'escrow-section');
    var histTitle = mk('div', 'escrow-section-title');
    histTitle.textContent = 'AGENT HISTORY WITH THIS TOOL';
    histSection.appendChild(histTitle);

    var histInfo = mk('div', 'escrow-history-item');
    if (hist.tool_use_count === 0) {
      histInfo.textContent = req.tool_name + ': never used by ' + req.identity_name;
    } else {
      histInfo.textContent = req.tool_name + ': used ' + hist.tool_use_count + ' times in last 30 days';
      if (hist.last_used) {
        histInfo.textContent += ' (last: ' + formatTime(hist.last_used) + ')';
      }
    }
    histSection.appendChild(histInfo);

    if (hist.similar_tool_uses && hist.similar_tool_uses.length > 0) {
      var simTitle = mk('div', 'escrow-history-item');
      simTitle.style.cssText = 'margin-top: var(--space-1); font-weight: var(--font-medium);';
      simTitle.textContent = 'Similar tools (' + hist.similar_tool_uses.length + '):';
      histSection.appendChild(simTitle);
      for (var s = 0; s < Math.min(hist.similar_tool_uses.length, 5); s++) {
        var su = hist.similar_tool_uses[s];
        var simItem = mk('div', 'escrow-history-item');
        simItem.textContent = '  ' + su.tool_name + ' (' + su.decision + ', ' + formatTime(su.timestamp) + ')';
        histSection.appendChild(simItem);
      }
    }
    body.appendChild(histSection);

    // --- Contextual Assessment ---
    var assessment = data.assessment || [];
    if (assessment.length > 0) {
      var assessSection = mk('div', 'escrow-section');
      var assessTitle = mk('div', 'escrow-section-title');
      assessTitle.textContent = 'ASSESSMENT';
      assessSection.appendChild(assessTitle);

      var assessList = mk('ul', 'escrow-assessment');
      for (var a = 0; a < assessment.length; a++) {
        var aLi = mk('li');
        aLi.textContent = assessment[a];
        assessList.appendChild(aLi);
      }
      assessSection.appendChild(assessList);
      body.appendChild(assessSection);
    }

    // --- Audit Note ---
    var noteSection = mk('div', 'escrow-section');
    var noteTitle = mk('div', 'escrow-section-title');
    noteTitle.textContent = 'AUDIT NOTE';
    noteSection.appendChild(noteTitle);
    var noteInput = mk('textarea', 'escrow-note-input');
    noteInput.placeholder = 'Add a note for the audit trail (optional)...';
    noteInput.id = 'escrow-audit-note';
    noteSection.appendChild(noteInput);
    body.appendChild(noteSection);

    // --- Action Buttons ---
    var actionsDiv = mk('div', 'escrow-actions');

    var approveBtn = mk('button', 'btn btn-approve');
    approveBtn.textContent = 'Approve';
    approveBtn.addEventListener('click', function () {
      clearInterval(countdownInterval);
      var note = document.getElementById('escrow-audit-note').value;
      SG.api.post('/v1/approvals/' + encodeURIComponent(approvalId) + '/approve', { note: note }).then(function () {
        SG.toast.success('Approved');
        SG.modal.close();
        dismissNotif(notifId);
      }).catch(function (err) {
        SG.toast.error(err.message || 'Approve failed');
      });
    });
    actionsDiv.appendChild(approveBtn);

    var denyBtn = mk('button', 'btn btn-deny');
    denyBtn.textContent = 'Deny';
    denyBtn.addEventListener('click', function () {
      clearInterval(countdownInterval);
      var note = document.getElementById('escrow-audit-note').value;
      SG.api.post('/v1/approvals/' + encodeURIComponent(approvalId) + '/deny', { reason: 'denied by admin', note: note }).then(function () {
        SG.toast.success('Denied');
        SG.modal.close();
        dismissNotif(notifId);
      }).catch(function (err) {
        SG.toast.error(err.message || 'Deny failed');
      });
    });
    actionsDiv.appendChild(denyBtn);

    var closeBtn = mk('button', 'btn btn-secondary');
    closeBtn.textContent = 'Close';
    closeBtn.addEventListener('click', function () {
      clearInterval(countdownInterval);
      SG.modal.close();
    });
    actionsDiv.appendChild(closeBtn);

    body.appendChild(actionsDiv);

    SG.modal.open({
      title: 'Approval Required — ' + req.tool_name,
      body: body,
      width: '700px',
      onClose: function () { clearInterval(countdownInterval); }
    });
  }

  function addDetailRow(grid, label, value) {
    var l = mk('span', 'escrow-detail-label');
    l.textContent = label + ':';
    grid.appendChild(l);
    var v = mk('span', 'escrow-detail-value');
    v.textContent = value;
    grid.appendChild(v);
  }

  function formatCountdown(seconds) {
    var m = Math.floor(seconds / 60);
    var s = seconds % 60;
    return m + ':' + (s < 10 ? '0' : '') + s;
  }

  function formatTime(ts) {
    if (!ts) return '';
    var d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    var yyyy = d.getFullYear();
    var mo = String(d.getMonth() + 1).padStart(2, '0');
    var dd = String(d.getDate()).padStart(2, '0');
    var hh = String(d.getHours()).padStart(2, '0');
    var mi = String(d.getMinutes()).padStart(2, '0');
    var sc = String(d.getSeconds()).padStart(2, '0');
    return yyyy + '-' + mo + '-' + dd + ' ' + hh + ':' + mi + ':' + sc;
  }

  // -- Page render ----------------------------------------------------------

  function render(container) {
    injectStyles();
    pageRoot = container;
    // L-14: Create a new AbortController for this page session
    pageAbortController = new AbortController();

    var page = mk('div', 'notif-page');

    // Header.
    var header = mk('div', 'notif-header');
    var headerLeft = mk('div', '');
    var h1 = mk('h1');
    h1.innerHTML = SG.icon('bell', 24) + ' ';
    h1.appendChild(document.createTextNode('Notifications'));
    headerLeft.appendChild(h1);
    var subtitle = mk('p', 'page-subtitle');
    subtitle.textContent = 'Alerts and approval requests that need your attention.';
    headerLeft.appendChild(subtitle);
    header.appendChild(headerLeft);

    var headerActions = mk('div', '', { style: 'display: flex; gap: var(--space-2); align-items: center;' });
    var liveDot = mk('span', 'notif-live-dot');
    liveDot.id = 'notif-live-dot';
    headerActions.appendChild(liveDot);
    var liveText = mk('span', '', { style: 'font-size: var(--text-xs); color: var(--text-muted); margin-right: var(--space-3);' });
    liveText.textContent = 'Live';
    headerActions.appendChild(liveText);

    var dismissAllBtn = mk('button', 'btn btn-secondary btn-sm');
    dismissAllBtn.textContent = 'Dismiss All';
    dismissAllBtn.addEventListener('click', function () {
      SG.api.post('/v1/notifications/dismiss-all').then(function () {
        for (var i = 0; i < notifications.length; i++) notifications[i].dismissed = true;
        renderPage();
        updateBadge();
      }).catch(function () {});
    });
    headerActions.appendChild(dismissAllBtn);
    header.appendChild(headerActions);
    var helpBtn = mk('button', 'help-btn', { type: 'button' });
    helpBtn.textContent = '?';
    helpBtn.addEventListener('click', function() { if (SG.help) SG.help.toggle('notifications'); });
    header.appendChild(helpBtn);
    page.appendChild(header);

    // Content container.
    var content = mk('div', 'notif-content');
    page.appendChild(content);

    container.appendChild(page);

    // Load data.
    // L-14: Pass AbortController signal to cancel fetch on page navigation
    var signal = pageAbortController ? pageAbortController.signal : undefined;
    SG.api.get('/v1/notifications', { signal: signal }).then(function (data) {
      notifications = data || [];
      renderPage();
    }).catch(function (err) {
      if (err && err.name === 'AbortError') return; // L-14: silently ignore aborted requests
      notifications = [];
      renderPage();
    });

    // Start SSE.
    startSSE();
    ensureBadge();
    updateBadge();
  }

  function cleanup() {
    stopSSE();
    // L-14: Abort any in-flight fetch requests for this page
    if (pageAbortController) {
      pageAbortController.abort();
      pageAbortController = null;
    }
    // M-33: close approval modal if open to prevent countdown interval leak
    if (SG.modal && SG.modal.close) SG.modal.close();
    // H-15: badgeInterval is global (always-on); do NOT clear it on nav away
    pageRoot = null;
    notifications = [];
  }

  // -- Global badge polling (runs even when not on notifications page) ------

  var badgeInterval = null;
  function startBadgePolling() {
    ensureBadge();
    updateBadge();
    if (!badgeInterval) {
      badgeInterval = setInterval(function () {
        ensureBadge();
        updateBadge();
      }, 30000); // every 30s
    }
  }

  // Start badge polling on load.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startBadgePolling);
  } else {
    setTimeout(startBadgePolling, 500);
  }

  // -- Expose for use from other pages --------------------------------------
  SG.notifications = {
    openDiffViewer: openDiffViewer,
    openApprovalContext: openApprovalContext,
    updateBadge: updateBadge
  };

  // -- Registration ---------------------------------------------------------

  SG.router.register('notifications', render);
  SG.router.registerCleanup('notifications', cleanup);
})();
