/**
 * onboarding.js -- Onboarding welcome screen for SentinelGate admin UI.
 *
 * Shown on the dashboard when no upstreams are configured (first boot).
 * Displays a 3-step guide (Add Servers, Set Rules, Connect Client) and
 * a prominent "Add MCP Server" button that opens the upstream modal.
 *
 * Auto-dismisses when the first upstream is detected via polling.
 *
 * This is NOT a regular page registered with SG.router. It is a
 * conditional overlay/replacement rendered by app.js when the upstream
 * list is empty.
 *
 * Data sources:
 *   GET /admin/api/upstreams  -> check if upstreams exist
 *
 * Design features:
 *   - Large shield icon with accent color
 *   - 3-step horizontal cards (vertical on mobile)
 *   - Step numbers in accent-colored circles
 *   - Fade-in entrance animation
 *   - Auto-dismiss poll every 3 seconds
 *   - All text via textContent (XSS-safe)
 *
 * Requirements:
 *   ONBRD-01  Welcome screen on first boot
 *   ONBRD-02  3-step explanation (Add Servers, Set Rules, Connect Client)
 *   ONBRD-03  Add MCP Server button calls SG.tools.openAddUpstreamModal()
 *   ONBRD-04  Auto-dismiss after first upstream added
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // -- State ------------------------------------------------------------------

  var styleInjected = false;
  var pollInterval = null;

  // -- Onboarding-specific styles ---------------------------------------------

  var ONBOARDING_CSS = [
    /* -- Fade-in animation ------------------------------------------------- */
    '@keyframes onboardingFadeIn {',
    '  from { opacity: 0; transform: translateY(16px); }',
    '  to   { opacity: 1; transform: translateY(0); }',
    '}',

    /* -- Container --------------------------------------------------------- */
    '.onboarding {',
    '  display: flex;',
    '  flex-direction: column;',
    '  align-items: center;',
    '  justify-content: center;',
    '  max-width: 600px;',
    '  margin: 0 auto;',
    '  padding: var(--space-8) var(--space-4);',
    '  min-height: 60vh;',
    '  animation: onboardingFadeIn 0.5s ease both;',
    '}',

    /* -- Shield icon ------------------------------------------------------- */
    '.onboarding-icon {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  width: 80px;',
    '  height: 80px;',
    '  border-radius: var(--radius-full);',
    '  background: var(--accent-subtle);',
    '  color: var(--accent);',
    '  margin-bottom: var(--space-5);',
    '}',
    '.onboarding-icon svg {',
    '  width: 48px;',
    '  height: 48px;',
    '}',

    /* -- Title and subtitle ------------------------------------------------ */
    '.onboarding-title {',
    '  font-size: var(--text-2xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0 0 var(--space-2) 0;',
    '  text-align: center;',
    '  letter-spacing: -0.02em;',
    '}',
    '.onboarding-subtitle {',
    '  font-size: var(--text-base);',
    '  color: var(--text-muted);',
    '  margin: 0 0 var(--space-6) 0;',
    '  text-align: center;',
    '}',

    /* -- Steps row --------------------------------------------------------- */
    '.onboarding-steps {',
    '  display: flex;',
    '  flex-direction: row;',
    '  gap: var(--space-4);',
    '  margin-bottom: var(--space-6);',
    '  width: 100%;',
    '}',
    '@media (max-width: 600px) {',
    '  .onboarding-steps { flex-direction: column; }',
    '}',

    /* -- Individual step card ---------------------------------------------- */
    '.onboarding-step {',
    '  display: flex;',
    '  flex-direction: column;',
    '  align-items: center;',
    '  flex: 1;',
    '  padding: var(--space-4);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  background: var(--bg-surface);',
    '  text-align: center;',
    '}',

    /* -- Step number circle ------------------------------------------------ */
    '.onboarding-step-number {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  width: 32px;',
    '  height: 32px;',
    '  border-radius: var(--radius-full);',
    '  background: var(--accent);',
    '  color: #fff;',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-bold);',
    '  margin-bottom: var(--space-3);',
    '  flex-shrink: 0;',
    '}',

    /* -- Step icon --------------------------------------------------------- */
    '.onboarding-step-icon {',
    '  color: var(--accent);',
    '  margin-bottom: var(--space-2);',
    '}',
    '.onboarding-step-icon svg {',
    '  width: 24px;',
    '  height: 24px;',
    '}',

    /* -- Step title and description ---------------------------------------- */
    '.onboarding-step-title {',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '  margin: 0 0 var(--space-1) 0;',
    '}',
    '.onboarding-step-desc {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  margin: 0;',
    '  line-height: 1.4;',
    '}',

    /* -- CTA button -------------------------------------------------------- */
    '.onboarding-cta {',
    '  margin-top: var(--space-2);',
    '  text-align: center;',
    '}',
    '.onboarding-cta .btn {',
    '  padding: var(--space-3) var(--space-6);',
    '  font-size: var(--text-base);',
    '}'
  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-onboarding', '');
    s.textContent = ONBOARDING_CSS;
    document.head.appendChild(s);
    styleInjected = true;
  }

  // -- DOM helpers ------------------------------------------------------------

  function mk(tag, className, attrs) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (attrs) {
      var keys = Object.keys(attrs);
      for (var i = 0; i < keys.length; i++) {
        var k = keys[i];
        if (k === 'style') {
          node.style.cssText = attrs[k];
        } else {
          node.setAttribute(k, attrs[k]);
        }
      }
    }
    return node;
  }

  // -- Shield SVG icon --------------------------------------------------------

  function shieldSVG() {
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    svg.setAttribute('width', '48');
    svg.setAttribute('height', '48');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z');
    svg.appendChild(path);
    return svg;
  }

  // -- Build step card --------------------------------------------------------

  function buildStepCard(number, iconName, title, description) {
    var card = mk('div', 'onboarding-step');

    // Number circle
    var numCircle = mk('div', 'onboarding-step-number');
    numCircle.textContent = String(number);
    card.appendChild(numCircle);

    // Icon
    if (SG.icon) {
      var iconWrap = mk('div', 'onboarding-step-icon');
      iconWrap.innerHTML = SG.icon(iconName, 24);
      card.appendChild(iconWrap);
    }

    // Title
    var titleEl = mk('div', 'onboarding-step-title');
    titleEl.textContent = title;
    card.appendChild(titleEl);

    // Description
    var descEl = mk('p', 'onboarding-step-desc');
    descEl.textContent = description;
    card.appendChild(descEl);

    return card;
  }

  // -- Render onboarding welcome screen ---------------------------------------

  function render(container) {
    cleanup();
    injectStyles();

    var root = mk('div', 'onboarding');

    // Shield icon
    var iconWrap = mk('div', 'onboarding-icon');
    iconWrap.appendChild(shieldSVG());
    root.appendChild(iconWrap);

    // Title
    var title = mk('h1', 'onboarding-title');
    title.textContent = 'Welcome to SentinelGate';
    root.appendChild(title);

    // Subtitle
    var subtitle = mk('p', 'onboarding-subtitle');
    subtitle.textContent = 'Your MCP proxy is running. Let\'s set it up.';
    root.appendChild(subtitle);

    // 3-step explanation cards
    var steps = mk('div', 'onboarding-steps');
    steps.appendChild(buildStepCard(
      1, 'server', 'Add Servers',
      'Connect your MCP servers (Claude, GPT, etc.)'
    ));
    steps.appendChild(buildStepCard(
      2, 'shield', 'Set Rules',
      'Define which tools are allowed or denied'
    ));
    steps.appendChild(buildStepCard(
      3, 'link', 'Connect Client',
      'Use the generated config to connect your AI client'
    ));
    root.appendChild(steps);

    // CTA button
    var ctaWrap = mk('div', 'onboarding-cta');
    var ctaBtn = mk('button', 'btn btn-primary');
    ctaBtn.textContent = 'Add MCP Server';
    ctaBtn.addEventListener('click', function () {
      SG.tools.openAddUpstreamModal();
    });
    ctaWrap.appendChild(ctaBtn);
    root.appendChild(ctaWrap);

    container.innerHTML = '';
    container.appendChild(root);

    // Start auto-dismiss polling (every 3 seconds)
    startPoll(container);
  }

  // -- Auto-dismiss polling ---------------------------------------------------

  function startPoll(container) {
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }

    pollInterval = setInterval(function () {
      SG.api.get('/upstreams').then(function (upstreams) {
        if (upstreams && upstreams.length > 0) {
          cleanup();
          // Navigate to dashboard to trigger full dashboard render
          window.location.hash = '#/dashboard';
          // Force re-render since we may already be on dashboard hash
          if (SG.router && SG.router.currentPage === 'dashboard') {
            SG.router.currentPage = null;
            SG.router.navigate('#/dashboard');
          }
        }
      }).catch(function () {
        // Non-fatal -- keep polling
      });
    }, 3000);
  }

  // -- Check and show ---------------------------------------------------------

  function checkAndShow(container) {
    return SG.api.get('/upstreams').then(function (upstreams) {
      if (!upstreams || upstreams.length === 0) {
        render(container);
        return true;
      }
      return false;
    }).catch(function () {
      // On error, let dashboard render normally
      return false;
    });
  }

  // -- Cleanup ----------------------------------------------------------------

  function cleanup() {
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
  }

  // -- Expose (NOT registered with router) ------------------------------------

  SG.onboarding = {
    render: render,
    cleanup: cleanup,
    checkAndShow: checkAndShow
  };
})();
