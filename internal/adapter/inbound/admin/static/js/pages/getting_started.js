/**
 * getting_started.js -- Getting Started wizard page for SentinelGate admin UI.
 *
 * Presents three use-case cards (MCP Proxy, HTTP Gateway, MCP Client SDK)
 * in a responsive grid. Each card expands accordion-style to show
 * step-by-step setup instructions with code blocks.
 *
 * Data sources:
 *   None (static content -- all instructions are embedded)
 *
 * Design features:
 *   - 3-column responsive grid (2 col on tablet, 1 col on mobile)
 *   - Accordion expansion (one card at a time)
 *   - Code blocks with copy button
 *   - Links to relevant admin UI sections
 *   - All text via textContent where possible (XSS-safe)
 *
 * Requirements:
 *   UI-04  Getting Started wizard with use-case options
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // -- State ------------------------------------------------------------------

  var styleInjected = false;
  var expandedCard = null;

  // -- Getting Started styles -------------------------------------------------

  var GETTING_STARTED_CSS = [
    /* Container */
    '.gs-page {',
    '  padding: var(--space-6);',
    '  max-width: 900px;',
    '}',

    /* Header */
    '.gs-header {',
    '  margin-bottom: var(--space-6);',
    '}',
    '.gs-header h1 {',
    '  font-size: var(--text-2xl);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0 0 var(--space-1) 0;',
    '  letter-spacing: -0.02em;',
    '}',
    '.gs-header p {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-muted);',
    '  margin: 0;',
    '}',

    /* Unified cards grid -- 2 columns */
    '.gs-cards {',
    '  display: grid;',
    '  grid-template-columns: 1fr 1fr;',
    '  gap: var(--space-3);',
    '}',
    '@media (max-width: 640px) {',
    '  .gs-cards { grid-template-columns: 1fr; }',
    '}',

    /* Card */
    '.gs-card {',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  background: var(--bg-surface);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '  overflow: hidden;',
    '}',
    '.gs-card:hover {',
    '  border-color: var(--text-muted);',
    '  background: var(--bg-secondary);',
    '}',
    '.gs-card.expanded {',
    '  border-color: var(--accent);',
    '  cursor: default;',
    '  grid-column: 1 / -1;',
    '}',

    /* Card header */
    '.gs-card-header {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3) var(--space-4);',
    '}',
    '.gs-card-icon {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  width: 36px;',
    '  height: 36px;',
    '  border-radius: var(--radius-md);',
    '  background: var(--accent-subtle);',
    '  color: var(--accent);',
    '  flex-shrink: 0;',
    '}',
    '.gs-card-text {',
    '  flex: 1;',
    '  min-width: 0;',
    '}',
    '.gs-card-title {',
    '  font-size: var(--text-base);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '  margin: 0 0 2px 0;',
    '}',
    '.gs-card-desc {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  margin: 0;',
    '}',
    '.gs-card-chevron {',
    '  color: var(--text-muted);',
    '  flex-shrink: 0;',
    '  transition: transform var(--transition-fast);',
    '}',
    '.gs-card.expanded .gs-card-chevron {',
    '  transform: rotate(90deg);',
    '}',

    /* Card content (instructions) */
    '.gs-card-content {',
    '  display: none;',
    '  padding: 0 var(--space-4) var(--space-4);',
    '  border-top: 1px solid var(--border);',
    '}',
    '.gs-card.expanded .gs-card-content {',
    '  display: block;',
    '}',

    /* Steps */
    '.gs-step {',
    '  display: flex;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3) 0;',
    '}',
    '.gs-step:not(:last-child) {',
    '  border-bottom: 1px solid var(--border);',
    '}',
    '.gs-step-num {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  width: 24px;',
    '  height: 24px;',
    '  border-radius: var(--radius-full);',
    '  background: var(--accent);',
    '  color: #fff;',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-bold);',
    '  flex-shrink: 0;',
    '  margin-top: 1px;',
    '}',
    '.gs-step-body {',
    '  flex: 1;',
    '  min-width: 0;',
    '}',
    '.gs-step-text {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-primary);',
    '  margin: 0;',
    '  line-height: 1.5;',
    '}',
    '.gs-step-text a {',
    '  color: var(--accent);',
    '  text-decoration: none;',
    '}',
    '.gs-step-text a:hover {',
    '  text-decoration: underline;',
    '}',

    /* Code block */
    '.gs-code {',
    '  position: relative;',
    '  margin-top: var(--space-3);',
    '  border-radius: var(--radius-md);',
    '  background: var(--bg-primary);',
    '  border: 1px solid var(--border);',
    '  overflow: hidden;',
    '}',
    '.gs-code pre {',
    '  margin: 0;',
    '  padding: var(--space-3);',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-secondary);',
    '  line-height: 1.6;',
    '  overflow-x: auto;',
    '  white-space: pre;',
    '}',
    '.gs-code-copy {',
    '  position: absolute;',
    '  top: var(--space-2);',
    '  right: var(--space-2);',
    '  background: var(--bg-secondary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-sm);',
    '  padding: 4px 6px;',
    '  cursor: pointer;',
    '  color: var(--text-muted);',
    '  font-size: var(--text-xs);',
    '  transition: all var(--transition-fast);',
    '}',
    '.gs-code-copy:hover {',
    '  background: var(--bg-surface);',
    '  color: var(--text-primary);',
    '}',

    /* Agent config link button */
    '.gs-agent-link {',
    '  display: inline-flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  margin-top: var(--space-4);',
    '  padding: var(--space-2) var(--space-4);',
    '  background: var(--accent);',
    '  color: #fff;',
    '  border: none;',
    '  border-radius: var(--radius-md);',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-medium);',
    '  cursor: pointer;',
    '  text-decoration: none;',
    '  transition: all var(--transition-fast);',
    '}',
    '.gs-agent-link:hover {',
    '  opacity: 0.9;',
    '  text-decoration: none;',
    '}',
    '.gs-agent-chips {',
    '  display: flex;',
    '  flex-wrap: wrap;',
    '  gap: var(--space-2);',
    '  margin-top: var(--space-3);',
    '}',
    '.gs-agent-chip {',
    '  display: inline-block;',
    '  padding: 2px 10px;',
    '  background: var(--bg-secondary);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-full);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-secondary);',
    '}',

    /* New in v1.1 section */
    '.gs-new-section {',
    '  margin-top: var(--space-6);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.gs-new-header {',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '  margin-bottom: var(--space-4);',
    '}',
    '.gs-new-header h2 {',
    '  font-size: var(--text-lg);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0;',
    '}',
    '.gs-new-grid {',
    '  display: grid;',
    '  grid-template-columns: 1fr 1fr;',
    '  gap: var(--space-3);',
    '}',
    '@media (max-width: 640px) {',
    '  .gs-new-grid { grid-template-columns: 1fr; }',
    '}',
    '.gs-new-card {',
    '  display: flex;',
    '  align-items: flex-start;',
    '  gap: var(--space-3);',
    '  padding: var(--space-3) var(--space-4);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  background: var(--bg-surface);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '  text-decoration: none;',
    '}',
    '.gs-new-card:hover {',
    '  border-color: var(--accent);',
    '  background: var(--bg-secondary);',
    '}',
    '.gs-new-card-icon {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  width: 36px;',
    '  height: 36px;',
    '  border-radius: var(--radius-md);',
    '  background: var(--accent-subtle);',
    '  color: var(--accent);',
    '  flex-shrink: 0;',
    '  margin-top: 2px;',
    '}',
    '.gs-new-card-text {',
    '  flex: 1;',
    '  min-width: 0;',
    '}',
    '.gs-new-card-title {',
    '  font-size: var(--text-sm);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '  margin: 0 0 2px 0;',
    '}',
    '.gs-new-card-desc {',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  margin: 0;',
    '  line-height: 1.4;',
    '}',
    '.gs-new-card-arrow {',
    '  color: var(--text-muted);',
    '  flex-shrink: 0;',
    '  margin-top: 8px;',
    '  transition: transform var(--transition-fast);',
    '}',
    '.gs-new-card:hover .gs-new-card-arrow {',
    '  transform: translateX(2px);',
    '  color: var(--accent);',
    '}'
  ].join('\n');

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-getting-started', '');
    s.textContent = GETTING_STARTED_CSS;
    document.head.appendChild(s);
    styleInjected = true;
  }

  // -- DOM helpers ------------------------------------------------------------

  function mk(tag, className) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    return node;
  }

  // -- Code block builder -----------------------------------------------------

  function buildCodeBlock(code) {
    var wrap = mk('div', 'gs-code');
    var pre = mk('pre', '');
    pre.textContent = code;
    wrap.appendChild(pre);

    var copyBtn = mk('button', 'gs-code-copy');
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      navigator.clipboard.writeText(code).then(function () {
        copyBtn.textContent = 'Copied!';
        setTimeout(function () { copyBtn.textContent = 'Copy'; }, 2000);
      });
    });
    wrap.appendChild(copyBtn);

    return wrap;
  }

  // -- Step builder -----------------------------------------------------------

  function buildStep(num, html) {
    var step = mk('div', 'gs-step');

    var numEl = mk('div', 'gs-step-num');
    numEl.textContent = String(num);
    step.appendChild(numEl);

    var body = mk('div', 'gs-step-body');
    var text = mk('div', 'gs-step-text');
    text.innerHTML = html;
    body.appendChild(text);
    step.appendChild(body);

    return body;
  }

  // -- Use-case card definitions ----------------------------------------------

  var AGENTS_LIST = ['Claude Code', 'Gemini CLI', 'Codex CLI', 'Cursor / IDE', 'Python', 'Node.js', 'cURL'];

  var USE_CASES = [
    {
      id: 'mcp-proxy',
      icon: 'server',
      title: 'MCP Proxy',
      desc: 'Connect Claude Code, Gemini CLI, Codex CLI, Cursor, and more',
      steps: [
        { text: 'Add your MCP server in <a href="#/tools">Tools &amp; Rules</a>', code: null },
        { text: 'Create an API key in <a href="#/access">Access</a> for your agent', code: null },
        { text: 'Configure your AI agent to connect through SentinelGate\'s <code>/mcp</code> endpoint', code: null }
      ],
      codeBlock: null,
      customContent: 'mcp-proxy-agents'
    },
    {
      id: 'http-gateway',
      icon: 'globe',
      title: 'HTTP Gateway',
      desc: 'Control outbound HTTP requests from your agents',
      steps: [
        { text: 'Enable the HTTP Gateway in <a href="#/security">Security</a> settings', code: null },
        { text: 'Set your agent\'s HTTP_PROXY / HTTPS_PROXY to SentinelGate\'s address', code: null },
        { text: 'Define outbound policies to allow or block specific domains and paths', code: null }
      ],
      codeBlock: [
        '# Point your agent\'s outbound traffic through SentinelGate',
        'export HTTP_PROXY=http://localhost:8080',
        'export HTTPS_PROXY=http://localhost:8080',
        '',
        '# All HTTP requests from your agent are now',
        '# logged and subject to outbound policies',
        'python my_agent.py'
      ].join('\n')
    },
    {
      id: 'mcp-client-sdk',
      icon: 'code',
      title: 'MCP Client SDK',
      desc: 'Connect to SentinelGate programmatically using MCP client libraries',
      steps: [
        { text: 'Install the MCP client library: <code>pip install mcp</code> (Python) or <code>npm install @modelcontextprotocol/sdk</code> (Node.js)', code: null },
        { text: 'Connect to SentinelGate\'s <code>/mcp</code> endpoint with your API key', code: null },
        { text: 'Create an API key in <a href="#/access">Access</a> and use it in the Authorization header', code: null }
      ],
      codeBlock: null,
      customContent: 'mcp-sdk-link'
    }
  ];

  // -- New in v1.1 features ---------------------------------------------------

  var V11_FEATURES = [
    {
      icon: 'shield',
      title: 'Policy Templates',
      desc: 'Pre-built security policies for common scenarios — apply with one click.',
      link: '#/tools'
    },
    {
      icon: 'zap',
      title: 'Response Transforms',
      desc: 'Redact, mask, or modify tool responses before they reach the client.',
      link: '#/tools?tab=transforms'
    },
    {
      icon: 'gauge',
      title: 'Budget & Quota',
      desc: 'Set per-identity usage limits with configurable actions on breach.',
      link: '#/access'
    },
    {
      icon: 'record',
      title: 'Session Recording',
      desc: 'Record and replay full MCP sessions for audit and debugging.',
      link: '#/sessions'
    }
  ];

  function buildNewInV11Section() {
    var section = mk('div', 'gs-new-section');

    // Header
    var header = mk('div', 'gs-new-header');
    var h2 = mk('h2', '');
    h2.textContent = 'Features';
    header.appendChild(h2);
    section.appendChild(header);

    // Feature cards grid
    var grid = mk('div', 'gs-new-grid');

    for (var i = 0; i < V11_FEATURES.length; i++) {
      (function (feat) {
        var card = mk('a', 'gs-new-card');
        card.href = feat.link;

        var iconWrap = mk('div', 'gs-new-card-icon');
        if (SG.icon) {
          iconWrap.innerHTML = SG.icon(feat.icon, 18);
        }
        card.appendChild(iconWrap);

        var textWrap = mk('div', 'gs-new-card-text');
        var title = mk('div', 'gs-new-card-title');
        title.textContent = feat.title;
        textWrap.appendChild(title);
        var desc = mk('p', 'gs-new-card-desc');
        desc.textContent = feat.desc;
        textWrap.appendChild(desc);
        card.appendChild(textWrap);

        var arrow = mk('div', 'gs-new-card-arrow');
        if (SG.icon) {
          arrow.innerHTML = SG.icon('chevronRight', 14);
        }
        card.appendChild(arrow);

        grid.appendChild(card);
      })(V11_FEATURES[i]);
    }

    section.appendChild(grid);
    return section;
  }

  // -- Build custom content for MCP Proxy card --------------------------------

  function buildMcpProxyAgentContent() {
    var wrap = mk('div', '');

    var info = mk('p', 'gs-step-text');
    info.style.marginTop = 'var(--space-3)';
    info.textContent = 'SentinelGate supports all major AI agents and MCP clients. Get the exact configuration snippet for your agent:';
    wrap.appendChild(info);

    // Agent chips
    var chips = mk('div', 'gs-agent-chips');
    for (var i = 0; i < AGENTS_LIST.length; i++) {
      var chip = mk('span', 'gs-agent-chip');
      chip.textContent = AGENTS_LIST[i];
      chips.appendChild(chip);
    }
    wrap.appendChild(chips);

    // Link button to Access page
    var link = mk('a', 'gs-agent-link');
    link.href = '#/access';
    link.textContent = 'View Agent Configuration ';
    var arrow = document.createTextNode('\u2192');
    link.appendChild(arrow);
    link.addEventListener('click', function (e) {
      e.stopPropagation();
    });
    wrap.appendChild(link);

    return wrap;
  }

  // -- Build custom content for MCP Client SDK card ---------------------------

  function buildMcpSdkLinkContent() {
    var wrap = mk('div', '');

    var info = mk('p', 'gs-step-text');
    info.style.marginTop = 'var(--space-3)';
    info.textContent = 'Full Python and Node.js code examples with initialize, list tools, and call tool are available in the Access page:';
    wrap.appendChild(info);

    // Link button to Access page
    var link = mk('a', 'gs-agent-link');
    link.href = '#/access';
    link.textContent = 'View SDK Examples ';
    var arrow = document.createTextNode('\u2192');
    link.appendChild(arrow);
    link.addEventListener('click', function (e) {
      e.stopPropagation();
    });
    wrap.appendChild(link);

    return wrap;
  }

  // -- Build a use-case card --------------------------------------------------

  function buildCard(uc, container) {
    var card = mk('div', 'gs-card');
    card.setAttribute('data-uc', uc.id);

    // Header
    var header = mk('div', 'gs-card-header');

    var iconWrap = mk('div', 'gs-card-icon');
    if (SG.icon) {
      iconWrap.innerHTML = SG.icon(uc.icon, 20);
    }
    header.appendChild(iconWrap);

    var textWrap = mk('div', 'gs-card-text');
    var title = mk('div', 'gs-card-title');
    title.textContent = uc.title;
    textWrap.appendChild(title);

    var desc = mk('p', 'gs-card-desc');
    desc.textContent = uc.desc;
    textWrap.appendChild(desc);
    header.appendChild(textWrap);

    var chevron = mk('div', 'gs-card-chevron');
    if (SG.icon) {
      chevron.innerHTML = SG.icon('chevronRight', 16);
    }
    header.appendChild(chevron);

    card.appendChild(header);

    // Content (expanded)
    var content = mk('div', 'gs-card-content');
    for (var i = 0; i < uc.steps.length; i++) {
      var stepBody = buildStep(i + 1, uc.steps[i].text);
      content.appendChild(stepBody.parentNode);
    }

    if (uc.codeBlock) {
      content.appendChild(buildCodeBlock(uc.codeBlock));
    }

    // Custom content sections
    if (uc.customContent === 'mcp-proxy-agents') {
      content.appendChild(buildMcpProxyAgentContent());
    } else if (uc.customContent === 'mcp-sdk-link') {
      content.appendChild(buildMcpSdkLinkContent());
    }

    card.appendChild(content);

    // Click handler (accordion)
    header.addEventListener('click', function () {
      var isExpanded = card.classList.contains('expanded');

      // Collapse all
      var allCards = container.querySelectorAll('.gs-card');
      for (var j = 0; j < allCards.length; j++) {
        allCards[j].classList.remove('expanded');
      }

      // Expand clicked (if was collapsed)
      if (!isExpanded) {
        card.classList.add('expanded');
        expandedCard = uc.id;
      } else {
        expandedCard = null;
      }
    });

    return card;
  }

  // -- Render page ------------------------------------------------------------

  function buildFeatureCard(feat) {
    var card = mk('div', 'gs-card');
    card.style.cursor = 'pointer';

    var header = mk('div', 'gs-card-header');
    var iconWrap = mk('div', 'gs-card-icon');
    if (SG.icon) iconWrap.innerHTML = SG.icon(feat.icon, 18);
    header.appendChild(iconWrap);

    var textWrap = mk('div', 'gs-card-text');
    var title = mk('div', 'gs-card-title');
    title.textContent = feat.title;
    textWrap.appendChild(title);
    var desc = mk('p', 'gs-card-desc');
    desc.textContent = feat.desc;
    textWrap.appendChild(desc);
    header.appendChild(textWrap);

    var arrow = mk('div', 'gs-card-chevron');
    if (SG.icon) arrow.innerHTML = SG.icon('chevronRight', 14);
    header.appendChild(arrow);

    card.appendChild(header);

    card.addEventListener('click', function () {
      window.location.hash = feat.link;
    });

    return card;
  }

  function render(container) {
    expandedCard = null;
    injectStyles();

    var page = mk('div', 'gs-page');

    // Header
    var header = mk('div', 'gs-header');
    var h1 = mk('h1', '');
    h1.textContent = 'Getting Started';
    header.appendChild(h1);

    var subtitle = mk('p', '');
    subtitle.textContent = 'Choose how you use AI agents to get the right setup';
    header.appendChild(subtitle);
    page.appendChild(header);

    // Single unified grid — all cards same style
    var grid = mk('div', 'gs-cards');

    for (var i = 0; i < V11_FEATURES.length; i++) {
      grid.appendChild(buildFeatureCard(V11_FEATURES[i]));
    }
    for (var j = 0; j < USE_CASES.length; j++) {
      grid.appendChild(buildCard(USE_CASES[j], grid));
    }

    page.appendChild(grid);

    container.innerHTML = '';
    container.appendChild(page);
  }

  // -- Cleanup ----------------------------------------------------------------

  function cleanup() {
    expandedCard = null;
  }

  // -- Register with router ---------------------------------------------------

  SG.router.register('getting-started', render);
  SG.router.registerCleanup('getting-started', cleanup);
})();
