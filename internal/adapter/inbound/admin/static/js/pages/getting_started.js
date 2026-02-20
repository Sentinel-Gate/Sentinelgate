/**
 * getting_started.js -- Getting Started wizard page for SentinelGate admin UI.
 *
 * Presents four use-case cards (MCP Proxy, HTTP Gateway, Runtime Protection,
 * SDK Integration) in a 2x2 responsive grid. Each card expands accordion-style
 * to show step-by-step setup instructions with code blocks.
 *
 * Data sources:
 *   None (static content -- all instructions are embedded)
 *
 * Design features:
 *   - 2x2 responsive grid (1 col on mobile)
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

    /* Cards grid */
    '.gs-cards {',
    '  display: grid;',
    '  grid-template-columns: 1fr 1fr;',
    '  gap: var(--space-4);',
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
    '  padding: var(--space-4);',
    '}',
    '.gs-card-icon {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  width: 40px;',
    '  height: 40px;',
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

  var USE_CASES = [
    {
      id: 'mcp-proxy',
      icon: 'server',
      title: 'MCP Proxy',
      desc: 'I use MCP-compatible tools (Claude Desktop, Cursor, etc.)',
      steps: [
        { text: 'Add your MCP server in <a href="#/tools">Tools &amp; Rules</a>', code: null },
        { text: 'Point your MCP client to <code>http://localhost:8080/mcp</code>', code: null },
        { text: 'Configure policies in <a href="#/tools">Tools &amp; Rules</a> to control access', code: null }
      ],
      codeBlock: [
        '# sentinel-gate.yaml',
        'upstreams:',
        '  - name: my-mcp-server',
        '    type: sse',
        '    url: http://localhost:3000/sse',
        '',
        '# Then point your MCP client to:',
        '# http://localhost:8080/mcp'
      ].join('\n')
    },
    {
      id: 'http-gateway',
      icon: 'globe',
      title: 'HTTP Gateway',
      desc: 'My agents make HTTP API calls I want to monitor and control',
      steps: [
        { text: 'Enable the HTTP Gateway in <a href="#/security">Security</a> settings', code: null },
        { text: 'Configure your agent\'s HTTP proxy: <code>http://localhost:8080</code>', code: null },
        { text: 'Optionally enable TLS inspection for HTTPS traffic', code: null }
      ],
      codeBlock: [
        '# Set proxy environment variables',
        'export HTTP_PROXY=http://localhost:8080',
        'export HTTPS_PROXY=http://localhost:8080',
        '',
        '# Run your agent with proxy configured',
        'python my_agent.py'
      ].join('\n')
    },
    {
      id: 'runtime-protection',
      icon: 'zap',
      title: 'Runtime Protection',
      desc: 'I want to wrap my Python/Node.js agent with automatic protection',
      steps: [
        { text: 'Install the <code>sentinel-gate</code> binary', code: null },
        { text: 'Run your agent: <code>sentinel-gate run -- python agent.py</code>', code: null },
        { text: 'File access, subprocess, and network calls are automatically intercepted', code: null }
      ],
      codeBlock: [
        '# Python agent',
        'sentinel-gate run -- python agent.py',
        '',
        '# Node.js agent',
        'sentinel-gate run -- node agent.js',
        '',
        '# With explicit fail mode',
        'sentinel-gate run --fail-mode=closed -- python agent.py'
      ].join('\n')
    },
    {
      id: 'sdk-integration',
      icon: 'code',
      title: 'SDK Integration',
      desc: 'I want to integrate policy checks directly in my code',
      steps: [
        { text: 'Install the SDK: <code>pip install sentinelgate</code> or <code>npm install @sentinelgate/sdk</code>', code: null },
        { text: 'Import and check actions before executing them', code: null }
      ],
      codeBlock: [
        '# Python',
        'from sentinelgate import SentinelGateClient',
        'client = SentinelGateClient()',
        'result = client.evaluate("tool_call", "read_file", {"path": "/etc/passwd"})',
        'if result.allowed:',
        '    # proceed with action',
        '',
        '// Node.js',
        'const { SentinelGateClient } = require("@sentinelgate/sdk");',
        'const client = new SentinelGateClient();',
        'const result = await client.evaluate("tool_call", "read_file", { path: "/etc/passwd" });',
        'if (result.allowed) {',
        '  // proceed with action',
        '}'
      ].join('\n')
    }
  ];

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

    // Cards grid
    var grid = mk('div', 'gs-cards');

    for (var i = 0; i < USE_CASES.length; i++) {
      grid.appendChild(buildCard(USE_CASES[i], grid));
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
