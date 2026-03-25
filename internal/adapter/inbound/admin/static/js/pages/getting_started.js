/**
 * getting_started.js -- Getting Started wizard page for SentinelGate admin UI.
 *
 * Presents two use-case cards (MCP Proxy, Connect Your Agent)
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
    '  align-items: stretch;',
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

    '/* Agent config tabs (Getting Started MCP Proxy card) */',
    '.gs-config-tabs {',
    '  display: flex;',
    '  flex-wrap: wrap;',
    '  gap: var(--space-1);',
    '  margin-top: var(--space-4);',
    '  border-bottom: 1px solid var(--border);',
    '  padding-bottom: var(--space-1);',
    '}',
    '.gs-config-tab {',
    '  padding: var(--space-1) var(--space-3);',
    '  background: none;',
    '  border: 1px solid transparent;',
    '  border-radius: var(--radius-sm) var(--radius-sm) 0 0;',
    '  font-size: var(--text-xs);',
    '  color: var(--text-muted);',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '}',
    '.gs-config-tab:hover {',
    '  color: var(--text-primary);',
    '  background: var(--bg-surface);',
    '}',
    '.gs-config-tab.active {',
    '  color: var(--accent-text);',
    '  border-color: var(--border);',
    '  border-bottom-color: var(--bg-primary);',
    '  background: var(--bg-primary);',
    '  font-weight: var(--font-medium);',
    '}',
    '.gs-config-panel {',
    '  margin-top: var(--space-3);',
    '  position: relative;',
    '}',
    '.gs-config-code {',
    '  background: var(--bg-deep);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  padding: var(--space-3);',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-primary);',
    '  overflow-x: auto;',
    '  white-space: pre;',
    '  margin: 0;',
    '  line-height: 1.6;',
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
    '  align-items: stretch;',
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
    '}',

    /* Start-here label */
    '.gs-start-here {',
    '  display: inline-block;',
    '  font-size: var(--text-xs);',
    '  font-weight: var(--font-bold);',
    '  text-transform: uppercase;',
    '  letter-spacing: 0.08em;',
    '  color: var(--accent);',
    '  margin-bottom: var(--space-2);',
    '}',

    /* Help inline block */
    '.gs-help-inline {',
    '  margin-top: var(--space-4);',
    '  margin-bottom: var(--space-6);',
    '  padding: var(--space-4);',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-lg);',
    '  font-size: var(--text-sm);',
    '  color: var(--text-secondary);',
    '  line-height: 1.6;',
    '}',
    '.gs-help-inline p {',
    '  margin: 0 0 var(--space-2) 0;',
    '}',
    '.gs-help-inline p:last-child {',
    '  margin-bottom: 0;',
    '}',
    '.gs-help-inline strong {',
    '  color: var(--text-primary);',
    '}',

    /* Featured cards section */
    '.gs-featured-section {',
    '  margin-top: var(--space-6);',
    '}',
    '.gs-featured-header {',
    '  margin-bottom: var(--space-4);',
    '}',
    '.gs-featured-header h2 {',
    '  font-size: var(--text-lg);',
    '  font-weight: var(--font-bold);',
    '  color: var(--text-primary);',
    '  margin: 0 0 var(--space-1) 0;',
    '}',
    '.gs-featured-header p {',
    '  font-size: var(--text-sm);',
    '  color: var(--text-muted);',
    '  margin: 0;',
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
      }).catch(function () { /* L-FE-3: ignore clipboard errors gracefully */ });
    });
    wrap.appendChild(copyBtn);

    return wrap;
  }

  // -- Step builder -----------------------------------------------------------

  // SAFETY: html parameter must be hardcoded/trusted HTML only (contains <a> links).
  // Never pass user-supplied content to this function.
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
        { text: 'Add your MCP server in <a href="#/access">Connections</a>', code: null },
        { text: 'Create an identity and API key in <a href="#/access">Connections</a>, then configure your agent to connect', code: null },
        { text: 'Set security rules in <a href="#/tools">Tools &amp; Rules</a> to control which tools are allowed', code: null }
      ],
      codeBlock: null,
      customContent: 'mcp-proxy-agents'
    },
    {
      id: 'mcp-client-sdk',
      icon: 'code',
      title: 'Connect Your Agent',
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
      example: "Example: 'Allow read-only' blocks file writes and deletes in one click.",
      link: '#/tools?tab=templates'
    },
    {
      icon: 'zap',
      title: 'Response Transforms',
      desc: 'Redact, mask, or modify tool responses before they reach the agent.',
      example: 'Example: Automatically hide API keys and credit card numbers from responses.',
      link: '#/tools?tab=transforms'
    },
    {
      icon: 'gauge',
      title: 'Budget & Quota',
      desc: 'Set per-identity usage limits with configurable actions on breach.',
      example: 'Example: Limit each user to 100 tool calls per session.',
      link: '#/access'
    },
    {
      icon: 'record',
      title: 'Session Recording',
      desc: 'Record and replay full MCP sessions for audit and debugging.',
      example: 'Example: Replay a session to see exactly what your agent did.',
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
        if (feat.example) {
          var ex = mk('p', 'gs-new-card-desc');
          ex.style.cssText = 'color: var(--text-muted); font-style: italic; margin-top: var(--space-1);';
          ex.textContent = feat.example;
          textWrap.appendChild(ex);
        }
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
    var proxyAddress = window.location.host || 'localhost:8080';

    var info = mk('p', 'gs-step-text');
    info.style.marginTop = 'var(--space-3)';
    info.textContent = 'Configure your AI agent to connect through SentinelGate. Select your agent below and copy the configuration:';
    wrap.appendChild(info);

    // Same agent config snippets as the Access page (kept in sync)
    var agentSnippets = [
      {
        label: 'Claude Code',
        snippet: '# Option 1: CLI (recommended)\nclaude mcp add --transport http sentinelgate \\\n  http://' + proxyAddress + '/mcp \\\n  --header "Authorization: Bearer <your-api-key>"\n\n# Option 2: ~/.claude/settings.json\n' + JSON.stringify({ mcpServers: { sentinelgate: { type: 'http', url: 'http://' + proxyAddress + '/mcp', headers: { Authorization: 'Bearer <your-api-key>' } } } }, null, 2)
      },
      {
        label: 'Gemini CLI',
        snippet: '# Option 1: CLI (recommended)\ngemini mcp add --transport http -s user \\\n  --header "Authorization: Bearer <your-api-key>" \\\n  sentinelgate http://' + proxyAddress + '/mcp\n\n# Option 2: ~/.gemini/settings.json\n' + JSON.stringify({ mcpServers: { sentinelgate: { url: 'http://' + proxyAddress + '/mcp', type: 'http', headers: { Authorization: 'Bearer <your-api-key>' } } } }, null, 2)
      },
      {
        label: 'Codex CLI',
        snippet: '# Option 1: CLI with env var (recommended)\nexport SG_KEY="<your-api-key>"\ncodex mcp add sentinelgate --url http://' + proxyAddress + '/mcp \\\n  --bearer-token-env-var SG_KEY\n\n# Option 2: ~/.codex/config.toml\n[mcp_servers.sentinelgate]\nurl = "http://' + proxyAddress + '/mcp"\nbearer_token_env_var = "SG_KEY"\n\n# Then launch with: SG_KEY="<your-api-key>" codex\n\n# NOTE: Codex does NOT persist the API key (unlike Claude/Gemini).\n# The env var must be set each time. To make it permanent:\n# echo \'export SG_KEY="<your-api-key>"\' >> ~/.zshrc'
      },
      {
        label: 'Cursor / IDE',
        snippet: '// Add to your IDE\'s MCP settings (e.g. .cursor/mcp.json):\n' + JSON.stringify({ mcpServers: { sentinelgate: { type: 'http', url: 'http://' + proxyAddress + '/mcp', headers: { Authorization: 'Bearer <your-api-key>' } } } }, null, 2)
      },
      {
        label: 'Python',
        snippet: 'import httpx\nfrom mcp import ClientSession\nfrom mcp.client.streamable_http import streamable_http_client\n\nasync def main():\n    http_client = httpx.AsyncClient(\n        headers={"Authorization": "Bearer <your-api-key>"}\n    )\n    async with streamable_http_client(\n        "http://' + proxyAddress + '/mcp", http_client=http_client\n    ) as (r, w, _):\n        async with ClientSession(r, w) as session:\n            await session.initialize()\n\n            # List available tools\n            tools = await session.list_tools()\n            print(tools)\n\n            # Call a tool\n            result = await session.call_tool(\n                "tool_name", {"arg": "value"}\n            )\n            print(result)'
      },
      {
        label: 'Node.js',
        snippet: 'import { Client } from "@modelcontextprotocol/sdk/client/index.js";\nimport { StreamableHTTPClientTransport }\n  from "@modelcontextprotocol/sdk/client/streamableHttp.js";\n\nconst transport = new StreamableHTTPClientTransport(\n  new URL("http://' + proxyAddress + '/mcp"),\n  {\n    requestInit: {\n      headers: { "Authorization": "Bearer <your-api-key>" }\n    }\n  }\n);\n\nconst client = new Client(\n  { name: "my-client", version: "1.0.0" }\n);\nawait client.connect(transport);\n\n// List available tools\nconst { tools } = await client.listTools();\nconsole.log(tools);\n\n// Call a tool\nconst result = await client.callTool(\n  { name: "tool_name", arguments: { arg: "value" } }\n);\nconsole.log(result);'
      },
      {
        label: 'cURL',
        snippet: '# Initialize\ncurl -X POST http://' + proxyAddress + '/mcp \\\n  -H "Authorization: Bearer <your-api-key>" \\\n  -H "Content-Type: application/json" \\\n  -d \'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"curl","version":"1.0"},"capabilities":{}}}\'\n\n# List tools\ncurl -X POST http://' + proxyAddress + '/mcp \\\n  -H "Authorization: Bearer <your-api-key>" \\\n  -H "Content-Type: application/json" \\\n  -d \'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\''
      }
    ];

    // Tab bar
    var tabBar = mk('div', 'gs-config-tabs');
    var tabPanels = [];

    for (var i = 0; i < agentSnippets.length; i++) {
      (function (idx) {
        var tab = agentSnippets[idx];

        // Tab button
        var tabBtn = mk('button', 'gs-config-tab' + (idx === 0 ? ' active' : ''));
        tabBtn.textContent = tab.label;
        tabBtn.addEventListener('click', function (e) {
          e.stopPropagation();
          // Deactivate all tabs and panels
          var btns = tabBar.querySelectorAll('.gs-config-tab');
          for (var j = 0; j < btns.length; j++) btns[j].classList.remove('active');
          for (var j = 0; j < tabPanels.length; j++) tabPanels[j].style.display = 'none';
          // Activate clicked tab
          tabBtn.classList.add('active');
          tabPanels[idx].style.display = 'block';
        });
        tabBar.appendChild(tabBtn);

        // Tab panel with code block and copy button
        var panel = mk('div', 'gs-config-panel');
        panel.style.display = idx === 0 ? 'block' : 'none';

        var pre = mk('pre', 'gs-config-code');
        var code = mk('code', '');
        code.textContent = tab.snippet;
        pre.appendChild(code);

        var copyBtn = mk('button', 'gs-code-copy');
        copyBtn.textContent = 'Copy';
        copyBtn.addEventListener('click', function (e) {
          e.stopPropagation();
          if (window.SG && window.SG.clipboard) {
            window.SG.clipboard.copy(tab.snippet);
          } else if (navigator.clipboard) {
            navigator.clipboard.writeText(tab.snippet);
          }
          copyBtn.textContent = 'Copied!';
          setTimeout(function () { copyBtn.textContent = 'Copy'; }, 1500);
        });

        panel.appendChild(pre);
        panel.appendChild(copyBtn);
        tabPanels.push(panel);
      })(i);
    }

    wrap.appendChild(tabBar);
    for (var i = 0; i < tabPanels.length; i++) {
      wrap.appendChild(tabPanels[i]);
    }

    // Link to full configuration on Access page
    var link = mk('a', 'gs-agent-link');
    link.href = '#/access';
    link.textContent = 'Full configuration options ';
    link.appendChild(document.createTextNode('\u2192'));
    link.style.marginTop = 'var(--space-3)';
    link.style.fontSize = 'var(--text-xs)';
    link.addEventListener('click', function (e) { e.stopPropagation(); });
    wrap.appendChild(link);

    return wrap;
  }

  // -- Build custom content for Connect Your Agent card ---------------------------

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
    var card = mk('a', 'gs-new-card');
    card.href = feat.link;

    var iconWrap = mk('div', 'gs-new-card-icon');
    if (SG.icon) iconWrap.innerHTML = SG.icon(feat.icon, 18);
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
    if (SG.icon) arrow.innerHTML = SG.icon('chevronRight', 14);
    card.appendChild(arrow);

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
    subtitle.textContent = 'Choose how you want to use SentinelGate and follow the setup guide.';
    header.appendChild(subtitle);

    var helpBtn = mk('button', 'help-btn');
    helpBtn.type = 'button';
    helpBtn.setAttribute('aria-label', 'Help for Getting Started');
    helpBtn.textContent = '?';
    helpBtn.addEventListener('click', function () {
      if (SG.help) SG.help.toggle('getting_started');
    });
    header.appendChild(helpBtn);
    page.appendChild(header);

    // "Start here" label above MCP Proxy card
    var startLabel = mk('div', 'gs-start-here');
    startLabel.textContent = 'Start here';
    page.appendChild(startLabel);

    // MCP Proxy card — auto-expanded
    var proxyGrid = mk('div', 'gs-cards');
    var proxyCard = buildCard(USE_CASES[0], proxyGrid);
    proxyCard.classList.add('expanded');
    expandedCard = USE_CASES[0].id;
    proxyGrid.appendChild(proxyCard);
    page.appendChild(proxyGrid);

    // Help inline — always visible below MCP Proxy card
    var helpInline = mk('div', 'gs-help-inline');
    helpInline.innerHTML =
      '<p><strong>MCP Proxy</strong> is the primary way to use SentinelGate. It sits between your AI agent and your MCP servers, enforcing security rules, logging all activity, and applying response transforms.</p>' +
      '<p>Use the <strong>Connections</strong> page to add MCP servers, create identities and API keys, and get agent configuration snippets. Use <strong>Tools &amp; Rules</strong> to define security policies that control which tools are allowed.</p>';
    page.appendChild(helpInline);

    // Featured Cards section
    var featuredSection = mk('div', 'gs-featured-section');
    var featuredHeader = mk('div', 'gs-featured-header');
    var featuredTitle = mk('h2', '');
    featuredTitle.textContent = 'Featured Cards';
    featuredHeader.appendChild(featuredTitle);
    var featuredSubtitle = mk('p', '');
    featuredSubtitle.textContent = 'Quick links to configure specific features';
    featuredHeader.appendChild(featuredSubtitle);
    featuredSection.appendChild(featuredHeader);

    var featuredGrid = mk('div', 'gs-new-grid');

    // Connect Your Agent card
    featuredGrid.appendChild(buildFeatureCard({
      icon: USE_CASES[1].icon,
      title: USE_CASES[1].title,
      desc: USE_CASES[1].desc,
      link: '#/access'
    }));

    // V11 Features
    for (var i = 0; i < V11_FEATURES.length; i++) {
      featuredGrid.appendChild(buildFeatureCard(V11_FEATURES[i]));
    }

    featuredSection.appendChild(featuredGrid);
    page.appendChild(featuredSection);

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
