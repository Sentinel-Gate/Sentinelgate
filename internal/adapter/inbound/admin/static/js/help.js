/**
 * help.js -- Help panel (slide-in drawer) for SentinelGate admin UI.
 *
 * Provides contextual help for each page via a right-side drawer panel.
 * Includes glossary tooltips for common terms, both inside the panel
 * and as a utility for other pages to use inline.
 *
 * API:
 *   SG.help.open(pageId)    - Open help panel for a specific page
 *   SG.help.close()         - Close the help panel
 *   SG.help.toggle(pageId)  - Toggle the help panel
 *   SG.help.glossary(term)  - Returns a DOM element with glossary tooltip
 *
 * Design:
 *   - CSS injected via JS (style tag) on first use
 *   - Fixed-position panel slides from right (360px wide)
 *   - Dismissible via X button, backdrop click, or ESC key
 *   - Glossary terms in help content get automatic tooltips
 */
'use strict';

(function () {
  window.SG = window.SG || {};

  // -- State ------------------------------------------------------------------

  var styleInjected = false;
  var panelEl = null;
  var backdropEl = null;
  var escHandler = null;
  var currentPageId = null;

  // -- Help content per page --------------------------------------------------

  var HELP_CONTENT = {
    dashboard: {
      title: 'Dashboard',
      content:
        '<h4>Health Indicator</h4>' +
        '<ul>' +
        '<li><strong style="color:var(--success);">\u25CF Green</strong> \u2014 All servers connected, error rate below 5%</li>' +
        '<li><strong style="color:var(--warning);">\u25CF Yellow</strong> \u2014 Some servers disconnected or error rate 5\u201320%</li>' +
        '<li><strong style="color:var(--danger);">\u25CF Red</strong> \u2014 All servers disconnected or error rate above 20%</li>' +
        '</ul>' +
        '<h4>Stat Cards</h4>' +
        '<ul>' +
        '<li><strong>Requests</strong> \u2014 Total tool calls processed by the proxy</li>' +
        '<li><strong>Allowed</strong> \u2014 Tool calls permitted by policy rules</li>' +
        '<li><strong>Denied</strong> \u2014 Tool calls blocked by policy rules (matched a deny rule)</li>' +
        '<li><strong>Blocked</strong> \u2014 Tool calls blocked by quota enforcement (quota limit exceeded)</li>' +
        '<li><strong>Warned</strong> \u2014 Tool calls that exceeded a quota limit but were allowed through (action set to Warn instead of Deny)</li>' +
        '<li><strong>Errors</strong> \u2014 Tool calls that failed due to upstream errors or internal issues</li>' +
        '</ul>' +
        '<h4>Security Score</h4>' +
        '<p>Your security score out of 100. Click the suggestion count to see what to improve.</p>' +
        '<p>Scoring categories:</p>' +
        '<ul>' +
        '<li><strong>Tool Coverage (30pts)</strong> \u2014 How many discovered tools are protected by at least one rule. A wildcard rule (<code>*</code>) covers all tools instantly. Otherwise, each unique tool-match pattern counts toward coverage. Maximum 30 points when all tools are covered.</li>' +
        '<li><strong>Policy Quality (25pts)</strong> \u2014 No wildcard allow (+10), default deny (+10), identity conditions (+5)</li>' +
        '<li><strong>Content Protection (20pts)</strong> \u2014 Content scanning (+10), response transforms (+5), rate limiting (+5)</li>' +
        '<li><strong>Monitoring (15pts)</strong> \u2014 Tool integrity (+8), session recording (+7)</li>' +
        '<li><strong>Penalties</strong> \u2014 Uncovered tools (-2 each, max -10), wildcard allow without conditions (-15)</li>' +
        '</ul>' +
        ''
    },
    tools: {
      title: 'Tools & Rules',
      content: '<p>This page manages your security rules and tool configuration.</p>' +
        '<ul>' +
        '<li><strong>Policy Rules</strong> \u2014 Rules decide what\'s allowed or blocked. Each rule matches tools by name pattern and sets an action (Allow, Deny, or Ask).</li>' +
        '<li><strong>Tool Match</strong> \u2014 Use <code>*</code> to match everything, or patterns like <code>read_*</code> to match tools starting with "read_".</li>' +
        '<li><strong>Priority</strong> \u2014 Rules with higher priority numbers are checked first. The first matching rule wins.</li>' +
        '<li><strong>Response Transforms</strong> \u2014 Automatically modify tool responses. Use Redact to hide sensitive data (API keys, credit cards), Mask to partially hide (emails), or Truncate to limit response size.</li>' +
        '</ul>' +
        '<h4>Policy Test</h4>' +
        '<p>Test your rules against specific scenarios without making real calls. Enter a tool name, identity, and optional session context to see which rules would match and what decision would be made.</p>' +
        '<ul>' +
        '<li>Select a tool from the autocomplete dropdown</li>' +
        '<li>Choose an identity to test as (rules may depend on identity name or roles)</li>' +
        '<li>Session Context lets you set values like <code>session_cumulative_cost</code> for cost-based rules</li>' +
        '</ul>' +
        '<h4>Simulation</h4>' +
        '<p>Replay recent audit traffic against your current rule set to estimate the real-world impact of changes. Simulation shows:</p>' +
        '<ul>' +
        '<li><strong>Would Block</strong> \u2014 Calls that were allowed but would now be denied</li>' +
        '<li><strong>Would Allow</strong> \u2014 Calls that were denied but would now be allowed</li>' +
        '<li><strong>Impacted identities and tools</strong> \u2014 Which agents and tools are affected</li>' +
        '</ul>' +
        '<h4>Tool Status</h4>' +
        '<p>The status column shows the current policy outcome for each tool:</p>' +
        '<ul>' +
        '<li><strong>Allow</strong> \u2014 All matching rules permit this tool.</li>' +
        '<li><strong>Deny</strong> \u2014 All matching rules block this tool.</li>' +
        '<li><strong>Ask</strong> \u2014 Tool requires human approval before proceeding.</li>' +
        '<li><strong>No rule</strong> \u2014 No policy rule covers this tool. The default policy applies.</li>' +
        '<li><strong>Conditional</strong> \u2014 Multiple rules with different actions match this tool. The outcome depends on the call arguments (e.g., a tool may be denied for certain file paths but allowed for others). Click the badge to see the rule chain.</li>' +
        '</ul>' +
        '<h4>Default Rules</h4>' +
        '<p>SentinelGate includes a built-in default rule that allows all tool calls when no other rules match. ' +
        'This ensures agents can work out of the box. When you click <strong>Clear All Rules</strong>, all custom rules ' +
        'are removed but the default rule is preserved. To restrict access, add a deny rule with a lower priority ' +
        'or remove the default allow rule and create explicit allow rules for each tool.</p>'
    },
    access: {
      title: 'Connections',
      content: '<p>Manage your MCP servers, identities, API keys, and agent connections.</p>' +
        '<ul>' +
        '<li><strong>MCP Servers</strong> \u2014 Manage your connected MCP servers. Add, edit, or remove servers.</li>' +
        '<li><strong>Identities</strong> \u2014 An identity represents a person, team, or service that connects through the proxy.</li>' +
        '<li><strong>API Keys</strong> \u2014 Each identity needs a key to authenticate. The key is shown only once \u2014 copy it immediately!</li>' +
        '</ul>' +
        '<p><strong>Quotas</strong> \u2014 Optionally limit how many tool calls each identity can make.</p>' +
        '<h4>Roles</h4>' +
        '<p>Roles are <strong>labels</strong> for identities. They do not grant or restrict access on their own \u2014 use them in CEL policy conditions to enforce role-based access.</p>' +
        '<ul>' +
        '<li><strong>admin</strong> \u2014 Label for privileged identities. Use in policies: <code>"admin" in identity_roles</code></li>' +
        '<li><strong>user</strong> \u2014 Label for standard agent identities</li>' +
        '<li><strong>read-only</strong> \u2014 Label for agents intended to only read data. Pair with a policy template to enforce</li>' +
        '<li><strong>developer</strong> \u2014 Label for teams managing tool definitions</li>' +
        '<li><strong>auditor</strong> \u2014 Label for identities that should only view activity</li>' +
        '</ul>' +
        '<p>Use the <code>identity_roles</code> variable in policy rules to enforce role-based access. Example: <code>"read-only" in identity_roles</code> to match read-only agents.</p>' +
        '<p><strong>Tip</strong> \u2014 Create separate identities for different tasks (e.g., "read-only-files", "train-lookup") to control exactly what each agent can do.</p>'
    },
    audit: {
      title: 'Activity',
      content: '<p>Every tool call that flows through SentinelGate is recorded here. Use the filters to search by tool name, identity, time range, or decision (allowed/denied).</p>' +
        '<ul>' +
        '<li>Green rows = allowed, Red rows = denied</li>' +
        '<li>Click any row to see full details including arguments and response</li>' +
        '</ul>'
    },
    sessions: {
      title: 'Sessions',
      content: '<p>Monitor active sessions and review recorded conversations between agents and tools.</p>' +
        '<h4>Active Sessions</h4>' +
        '<ul>' +
        '<li>Shows all currently connected agents with live call counters and quota progress</li>' +
        '<li>Use <strong>Terminate</strong> to immediately end a session \u2014 the agent will need to reconnect</li>' +
        '</ul>' +
        '<h4>Recording</h4>' +
        '<ul>' +
        '<li><strong>Record</strong> \u2014 Enable recording to capture sessions automatically</li>' +
        '<li><strong>Record Payloads</strong> \u2014 When enabled, full tool arguments are recorded, ' +
        'not just metadata. Disable if arguments contain sensitive data.</li>' +
        '<li><strong>Export</strong> \u2014 Download sessions as JSON (indented) or CSV with identity names, arguments, and quota state</li>' +
        '<li><strong>Replay</strong> \u2014 Click any session to see the exact sequence of tool calls</li>' +
        '</ul>' +
        '<h4>What is a Session?</h4>' +
        '<p>A session starts when an agent connects (MCP <code>initialize</code>) and ends on disconnect ' +
        'or after 30 minutes of inactivity. Reconnections create new sessions.</p>'
    },
    agents: {
      title: 'Agents',
      content: '<p>Monitor connected agents and their behavioral health.</p>' +
        '<h4>Metrics</h4>' +
        '<ul>' +
        '<li><strong>Denied</strong> — Tool calls blocked by policy rules</li>' +
        '<li><strong>Violations</strong> — Total blocks (policy denies + security scan blocks)</li>' +
        '<li><strong>Drift Score</strong> (0.0\u20131.0) — Composite measure of behavioral change vs. the 14-day historical pattern. Components: ' +
          '<em>temporal pattern</em> (shift in active hours), <em>tool distribution</em> (change in which tools are called), ' +
          '<em>deny rate</em> (increase in blocked calls), <em>error rate</em> (more failures than usual), ' +
          '<em>argument shift</em> (different argument patterns for the same tools). Higher = more unusual.</li>' +
        '<li><strong>Health Status</strong> — Healthy (&lt;10% deny), Attention (10\u201325%), Critical (&gt;25% deny or drift &gt;0.60)</li>' +
        '</ul>' +
        '<h4>Understanding Critical Status</h4>' +
        '<p>An agent enters <strong>Critical</strong> when:</p>' +
        '<ul>' +
        '<li><strong>High Deny Rate</strong> (&gt;25%) \u2014 Many tool calls are being blocked. This is <em>expected</em> for restrictive policies (e.g., Read Only role), and means your rules are working correctly.</li>' +
        '<li><strong>High Drift Score</strong> (&gt;0.60) \u2014 Behavior has diverged significantly from the historical pattern. Investigate whether the agent is acting unexpectedly or if the historical pattern needs a refresh.</li>' +
        '<li><strong>High Error Rate</strong> (&gt;15%) \u2014 Tool failures are common. Check upstream tool health and audit logs.</li>' +
        '</ul>' +
        '<h4>Acknowledging Alerts</h4>' +
        '<p>Click <strong>Acknowledge Alert</strong> in the agent header to silence notifications if you\'ve reviewed the cause and determined it\'s expected behavior. Acknowledging does NOT change rules or thresholds \u2014 it only suppresses duplicate notifications for 24 hours.</p>' +
        '<h4>Sessions</h4>' +
        '<p>Each connection creates a session. Reconnections or idle timeouts (30 min) create new ones. "Stale" sessions are expired but not yet cleaned up.</p>'
    },
    notifications: {
      title: 'Notifications',
      content: '<p>Alerts and events that need your attention.</p>' +
        '<h4>Types</h4>' +
        '<ul>' +
        '<li><strong>Approval Requests</strong> — Tool calls waiting for your decision (from rules set to "Ask")</li>' +
        '<li><strong>Security Alerts</strong> — Content scanning detections, prompt injection attempts</li>' +
        '<li><strong>Health Alerts</strong> — Agent health status changes (e.g., high deny rate, drift detected)</li>' +
        '<li><strong>Tool Integrity</strong> — Tools added, removed, or modified on connected servers</li>' +
        '<li><strong>Red Team</strong> — Scan completed with results summary</li>' +
        '<li><strong>Budget</strong> — Cost threshold warnings</li>' +
        '</ul>' +
        '<p>Dismiss notifications individually or use "Dismiss All" to clear.</p>'
    },
    compliance: {
      title: 'Compliance',
      content: '<p>Track how well your security setup covers regulatory frameworks. Currently supports EU AI Act transparency requirements.</p>' +
        '<ul>' +
        '<li><strong>Coverage Score</strong> \u2014 Percentage of requirements met by your current configuration</li>' +
        '<li><strong>Gaps</strong> \u2014 Requirements that aren\'t yet covered, with actionable suggestions</li>' +
        '<li><strong>Evidence Bundle</strong> \u2014 Download a JSON bundle with audit records, configuration state, and compliance assessment for auditors</li>' +
        '</ul>'
    },
    getting_started: {
      title: 'Getting Started',
      content: '<p>Your starting point for setting up SentinelGate.</p>' +
        '<ul>' +
        '<li><strong>MCP Proxy</strong> \u2014 Route your AI agent through SentinelGate for security and monitoring</li>' +
        '<li><strong>Featured Cards</strong> \u2014 Quick links to connect agents and configure advanced features</li>' +
        '</ul>' +
        '<h4>Command Palette</h4>' +
        '<p>Press <strong>\u2318K</strong> (Mac) or <strong>Ctrl+K</strong> (Windows/Linux) to open the command palette. ' +
        'Available actions include:</p>' +
        '<ul>' +
        '<li>Navigate between sections (Dashboard, Tools &amp; Rules, Access, Audit, etc.)</li>' +
        '<li>Create resources \u2014 Add MCP Server, Create Rule, Create Identity</li>' +
        '<li>Factory Reset \u2014 Reset all dynamic configuration</li>' +
        '</ul>' +
        '<h4>Factory Reset</h4>' +
        '<p>Removes all dynamically created resources: MCP server connections, policies, identities, API keys, sessions, ' +
        'quotas, transforms, tool baselines, quarantine entries, stats, and notifications. ' +
        'Read-only resources from your YAML config file are preserved.</p>' +
        '<p>Access it via the Command Palette (\u2318K / Ctrl+K) \u2192 type "Factory Reset".</p>'
    },
    permissions: {
      title: 'Access Review',
      content: '<p>Fine-grained access control for identities and roles.</p>' +
        '<ul>' +
        '<li><strong>Shadow Mode</strong> — Test permission changes without enforcing them (report only, suggest, or auto-tighten)</li>' +
        '<li><strong>Usage Overview</strong> — See which tools each identity can access and how permissions compare across agents</li>' +
        '<li><strong>Identity Detail</strong> — Click any identity to see which tools it can access and adjust permissions</li>' +
        '<li><strong>Least Privilege Score</strong> — Measures how tightly permissions match actual usage. Score = (permitted \u2212 gaps) \u00f7 permitted \u00d7 100. A "gap" is a tool that is permitted but: never used, rarely used (fewer than 3 calls), or used only during a narrow time window (4 or fewer active hours) within the observation period. Lower scores indicate over-privileged identities that could be tightened.</li>' +
        '</ul>'
    },
    security: {
      title: 'Security',
      content: '<p>Configure content scanning and tool security features.</p>' +
        '<ul>' +
        '<li><strong>Content Scanning</strong> — Scan tool responses for prompt injection patterns ' +
        '(system prompt override, role hijacking, delimiter escape, tool poisoning, etc.). ' +
        'Monitor mode logs detections; Enforce mode blocks them.</li>' +
        '<li><strong>Input Scanning</strong> — Detect sensitive data (API keys, credentials, PII like ' +
        'emails, credit cards, phone numbers) in tool arguments before they reach the server.</li>' +
        '<li><strong>Whitelist</strong> — Exclude specific patterns from scanning. Select which detection to ' +
        'ignore (e.g., Email), the scope (Tool name, Agent identity, or Path pattern), and enter the value. ' +
        'Example: to skip email detection in <code>read_file</code> arguments, select Email + Tool and enter ' +
        '<code>read_file</code>.</li>' +
        '<li><strong>Tool Security</strong> — Baseline integrity checks and quarantine for suspicious tools.</li>' +
        '</ul>' +
        '<h4>Tool Security Flow</h4>' +
        '<p>1. On first startup, SentinelGate automatically captures a <strong>baseline</strong> \u2014 ' +
        'a snapshot of all tools from your servers.</p>' +
        '<p>2. <strong>Check Drift</strong> compares current tools against the baseline to detect ' +
        'additions, removals, or changes.</p>' +
        '<p>3. <strong>Capture Baseline</strong> \u2014 Update the reference snapshot after intentionally ' +
        'adding or removing servers.</p>' +
        '<p>4. When a tool changes, you receive a notification with <strong>Accept</strong> and ' +
        '<strong>Quarantine</strong> buttons to handle it without recapturing the full baseline.</p>' +
        '<p><strong>Note:</strong> Content Scanning may flag files that describe injection techniques ' +
        '(e.g., security documentation, audit reports). Review detections in Activity before taking action.</p>'
    },
    redteam: {
      title: 'Red Team',
      content: '<p>Simulate adversarial attacks to test if your policies hold up.</p>' +
        '<h4>How it works</h4>' +
        '<p>The scan sends crafted tool call requests designed to bypass your rules \u2014 path traversal, ' +
        'prompt injection, privilege escalation, etc. Each test checks if your policies correctly block the attack.</p>' +
        '<h4>Configuration</h4>' +
        '<ul>' +
        '<li><strong>Target Identity</strong> — Which identity to simulate attacks as (uses its roles and permissions)</li>' +
        '<li><strong>Roles</strong> — Comma-separated roles to assign to the test identity (e.g., "developer, analyst"). ' +
        'These match against role-based conditions in your rules. Leave empty to use each pattern\'s default roles.</li>' +
        '<li><strong>Category</strong> — Type of attack to simulate. "Full Suite" runs all categories.</li>' +
        '</ul>' +
        '<h4>Results</h4>' +
        '<ul>' +
        '<li><strong>Scorecard</strong> — Per-category pass/fail rates</li>' +
        '<li><strong>Vulnerabilities</strong> — Attacks that got through, with severity and suggested fixes</li>' +
        '<li><strong>Apply Policy</strong> — One-click fix: creates a deny rule to block the specific attack pattern</li>' +
        '</ul>'
    },
    finops: {
      title: 'Cost Tracking',
      content: '<p><strong>Note:</strong> Costs are estimates based on a configurable per-call rate ' +
        '(default $0.01/call), not actual API billing from your provider. Adjust the rate in Configuration.</p>' +
        '<p><strong>Retroactive tracking:</strong> Costs include all calls made during the current month, even before enabling cost tracking. ' +
        'Historical data is calculated from audit logs when the feature is activated.</p>' +
        '<ul>' +
        '<li><strong>Budget Guardrails</strong> — Set monthly spending limits per identity in Configuration. ' +
          'Choose <em>Notify</em> to receive alerts, or <em>Block</em> to deny all tool calls once the budget is exceeded. ' +
          'To unblock an identity, raise its budget or switch the action back to Notify. ' +
          'Budget progress bars appear on the main page when budgets are configured.</li>' +
        '<li><strong>Cost Breakdown</strong> — Per-identity and per-tool cost analysis</li>' +
        '<li><strong>Alerts</strong> — Get notified at 70%, 85%, and 100% of budget thresholds</li>' +
        '<li><strong>Identity Detail</strong> — Click any identity to see its tool-by-tool cost history</li>' +
        '<li><strong>CEL Variable</strong> — Use <code>session_cumulative_cost</code> in policy rules for fine-grained cost-based conditions</li>' +
        '</ul>'
    }
  };

  // -- Glossary ---------------------------------------------------------------

  var GLOSSARY = {
    'MCP': 'Model Context Protocol, the standard way AI agents communicate with tools',
    'Policy': 'A security rule that decides whether a tool call is allowed or blocked',
    'Rule': 'A security rule that decides whether a tool call is allowed or blocked',
    'Identity': 'A named user or service that connects through SentinelGate',
    'API Key': 'A secret token used to authenticate an identity',
    'Tool': 'A capability provided by an MCP server (e.g., read a file, run a query)',
    'Rate Limit': 'Maximum number of requests allowed per time period',
    'CEL': 'Common Expression Language, an advanced way to write rule conditions',
    'Transform': 'Automatic modification of tool responses (e.g., hiding sensitive data)',
    'Session': 'A complete conversation between an agent and SentinelGate'
  };

  // -- CSS (injected on first use) --------------------------------------------

  var HELP_CSS = [
    /* Backdrop */
    '.help-panel-backdrop {',
    '  position: fixed;',
    '  top: 0;',
    '  left: 0;',
    '  right: 0;',
    '  bottom: 0;',
    '  background: rgba(0, 0, 0, 0.4);',
    '  z-index: 8000;',
    '  opacity: 0;',
    '  transition: opacity 0.3s ease;',
    '  pointer-events: none;',
    '}',
    '.help-panel-backdrop.open {',
    '  opacity: 1;',
    '  pointer-events: auto;',
    '}',

    /* Panel */
    '.help-panel {',
    '  position: fixed;',
    '  top: 0;',
    '  right: 0;',
    '  width: 360px;',
    '  height: 100vh;',
    '  background: var(--bg-secondary);',
    '  border-left: 1px solid var(--border);',
    '  z-index: 8001;',
    '  display: flex;',
    '  flex-direction: column;',
    '  transform: translateX(100%);',
    '  transition: transform 0.3s ease;',
    '  box-shadow: -4px 0 24px rgba(0, 0, 0, 0.3);',
    '}',
    '.help-panel.open {',
    '  transform: translateX(0);',
    '}',
    '@media (max-width: 1400px) {',
    '  .help-panel { width: 300px; }',
    '}',

    /* Header */
    '.help-panel-header {',
    '  display: flex;',
    '  align-items: center;',
    '  justify-content: space-between;',
    '  padding: var(--space-4) var(--space-5);',
    '  border-bottom: 1px solid var(--border);',
    '  flex-shrink: 0;',
    '}',
    '.help-panel-header h2 {',
    '  font-size: var(--text-lg);',
    '  font-weight: var(--font-semibold);',
    '  color: var(--text-primary);',
    '  margin: 0;',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-2);',
    '}',
    '.help-panel-close {',
    '  width: 32px;',
    '  height: 32px;',
    '  border-radius: var(--radius-md);',
    '  background: transparent;',
    '  border: 1px solid transparent;',
    '  color: var(--text-secondary);',
    '  display: inline-flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  cursor: pointer;',
    '  transition: all var(--transition-fast);',
    '}',
    '.help-panel-close:hover {',
    '  background: var(--bg-elevated);',
    '  color: var(--text-primary);',
    '  border-color: var(--border);',
    '}',

    /* Body */
    '.help-panel-body {',
    '  flex: 1;',
    '  overflow-y: auto;',
    '  padding: var(--space-5);',
    '  color: var(--text-secondary);',
    '  font-size: var(--text-sm);',
    '  line-height: 1.7;',
    '}',
    '.help-panel-body p {',
    '  margin: 0 0 var(--space-3) 0;',
    '}',
    '.help-panel-body ul, .help-panel-body ol {',
    '  margin: 0 0 var(--space-3) 0;',
    '  padding-left: var(--space-5);',
    '}',
    '.help-panel-body li {',
    '  margin-bottom: var(--space-2);',
    '}',
    '.help-panel-body strong {',
    '  color: var(--text-primary);',
    '  font-weight: var(--font-semibold);',
    '}',
    '.help-panel-body code {',
    '  background: var(--bg-surface);',
    '  padding: 2px 6px;',
    '  border-radius: var(--radius-md);',
    '  font-family: var(--font-mono);',
    '  font-size: var(--text-xs);',
    '  color: var(--accent-text);',
    '}',

    /* Footer */
    '.help-panel-footer {',
    '  padding: var(--space-3) var(--space-5);',
    '  border-top: 1px solid var(--border);',
    '  flex-shrink: 0;',
    '}',
    '.help-panel-footer a {',
    '  font-size: var(--text-xs);',
    '  color: var(--accent);',
    '  text-decoration: none;',
    '  display: flex;',
    '  align-items: center;',
    '  gap: var(--space-1);',
    '  transition: color var(--transition-fast);',
    '}',
    '.help-panel-footer a:hover {',
    '  color: var(--accent-hover);',
    '  text-decoration: underline;',
    '  text-underline-offset: 2px;',
    '}',

    /* Help button (used by pages) */
    '.help-btn {',
    '  width: 28px;',
    '  height: 28px;',
    '  border-radius: 50%;',
    '  background: var(--bg-surface);',
    '  border: 1px solid var(--border);',
    '  color: var(--text-secondary);',
    '  display: inline-flex;',
    '  align-items: center;',
    '  justify-content: center;',
    '  cursor: pointer;',
    '  font-size: var(--text-sm);',
    '  transition: all var(--transition-fast);',
    '  margin-left: auto;',
    '}',
    '.help-btn:hover {',
    '  background: var(--bg-elevated);',
    '  color: var(--text-primary);',
    '  border-color: var(--accent);',
    '}',

    /* Glossary tooltips inside help panel */
    '.help-glossary-term {',
    '  border-bottom: 1px dashed var(--text-muted);',
    '  cursor: help;',
    '  position: relative;',
    '}',
    '.help-glossary-tooltip {',
    '  position: absolute;',
    '  bottom: calc(100% + 4px);',
    '  left: 50%;',
    '  transform: translateX(-50%);',
    '  background: var(--bg-elevated);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-secondary);',
    '  white-space: nowrap;',
    '  pointer-events: none;',
    '  opacity: 0;',
    '  transition: opacity var(--transition-fast);',
    '  z-index: 9999;',
    '  font-weight: normal;',
    '}',
    '.help-glossary-term:hover .help-glossary-tooltip {',
    '  opacity: 1;',
    '}',

    /* In-page glossary tooltips (used by SG.help.glossary()) */
    '.glossary-term {',
    '  border-bottom: 1px dashed var(--text-muted);',
    '  cursor: help;',
    '  position: relative;',
    '  display: inline;',
    '}',
    '.glossary-term .glossary-tooltip {',
    '  position: absolute;',
    '  bottom: calc(100% + 4px);',
    '  left: 50%;',
    '  transform: translateX(-50%);',
    '  background: var(--bg-elevated);',
    '  border: 1px solid var(--border);',
    '  border-radius: var(--radius-md);',
    '  padding: var(--space-2) var(--space-3);',
    '  font-size: var(--text-xs);',
    '  color: var(--text-secondary);',
    '  white-space: nowrap;',
    '  pointer-events: none;',
    '  opacity: 0;',
    '  transition: opacity var(--transition-fast);',
    '  z-index: 9999;',
    '}',
    '.glossary-term:hover .glossary-tooltip {',
    '  opacity: 1;',
    '}'
  ].join('\n');

  // -- CSS injection ----------------------------------------------------------

  function injectStyles() {
    if (styleInjected) return;
    var s = document.createElement('style');
    s.setAttribute('data-help', '');
    s.textContent = HELP_CSS;
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

  // -- Glossary processing ----------------------------------------------------

  /**
   * Process HTML content: wrap <strong>TERM</strong> in glossary tooltips
   * when TERM matches a glossary key.
   */
  function processGlossary(html) {
    var keys = Object.keys(GLOSSARY);
    for (var i = 0; i < keys.length; i++) {
      var term = keys[i];
      var def = GLOSSARY[term];
      // Escape special regex chars in the term
      var escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      var re = new RegExp('<strong>' + escaped + '</strong>', 'g');
      // M-52: Escape definition text to prevent latent XSS.
      var safeDef = def.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
      var replacement = '<strong class="help-glossary-term">' + term +
        '<span class="help-glossary-tooltip">' + safeDef + '</span></strong>';
      html = html.replace(re, replacement);
    }
    return html;
  }

  // -- Panel DOM construction -------------------------------------------------

  function buildPanel() {
    // Backdrop
    backdropEl = mk('div', 'help-panel-backdrop');
    backdropEl.addEventListener('click', close);

    // Panel
    panelEl = mk('div', 'help-panel');

    // Header
    var header = mk('div', 'help-panel-header');
    var titleEl = mk('h2', '');
    titleEl.innerHTML = SG.icon('helpCircle', 18) + ' <span class="help-panel-title">Help</span>';
    var closeBtn = mk('button', 'help-panel-close', { 'aria-label': 'Close help panel' });
    closeBtn.innerHTML = SG.icon('x', 18);
    closeBtn.addEventListener('click', close);
    header.appendChild(titleEl);
    header.appendChild(closeBtn);

    // Body
    var body = mk('div', 'help-panel-body');
    body.setAttribute('id', 'help-panel-body');

    // Footer
    var footer = mk('div', 'help-panel-footer');
    var footerLink = mk('a', '', { href: '/admin/static/docs/Guide.md', target: '_blank', rel: 'noopener' });
    footerLink.innerHTML = 'View full documentation ' + SG.icon('externalLink', 12);
    footer.appendChild(footerLink);

    panelEl.appendChild(header);
    panelEl.appendChild(body);
    panelEl.appendChild(footer);

    document.body.appendChild(backdropEl);
    document.body.appendChild(panelEl);
  }

  // -- Open / Close / Toggle --------------------------------------------------

  function open(pageId) {
    injectStyles();

    if (!panelEl) {
      buildPanel();
    }

    // Resolve content — handle hyphenated page IDs (e.g., "getting-started" -> "getting_started")
    var id = pageId || 'dashboard';
    var underscored = id.replace(/-/g, '_');
    var entry = HELP_CONTENT[id] || HELP_CONTENT[underscored] || null;

    var body = document.getElementById('help-panel-body');
    var titleSpan = panelEl.querySelector('.help-panel-title');

    if (entry) {
      titleSpan.textContent = 'Help \u2014 ' + entry.title;
      body.innerHTML = processGlossary(entry.content);
    } else {
      titleSpan.textContent = 'Help';
      body.innerHTML = '<p>No help content available for this page yet.</p>';
    }

    currentPageId = id;

    // Animate open (use rAF to ensure transition fires)
    requestAnimationFrame(function () {
      backdropEl.classList.add('open');
      panelEl.classList.add('open');
    });

    // ESC handler
    if (!escHandler) {
      escHandler = function (e) {
        if (e.key === 'Escape') {
          close();
        }
      };
      document.addEventListener('keydown', escHandler);
    }
  }

  // L-FE-9: Guard against rapid toggle during close animation.
  var isClosing = false;

  function close() {
    if (!panelEl || isClosing) return;
    isClosing = true;

    backdropEl.classList.remove('open');
    panelEl.classList.remove('open');
    currentPageId = null;

    if (escHandler) {
      document.removeEventListener('keydown', escHandler);
      escHandler = null;
    }

    setTimeout(function () {
      if (panelEl && panelEl.parentNode) {
        panelEl.parentNode.removeChild(panelEl);
      }
      if (backdropEl && backdropEl.parentNode) {
        backdropEl.parentNode.removeChild(backdropEl);
      }
      panelEl = null;
      backdropEl = null;
      isClosing = false;
    }, 300);
  }

  function toggle(pageId) {
    // L-FE-9: Ignore toggle during close animation to prevent race condition.
    if (isClosing) return;
    if (panelEl && panelEl.classList.contains('open')) {
      // If same page, close; if different page, switch content
      var id = pageId || 'dashboard';
      var underscored = id.replace(/-/g, '_');
      if (currentPageId === id || currentPageId === underscored) {
        close();
      } else {
        open(pageId);
      }
    } else {
      open(pageId);
    }
  }

  // -- In-page glossary utility -----------------------------------------------

  /**
   * Create an in-page glossary term DOM element with tooltip.
   *
   * @param {string} term - The glossary term to look up
   * @returns {HTMLElement} A <span> element with the term and tooltip, or
   *          a plain <span> if the term is not in the glossary.
   */
  function glossaryElement(term) {
    injectStyles();

    var definition = GLOSSARY[term];
    var span = mk('span', definition ? 'glossary-term' : '');
    span.textContent = term;

    if (definition) {
      var tooltip = mk('span', 'glossary-tooltip');
      tooltip.textContent = definition;
      span.appendChild(tooltip);
    }

    return span;
  }

  // -- Public API -------------------------------------------------------------

  SG.help = {
    open: open,
    close: close,
    toggle: toggle,
    glossary: glossaryElement
  };
})();
