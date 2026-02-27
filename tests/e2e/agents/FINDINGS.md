# Findings — Phase E+F Manual Testing

## Finding 1: Policy templates reference removed `execute_*` tools
- **Where**: `internal/domain/policy/template.go`
- **Templates affected**: Safe Coding (line 101), Data Protection (line 245)
- **Issue**: Rule "Deny command execution" with `tool_match: execute_*` matches no real tool (removed with `run`)
- **Descriptions affected**:
  - Safe Coding: "blocks command execution" — no longer applicable
  - Read Only: "Blocks all writes and executions" — "executions" misleading
  - Data Protection: "and command execution" — no longer applicable
- **Impact**: Functional (no errors), but misleading to users
- **Fix**: Remove `execute_*` rules, update descriptions

---

## Finding 2: Getting Started — card layout spacing not uniform
- **Where**: Getting Started page, bottom 3 cards (MCP Proxy, HTTP Gateway, MCP Client SDK)
- **Issue**: The top 4 feature cards have uniform grid spacing, but the bottom 3 use-case cards have inconsistent spacing — MCP Proxy + HTTP Gateway on one row, MCP Client SDK alone below, heights/margins unbalanced
- **Screenshots**: `Screen/1.png`
- **Fix**: CSS grid fix for the bottom card row

---

## Finding 3: Getting Started — MCP Proxy card has wrong/incomplete agent config
- **Where**: Getting Started page → MCP Proxy card (expanded)
- **Issues**:
  1. Says "Claude Desktop, Cursor, etc." — should say "Claude Code, Gemini CLI, Codex CLI, Cursor, etc."
  2. Expanded content shows only a generic `sentinel-gate.yaml` snippet
  3. Does NOT show how to configure each agent:
     - Claude Code: `claude mcp add` command
     - Gemini CLI: `~/.gemini/settings.json` snippet
     - Codex CLI: `~/.codex/config.toml` snippet
     - Cursor/IDE: JSON config snippet
     - Python: code snippet with MCP SDK
     - Node.js: code snippet with MCP SDK
  4. This was supposed to be the main onboarding point for users connecting AI agents
  5. The YAML snippet shown is not even the standard format — we typically use JSON/TOML, and before this regression there were JSON and TOML examples. Now there's only a useless YAML block
- **Screenshots**: `Screen/2.png`
- **Fix**: Rewrite MCP Proxy expanded content with per-agent config tabs (like Access page already has) showing JSON/TOML/CLI snippets per agent

---

## Finding 4: Getting Started MCP Proxy card should reuse Access page agent tabs
- **Where**: Getting Started page → MCP Proxy expanded vs Access page → "Connect Your Agent"
- **Issue**: The Access page already has excellent per-agent config tabs (Claude Code, Gemini CLI, Codex CLI, Cursor/IDE, Python, Node.js, cURL) with correct snippets. But the Getting Started page (which is the first thing users see) shows a useless YAML block instead. These two pages are inconsistent — the onboarding page is worse than the detail page.
- **Fix**: Either embed the same tab component from Access into Getting Started's MCP Proxy card, or replace the MCP Proxy expanded content with a direct link "Go to Access → Connect Your Agent" with a brief intro

---

## Finding 5: Python/Node.js snippets in Access end with "Follow MCP client library documentation"
- **Where**: Access page → Connect Your Agent → Python tab, Node.js tab
- **Issue**: Both snippets show only the import + client creation, then say "Follow MCP client library documentation" without showing how to actually call tools (initialize, tools/list, tools/call). The cURL tab is more complete (shows initialize + tools/list).
- **Impact**: Minor — user still needs to figure out the actual usage
- **Fix**: Add 2-3 more lines showing initialize + tools/list call, or link to docs

---

## Note 1: macOS /tmp → /private/tmp symlink (NOT a bug)
- **What**: When an agent asks for `/tmp/sg-e2e-test/`, the filesystem MCP server rejects it because it's configured with `/private/tmp/sg-e2e-test` (the real path). Agent retries with `/private/tmp/...` and succeeds.
- **Why**: macOS has `/tmp` as symlink to `/private/tmp`. The global-setup resolves it with `fs.realpathSync`.
- **Impact**: Claude handles it, but dumber agents (Gemini, Codex, custom Python) might just fail
- **Suggestion**: Add a macOS note in Getting Started/docs warning that `/tmp` → `/private/tmp`. Also, agent-setup.sh and test instructions should always use `/private/tmp/sg-e2e-test` on macOS

---

## Finding 6: Clients page shows identity UUID instead of name
- **Where**: Clients page → IDENTITY column
- **Issue**: Shows UUIDs like `6c435f12-2930-4d87-9ad4-25e959a856ae` instead of human-readable names like `gemini-tester`. The Dashboard page correctly shows names in the Active Sessions widget — so the data is available, just not used in Clients.
- **Screenshots**: `Screen/clients-uuid.png`
- **Fix**: Resolve identity ID → name in the Clients page JS (same lookup the Dashboard already does)

---

## Finding 7: Codex CLI fails to authenticate with SentinelGate
- **Where**: Codex CLI MCP startup
- **Issue**: `MCP startup failed: handshaking with MCP server failed: JSON-RPC error: -32600: Authentication required`
- **Config used**:
  ```toml
  [mcp_servers.sentinelgate]
  url = "http://localhost:8080/mcp"
  [mcp_servers.sentinelgate.headers]
  Authorization = "Bearer sg_..."
  ```
- **Hypothesis**: Codex may not support custom headers in TOML config, or the format is different. Need to check Codex docs for correct MCP server config with auth headers.
- **Impact**: Codex CLI cannot connect to SentinelGate with auth enabled
- **Fix**: Investigate correct Codex TOML format for MCP headers; update Access page snippet if wrong

---

## Finding 8: Sessions show "connected" after agents disconnect
- **Where**: Clients page
- **Issue**: After closing all agents (Claude, Gemini, Codex), the Clients page still shows 2 active sessions with "connected" status. Sessions remain until the 30min timeout expires.
- **Root cause**: Agents don't send `DELETE /mcp` on shutdown — they just close the TCP connection. SentinelGate has no way to detect the disconnect until session timeout.
- **Impact**: Misleading status — admin thinks agents are still connected when they're not
- **Possible fixes**:
  1. Show "last activity" age more prominently — if >5min, show as "idle" or "stale"
  2. Add a heartbeat/ping mechanism (but this would require client cooperation)
  3. Reduce default session timeout for display purposes
- **Screenshots**: Clients page after all agents closed, still showing 2 connected

---

## TODO — Phase F (da fare alla prossima sessione)
- [ ] Test notifications: aggiungere upstream mentre Claude/Gemini sono connessi → verificare che ricevano nuovi tool
- [ ] Test con MCP server esterno HTTP (non stdio) — upstream remoto via internet
- [ ] Test transform + agent (redact)
- [ ] Test quota + agent (deny al superamento)
- [ ] Ripristinare config Gemini e Codex con agent-cleanup.sh

---

<!-- Add new findings below -->
