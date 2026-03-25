<h1 align="center">SentinelGate</h1>

<p align="center">
  <strong>Access control for AI agents.</strong><br>
  Every MCP tool call intercepted, evaluated, and logged — before it executes.<br>
  RBAC · CEL policies · Full audit trail<br><br>
  <sub>For developers and security teams running AI agents with MCP.</sub>
</p>

<p align="center">
  <a href="https://github.com/Sentinel-Gate/Sentinelgate/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Sentinel-Gate/Sentinelgate/ci.yml?style=flat-square&label=CI" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue?style=flat-square" alt="License: AGPL-3.0"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.24+"></a>
  <a href="https://github.com/Sentinel-Gate/Sentinelgate/releases"><img src="https://img.shields.io/badge/Release-v2.0-brightgreen?style=flat-square" alt="Release v2.0"></a>
</p>

<p align="center">
  <a href="#quick-start">Get Started</a> · <a href="https://www.sentinelgate.co.uk">Website</a> · <a href="docs/Guide.md">Docs</a>
</p>

<p align="center">
  <video src="assets/sentinelgate-demo-final.mp4" width="720"></video>
</p>

---

## The problem

AI agents have unrestricted access to your machine — every tool call, shell command, file read, and HTTP request runs with no policy, no authentication, and no audit trail. One prompt injection or one hallucination is all it takes.

## How SentinelGate works

SentinelGate sits between the AI agent and your system. Every action is intercepted, evaluated against your policies, and logged — before it reaches anything. Denied actions are blocked at the proxy.

<p align="center">
  <img src="assets/diagram-how-it-works-2.svg" width="720" alt="How SentinelGate works">
</p>


No code changes. No agent modifications. Single binary, zero dependencies, sub-millisecond overhead.

<p align="center">
  <img src="assets/screenshot-hero.png" width="820" alt="Tools & Rules with per-tool Allow/Deny enforcement">
</p>

---

## Quick start

**Install** (macOS / Linux):

```bash
curl -sSfL https://raw.githubusercontent.com/Sentinel-Gate/Sentinelgate/main/install.sh | sh
```

**Install** (Windows PowerShell):

```powershell
irm https://raw.githubusercontent.com/Sentinel-Gate/Sentinelgate/main/install.ps1 | iex
```

<details>
<summary>Manual download or build from source</summary>

**Download** from [GitHub Releases](https://github.com/Sentinel-Gate/Sentinelgate/releases):

| Platform | Archive |
|----------|---------|
| macOS (Apple Silicon) | `sentinel-gate_darwin_arm64.tar.gz` |
| macOS (Intel) | `sentinel-gate_darwin_amd64.tar.gz` |
| Linux (x86_64) | `sentinel-gate_linux_amd64.tar.gz` |
| Linux (ARM64) | `sentinel-gate_linux_arm64.tar.gz` |
| Windows (x86_64) | `sentinel-gate_windows_amd64.zip` |
| Windows (ARM64) | `sentinel-gate_windows_arm64.zip` |

**macOS / Linux:**
```bash
tar xzf sentinel-gate_*.tar.gz
chmod +x sentinel-gate
sudo mv sentinel-gate /usr/local/bin/
```

**Windows:** extract the `.zip` and add `sentinel-gate.exe` to your `PATH`.

**Build from source** (Go 1.24+):

macOS / Linux:
```bash
git clone https://github.com/Sentinel-Gate/Sentinelgate.git
cd Sentinelgate && go build -o sentinel-gate ./cmd/sentinel-gate
```

Windows:
```powershell
git clone https://github.com/Sentinel-Gate/Sentinelgate.git
cd Sentinelgate; go build -o sentinel-gate.exe ./cmd/sentinel-gate
```

</details>

**Start:**

```bash
$ sentinel-gate start

  SentinelGate 2.0.0
  ─────────────────────────────────────
  Admin UI:      http://localhost:8080/admin
  Proxy:         http://localhost:8080/mcp
  Upstreams:     1 connected / 1 configured
  Tools:         12 discovered
  Rules:         0 active
  ─────────────────────────────────────
```

> Output may vary depending on your configuration.

Open **http://localhost:8080/admin** to manage policies, upstreams, and identities. The MCP endpoint is **http://localhost:8080/mcp** — configure your agent to connect there with an API key.

---

## Playground

See SentinelGate block a prompt injection attack — 30 seconds, no setup:

**macOS / Linux:**
```bash
cd examples/playground
./playground.sh
```

**Windows PowerShell:**
```powershell
cd examples\playground
.\playground.ps1
```

The script creates 3 policies, simulates 4 agent tool calls (1 allowed, 3 blocked), and cleans up after. Only needs bash + curl or PowerShell. Full walkthrough: [examples/playground/READMEplayground.md](examples/playground/READMEplayground.md).

---

## Connect your agent

SentinelGate works with any MCP-compatible client. Point your agent to `http://localhost:8080/mcp` with an API key:

| Client | Setup |
|--------|-------|
| Claude Code | `claude mcp add --transport http sentinelgate http://localhost:8080/mcp --header "Authorization: Bearer <key>"` |
| Cursor / IDE | Add MCP server in settings with URL `http://localhost:8080/mcp` |
| Gemini CLI | MCP config with `http` transport |
| Codex CLI | MCP config with `http` transport |
| Python / Node.js / cURL | Standard HTTP with `Authorization: Bearer <key>` header |

Full setup snippets for each client: [Connect Your Agent](docs/Guide.md#2-quick-start)

---

## Features

**Deterministic enforcement** — Explicit rules, not AI judgment. `deny delete_*` means denied. Always.

**MCP-native** — Built as an [MCP](https://modelcontextprotocol.io) proxy. Aggregates multiple upstream servers, applies per-tool policies, exposes a single endpoint.

**CEL-powered rules** — [Common Expression Language](https://github.com/google/cel-go), the same engine behind Kubernetes, Firebase, and Envoy:

```cel
action_arg_contains(arguments, "secret")                      // block by content
action_name == "bash" && !("admin" in identity_roles)             // role-based shell control
dest_domain_matches(dest_domain, "*.pastebin.com")             // outbound blocking
```

Simple tool patterns (`read_*`, `delete_*`) cover most cases. CEL handles the rest.

**Full audit trail** — Every action logged with identity, decision, timestamp, and arguments. Stream live via SSE, filter, or export.

**Admin UI** — Browser-based policy editor, test playground, security settings, audit viewer. No config files, no restarts.

**Identity and access control** — API keys, roles, per-identity policies. Each agent gets isolated credentials.

**Content scanning** — Bidirectional PII, secrets, and IPI detection on tool arguments and responses. Configurable whitelist with contextual exemptions.

**Session-aware policies** — CEL functions that use session history for context-dependent rules. Detect patterns like read-then-exfiltrate across multiple tool calls: `session_call_count`, `session_write_count`, `session_sequence`, and more.

**Red team testing** — 30 built-in attack patterns across 6 categories (prompt injection, tool poisoning, exfiltration, privilege escalation, evasion, resource abuse). Interactive report with one-click remediation.

&nbsp;

<details>
<summary><strong>More features (13)</strong></summary>

**Policy templates** — Seven pre-built security profiles (Safe Coding, Read Only, Research Mode, Full Lockdown, Audit Only, Data Protection, Anti-Exfiltration). One click to apply, fully customizable after.

**Budget and quota** — Per-identity usage limits: max calls, writes, deletes per session, rate limiting per minute. Deny or warn when limits are reached. Live progress tracking on the dashboard.

**Response transformation** — Five transform types applied to tool responses before they reach the agent: redact (regex-based), truncate (size limits), inject (prepend/append warnings), dry-run (mock responses), mask (partial reveal). Test in the built-in sandbox.

**Session recording** — Record every tool call with full request/response payloads. Timeline replay in the UI, export to JSON or CSV, configurable retention, privacy mode (record metadata only).

**Cryptographic evidence** — Every decision signed with ECDSA P-256 and hash-chained. Tamper-proof audit receipts for compliance. EU AI Act-ready compliance bundles with coverage mapping.

**Tool integrity** — Hash-based baseline for tool definitions, drift detection on schema changes, quarantine for mutated tools, diff viewer.

**Behavioral drift detection** — 14-day baseline vs current behavior comparison. Detects tool distribution shifts, deny rate changes, temporal anomalies, and argument pattern drift.

**Agent health dashboard** — Per-agent health metrics (deny rate, drift score, violations) with 30-day sparklines, baseline comparison, and cross-agent overview. CEL variables for health-based policies.

**Permission health & shadow mode** — Identifies over-privileged agents by comparing granted vs actual tool usage. Auto-tighten suggestions with one-click apply.

**FinOps cost explorer** — Per-tool cost estimation, per-identity budgets with threshold alerts, cost drill-down, budget guardrail creation via Policy Builder.

**Namespace isolation** — Role-based tool visibility with whitelist/blacklist glob patterns.

**OpenTelemetry export** — Stdout span export for every tool call with identity, decision, and latency.

**Human-in-the-loop** — Escrow workflow for sensitive operations. Approve/deny with decision context, session trail, and signed audit note.

</details>

---

## Admin UI

| Tools & Rules | Audit Log |
|:-:|:-:|
| <img src="assets/screenshot-rules.png" width="410" alt="Tools & Rules with per-tool Allow/Deny enforcement"> | <img src="assets/screenshot-audit.png" width="410" alt="Audit log viewer"> |

| Content Scanning | Policy Test |
|:-:|:-:|
| <img src="assets/screenshot-security.png" width="410" alt="Content scanning with Monitor and Enforce modes"> | <img src="assets/screenshot-policy-test.png" width="410" alt="Policy test playground"> |

13 pages: Dashboard, Getting Started, Tools & Rules (with Transforms, Policy Test, and Simulation tabs), Access (with Quota management), Audit Log, Sessions, Notifications, Compliance, Permissions, Security, Red Team, FinOps, and Clients (with Agent Health).

---

## Configuration

> [!NOTE]
> Works with **zero configuration**. Everything is managed from the Admin UI and persisted automatically.

For infrastructure tuning, an optional YAML config is available:

```yaml
server:
  http_addr: ":8080"
rate_limit:
  enabled: true
  ip_rate: 100
```

Full reference: [Configuration](docs/Guide.md#7-configuration-reference) · [CLI](docs/Guide.md#8-cli-reference) · [API](docs/Guide.md#9-admin-api-reference)

---

## Limitations

> [!CAUTION]
> SentinelGate is an MCP proxy — it controls what tools and data your agents can access through the MCP protocol. It is effective against mistakes, prompt injection, and overreach. For full OS-level isolation, combine with container or VM sandboxes.

Full [threat model](docs/Guide.md#13-threat-model-and-limitations).

---

## SentinelGate Pro

Extended retention · SIEM integration · SSO · Multi-tenancy · Advanced FinOps with billing API integration · Cross-agent health export — [sentinelgate.co.uk](https://www.sentinelgate.co.uk)

## Contributing

Bug fixes, features, docs, and feedback welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). A CLA is required for code contributions — see [CLA.md](CLA.md).

## License

[AGPL-3.0](LICENSE) — free to use, modify, and self-host. For commercial licensing, [contact us](mailto:hello@sentinelgate.co.uk).

---
<p align="center">
  <a href="https://www.sentinelgate.co.uk">Website</a> &middot; <a href="docs/Guide.md">Docs</a> &middot; <a href="https://github.com/Sentinel-Gate/Sentinelgate/releases">Releases</a>
</p>
