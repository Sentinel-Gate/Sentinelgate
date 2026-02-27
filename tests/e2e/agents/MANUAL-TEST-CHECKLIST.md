# SentinelGate E2E Manual Test Checklist — Phases E & F

> **Version**: 1.0
> **Date**: 2026-02-26
> **Total checks**: 94
> **Estimated time**: ~60-90 minutes

---

## Table of Contents

1. [Prerequisites & Setup](#prerequisites--setup)
2. [Phase E: Real Agent Testing](#phase-e-real-agent-testing)
   - [E.1 Claude Code](#e1-claude-code)
   - [E.2 Gemini CLI](#e2-gemini-cli)
   - [E.3 Codex CLI](#e3-codex-cli)
3. [Phase F: Cross-Feature Scenarios](#phase-f-cross-feature-scenarios)
   - [F.1 Multi-Agent Simultaneous](#f1-multi-agent-simultaneous)
   - [F.2 Notifications with Real Agent](#f2-notifications-with-real-agent)
   - [F.3 Transform + Agent](#f3-transform--agent)
   - [F.4 Quota + Agent](#f4-quota--agent)
4. [Results Summary](#results-summary)

---

## Prerequisites & Setup

### Environment Preparation

- [ ] SentinelGate binary is built and up to date (`go build -o sentinel-gate ./cmd/sentinel-gate`)
- [ ] SentinelGate is running on `http://localhost:8080`
- [ ] Admin UI is accessible at `http://localhost:8080/admin/`

### Upstream Servers

- [ ] **filesystem** upstream configured and reachable (e.g. `npx @anthropic/mcp-filesystem /tmp/sg-e2e-test`)
- [ ] **fetch** upstream configured and reachable (e.g. `npx @anthropic/mcp-fetch`)
- [ ] **memory** upstream configured and reachable (e.g. `npx @anthropic/mcp-memory`)
- [ ] All 3 upstreams visible in Admin UI → Upstreams page

### Identity & Auth

- [ ] Identity `e2e-tester` created with a dedicated API key
- [ ] API key noted down: `_________________________________________`
- [ ] (Phase F only) Second identity `e2e-tester-2` created with a separate API key
- [ ] Second API key noted down: `_________________________________________`

### Policy Configuration

- [ ] Default policy: **allow-all**
- [ ] Deny policy active on tool `write_file` (applies to `e2e-tester`)
- [ ] Policy verified in Admin UI → Policies page

### Recording Configuration

- [ ] Recording mode set to `all`
- [ ] `record_payloads` set to `true`
- [ ] Recording config verified in Admin UI → Settings or config file

### Test Directory

- [ ] `/tmp/sg-e2e-test/` directory exists
- [ ] `/tmp/sg-e2e-test/test.txt` exists with known content (e.g. `Hello from SentinelGate E2E test`)
- [ ] `/tmp/sg-e2e-test/data.json` exists with known JSON (e.g. `{"key": "value", "number": 42}`)
- [ ] `/tmp/sg-e2e-test/subdir/` directory exists

Create the test directory:

```bash
mkdir -p /tmp/sg-e2e-test/subdir
echo "Hello from SentinelGate E2E test" > /tmp/sg-e2e-test/test.txt
echo '{"key": "value", "number": 42}' > /tmp/sg-e2e-test/data.json
```

---

## Phase E: Real Agent Testing

### E.1 Claude Code

#### Configuration

Add the MCP server to Claude Code:

```bash
claude mcp add sentinelgate --transport http http://localhost:8080/mcp \
  -H "Authorization: Bearer <key>"
```

- [ ] MCP server added successfully (no errors)
- [ ] Claude Code recognizes the sentinelgate server (`claude mcp list` shows it)

#### Task 1: List Files & Read Content

**Prompt to give Claude:**

> Using the sentinelgate MCP server, list the files in /tmp/sg-e2e-test/, then read the content of test.txt

**Verification — Agent behavior:**

- [ ] Claude calls `list_directory` (or equivalent) on `/tmp/sg-e2e-test/`
- [ ] Claude receives and displays the file listing (test.txt, data.json, subdir/)
- [ ] Claude calls `read_file` on `/tmp/sg-e2e-test/test.txt`
- [ ] Claude displays the correct content: `Hello from SentinelGate E2E test`

**Verification — Admin UI:**

- [ ] Audit log shows `list_directory` call from identity `e2e-tester`
- [ ] Audit log shows decision: **allowed**
- [ ] Audit log shows `read_file` call from identity `e2e-tester`
- [ ] Audit log shows decision: **allowed**
- [ ] Recorded payload contains the correct file content

#### Task 2: Fetch URL

**Prompt to give Claude:**

> Using sentinelgate, fetch the URL https://httpbin.org/get

**Verification — Agent behavior:**

- [ ] Claude calls `fetch` with URL `https://httpbin.org/get`
- [ ] Claude receives and displays a valid HTTP JSON response (contains `"url"`, `"headers"`, etc.)

**Verification — Admin UI:**

- [ ] Audit log shows `fetch` call from identity `e2e-tester`
- [ ] Audit log shows decision: **allowed**
- [ ] Recorded payload contains the httpbin response

#### Task 3: Memory Store & Retrieve

**Prompt to give Claude:**

> Using sentinelgate, store value 'hello' with key 'test' in memory, then retrieve it

**Verification — Agent behavior:**

- [ ] Claude calls the memory store tool (e.g. `store` or `create_entities`)
- [ ] Claude calls the memory retrieve tool (e.g. `retrieve` or `read_graph`)
- [ ] Claude displays the stored value `hello`

**Verification — Admin UI:**

- [ ] Audit log shows store call from identity `e2e-tester` — **allowed**
- [ ] Audit log shows retrieve call from identity `e2e-tester` — **allowed**

#### Task 4: Deny Test (write_file)

**Prompt to give Claude:**

> Using sentinelgate, write a file test-deny.txt in /tmp/sg-e2e-test/ with content "this should be denied"

**Verification — Agent behavior:**

- [ ] Claude attempts to call `write_file`
- [ ] Claude receives a denial/error response
- [ ] File `/tmp/sg-e2e-test/test-deny.txt` does NOT exist on disk

**Verification — Admin UI:**

- [ ] Audit log shows `write_file` call from identity `e2e-tester`
- [ ] Audit log shows decision: **denied**

#### Session Verification

- [ ] Session recording in Admin UI → Recordings shows the complete Claude session
- [ ] All 4+ tool calls are visible in the recording
- [ ] Connected Clients showed an active session while Claude was connected

#### Cleanup

```bash
claude mcp remove sentinelgate
```

- [ ] MCP server removed from Claude Code

---

### E.2 Gemini CLI

#### Configuration

Create or update `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "sentinelgate": {
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer <key>"
      }
    }
  }
}
```

- [ ] Config file saved
- [ ] Gemini CLI starts and recognizes the sentinelgate server

#### Task 1: List Files & Read Content

**Prompt to give Gemini:**

> Using the sentinelgate MCP server, list the files in /tmp/sg-e2e-test/, then read the content of test.txt

**Verification — Agent behavior:**

- [ ] Gemini calls `list_directory` and displays file listing
- [ ] Gemini calls `read_file` and displays correct content

**Verification — Admin UI:**

- [ ] Audit log shows `list_directory` from `e2e-tester` — **allowed**
- [ ] Audit log shows `read_file` from `e2e-tester` — **allowed**

#### Task 2: Fetch URL

**Prompt to give Gemini:**

> Using sentinelgate, fetch the URL https://httpbin.org/get

**Verification — Agent behavior:**

- [ ] Gemini calls `fetch` and displays valid HTTP JSON response

**Verification — Admin UI:**

- [ ] Audit log shows `fetch` from `e2e-tester` — **allowed**

#### Task 3: Memory Store & Retrieve

**Prompt to give Gemini:**

> Using sentinelgate, store value 'hello' with key 'test' in memory, then retrieve it

**Verification — Agent behavior:**

- [ ] Gemini calls memory store tool and retrieves the value successfully

**Verification — Admin UI:**

- [ ] Audit log shows store and retrieve calls — both **allowed**

#### Task 4: Deny Test (write_file)

**Prompt to give Gemini:**

> Using sentinelgate, write a file test-deny.txt in /tmp/sg-e2e-test/ with content "this should be denied"

**Verification — Agent behavior:**

- [ ] Gemini attempts `write_file` and receives denial/error
- [ ] File does NOT exist on disk

**Verification — Admin UI:**

- [ ] Audit log shows `write_file` from `e2e-tester` — **denied**

#### Session Verification

- [ ] Session recording shows complete Gemini session
- [ ] Connected Clients showed active session during execution

#### Cleanup

- [ ] Remove sentinelgate entry from `~/.gemini/settings.json`

---

### E.3 Codex CLI

#### Configuration

Create or update `~/.codex/config.toml`:

```toml
[mcp_servers.sentinelgate]
url = "http://localhost:8080/mcp"

[mcp_servers.sentinelgate.headers]
Authorization = "Bearer <key>"
```

- [ ] Config file saved
- [ ] Codex CLI starts and recognizes the sentinelgate server

#### Task 1: List Files & Read Content

**Prompt to give Codex:**

> Using the sentinelgate MCP server, list the files in /tmp/sg-e2e-test/, then read the content of test.txt

**Verification — Agent behavior:**

- [ ] Codex calls `list_directory` and displays file listing
- [ ] Codex calls `read_file` and displays correct content

**Verification — Admin UI:**

- [ ] Audit log shows `list_directory` from `e2e-tester` — **allowed**
- [ ] Audit log shows `read_file` from `e2e-tester` — **allowed**

#### Task 2: Fetch URL

**Prompt to give Codex:**

> Using sentinelgate, fetch the URL https://httpbin.org/get

**Verification — Agent behavior:**

- [ ] Codex calls `fetch` and displays valid HTTP JSON response

**Verification — Admin UI:**

- [ ] Audit log shows `fetch` from `e2e-tester` — **allowed**

#### Task 3: Memory Store & Retrieve

**Prompt to give Codex:**

> Using sentinelgate, store value 'hello' with key 'test' in memory, then retrieve it

**Verification — Agent behavior:**

- [ ] Codex calls memory store tool and retrieves the value successfully

**Verification — Admin UI:**

- [ ] Audit log shows store and retrieve calls — both **allowed**

#### Task 4: Deny Test (write_file)

**Prompt to give Codex:**

> Using sentinelgate, write a file test-deny.txt in /tmp/sg-e2e-test/ with content "this should be denied"

**Verification — Agent behavior:**

- [ ] Codex attempts `write_file` and receives denial/error
- [ ] File does NOT exist on disk

**Verification — Admin UI:**

- [ ] Audit log shows `write_file` from `e2e-tester` — **denied**

#### Session Verification

- [ ] Session recording shows complete Codex session
- [ ] Connected Clients showed active session during execution

#### Cleanup

- [ ] Remove sentinelgate entry from `~/.codex/config.toml`

---

## Phase F: Cross-Feature Scenarios

### F.1 Multi-Agent Simultaneous

#### Prerequisites

- [ ] Two distinct identities configured: `e2e-tester` (key A) and `e2e-tester-2` (key B)
- [ ] Claude Code configured with key A
- [ ] Gemini CLI configured with key B
- [ ] Both agents started and connected

#### Test Steps

**Prompt to Claude:**

> Using sentinelgate, list the files in /tmp/sg-e2e-test/

**Prompt to Gemini (while Claude is still connected):**

> Using sentinelgate, read the file /tmp/sg-e2e-test/data.json

#### Verification

- [ ] Both agents execute their tool calls successfully
- [ ] Audit log shows `list_directory` from identity `e2e-tester`
- [ ] Audit log shows `read_file` from identity `e2e-tester-2`
- [ ] Identities are correctly distinguished (not mixed up)
- [ ] Dashboard → Connected Clients shows **2** active sessions simultaneously
- [ ] Per-identity call counts are independent (each shows own count)

#### Cleanup

- [ ] Disconnect both agents

---

### F.2 Notifications with Real Agent

#### Prerequisites

- [ ] Claude Code connected to sentinelgate and working
- [ ] Claude has already called `tools/list` at least once (e.g. by executing any tool call)
- [ ] A new upstream MCP server is ready to be added (e.g. a second memory server on a different port)

#### Test Steps

1. Note the current tool list Claude sees from sentinelgate

   - [ ] Current tool count noted: `_____`

2. In Admin UI, add a new upstream server (e.g. another MCP server)

   - [ ] New upstream added via Admin UI
   - [ ] Upstream shows as connected in Admin UI

3. Wait for notification propagation (up to 30 seconds)

4. Ask Claude:

   > Using sentinelgate, list all available tools

   - [ ] Claude calls `tools/list`

#### Verification

- [ ] Claude sees new tools that were not present before
- [ ] New tool count is greater than previous: `_____` > `_____`
- [ ] Claude did NOT need to be restarted
- [ ] Audit log shows the notification event (if logged)

#### Cleanup

- [ ] Remove the extra upstream from Admin UI (optional)

---

### F.3 Transform + Agent

#### Prerequisites

- [ ] A **Redact** transform is configured with pattern: `Bearer [a-zA-Z0-9_]+`
- [ ] Transform is active and applied to outbound responses
- [ ] Transform verified in Admin UI → Transforms page

#### Test Steps

**Prompt to Claude:**

> Using sentinelgate, fetch the URL https://httpbin.org/get

(httpbin.org/get echoes back request headers including the Authorization header)

#### Verification

- [ ] Claude receives the fetch response
- [ ] The response displayed by Claude does NOT contain the raw Bearer token
- [ ] The token value is redacted (replaced with `[REDACTED]` or similar)
- [ ] Audit log shows the transform was applied to this call
- [ ] The original (un-redacted) response is NOT leaked to the agent

#### Cleanup

- [ ] Deactivate or remove the Redact transform

---

### F.4 Quota + Agent

#### Prerequisites

- [ ] Identity `e2e-tester` (or a dedicated test identity) configured with `MaxCallsPerSession = 5`
- [ ] Quota configuration verified in Admin UI
- [ ] Claude Code connected with this identity
- [ ] Start a fresh session (no prior calls in this session)

#### Test Steps

Ask Claude to make repeated calls. Give these prompts one at a time:

**Call 1:**
> Using sentinelgate, list the files in /tmp/sg-e2e-test/

- [ ] Call 1 succeeds

**Call 2:**
> Using sentinelgate, read the file /tmp/sg-e2e-test/test.txt

- [ ] Call 2 succeeds

**Call 3:**
> Using sentinelgate, read the file /tmp/sg-e2e-test/data.json

- [ ] Call 3 succeeds

**Call 4:**
> Using sentinelgate, fetch the URL https://httpbin.org/get

- [ ] Call 4 succeeds

**Call 5:**
> Using sentinelgate, list the files in /tmp/sg-e2e-test/subdir/

- [ ] Call 5 succeeds (this is the last allowed call)

**Call 6 (should be denied):**
> Using sentinelgate, read the file /tmp/sg-e2e-test/test.txt again

- [ ] Call 6 is **denied** (quota exceeded)
- [ ] Claude receives a clear error indicating quota exhaustion

#### Verification — Admin UI

- [ ] Audit log shows 5 allowed calls + 1 denied call for this session
- [ ] The 6th call denial reason is quota exceeded
- [ ] Dashboard shows quota usage at 100% for this identity/session
- [ ] Dashboard progress bar is red (or indicates exhaustion)

#### Cleanup

- [ ] Reset quota for the identity or remove the MaxCallsPerSession limit

---

## Results Summary

### Phase E — Real Agent Testing

| Agent       | Task 1 (List+Read) | Task 2 (Fetch) | Task 3 (Memory) | Task 4 (Deny) | Session Recording | Overall |
|-------------|:-------------------:|:--------------:|:---------------:|:--------------:|:-----------------:|:-------:|
| Claude Code | [ ] PASS / [ ] FAIL | [ ] PASS / [ ] FAIL | [ ] PASS / [ ] FAIL | [ ] PASS / [ ] FAIL | [ ] PASS / [ ] FAIL | _______ |
| Gemini CLI  | [ ] PASS / [ ] FAIL | [ ] PASS / [ ] FAIL | [ ] PASS / [ ] FAIL | [ ] PASS / [ ] FAIL | [ ] PASS / [ ] FAIL | _______ |
| Codex CLI   | [ ] PASS / [ ] FAIL | [ ] PASS / [ ] FAIL | [ ] PASS / [ ] FAIL | [ ] PASS / [ ] FAIL | [ ] PASS / [ ] FAIL | _______ |

### Phase F — Cross-Feature Scenarios

| Scenario                   | Result              | Notes |
|----------------------------|:-------------------:|-------|
| F.1 Multi-Agent Simultaneous | [ ] PASS / [ ] FAIL |       |
| F.2 Notifications           | [ ] PASS / [ ] FAIL |       |
| F.3 Transform + Agent       | [ ] PASS / [ ] FAIL |       |
| F.4 Quota + Agent           | [ ] PASS / [ ] FAIL |       |

### Overall Summary

| Phase   | Total Checks | Passed | Failed | Skipped | Notes |
|---------|:------------:|:------:|:------:|:-------:|-------|
| Phase E |              |        |        |         |       |
| Phase F |              |        |        |         |       |
| **Total** |            |        |        |         |       |

### Issues Found

| # | Phase | Scenario | Description | Severity | Status |
|---|-------|----------|-------------|----------|--------|
| 1 |       |          |             |          |        |
| 2 |       |          |             |          |        |
| 3 |       |          |             |          |        |

---

**Tester**: ___________________________
**Date completed**: ___________________________
**SentinelGate version**: ___________________________
**Go version**: ___________________________
**OS**: ___________________________
