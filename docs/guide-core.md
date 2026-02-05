# Sentinel Gate OSS - Complete Guide

This guide covers everything you need to install, configure, and run Sentinel Gate, the open-source MCP (Model Context Protocol) proxy with RBAC policy enforcement.

---

## Concepts

### What is MCP?

MCP (Model Context Protocol) is a standard protocol that allows AI agents (like Claude, GPT, etc.) to call external tools. These tools can do anything: read files, query databases, send emails, execute code.

### The Problem

Without control, an AI agent can call **any** tool with **any** arguments. This is dangerous:
- An agent could delete files instead of reading them
- An agent could send emails to anyone
- An agent could access sensitive data
- You have no visibility into what's happening

### The Solution: Sentinel Gate

Sentinel Gate sits between your AI agent and the MCP tools. Every request passes through Sentinel Gate, which:

1. **Authenticates** — Who is making this request?
2. **Evaluates policies** — Is this action allowed for this user?
3. **Logs everything** — Full audit trail of all actions
4. **Forwards or blocks** — Only allowed requests reach the tools

```
┌─────────────┐      ┌─────────────────┐      ┌─────────────┐
│  AI Agent   │ ───► │  Sentinel Gate  │ ───► │  MCP Server │
│  (Claude)   │      │                 │      │  (tools)    │
└─────────────┘      │  ✓ Auth         │      └─────────────┘
                     │  ✓ Policy       │
                     │  ✓ Audit        │
                     └─────────────────┘
```

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Identity** | A user or service account (e.g., "claude", "ci-pipeline") |
| **Role** | A permission group assigned to identities (e.g., "admin", "reader") |
| **API Key** | A secret token that identifies a caller |
| **Policy** | Rules that decide what actions are allowed |
| **Upstream** | The actual MCP server that executes tools |

### How Requests Flow

```
1. Agent sends request  →  "Call tool: delete_file"
2. Sentinel Gate checks →  API key valid? Identity = "claude"
3. Policy evaluation    →  "claude" has role "reader", not "admin"
4. Rule matches         →  "delete_* requires admin role" → DENY
5. Audit log            →  Record: who, what, when, result
6. Response             →  Return error to agent (tool not called)
```

All decisions are **deterministic**: same input = same output. No AI interpretation.

---

## Installation

### Binary Download

Download the latest release for your platform from the [releases page](https://github.com/Sentinel-Gate/Sentinelgate/releases).

```bash
# Linux (amd64)
curl -L https://github.com/Sentinel-Gate/Sentinelgate/releases/latest/download/sentinel-gate-linux-amd64 -o sentinel-gate
chmod +x sentinel-gate
sudo mv sentinel-gate /usr/local/bin/

# macOS (arm64)
curl -L https://github.com/Sentinel-Gate/Sentinelgate/releases/latest/download/sentinel-gate-darwin-arm64 -o sentinel-gate
chmod +x sentinel-gate
sudo mv sentinel-gate /usr/local/bin/
```

### Docker

Pull the pre-built image or build locally:

```bash
# Pull from registry
docker pull ghcr.io/sentinel-gate/sentinelgate:latest

# Or build from source
docker build -t sentinel-gate:latest .

# Run with config file
docker run -d \
  -p 8080:8080 \
  -v ./sentinel-gate.yaml:/etc/sentinel-gate/sentinel-gate.yaml:ro \
  --name sentinel-gate \
  sentinel-gate:latest
```

### Build from Source

Requires Go 1.24 or later:

```bash
git clone https://github.com/Sentinel-Gate/Sentinelgate.git
cd sentinel-gate
go build ./cmd/sentinel-gate
./sentinel-gate --help
```

## Configuration

### File Locations

Sentinel Gate searches for configuration files in this order:

1. `./sentinel-gate.yaml` (current directory)
2. `~/.sentinel-gate/sentinel-gate.yaml` (user home)
3. `/etc/sentinel-gate/sentinel-gate.yaml` (system)

You can override with the `--config` flag:

```bash
sentinel-gate --config /path/to/custom.yaml start
```

### Environment Variables

All configuration can be overridden via environment variables with the `SENTINEL_GATE_` prefix. Nested keys use underscores:

| Config Path | Environment Variable |
|-------------|---------------------|
| `server.http_addr` | `SENTINEL_GATE_SERVER_HTTP_ADDR` |
| `upstream.http` | `SENTINEL_GATE_UPSTREAM_HTTP` |
| `rate_limit.enabled` | `SENTINEL_GATE_RATE_LIMIT_ENABLED` |
| `dev_mode` | `SENTINEL_GATE_DEV_MODE` |

Example:

```bash
export SENTINEL_GATE_SERVER_HTTP_ADDR=":9090"
export SENTINEL_GATE_DEV_MODE=true
sentinel-gate start
```

### Complete Configuration Reference

See the example configuration file `sentinel-gate.example.yaml` for a full working example.

```yaml
# Server configuration
server:
  http_addr: ":8080"  # Address to listen on (default: ":8080")

# Upstream MCP server (exactly one of http or command required)
upstream:
  http: "http://localhost:3000/mcp"  # Remote MCP server URL
  # OR
  command: "npx"                      # Local MCP server command
  args: ["@modelcontextprotocol/server-filesystem", "/tmp"]

# Authentication
auth:
  identities:
    - id: "user-1"
      name: "Alice"
      roles: ["developer"]
  api_keys:
    - key_hash: "sha256:..."   # Generated with: sentinel-gate hash-key "your-key"
      identity_id: "user-1"

# Audit logging
audit:
  output: "stdout"              # Or "file:///var/log/sentinel-gate/audit.log"

# Rate limiting (optional)
rate_limit:
  enabled: true
  ip_rate: 100                  # Requests per minute per IP
  user_rate: 1000               # Requests per minute per user

# Access control policies
policies:
  - name: "default"
    rules:
      - name: "allow-read"
        condition: 'tool.name.startsWith("read_")'
        action: "allow"
      - name: "deny-all"
        condition: "true"
        action: "deny"

# Development mode (disables authentication - NEVER use in production)
dev_mode: false
```

## Authentication

### Generating API Keys

Use the `hash-key` command to generate SHA-256 hashes for API keys:

```bash
# Generate a random 32-byte API key
API_KEY=$(openssl rand -hex 32)
echo "Your API key: $API_KEY"

# Hash it for config
sentinel-gate hash-key "$API_KEY"
# Output: sha256:abc123def456...
```

Store the plaintext key securely for API clients. Store the hash in your config file.

### Identity Configuration

Each identity has an ID, name, and list of roles:

```yaml
auth:
  identities:
    - id: "service-account"
      name: "CI/CD Pipeline"
      roles: ["user"]
    - id: "admin"
      name: "Administrator"
      roles: ["admin", "user"]
```

Roles are arbitrary strings used in policy conditions.

## Admin UI

Sentinel Gate includes a built-in admin interface for managing the proxy.

### Accessing the Admin UI

Open your browser to:

```
http://localhost:8080/admin
```

### Features

The Admin UI allows you to:
- **View status** - Health and configuration overview
- **Manage policies** - Add, edit, and delete policy rules without editing YAML
- **Manage identities** - Create users and assign roles
- **Manage API keys** - Generate and revoke API keys
- **View audit logs** - See recent tool calls and decisions

### Authentication

- **Dev mode**: No API key required - access is open for testing
- **Production mode**: Enter your admin API key to authenticate

Changes made in the Admin UI are saved automatically.

### API Key Headers

Clients authenticate using the `Authorization` header with a Bearer token:

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{}},"id":1}'
```

## Policies

Policies define access control rules using CEL (Common Expression Language).

### CEL Expression Language

CEL is a simple, fast, and safe expression language. Key features:

- String operations: `startsWith()`, `endsWith()`, `contains()`, `matches()`
- List operations: `in`, `size()`, `exists()`, `all()`
- Comparison: `==`, `!=`, `<`, `>`, `<=`, `>=`
- Logic: `&&`, `||`, `!`

### Available Variables

| Variable | Type | Description |
|----------|------|-------------|
| `tool.name` | string | Name of the tool being called |
| `tool.arguments` | map | Arguments passed to the tool |
| `user.id` | string | Authenticated user's identity ID |
| `user.roles` | list | List of roles assigned to the user |
| `request.method` | string | MCP method (e.g., "tools/call") |

### Policy Examples

```yaml
policies:
  - name: "production"
    rules:
      # Allow read-only tools
      - name: "allow-read-tools"
        condition: 'tool.name.startsWith("read_") || tool.name.startsWith("list_")'
        action: "allow"

      # Allow admin users full access
      - name: "admin-full-access"
        condition: '"admin" in user.roles'
        action: "allow"

      # Allow specific tools for developers
      - name: "developer-tools"
        condition: '"developer" in user.roles && tool.name in ["run_tests", "build"]'
        action: "allow"

      # Deny dangerous tools
      - name: "deny-delete"
        condition: 'tool.name.contains("delete")'
        action: "deny"

      # Default deny (catch-all)
      - name: "deny-all"
        condition: "true"
        action: "deny"
```

Rules are evaluated in order. The first matching rule determines the action.

## Transports

### HTTP Mode

HTTP mode is the default when `server.http_addr` is configured. It accepts MCP requests over HTTP:

```yaml
server:
  http_addr: ":8080"

upstream:
  http: "http://localhost:3000/mcp"
```

Clients send requests to the proxy's HTTP endpoint:

```bash
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer your-key" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}'
```

### Stdio Mode

Stdio mode is used when running as an MCP transport layer. Configure an upstream command:

```yaml
upstream:
  command: "npx"
  args: ["@modelcontextprotocol/server-filesystem", "/tmp"]
```

Or pass the command after `--`:

```bash
sentinel-gate start -- npx @modelcontextprotocol/server-filesystem /tmp
```

In stdio mode, the proxy reads JSON-RPC from stdin and writes to stdout, suitable for MCP clients like Claude Desktop.

## Audit Logging

All tool calls are logged to the configured output.

### Stdout Output

```yaml
audit:
  output: "stdout"
```

Logs appear in the container or process stdout as JSON:

```json
{"timestamp":"2024-01-15T10:30:00Z","user_id":"user-1","tool":"read_file","action":"allow","duration_ms":45}
```

### File Output

```yaml
audit:
  output: "file:///var/log/sentinel-gate/audit.log"
```

The path must be absolute. The directory must exist and be writable.

### Log Format

Each log entry contains:

| Field | Description |
|-------|-------------|
| `timestamp` | ISO 8601 timestamp |
| `user_id` | Authenticated identity ID |
| `tool` | Tool name being called |
| `action` | Policy decision (allow/deny) |
| `duration_ms` | Request processing time |

## Rate Limiting

### Configuration

Enable rate limiting to protect against abuse:

```yaml
rate_limit:
  enabled: true
  ip_rate: 100      # Max requests per minute per IP address
  user_rate: 1000   # Max requests per minute per authenticated user
```

### Algorithm

Sentinel Gate uses the GCRA (Generic Cell Rate Algorithm) for smooth rate limiting:

- No "thundering herd" at window boundaries
- Allows brief bursts up to the rate limit
- Accurate tracking per IP and per user

When rate limited, clients receive a `429 Too Many Requests` response.

## Docker Deployment

### Dockerfile

The included `Dockerfile` uses a multi-stage build:

1. **Build stage**: Compiles static binary using `golang:1.24-alpine`
2. **Runtime stage**: Runs on `distroless/static-debian12` (~30MB)

Key features:
- Static binary with no CGO dependencies
- Non-root user for security
- Single exposed port (8080)
- No shell for minimal attack surface

Build the image:

```bash
docker build -t sentinel-gate:latest .
```

### Docker Compose

The `docker-compose.yml` provides a complete deployment with dev mode enabled by default:

```yaml
services:
  sentinel-gate:
    build: .
    ports:
      - "8080:8080"
    environment:
      - SENTINEL_GATE_DEV_MODE=true
    volumes:
      - ./sentinel-gate.example.yaml:/etc/sentinel-gate/sentinel-gate.yaml:ro
    command: ["--config", "/etc/sentinel-gate/sentinel-gate.yaml", "start"]
    healthcheck:
      test: ["CMD", "/sentinel-gate", "--help"]
      interval: 30s
      timeout: 10s
      retries: 3
```

> **Note:** Docker Compose starts in dev mode by default for easy testing. For production, set `SENTINEL_GATE_DEV_MODE=false` and configure API keys.

Commands:

```bash
# Start (with build)
docker compose up -d --build

# View logs
docker compose logs -f

# Stop and clean up
docker compose down -v
```

### Health Checks

The container health check runs `/sentinel-gate --help` which:
- Validates the binary is executable
- Returns exit code 0 on success
- Runs every 30 seconds

### Volume Mounts

Mount your configuration file as read-only:

```bash
-v ./sentinel-gate.yaml:/etc/sentinel-gate/sentinel-gate.yaml:ro
```

For file-based audit logging, mount a writable directory:

```bash
-v ./logs:/var/log/sentinel-gate
```

## CLI Reference

### start

Start the proxy server:

```bash
# Using config file
sentinel-gate start

# With specific config
sentinel-gate --config /path/to/config.yaml start

# With stdio upstream command
sentinel-gate start -- npx @modelcontextprotocol/server-filesystem /tmp
```

### hash-key

Generate SHA-256 hash for an API key:

```bash
sentinel-gate hash-key "your-secret-key"
# Output: sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### version

Display version information:

```bash
sentinel-gate version
```

### help

Display help for any command:

```bash
sentinel-gate --help
sentinel-gate start --help
sentinel-gate hash-key --help
```

## Troubleshooting

### Container Exits Immediately

**Symptoms**: Container starts then exits with code 0 or 1.

**Causes and fixes**:
1. **Missing config file**: Ensure the config is mounted correctly
   ```bash
   docker run -v ./sentinel-gate.yaml:/etc/sentinel-gate/sentinel-gate.yaml:ro ...
   ```

2. **Invalid config**: Check logs for validation errors
   ```bash
   docker logs sentinel-gate
   ```

3. **Missing upstream**: Ensure `upstream.http` or `upstream.command` is configured

### 401 Unauthorized

**Symptoms**: All requests return 401 status.

**Causes and fixes**:
1. **Missing Authorization header**: Include `Authorization: Bearer your-key`

2. **Wrong API key**: Verify the key hash matches
   ```bash
   sentinel-gate hash-key "your-key"
   # Compare output with config
   ```

3. **Key not in config**: Ensure the API key is listed in `auth.api_keys`

### 403 Forbidden

**Symptoms**: Authenticated requests return 403.

**Causes and fixes**:
1. **Policy denies access**: Check policy rules match your use case

2. **Wrong role**: Verify the identity has required roles
   ```yaml
   identities:
     - id: "user-1"
       roles: ["admin"]  # Add required role
   ```

3. **Rule order**: First matching rule wins - check order

### Connection Refused

**Symptoms**: Proxy cannot connect to upstream.

**Causes and fixes**:
1. **Wrong upstream URL**: Verify `upstream.http` is correct

2. **Docker networking**: Use `host.docker.internal` for host services
   ```yaml
   upstream:
     http: "http://host.docker.internal:3000/mcp"
   ```

3. **Upstream not running**: Ensure the MCP server is started

### Rate Limited (429)

**Symptoms**: Requests return 429 Too Many Requests.

**Causes and fixes**:
1. **Too many requests**: Wait and retry with backoff

2. **Limits too low**: Increase rate limits
   ```yaml
   rate_limit:
     ip_rate: 500
     user_rate: 5000
   ```

3. **Shared IP**: Multiple clients behind NAT share IP limit

### Development Mode

Dev mode provides easy testing by:
- **Bypassing authentication** for both Admin UI and MCP proxy calls
- **Enabling debug logging** with verbose output
- **Creating a dev user** with admin and user roles automatically

Enable dev mode in config:

```yaml
dev_mode: true
```

Or via environment:

```bash
export SENTINEL_GATE_DEV_MODE=true
sentinel-gate start
```

> **Warning:** Never use dev mode in production. It disables all authentication.

Debug logs include:
- Config loading details
- Auth decisions
- Policy evaluations
- Upstream communication

---

## Practical Example: Protecting Gmail Access

This example shows how to configure Sentinel Gate to protect Claude Code when it accesses Gmail tools.

### Scenario

You have:
- Claude Code as your AI agent
- A Gmail MCP server that provides email tools
- You want Claude to read emails but NOT delete them

### Step 1: Configure the Upstream

Point Sentinel Gate to your Gmail MCP server:

```yaml
upstream:
  http: "http://localhost:3000/mcp"  # Your Gmail MCP server
```

### Step 2: Create an Identity for Claude

```yaml
auth:
  identities:
    - id: "claude"
      name: "Claude Code"
      roles: ["ai-assistant"]
```

### Step 3: Generate an API Key

```bash
# Generate a random key
API_KEY=$(openssl rand -hex 32)
echo "Save this key: $API_KEY"

# Hash it for config
sentinel-gate hash-key "$API_KEY"
```

Add the hash to config:

```yaml
auth:
  api_keys:
    - key_hash: "sha256:..."  # Output from hash-key command
      identity_id: "claude"
```

### Step 4: Create Policies

```yaml
policies:
  - name: "gmail-safe"
    rules:
      # Allow read operations
      - name: "allow-read"
        condition: 'tool.name in ["read_emails", "get_email", "search_emails", "list_folders"]'
        action: "allow"

      # Allow sending emails
      - name: "allow-send"
        condition: 'tool.name == "send_email"'
        action: "allow"

      # Block ALL destructive operations
      - name: "block-destructive"
        condition: 'tool.name.contains("delete") || tool.name.contains("trash")'
        action: "deny"

      # Deny everything else
      - name: "deny-all"
        condition: "true"
        action: "deny"
```

### Step 5: Configure Claude Code

In Claude Code's MCP settings, point to Sentinel Gate:

```json
{
  "mcpServers": {
    "gmail": {
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer your-api-key-here"
      }
    }
  }
}
```

### Result

| Action | Without Sentinel Gate | With Sentinel Gate |
|--------|----------------------|-------------------|
| Read emails | ✅ Allowed | ✅ Allowed |
| Search emails | ✅ Allowed | ✅ Allowed |
| Send email | ✅ Allowed | ✅ Allowed |
| Delete email | ✅ Allowed | ❌ **Blocked** |
| Empty trash | ✅ Allowed | ❌ **Blocked** |

Everything is logged in the audit trail.

---

## FAQ

### General

**Q: Does Sentinel Gate slow down my AI agent?**

A: Minimal overhead. Sentinel Gate evaluates policies in microseconds and forwards requests immediately. The bottleneck is always the upstream MCP server, not the proxy.

**Q: Do I need a database?**

A: No. Sentinel Gate OSS stores everything in YAML files. No PostgreSQL, no Redis, no external dependencies. Enterprise version uses databases for multi-tenant and advanced features.

**Q: Can I run multiple instances?**

A: Yes. Sentinel Gate is stateless. You can run multiple instances behind a load balancer for high availability.

### Authentication

**Q: What happens if someone steals an API key?**

A: You can revoke it immediately by removing it from the config. The audit log shows exactly what actions were performed with that key. Best practice: one key per identity, rotate regularly.

**Q: Can I use SSO instead of API keys?**

A: SSO/SAML is available in Sentinel Gate Pro (Enterprise). The OSS version uses API keys only.

**Q: What's the difference between Admin UI auth and Proxy auth?**

A: Both use API keys, but for different purposes:
- **Admin UI**: Managing policies, users, viewing logs
- **Proxy**: Making MCP tool calls through Sentinel Gate

In dev mode, both are bypassed for easy testing.

### Policies

**Q: What if no policy matches?**

A: The request is denied by default. Always add a catch-all rule at the end of your policies.

**Q: Can I test policies without affecting production?**

A: Yes. Use `dev_mode: true` locally to test policy changes before deploying.

**Q: How do I debug why a request was denied?**

A: Check the audit log. It shows which rule matched and why the decision was made. Enable debug logging for more details.

### Deployment

**Q: Can I use Sentinel Gate with Claude Desktop?**

A: Yes. Use stdio mode:
```bash
sentinel-gate start -- npx @modelcontextprotocol/server-filesystem /tmp
```
Then configure Claude Desktop to use Sentinel Gate as the MCP server.

**Q: How do I handle multiple MCP servers?**

A: Run multiple Sentinel Gate instances, one per upstream MCP server, on different ports.

**Q: What's the recommended production setup?**

A:
1. Set `dev_mode: false`
2. Configure proper API keys with hashes
3. Enable rate limiting
4. Use file-based audit logging
5. Run in Docker with health checks
6. Put behind a reverse proxy (nginx) with TLS

### Troubleshooting

**Q: I get "authentication required" but I set dev_mode: true**

A: Make sure the environment variable is set correctly:
```bash
export SENTINEL_GATE_DEV_MODE=true
```
Or check that the config file has `dev_mode: true` at the root level (not nested).

**Q: The Admin UI loads but shows errors**

A: Check that the upstream MCP server is running and reachable. Use `/health` endpoint to verify Sentinel Gate is healthy.

**Q: Rate limiting is blocking legitimate requests**

A: Increase the limits:
```yaml
rate_limit:
  ip_rate: 500      # Increase from default 100
  user_rate: 5000   # Increase from default 1000
```
