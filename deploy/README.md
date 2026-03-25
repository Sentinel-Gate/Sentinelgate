# SentinelGate Deployment

## Auto-Restart Configuration

SentinelGate is a single point in the agent tool-call path. If it crashes, all agents stop. These configurations ensure automatic restart within seconds.

### Docker (recommended)

```bash
docker run -d --restart=unless-stopped \
  -p 8080:8080 \
  -v ./config.yaml:/etc/sentinel-gate/sentinel-gate.yaml:ro \
  -v sg-data:/data \
  ghcr.io/sentinel-gate/sentinelgate:latest
```

The Dockerfile includes a built-in healthcheck (`/health` endpoint, 30s interval).

### systemd (Linux)

```bash
# Install binary
sudo cp sentinel-gate /usr/local/bin/
sudo chmod +x /usr/local/bin/sentinel-gate

# Create user and data directory
sudo useradd -r -s /usr/sbin/nologin sentinel-gate
sudo mkdir -p /var/lib/sentinel-gate
sudo chown sentinel-gate:sentinel-gate /var/lib/sentinel-gate

# Install service
sudo cp deploy/systemd/sentinel-gate.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sentinel-gate
sudo systemctl start sentinel-gate

# Check status
sudo systemctl status sentinel-gate
journalctl -u sentinel-gate -f
```

Key settings: `Restart=always`, `RestartSec=2`, `WatchdogSec=30`.

### launchd (macOS)

```bash
# Install binary
sudo cp sentinel-gate /usr/local/bin/
sudo mkdir -p /usr/local/var/sentinel-gate /usr/local/var/log

# Install service
sudo cp deploy/launchd/co.sentinelgate.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/co.sentinelgate.plist

# Check status
sudo launchctl list | grep sentinelgate
tail -f /usr/local/var/log/sentinel-gate.log
```

`KeepAlive.SuccessfulExit=false` ensures restart on crash. `ThrottleInterval=2` prevents restart loops.

### Kubernetes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 2
  periodSeconds: 5
```

## Fail Mode

SentinelGate defaults to **fail-closed**: if the proxy is unreachable, agents receive errors. No tool call passes without governance. This is correct for production.

For development environments where availability matters more than security, configure agents with a direct fallback to the upstream MCP server. This is a client-side configuration, not a SentinelGate setting.

Example Claude Code config with fallback:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@anthropic-ai/mcp-filesystem"],
      "env": {}
    }
  }
}
```

When SentinelGate is running, route through it. When it's not, the agent falls back to the direct config above.
