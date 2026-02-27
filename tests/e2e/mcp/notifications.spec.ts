import * as http from 'http';
import { test, expect, MCPClient, createMCPSession, getTestEnv } from '../helpers/fixtures';

interface SSEHandle {
  events: string[];
  raw: string[];
  close: () => void;
}

function openSSE(sessionId: string, apiKey: string): Promise<SSEHandle> {
  return new Promise((resolve, reject) => {
    const events: string[] = [];
    const raw: string[] = [];

    const req = http.get('http://localhost:8080/mcp', {
      headers: {
        'Mcp-Session-Id': sessionId,
        'Authorization': `Bearer ${apiKey}`,
        'Accept': 'text/event-stream',
      },
    }, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`SSE status ${res.statusCode}`));
        return;
      }

      let buffer = '';
      res.on('data', (chunk: Buffer) => {
        buffer += chunk.toString();
        const parts = buffer.split('\n\n');
        buffer = parts.pop() || '';
        for (const part of parts) {
          raw.push(part);
          if (part.startsWith('data: ')) {
            events.push(part.substring(6));
          }
        }
      });

      setTimeout(() => resolve({ events, raw, close: () => req.destroy() }), 500);
    });

    req.on('error', reject);
    req.setTimeout(30_000);
  });
}

async function waitForEvents(events: string[], count: number, timeout = 15_000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (events.length >= count) return;
    await new Promise(r => setTimeout(r, 300));
  }
}

test.describe('MCP Notifications', () => {
  let createdUpstreamIds: string[] = [];
  let sseHandles: SSEHandle[] = [];

  test.afterEach(async ({ adminAPI }) => {
    for (const h of sseHandles) {
      try { h.close(); } catch { /* ignore */ }
    }
    sseHandles = [];
    for (const id of createdUpstreamIds) {
      try { await adminAPI.deleteUpstream(id); } catch { /* ignore */ }
    }
    createdUpstreamIds = [];
  });

  test('SSE connection receives tools/list_changed on upstream add', async ({ mcpClient, adminAPI, env }) => {
    const sessionId = mcpClient.getSessionId()!;

    const sse = await openSSE(sessionId, env.apiKey);
    sseHandles.push(sse);

    // Add upstream — triggers tool discovery then notification
    const upstream = await adminAPI.createUpstream({
      name: 'e2e-notify-add',
      type: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-memory'],
      enabled: true,
    });
    createdUpstreamIds.push(upstream.id);

    await waitForEvents(sse.events, 1, 15_000);

    expect(sse.events.length).toBeGreaterThanOrEqual(1);
    const hasNotification = sse.events.some(e => {
      try { return JSON.parse(e).method === 'notifications/tools/list_changed'; } catch { return false; }
    });
    expect(hasNotification).toBe(true);
  });

  test('SSE connection receives notification on upstream delete', async ({ mcpClient, adminAPI, env }) => {
    // Add upstream and wait for it to connect
    const upstream = await adminAPI.createUpstream({
      name: 'e2e-notify-del',
      type: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-memory'],
      enabled: true,
    });
    createdUpstreamIds.push(upstream.id);

    // Wait for upstream to connect (poll status instead of tool count —
    // duplicate upstream provides the same tools so count won't increase)
    const deadline = Date.now() + 15_000;
    let connected = false;
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 1_000));
      const data = await adminAPI.getUpstreams();
      const list = data?.upstreams || data || [];
      const found = (Array.isArray(list) ? list : []).find((u: any) => u.id === upstream.id);
      if (found?.status === 'connected') {
        connected = true;
        break;
      }
    }
    expect(connected).toBe(true);

    // Open SSE AFTER tools are discovered
    const sessionId = mcpClient.getSessionId()!;
    const sse = await openSSE(sessionId, env.apiKey);
    sseHandles.push(sse);

    // Small delay to ensure SSE connection is fully established
    await new Promise(r => setTimeout(r, 500));

    // Delete upstream — should trigger notification
    await adminAPI.deleteUpstream(upstream.id);
    createdUpstreamIds = createdUpstreamIds.filter(id => id !== upstream.id);

    await waitForEvents(sse.events, 1, 15_000);

    expect(sse.events.length).toBeGreaterThanOrEqual(1);
    const hasNotification = sse.events.some(e => {
      try { return JSON.parse(e).method === 'notifications/tools/list_changed'; } catch { return false; }
    });
    expect(hasNotification).toBe(true);
  });

  test('tools/list returns valid tools after upstream change notification', async ({ mcpClient, adminAPI, env }) => {
    const initialTools = await mcpClient.listTools();
    const initialCount = initialTools.length;

    const sessionId = mcpClient.getSessionId()!;
    const sse = await openSSE(sessionId, env.apiKey);
    sseHandles.push(sse);

    const upstream = await adminAPI.createUpstream({
      name: 'e2e-notify-tools',
      type: 'stdio',
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-memory'],
      enabled: true,
    });
    createdUpstreamIds.push(upstream.id);

    // Wait for tools/list_changed notification
    await waitForEvents(sse.events, 1, 15_000);
    expect(sse.events.length).toBeGreaterThanOrEqual(1);

    const hasNotification = sse.events.some(e => {
      try { return JSON.parse(e).method === 'notifications/tools/list_changed'; } catch { return false; }
    });
    expect(hasNotification).toBe(true);

    // After notification, tools/list still returns valid results
    const updatedTools = await mcpClient.listTools();
    expect(updatedTools.length).toBeGreaterThanOrEqual(initialCount);
  });

  test('SSE without session ID returns 400', async ({ request, env }) => {
    const res = await request.get('/mcp', {
      headers: {
        'Authorization': `Bearer ${env.apiKey}`,
        'Accept': 'text/event-stream',
      },
    });
    expect(res.status()).toBe(400);
  });

  test('SSE initial connection sends ": connected" comment', async ({ mcpClient, env }) => {
    const sessionId = mcpClient.getSessionId()!;
    const sse = await openSSE(sessionId, env.apiKey);
    sseHandles.push(sse);

    expect(sse.raw.length).toBeGreaterThanOrEqual(1);
    expect(sse.raw[0]).toMatch(/^:\s*connected/);
  });
});
