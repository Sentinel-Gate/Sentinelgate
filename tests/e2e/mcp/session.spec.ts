import * as http from 'http';
import { test, expect, MCPClient, createMCPSession, getTestEnv } from '../helpers/fixtures';

test.describe('MCP Sessions', () => {
  test('session ID is returned on initialize', async ({ request }) => {
    const client = new MCPClient(request);
    const res = await client.send('initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'session-test', version: '1.0.0' },
    });
    expect(res.error).toBeUndefined();
    const sid = res.headers['mcp-session-id'];
    expect(sid).toBeDefined();
    expect(sid).toMatch(/^[0-9a-f]{64}$/);
  });

  test('session ID is consistent across requests', async ({ request }) => {
    const client = new MCPClient(request);
    const initRes = await client.send('initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'consistency-test', version: '1.0.0' },
    });
    // The session ID may be in the response header or tracked by the client
    const sessionId = initRes.headers['mcp-session-id'] || client.getSessionId();
    expect(sessionId).toBeDefined();
    expect(sessionId).toBeTruthy();

    await client.notify('notifications/initialized');

    // Subsequent requests should use the same session (tracked by client)
    const listRes = await client.send('tools/list');
    const listSessionId = listRes.headers['mcp-session-id'] || client.getSessionId();
    expect(listSessionId).toBe(sessionId);

    const listRes2 = await client.send('tools/list');
    const listSessionId2 = listRes2.headers['mcp-session-id'] || client.getSessionId();
    expect(listSessionId2).toBe(sessionId);
  });

  test('each initialize creates a unique session ID', async ({ request }) => {
    const clientA = await createMCPSession(request);
    const sessionA = clientA.getSessionId();

    // Small delay to avoid rate limiting on back-to-back initializations
    await new Promise(r => setTimeout(r, 1000));

    const clientB = await createMCPSession(request);
    const sessionB = clientB.getSessionId();

    expect(sessionA).toBeTruthy();
    expect(sessionB).toBeTruthy();
    expect(sessionA).not.toBe(sessionB);
  });

  test('DELETE without session ID returns appropriate status', async ({ request }) => {
    const env = getTestEnv();
    const res = await request.delete('/mcp', {
      headers: { 'Authorization': `Bearer ${env.apiKey}` },
    });
    // Server may return 400 (missing session) or 200 (graceful handling)
    expect([200, 400]).toContain(res.status());
  });

  test('DELETE with unknown session ID returns appropriate status', async ({ request }) => {
    const env = getTestEnv();
    const res = await request.delete('/mcp', {
      headers: {
        'Authorization': `Bearer ${env.apiKey}`,
        'Mcp-Session-Id': '0'.repeat(64),
      },
    });
    // Server may return 404 (not found) or 200 (graceful handling)
    expect([200, 404]).toContain(res.status());
  });

  test('DELETE terminates SSE session and returns 204', async ({ request }) => {
    // Initialize a session
    const client = await createMCPSession(request);
    const sessionId = client.getSessionId()!;
    const env = getTestEnv();

    // Open SSE connection to register session in the registry
    const sseReady = new Promise<http.ClientRequest>((resolve, reject) => {
      const req = http.get(`${env.baseUrl}/mcp`, {
        headers: {
          'Mcp-Session-Id': sessionId,
          'Authorization': `Bearer ${env.apiKey}`,
          'Accept': 'text/event-stream',
        },
      }, (res) => {
        // Wait for initial data (": connected\n\n")
        res.once('data', () => resolve(req));
      });
      req.on('error', reject);
      req.setTimeout(10_000);
    });

    const sseReq = await sseReady;

    // Now DELETE the session — should return 204 since SSE is registered
    const status = await client.deleteSession();
    expect(status).toBe(204);

    // Cleanup
    sseReq.destroy();
  });

  test('OPTIONS /mcp returns CORS headers', async ({ request }) => {
    const client = new MCPClient(request);
    const res = await client.options();
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-methods']).toBeDefined();
    expect(res.headers['access-control-allow-methods']).toContain('POST');
    expect(res.headers['access-control-allow-methods']).toContain('DELETE');
    expect(res.headers['access-control-allow-headers']).toBeDefined();
  });
});
