import { test, expect, MCPClient, createMCPSession } from '../helpers/fixtures';

test.describe('Initialize', () => {
  test('returns valid initialize result', async ({ request }) => {
    const client = new MCPClient(request);
    const res = await client.send('initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'test', version: '1.0.0' },
    });

    expect(res.error).toBeUndefined();
    expect(res.result).toBeDefined();
    expect(res.result.protocolVersion).toBeDefined();
    expect(res.result.capabilities).toBeDefined();
    expect(res.result.serverInfo).toBeDefined();
  });

  test('returns Mcp-Session-Id header (64 hex chars)', async ({ request }) => {
    const client = new MCPClient(request);
    const res = await client.send('initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'test', version: '1.0.0' },
    });

    const sessionId = res.headers['mcp-session-id'];
    expect(sessionId).toBeDefined();
    expect(sessionId).toMatch(/^[0-9a-f]{64}$/);
  });

  test('capabilities include tools.listChanged', async ({ request }) => {
    const client = new MCPClient(request);
    const res = await client.send('initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'test', version: '1.0.0' },
    });

    expect(res.result.capabilities).toBeDefined();
    expect(res.result.capabilities.tools).toBeDefined();
    expect(res.result.capabilities.tools.listChanged).toBe(true);
  });

  test('serverInfo contains name and version', async ({ request }) => {
    const client = new MCPClient(request);
    const res = await client.send('initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'test', version: '1.0.0' },
    });

    const serverInfo = res.result.serverInfo;
    expect(serverInfo).toBeDefined();
    expect(typeof serverInfo.name).toBe('string');
    expect(serverInfo.name.length).toBeGreaterThan(0);
    expect(typeof serverInfo.version).toBe('string');
    expect(serverInfo.version.length).toBeGreaterThan(0);
  });

  test('MCP-Protocol-Version header present', async ({ request }) => {
    const client = new MCPClient(request);
    const res = await client.send('initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'test', version: '1.0.0' },
    });

    // Header names are lowercased by Playwright
    const protocolVersion = res.headers['mcp-protocol-version'];
    expect(protocolVersion).toBe('2025-11-25');
  });

  test('notifications/initialized returns 202', async ({ request }) => {
    const client = new MCPClient(request);
    // First perform the initialize handshake
    await client.send('initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'test', version: '1.0.0' },
    });

    // Then send the initialized notification
    const status = await client.notify('notifications/initialized');
    expect(status).toBe(202);
  });

  test('session ID persists across requests', async ({ request }) => {
    const client = new MCPClient(request);

    // Initialize
    const initRes = await client.send('initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'test', version: '1.0.0' },
    });
    const sessionIdAfterInit = initRes.headers['mcp-session-id'];
    expect(sessionIdAfterInit).toBeDefined();

    // Send initialized notification
    await client.notify('notifications/initialized');

    // Send tools/list and verify same session ID
    const listRes = await client.send('tools/list');
    const sessionIdAfterList = listRes.headers['mcp-session-id'];

    expect(sessionIdAfterList).toBe(sessionIdAfterInit);

    // Also verify the client tracks it correctly
    expect(client.getSessionId()).toBe(sessionIdAfterInit);
  });
});
