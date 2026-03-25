import * as http from 'http';
import { test, expect, MCPClient, getTestEnv } from '../helpers/fixtures';

function rawMCPRequest(body: object, headers: Record<string, string> = {}): Promise<{status: number, body: any}> {
  const env = getTestEnv();
  const u = new URL(env.baseUrl);
  const data = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: u.hostname,
      port: Number(u.port),
      path: '/mcp',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': String(Buffer.byteLength(data)),
        ...headers,
      },
    }, (res) => {
      let response = '';
      res.on('data', (chunk: Buffer) => response += chunk);
      res.on('end', () => {
        let parsed: any;
        try { parsed = JSON.parse(response); } catch { parsed = response; }
        resolve({ status: res.statusCode || 0, body: parsed });
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

test.describe('MCP Auth', () => {
  test('valid API key succeeds', async ({ request, env }) => {
    const client = new MCPClient(request, { apiKey: env.apiKey });
    const result = await client.initialize();
    expect(result).toBeDefined();
    expect(result.protocolVersion).toBe('2025-11-25');
  });

  test('request without API key returns auth error', async () => {
    // Send request without Authorization header using raw http
    // MCP spec 2025-03-26: auth errors are promoted to HTTP 401 with JSON-RPC body
    const res = await rawMCPRequest({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'no-auth-test', version: '1.0.0' } },
    });
    expect(res.status).toBe(401);
    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe(-32600);
    expect(res.body.error.message).toContain('Authentication required');
  });

  test('invalid API key returns auth error', async () => {
    // MCP spec 2025-03-26: auth errors are promoted to HTTP 401 with JSON-RPC body
    const res = await rawMCPRequest(
      {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'bad-key-test', version: '1.0.0' } },
      },
      { 'Authorization': 'Bearer totally-invalid-key-12345' },
    );
    expect(res.status).toBe(401);
    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe(-32600);
    expect(res.body.error.message).toContain('Invalid API key');
  });

  test('session ID is returned with valid auth', async ({ request, env }) => {
    const client = new MCPClient(request, { apiKey: env.apiKey });
    const res = await client.send('initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'auth-session-test', version: '1.0.0' },
    });
    expect(res.error).toBeUndefined();
    const sid = res.headers['mcp-session-id'];
    expect(sid).toMatch(/^[0-9a-f]{64}$/);
  });
});
