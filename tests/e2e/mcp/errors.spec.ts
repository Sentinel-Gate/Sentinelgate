import * as http from 'http';
import { test, expect, getTestEnv } from '../helpers/fixtures';

/**
 * Low-level HTTP POST using Node's native http module.
 * Needed because Playwright's fetch can fail with raw string bodies
 * that aren't valid HTTP payloads (e.g., non-JSON strings, empty body).
 */
function rawPost(body: string, headers: Record<string, string>): Promise<{ status: number; body: any }> {
  const env = getTestEnv();
  const u = new URL(env.baseUrl);
  const allHeaders: Record<string, string> = {
    'Authorization': `Bearer ${env.apiKey}`,
    ...headers,
    'Content-Length': String(Buffer.byteLength(body)),
  };
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: u.hostname,
      port: Number(u.port),
      path: '/mcp',
      method: 'POST',
      headers: allHeaders,
    }, (res) => {
      let data = '';
      res.on('data', (chunk: Buffer) => data += chunk);
      res.on('end', () => {
        let parsed: any;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode || 0, body: parsed });
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

test.describe('MCP Errors', () => {
  test('invalid JSON returns parse error -32700', async () => {
    const res = await rawPost('this is not json', {
      'Content-Type': 'application/json',
    });
    expect(res.status).toBe(200);
    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe(-32700);
    expect(res.body.error.message).toContain('Parse error');
  });

  test('empty body returns parse error -32700', async () => {
    const res = await rawPost('', {
      'Content-Type': 'application/json',
      'Content-Length': '0',
    });
    expect(res.status).toBe(200);
    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe(-32700);
    expect(res.body.error.message).toContain('Parse error');
  });

  test('wrong content-type returns parse error -32700', async () => {
    const res = await rawPost(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' }),
      { 'Content-Type': 'text/plain' },
    );
    expect(res.status).toBe(200);
    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe(-32700);
    expect(res.body.error.message).toContain('content type');
  });

  test('non-object JSON returns invalid request -32600', async () => {
    const res = await rawPost('[1,2,3]', {
      'Content-Type': 'application/json',
    });
    expect(res.status).toBe(200);
    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe(-32600);
  });

  test('missing jsonrpc field returns -32600', async () => {
    const res = await rawPost('{"id":1,"method":"initialize"}', {
      'Content-Type': 'application/json',
    });
    expect(res.status).toBe(200);
    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe(-32600);
  });

  test('wrong jsonrpc version returns -32600', async () => {
    const res = await rawPost('{"jsonrpc":"1.0","id":1,"method":"initialize"}', {
      'Content-Type': 'application/json',
    });
    expect(res.status).toBe(200);
    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe(-32600);
  });

  test('missing method field returns -32600', async () => {
    const res = await rawPost('{"jsonrpc":"2.0","id":1}', {
      'Content-Type': 'application/json',
    });
    expect(res.status).toBe(200);
    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe(-32600);
  });

  test('body over 1MB returns parse error -32700', async () => {
    const res = await rawPost('x'.repeat(1024 * 1024 + 1), {
      'Content-Type': 'application/json',
    });
    expect(res.body.error).toBeDefined();
    expect(res.body.error.code).toBe(-32700);
  });
});
