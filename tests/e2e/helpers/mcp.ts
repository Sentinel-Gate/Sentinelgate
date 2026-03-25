import { APIRequestContext } from '@playwright/test';
import * as http from 'http';
import { getTestEnv } from './api';

/**
 * MCP JSON-RPC helper — sends real MCP protocol requests to /mcp.
 */
export class MCPClient {
  private sessionId: string | null = null;
  private nextId = 1;
  private baseUrl: string;
  private apiKey: string;

  constructor(private request: APIRequestContext, opts?: { apiKey?: string; baseUrl?: string }) {
    const env = getTestEnv();
    this.baseUrl = opts?.baseUrl || env.baseUrl;
    this.apiKey = opts?.apiKey || env.apiKey;
  }

  getSessionId(): string | null {
    return this.sessionId;
  }

  /**
   * Send a JSON-RPC request to /mcp and return the parsed response.
   */
  /**
   * Send a JSON-RPC request using Node.js http module directly.
   * Playwright's APIRequestContext truncates response bodies on chunked
   * transfer encoding — Node.js http properly concatenates all chunks.
   */
  async send(method: string, params?: any, _retried?: boolean): Promise<{ id: number; result?: any; error?: any; headers: Record<string, string> }> {
    const id = this.nextId++;
    const body: any = { jsonrpc: '2.0', id, method };
    if (params !== undefined) body.params = params;
    const data = JSON.stringify(body);

    const url = new URL('/mcp', this.baseUrl);

    const responseData = await new Promise<{ status: number; headers: Record<string, string>; body: string }>((resolve, reject) => {
      const req = http.request({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Length': String(Buffer.byteLength(data)),
          'Connection': 'close', // Prevent keep-alive response mixing
          ...(this.sessionId ? { 'Mcp-Session-Id': this.sessionId } : {}),
        },
        timeout: 30_000,
      }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const responseBody = Buffer.concat(chunks).toString('utf-8');
          const headers: Record<string, string> = {};
          for (const [key, value] of Object.entries(res.headers)) {
            if (typeof value === 'string') headers[key] = value;
            else if (Array.isArray(value)) headers[key] = value[0];
          }
          resolve({ status: res.statusCode || 0, headers, body: responseBody });
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('MCP request timeout (30s)')); });
      req.write(data);
      req.end();
    });

    // Capture session ID
    if (responseData.headers['mcp-session-id']) {
      this.sessionId = responseData.headers['mcp-session-id'];
    }

    if (responseData.status === 202) {
      return { id, result: null, headers: responseData.headers };
    }

    let parsed: any;
    try {
      parsed = JSON.parse(responseData.body);
    } catch (parseErr) {
      // Debug: log the raw response for diagnosis
      console.error(`[MCPClient] JSON parse failed for ${method} (${responseData.body.length} bytes, status ${responseData.status})`);
      console.error(`[MCPClient] Content-Length header: ${responseData.headers['content-length'] || 'not set'}`);
      console.error(`[MCPClient] First 200 chars: ${responseData.body.substring(0, 200)}`);
      console.error(`[MCPClient] Last 100 chars: ${responseData.body.substring(responseData.body.length - 100)}`);

      // Try extracting from newline-delimited or SSE format
      const lines = responseData.body.split('\n');
      let found = false;
      for (let i = lines.length - 1; i >= 0; i--) {
        let line = lines[i].trim();
        if (line.startsWith('data: ')) line = line.slice(6);
        if (!line.startsWith('{')) continue;
        try { parsed = JSON.parse(line); found = true; break; } catch { /* next */ }
      }
      if (!found) {
        // Retry once: transient truncation can occur when the upstream response
        // races with the HTTP handler's buffer read (flaky, <1% of requests).
        if (!_retried) {
          console.error(`[MCPClient] Retrying ${method} after truncated response`);
          await new Promise(r => setTimeout(r, 500));
          return this.send(method, params, true);
        }
        throw new Error(`Invalid JSON response (${responseData.body.length} bytes): ${responseData.body.substring(0, 300)}`);
      }
    }

    return {
      id: parsed.id,
      result: parsed.result,
      error: parsed.error,
      headers: responseData.headers,
    };
  }

  /**
   * Send a notification (no id field, expect 202).
   */
  async notify(method: string, params?: any): Promise<number> {
    const body: any = { jsonrpc: '2.0', method };
    if (params !== undefined) body.params = params;
    const data = JSON.stringify(body);
    const url = new URL('/mcp', this.baseUrl);

    return new Promise<number>((resolve, reject) => {
      const req = http.request({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Length': String(Buffer.byteLength(data)),
          ...(this.sessionId ? { 'Mcp-Session-Id': this.sessionId } : {}),
        },
        timeout: 10_000,
      }, (res) => {
        res.resume(); // drain body
        resolve(res.statusCode || 0);
      });
      req.on('error', reject);
      req.write(data);
      req.end();
    });
  }

  /**
   * Send raw POST to /mcp (for error testing).
   */
  async sendRaw(body: string | object, headers?: Record<string, string>) {
    const defaultHeaders: Record<string, string> = {
      'Authorization': `Bearer ${this.apiKey}`,
    };
    if (this.sessionId) {
      defaultHeaders['Mcp-Session-Id'] = this.sessionId;
    }
    if (typeof body === 'object') {
      defaultHeaders['Content-Type'] = 'application/json';
      body = JSON.stringify(body);
    }

    const res = await this.request.post('/mcp', {
      data: body as string,
      headers: { ...defaultHeaders, ...headers },
    });

    const text = await res.text();
    let parsed: any;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }

    return { status: res.status(), body: parsed, headers: res.headers() };
  }

  /**
   * DELETE /mcp to terminate session.
   */
  async deleteSession(): Promise<number> {
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${this.apiKey}`,
    };
    if (this.sessionId) {
      headers['Mcp-Session-Id'] = this.sessionId;
    }
    const res = await this.request.delete('/mcp', { headers });
    return res.status();
  }

  /**
   * OPTIONS /mcp for CORS preflight.
   */
  async options() {
    const res = await this.request.fetch('/mcp', { method: 'OPTIONS' });
    return { status: res.status(), headers: res.headers() };
  }

  // --- High-level MCP operations ---

  /**
   * Perform full MCP initialization handshake.
   */
  async initialize(): Promise<any> {
    // Retry on rate limit (429 / -32600) with backoff
    for (let attempt = 0; attempt < 4; attempt++) {
      const res = await this.send('initialize', {
        protocolVersion: '2025-11-25',
        capabilities: {},
        clientInfo: { name: 'e2e-test', version: '1.0.0' },
      });

      if (res.error) {
        const msg = typeof res.error.message === 'string' ? res.error.message.toLowerCase() : '';
        if (msg.includes('rate limit') && attempt < 3) {
          await new Promise(r => setTimeout(r, 1500 * (attempt + 1)));
          continue;
        }
        throw new Error(`Initialize failed: ${JSON.stringify(res.error)}`);
      }

      // Send initialized notification
      await this.notify('notifications/initialized');
      return res.result;
    }
    throw new Error('Initialize failed after retries');
  }

  /**
   * List all available tools.
   */
  async listTools(): Promise<any[]> {
    for (let attempt = 0; attempt < 3; attempt++) {
      const res = await this.send('tools/list');
      if (res.error) {
        const msg = typeof res.error.message === 'string' ? res.error.message.toLowerCase() : '';
        if (msg.includes('rate limit') && attempt < 2) {
          await new Promise(r => setTimeout(r, 1500 * (attempt + 1)));
          continue;
        }
        throw new Error(`tools/list failed: ${JSON.stringify(res.error)}`);
      }
      return res.result?.tools || [];
    }
    throw new Error('tools/list failed after retries');
  }

  /**
   * Call a tool and return the result.
   */
  async callTool(name: string, args: Record<string, any> = {}): Promise<{ content?: any[]; error?: any; isError?: boolean }> {
    for (let attempt = 0; attempt < 3; attempt++) {
      const res = await this.send('tools/call', { name, arguments: args });
      if (res.error) {
        const msg = typeof res.error.message === 'string' ? res.error.message.toLowerCase() : '';
        if (msg.includes('rate limit') && attempt < 2) {
          await new Promise(r => setTimeout(r, 1500 * (attempt + 1)));
          continue;
        }
        return { error: res.error, isError: true };
      }
      return { content: res.result?.content, isError: res.result?.isError };
    }
    return { error: { message: 'rate limit after retries' }, isError: true };
  }

  /**
   * Shorthand: call tool and return the text content.
   */
  async callToolText(name: string, args: Record<string, any> = {}): Promise<string> {
    const result = await this.callTool(name, args);
    if (result.error) {
      throw new Error(`Tool call failed: ${JSON.stringify(result.error)}`);
    }
    if (result.isError) {
      const text = result.content?.map(c => c.text || '').join('') || 'Unknown error';
      throw new Error(`Tool returned error: ${text}`);
    }
    return result.content?.map(c => c.text || '').join('') || '';
  }
}

/**
 * Create a new MCP client and perform initialize handshake.
 */
export async function createMCPSession(request: APIRequestContext, opts?: { apiKey?: string }): Promise<MCPClient> {
  const client = new MCPClient(request, opts);
  await client.initialize();
  return client;
}
