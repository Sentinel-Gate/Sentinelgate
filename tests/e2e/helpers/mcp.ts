import { APIRequestContext } from '@playwright/test';
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
  async send(method: string, params?: any): Promise<{ id: number; result?: any; error?: any; headers: Record<string, string> }> {
    const id = this.nextId++;
    const body: any = { jsonrpc: '2.0', id, method };
    if (params !== undefined) body.params = params;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.apiKey}`,
    };
    if (this.sessionId) {
      headers['Mcp-Session-Id'] = this.sessionId;
    }

    const res = await this.request.post('/mcp', {
      data: body,
      headers,
    });

    // Capture session ID from response
    const responseSessionId = res.headers()['mcp-session-id'];
    if (responseSessionId) {
      this.sessionId = responseSessionId;
    }

    const responseHeaders = res.headers();

    if (res.status() === 202) {
      // Notification — no body
      return { id, result: null, headers: responseHeaders };
    }

    const text = await res.text();
    let parsed: any;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error(`Invalid JSON response: ${text.substring(0, 200)}`);
    }

    return {
      id: parsed.id,
      result: parsed.result,
      error: parsed.error,
      headers: responseHeaders,
    };
  }

  /**
   * Send a notification (no id field, expect 202).
   */
  async notify(method: string, params?: any): Promise<number> {
    const body: any = { jsonrpc: '2.0', method };
    if (params !== undefined) body.params = params;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.apiKey}`,
    };
    if (this.sessionId) {
      headers['Mcp-Session-Id'] = this.sessionId;
    }

    const res = await this.request.post('/mcp', {
      data: body,
      headers,
    });

    return res.status();
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
    const res = await this.send('initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'e2e-test', version: '1.0.0' },
    });

    if (res.error) {
      throw new Error(`Initialize failed: ${JSON.stringify(res.error)}`);
    }

    // Send initialized notification
    await this.notify('notifications/initialized');

    return res.result;
  }

  /**
   * List all available tools.
   */
  async listTools(): Promise<any[]> {
    const res = await this.send('tools/list');
    if (res.error) {
      throw new Error(`tools/list failed: ${JSON.stringify(res.error)}`);
    }
    return res.result?.tools || [];
  }

  /**
   * Call a tool and return the result.
   */
  async callTool(name: string, args: Record<string, any> = {}): Promise<{ content?: any[]; error?: any; isError?: boolean }> {
    const res = await this.send('tools/call', { name, arguments: args });
    if (res.error) {
      return { error: res.error, isError: true };
    }
    return { content: res.result?.content, isError: res.result?.isError };
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
