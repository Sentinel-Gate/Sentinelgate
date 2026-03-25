#!/usr/bin/env node

/**
 * SentinelGate E2E — Node.js MCP Client (SDK)
 *
 * Tests the SentinelGate MCP proxy by acting as a real MCP client
 * using the official @modelcontextprotocol/sdk.
 *
 * Usage:  node tests/e2e/agents/node_client.mjs
 * Prereq: server running, .env.test populated by global-setup
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as http from 'node:http';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ENV_FILE = path.resolve(__dirname, '..', '.env.test');

function loadEnv(filepath) {
  const contents = fs.readFileSync(filepath, 'utf-8');
  const env = {};
  for (const line of contents.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx === -1) continue;
    env[trimmed.slice(0, idx)] = trimmed.slice(idx + 1);
  }
  return env;
}

const env = loadEnv(ENV_FILE);
const API_KEY = env.API_KEY;
const BASE_URL = env.BASE_URL || 'http://localhost:8080';
const TEST_DIR = env.TEST_DIR || '/private/tmp/sg-e2e-test';

if (!API_KEY) {
  console.error('ERROR: API_KEY not found in .env.test — run Playwright global-setup first');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Admin API helper (CSRF double-submit cookie)
// ---------------------------------------------------------------------------

function adminRequest(method, apiPath, body) {
  const csrf = crypto.randomBytes(32).toString('hex');
  const data = body ? JSON.stringify(body) : '';
  const url = new URL(BASE_URL);

  return new Promise((resolve, reject) => {
    const headers = {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf,
      'Cookie': `sentinel_csrf_token=${csrf}`,
    };
    if (data) {
      headers['Content-Length'] = String(Buffer.byteLength(data));
    }

    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port || 8080,
        path: `/admin/api${apiPath}`,
        method,
        headers,
      },
      (res) => {
        let responseBody = '';
        res.on('data', (c) => (responseBody += c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(responseBody));
          } catch {
            resolve(responseBody);
          }
        });
      },
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

const results = [];

async function runTest(name, fn) {
  try {
    const detail = await fn();
    results.push({ name, passed: true, detail });
    console.log(`[PASS] ${name}: ${detail}`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    results.push({ name, passed: false, detail: msg });
    console.log(`[FAIL] ${name}: ${msg}`);
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

async function main() {
  console.log('');
  console.log('=== SentinelGate E2E — Node.js MCP Client (SDK) ===');
  console.log('');

  // ---- Create transport & client ----
  const transport = new StreamableHTTPClientTransport(
    new URL(`${BASE_URL}/mcp`),
    {
      requestInit: {
        headers: {
          Authorization: `Bearer ${API_KEY}`,
        },
      },
    },
  );

  const client = new Client(
    { name: 'node-e2e', version: '1.0.0' },
    { capabilities: {} },
  );

  // 1. test_connect
  await runTest('test_connect', async () => {
    await client.connect(transport);
    const caps = client.getServerCapabilities();
    if (!caps) throw new Error('No server capabilities returned');
    if (!caps.tools?.listChanged) {
      throw new Error('Server missing tools.listChanged capability');
    }
    const info = client.getServerVersion();
    const serverName = info?.name || 'unknown';
    const serverVer = info?.version || 'unknown';
    return `Connected to server (${serverName} v${serverVer})`;
  });

  // 2. test_tools_list
  let toolNames = [];
  await runTest('test_tools_list', async () => {
    const resp = await client.listTools();
    const tools = resp.tools;
    if (!tools || tools.length === 0) {
      throw new Error('No tools returned');
    }
    toolNames = tools.map((t) => t.name);
    const required = ['read_file', 'list_directory', 'create_entities'];
    const missing = required.filter((r) => !toolNames.includes(r));
    if (missing.length > 0) {
      throw new Error(`Missing expected tools: ${missing.join(', ')}`);
    }
    return `Found ${tools.length} tools`;
  });

  // 3. test_read_file
  await runTest('test_read_file', async () => {
    const result = await client.callTool({
      name: 'read_file',
      arguments: { path: path.join(TEST_DIR, 'test.txt') },
    });
    if (result.isError) {
      const errText = result.content?.[0]?.text || 'unknown error';
      throw new Error(`Tool returned error: ${errText}`);
    }
    const text = result.content?.[0]?.text || '';
    if (!text.includes('Hello from SentinelGate E2E test!')) {
      throw new Error(`Unexpected content: ${text.substring(0, 80)}`);
    }
    return 'Got expected content';
  });

  // 4. test_list_directory
  await runTest('test_list_directory', async () => {
    const result = await client.callTool({
      name: 'list_directory',
      arguments: { path: TEST_DIR },
    });
    if (result.isError) {
      const errText = result.content?.[0]?.text || 'unknown error';
      throw new Error(`Tool returned error: ${errText}`);
    }
    const text = result.content?.[0]?.text || '';
    if (!text.includes('test.txt')) {
      throw new Error(`test.txt not found in listing: ${text.substring(0, 120)}`);
    }
    return 'Found test.txt in listing';
  });

  // 5. test_memory_create
  await runTest('test_memory_create', async () => {
    const result = await client.callTool({
      name: 'create_entities',
      arguments: {
        entities: [
          {
            name: 'node-test',
            entityType: 'test',
            observations: ['created by node e2e'],
          },
        ],
      },
    });
    if (result.isError) {
      const errText = result.content?.[0]?.text || 'unknown error';
      throw new Error(`Tool returned error: ${errText}`);
    }
    return 'Entity created';
  });

  // 6. test_memory_read
  await runTest('test_memory_read', async () => {
    const result = await client.callTool({
      name: 'read_graph',
      arguments: {},
    });
    if (result.isError) {
      const errText = result.content?.[0]?.text || 'unknown error';
      throw new Error(`Tool returned error: ${errText}`);
    }
    const text = result.content?.[0]?.text || '';
    if (!text.includes('node-test')) {
      throw new Error(`node-test entity not found in graph: ${text.substring(0, 200)}`);
    }
    return 'Found node-test entity';
  });

  // 7. test_policy_deny
  await runTest('test_policy_deny', async () => {
    // a. Create deny policy via admin API
    const policy = await adminRequest('POST', '/policies', {
      name: 'e2e-deny-write-node',
      priority: 200,
      enabled: true,
      rules: [
        {
          name: 'deny-write',
          priority: 1,
          tool_match: 'write_file',
          condition: 'true',
          action: 'deny',
        },
      ],
    });

    if (!policy?.id) {
      throw new Error(`Failed to create deny policy: ${JSON.stringify(policy)}`);
    }

    const policyId = policy.id;

    try {
      // b. Attempt write_file — should be denied
      let denied = false;
      try {
        const result = await client.callTool({
          name: 'write_file',
          arguments: {
            path: path.join(TEST_DIR, 'denied.txt'),
            content: 'should fail',
          },
        });
        // If callTool did not throw, check isError
        if (result.isError) {
          denied = true;
        } else {
          throw new Error('write_file succeeded but should have been denied');
        }
      } catch (callErr) {
        // JSON-RPC error thrown by SDK — this also counts as denied
        denied = true;
      }

      if (!denied) {
        throw new Error('write_file was not denied');
      }

      return 'write_file correctly denied';
    } finally {
      // c. Always clean up the deny policy
      await adminRequest('DELETE', `/policies/${policyId}`);
    }
  });

  // ---- Cleanup ----
  try {
    await client.close();
  } catch {
    // Ignore close errors
  }

  // ---- Summary ----
  console.log('');
  const passed = results.filter((r) => r.passed).length;
  const total = results.length;
  console.log(`=== Results: ${passed}/${total} PASS ===`);
  console.log('');

  process.exit(passed === total ? 0 : 1);
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
