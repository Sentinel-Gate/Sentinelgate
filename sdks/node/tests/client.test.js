'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const SentinelGateClient = require('../src/client');
const {
  PolicyDeniedError,
  ApprovalTimeoutError,
  ServerUnreachableError,
  SentinelGateError,
} = require('../src/errors');

// -- Test HTTP server helpers -------------------------------------------------

function createTestServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        server,
        addr: `http://127.0.0.1:${addr.port}`,
        close: () => new Promise((res) => server.close(res)),
      });
    });
  });
}

function jsonResponse(res, data, status = 200) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

// -- Tests --------------------------------------------------------------------

describe('SentinelGateClient', () => {
  let testServer;
  let client;

  afterEach(async () => {
    if (testServer) {
      await testServer.close();
      testServer = null;
    }
  });

  it('evaluate() with allow response', async () => {
    let receivedBody = null;

    testServer = await createTestServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        receivedBody = JSON.parse(body);
        jsonResponse(res, {
          decision: 'allow',
          rule_id: '',
          rule_name: '',
          reason: '',
          help_url: '',
          help_text: '',
          request_id: 'req-123',
          latency_ms: 2,
        });
      });
    });

    client = new SentinelGateClient({
      serverAddr: testServer.addr,
      apiKey: 'test-key',
    });

    const result = await client.evaluate('command_exec', 'ls');

    assert.equal(result.decision, 'allow');
    assert.equal(result.requestId, 'req-123');

    // Verify request body matches PolicyEvaluateRequest schema
    assert.equal(receivedBody.action_type, 'command_exec');
    assert.equal(receivedBody.action_name, 'ls');
    assert.equal(receivedBody.protocol, 'sdk');
    assert.equal(receivedBody.identity_name, 'sdk-client');
    assert.deepEqual(receivedBody.identity_roles, ['agent']);
  });

  it('evaluate() with deny response throws PolicyDeniedError', async () => {
    testServer = await createTestServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        jsonResponse(res, {
          decision: 'deny',
          rule_id: 'rule-1',
          rule_name: 'block-rm',
          reason: 'rm is blocked',
          help_url: '/admin/policies#rule-rule-1',
          help_text: 'Contact admin',
          request_id: 'req-456',
          latency_ms: 1,
        });
      });
    });

    client = new SentinelGateClient({
      serverAddr: testServer.addr,
      apiKey: 'test-key',
    });

    await assert.rejects(
      () => client.evaluate('command_exec', 'rm'),
      (err) => {
        assert.ok(err instanceof PolicyDeniedError);
        assert.equal(err.ruleId, 'rule-1');
        assert.equal(err.ruleName, 'block-rm');
        assert.equal(err.reason, 'rm is blocked');
        assert.equal(err.helpUrl, '/admin/policies#rule-rule-1');
        assert.equal(err.helpText, 'Contact admin');
        return true;
      }
    );
  });

  it('evaluate() with raiseOnDeny=false returns object without throwing', async () => {
    testServer = await createTestServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        jsonResponse(res, {
          decision: 'deny',
          rule_id: 'rule-1',
          rule_name: 'block-rm',
          reason: 'rm is blocked',
          help_url: '',
          help_text: '',
          request_id: 'req-789',
          latency_ms: 1,
        });
      });
    });

    client = new SentinelGateClient({
      serverAddr: testServer.addr,
      apiKey: 'test-key',
    });

    const result = await client.evaluate('command_exec', 'rm', {
      raiseOnDeny: false,
    });
    assert.equal(result.decision, 'deny');
    assert.equal(result.ruleId, 'rule-1');
  });

  it('check() returns true on allow', async () => {
    testServer = await createTestServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        jsonResponse(res, {
          decision: 'allow',
          rule_id: '',
          rule_name: '',
          reason: '',
          help_url: '',
          help_text: '',
          request_id: 'req-1',
          latency_ms: 1,
        });
      });
    });

    client = new SentinelGateClient({
      serverAddr: testServer.addr,
      apiKey: 'test-key',
    });

    const allowed = await client.check('command_exec', 'ls');
    assert.equal(allowed, true);
  });

  it('check() returns false on deny', async () => {
    testServer = await createTestServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        jsonResponse(res, {
          decision: 'deny',
          rule_id: 'rule-1',
          rule_name: '',
          reason: 'denied',
          help_url: '',
          help_text: '',
          request_id: 'req-2',
          latency_ms: 1,
        });
      });
    });

    client = new SentinelGateClient({
      serverAddr: testServer.addr,
      apiKey: 'test-key',
    });

    const allowed = await client.check('command_exec', 'rm');
    assert.equal(allowed, false);
  });

  it('env var auto-configuration', () => {
    const origAddr = process.env.SENTINELGATE_SERVER_ADDR;
    const origKey = process.env.SENTINELGATE_API_KEY;
    const origFail = process.env.SENTINELGATE_FAIL_MODE;
    const origTTL = process.env.SENTINELGATE_CACHE_TTL;

    try {
      process.env.SENTINELGATE_SERVER_ADDR = 'http://sentinel:9090';
      process.env.SENTINELGATE_API_KEY = 'env-key-123';
      process.env.SENTINELGATE_FAIL_MODE = 'closed';
      process.env.SENTINELGATE_CACHE_TTL = '10';

      const c = new SentinelGateClient();
      assert.equal(c._serverAddr, 'http://sentinel:9090');
      assert.equal(c._apiKey, 'env-key-123');
      assert.equal(c._failMode, 'closed');
      assert.equal(c._cacheTTL, 10000);
    } finally {
      if (origAddr === undefined) delete process.env.SENTINELGATE_SERVER_ADDR;
      else process.env.SENTINELGATE_SERVER_ADDR = origAddr;
      if (origKey === undefined) delete process.env.SENTINELGATE_API_KEY;
      else process.env.SENTINELGATE_API_KEY = origKey;
      if (origFail === undefined) delete process.env.SENTINELGATE_FAIL_MODE;
      else process.env.SENTINELGATE_FAIL_MODE = origFail;
      if (origTTL === undefined) delete process.env.SENTINELGATE_CACHE_TTL;
      else process.env.SENTINELGATE_CACHE_TTL = origTTL;
    }
  });

  it('LRU cache hit (second call does not make HTTP request)', async () => {
    let requestCount = 0;

    testServer = await createTestServer((req, res) => {
      requestCount++;
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        jsonResponse(res, {
          decision: 'allow',
          rule_id: '',
          rule_name: '',
          reason: '',
          help_url: '',
          help_text: '',
          request_id: 'req-cache',
          latency_ms: 1,
        });
      });
    });

    client = new SentinelGateClient({
      serverAddr: testServer.addr,
      apiKey: 'test-key',
    });

    // First call - makes HTTP request
    const result1 = await client.evaluate('command_exec', 'echo');
    assert.equal(result1.decision, 'allow');
    assert.equal(requestCount, 1);

    // Second call - should use cache
    const result2 = await client.evaluate('command_exec', 'echo');
    assert.equal(result2.decision, 'allow');
    assert.equal(requestCount, 1); // No additional request
  });

  it('fail-open on connection error (resolves with allow)', async () => {
    // Use a port that nothing is listening on
    client = new SentinelGateClient({
      serverAddr: 'http://127.0.0.1:1',
      apiKey: 'test-key',
      timeout: 500,
    });

    const result = await client.evaluate('command_exec', 'ls');
    assert.equal(result.decision, 'allow');
    assert.equal(result.reason, 'fail-open');
  });

  it('fail-closed on connection error (rejects with ServerUnreachableError)', async () => {
    client = new SentinelGateClient({
      serverAddr: 'http://127.0.0.1:1',
      apiKey: 'test-key',
      failMode: 'closed',
      timeout: 500,
    });

    await assert.rejects(
      () => client.evaluate('command_exec', 'ls'),
      (err) => {
        assert.ok(err instanceof ServerUnreachableError);
        return true;
      }
    );
  });

  it('approval_required polling (pending then approved)', async () => {
    let pollCount = 0;

    testServer = await createTestServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        if (req.url === '/admin/api/v1/policy/evaluate') {
          // Initial evaluation: approval_required
          jsonResponse(res, {
            decision: 'approval_required',
            rule_id: 'rule-approval',
            rule_name: 'needs-approval',
            reason: 'requires human approval',
            help_url: '',
            help_text: '',
            request_id: 'req-approval-1',
            latency_ms: 3,
          });
        } else if (
          req.url === '/admin/api/v1/policy/evaluate/req-approval-1/status'
        ) {
          pollCount++;
          if (pollCount === 1) {
            // First poll: still pending
            jsonResponse(res, {
              request_id: 'req-approval-1',
              status: 'pending',
              decision: 'approval_required',
              updated_at: '2026-01-01T00:00:00Z',
            });
          } else {
            // Second poll: approved
            jsonResponse(res, {
              request_id: 'req-approval-1',
              status: 'approved',
              decision: 'allow',
              updated_at: '2026-01-01T00:00:02Z',
            });
          }
        }
      });
    });

    client = new SentinelGateClient({
      serverAddr: testServer.addr,
      apiKey: 'test-key',
    });

    // Override _sleep to avoid real delays in tests
    client._sleep = () => Promise.resolve();

    const result = await client.evaluate('command_exec', 'deploy');

    assert.equal(result.decision, 'allow');
    assert.equal(result.reason, 'approved');
    assert.equal(result.requestId, 'req-approval-1');
    assert.equal(pollCount, 2);
  });

  it('identity defaults from env vars', async () => {
    let receivedBody = null;

    testServer = await createTestServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        receivedBody = JSON.parse(body);
        jsonResponse(res, {
          decision: 'allow',
          rule_id: '',
          rule_name: '',
          reason: '',
          help_url: '',
          help_text: '',
          request_id: 'req-env',
          latency_ms: 1,
        });
      });
    });

    const origName = process.env.SENTINELGATE_IDENTITY_NAME;
    const origRoles = process.env.SENTINELGATE_IDENTITY_ROLES;

    try {
      process.env.SENTINELGATE_IDENTITY_NAME = 'my-bot';
      process.env.SENTINELGATE_IDENTITY_ROLES = 'admin,reviewer';

      client = new SentinelGateClient({
        serverAddr: testServer.addr,
        apiKey: 'test-key',
      });

      await client.evaluate('command_exec', 'test-cmd');

      assert.equal(receivedBody.identity_name, 'my-bot');
      assert.deepEqual(receivedBody.identity_roles, ['admin', 'reviewer']);
    } finally {
      if (origName === undefined) delete process.env.SENTINELGATE_IDENTITY_NAME;
      else process.env.SENTINELGATE_IDENTITY_NAME = origName;
      if (origRoles === undefined) delete process.env.SENTINELGATE_IDENTITY_ROLES;
      else process.env.SENTINELGATE_IDENTITY_ROLES = origRoles;
    }
  });

  it('exception hierarchy', () => {
    assert.ok(new PolicyDeniedError() instanceof SentinelGateError);
    assert.ok(new ApprovalTimeoutError() instanceof SentinelGateError);
    assert.ok(new ServerUnreachableError() instanceof SentinelGateError);
    assert.ok(new SentinelGateError() instanceof Error);
  });
});
