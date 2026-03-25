import * as path from 'path';
import { test, expect } from '../helpers/fixtures';

test.describe('Policy Enforcement via MCP', () => {
  // ---------------------------------------------------------------------------
  // 1. Tool call allowed by default
  // ---------------------------------------------------------------------------

  test('tool call allowed by default policy', async ({ mcpClient, env }) => {
    // With the default allow policy, a normal read_file call should succeed.
    const text = await mcpClient.callToolText('read_file', {
      path: path.join(env.testDir, 'test.txt'),
    });
    expect(text).toContain('Hello from SentinelGate');
  });

  // ---------------------------------------------------------------------------
  // 2. Tool call denied by policy
  // ---------------------------------------------------------------------------

  test('tool call denied by deny policy', async ({ mcpClient, adminAPI, env }) => {
    // Create a deny policy for read_file with priority > 100 to override default allow.
    // Policy engine sorts rules by priority DESCENDING (higher number = evaluated first).
    const policy = await adminAPI.createPolicy({
      name: 'e2e-deny-read-file',
      priority: 200,
      rules: [
        {
          name: 'deny-read-file',
          priority: 200,
          tool_match: 'read_file',
          condition: 'true',
          action: 'deny',
        },
      ],
    });

    try {
      // Call the denied tool — expect an error response.
      const result = await mcpClient.callTool('read_file', {
        path: path.join(env.testDir, 'test.txt'),
      });

      // The proxy returns a JSON-RPC error for denied tool calls.
      // callTool wraps this as { error, isError: true }.
      expect(result.isError).toBe(true);

      // The error message from SafeErrorMessage should indicate policy denial.
      if (result.error) {
        const errMsg = typeof result.error === 'string'
          ? result.error
          : result.error.message || JSON.stringify(result.error);
        expect(errMsg.toLowerCase()).toMatch(/denied|policy|blocked|access/);
      }

      // A different tool (not matched by the policy) should still work.
      const listText = await mcpClient.callToolText('list_directory', {
        path: env.testDir,
      });
      expect(listText).toContain('test.txt');
    } finally {
      await adminAPI.deletePolicy(policy.id);
    }
  });

  test('wildcard deny policy blocks all tools', async ({ mcpClient, adminAPI, env }) => {
    // Create a deny-all policy with wildcard tool_match.
    const policy = await adminAPI.createPolicy({
      name: 'e2e-deny-all-tools',
      priority: 200,
      rules: [
        {
          name: 'deny-everything',
          priority: 200,
          tool_match: '*',
          condition: 'true',
          action: 'deny',
        },
      ],
    });

    try {
      // Both filesystem and memory tools should be denied.
      const readResult = await mcpClient.callTool('read_file', {
        path: path.join(env.testDir, 'test.txt'),
      });
      expect(readResult.isError).toBe(true);

      const listResult = await mcpClient.callTool('list_directory', {
        path: env.testDir,
      });
      expect(listResult.isError).toBe(true);

      const graphResult = await mcpClient.callTool('read_graph');
      expect(graphResult.isError).toBe(true);
    } finally {
      await adminAPI.deletePolicy(policy.id);
    }
  });

  // ---------------------------------------------------------------------------
  // 3. Rate limiting
  // ---------------------------------------------------------------------------
  // NOTE: Rate limit testing is intentionally omitted from this file.
  // Sending enough requests to trigger rate limits (100 req/min per IP)
  // poisons the global IP rate limiter, causing cascade failures in all
  // subsequent MCP tests that share the same localhost IP. Rate limiting
  // is covered by Go unit tests instead.

  // ---------------------------------------------------------------------------
  // 4. Content scanning config via MCP
  // ---------------------------------------------------------------------------

  test('content scanning can be toggled via admin API', async ({ adminAPI }) => {
    // Verify we can enable content scanning in enforce mode.
    await adminAPI.setContentScanning({ enabled: true, mode: 'enforce' });

    try {
      const config = await adminAPI.getContentScanning();
      expect(config.enabled).toBe(true);
      expect(config.mode).toBe('enforce');

      // Switch to monitor mode.
      await adminAPI.setContentScanning({ enabled: true, mode: 'monitor' });
      const config2 = await adminAPI.getContentScanning();
      expect(config2.enabled).toBe(true);
      expect(config2.mode).toBe('monitor');
    } finally {
      // Restore to disabled state.
      await adminAPI.setContentScanning({ enabled: false, mode: 'monitor' });
    }
  });

  test('tool calls work with content scanning disabled', async ({ mcpClient, adminAPI, env }) => {
    // Ensure content scanning is disabled (default state).
    await adminAPI.setContentScanning({ enabled: false, mode: 'monitor' });

    // Normal tool calls should succeed without interference.
    const text = await mcpClient.callToolText('read_file', {
      path: path.join(env.testDir, 'test.txt'),
    });
    expect(text).toContain('Hello from SentinelGate');
  });

  // ---------------------------------------------------------------------------
  // 5. tools/list unaffected by deny policy
  // ---------------------------------------------------------------------------

  test('tools/list unaffected by deny policy', async ({ mcpClient, adminAPI }) => {
    // A deny policy for tools/call should NOT affect tools/list.
    // tools/list is a protocol method, not a tool call.
    const policy = await adminAPI.createPolicy({
      name: 'e2e-deny-all-for-list-test',
      priority: 200,
      rules: [
        {
          name: 'deny-all-calls',
          priority: 200,
          tool_match: '*',
          condition: 'true',
          action: 'deny',
        },
      ],
    });

    try {
      // tools/list should still return the full tool set.
      const tools = await mcpClient.listTools();
      expect(tools.length).toBeGreaterThan(0);

      const toolNames = tools.map((t: any) => t.name);
      expect(toolNames).toContain('read_file');
    } finally {
      await adminAPI.deletePolicy(policy.id);
    }
  });

  // ---------------------------------------------------------------------------
  // Policy lifecycle: create, verify enforcement, delete, verify restored
  // ---------------------------------------------------------------------------

  test('policy lifecycle: create deny, verify block, delete, verify restored', async ({ mcpClient, adminAPI, env }) => {
    // Step 1: Verify tool works before policy.
    const beforeText = await mcpClient.callToolText('read_file', {
      path: path.join(env.testDir, 'test.txt'),
    });
    expect(beforeText).toContain('Hello from SentinelGate');

    // Step 2: Create deny policy.
    const policy = await adminAPI.createPolicy({
      name: 'e2e-lifecycle-deny',
      priority: 200,
      rules: [
        {
          name: 'lifecycle-deny-read',
          priority: 200,
          tool_match: 'read_file',
          condition: 'true',
          action: 'deny',
        },
      ],
    });

    try {
      // Step 3: Verify tool is now blocked.
      const deniedResult = await mcpClient.callTool('read_file', {
        path: path.join(env.testDir, 'test.txt'),
      });
      expect(deniedResult.isError).toBe(true);
    } finally {
      // Step 4: Delete policy.
      await adminAPI.deletePolicy(policy.id);
    }

    // Step 5: Verify tool works again after policy removal.
    const afterText = await mcpClient.callToolText('read_file', {
      path: path.join(env.testDir, 'test.txt'),
    });
    expect(afterText).toContain('Hello from SentinelGate');
  });

  // ---------------------------------------------------------------------------
  // T4.1: Read Only template allows read_text_file but denies write_file
  // ---------------------------------------------------------------------------

  test('T4.1: Read Only template allows read operations and denies writes', async ({ mcpClient, adminAPI, env }) => {
    // Apply the read-only template
    const policy = await adminAPI.applyTemplate('read-only');

    try {
      // read_file should be ALLOWED
      const readResult = await mcpClient.callTool('read_file', {
        path: path.join(env.testDir, 'test.txt'),
      });
      expect(readResult.isError).not.toBe(true);

      // write_file should be DENIED
      const writeResult = await mcpClient.callTool('write_file', {
        path: path.join(env.testDir, 'denied-write.txt'),
        content: 'this should be denied',
      });
      expect(writeResult.isError).toBe(true);
    } finally {
      // Cleanup: remove the template-created policy
      if (policy?.id) {
        await adminAPI.deletePolicy(policy.id);
      }
    }
  });
});
