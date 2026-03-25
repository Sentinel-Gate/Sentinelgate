import { test, expect } from '../helpers/fixtures';
import { getTestEnv } from '../helpers/api';
import * as http from 'http';

test.describe('SSE Streams', () => {
  test.setTimeout(60_000);

  /**
   * Connect to an SSE endpoint and collect events for a given duration.
   */
  function collectSSEEvents(url: string, durationMs: number): Promise<string[]> {
    return new Promise((resolve) => {
      const events: string[] = [];
      const req = http.get(url, (res) => {
        res.on('data', (chunk: Buffer) => {
          const text = chunk.toString();
          // SSE format: "data: {...}\n\n"
          const lines = text.split('\n').filter(l => l.startsWith('data:'));
          for (const line of lines) {
            events.push(line.substring(5).trim());
          }
        });
      });
      req.on('error', () => {});
      setTimeout(() => {
        req.destroy();
        resolve(events);
      }, durationMs);
    });
  }

  test('audit SSE stream delivers events after tool call', async ({ mcpClient }) => {
    const env = getTestEnv();

    // Start listening to audit SSE
    const eventPromise = collectSSEEvents(`${env.baseUrl}/admin/api/audit/stream`, 10_000);

    // Wait a moment for SSE to connect
    await new Promise(r => setTimeout(r, 1_000));

    // Make a tool call to generate an audit event
    await mcpClient.send('tools/call', {
      name: 'read_file',
      arguments: { path: env.testDir + '/test.txt' },
    });

    const events = await eventPromise;

    // Should have received at least one SSE event
    expect(events.length).toBeGreaterThan(0);

    // Event should be parseable JSON with audit fields
    const parsed = JSON.parse(events[events.length - 1]);
    expect(parsed.tool_name || parsed.tool || parsed.method).toBeTruthy();
  });

  test('notification SSE stream connects without error', async () => {
    const env = getTestEnv();

    // Connect to notification stream for 3 seconds
    const connected = await new Promise<boolean>((resolve) => {
      const req = http.get(`${env.baseUrl}/admin/api/v1/notifications/stream`, (res) => {
        // 200 means SSE connection established
        resolve(res.statusCode === 200);
        req.destroy();
      });
      req.on('error', () => resolve(false));
      setTimeout(() => { req.destroy(); resolve(false); }, 5_000);
    });

    expect(connected).toBeTruthy();
  });

  test('audit SSE delivers denied events with correct decision', async ({ mcpClient, adminAPI }) => {
    const env = getTestEnv();

    // Create deny policy
    const policy = await adminAPI.createPolicy({
      name: 'sse-deny-test',
      rules: [{ name: 'deny-write', tool_match: 'write_file', condition: 'true', action: 'deny', priority: 200 }],
    });

    try {
      // Listen to SSE
      const eventPromise = collectSSEEvents(`${env.baseUrl}/admin/api/audit/stream`, 10_000);
      await new Promise(r => setTimeout(r, 1_000));

      // Make a denied tool call
      await mcpClient.send('tools/call', {
        name: 'write_file',
        arguments: { path: env.testDir + '/sse-test.txt', content: 'test' },
      });

      const events = await eventPromise;
      expect(events.length).toBeGreaterThan(0);

      // Find the denied event
      const deniedEvent = events.find(e => {
        try {
          const parsed = JSON.parse(e);
          return parsed.decision === 'denied' || parsed.decision === 'deny';
        } catch { return false; }
      });

      expect(deniedEvent).toBeTruthy();
    } finally {
      await adminAPI.deletePolicy(policy.id);
    }
  });

  test('audit SSE reconnects after brief disconnect', async ({ page, mcpClient }) => {
    // Navigate to audit page (which uses SSE)
    await page.goto('/admin/#/audit');
    await page.waitForSelector('#page-content', { timeout: 15_000 });

    // Navigate away (disconnects SSE)
    await page.goto('/admin/#/tools');
    await page.waitForSelector('#page-content', { timeout: 15_000 });

    // Make a tool call while on another page
    const env = getTestEnv();
    await mcpClient.send('tools/call', {
      name: 'read_file',
      arguments: { path: env.testDir + '/test.txt' },
    });

    // Navigate back to audit (reconnects SSE)
    await page.goto('/admin/#/audit');
    await page.waitForSelector('#page-content', { timeout: 15_000 });

    // Entries should be visible (from the call made between navigations)
    await expect(async () => {
      const entries = page.locator('.audit-row, .audit-entry');
      const count = await entries.count();
      expect(count).toBeGreaterThan(0);
    }).toPass({ timeout: 15_000 });
  });

  test('multiple concurrent SSE connections work', async ({ mcpClient }) => {
    const env = getTestEnv();

    // Open two SSE connections simultaneously
    const promise1 = collectSSEEvents(`${env.baseUrl}/admin/api/audit/stream`, 8_000);
    const promise2 = collectSSEEvents(`${env.baseUrl}/admin/api/audit/stream`, 8_000);

    await new Promise(r => setTimeout(r, 1_000));

    // Make a tool call
    await mcpClient.send('tools/call', {
      name: 'read_file',
      arguments: { path: env.testDir + '/test.txt' },
    });

    const [events1, events2] = await Promise.all([promise1, promise2]);

    // Both connections should receive the event
    expect(events1.length).toBeGreaterThan(0);
    expect(events2.length).toBeGreaterThan(0);
  });

  test('SSE events contain required audit fields', async ({ mcpClient }) => {
    const env = getTestEnv();

    const eventPromise = collectSSEEvents(`${env.baseUrl}/admin/api/audit/stream`, 8_000);
    await new Promise(r => setTimeout(r, 1_000));

    await mcpClient.send('tools/call', {
      name: 'read_file',
      arguments: { path: env.testDir + '/test.txt' },
    });

    const events = await eventPromise;
    expect(events.length).toBeGreaterThan(0);

    const event = JSON.parse(events[events.length - 1]);

    // Verify essential audit fields exist
    expect(event.timestamp || event.ts).toBeTruthy();
    expect(event.tool_name || event.tool || event.method).toBeTruthy();
    expect(event.decision || event.action).toBeTruthy();
    expect(event.identity_name || event.identity || event.identity_id).toBeTruthy();
  });

  test('dashboard SSE shows live indicator active', async ({ page, mcpClient }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards', { timeout: 15_000 });

    // Live indicator should become active after SSE connects
    const indicator = page.locator('#live-indicator');
    await expect(indicator).toBeVisible({ timeout: 10_000 });

    // Wait for SSE to establish
    await expect(async () => {
      const classes = await indicator.getAttribute('class');
      expect(classes).not.toContain('inactive');
    }).toPass({ timeout: 15_000 });

    // Make a tool call — activity feed should update
    const env = getTestEnv();
    await mcpClient.send('tools/call', {
      name: 'read_file',
      arguments: { path: env.testDir + '/test.txt' },
    });

    // Verify activity entry appears in the activity feed.
    // The dashboard renders entries as .upstream-item inside #activity-feed.
    await expect(async () => {
      const entries = page.locator('#activity-feed .upstream-item');
      expect(await entries.count()).toBeGreaterThan(0);
    }).toPass({ timeout: 15_000 });
  });

  test('audit stream handles rapid events correctly', async ({ mcpClient }) => {
    const env = getTestEnv();

    const eventPromise = collectSSEEvents(`${env.baseUrl}/admin/api/audit/stream`, 12_000);
    await new Promise(r => setTimeout(r, 1_000));

    // Fire 5 rapid tool calls
    const calls = [];
    for (let i = 0; i < 5; i++) {
      calls.push(mcpClient.send('tools/call', {
        name: 'read_file',
        arguments: { path: env.testDir + '/test.txt' },
      }));
    }
    await Promise.all(calls);

    const events = await eventPromise;

    // Should receive all 5 events (or close to it)
    expect(events.length).toBeGreaterThanOrEqual(3); // Allow some tolerance
  });
});
