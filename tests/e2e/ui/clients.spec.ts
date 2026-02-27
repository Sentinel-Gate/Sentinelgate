import { test, expect, createMCPSession } from '../helpers/fixtures';

test.describe('Connected Clients', () => {
  test('page loads with heading', async ({ page }) => {
    await page.goto('/admin/#/agents');

    const heading = page.locator('h1, h2').filter({ hasText: /Clients|Connected Clients/ });
    await expect(heading).toBeVisible({ timeout: 10_000 });
  });

  test('shows connected MCP client', async ({ page, mcpClient }) => {
    await page.goto('/admin/#/agents');

    // mcpClient fixture already created a session — wait for a client row to appear
    const clientRow = page.locator('table.client-table tbody tr.client-row').first();
    await expect(clientRow).toBeVisible({ timeout: 10_000 });

    // Verify at least one row has a non-empty identity and a "connected" status
    const rowText = await clientRow.textContent();
    expect(rowText).toContain('connected');
    // Identity column should not be empty/dash (server resolves from API key)
    const identityCell = clientRow.locator('td').nth(1);
    const identity = await identityCell.textContent();
    expect(identity).toBeTruthy();
    expect(identity).not.toBe('-');
  });

  test('stats bar shows active sessions', async ({ page, mcpClient }) => {
    await page.goto('/admin/#/agents');

    const statsBar = page.locator('.clients-stats');
    await expect(statsBar).toBeVisible({ timeout: 10_000 });

    // Find the stat item that mentions "Active Sessions"
    const activeStat = page.locator('.clients-stat').filter({ hasText: /Active Sessions/i });
    await expect(activeStat).toBeVisible();

    // The count should be at least 1 (from the mcpClient fixture)
    const statText = await activeStat.textContent();
    const match = statText?.match(/(\d+)/);
    expect(match).not.toBeNull();
    expect(Number(match![1])).toBeGreaterThanOrEqual(1);
  });

  test('after MCP calls, request count updates', async ({ page, mcpClient }) => {
    // Make MCP tool call first — only tools/call increments total_calls (not initialize or tools/list)
    const tools = await mcpClient.listTools();
    expect(tools.length).toBeGreaterThan(0);
    await mcpClient.callTool(tools[0].name, {});

    // Load the page after the call so the session already has the count
    await page.goto('/admin/#/agents');

    const clientRow = page.locator('table.client-table tbody tr.client-row').first();
    await expect(clientRow).toBeVisible({ timeout: 10_000 });

    // The "Requests" column shows total_calls via a .client-count-badge span
    const requestsBadge = clientRow.locator('.client-count-badge');
    await expect(requestsBadge).toBeVisible();

    const countText = await requestsBadge.textContent();
    const count = Number(countText);
    expect(count).toBeGreaterThanOrEqual(1);
  });
});
