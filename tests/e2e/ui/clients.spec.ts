import { test, expect, createMCPSession } from '../helpers/fixtures';

/**
 * Helper: find a tool that can be called without arguments.
 * Prefers list_allowed_directories > read_graph > first tool in list.
 */
function findSafeTool(tools: any[]): any {
  return (
    tools.find((t: any) => t.name === 'list_allowed_directories') ||
    tools.find((t: any) => t.name === 'read_graph') ||
    tools[0]
  );
}

test.describe('Connected Clients', () => {
  test('page loads with heading', async ({ page }) => {
    await page.goto('/admin/#/agents');

    const heading = page.locator('h1, h2').filter({ hasText: /Agents|Connected Agents/ });
    await expect(heading).toBeVisible({ timeout: 10_000 });
  });

  test('shows connected MCP client', async ({ page, mcpClient }) => {
    // The session tracker only creates entries on tools/call (RecordCall),
    // not on initialize. Call a safe tool first to register the session.
    const tools = await mcpClient.listTools();
    expect(tools.length).toBeGreaterThan(0);
    const safeTool = findSafeTool(tools);
    await mcpClient.callTool(safeTool.name, {});

    await page.goto('/admin/#/agents');

    // Wait for the page to poll active sessions (polls every 5s)
    const clientRow = page.locator('table.client-table tbody tr.client-row').first();
    await expect(clientRow).toBeVisible({ timeout: 15_000 });

    // Verify at least one row has a non-empty identity
    const identityCell = clientRow.locator('td').nth(1);
    const identity = await identityCell.textContent();
    expect(identity).toBeTruthy();
    expect(identity).not.toBe('-');
  });

  test('stats bar shows active sessions', async ({ page, mcpClient }) => {
    // Ensure the session is tracked by making a tool call
    const tools = await mcpClient.listTools();
    expect(tools.length).toBeGreaterThan(0);
    const safeTool = findSafeTool(tools);
    await mcpClient.callTool(safeTool.name, {});

    await page.goto('/admin/#/agents');

    const statsBar = page.locator('.clients-stats');
    await expect(statsBar).toBeVisible({ timeout: 15_000 });

    // Wait for stats to populate (page polls /v1/sessions/active)
    await page.waitForTimeout(3000);

    // Find the stat item that mentions "Active Sessions" or similar
    const activeStat = page.locator('.clients-stat').filter({ hasText: /^[\d]+Active Sessions$/i });
    await expect(activeStat).toBeVisible({ timeout: 10_000 });

    // The count should be at least 1 (from the mcpClient session)
    const statText = await activeStat.textContent();
    const match = statText?.match(/(\d+)/);
    expect(match).not.toBeNull();
    expect(Number(match![1])).toBeGreaterThanOrEqual(1);
  });

  test('after MCP calls, request count updates', async ({ page, mcpClient }) => {
    // Make MCP tool call first — only tools/call increments total_calls (not initialize or tools/list)
    const tools = await mcpClient.listTools();
    expect(tools.length).toBeGreaterThan(0);
    const safeTool = findSafeTool(tools);
    await mcpClient.callTool(safeTool.name, {});

    // Load the page after the call so the session already has the count
    await page.goto('/admin/#/agents');

    // Wait for the page data to load
    await page.waitForTimeout(3000);

    const clientRow = page.locator('table.client-table tbody tr.client-row').first();
    await expect(clientRow).toBeVisible({ timeout: 15_000 });

    // The "Requests" column shows total_calls via a .client-count-badge span
    const requestsBadge = clientRow.locator('.client-count-badge');
    await expect(requestsBadge).toBeVisible({ timeout: 10_000 });

    const countText = await requestsBadge.textContent();
    const count = Number(countText);
    expect(count).toBeGreaterThanOrEqual(1);
  });
});
