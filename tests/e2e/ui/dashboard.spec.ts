import { test, expect, AdminAPI, MCPClient, createMCPSession } from '../helpers/fixtures';

test.describe('Dashboard', () => {
  test('stat cards visible with correct labels', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards');

    const statCards = page.locator('#stat-cards .stat-card');
    await expect(statCards).toHaveCount(5);

    await expect(page.locator('#stat-upstreams')).toBeVisible();
    await expect(page.locator('#stat-tools')).toBeVisible();
    await expect(page.locator('#stat-allowed')).toBeVisible();
    await expect(page.locator('#stat-denied')).toBeVisible();
    await expect(page.locator('#stat-ratelimited')).toBeVisible();

    // Verify labels — the #stat-* IDs are on the value divs; labels are sibling
    // .stat-card-label elements inside the parent .stat-card container.
    const cardWith = (id: string) =>
      page.locator('.stat-card').filter({ has: page.locator(`#${id}`) });

    await expect(cardWith('stat-upstreams')).toContainText('Upstreams');
    await expect(cardWith('stat-tools')).toContainText('Tools');
    await expect(cardWith('stat-allowed')).toContainText('Allowed');
    await expect(cardWith('stat-denied')).toContainText('Denied');
    await expect(cardWith('stat-ratelimited')).toContainText('Rate Limited');
  });

  test('stat cards show correct values from API', async ({ page, adminAPI }) => {
    const stats = await adminAPI.getStats();

    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards');

    // Wait for the dashboard to load data (polls every 2s)
    await page.waitForTimeout(2500);

    await expect(page.locator('#stat-upstreams')).toContainText(String(stats.upstreams));
    await expect(page.locator('#stat-tools')).toContainText(String(stats.tools));
    await expect(page.locator('#stat-allowed')).toContainText(String(stats.allowed));
    await expect(page.locator('#stat-denied')).toContainText(String(stats.denied));
    await expect(page.locator('#stat-ratelimited')).toContainText(String(stats.rate_limited));
  });

  test('upstream panel shows connected upstreams', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#upstream-list');

    const upstreamItems = page.locator('#upstream-list .upstream-item-link');
    await expect(upstreamItems).toHaveCount(2);

    // Verify the two expected upstreams (filesystem and memory)
    const allText = await page.locator('#upstream-list').textContent();
    expect(allText).toContain('filesystem');
    expect(allText).toContain('memory');
  });

  test('click upstream navigates to Tools filtered', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#upstream-list');

    const firstUpstream = page.locator('#upstream-list .upstream-item-link').first();
    await firstUpstream.click();

    // Verify navigation to #/tools
    await page.waitForURL(/.*#\/tools/);
    expect(page.url()).toContain('#/tools');
  });

  test('SSE activity feed shows events after tool call', async ({ page, mcpClient }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#activity-feed');

    // Make a tool call via MCP to generate activity
    const tools = await mcpClient.listTools();
    expect(tools.length).toBeGreaterThan(0);

    // Call the first available tool to generate an audit event
    const toolName = tools[0].name;
    await mcpClient.callTool(toolName, {});

    // Wait for the activity entry to appear in the feed (SSE push + poll cycle)
    // Activity items use class "upstream-item" (reused from upstream panel styling)
    await expect(page.locator('#activity-feed .upstream-item').first()).toBeVisible({
      timeout: 10_000,
    });

    // Verify the empty state is gone
    await expect(page.locator('#activity-empty')).not.toBeVisible();
  });

  test('active sessions widget shows session card', async ({ page, request }) => {
    // Create a new MCP session so there is at least one active session
    const extraClient = await createMCPSession(request);

    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#active-sessions-container');

    // Wait for the dashboard poll to pick up the session
    await expect(page.locator('#active-sessions-container .session-card').first()).toBeVisible({
      timeout: 10_000,
    });

    // Badge should show a count >= 1
    const badge = page.locator('#active-session-count');
    await expect(badge).toBeVisible();
    const countText = await badge.textContent();
    expect(Number(countText)).toBeGreaterThanOrEqual(1);

    // Cleanup
    await extraClient.deleteSession();
  });

  test('live indicator present', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#live-indicator');

    await expect(page.locator('#live-indicator')).toBeVisible();
    await expect(page.locator('#live-indicator .live-dot')).toBeVisible();
  });
});
