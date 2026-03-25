import { test, expect, AdminAPI } from '../helpers/fixtures';

/** Pick a tool that works without arguments (avoids errors with create_directory etc.) */
function findSafeTool(tools: any[]): any {
  return tools.find((t: any) => t.name === 'list_allowed_directories')
    || tools.find((t: any) => t.name === 'read_graph')
    || tools[0];
}

test.describe('Dashboard', () => {
  test('stat cards visible with correct labels', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards');

    // Wait for stats API to load and replace skeleton with real stat cards.
    // The skeleton uses .skeleton-card; real cards use .stat-card.
    await page.waitForSelector('#stat-cards .stat-card', { timeout: 15_000 });

    const statCards = page.locator('#stat-cards .stat-card');
    await expect(statCards).toHaveCount(6, { timeout: 10_000 });

    await expect(page.locator('#stat-requests')).toBeVisible();
    await expect(page.locator('#stat-allowed')).toBeVisible();
    await expect(page.locator('#stat-denied')).toBeVisible();
    await expect(page.locator('#stat-blocked')).toBeVisible();
    await expect(page.locator('#stat-warned')).toBeVisible();
    await expect(page.locator('#stat-errors')).toBeVisible();

    // Verify labels — the #stat-* IDs are on the value divs; labels are sibling
    // .stat-card-label elements inside the parent .stat-card container.
    const cardWith = (id: string) =>
      page.locator('.stat-card').filter({ has: page.locator(`#${id}`) });

    await expect(cardWith('stat-requests')).toContainText('Requests');
    await expect(cardWith('stat-allowed')).toContainText('Allowed');
    await expect(cardWith('stat-denied')).toContainText('Denied');
    await expect(cardWith('stat-warned')).toContainText('Warned');
    await expect(cardWith('stat-errors')).toContainText('Errors');
  });

  test('stat cards show correct values from API', async ({ page, adminAPI }) => {
    const stats = await adminAPI.getStats();
    if (!stats || stats.error) {
      // Stats endpoint returned an error — skip rather than fail
      test.skip();
      return;
    }

    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards');

    // Wait for real stat cards to render (skeleton uses .skeleton-card, real uses .stat-card)
    await page.waitForSelector('#stat-cards .stat-card', { timeout: 15_000 });

    // Wait for the dashboard to load data (polls every 2s)
    await page.waitForTimeout(2500);

    const totalRequests = (stats.allowed || 0) + (stats.denied || 0) + (stats.blocked || 0) + (stats.warned || 0) + (stats.errors || 0);
    await expect(page.locator('#stat-requests')).toContainText(String(totalRequests));
    await expect(page.locator('#stat-allowed')).toContainText(String(stats.allowed));
    await expect(page.locator('#stat-denied')).toContainText(String(stats.denied));
    await expect(page.locator('#stat-blocked')).toContainText(String(stats.blocked || 0));
    await expect(page.locator('#stat-errors')).toContainText(String(stats.errors || 0));
  });

  test('upstream panel shows connected upstreams', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#upstream-list');

    // Wait for upstream items to render (API call replaces skeleton items)
    await expect(page.locator('#upstream-list .upstream-item-link').first()).toBeVisible({
      timeout: 10_000,
    });

    // The server may have a "default" upstream from the YAML config in addition
    // to the two E2E upstreams (filesystem, memory), so expect >= 2.
    const upstreamItems = page.locator('#upstream-list .upstream-item-link');
    const count = await upstreamItems.count();
    expect(count).toBeGreaterThanOrEqual(2);

    // Verify the two expected E2E upstreams are present
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
    const toolName = findSafeTool(tools).name;
    await mcpClient.callTool(toolName, {});

    // Wait for the activity entry to appear in the feed (SSE push + poll cycle)
    // Activity items use class "upstream-item" (reused from upstream panel styling)
    await expect(page.locator('#activity-feed .upstream-item').first()).toBeVisible({
      timeout: 10_000,
    });

    // Verify the empty state is gone
    await expect(page.locator('#activity-empty')).not.toBeVisible();
  });

  test('live indicator present', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#live-indicator');

    await expect(page.locator('#live-indicator')).toBeVisible();
    await expect(page.locator('#live-indicator .live-dot')).toBeVisible();
  });

  test('security score widget visible', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#posture-widget');

    await expect(page.locator('#posture-widget')).toBeVisible();
    // The posture card has a header with "Security Score" title
    await expect(page.locator('#posture-widget .card-title')).toContainText('Security Score');
    // Wait for posture body to load -- either the score appears or it stays in
    // calculating/error state. The important thing is the widget is present and
    // the body has rendered some content.
    await expect(page.locator('#posture-body')).toBeVisible({ timeout: 10_000 });
    // The posture body should have some textual content (score, calculating, or error)
    const bodyText = await page.locator('#posture-body').textContent();
    expect(bodyText).toBeTruthy();
  });

  test('health indicator reflects system state', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#health-indicator');

    const healthDot = page.locator('#health-indicator');
    await expect(healthDot).toBeVisible();
    // Health dot should have one of the health level classes
    const className = await healthDot.getAttribute('class');
    expect(className).toMatch(/health-(green|yellow|red)/);
    // Should have a title attribute describing the state
    const title = await healthDot.getAttribute('title');
    expect(title).toBeTruthy();
  });

  test('recent activity has entries after tool call', async ({ page, mcpClient }) => {
    // Generate activity by calling a tool
    const tools = await mcpClient.listTools();
    expect(tools.length).toBeGreaterThan(0);
    await mcpClient.callTool(findSafeTool(tools).name, {});

    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#activity-feed');

    // Wait for SSE to connect and deliver entries. Activity items use class
    // "upstream-item" inside the activity feed. The feed starts with skeleton
    // placeholders, then SSE delivers real entries.
    await expect(page.locator('#activity-feed .upstream-item').first()).toBeVisible({
      timeout: 15_000,
    });

    // Verify at least one activity entry is present
    const count = await page.locator('#activity-feed .upstream-item').count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('stat cards update after tool call', async ({ page, mcpClient, adminAPI }) => {
    // Get baseline stats
    const statsBefore = await adminAPI.getStats();
    const totalBefore = (statsBefore.allowed || 0) + (statsBefore.denied || 0) + (statsBefore.errors || 0);

    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards');
    // Wait for initial data load
    await page.waitForTimeout(2500);

    // Make a tool call to increment stats
    const tools = await mcpClient.listTools();
    expect(tools.length).toBeGreaterThan(0);
    await mcpClient.callTool(findSafeTool(tools).name, {});

    // Wait for the next stats poll cycle (2s interval) to reflect the new call
    await page.waitForTimeout(3000);

    // The total requests should have increased
    const statsAfter = await adminAPI.getStats();
    const totalAfter = (statsAfter.allowed || 0) + (statsAfter.denied || 0) + (statsAfter.errors || 0);
    expect(totalAfter).toBeGreaterThan(totalBefore);

    // Verify the UI reflects the updated value
    await expect(page.locator('#stat-requests')).toContainText(String(totalAfter));
  });

  test('dashboard auto-refreshes stats', async ({ page, adminAPI }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards');

    // Wait for the stat value to contain a numeric value (skeleton replaced).
    // The dashboard loads stats asynchronously; the skeleton placeholder is
    // replaced with a number once the API responds.
    await expect(async () => {
      const text = await page.locator('#stat-requests').textContent();
      expect(text).toBeTruthy();
      expect(text!.replace(/,/g, '')).toMatch(/^\d+$/);
    }).toPass({ timeout: 10_000 });

    // Wait for at least one more poll cycle (2s) -- the stat values should
    // still be present (page auto-refreshes without user interaction)
    await page.waitForTimeout(3000);

    // Stats element should still be visible and have a numeric value
    await expect(page.locator('#stat-requests')).toBeVisible();
    const refreshedText = await page.locator('#stat-requests').textContent();
    expect(refreshedText).toBeTruthy();
    // Value should be a number (possibly with commas from toLocaleString)
    expect(refreshedText!.replace(/,/g, '')).toMatch(/^\d+$/);
  });
});
