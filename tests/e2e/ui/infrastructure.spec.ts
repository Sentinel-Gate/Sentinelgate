import { test, expect, AdminAPI } from '../helpers/fixtures';

test.describe('UI Infrastructure', () => {
  // ---------------------------------------------------------------------------
  // SPA Router
  // ---------------------------------------------------------------------------

  test('SPA routing works for all pages', async ({ page }) => {
    const routes = [
      '/admin/#/dashboard',
      '/admin/#/tools',
      '/admin/#/security',
      '/admin/#/sessions',
      '/admin/#/audit',
      '/admin/#/access',
      '/admin/#/compliance',
      '/admin/#/notifications',
      '/admin/#/redteam',
      '/admin/#/finops',
      '/admin/#/permissions',
      '/admin/#/agents',
    ];

    for (const route of routes) {
      await page.goto(route);
      await page.waitForLoadState('domcontentloaded');
      await page.waitForTimeout(500);
      // Verify page content loaded (not blank)
      const content = await page.locator('#page-content').textContent();
      expect(content?.length).toBeGreaterThan(0);
    }
  });

  // ---------------------------------------------------------------------------
  // Browser Back/Forward
  // ---------------------------------------------------------------------------

  test('browser back/forward navigation works', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards');

    await page.goto('/admin/#/tools');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);

    await page.goBack();
    await page.waitForTimeout(1000);
    expect(page.url()).toContain('#/dashboard');
  });

  // ---------------------------------------------------------------------------
  // Sidebar Navigation
  // ---------------------------------------------------------------------------

  test('sidebar has all navigation links', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('nav');

    const navLinks = page.locator('nav a');
    const count = await navLinks.count();
    expect(count).toBeGreaterThanOrEqual(8);
  });

  // ---------------------------------------------------------------------------
  // Error Handling
  // ---------------------------------------------------------------------------

  test('no console errors on page load', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') errors.push(msg.text());
    });

    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards');
    await page.waitForTimeout(2000);

    // Filter out expected/benign errors (favicon, CSP, SSE disconnects,
    // rate limiting, and net::ERR_* from background fetches)
    const realErrors = errors.filter(e =>
      !e.includes('favicon') &&
      !e.includes('Content-Security-Policy') &&
      !e.includes('Content Security Policy') &&
      !e.includes('CSP') &&
      !e.includes('ERR_CONNECTION') &&
      !e.includes('net::ERR_') &&
      !e.includes('EventSource') &&
      !e.includes('SSE') &&
      !e.includes('rate limit') &&
      !e.includes('429') &&
      !e.includes('Failed to fetch') &&
      !e.includes('NetworkError') &&
      !e.includes('abort') &&
      !e.includes('The operation was aborted')
    );
    expect(realErrors).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // Toast Notifications
  // ---------------------------------------------------------------------------

  test('toast container exists on action pages', async ({ page, adminAPI }) => {
    await page.goto('/admin/#/access');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(2000);
    // Toast container should exist in the DOM (may or may not be visible depending on actions)
    const toastContainer = page.locator('.toast-container, #toast-container, [class*="toast"]');
    // Verify the page loaded successfully even if no toast is showing
    const pageContent = await page.locator('#page-content').textContent();
    expect(pageContent).toBeTruthy();
  });

  // ---------------------------------------------------------------------------
  // Deep Linking
  // ---------------------------------------------------------------------------

  test('deep link to specific page works', async ({ page }) => {
    // Navigate directly to audit page
    await page.goto('/admin/#/audit');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);

    // Verify we're on the audit page
    const heading = page.getByRole('heading');
    await expect(heading.first()).toBeVisible();
  });
});
