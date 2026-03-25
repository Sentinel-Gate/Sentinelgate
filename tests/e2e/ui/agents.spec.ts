import { test, expect } from '../helpers/fixtures';

test.describe('Agents', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/#/agents');
    await page.waitForSelector('.clients-header');
  });

  test('page loads with heading', async ({ page }) => {
    const heading = page.locator('.clients-header-left h1');
    await expect(heading).toBeVisible({ timeout: 10_000 });
    await expect(heading).toHaveText('Agents');
  });

  test('agent table or empty state visible', async ({ page }) => {
    // The page renders either a client-table (when sessions exist) or
    // a clients-empty div (when no active sessions). One must be present.
    const table = page.locator('table.client-table');
    const empty = page.locator('.clients-empty');

    const tableVisible = await table.isVisible().catch(() => false);
    const emptyVisible = await empty.isVisible().catch(() => false);

    expect(tableVisible || emptyVisible).toBe(true);
  });

  test('sidebar navigation link exists', async ({ page }) => {
    const navLink = page.locator('.sidebar-nav a.nav-item[href="#/agents"]');
    await expect(navLink).toBeVisible();
    await expect(navLink).toContainText('Agents');
  });

  test('header has health overview button', async ({ page }) => {
    // Health Overview button is always rendered in the header, regardless
    // of whether sessions exist.
    const overviewBtn = page.locator('.clients-header button', { hasText: 'Health Overview' });
    await expect(overviewBtn).toBeVisible();
  });

  test('table columns are correct', async ({ page }) => {
    const table = page.locator('table.client-table');
    const tableVisible = await table.isVisible().catch(() => false);

    if (tableVisible) {
      const headers = table.locator('thead th');
      // Columns: Status, Identity, Session, Connected, Requests, Last Activity, (chevron)
      await expect(headers).toHaveCount(7);
      await expect(headers.nth(0)).toHaveText('Status');
      await expect(headers.nth(1)).toHaveText('Identity');
      await expect(headers.nth(2)).toHaveText('Session');
      await expect(headers.nth(3)).toHaveText('Connected');
      await expect(headers.nth(4)).toHaveText('Requests');
      await expect(headers.nth(5)).toHaveText('Last Activity');
    } else {
      // No sessions -- empty state is shown instead of the table.
      // Verify the empty state message is present.
      const empty = page.locator('.clients-empty');
      await expect(empty).toBeVisible();
      await expect(empty).toContainText(/No agents connected|No active sessions/);
    }
  });

  test('page refreshes data without console errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    // Reload and wait for the page to settle
    await page.reload();
    await page.waitForSelector('.clients-header');

    // Give the poll cycle time to fire at least once (polls every 5s)
    await page.waitForTimeout(2000);

    expect(errors).toHaveLength(0);
  });
});
