import { test, expect } from '../helpers/fixtures';

test.describe('Notifications', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/#/notifications');
    // Don't use networkidle — SSE stream keeps connection open
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);
  });

  test('page loads with heading', async ({ page }) => {
    const heading = page.getByRole('heading', { name: /notification/i });
    await expect(heading).toBeVisible({ timeout: 5000 });
    await expect(heading).toContainText('Notifications');
  });

  test('notification list or empty state visible', async ({ page }) => {
    // The page always renders .notif-content inside .notif-page
    const content = page.locator('.notif-content');
    await expect(content).toBeVisible({ timeout: 5000 });

    // Either we have notification cards or the empty state message
    const hasCards = await page.locator('.notif-card').count();
    const hasEmpty = await page.locator('.notif-empty').count();
    expect(hasCards > 0 || hasEmpty > 0).toBe(true);
  });

  test('sidebar notification link exists', async ({ page }) => {
    const navLink = page.locator('a[data-page="notifications"]');
    await expect(navLink).toBeVisible();
    await expect(navLink).toHaveAttribute('href', '#/notifications');
  });

  test('dismiss all button visible', async ({ page }) => {
    // The Dismiss All button is in the header actions area
    const dismissAllBtn = page.locator('button', { hasText: 'Dismiss All' });
    await expect(dismissAllBtn).toBeVisible({ timeout: 5000 });
  });

  test('live indicator present', async ({ page }) => {
    // The SSE live dot is rendered with id="notif-live-dot"
    const liveDot = page.locator('#notif-live-dot');
    await expect(liveDot).toBeVisible({ timeout: 5000 });

    // "Live" text label next to the dot
    const liveText = page.locator('span', { hasText: 'Live' });
    await expect(liveText.first()).toBeVisible();
  });

  test('notification cards have structure', async ({ page }) => {
    // Wait for data to load
    await page.waitForTimeout(500);

    const cards = page.locator('.notif-card');
    const cardCount = await cards.count();

    if (cardCount > 0) {
      const firstCard = cards.first();

      // Each card has a header with source and time
      await expect(firstCard.locator('.notif-card-header')).toBeVisible();
      await expect(firstCard.locator('.notif-card-source')).toBeVisible();
      await expect(firstCard.locator('.notif-card-time')).toBeVisible();

      // Each card has a title
      await expect(firstCard.locator('.notif-card-title')).toBeVisible();

      // Each card has an actions area with at least a dismiss button
      await expect(firstCard.locator('.notif-card-actions')).toBeVisible();
      await expect(firstCard.locator('.notif-dismiss-btn')).toBeVisible();

      // Cards have severity classes applied
      const cardClass = await firstCard.getAttribute('class');
      expect(cardClass).toMatch(/severity-(critical|warning|info)/);
    } else {
      // No cards — empty state should be shown
      await expect(page.locator('.notif-empty')).toBeVisible();
    }
  });

  test('empty state shows message', async ({ page }) => {
    // Wait for data to load
    await page.waitForTimeout(500);

    const emptyState = page.locator('.notif-empty');
    const cardCount = await page.locator('.notif-card').count();

    if (cardCount === 0) {
      await expect(emptyState).toBeVisible();
      await expect(emptyState).toContainText('All clear');
    } else {
      // If there are cards, the empty state should not appear
      await expect(emptyState).not.toBeVisible();
    }
  });

  test('page handles SSE connection', async ({ page }) => {
    // Collect console errors during page load
    const errors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });

    // Reload to capture any console errors from SSE setup
    await page.goto('/admin/#/notifications');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(2000);

    // The page should load without JS errors related to SSE or notifications
    const jsErrors = errors.filter(
      e => e.includes('notifications') || e.includes('SSE') || e.includes('EventSource')
    );
    expect(jsErrors).toHaveLength(0);

    // The live dot should be present (connected or disconnected)
    const liveDot = page.locator('#notif-live-dot');
    await expect(liveDot).toBeVisible();
  });

  test('section titles appear when notifications exist', async ({ page }) => {
    await page.waitForTimeout(500);

    const cards = page.locator('.notif-card');
    const cardCount = await cards.count();

    if (cardCount > 0) {
      // Section titles (ACTIONS REQUIRED or INFORMATIONAL) should be visible
      const sectionTitles = page.locator('.notif-section-title');
      const titleCount = await sectionTitles.count();
      expect(titleCount).toBeGreaterThan(0);

      // Each section title should have recognizable text
      for (let i = 0; i < titleCount; i++) {
        const text = await sectionTitles.nth(i).textContent();
        expect(text).toMatch(/ACTIONS REQUIRED|INFORMATIONAL/);
      }
    }
  });
});
