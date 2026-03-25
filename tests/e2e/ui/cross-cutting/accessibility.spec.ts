import { test, expect, navigateAndWait } from '../../helpers/fixtures';

test.describe('Accessibility', () => {
  test.beforeEach(async ({ page }) => {
    await navigateAndWait(page, '/admin/#/dashboard', '#page-content');
  });

  test('skip-to-content link exists and targets #page-content', async ({ page }) => {
    const skipLink = page.locator('a.skip-to-content');
    await expect(skipLink).toHaveAttribute('href', '#page-content');
    // Skip link should become visible on focus (Tab key)
    await page.keyboard.press('Tab');
    // Verify the link is focusable (it exists in tab order)
    const activeTag = await page.evaluate(() => document.activeElement?.tagName);
    // The skip link should be one of the first focusable elements
    expect(activeTag).toBe('A');
  });

  test('skip-to-content link navigates to main content', async ({ page }) => {
    const skipLink = page.locator('a.skip-to-content');
    // Force the link to be visible and click it
    await skipLink.evaluate(el => (el as HTMLElement).style.position = 'static');
    await skipLink.click();
    // After clicking, focus should move to or near #page-content
    const url = page.url();
    expect(url).toContain('#page-content');
  });

  test('modals have role="dialog" and aria-modal="true"', async ({ page }) => {
    // Navigate to access page and trigger a modal via Add Identity
    await navigateAndWait(page, '/admin/#/access', '.access-header');
    await page.waitForSelector('[data-action="add-identity"]', { timeout: 10_000 });
    await page.click('[data-action="add-identity"]');
    await page.waitForSelector('.modal-backdrop.active', { timeout: 5_000 });
    const modal = page.locator('.modal');
    await expect(modal).toBeVisible();
    await expect(modal).toHaveAttribute('role', 'dialog');
    await expect(modal).toHaveAttribute('aria-modal', 'true');
    // Close modal
    await page.keyboard.press('Escape');
  });

  test('modal close button has aria-label', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.access-header');
    await page.waitForSelector('[data-action="add-identity"]', { timeout: 10_000 });
    await page.click('[data-action="add-identity"]');
    await page.waitForSelector('.modal-backdrop.active', { timeout: 5_000 });
    const closeBtn = page.locator('.modal-close');
    await expect(closeBtn).toBeVisible();
    await expect(closeBtn).toHaveAttribute('aria-label', 'Close dialog');
    await page.keyboard.press('Escape');
  });

  test('toast close button has aria-label', async ({ page }) => {
    // Trigger a toast via JS
    await page.evaluate(() => (window as any).SG.toast.success('Accessibility test'));
    const closeBtn = page.locator('.toast-close').first();
    await expect(closeBtn).toBeVisible();
    const ariaLabel = await closeBtn.getAttribute('aria-label');
    expect(ariaLabel).toBeTruthy(); // Has some aria-label
  });

  test('form inputs have associated labels', async ({ page }) => {
    // Navigate to access page and open a modal with form
    await navigateAndWait(page, '/admin/#/access', '.access-header');
    await page.waitForSelector('[data-action="add-identity"]', { timeout: 10_000 });
    await page.click('[data-action="add-identity"]');
    await page.waitForSelector('.modal-backdrop.active', { timeout: 5_000 });
    await expect(page.locator('.modal')).toBeVisible();

    // Check that visible inputs inside the modal have labels
    const inputs = page.locator('.modal input:visible, .modal select:visible, .modal textarea:visible');
    const count = await inputs.count();
    expect(count).toBeGreaterThan(0);

    // Each input should have an associated label (via for/id or wrapping label or aria-label or placeholder)
    for (let i = 0; i < Math.min(count, 5); i++) {
      const input = inputs.nth(i);
      const id = await input.getAttribute('id');
      const ariaLabel = await input.getAttribute('aria-label');
      const placeholder = await input.getAttribute('placeholder');

      // Input must have at least one accessibility mechanism
      const hasLabel = id ? await page.locator(`label[for="${id}"]`).count() > 0 : false;
      const hasAriaLabel = !!ariaLabel;
      const hasPlaceholder = !!placeholder;
      const isWrappedInLabel = await input.evaluate(
        el => el.closest('label') !== null
      );
      // Also check if a label sibling exists within the same form-group
      const hasSiblingLabel = await input.evaluate(
        el => el.closest('.form-group')?.querySelector('.form-label') !== null
      );

      expect(hasLabel || hasAriaLabel || hasPlaceholder || isWrappedInLabel || hasSiblingLabel).toBeTruthy();
    }

    await page.keyboard.press('Escape');
  });

  test('nav items are keyboard navigable', async ({ page }) => {
    // Tab through sidebar nav items
    const navItems = page.locator('.nav-item');
    const navCount = await navItems.count();
    expect(navCount).toBeGreaterThan(5);

    // Each nav item should be a link (focusable by default)
    for (let i = 0; i < Math.min(navCount, 3); i++) {
      const tagName = await navItems.nth(i).evaluate(el => el.tagName);
      expect(tagName).toBe('A');
    }
  });

  test('active nav item is visually distinguishable', async ({ page }) => {
    // Dashboard should be active after beforeEach navigation
    const activeNav = page.locator('.nav-item.active');
    await expect(activeNav).toHaveCount(1);
    await expect(activeNav).toHaveAttribute('data-page', 'dashboard');

    // Navigate to tools
    await page.click('a.nav-item[data-page="tools"]');
    await page.waitForURL(/.*#\/tools/);

    // Wait for the router to update the active class on the tools nav item.
    // The hashchange handler runs asynchronously after the URL changes, so
    // the DOM may not reflect the new active state immediately.
    const toolsActive = page.locator('.nav-item.active[data-page="tools"]');
    await expect(toolsActive).toHaveCount(1, { timeout: 5_000 });

    // Exactly one nav item should be active
    const newActive = page.locator('.nav-item.active');
    await expect(newActive).toHaveCount(1);
    const activePage = await newActive.getAttribute('data-page');
    expect(activePage).toBe('tools');
  });
});
