import { test, expect, navigateAndWait } from '../../helpers/fixtures';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DASHBOARD_URL = '/admin/#/dashboard';
const DASHBOARD_SELECTOR = '#stat-cards';

/** Open the command palette via Meta+k and wait for it to become active. */
async function openPalette(page: import('@playwright/test').Page): Promise<void> {
  await page.keyboard.press('Meta+k');
  await page.waitForSelector('.cmd-palette-backdrop.active', { timeout: 5_000 });
}

/** Verify the palette is closed (backdrop removed from DOM or not active). */
async function expectPaletteClosed(page: import('@playwright/test').Page): Promise<void> {
  // After closing, the backdrop is removed from the DOM after a 200ms transition.
  await expect(page.locator('.cmd-palette-backdrop.active')).toHaveCount(0, { timeout: 5_000 });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('Command Palette', () => {

  // Every test starts on the dashboard so the page is fully loaded.
  test.beforeEach(async ({ page }) => {
    await navigateAndWait(page, DASHBOARD_URL, DASHBOARD_SELECTOR);
  });

  // 1. Meta+k opens palette (backdrop.active visible, input focused)
  test('Meta+k opens palette with active backdrop and focused input', async ({ page }) => {
    await openPalette(page);

    await expect(page.locator('.cmd-palette-backdrop')).toHaveClass(/active/);
    await expect(page.locator('.cmd-palette')).toBeVisible();
    await expect(page.locator('.cmd-palette-input')).toBeFocused();
  });

  // 2. Meta+k again closes palette (toggle behavior)
  test('Meta+k toggles palette closed when already open', async ({ page }) => {
    await openPalette(page);
    await expect(page.locator('.cmd-palette-backdrop')).toHaveClass(/active/);

    // Press Meta+k again to close
    await page.keyboard.press('Meta+k');
    await expectPaletteClosed(page);
  });

  // 3. Esc closes palette
  test('Escape closes the palette', async ({ page }) => {
    await openPalette(page);

    await page.keyboard.press('Escape');
    await expectPaletteClosed(page);
  });

  // 4. Backdrop click closes palette
  test('clicking the backdrop closes the palette', async ({ page }) => {
    await openPalette(page);

    // Click in the top-left corner of the backdrop (outside the centered palette)
    const backdrop = page.locator('.cmd-palette-backdrop');
    await backdrop.click({ position: { x: 10, y: 10 } });
    await expectPaletteClosed(page);
  });

  // 5. Input has correct placeholder text
  test('input has correct placeholder text', async ({ page }) => {
    await openPalette(page);

    await expect(page.locator('.cmd-palette-input')).toHaveAttribute(
      'placeholder',
      'Type a command or search...',
    );
  });

  // 6. Default shows Pages and Actions groups
  test('default view shows Pages and Actions groups', async ({ page }) => {
    await openPalette(page);

    const groupTitles = page.locator('.cmd-palette-group-title');
    // At minimum Pages and Actions; Servers/Tools may also appear after API fetch
    const titles: string[] = [];
    const count = await groupTitles.count();
    for (let i = 0; i < count; i++) {
      titles.push((await groupTitles.nth(i).textContent()) || '');
    }
    expect(titles).toContain('Pages');
    expect(titles).toContain('Actions');
  });

  // 7. Pages group contains all navigation pages
  test('Pages group contains all 12 navigation items', async ({ page }) => {
    await openPalette(page);

    const expectedPages = [
      'Dashboard',
      'Servers & Rules',
      'Connections',
      'Activity',
      'Sessions',
      'Notifications',
      'Security',
      'Compliance',
      'Access Review',
      'Red Team',
      'Cost Tracking',
      'Clients',
    ];

    for (const label of expectedPages) {
      const item = page.locator('.cmd-palette-item').filter({ hasText: label });
      await expect(item.first()).toBeVisible();
    }
  });

  // 8. Actions group shows 3 quick actions
  test('Actions group shows 3 quick actions', async ({ page }) => {
    await openPalette(page);

    const expectedActions = ['Add MCP Server', 'Create Rule', 'Create Identity'];
    for (const label of expectedActions) {
      const item = page.locator('.cmd-palette-item').filter({ hasText: label });
      await expect(item.first()).toBeVisible();
    }
  });

  // 9. Fuzzy search filters results
  test('fuzzy search filters results to matching items', async ({ page }) => {
    await openPalette(page);

    await page.locator('.cmd-palette-input').fill('dash');

    // Dashboard should be visible
    const dashboard = page.locator('.cmd-palette-item').filter({ hasText: 'Dashboard' });
    await expect(dashboard).toBeVisible();

    // Non-matching items like "Sessions" or "Security" should be hidden
    const sessions = page.locator('.cmd-palette-item').filter({ hasText: 'Sessions' });
    await expect(sessions).toHaveCount(0);

    const security = page.locator('.cmd-palette-item').filter({ hasText: 'Security' });
    await expect(security).toHaveCount(0);
  });

  // 10. Arrow down changes selected item
  test('ArrowDown moves selection to next item', async ({ page }) => {
    await openPalette(page);

    // First item should be selected by default
    const items = page.locator('.cmd-palette-item');
    await expect(items.first()).toHaveClass(/selected/);

    // Press ArrowDown
    await page.keyboard.press('ArrowDown');

    // First item should no longer be selected, second should be
    await expect(items.first()).not.toHaveClass(/selected/);
    await expect(items.nth(1)).toHaveClass(/selected/);
  });

  // 11. Enter selects and navigates (Dashboard -> #/dashboard)
  test('Enter on selected item navigates to its page', async ({ page }) => {
    await openPalette(page);

    // "Dashboard" is the first item in the Pages group, selected by default
    const firstItem = page.locator('.cmd-palette-item').first();
    await expect(firstItem).toHaveClass(/selected/);
    await expect(firstItem).toContainText('Dashboard');

    await page.keyboard.press('Enter');

    // Palette should close
    await expectPaletteClosed(page);

    // URL should contain #/dashboard
    await page.waitForURL(/.*#\/dashboard/, { timeout: 5_000 });
    expect(page.url()).toContain('#/dashboard');
  });

  // 12. Mouse click on item navigates and closes palette
  test('clicking an item navigates and closes palette', async ({ page }) => {
    await openPalette(page);

    // Click "Activity" item to navigate to #/audit
    const activityItem = page.locator('.cmd-palette-item').filter({ hasText: 'Activity' });
    await activityItem.click();

    await expectPaletteClosed(page);
    await page.waitForURL(/.*#\/audit/, { timeout: 5_000 });
    expect(page.url()).toContain('#/audit');
  });

  // 13. Empty results message on gibberish input
  test('gibberish input shows empty results message', async ({ page }) => {
    await openPalette(page);

    const gibberish = 'xzqwvbn';
    await page.locator('.cmd-palette-input').fill(gibberish);

    const emptyMsg = page.locator('.cmd-palette-empty');
    await expect(emptyMsg).toBeVisible();
    await expect(emptyMsg).toContainText(`No results for "${gibberish}"`);

    // No items should be visible
    await expect(page.locator('.cmd-palette-item')).toHaveCount(0);
  });

  // 14. Selecting "Add MCP Server" action opens the Add MCP Server modal
  test('"Add MCP Server" action opens Add MCP Server modal', async ({ page }) => {
    // Navigate to tools first so SG.tools.openAddUpstreamModal is available
    await page.goto('/admin/#/tools');
    await page.waitForLoadState('networkidle');

    await openPalette(page);

    const addServer = page.locator('.cmd-palette-item').filter({ hasText: 'Add MCP Server' });
    await addServer.click();

    await expectPaletteClosed(page);
    // The modal should open with "Add MCP Server" title
    await expect(page.locator('.modal-title, .sg-modal-title').filter({ hasText: /Add MCP Server/i })).toBeVisible({ timeout: 5_000 });
  });

  // 15. Selecting a page item via keyboard navigates correctly
  test('keyboard navigation and Enter on "Sessions" navigates to sessions page', async ({ page }) => {
    await openPalette(page);

    // Type "sess" to filter to Sessions
    await page.locator('.cmd-palette-input').fill('sess');

    // Sessions should be the first (and likely only) result
    const sessionsItem = page.locator('.cmd-palette-item').filter({ hasText: 'Sessions' });
    await expect(sessionsItem).toBeVisible();
    await expect(sessionsItem).toHaveClass(/selected/);

    await page.keyboard.press('Enter');

    await expectPaletteClosed(page);
    await page.waitForURL(/.*#\/sessions/, { timeout: 5_000 });
    expect(page.url()).toContain('#/sessions');
  });

  // -- Footer is present and informative ------------------------------------

  test('footer shows keyboard shortcut hints', async ({ page }) => {
    await openPalette(page);

    const footer = page.locator('.cmd-palette-footer');
    await expect(footer).toBeVisible();
    await expect(footer).toContainText('navigate');
    await expect(footer).toContainText('select');
    await expect(footer).toContainText('close');
  });
});
