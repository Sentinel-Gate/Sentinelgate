import { test, expect } from '../helpers/fixtures';

test.describe('Compliance', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/#/compliance');
    await page.waitForLoadState('domcontentloaded');
    // Wait a bit for initial render
    await page.waitForTimeout(500);
    // If the page shows a rate limit error, reload once after a delay
    const pageText = await page.locator('#page-content').textContent();
    if (pageText?.includes('rate limit') || pageText?.includes('Failed to load')) {
      await page.waitForTimeout(2000);
      await page.reload();
      await page.waitForLoadState('domcontentloaded');
    }
  });

  test('page loads with heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /compliance/i })).toBeVisible();
  });

  test('EU AI Act pack loads with coverage data', async ({ page }) => {
    // Wait for async coverage data to load. The coverage API may fail due to
    // rate limiting; in that case we reload and retry.
    const loaded = await page.getByText(/Overall Coverage/i).isVisible().catch(() => false);
    if (!loaded) {
      await page.waitForTimeout(2000);
      await page.reload();
      await page.waitForLoadState('domcontentloaded');
    }
    await expect(page.getByText(/Overall Coverage/i)).toBeVisible({ timeout: 15000 });
    // The page shows category headers like "Transparency & Oversight" --
    // these come from the requirement titles; check for general coverage text
    const contentText = await page.locator('#compliance-content').textContent();
    expect(contentText).toBeTruthy();
    expect(contentText!.length).toBeGreaterThan(50);
  });

  test('requirement cards visible', async ({ page }) => {
    // Wait for coverage grid to load (may need reload if rate-limited)
    const gridVisible = await page.locator('.compliance-grid').isVisible().catch(() => false);
    if (!gridVisible) {
      await page.waitForTimeout(2000);
      await page.reload();
      await page.waitForLoadState('domcontentloaded');
    }
    await expect(page.getByText(/Art\. 13|Art\. 14|Art\. 15/i).first()).toBeVisible({ timeout: 15000 });
  });

  test('generate bundle button present', async ({ page }) => {
    // The button only renders after coverage data loads successfully
    const buttonVisible = await page.getByRole('button', { name: /Generate Evidence Bundle/i }).isVisible().catch(() => false);
    if (!buttonVisible) {
      await page.waitForTimeout(2000);
      await page.reload();
      await page.waitForLoadState('domcontentloaded');
    }
    await expect(page.getByRole('button', { name: /Generate Evidence Bundle/i })).toBeVisible({ timeout: 15000 });
  });

  test('pack cards have titles and scores', async ({ page }) => {
    // Wait for coverage data to load and render the requirement grid
    const gridReady = await page.locator('.compliance-grid').first().isVisible().catch(() => false);
    if (!gridReady) {
      await page.waitForTimeout(2000);
      await page.reload();
      await page.waitForLoadState('domcontentloaded');
    }
    await expect(page.locator('.compliance-grid').first()).toBeVisible({ timeout: 15000 });

    const reqCards = page.locator('.compliance-req');
    const count = await reqCards.count();
    expect(count).toBeGreaterThan(0);

    // Each requirement card should have an article label and a title
    const firstCard = reqCards.first();
    await expect(firstCard.locator('.compliance-req-article')).toBeVisible();
    await expect(firstCard.locator('.compliance-req-title')).toBeVisible();
    // Each card has a score percentage
    await expect(firstCard.locator('.compliance-req-score')).toBeVisible();
    const scoreText = await firstCard.locator('.compliance-req-score').textContent();
    expect(scoreText).toMatch(/\d+%/);
  });

  test('pack detail expandable on click', async ({ page }) => {
    // Wait for coverage grid to load
    const gridReady = await page.locator('.compliance-grid').first().isVisible().catch(() => false);
    if (!gridReady) {
      await page.waitForTimeout(2000);
      await page.reload();
      await page.waitForLoadState('domcontentloaded');
    }
    await expect(page.locator('.compliance-grid').first()).toBeVisible({ timeout: 15000 });

    // The first requirement is auto-selected, so detail panel should already be visible
    const detailPanel = page.locator('#compliance-detail .compliance-detail');
    await expect(detailPanel).toBeVisible({ timeout: 5000 });

    // Detail panel should have a heading with article and title
    await expect(detailPanel.locator('h3')).toBeVisible();

    // Click a different requirement card to expand its detail
    const reqCards = page.locator('.compliance-req');
    const cardCount = await reqCards.count();
    if (cardCount > 1) {
      await reqCards.nth(1).click();
      // Detail panel should update with new content
      await expect(detailPanel.locator('h3')).toBeVisible();
    }
  });

  test('requirement items have status indicators', async ({ page }) => {
    // Wait for coverage data and auto-selected detail panel
    const gridReady = await page.locator('.compliance-grid').first().isVisible().catch(() => false);
    if (!gridReady) {
      await page.waitForTimeout(2000);
      await page.reload();
      await page.waitForLoadState('domcontentloaded');
    }
    await expect(page.locator('.compliance-grid').first()).toBeVisible({ timeout: 15000 });
    await expect(page.locator('#compliance-detail .compliance-detail')).toBeVisible({ timeout: 5000 });

    // Check that the detail panel contains check items with pass/fail icons
    const checks = page.locator('.compliance-check');
    const checkCount = await checks.count();
    expect(checkCount).toBeGreaterThan(0);

    // Each check should have an icon (pass or fail) and a description
    const firstCheck = checks.first();
    await expect(firstCheck.locator('.compliance-check-icon')).toBeVisible();
    await expect(firstCheck.locator('.compliance-check-desc')).toBeVisible();

    // Icon should have pass or fail class
    const iconClass = await firstCheck.locator('.compliance-check-icon').getAttribute('class');
    expect(iconClass).toMatch(/pass|fail/);
  });

  test('sidebar link to compliance exists', async ({ page }) => {
    const navLink = page.locator('a.nav-item[data-page="compliance"]');
    await expect(navLink).toBeVisible();
    await expect(navLink).toContainText('Compliance');
  });

  test('overall score bar visible with percentage', async ({ page }) => {
    // Wait for coverage data to render the score bar
    const barReady = await page.locator('.compliance-score-bar').isVisible().catch(() => false);
    if (!barReady) {
      await page.waitForTimeout(2000);
      await page.reload();
      await page.waitForLoadState('domcontentloaded');
    }
    await expect(page.locator('.compliance-score-bar')).toBeVisible({ timeout: 15000 });

    // Score number should show a percentage
    const scoreNumber = page.locator('.compliance-score-number');
    await expect(scoreNumber).toBeVisible();
    const scoreText = await scoreNumber.textContent();
    expect(scoreText).toMatch(/\d+%/);

    // Score label should say "Overall Coverage"
    await expect(page.locator('.compliance-score-label').first()).toContainText('Overall Coverage');

    // Progress bar fill should be present
    await expect(page.locator('.compliance-score-fill')).toBeVisible();
  });

  test('disclaimer text visible', async ({ page }) => {
    // Wait for the page to fully render (may need reload if rate-limited)
    const disclaimerReady = await page.locator('.compliance-disclaimer').isVisible().catch(() => false);
    if (!disclaimerReady) {
      await page.waitForTimeout(2000);
      await page.reload();
      await page.waitForLoadState('domcontentloaded');
    }
    await expect(page.locator('.compliance-disclaimer')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('.compliance-disclaimer')).toContainText('does not constitute legal advice');
  });
});
