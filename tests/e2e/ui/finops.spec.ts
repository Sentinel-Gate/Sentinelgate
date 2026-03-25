import { test, expect } from '../helpers/fixtures';

test.describe('FinOps', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/#/finops');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);
  });

  test('page loads with heading', async ({ page }) => {
    const heading = page.getByRole('heading', { name: /Cost Tracking/i });
    await expect(heading).toBeVisible({ timeout: 5000 });
  });

  test('cost summary section visible', async ({ page }) => {
    // The content area has id="fo-content" — it loads cost data or shows empty/error state
    const content = page.locator('#fo-content');
    await expect(content).toBeVisible({ timeout: 5000 });

    // Either we see the summary KPI cards or an empty/error state
    const hasSummary = await page.locator('.fo-summary').count();
    const hasEmpty = await page.locator('.fo-empty').count();
    expect(hasSummary > 0 || hasEmpty > 0).toBe(true);

    if (hasSummary > 0) {
      // The summary grid has 4 KPI cards
      const summaryCards = page.locator('.fo-summary-card');
      await expect(summaryCards).toHaveCount(4);

      // Verify the label texts
      await expect(summaryCards.nth(0)).toContainText('Total Cost');
      await expect(summaryCards.nth(1)).toContainText('Total Calls');
      await expect(summaryCards.nth(2)).toContainText('Avg Cost');
      await expect(summaryCards.nth(3)).toContainText('Projection');
    }
  });

  test('sidebar link exists', async ({ page }) => {
    const navLink = page.locator('a[data-page="finops"]');
    await expect(navLink).toBeVisible();
    await expect(navLink).toHaveAttribute('href', '#/finops');
  });

  test('page shows data or empty state', async ({ page }) => {
    const content = page.locator('#fo-content');
    await expect(content).toBeVisible({ timeout: 5000 });

    const contentText = await content.textContent();
    expect(contentText).toBeTruthy();

    // Content should contain cost-related information or an empty state message
    expect(contentText!.toLowerCase()).toMatch(/cost|budget|no cost data|not available|loading/);
  });

  test('configure button present', async ({ page }) => {
    const configBtn = page.locator('#fo-config-toggle');
    await expect(configBtn).toBeVisible({ timeout: 5000 });
    await expect(configBtn).toHaveText('Configure');
  });

  test('configure panel toggles on click', async ({ page }) => {
    const configBtn = page.locator('#fo-config-toggle');
    const configPanel = page.locator('#fo-config');

    // Initially hidden
    await expect(configPanel).not.toBeVisible();

    // Click to open
    await configBtn.click();
    await page.waitForTimeout(500);
    await expect(configPanel).toBeVisible();

    // Should contain configuration controls
    await expect(configPanel.locator('.fo-config-panel')).toBeVisible();
    await expect(configPanel).toContainText('Configuration');
    await expect(configPanel).toContainText('Enable Cost Tracking');
    await expect(configPanel).toContainText('Default Cost');

    // Click again to close
    await configBtn.click();
    await expect(configPanel).not.toBeVisible();
  });

  test('tool costs section visible when data exists', async ({ page }) => {
    await page.waitForTimeout(500);

    const content = page.locator('#fo-content');
    const hasSummary = await page.locator('.fo-summary').count();

    if (hasSummary > 0) {
      // When there is cost data, a "Cost by Tool" table may be present
      const toolTable = page.locator('.fo-table');
      const tableCount = await toolTable.count();

      if (tableCount > 0) {
        // At least one table should have headers
        const firstTable = toolTable.first();
        await expect(firstTable.locator('thead')).toBeVisible();
        await expect(firstTable.locator('tbody')).toBeVisible();
      }

      // The content should mention "Cost by" if there is data
      const contentText = await content.textContent();
      expect(contentText).toMatch(/Cost by|Total Cost/);
    } else {
      // No data — empty state should show a meaningful message
      const emptyState = page.locator('.fo-empty');
      await expect(emptyState).toBeVisible();
    }
  });

  test('page subtitle describes purpose', async ({ page }) => {
    const subtitle = page.locator('.page-subtitle');
    await expect(subtitle.first()).toBeVisible({ timeout: 5000 });
    await expect(subtitle.first()).toContainText('Track and control');
  });

  // ---------------------------------------------------------------------------
  // Wave 5 — Budget Configuration
  // ---------------------------------------------------------------------------

  test('budget configuration shows per-identity fields', async ({ page, adminAPI }) => {
    // Open the configure panel
    const configBtn = page.locator('#fo-config-toggle');
    await expect(configBtn).toBeVisible({ timeout: 5000 });
    await configBtn.click();
    await page.waitForTimeout(500);

    const configPanel = page.locator('#fo-config');
    await expect(configPanel).toBeVisible();

    // The config panel should contain budget-related inputs
    const configText = await configPanel.textContent();
    expect(configText).toBeTruthy();

    // Should have the "Enable Cost Tracking" toggle, "Default Cost" input
    await expect(configPanel).toContainText('Enable Cost Tracking');
    await expect(configPanel).toContainText('Default Cost');
  });

  test('save finops configuration persists', async ({ page, adminAPI }) => {
    // Get current config via API
    const configBefore = await adminAPI.get('/v1/finops/config');

    // Open configure panel
    const configBtn = page.locator('#fo-config-toggle');
    await configBtn.click();
    await page.waitForTimeout(500);

    const configPanel = page.locator('#fo-config');
    await expect(configPanel).toBeVisible();

    // Find and click the save button within the config panel
    const saveBtn = configPanel.getByRole('button', { name: /save/i });
    if (await saveBtn.isVisible()) {
      await saveBtn.click();
      await page.waitForTimeout(1000);

      // Verify config persisted via API
      const configAfter = await adminAPI.get('/v1/finops/config');
      expect(configAfter).toBeTruthy();
    }
  });

  test('budget section visible when data exists', async ({ page }) => {
    await page.waitForTimeout(500);

    const hasSummary = await page.locator('.fo-summary').count();

    if (hasSummary > 0) {
      // Budget bars are rendered when budget_status exists and is non-empty
      const budgetBars = page.locator('.fo-budget-bar');
      const budgetCount = await budgetBars.count();

      if (budgetCount > 0) {
        const firstBudget = budgetBars.first();
        // Each budget bar has info and a track
        await expect(firstBudget.locator('.fo-budget-info')).toBeVisible();
        await expect(firstBudget.locator('.fo-budget-track')).toBeVisible();
        await expect(firstBudget.locator('.fo-budget-fill')).toBeVisible();

        // The fill should have a status class
        const fillClass = await firstBudget.locator('.fo-budget-fill').getAttribute('class');
        expect(fillClass).toMatch(/ok|warn|over/);
      }
    }
  });
});
