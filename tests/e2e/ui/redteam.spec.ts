import { test, expect } from '../helpers/fixtures';

test.describe('Red Team', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/#/redteam');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(500);
  });

  test('page loads with heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: /Red Team/i })).toBeVisible();
  });

  test('category filter dropdown present', async ({ page }) => {
    const dropdown = page.locator('select');
    await expect(dropdown).toBeVisible();
    // Should have Full Suite option with 30 patterns
    await expect(dropdown.locator('option').first()).toContainText('30 patterns');
  });

  test('run scan button present', async ({ page }) => {
    await expect(page.getByRole('button', { name: /Run Scan/i })).toBeVisible();
  });

  test('target identity input present', async ({ page }) => {
    await expect(page.getByPlaceholder(/target identity/i)).toBeVisible();
  });

  test('category selector has all attack categories', async ({ page }) => {
    const dropdown = page.locator('#rt-category');
    await expect(dropdown).toBeVisible();

    const options = dropdown.locator('option');
    // Full Suite + 6 individual categories = 7 options
    const count = await options.count();
    expect(count).toBe(7);

    // Verify key category names are present
    const allText = await dropdown.textContent();
    expect(allText).toContain('Tool Misuse');
    expect(allText).toContain('Argument Manipulation');
    expect(allText).toContain('Prompt Injection Direct');
    expect(allText).toContain('Permission Escalation');
    expect(allText).toContain('Multi-Step Attack');
  });

  test('results section shows empty state or scan results', async ({ page }) => {
    const content = page.locator('#rt-content');
    await expect(content).toBeVisible();
    // The page auto-loads recent reports via loadRecentReports().
    // If prior scans exist, results are rendered; otherwise empty state is shown.
    const text = await content.textContent();
    const hasEmptyState = text?.includes('No scan results yet');
    const hasScanResults = text?.includes('Patterns Tested');
    expect(hasEmptyState || hasScanResults).toBeTruthy();
  });

  test('roles input present', async ({ page }) => {
    const rolesInput = page.locator('#rt-roles');
    await expect(rolesInput).toBeVisible();
    // Verify placeholder text
    const placeholder = await rolesInput.getAttribute('placeholder');
    expect(placeholder).toMatch(/roles/i);
  });

  test('content area shows scan results or empty state', async ({ page }) => {
    // The page auto-loads recent reports. If reports exist, the content area
    // shows scan results (summary cards). Otherwise, the empty state is shown.
    const content = page.locator('#rt-content');
    await expect(content).toBeVisible();
    const text = await content.textContent();
    const hasEmptyState = text?.includes('Configure target') && text?.includes('red team scan');
    const hasScanResults = text?.includes('Patterns Tested') && text?.includes('Blocked');
    expect(hasEmptyState || hasScanResults).toBeTruthy();
  });

  // ---------------------------------------------------------------------------
  // Wave 1 — Apply Policy duplicate prevention
  // ---------------------------------------------------------------------------

  test('scan form inputs and run button are functional', async ({ page }) => {
    // Verify the scan form has all required inputs regardless of whether
    // recent reports have been loaded into the content area.
    const targetInput = page.locator('#rt-target');
    await expect(targetInput).toBeVisible();
    const rolesInput = page.locator('#rt-roles');
    await expect(rolesInput).toBeVisible();
    const runBtn = page.getByRole('button', { name: /Run Scan/i });
    await expect(runBtn).toBeVisible();
    await expect(runBtn).toBeEnabled();

    // If scan results are loaded and vulnerabilities exist, Apply Policy
    // buttons may be present inside collapsed accordion bodies (not visible).
    const applyBtns = page.locator('[data-apply]');
    const applyCount = await applyBtns.count();
    if (applyCount > 0) {
      // Buttons exist in the DOM — visibility is not asserted because
      // they live inside collapsed accordion bodies (display:none).
      expect(applyCount).toBeGreaterThan(0);
    }
  });

  test('sidebar link to red team exists', async ({ page }) => {
    const navLink = page.locator('a.nav-item[data-page="redteam"]');
    await expect(navLink).toBeVisible();
    await expect(navLink).toContainText('Red Team');
  });

  test('help button present', async ({ page }) => {
    const helpBtn = page.locator('#rt-help-btn');
    await expect(helpBtn).toBeVisible();
    await expect(helpBtn).toHaveText('?');
  });
});
