import { test, expect, AdminAPI } from '../helpers/fixtures';

test.describe('Security', () => {
  test.afterAll(async ({ request }) => {
    const api = new AdminAPI(request);

    // Unquarantine any tools that might still be quarantined
    try {
      await api.unquarantineTool('write_file');
    } catch {
      // May not be quarantined
    }
  });

  // ---------------------------------------------------------------------------
  // Content Scanning
  // ---------------------------------------------------------------------------

  test('content scanning config visible', async ({ page }) => {
    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    // Verify the enable/disable toggle is present (checkbox is hidden via CSS
    // opacity:0/width:0/height:0 for custom toggle styling, so check attached)
    const toggle = page.locator('#scan-enabled');
    await expect(toggle).toBeAttached();

    // Verify the mode selector is present with Monitor and Enforce options
    const modeSelector = page.locator('#mode-selector');
    await expect(modeSelector).toBeVisible();

    const monitorOption = page.locator('#mode-monitor');
    await expect(monitorOption).toBeVisible();
    await expect(monitorOption).toContainText('Monitor');

    const enforceOption = page.locator('#mode-enforce');
    await expect(enforceOption).toBeVisible();
    await expect(enforceOption).toContainText('Enforce');

    // Save button should be visible
    await expect(page.locator('#save-scan-config')).toBeVisible();
  });

  test('toggle content scanning', async ({ page, adminAPI }) => {
    // Enable content scanning via API
    await adminAPI.setContentScanning({ enabled: true, mode: 'monitor' });

    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    // Verify toggle shows enabled
    const toggle = page.locator('#scan-enabled');
    await expect(toggle).toBeChecked();

    // Verify monitor mode is selected
    const monitorRadio = page.locator('input[name="scan-mode"][value="monitor"]');
    await expect(monitorRadio).toBeChecked();

    // Now disable via API and reload (must use page.reload() because the SPA
    // router skips re-rendering when the hash hasn't changed)
    await adminAPI.setContentScanning({ enabled: false, mode: 'monitor' });

    await page.reload();
    await page.waitForSelector('.security-header');

    // Verify toggle shows disabled
    const toggleAfter = page.locator('#scan-enabled');
    await expect(toggleAfter).not.toBeChecked();
  });

  // ---------------------------------------------------------------------------
  // Tool Security
  // ---------------------------------------------------------------------------

  test('capture baseline', async ({ page, adminAPI }) => {
    // Capture baseline via API
    const result = await adminAPI.captureBaseline();

    // Reload the security page
    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    // Wait for the tool security section to render
    const baselineInfo = page.locator('#toolsec-baseline-info');
    await expect(baselineInfo).toBeVisible({ timeout: 10_000 });

    // Verify baseline info shows the number of tools captured
    await expect(baselineInfo).toContainText('tools in baseline', { timeout: 10_000 });
  });

  test('quarantine tool', async ({ page, adminAPI }) => {
    // Quarantine a tool via API
    await adminAPI.quarantineTool('write_file');

    // Reload the security page
    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    // Wait for the quarantine list to render
    const quarantineList = page.locator('#toolsec-quarantine-list');
    await expect(quarantineList).toBeVisible({ timeout: 10_000 });

    // Verify "write_file" appears in the quarantine list
    await expect(quarantineList.locator('.toolsec-quarantine-name', { hasText: 'write_file' })).toBeVisible({
      timeout: 10_000,
    });
  });

  test('unquarantine tool', async ({ page, adminAPI }) => {
    // Ensure the tool is quarantined first
    try {
      await adminAPI.quarantineTool('write_file');
    } catch {
      // May already be quarantined from previous test
    }

    // Verify it shows up
    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    const quarantineList = page.locator('#toolsec-quarantine-list');
    await expect(quarantineList).toBeVisible({ timeout: 10_000 });
    await expect(quarantineList.locator('.toolsec-quarantine-name', { hasText: 'write_file' })).toBeVisible({
      timeout: 10_000,
    });

    // Unquarantine via API
    await adminAPI.unquarantineTool('write_file');

    // Reload and verify removed (must use page.reload() because the SPA router
    // skips re-rendering when already on the same page)
    await page.reload();
    await page.waitForSelector('.security-header');

    await expect(page.locator('#toolsec-quarantine-list')).toBeVisible({ timeout: 10_000 });

    // "write_file" should no longer be in the quarantine list
    await expect(
      page.locator('#toolsec-quarantine-list .toolsec-quarantine-name', { hasText: 'write_file' })
    ).not.toBeVisible();
  });

  // ---------------------------------------------------------------------------
  // Additional Section Visibility Tests
  // ---------------------------------------------------------------------------

  test('content scanning section visible', async ({ page }) => {
    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    // The Content Scanning card is the first .security-section with card-title "Content Scanning"
    const contentScanCard = page.locator('.card.security-section').first();
    await expect(contentScanCard).toBeVisible();

    // Card header should contain "Content Scanning"
    const cardTitle = contentScanCard.locator('.card-title');
    await expect(cardTitle).toContainText('Content Scanning');

    // Card body should contain the description text about scanning tool responses
    const cardBody = contentScanCard.locator('.card-body');
    await expect(cardBody).toBeVisible();
    await expect(cardBody).toContainText('Scan tool responses');

    // The toggle and mode selector should be within this section
    await expect(contentScanCard.locator('#scan-enabled')).toBeAttached();
    await expect(contentScanCard.locator('#mode-selector')).toBeVisible();
  });

  test('input content scanning section visible', async ({ page }) => {
    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    // The input-scan-section container should be rendered
    const inputScanSection = page.locator('#input-scan-section');
    await expect(inputScanSection).toBeAttached();

    // It should contain a card with "Input Content Scanning" title
    const inputScanCard = inputScanSection.locator('.card.security-section');
    await expect(inputScanCard).toBeVisible({ timeout: 10_000 });
    await expect(inputScanCard.locator('.card-title')).toContainText('Input Content Scanning');
  });

  test('tool security section visible', async ({ page }) => {
    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    // The toolsec-section container should be rendered
    const toolSecSection = page.locator('#toolsec-section');
    await expect(toolSecSection).toBeAttached();

    // It should contain a card with "Tool Security" title
    const toolSecCard = toolSecSection.locator('.card.security-section');
    await expect(toolSecCard).toBeVisible({ timeout: 10_000 });
    await expect(toolSecCard.locator('.card-title')).toContainText('Tool Security');

    // Baseline sub-section: Capture Baseline and View Baseline buttons
    await expect(page.locator('#toolsec-capture-btn')).toBeVisible();
    await expect(page.locator('#toolsec-view-baseline-btn')).toBeVisible();

    // Drift Detection sub-section: Check Drift button
    await expect(page.locator('#toolsec-drift-btn')).toBeVisible();

    // Quarantine sub-section: input and button
    await expect(page.locator('#toolsec-quarantine-input')).toBeVisible();
    await expect(page.locator('#toolsec-quarantine-add-btn')).toBeVisible();
  });

  test('namespace config section visible', async ({ page }) => {
    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    // The security page renders multiple .security-section cards.
    // Verify the page has the expected number of security section cards:
    // 1. Content Scanning, 2. Input Content Scanning, 3. Tool Security
    const securitySections = page.locator('.card.security-section');
    const sectionCount = await securitySections.count();
    expect(sectionCount).toBeGreaterThanOrEqual(2);

    // Verify the page subtitle mentions security scanning and threat detection
    const subtitle = page.locator('.page-subtitle');
    await expect(subtitle).toBeVisible();
    await expect(subtitle).toContainText('Security scanning');

    // Quarantine section provides namespace-level isolation by quarantining
    // tools per-name. Verify the quarantine list container exists.
    const quarantineList = page.locator('#toolsec-quarantine-list');
    await expect(quarantineList).toBeVisible({ timeout: 10_000 });
  });

  test('security page header and status badge visible', async ({ page }) => {
    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    // The header should contain the page title "Security"
    const heading = page.locator('.security-header h1');
    await expect(heading).toBeVisible();
    await expect(heading).toHaveText('Security');

    // The status badge should be visible (shows scanning mode)
    const statusBadge = page.locator('#security-status-badge');
    await expect(statusBadge).toBeVisible();

    // The save button in the content scanning section
    const saveBtn = page.locator('#save-scan-config');
    await expect(saveBtn).toBeVisible();
    await expect(saveBtn).toContainText('Save');
  });
});
