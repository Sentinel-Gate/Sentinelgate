import { test, expect, AdminAPI } from '../helpers/fixtures';

test.describe('Security', () => {
  // Track resources created during tests for cleanup
  let createdRuleIds: string[] = [];

  test.afterAll(async ({ request }) => {
    const api = new AdminAPI(request);

    // Clean up any outbound rules created during tests
    for (const id of createdRuleIds) {
      try {
        await api.deleteOutboundRule(id);
      } catch {
        // Rule may already be deleted
      }
    }

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
  // Outbound Control
  // ---------------------------------------------------------------------------

  test('default outbound rules visible', async ({ page }) => {
    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    // Wait for outbound section to render
    const ruleListBody = page.locator('#outbound-rule-list-body');
    await expect(ruleListBody).toBeVisible({ timeout: 10_000 });

    // Default blocklist rules should be present (read-only rows)
    const ruleRows = page.locator('.outbound-rule-row');
    await expect(ruleRows.first()).toBeVisible({ timeout: 10_000 });

    // There should be at least one default rule
    const count = await ruleRows.count();
    expect(count).toBeGreaterThan(0);

    // Verify the "Outbound Control" heading is rendered
    const heading = page.locator('.card-title', { hasText: 'Outbound Control' });
    await expect(heading).toBeVisible();
  });

  test('create outbound rule', async ({ page, adminAPI }) => {
    // Create a rule via API
    const rule = await adminAPI.createOutboundRule({
      name: 'block-evil',
      mode: 'blocklist',
      targets: [{ type: 'domain_glob', value: '*.evil.com' }],
      action: 'block',
      enabled: true,
    });

    if (rule && rule.id) {
      createdRuleIds.push(rule.id);
    }

    // Reload the security page
    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    // Wait for the outbound rules to render
    const ruleListBody = page.locator('#outbound-rule-list-body');
    await expect(ruleListBody).toBeVisible({ timeout: 10_000 });

    // Verify the created rule appears in the list
    await expect(page.locator('.outbound-rule-row', { hasText: 'block-evil' })).toBeVisible({
      timeout: 10_000,
    });

    // Verify it shows the correct target
    const ruleRow = page.locator('.outbound-rule-row', { hasText: 'block-evil' });
    await expect(ruleRow).toContainText('evil.com');
  });

  test('delete outbound rule', async ({ page, adminAPI }) => {
    // Create a rule to delete
    const rule = await adminAPI.createOutboundRule({
      name: 'to-be-deleted',
      mode: 'blocklist',
      targets: [{ type: 'domain_glob', value: '*.deleteme.com' }],
      action: 'block',
      enabled: true,
    });

    const ruleId = rule?.id;

    // Verify it exists first
    await page.goto('/admin/#/security');
    await page.waitForSelector('.security-header');

    const ruleListBody = page.locator('#outbound-rule-list-body');
    await expect(ruleListBody).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('.outbound-rule-row', { hasText: 'to-be-deleted' })).toBeVisible({
      timeout: 10_000,
    });

    // Delete via API
    if (ruleId) {
      await adminAPI.deleteOutboundRule(ruleId);
    }

    // Reload and verify gone (must use page.reload() because the SPA router
    // skips re-rendering when already on the same page)
    await page.reload();
    await page.waitForSelector('.security-header');

    await expect(page.locator('#outbound-rule-list-body')).toBeVisible({ timeout: 10_000 });

    // The deleted rule should no longer be in the list
    await expect(page.locator('.outbound-rule-row', { hasText: 'to-be-deleted' })).not.toBeVisible();
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
});
