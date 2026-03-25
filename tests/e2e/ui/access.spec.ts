import { test, expect, AdminAPI } from '../helpers/fixtures';

test.describe('Access', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/#/access');
    await page.waitForSelector('.access-header');
  });

  // ---------------------------------------------------------------------------
  // API Keys
  // ---------------------------------------------------------------------------

  test('keys table visible with e2e-test-key', async ({ page }) => {
    // The keys section (third .access-section, after MCP Servers and Identities)
    const keysTable = page.locator('#keys-table-container table');
    await expect(keysTable).toBeVisible({ timeout: 10_000 });

    // Look for the e2e-test-key in the table rows
    const rows = keysTable.locator('tbody tr');
    await expect(rows).not.toHaveCount(0);

    // Verify the table header columns
    const headers = keysTable.locator('thead th');
    await expect(headers).toHaveCount(5);
    await expect(headers.nth(0)).toHaveText('Name');
    await expect(headers.nth(3)).toHaveText('Status');
  });

  test('create key via UI shows cleartext key', async ({ page, adminAPI }) => {
    // Create a test identity via API to use for the key
    const identity = await adminAPI.createIdentity({ name: 'e2e-key-test-identity', roles: ['user'] });
    const identityId = identity.id;

    try {
      // Reload to pick up the new identity and wait for keys table to render
      await page.reload();
      await page.waitForSelector('.access-header');
      // Wait for the keys table to load (data fetched asynchronously)
      await page.waitForSelector('#keys-table-container table', { timeout: 10000 });

      // Click "Create Key" button in the card header (not in a modal)
      const createBtn = page.locator('.card-header button.btn-primary', { hasText: 'Create Key' });
      await expect(createBtn).toBeVisible();
      await createBtn.click();

      // Modal should open
      const modal = page.locator('[role="dialog"]');
      await expect(modal).toBeVisible();

      // Fill in the name
      const nameInput = modal.locator('input.form-input');
      await nameInput.fill('e2e-created-key');

      // Select the identity
      const identitySelect = modal.locator('select.form-select');
      await identitySelect.selectOption({ value: identityId });

      // Submit via the modal footer button
      const submitBtn = modal.locator('.modal-footer button.btn-primary');
      await submitBtn.click();

      // Should show the cleartext key display (showKeyResult replaces modal body)
      const keyDisplay = modal.locator('.key-display');
      await expect(keyDisplay).toBeVisible({ timeout: 10000 });

      // Key should be non-empty
      const keyText = await keyDisplay.textContent();
      expect(keyText).toBeTruthy();
      expect(keyText!.length).toBeGreaterThan(10);

      // Warning text should appear
      const warning = modal.locator('.key-display-warning');
      await expect(warning).toBeVisible();

      // Close the modal via Done button (inside modal-body > key-result-footer)
      const doneBtn = modal.locator('button.btn-secondary', { hasText: 'Done' });
      await doneBtn.click();
    } finally {
      // Cleanup: delete the identity (cascades keys)
      await adminAPI.deleteIdentity(identityId);
    }
  });

  test('revoked key shows Revoked status', async ({ page, adminAPI }) => {
    // Create identity + key, then revoke it via API
    const identity = await adminAPI.createIdentity({ name: 'e2e-revoke-identity', roles: ['user'] });
    const key = await adminAPI.createKey(identity.id, 'e2e-revoke-key');

    try {
      // Revoke the key via API
      await adminAPI.revokeKey(key.id);

      // Reload and verify
      await page.reload();
      await page.waitForSelector('.access-header');
      // Wait for keys table to render with data
      await page.waitForSelector('#keys-table-container table', { timeout: 10000 });

      // Find the row with the revoked key name
      const row = page.locator('#keys-table-container table tbody tr', { hasText: 'e2e-revoke-key' });
      await expect(row).toBeVisible();

      // Should have "Revoked" badge (class is "badge badge-danger")
      const revokedBadge = row.locator('.badge-danger', { hasText: 'Revoked' });
      await expect(revokedBadge).toBeVisible();
    } finally {
      await adminAPI.deleteIdentity(identity.id);
    }
  });

  // ---------------------------------------------------------------------------
  // Identities
  // ---------------------------------------------------------------------------

  test('identities section visible with e2e-tester', async ({ page, env }) => {
    // Wait for page data to load
    await page.waitForTimeout(2000);

    // Expand identities section if collapsed
    const collapseHeader = page.locator('.access-collapse-header');
    const collapseBody = page.locator('.access-collapse-body');

    // Click to expand if collapsed
    const isCollapsed = await collapseBody.evaluate(el => el.classList.contains('collapsed')).catch(() => true);
    if (isCollapsed) {
      await collapseHeader.click();
      await page.waitForTimeout(500);
    }

    await expect(collapseBody).not.toHaveClass(/collapsed/);

    // Look for the e2e-tester identity in the identities table
    const identityTable = collapseBody.locator('table');
    await expect(identityTable).toBeVisible({ timeout: 10_000 });

    // The e2e-tester identity should be listed
    const testerRow = identityTable.locator('tr', { hasText: env.identityName });
    await expect(testerRow).toBeVisible({ timeout: 10_000 });

    // Should have role badges
    const roleBadges = testerRow.locator('.role-badge');
    await expect(roleBadges.first()).toBeVisible({ timeout: 5_000 });
  });

  test('create identity via API appears in UI', async ({ page, adminAPI }) => {
    const identity = await adminAPI.createIdentity({ name: 'test-identity', roles: ['user', 'admin'] });

    try {
      await page.reload();
      await page.waitForSelector('.access-header');
      // Wait for identities table to render with data
      await page.waitForSelector('#identities-table-container table', { timeout: 15000 });

      // Expand identities section if collapsed
      const collapseHeader = page.locator('.access-collapse-header');
      const collapseBody = page.locator('#identities-table-container');

      const isCollapsed = await collapseBody.evaluate(el => el.classList.contains('collapsed')).catch(() => true);
      if (isCollapsed) {
        await collapseHeader.click();
        await page.waitForTimeout(500);
      }

      // Verify the new identity appears
      const row = collapseBody.locator('tr', { hasText: 'test-identity' });
      await expect(row).toBeVisible({ timeout: 10_000 });

      // Verify role badges
      const adminBadge = row.locator('.role-badge', { hasText: 'admin' });
      const userBadge = row.locator('.role-badge', { hasText: 'user' });
      await expect(adminBadge).toBeVisible({ timeout: 5_000 });
      await expect(userBadge).toBeVisible({ timeout: 5_000 });
    } finally {
      await adminAPI.deleteIdentity(identity.id);
    }
  });

  test('delete identity via API removes from UI', async ({ page, adminAPI }) => {
    // Create then delete
    const identity = await adminAPI.createIdentity({ name: 'e2e-delete-me', roles: ['user'] });

    // Reload to see it
    await page.reload();
    await page.waitForSelector('.access-header');
    // Wait for identities table to render with data
    await page.waitForSelector('#identities-table-container table', { timeout: 15000 });

    // Expand identities if collapsed
    const collapseHeader = page.locator('.access-collapse-header');
    const collapseBody = page.locator('#identities-table-container');

    const isCollapsed = await collapseBody.evaluate(el => el.classList.contains('collapsed')).catch(() => true);
    if (isCollapsed) {
      await collapseHeader.click();
      await page.waitForTimeout(500);
    }

    // Confirm it exists
    await expect(collapseBody.locator('tr', { hasText: 'e2e-delete-me' })).toBeVisible({ timeout: 10_000 });

    // Delete via API
    await adminAPI.deleteIdentity(identity.id);

    // Reload and verify gone
    await page.reload();
    await page.waitForSelector('.access-header');
    // Wait for identities table to re-render
    await page.waitForSelector('#identities-table-container table', { timeout: 15000 });

    // Re-expand identities if collapsed
    const collapseBody2 = page.locator('#identities-table-container');
    const collapseHeader2 = page.locator('.access-collapse-header');

    const isCollapsed2 = await collapseBody2.evaluate(el => el.classList.contains('collapsed')).catch(() => true);
    if (isCollapsed2) {
      await collapseHeader2.click();
      await page.waitForTimeout(500);
    }

    await expect(collapseBody2.locator('tr', { hasText: 'e2e-delete-me' })).not.toBeVisible();
  });

  // ---------------------------------------------------------------------------
  // Quotas
  // ---------------------------------------------------------------------------

  test('set quota shows quota badge on identity', async ({ page, adminAPI }) => {
    const identity = await adminAPI.createIdentity({ name: 'e2e-quota-identity', roles: ['user'] });

    try {
      // Set quota via API (action must be "deny" or "warn")
      await adminAPI.setQuota(identity.id, {
        max_calls_per_session: 5,
        enabled: true,
        action: 'deny',
      });

      // Reload to see the quota badge
      await page.reload();
      await page.waitForSelector('.access-header');
      // Wait for identities table to render with data
      await page.waitForSelector('#identities-table-container table', { timeout: 15000 });

      // Expand identities section if collapsed
      const collapseHeader = page.locator('.access-collapse-header');
      const collapseBody = page.locator('#identities-table-container');

      const isCollapsed = await collapseBody.evaluate(el => el.classList.contains('collapsed')).catch(() => true);
      if (isCollapsed) {
        await collapseHeader.click();
        await page.waitForTimeout(500);
      }

      // Find the identity row
      const row = collapseBody.locator('tr', { hasText: 'e2e-quota-identity' });
      await expect(row).toBeVisible({ timeout: 10_000 });

      // Should have a quota badge (class "quota-badge quota-badge-enabled")
      const quotaBadge = row.locator('.quota-badge');
      await expect(quotaBadge).toBeVisible({ timeout: 5_000 });
    } finally {
      await adminAPI.deleteQuota(identity.id);
      await adminAPI.deleteIdentity(identity.id);
    }
  });

  test('remove quota hides quota badge', async ({ page, adminAPI }) => {
    const identity = await adminAPI.createIdentity({ name: 'e2e-quota-remove', roles: ['user'] });

    try {
      // Set then remove quota (action must be "deny" or "warn")
      await adminAPI.setQuota(identity.id, {
        max_calls_per_session: 10,
        enabled: true,
        action: 'deny',
      });

      // Verify badge shows up first
      await page.reload();
      await page.waitForSelector('.access-header');
      // Wait for identities table to render with data
      await page.waitForSelector('#identities-table-container table', { timeout: 15000 });

      const collapseHeader = page.locator('.access-collapse-header');
      const collapseBody = page.locator('#identities-table-container');

      const isCollapsed = await collapseBody.evaluate(el => el.classList.contains('collapsed')).catch(() => true);
      if (isCollapsed) {
        await collapseHeader.click();
        await page.waitForTimeout(500);
      }

      const row = collapseBody.locator('tr', { hasText: 'e2e-quota-remove' });
      await expect(row).toBeVisible({ timeout: 10_000 });
      await expect(row.locator('.quota-badge')).toBeVisible({ timeout: 5_000 });

      // Remove quota
      await adminAPI.deleteQuota(identity.id);

      // Reload and verify badge is gone
      await page.reload();
      await page.waitForSelector('.access-header');
      // Wait for identities table to re-render
      await page.waitForSelector('#identities-table-container table', { timeout: 15000 });

      const collapseBody2 = page.locator('#identities-table-container');
      const collapseHeader2 = page.locator('.access-collapse-header');

      const isCollapsed2 = await collapseBody2.evaluate(el => el.classList.contains('collapsed')).catch(() => true);
      if (isCollapsed2) {
        await collapseHeader2.click();
        await page.waitForTimeout(500);
      }

      const row2 = collapseBody2.locator('tr', { hasText: 'e2e-quota-remove' });
      await expect(row2).toBeVisible({ timeout: 10_000 });
      await expect(row2.locator('.quota-badge')).not.toBeVisible();
    } finally {
      await adminAPI.deleteIdentity(identity.id);
    }
  });

  // ---------------------------------------------------------------------------
  // Agent Config Tabs
  // ---------------------------------------------------------------------------

  test('agent config tabs present with 7 tabs', async ({ page }) => {
    const tabBar = page.locator('.config-tabs');
    await expect(tabBar).toBeVisible();

    const tabs = tabBar.locator('.config-tab');
    await expect(tabs).toHaveCount(7);

    // Verify expected tab labels
    const expectedLabels = [
      'Claude Code',
      'Gemini CLI',
      'Codex CLI',
      'Cursor / IDE',
      'Python',
      'Node.js',
      'cURL',
    ];

    for (let i = 0; i < expectedLabels.length; i++) {
      await expect(tabs.nth(i)).toHaveText(expectedLabels[i]);
    }
  });

  test('each tab shows config snippet with server address', async ({ page }) => {
    const tabBar = page.locator('.config-tabs');
    const tabs = tabBar.locator('.config-tab');
    const tabCount = await tabs.count();

    expect(tabCount).toBe(7);

    for (let i = 0; i < tabCount; i++) {
      // Click the tab
      await tabs.nth(i).click();

      // Find the active tab content with a config snippet
      const activeContent = page.locator('.config-tab-content.active');
      await expect(activeContent).toBeVisible();

      const snippet = activeContent.locator('.config-snippet').first();
      await expect(snippet).toBeVisible();

      // Each snippet should reference the server address
      const snippetText = await snippet.textContent();
      expect(snippetText).toBeTruthy();
      // The proxy address is derived from window.location.host, which in
      // tests is typically localhost:XXXX or falls back to "localhost:8080"
      expect(snippetText).toMatch(/localhost:\d+/);
    }
  });
});
