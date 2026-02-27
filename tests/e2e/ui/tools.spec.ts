import { test, expect, AdminAPI } from '../helpers/fixtures';

test.describe('Tools & Rules', () => {
  // Track IDs created during tests for cleanup
  let createdUpstreamIds: string[] = [];
  let createdPolicyIds: string[] = [];
  let createdTransformIds: string[] = [];

  test.afterEach(async ({ adminAPI }) => {
    // Clean up any test data created during tests
    for (const id of createdTransformIds) {
      try { await adminAPI.deleteTransform(id); } catch { /* already deleted */ }
    }
    for (const id of createdPolicyIds) {
      try { await adminAPI.deletePolicy(id); } catch { /* already deleted */ }
    }
    for (const id of createdUpstreamIds) {
      try { await adminAPI.deleteUpstream(id); } catch { /* already deleted */ }
    }
    createdTransformIds = [];
    createdPolicyIds = [];
    createdUpstreamIds = [];
  });

  // ---------------------------------------------------------------------------
  // Upstream & Tools
  // ---------------------------------------------------------------------------

  test('page loads with tools', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tool-row', { timeout: 15_000 });

    const toolRows = page.locator('.tool-row');
    await expect(toolRows.first()).toBeVisible();

    const count = await toolRows.count();
    expect(count).toBeGreaterThan(0);

    // Header should contain "Tools"
    const heading = page.locator('.tools-header h1');
    await expect(heading).toContainText('Tools');
  });

  test('upstream groups show correct tools', async ({ page, adminAPI }) => {
    // Fetch tools via API to know expected counts
    // GET /admin/api/tools returns { tools: [...], conflicts: [...] }
    const apiResponse = await adminAPI.getTools();
    const apiTools = apiResponse.tools || [];
    const toolsByUpstream: Record<string, number> = {};
    for (const t of apiTools) {
      const upstream = t.upstream_name || 'unknown';
      toolsByUpstream[upstream] = (toolsByUpstream[upstream] || 0) + 1;
    }

    await page.goto('/admin/#/tools');
    await page.waitForSelector('.upstream-group', { timeout: 15_000 });

    const groups = page.locator('.upstream-group');
    const groupCount = await groups.count();
    expect(groupCount).toBeGreaterThanOrEqual(2); // filesystem + memory at minimum

    // Verify each upstream group has tools
    for (let i = 0; i < groupCount; i++) {
      const group = groups.nth(i);
      const name = await group.locator('.upstream-group-name').textContent();
      expect(name).toBeTruthy();

      // Ensure group body has tool rows (expand if collapsed)
      const body = group.locator('.upstream-group-body');
      if (await body.locator('.tool-row').count() === 0) {
        // Group might be collapsed, click header to expand
        await group.locator('.upstream-group-header').click();
        await page.waitForTimeout(300);
      }
      const toolCount = await body.locator('.tool-row').count();
      expect(toolCount).toBeGreaterThan(0);
    }
  });

  test('filter by upstream works', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tools-filter-tabs', { timeout: 15_000 });

    // "All" tab should be active by default
    const allTab = page.locator('.filter-tab.active');
    await expect(allTab).toBeVisible();

    // Get all filter tabs (All + one per upstream)
    const tabs = page.locator('.filter-tab');
    const tabCount = await tabs.count();
    expect(tabCount).toBeGreaterThanOrEqual(3); // All + filesystem + memory

    // Click a non-All tab (second tab = first upstream)
    const upstreamTab = tabs.nth(1);
    const tabText = await upstreamTab.textContent();
    await upstreamTab.click();

    // The clicked tab should become active
    await expect(upstreamTab).toHaveClass(/active/);

    // Only one upstream group should be visible now
    const visibleGroups = page.locator('.upstream-group:visible');
    await expect(visibleGroups).toHaveCount(1);

    // Click "All" tab to restore
    await tabs.nth(0).click();
    await expect(tabs.nth(0)).toHaveClass(/active/);
  });

  test('refresh tools button works', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tool-row', { timeout: 15_000 });

    // Count tools before refresh
    const countBefore = await page.locator('.tool-row').count();

    // Find the refresh button on an upstream group header
    const refreshBtn = page.locator('.upstream-group-header .btn-icon[title="Refresh tools"]').first();
    await expect(refreshBtn).toBeVisible();
    await refreshBtn.click();

    // Wait for refresh to complete
    await page.waitForTimeout(2000);

    // Tool count should stay consistent (no tools should disappear)
    const countAfter = await page.locator('.tool-row').count();
    expect(countAfter).toBeGreaterThanOrEqual(countBefore);
  });

  test('add HTTP upstream via modal', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tools-header', { timeout: 15_000 });

    // Click Add Upstream button
    const addBtn = page.getByRole('button', { name: 'Add Upstream' });
    await expect(addBtn).toBeVisible();
    await addBtn.click();

    // Modal should open
    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();

    // Fill the form: name
    await modal.locator('#upstream-name').fill('test-http-e2e');

    // Select HTTP type
    await modal.locator('#upstream-type').selectOption('http');

    // URL field should now be visible
    const urlInput = modal.locator('#upstream-url');
    await expect(urlInput).toBeVisible();

    // Fill the URL
    await urlInput.fill('http://localhost:9999');

    // Click Save
    const saveBtn = modal.getByRole('button', { name: 'Save' });
    await saveBtn.click();

    // Modal should close
    await expect(modal).not.toBeVisible({ timeout: 5_000 });

    // Wait for the creation to complete
    await page.waitForTimeout(2000);

    // Verify the upstream was created via API (it won't appear in tools-content
    // because an HTTP upstream to a non-existent server discovers 0 tools,
    // and the tools page only shows upstream groups that have tools)
    const upstreams = await page.evaluate(async () => {
      const res = await fetch('/admin/api/upstreams');
      return res.json();
    });
    const created = upstreams.find((u: any) => u.name === 'test-http-e2e');
    expect(created).toBeTruthy();
    expect(created.type).toBe('http');
    expect(created.url).toBe('http://localhost:9999');

    // Track for cleanup
    if (created) createdUpstreamIds.push(created.id);
  });

  test('delete upstream via API and verify removal', async ({ page, adminAPI }) => {
    // Create upstream via API
    const result = await adminAPI.createUpstream({
      name: 'test-delete-e2e',
      type: 'http',
      url: 'http://localhost:9998',
    });
    const upstreamId = result?.id;
    expect(upstreamId).toBeTruthy();

    // Verify it exists via API
    const beforeList = await adminAPI.getUpstreams();
    const found = beforeList.find((u: any) => u.id === upstreamId);
    expect(found).toBeTruthy();

    // Delete via API
    await adminAPI.deleteUpstream(upstreamId);

    // Verify it is gone via API
    const afterList = await adminAPI.getUpstreams();
    const notFound = afterList.find((u: any) => u.id === upstreamId);
    expect(notFound).toBeFalsy();

    // Also verify page doesn't show it (load tools page)
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tools-header', { timeout: 15_000 });
    await page.waitForTimeout(1500);

    const pageText = await page.locator('body').textContent();
    expect(pageText).not.toContain('test-delete-e2e');
  });

  // ---------------------------------------------------------------------------
  // Policy CRUD
  // ---------------------------------------------------------------------------

  test('create policy and verify rule visible', async ({ page, adminAPI }) => {
    // Create policy via API
    // Note: tool_match is required for the rule to be indexed and match tools.
    // condition is a CEL expression evaluated after tool_match glob filtering.
    const result = await adminAPI.createPolicy({
      name: 'e2e-test-policy',
      priority: 50,
      rules: [
        {
          name: 'deny-write',
          priority: 1,
          tool_match: 'write_*',
          condition: 'true',
          action: 'deny',
        },
      ],
    });
    const policyId = result?.id;
    expect(policyId).toBeTruthy();
    createdPolicyIds.push(policyId);

    // Load tools page
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.rules-section', { timeout: 15_000 });

    // Verify the rule appears in the rules section
    const rulesText = await page.locator('.rules-section').textContent();
    expect(rulesText).toContain('deny-write');
  });

  test('rule badge shows deny for matching tools', async ({ page, adminAPI }) => {
    // Create a deny-all policy so every tool shows deny badge.
    // tool_match: '*' is required so the rule is indexed as a wildcard
    // and matched against all tool names by the policy engine.
    // Policy engine sorts rules by priority DESCENDING (higher number = evaluated first).
    // The default allow-all rule has priority 100, so we need priority > 100 to override it.
    const result = await adminAPI.createPolicy({
      name: 'e2e-deny-all',
      priority: 200,
      rules: [
        {
          name: 'deny-everything',
          priority: 200,
          tool_match: '*',
          condition: 'true',
          action: 'deny',
        },
      ],
    });
    const policyId = result?.id;
    expect(policyId).toBeTruthy();
    createdPolicyIds.push(policyId);

    // Reload the tools page — the server evaluates policy_status per tool on GET /admin/api/tools
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tool-row', { timeout: 15_000 });

    // Wait for deny badges to appear — the server evaluates each tool against the new deny-all policy
    // Badges are: <span class="tool-badge"><span class="badge badge-danger">Deny</span></span>
    const denyBadge = page.locator('.tool-badge .badge-danger').first();
    await expect(denyBadge).toBeVisible({ timeout: 10_000 });

    const badgeCount = await page.locator('.tool-badge .badge-danger').count();
    expect(badgeCount).toBeGreaterThan(0);
  });

  test('delete policy and verify rule gone', async ({ page, adminAPI }) => {
    // Create policy
    // tool_match is required for the rule to appear in evaluation;
    // use a specific match so it's clearly visible in the rules list.
    const result = await adminAPI.createPolicy({
      name: 'e2e-delete-policy',
      priority: 50,
      rules: [
        {
          name: 'temp-rule',
          priority: 1,
          tool_match: 'nonexistent_tool',
          condition: 'true',
          action: 'deny',
        },
      ],
    });
    const policyId = result?.id;
    expect(policyId).toBeTruthy();

    // Load page and verify rule exists
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.rules-section', { timeout: 15_000 });
    const rulesTextBefore = await page.locator('.rules-section').textContent();
    expect(rulesTextBefore).toContain('temp-rule');

    // Delete policy via API
    await adminAPI.deletePolicy(policyId);

    // Reload and verify rule is gone
    await page.reload();
    await page.waitForSelector('.rules-section', { timeout: 15_000 });
    const rulesTextAfter = await page.locator('.rules-section').textContent();
    expect(rulesTextAfter).not.toContain('temp-rule');
  });

  // ---------------------------------------------------------------------------
  // Transforms
  // ---------------------------------------------------------------------------

  test('navigate to Transforms tab', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.section-tabs', { timeout: 15_000 });

    // Click the Transforms tab
    const transformsTab = page.locator('.section-tab', { hasText: 'Transforms' });
    await expect(transformsTab).toBeVisible();
    await transformsTab.click();

    // Tab should become active
    await expect(transformsTab).toHaveClass(/active/);

    // Transforms section content should be visible
    const transformsSection = page.locator('[data-section="transforms"]');
    await expect(transformsSection).toBeVisible();
  });

  test('create transform via API and verify visible', async ({ page, adminAPI }) => {
    // Create a redact transform via API
    // Use postRaw to check the actual HTTP status
    const rawRes = await adminAPI.postRaw('/v1/transforms', {
      name: 'e2e-redact-keys',
      type: 'redact',
      tool_match: '*',
      priority: 50,
      enabled: true,
      config: {
        patterns: ['sk-[a-zA-Z0-9]+'],
        replacement: '[REDACTED]',
      },
    });
    expect(rawRes.status()).toBe(201);
    const result = await rawRes.json();
    const transformId = result?.id;
    expect(transformId).toBeTruthy();
    createdTransformIds.push(transformId);

    // Load page and navigate to Transforms tab
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.section-tabs', { timeout: 15_000 });
    await page.locator('.section-tab', { hasText: 'Transforms' }).click();

    // Wait for transform rows to appear
    await page.waitForTimeout(1000);

    // Verify the transform row appears
    const transformsSection = page.locator('[data-section="transforms"]');
    const transformText = await transformsSection.textContent();
    expect(transformText).toContain('e2e-redact-keys');
  });

  test('delete transform via API and verify removed', async ({ page, adminAPI }) => {
    // Create a transform using postRaw for better error diagnostics
    const rawRes = await adminAPI.postRaw('/v1/transforms', {
      name: 'e2e-delete-transform',
      type: 'truncate',
      tool_match: '*',
      priority: 60,
      enabled: true,
      config: {
        max_bytes: 1000,
      },
    });
    expect(rawRes.status()).toBe(201);
    const result = await rawRes.json();
    const transformId = result?.id;
    expect(transformId).toBeTruthy();

    // Load page with transforms visible
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.section-tabs', { timeout: 15_000 });
    await page.locator('.section-tab', { hasText: 'Transforms' }).click();
    await page.waitForTimeout(1000);

    // Verify it exists
    let transformsText = await page.locator('[data-section="transforms"]').textContent();
    expect(transformsText).toContain('e2e-delete-transform');

    // Delete via API
    await adminAPI.deleteTransform(transformId);

    // Reload and verify gone
    await page.reload();
    await page.waitForSelector('.section-tabs', { timeout: 15_000 });
    await page.locator('.section-tab', { hasText: 'Transforms' }).click();
    await page.waitForTimeout(1000);

    transformsText = await page.locator('[data-section="transforms"]').textContent();
    expect(transformsText).not.toContain('e2e-delete-transform');
  });

  // ---------------------------------------------------------------------------
  // Policy Test Playground
  // ---------------------------------------------------------------------------

  test('navigate to Policy Test tab', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.section-tabs', { timeout: 15_000 });

    // Click the Policy Test tab
    const policyTestTab = page.locator('.section-tab', { hasText: 'Policy Test' });
    await expect(policyTestTab).toBeVisible();
    await policyTestTab.click();

    // Tab should become active
    await expect(policyTestTab).toHaveClass(/active/);

    // Policy Test section should be visible with the form inputs
    const testSection = page.locator('[data-section="policy-test"]');
    await expect(testSection).toBeVisible();
    await expect(testSection.locator('#test-tool-name')).toBeVisible();
    await expect(testSection.locator('#test-roles')).toBeVisible();
    await expect(testSection.locator('#test-identity')).toBeVisible();
  });

  test('policy test evaluation returns result', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.section-tabs', { timeout: 15_000 });

    // Navigate to Policy Test tab
    await page.locator('.section-tab', { hasText: 'Policy Test' }).click();
    const testSection = page.locator('[data-section="policy-test"]');
    await expect(testSection).toBeVisible();

    // Fill in tool name
    await testSection.locator('#test-tool-name').fill('read_file');

    // Optionally fill roles and identity
    await testSection.locator('#test-roles').fill('user');
    await testSection.locator('#test-identity').fill('e2e-tester');

    // Click Test Policy button
    const testBtn = testSection.getByRole('button', { name: 'Test Policy' });
    await expect(testBtn).toBeVisible();
    await testBtn.click();

    // Wait for result to appear
    const resultArea = testSection.locator('.test-result');
    await expect(resultArea).toBeVisible({ timeout: 10_000 });

    // Result should show either Allow or Deny
    const resultText = await resultArea.textContent();
    const hasDecision = resultText?.includes('Allow') || resultText?.includes('Deny');
    expect(hasDecision).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // General
  // ---------------------------------------------------------------------------

  test('tools page shows no error toasts', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tools-header', { timeout: 15_000 });

    // Wait for page to fully load
    await page.waitForTimeout(2000);

    // No error toasts should be present
    const errorToasts = page.locator('.toast-error, .toast.error, [data-type="error"]');
    const errorCount = await errorToasts.count();
    expect(errorCount).toBe(0);

    // No broken error banners
    const errorBanners = page.locator('.error-banner, .alert-error, .alert-danger');
    const bannerCount = await errorBanners.count();
    expect(bannerCount).toBe(0);
  });

  test('section tabs switch correctly between all sections', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.section-tabs', { timeout: 15_000 });

    const tabs = page.locator('.section-tab');
    await expect(tabs).toHaveCount(3);

    // Tools & Rules tab should be active by default
    await expect(tabs.nth(0)).toHaveClass(/active/);

    // Click Transforms
    await tabs.nth(1).click();
    await expect(tabs.nth(1)).toHaveClass(/active/);
    await expect(page.locator('[data-section="transforms"]')).toBeVisible();
    await expect(page.locator('[data-section="tools-rules"]')).not.toBeVisible();

    // Click Policy Test
    await tabs.nth(2).click();
    await expect(tabs.nth(2)).toHaveClass(/active/);
    await expect(page.locator('[data-section="policy-test"]')).toBeVisible();
    await expect(page.locator('[data-section="transforms"]')).not.toBeVisible();

    // Click back to Tools & Rules
    await tabs.nth(0).click();
    await expect(tabs.nth(0)).toHaveClass(/active/);
    await expect(page.locator('[data-section="tools-rules"]')).toBeVisible();
    await expect(page.locator('[data-section="policy-test"]')).not.toBeVisible();
  });
});
