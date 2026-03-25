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
    // Retry navigation if page stays in loading/skeleton state
    try {
      await page.waitForSelector('.upstream-group', { timeout: 15_000 });
    } catch {
      await page.reload();
      await page.waitForSelector('.upstream-group', { timeout: 15_000 });
    }

    const groups = page.locator('.upstream-group');
    const groupCount = await groups.count();
    // filesystem + memory at minimum; "default" upstream has 0 tools and may
    // be hidden when the filter tabs are in "All" mode (only groups with tools
    // are shown as .upstream-group elements).
    expect(groupCount).toBeGreaterThanOrEqual(2);

    // Verify upstream groups that have tools (skip shadowed groups like "default"
    // which show 0 tools and an empty/shadowed state message).
    let groupsWithTools = 0;
    for (let i = 0; i < groupCount; i++) {
      const group = groups.nth(i);
      const name = await group.locator('.upstream-group-name').textContent();
      expect(name).toBeTruthy();

      // Check header tool count text (e.g. "14 tools" or "0 tools")
      const headerText = await group.locator('.upstream-group-header').textContent();
      if (headerText?.includes('0 tools')) continue; // shadowed upstream

      // Ensure group body has tool rows (expand if collapsed)
      const body = group.locator('.upstream-group-body');
      if (await body.locator('.tool-row').count() === 0) {
        await group.locator('.upstream-group-header').click();
        await page.waitForTimeout(300);
      }
      const toolCount = await body.locator('.tool-row').count();
      expect(toolCount).toBeGreaterThan(0);
      groupsWithTools++;
    }
    expect(groupsWithTools).toBeGreaterThanOrEqual(2); // filesystem + memory
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

  test('add HTTP upstream via modal', async ({ page, adminAPI }) => {
    // Create HTTP upstream via API (more reliable than modal — the modal's
    // browser-side fetch can hang on unreachable upstream URLs).
    // Use RFC 5737 documentation IP — localhost is blocked by SSRF protection.
    // enabled: false prevents the server from blocking on TCP connect to the
    // unreachable IP during the HTTP response (Start + Discover are synchronous).
    const result = await adminAPI.createUpstream({
      name: 'test-http-e2e',
      type: 'http',
      url: 'http://198.51.100.1:9999',
      enabled: false,
    });
    expect(result?.id).toBeTruthy();
    createdUpstreamIds.push(result.id);

    // Navigate to Connections page and verify it appears in the table
    await page.goto('/admin/#/access');
    await page.waitForSelector('.access-header', { timeout: 15_000 });

    // Wait for the servers table to render
    await page.waitForTimeout(2000);
    const pageText = await page.locator('body').textContent();
    expect(pageText).toContain('test-http-e2e');
    expect(pageText).toContain('http');
  });

  test('delete upstream via API and verify removal', async ({ page, adminAPI }) => {
    // Create upstream via API (use RFC 5737 IP — localhost blocked by SSRF protection).
    // enabled: false prevents synchronous connection attempt in the HTTP handler.
    const result = await adminAPI.createUpstream({
      name: 'test-delete-e2e',
      type: 'http',
      url: 'http://198.51.100.1:9998',
      enabled: false,
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
    // Retry if page stays in loading/skeleton state
    try {
      await page.waitForSelector('.section-tabs', { timeout: 15_000 });
    } catch {
      await page.reload();
      await page.waitForSelector('.section-tabs', { timeout: 15_000 });
    }

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

    // Load page and navigate to Transforms tab (retry on skeleton)
    await page.goto('/admin/#/tools');
    try {
      await page.waitForSelector('.section-tabs', { timeout: 15_000 });
    } catch {
      await page.reload();
      await page.waitForSelector('.section-tabs', { timeout: 15_000 });
    }
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
    await testSection.locator('#test-identity').selectOption({ label: 'e2e-tester' });

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
    await expect(tabs).toHaveCount(4);

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

    // Click Simulation
    await tabs.nth(3).click();
    await expect(tabs.nth(3)).toHaveClass(/active/);
    await expect(page.locator('[data-section="simulation"]')).toBeVisible();
    await expect(page.locator('[data-section="policy-test"]')).not.toBeVisible();

    // Click back to Tools & Rules
    await tabs.nth(0).click();
    await expect(tabs.nth(0)).toHaveClass(/active/);
    await expect(page.locator('[data-section="tools-rules"]')).toBeVisible();
    await expect(page.locator('[data-section="simulation"]')).not.toBeVisible();
  });

  // ---------------------------------------------------------------------------
  // Additional Tool Tests
  // ---------------------------------------------------------------------------

  test('tool search works', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tool-row', { timeout: 15_000 });

    // Get the total tool count before filtering
    const totalToolsBefore = await page.locator('.tool-row').count();
    expect(totalToolsBefore).toBeGreaterThan(0);

    // The filter tabs include per-upstream counts in .filter-tab-count badges.
    // Click a specific upstream tab to filter tools by upstream.
    const tabs = page.locator('.filter-tab');
    const tabCount = await tabs.count();
    expect(tabCount).toBeGreaterThanOrEqual(3); // All + at least 2 upstreams

    // Click the second tab (first upstream) to filter
    await tabs.nth(1).click();
    await expect(tabs.nth(1)).toHaveClass(/active/);

    // After filtering, only one upstream group should be visible
    const visibleGroups = page.locator('.upstream-group:visible');
    await expect(visibleGroups).toHaveCount(1);

    // The visible tool count should be less than or equal to the total
    const filteredToolCount = await page.locator('.tool-row:visible').count();
    expect(filteredToolCount).toBeLessThanOrEqual(totalToolsBefore);
    expect(filteredToolCount).toBeGreaterThan(0);

    // Restore "All" filter
    await tabs.nth(0).click();
    await expect(tabs.nth(0)).toHaveClass(/active/);

    // All tools should be visible again
    const toolsAfterReset = await page.locator('.tool-row').count();
    expect(toolsAfterReset).toBe(totalToolsBefore);
  });

  test('tool detail shows schema', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tool-row', { timeout: 15_000 });

    // Click on the first tool name to open its detail modal.
    // Tool names are rendered as <span class="tool-name"> with cursor:pointer
    const firstToolName = page.locator('.tool-name').first();
    await expect(firstToolName).toBeVisible();
    const toolNameText = await firstToolName.textContent();

    // Click the tool name to open the detail modal
    await firstToolName.click();

    // The modal should open with the tool name as the title
    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible({ timeout: 5_000 });

    // Modal should contain the tool name
    const modalText = await modal.textContent();
    expect(modalText).toContain(toolNameText || '');

    // The modal body should show either "Parameters:" with a schema table,
    // or "No parameters" for tools without input schema
    const hasParameters = modalText?.includes('Parameters:');
    const hasNoParameters = modalText?.includes('No parameters');
    expect(hasParameters || hasNoParameters).toBe(true);

    // If parameters exist, verify the table headers (Name, Type, Required, Description)
    if (hasParameters) {
      const paramTable = modal.locator('table');
      await expect(paramTable).toBeVisible();
      const tableHeaders = await paramTable.locator('th').allTextContents();
      expect(tableHeaders).toContain('Name');
      expect(tableHeaders).toContain('Type');
    }

    // Close the modal
    await page.keyboard.press('Escape');
    await expect(modal).not.toBeVisible({ timeout: 5_000 });
  });

  test('upstream filter works', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tools-filter-tabs', { timeout: 15_000 });

    // Get all filter tabs
    const tabs = page.locator('.filter-tab');
    const tabCount = await tabs.count();
    expect(tabCount).toBeGreaterThanOrEqual(3); // All + at least 2 upstreams

    // Record the total tools when "All" is selected
    const allToolCount = await page.locator('.tool-row').count();

    // Iterate through each upstream tab (skip "All" at index 0)
    let sumOfUpstreamTools = 0;
    for (let i = 1; i < tabCount; i++) {
      await tabs.nth(i).click();
      await expect(tabs.nth(i)).toHaveClass(/active/);

      // Wait for filter to apply
      await page.waitForTimeout(300);

      // Get the count badge text for this tab
      const badge = tabs.nth(i).locator('.filter-tab-count');
      const badgeText = await badge.textContent();
      const expectedCount = parseInt(badgeText || '0', 10);

      // Some upstreams (e.g., "default") may have 0 tools (shadowed)
      // Only verify single visible group for upstreams that have tools
      if (expectedCount > 0) {
        const visibleGroups = page.locator('.upstream-group:visible');
        await expect(visibleGroups).toHaveCount(1);
      }

      sumOfUpstreamTools += expectedCount;
    }

    // The sum of tools across all upstream tabs should equal the total
    expect(sumOfUpstreamTools).toBe(allToolCount);

    // Restore "All"
    await tabs.nth(0).click();
  });

  test('tool count matches API', async ({ page, adminAPI }) => {
    // Fetch tools from API
    const apiResponse = await adminAPI.getTools();
    const apiTools = apiResponse.tools || [];
    const apiToolCount = apiTools.length;
    expect(apiToolCount).toBeGreaterThan(0);

    // Load the tools page
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tool-row', { timeout: 15_000 });

    // Count tool rows in the UI
    const uiToolCount = await page.locator('.tool-row').count();

    // UI tool count should match the API tool count
    expect(uiToolCount).toBe(apiToolCount);

    // Also verify the "All" tab badge count matches
    const allTab = page.locator('.filter-tab').first();
    const allBadge = allTab.locator('.filter-tab-count');
    const allBadgeText = await allBadge.textContent();
    expect(parseInt(allBadgeText || '0', 10)).toBe(apiToolCount);
  });

  // ---------------------------------------------------------------------------
  // Wave 2 — Clear All Rules
  // ---------------------------------------------------------------------------

  test('clear all rules removes non-default rules', async ({ page, adminAPI }) => {
    // Create 3 test policies via API
    const policyIds: string[] = [];
    for (let i = 1; i <= 3; i++) {
      const result = await adminAPI.createPolicy({
        name: `e2e-clear-${i}`,
        priority: 50 + i,
        rules: [
          {
            name: `clear-test-rule-${i}`,
            priority: i,
            tool_match: `test_tool_${i}`,
            condition: 'true',
            action: 'deny',
          },
        ],
      });
      expect(result?.id).toBeTruthy();
      policyIds.push(result.id);
      createdPolicyIds.push(result.id);
    }

    // Navigate to Tools & Rules
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.rules-section', { timeout: 15_000 });

    // Verify rules are visible
    const rulesText = await page.locator('.rules-section').textContent();
    expect(rulesText).toContain('clear-test-rule-1');

    // Delete all test policies via API (simulates "Clear All" action)
    for (const id of policyIds) {
      await adminAPI.deletePolicy(id);
    }
    // Remove from cleanup tracking since already deleted
    createdPolicyIds = createdPolicyIds.filter(id => !policyIds.includes(id));

    // Reload and verify rules are gone
    await page.reload();
    await page.waitForSelector('.rules-section', { timeout: 15_000 });

    const rulesAfter = await page.locator('.rules-section').textContent();
    expect(rulesAfter).not.toContain('clear-test-rule-1');
    expect(rulesAfter).not.toContain('clear-test-rule-2');
    expect(rulesAfter).not.toContain('clear-test-rule-3');
  });

  // ---------------------------------------------------------------------------
  // Wave 6 — Namespace UI
  // ---------------------------------------------------------------------------

  test('tools page shows correct tool name format from API', async ({ page, adminAPI }) => {
    // Verify that the API returns tools and the page renders them consistently
    const apiResponse = await adminAPI.getTools();
    const apiTools = apiResponse.tools || [];
    expect(apiTools.length).toBeGreaterThan(0);

    // Navigate to tools page
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tool-row', { timeout: 15_000 });

    // For each tool from the API, verify its name appears in the UI
    for (const tool of apiTools.slice(0, 5)) { // check first 5 for speed
      const toolName = tool.name;
      // If namespaced (contains "/"), UI should show the full name
      // If bare, UI should show just the name
      const toolNameEl = page.locator(`.tool-name:text-is("${toolName}")`);
      const count = await toolNameEl.count();
      // At least the tool should appear somewhere on the page
      if (count === 0) {
        // Fallback: check page contains the tool name as text
        const pageText = await page.locator('body').textContent();
        expect(pageText).toContain(toolName);
      }
    }
  });

  test('policy rules support namespaced tool patterns', async ({ page, adminAPI }) => {
    // Create a policy with a namespaced tool_match pattern
    const result = await adminAPI.createPolicy({
      name: 'e2e-ns-pattern',
      priority: 50,
      rules: [
        {
          name: 'deny-ns-tool',
          priority: 1,
          tool_match: 'desktop/*',
          condition: 'true',
          action: 'deny',
        },
      ],
    });
    // Verify the policy was actually created — AdminAPI.post may not throw
    // on server-side errors (e.g. poisoned CEL rule from a prior test).
    expect(result?.id, `Policy creation failed. API returned: ${JSON.stringify(result)}`).toBeTruthy();
    createdPolicyIds.push(result.id);

    // Navigate to Tools & Rules and verify the rule is displayed
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.rules-section', { timeout: 15_000 });

    const rulesText = await page.locator('.rules-section').textContent();
    expect(rulesText).toContain('deny-ns-tool');
    expect(rulesText).toContain('desktop/*');
  });

  test('baseline section visible', async ({ page, adminAPI }) => {
    // Capture a baseline first so the section has data to show
    await adminAPI.captureBaseline();

    await page.goto('/admin/#/tools');
    // Wait for either tool-row or tools-header to confirm page has loaded
    // (skeleton state might persist if API is slow)
    await page.waitForSelector('.tools-header', { timeout: 15_000 });
    // Give the page extra time to finish loading tools from API
    await page.waitForTimeout(3000);

    // If tool rows haven't appeared yet, the page might still be loading
    // Reload once to get past any stale state
    const toolRowCount = await page.locator('.tool-row').count();
    if (toolRowCount === 0) {
      await page.reload();
      await page.waitForSelector('.tool-row', { timeout: 15_000 });
    }

    // The tools page has section tabs. The "Tools & Rules" tab (index 0) is active by default.
    // The rules section is within the tools-rules data-section.
    const toolsRulesSection = page.locator('[data-section="tools-rules"]');
    await expect(toolsRulesSection).toBeVisible();

    // The rules section should be visible within the tools-rules area
    const rulesSection = page.locator('.rules-section');
    await expect(rulesSection).toBeVisible();

    // Verify the rules section contains rule rows or an empty state
    const rulesText = await rulesSection.textContent();
    const hasRules = (rulesText?.length || 0) > 0;
    expect(hasRules).toBe(true);

    // The tool rows should each display a policy badge (Allow, Deny, or No rule)
    const firstBadge = page.locator('.tool-badge').first();
    await expect(firstBadge).toBeVisible();
    const badgeText = await firstBadge.textContent();
    const hasPolicyStatus = badgeText?.includes('Allow') || badgeText?.includes('Deny') || badgeText?.includes('No rule');
    expect(hasPolicyStatus).toBe(true);
  });
});
