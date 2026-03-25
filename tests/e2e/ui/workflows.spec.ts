import { test, expect, AdminAPI, createMCPSession } from '../helpers/fixtures';

function findSafeTool(tools: any[]): any {
  return tools.find((t: any) => t.name === 'list_allowed_directories')
    || tools.find((t: any) => t.name === 'read_graph')
    || tools[0];
}

test.describe('Cross-Page Workflows', () => {
  // ---------------------------------------------------------------------------
  // Admin Dashboard Flow
  // ---------------------------------------------------------------------------

  test('admin can navigate through main pages', async ({ page }) => {
    // Dashboard loads
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards');

    // Navigate to Tools
    await page.goto('/admin/#/tools');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(2000);
    // Verify tools page loaded (heading or tool list)
    const toolsContent = await page.locator('#page-content').textContent();
    expect(toolsContent).toBeTruthy();

    // Navigate to Security
    await page.goto('/admin/#/security');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);

    // Navigate to Sessions
    await page.goto('/admin/#/sessions');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);

    // Navigate to Audit
    await page.goto('/admin/#/audit');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);
  });

  // ---------------------------------------------------------------------------
  // Identity / Access Flow
  // ---------------------------------------------------------------------------

  test('identity lifecycle: create, generate key, verify in sessions, delete', async ({ page, adminAPI }) => {
    // Create identity via API (simulating what the Access page does)
    const identity = await adminAPI.createIdentity({ name: 'e2e-workflow-identity', roles: ['user'] });
    // API may return the identity directly or wrapped -- handle both
    const identityId = identity?.id ?? (identity as any)?.identity_id;
    expect(identityId).toBeTruthy();

    try {
      // Generate an API key for the identity
      const key = await adminAPI.createKey(identityId, 'e2e-workflow-key');
      const keyId = key?.id ?? (key as any)?.key_id;
      expect(keyId).toBeTruthy();

      // Navigate to Access page and verify the identity appears
      await page.goto('/admin/#/access');
      await page.waitForSelector('.access-header');
      await page.waitForSelector('#identities-table-container table', { timeout: 10_000 });

      // Expand identities section if collapsed
      const collapseHeader = page.locator('.access-collapse-header');
      const collapseBody = page.locator('#identities-table-container');
      if (await collapseBody.evaluate(el => el.classList.contains('collapsed')).catch(() => true)) {
        await collapseHeader.click();
      }

      const identityRow = collapseBody.locator('tr', { hasText: 'e2e-workflow-identity' });
      await expect(identityRow).toBeVisible();

      // Verify key appears in keys table
      const keysTable = page.locator('#keys-table-container table');
      await expect(keysTable).toBeVisible({ timeout: 10_000 });
      const keyRow = keysTable.locator('tbody tr', { hasText: 'e2e-workflow-key' });
      await expect(keyRow).toBeVisible();

      // Navigate to Sessions page and verify it loads
      await page.goto('/admin/#/sessions');
      await page.waitForSelector('#sessions-list-view');
      const sessionsHeader = page.locator('.sessions-header h1');
      await expect(sessionsHeader).toBeVisible();

      // Revoke the key
      await adminAPI.revokeKey(keyId);

      // Verify revocation shows on Access page
      await page.goto('/admin/#/access');
      await page.waitForSelector('#keys-table-container table', { timeout: 10_000 });
      const revokedRow = page.locator('#keys-table-container table tbody tr', { hasText: 'e2e-workflow-key' });
      await expect(revokedRow).toBeVisible();
      const revokedBadge = revokedRow.locator('.badge-danger', { hasText: 'Revoked' });
      await expect(revokedBadge).toBeVisible();
    } finally {
      // Cleanup: delete identity (cascades keys)
      await adminAPI.deleteIdentity(identityId);
    }
  });

  // ---------------------------------------------------------------------------
  // Tool Call Flow
  // ---------------------------------------------------------------------------

  test('tool call appears in audit log', async ({ page, mcpClient }) => {
    // Make a tool call via MCP first so audit has data
    const tools = await mcpClient.listTools();
    expect(tools.length).toBeGreaterThan(0);

    const toolName = findSafeTool(tools).name;
    await mcpClient.callTool(toolName, {});

    // Navigate to Audit page and wait for SSE to deliver entries
    await page.goto('/admin/#/audit');
    await page.waitForLoadState('domcontentloaded');

    // The audit page renders skeleton rows first, then real .audit-row elements
    // arrive via SSE stream. Wait for the first real entry to appear.
    await expect(page.locator('.audit-row').first()).toBeVisible({ timeout: 15_000 });

    // Verify the tool call appears in audit entries
    const entriesContainer = page.locator('#audit-entries');
    const allText = await entriesContainer.textContent();
    expect(allText).toContain(toolName);

    // Verify the entry has a decision badge
    const decisions = page.locator('.audit-row-summary .badge');
    await expect(decisions.first()).toBeVisible();
  });

  // ---------------------------------------------------------------------------
  // Policy Lifecycle
  // ---------------------------------------------------------------------------

  test('policy lifecycle: create, verify on security page, verify on tools page, delete', async ({ page, adminAPI }) => {
    // Navigate to Security page
    await page.goto('/admin/#/security');
    await page.waitForLoadState('domcontentloaded');

    // Verify security page loaded (wait for async render)
    const securityHeader = page.locator('.security-header');
    await expect(securityHeader).toBeVisible({ timeout: 15_000 });

    // Create a policy via API -- the CEL condition 'true' is a valid boolean literal
    const policy = await adminAPI.createPolicy({
      name: 'e2e-workflow-policy',
      priority: 50,
      rules: [
        {
          name: 'workflow-deny-rule',
          priority: 1,
          tool_match: 'nonexistent_workflow_tool',
          condition: 'true',
          action: 'deny',
        },
      ],
    });
    const policyId = policy?.id ?? (policy as any)?.policy_id;
    expect(policyId).toBeTruthy();

    try {
      // Navigate to Tools page and verify the rule is visible.
      // The tools page renders .tools-header immediately but .rules-section
      // only appears after async data fetch (policies, tools, identities).
      await page.goto('/admin/#/tools');
      await page.waitForSelector('.tools-header', { timeout: 15_000 });

      // Wait for .rules-section to appear (rendered after async data loads).
      // Use Playwright's built-in retry rather than manual waitForTimeout + isVisible.
      try {
        await page.waitForSelector('.rules-section', { timeout: 10_000 });
      } catch {
        // Data may not have loaded; reload and retry.
        await page.reload();
        await page.waitForSelector('.rules-section', { timeout: 15_000 });
      }

      // Verify the rule name appears in the rules section
      await expect(page.locator('.rules-section')).toContainText('workflow-deny-rule', { timeout: 10_000 });

      // Navigate back to Dashboard
      await page.goto('/admin/#/dashboard');
      await page.waitForSelector('#stat-cards', { timeout: 15_000 });
    } finally {
      // Delete the policy
      await adminAPI.deletePolicy(policyId);

      // Verify rule is gone on Tools page
      await page.goto('/admin/#/tools');
      await page.waitForSelector('.tools-header', { timeout: 15_000 });

      try {
        await page.waitForSelector('.rules-section', { timeout: 10_000 });
      } catch {
        await page.reload();
        await page.waitForSelector('.rules-section', { timeout: 15_000 });
      }

      // Verify the deleted rule no longer appears
      await expect(page.locator('.rules-section')).not.toContainText('workflow-deny-rule', { timeout: 10_000 });
    }
  });

  // ---------------------------------------------------------------------------
  // Browser Navigation
  // ---------------------------------------------------------------------------

  test('browser back/forward and deep links work', async ({ page }) => {
    // Start on Dashboard
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards');

    // Navigate to Tools
    await page.goto('/admin/#/tools');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);

    // Navigate to Audit
    await page.goto('/admin/#/audit');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);

    // Go back to Tools
    await page.goBack();
    await page.waitForTimeout(1000);
    expect(page.url()).toContain('#/tools');

    // Go back to Dashboard
    await page.goBack();
    await page.waitForTimeout(1000);
    expect(page.url()).toContain('#/dashboard');

    // Go forward to Tools
    await page.goForward();
    await page.waitForTimeout(1000);
    expect(page.url()).toContain('#/tools');

    // Deep link: navigate directly to a specific page
    await page.goto('/admin/#/security');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1000);
    expect(page.url()).toContain('#/security');
    const securityHeader = page.locator('.security-header');
    await expect(securityHeader).toBeVisible();
  });
});
