import { test, expect, createMCPSession } from '../helpers/fixtures';
import * as crypto from 'crypto';

/**
 * Helper: find a tool that can be called without arguments.
 * Prefers list_allowed_directories > read_graph > first tool in list.
 * Some tools (e.g. create_directory) require arguments and will fail with
 * a non-JSON error if called with {}.
 */
function findSafeTool(tools: any[]): any {
  return (
    tools.find((t: any) => t.name === 'list_allowed_directories') ||
    tools.find((t: any) => t.name === 'read_graph') ||
    tools[0]
  );
}

/**
 * Helper: make admin API requests using double-submit CSRF pattern.
 * AdminAPI.getCSRFToken() is broken — it GETs /admin/ which does NOT go through
 * the CSRF middleware (only /admin/api/* does). The double-submit pattern works
 * because the Go CSRF middleware only checks that Cookie value == Header value,
 * without verifying the token was server-issued.
 */
async function csrfRequest(
  request: import('@playwright/test').APIRequestContext,
  method: 'PUT' | 'POST' | 'DELETE',
  apiPath: string,
  data?: any,
) {
  const csrfToken = crypto.randomBytes(32).toString('hex');
  const url = `/admin/api${apiPath}`;
  const opts: any = {
    headers: {
      'X-CSRF-Token': csrfToken,
      'Cookie': `sentinel_csrf_token=${csrfToken}`,
    },
  };
  if (data !== undefined) opts.data = data;

  if (method === 'PUT') return request.put(url, opts);
  if (method === 'POST') return request.post(url, opts);
  return request.delete(url, opts);
}

/** Convenience: set recording config with working CSRF. */
async function setRecordingConfig(
  request: import('@playwright/test').APIRequestContext,
  config: { enabled: boolean; record_payloads: boolean; retention_days: number },
) {
  const res = await csrfRequest(request, 'PUT', '/v1/recordings/config', {
    ...config,
    storage_dir: 'sg-recordings',
  });
  return res.status() < 400;
}

test.describe('Sessions', () => {
  // Enable recording before all tests and disable after
  test.beforeAll(async ({ request }) => {
    await setRecordingConfig(request, {
      enabled: true,
      record_payloads: true,
      retention_days: 30,
    });
  });

  test.afterAll(async ({ request }) => {
    await setRecordingConfig(request, {
      enabled: false,
      record_payloads: false,
      retention_days: 30,
    });
  });

  test('recording config panel shows toggles and fields', async ({ page }) => {
    await page.goto('/admin/#/sessions');
    await page.waitForSelector('#sessions-list-view');

    // Verify page header
    const heading = page.locator('.sessions-header h1');
    await expect(heading).toBeVisible();
    await expect(heading).toHaveText('Sessions');

    // Config panel should be present
    const configPanel = page.locator('#sessions-config-panel');
    await expect(configPanel).toBeVisible();

    // Expand the config panel by clicking the header
    const configHeader = page.locator('#sessions-config-panel-header');
    await configHeader.click();
    await expect(page.locator('#sessions-config-body')).toHaveClass(/open/);

    // Verify config toggles and fields
    await expect(page.locator('#cfg-enabled')).toBeVisible();
    await expect(page.locator('#cfg-record-payloads')).toBeVisible();
    await expect(page.locator('#cfg-retention')).toBeVisible();
    await expect(page.locator('#cfg-redact')).toBeVisible();

    // Verify labels
    await expect(page.locator('label[for="cfg-enabled"]')).toContainText('Enable recording');
    await expect(page.locator('label[for="cfg-record-payloads"]')).toContainText('Record request/response payloads');
    await expect(page.locator('label[for="cfg-retention"]')).toContainText('Retention Days');
  });

  test('config reflects enabled state set via API', async ({ page, request }) => {
    // Ensure recording is enabled via API (using CSRF helper, not adminAPI)
    await setRecordingConfig(request, {
      enabled: true,
      record_payloads: true,
      retention_days: 45,
    });

    await page.goto('/admin/#/sessions');
    await page.waitForSelector('#sessions-config-panel');

    // Expand config panel
    await page.locator('#sessions-config-panel-header').click();
    await expect(page.locator('#sessions-config-body')).toHaveClass(/open/);

    // Wait for config to load from API
    await expect(page.locator('#cfg-enabled')).toBeChecked({ timeout: 5_000 });
    await expect(page.locator('#cfg-record-payloads')).toBeChecked();
    await expect(page.locator('#cfg-retention')).toHaveValue('45');

    // Restore retention to 30
    await setRecordingConfig(request, {
      enabled: true,
      record_payloads: true,
      retention_days: 30,
    });
  });

  test('recording appears after MCP calls', async ({ page, request }) => {
    // Ensure recording is enabled (using CSRF helper)
    await setRecordingConfig(request, {
      enabled: true,
      record_payloads: true,
      retention_days: 30,
    });

    // Create a fresh MCP session and make some tool calls
    const client = await createMCPSession(request);
    const tools = await client.listTools();
    expect(tools.length).toBeGreaterThan(0);

    // Make 2–3 tool calls to generate recorded events
    const safeTool = findSafeTool(tools);
    await client.callTool(safeTool.name, {});
    // Make a second call with the same safe tool (avoid tools that need args)
    await client.callTool(safeTool.name, {});
    await client.callTool(safeTool.name, {});

    // End the session so the recording is finalized
    await client.deleteSession();

    // Navigate to sessions page and wait for the recording to appear
    await page.goto('/admin/#/sessions');
    await page.waitForSelector('#sessions-list-view');

    // Wait for recording rows to appear (the API may need a moment)
    await expect(page.locator('.recording-row').first()).toBeVisible({
      timeout: 15_000,
    });

    // Verify at least one recording is in the table
    const rowCount = await page.locator('.recording-row').count();
    expect(rowCount).toBeGreaterThanOrEqual(1);

    // The empty state should not be visible
    const emptyRow = page.locator('#recording-empty-row');
    await expect(emptyRow).not.toBeVisible();
  });

  test('click recording row shows detail view with timeline', async ({ page, request }) => {
    // Ensure we have at least one recording (using CSRF helper)
    await setRecordingConfig(request, {
      enabled: true,
      record_payloads: true,
      retention_days: 30,
    });

    const client = await createMCPSession(request);
    const tools = await client.listTools();
    await client.callTool(findSafeTool(tools).name, {});
    await client.deleteSession();

    // Poll API until the recording is available (server may need time to finalize)
    for (let attempt = 0; attempt < 15; attempt++) {
      const listRes = await request.get('/admin/api/v1/recordings');
      const recs = await listRes.json();
      if (Array.isArray(recs) && recs.length > 0) break;
      await page.waitForTimeout(500);
    }

    await page.goto('/admin/#/sessions');
    await page.waitForSelector('#sessions-list-view');

    // Wait for at least one recording row
    await expect(page.locator('.recording-row').first()).toBeVisible({
      timeout: 15_000,
    });

    // Click the first recording row to open the detail view
    await page.locator('.recording-row').first().click();

    // Verify detail view is rendered
    await expect(page.locator('#sessions-detail-view')).toBeVisible({ timeout: 10_000 });

    // Verify back button exists
    await expect(page.locator('.detail-back')).toBeVisible();

    // Verify the detail header loads (session ID and identity)
    await expect(page.locator('.detail-session-id')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('.detail-identity')).toBeVisible();

    // Verify meta grid shows expected labels
    const metaLabels = page.locator('.detail-meta-item label');
    await expect(metaLabels).toHaveCount(4);

    // Verify timeline container exists and has at least one event
    await expect(page.locator('#detail-timeline')).toBeVisible();
    await expect(page.locator('.timeline-event').first()).toBeVisible({ timeout: 10_000 });

    // Verify export buttons are present in detail view
    await expect(page.locator('.detail-export-btns')).toBeVisible();
    await expect(page.locator('.detail-export-btns button').first()).toBeVisible();
  });

  test('export JSON triggers download', async ({ page, request }) => {
    // Ensure at least one recording exists (using CSRF helper)
    await setRecordingConfig(request, {
      enabled: true,
      record_payloads: true,
      retention_days: 30,
    });

    const client = await createMCPSession(request);
    const tools = await client.listTools();
    await client.callTool(findSafeTool(tools).name, {});
    await client.deleteSession();

    await page.goto('/admin/#/sessions');
    await page.waitForSelector('#sessions-list-view');

    await expect(page.locator('.recording-row').first()).toBeVisible({
      timeout: 15_000,
    });

    // The list view has JSON export buttons in each row's actions cell
    // Set up download listener before clicking
    const downloadPromise = page.waitForEvent('download', { timeout: 10_000 });

    // Click the JSON export button on the first recording row
    const jsonBtn = page.locator('.recording-row').first().locator('.recording-actions-cell button', { hasText: 'JSON' });
    await expect(jsonBtn).toBeVisible();
    await jsonBtn.click();

    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.json');
  });

  test('delete recording via API removes it from list', async ({ page, request }) => {
    // Create our own recording so this test is self-contained —
    // relying on previous tests' recordings is fragile.
    await setRecordingConfig(request, {
      enabled: true,
      record_payloads: true,
      retention_days: 30,
    });

    const client = await createMCPSession(request);
    const tools = await client.listTools();
    await client.callTool(findSafeTool(tools).name, {});
    await client.deleteSession();

    // Poll API until the recording is available (server may need time to finalize)
    let recordings: any[] = [];
    for (let attempt = 0; attempt < 15; attempt++) {
      const listRes = await request.get('/admin/api/v1/recordings');
      recordings = await listRes.json();
      if (Array.isArray(recordings) && recordings.length > 0) break;
      await page.waitForTimeout(500);
    }
    expect(recordings.length).toBeGreaterThan(0);

    // Pick the newest recording as the delete target
    recordings.sort((a: any, b: any) =>
      new Date(b.started_at).getTime() - new Date(a.started_at).getTime()
    );
    const target = recordings[0];
    expect(target).toBeTruthy();

    // Delete it via API (using CSRF helper for DELETE)
    await csrfRequest(request, 'DELETE', `/v1/recordings/${target.session_id}`);

    // Navigate to sessions page and verify it's gone
    await page.goto('/admin/#/sessions');
    await page.waitForSelector('#sessions-list-view');

    // Wait for list to load
    await page.waitForTimeout(2_000);

    // Verify the deleted recording's session ID is no longer in the table.
    // The UI truncates session IDs to the first 8 characters (truncateId in sessions.js),
    // so we must compare against the truncated form — the full ID never appears in textContent.
    const pageText = await page.locator('#recording-table-wrap').textContent();
    expect(pageText).not.toContain(target.session_id.slice(0, 8));
  });

  // ---------------------------------------------------------------------------
  // Additional Session Tests
  // ---------------------------------------------------------------------------

  test('session table has correct columns', async ({ page, request }) => {
    // Ensure recording is enabled and we have at least one recording
    await setRecordingConfig(request, {
      enabled: true,
      record_payloads: true,
      retention_days: 30,
    });

    const client = await createMCPSession(request);
    const tools = await client.listTools();
    await client.callTool(findSafeTool(tools).name, {});
    await client.deleteSession();

    await page.goto('/admin/#/sessions');
    await page.waitForSelector('#sessions-list-view');

    // Wait for the recording table to render
    const table = page.locator('#recording-table');
    await expect(table).toBeVisible({ timeout: 10_000 });

    // Verify table header columns match the expected list:
    // ['Session ID', 'Identity', 'Started', 'Duration', 'Events', 'Denies', 'Actions']
    const headers = table.locator('thead th');
    const headerCount = await headers.count();
    expect(headerCount).toBe(7);

    const expectedColumns = ['Session ID', 'Identity', 'Started', 'Duration', 'Events', 'Denies', 'Actions'];
    for (let i = 0; i < expectedColumns.length; i++) {
      const headerText = await headers.nth(i).textContent();
      expect(headerText).toBe(expectedColumns[i]);
    }
  });

  test('session detail shows actions', async ({ page, request }) => {
    // Ensure we have a recording with events
    await setRecordingConfig(request, {
      enabled: true,
      record_payloads: true,
      retention_days: 30,
    });

    const client = await createMCPSession(request);
    const tools = await client.listTools();
    await client.callTool(findSafeTool(tools).name, {});
    await client.deleteSession();

    // Poll API until the recording is available (server may need time to finalize)
    for (let attempt = 0; attempt < 15; attempt++) {
      const listRes = await request.get('/admin/api/v1/recordings');
      const recs = await listRes.json();
      if (Array.isArray(recs) && recs.length > 0) break;
      await page.waitForTimeout(500);
    }

    await page.goto('/admin/#/sessions');
    await page.waitForSelector('#sessions-list-view');

    // The recording table may be below the active sessions section.
    // Scroll down to ensure the recording table is in view.
    await page.locator('#recording-table-wrap').scrollIntoViewIfNeeded().catch(() => {});

    // Wait for at least one recording row (may take time for API to return data)
    await expect(page.locator('.recording-row').first()).toBeVisible({
      timeout: 15_000,
    });

    // Click the first recording row to open detail view
    await page.locator('.recording-row').first().click();

    // Verify detail view is shown
    await expect(page.locator('#sessions-detail-view')).toBeVisible({ timeout: 10_000 });

    // Wait for detail header to render (API call to fetch recording metadata)
    await expect(page.locator('.detail-session-id')).toBeVisible({ timeout: 10_000 });

    // Detail view should show meta items with labels: Started, Duration, Total Events, Deny Events
    const metaItems = page.locator('.detail-meta-item');
    await expect(metaItems).toHaveCount(4);

    // Verify the meta labels contain expected text
    const metaText = await page.locator('.detail-meta-grid').textContent();
    expect(metaText).toContain('Started');
    expect(metaText).toContain('Duration');
    expect(metaText).toContain('Total Events');
    expect(metaText).toContain('Deny Events');

    // Export buttons should be present in the detail view
    const exportBtns = page.locator('.detail-export-btns button');
    const exportCount = await exportBtns.count();
    expect(exportCount).toBeGreaterThanOrEqual(1);

    // Back button should be present to return to list
    const backBtn = page.locator('.detail-back');
    await expect(backBtn).toBeVisible();
  });

  test('filter controls visible', async ({ page }) => {
    await page.goto('/admin/#/sessions');
    await page.waitForSelector('#sessions-list-view');

    // Verify the filter controls are present in the list view
    // Identity filter input
    const identityFilter = page.locator('#filter-identity');
    await expect(identityFilter).toBeVisible();

    // Date range filters: from and to
    const fromFilter = page.locator('#filter-from');
    await expect(fromFilter).toBeVisible();

    const toFilter = page.locator('#filter-to');
    await expect(toFilter).toBeVisible();

    // Has denies checkbox
    const deniesFilter = page.locator('#filter-has-denies');
    await expect(deniesFilter).toBeVisible();

    // Apply and Clear buttons in filter actions
    const applyBtn = page.locator('.recording-filter-actions button', { hasText: 'Apply' });
    await expect(applyBtn).toBeVisible();

    const clearBtn = page.locator('.recording-filter-actions button', { hasText: 'Clear' });
    await expect(clearBtn).toBeVisible();
  });

  test('recording toggle visible', async ({ page }) => {
    await page.goto('/admin/#/sessions');
    await page.waitForSelector('#sessions-list-view');

    // Config panel should be present
    const configPanel = page.locator('#sessions-config-panel');
    await expect(configPanel).toBeVisible();

    // Expand the config panel
    const configHeader = page.locator('#sessions-config-panel-header');
    await configHeader.click();
    await expect(page.locator('#sessions-config-body')).toHaveClass(/open/);

    // The recording enabled toggle (cfg-enabled) should be visible and functional
    const enabledToggle = page.locator('#cfg-enabled');
    await expect(enabledToggle).toBeVisible();

    // It should be checked because beforeAll enabled recording
    await expect(enabledToggle).toBeChecked();

    // The record payloads toggle should also be visible
    const payloadsToggle = page.locator('#cfg-record-payloads');
    await expect(payloadsToggle).toBeVisible();

    // Retention days input should be visible with a numeric value
    const retentionInput = page.locator('#cfg-retention');
    await expect(retentionInput).toBeVisible();
    const retentionValue = await retentionInput.inputValue();
    expect(Number(retentionValue)).toBeGreaterThan(0);

    // Redact toggle should be visible
    const redactToggle = page.locator('#cfg-redact');
    await expect(redactToggle).toBeVisible();
  });
});
