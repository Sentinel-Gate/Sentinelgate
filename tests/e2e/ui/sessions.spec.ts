import { test, expect, createMCPSession } from '../helpers/fixtures';
import * as crypto from 'crypto';

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
    await client.callTool(tools[0].name, {});
    if (tools.length > 1) {
      await client.callTool(tools[1].name, {});
    }
    await client.callTool(tools[0].name, {});

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
    await client.callTool(tools[0].name, {});
    await client.deleteSession();

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
    await client.callTool(tools[0].name, {});
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
    // Use an existing recording from previous tests (tests 49-51 create recordings).
    // This test verifies DELETE behavior, not recording creation.
    const listRes = await request.get('/admin/api/v1/recordings');
    const recordings: any[] = await listRes.json();
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

    // Verify the deleted recording's session ID is no longer in the table
    const pageText = await page.locator('#recording-table-wrap').textContent();
    expect(pageText).not.toContain(target.session_id);
  });
});
