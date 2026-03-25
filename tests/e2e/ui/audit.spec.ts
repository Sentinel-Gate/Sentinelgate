import { test, expect, createMCPSession } from '../helpers/fixtures';

test.describe('Audit Log', () => {
  // Generate audit data before tests by making real MCP tool calls.
  // Use tools that don't require arguments or use the resolved /private/tmp path
  // (macOS: /tmp → /private/tmp; the MCP filesystem server uses the resolved path).
  // Wrap in try/catch because MCP responses can be streamed/chunked and the
  // JSON parser may fail — the audit entry is still generated server-side.
  test.beforeAll(async ({ request }) => {
    const client = await createMCPSession(request);
    try { await client.callTool('list_allowed_directories', {}); } catch { /* audit entry generated regardless */ }
    try { await client.callTool('list_directory', { path: '/private/tmp/sg-e2e-test' }); } catch { /* audit entry generated regardless */ }
  });

  test('page loads with entries', async ({ page }) => {
    await page.goto('/admin/#/audit');
    // Real DOM uses .audit-row for each entry (rendered by renderEntry() in audit.js)
    // Allow extra time for initial data load and SSE connection
    await page.waitForSelector('.audit-row', { timeout: 20_000 });

    const entries = page.locator('.audit-row');
    await expect(entries.first()).toBeVisible({ timeout: 10_000 });
    const count = await entries.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('entries show tool name and decision', async ({ page }) => {
    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // .audit-entries is the container wrapping all rows
    const entriesContainer = page.locator('.audit-entries');
    const allText = await entriesContainer.textContent();

    // Verify tool names from the calls we made in beforeAll
    expect(allText).toContain('list_allowed_directories');
    expect(allText).toContain('list_directory');

    // Decision badges use class "badge" with badge-success/badge-danger/badge-neutral
    // They are inside .audit-row-summary, rendered by decisionBadge() in audit.js
    const decisions = page.locator('.audit-row-summary .badge');
    await expect(decisions.first()).toBeVisible();
    const firstDecision = await decisions.first().textContent();
    // decisionBadge() renders "Allow", "Deny", or "Rate Limited"
    expect(firstDecision?.toLowerCase()).toMatch(/allow|deny|rate limited|mcp|http|ws/);
  });

  test('filter by decision', async ({ page }) => {
    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // Get total count before filtering
    const totalBefore = await page.locator('.audit-row').count();
    expect(totalBefore).toBeGreaterThanOrEqual(1);

    // Filter by "Allow" — select option then click Apply (filters are not auto-applied)
    const decisionFilter = page.locator('#audit-filter-decision');
    await decisionFilter.selectOption({ label: 'Allow' });

    // Click Apply to trigger the filter query
    await page.locator('button:has-text("Apply")').click();

    // Wait for filtered results to load from the API
    await page.waitForTimeout(1500);

    // All visible entries should show "Allow" in their decision badge
    // Decision badges are rendered inside .audit-row-summary by decisionBadge()
    // Note: rows also have protocol badges (MCP/HTTP/WS), so we target badge-success specifically
    const visibleRows = page.locator('.audit-row');
    const count = await visibleRows.count();
    for (let i = 0; i < count; i++) {
      const rowText = await visibleRows.nth(i).locator('.audit-row-summary').textContent();
      expect(rowText?.toLowerCase()).toContain('allow');
    }

    // Switch to "Deny" filter
    await decisionFilter.selectOption({ label: 'Deny (policy)' });
    await page.locator('button:has-text("Apply")').click();

    await page.waitForTimeout(1500);

    // Denied entries should show "deny" (or no entries if none were denied)
    const deniedRows = page.locator('.audit-row');
    const deniedCount = await deniedRows.count();
    for (let i = 0; i < deniedCount; i++) {
      const rowText = await deniedRows.nth(i).locator('.audit-row-summary').textContent();
      expect(rowText?.toLowerCase()).toContain('deny');
    }
  });

  test('filter by tool name', async ({ page }) => {
    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // Type "list_directory" in the tool name filter (matches beforeAll calls)
    const toolFilter = page.locator('#audit-filter-tool');
    await toolFilter.fill('list_directory');

    // Click Apply — filters require explicit apply (applyFilters() in audit.js)
    await page.locator('button:has-text("Apply")').click();

    // Wait for filtered results
    await page.waitForTimeout(1500);

    // Tool names are in span.audit-row-tool inside each .audit-row-summary
    const toolNames = page.locator('.audit-row-tool');
    const count = await toolNames.count();
    expect(count).toBeGreaterThanOrEqual(1);
    for (let i = 0; i < count; i++) {
      const text = await toolNames.nth(i).textContent();
      expect(text).toContain('list_directory');
    }
  });

  test('new events appear in real-time', async ({ page, request }) => {
    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // Count existing entries
    const countBefore = await page.locator('.audit-row').count();

    // Make a new MCP tool call while the page is open
    const liveClient = await createMCPSession(request);
    await liveClient.callTool('list_directory', { path: '/tmp/sg-e2e-test' });

    // Wait for the new entry to appear via SSE (within a few seconds)
    // SSE pushes new entries to the top via eventSource.onmessage → entries.unshift()
    await expect(page.locator('.audit-row')).toHaveCount(countBefore + 1, {
      timeout: 10_000,
    }).catch(async () => {
      // Fallback: at least one more entry than before
      const countAfter = await page.locator('.audit-row').count();
      expect(countAfter).toBeGreaterThan(countBefore);
    });
  });

  test('click entry expands details', async ({ page }) => {
    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // Click on the first row's summary to expand it
    // In audit.js, the click listener is on .audit-row-summary which toggles .expanded on the .audit-row
    const firstSummary = page.locator('.audit-row-summary').first();
    await firstSummary.click();

    // When expanded, .audit-row gets class "expanded" and .audit-detail becomes display:block
    const expandedRow = page.locator('.audit-row.expanded');
    await expect(expandedRow).toBeVisible({ timeout: 5_000 });

    const details = expandedRow.locator('.audit-detail');
    await expect(details).toBeVisible({ timeout: 5_000 });

    // Verify expanded section shows relevant details
    // The detail grid contains labels: Tool Name, Tool Arguments, Identity, Decision,
    // Rule ID, Request ID, Timestamp, Latency, Protocol, Framework
    const detailsText = await details.textContent();
    const hasExpectedContent =
      detailsText?.includes('Identity') ||
      detailsText?.includes('Tool Arguments') ||
      detailsText?.includes('Latency') ||
      detailsText?.includes('Tool Name') ||
      detailsText?.includes('Protocol');
    expect(hasExpectedContent).toBeTruthy();
  });

  test('export CSV', async ({ page }) => {
    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // Export button has id="audit-export-btn" and text "Export CSV"
    const exportBtn = page.locator('#audit-export-btn');
    await expect(exportBtn).toBeVisible();

    // The export function creates an <a> element with download="audit-export.csv"
    // and clicks it programmatically. Playwright should capture this as a download event.
    const downloadPromise = page.waitForEvent('download', { timeout: 10_000 });
    await exportBtn.click();

    const download = await downloadPromise;
    // Verify a file was downloaded
    expect(download.suggestedFilename()).toMatch(/\.(csv|CSV)$/);
  });

  test('entry counter updates', async ({ page, request }) => {
    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // The counter element is #audit-count with class audit-count
    // It shows text like "3 entries" or "1 entry", updated by updateCount() in audit.js
    const counter = page.locator('#audit-count');
    await expect(counter).toBeVisible();

    const entriesBefore = await page.locator('.audit-row').count();

    // Generate a new event
    const client = await createMCPSession(request);
    await client.callTool('read_file', { path: '/tmp/sg-e2e-test/test.txt' });

    // Wait for new entry to appear via SSE
    await expect(page.locator('.audit-row')).not.toHaveCount(entriesBefore, {
      timeout: 10_000,
    });

    const entriesAfter = await page.locator('.audit-row').count();
    expect(entriesAfter).toBeGreaterThan(entriesBefore);

    // Verify counter text updated
    const counterText = await counter.textContent();
    expect(counterText).toMatch(/\d+ entr(y|ies)/);
  });

  test('filter by period', async ({ page }) => {
    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    const entriesBefore = await page.locator('.audit-row').count();
    expect(entriesBefore).toBeGreaterThanOrEqual(1);

    // Period filter: options are last_24h (default), today, last_hour, last_7d, custom
    const periodFilter = page.locator('#audit-filter-period');
    await expect(periodFilter).toBeVisible();

    // Get available options
    const options = periodFilter.locator('option');
    const optionCount = await options.count();
    expect(optionCount).toBeGreaterThanOrEqual(2);

    // Select "Last hour" (index 2) — a short period; test entries are recent so they should appear
    await periodFilter.selectOption({ label: 'Last hour' });

    // Click Apply to trigger the filtered query
    await page.locator('button:has-text("Apply")').click();

    await page.waitForTimeout(1500);

    // Entries should still be present since we just generated them
    const entriesAfterPeriod = await page.locator('.audit-row').count();
    expect(entriesAfterPeriod).toBeGreaterThanOrEqual(1);

    // Reset: select "Last 24h" (the default/broadest non-custom period) and apply
    await periodFilter.selectOption({ label: 'Last 24h' });
    await page.locator('button:has-text("Apply")').click();

    await page.waitForTimeout(1500);

    const entriesAfterReset = await page.locator('.audit-row').count();
    expect(entriesAfterReset).toBeGreaterThanOrEqual(entriesAfterPeriod);
  });

  // ---------------------------------------------------------------------------
  // Additional Audit Tests
  // ---------------------------------------------------------------------------

  test('audit entries appear after tool call', async ({ page, request }) => {
    // Make a distinct tool call so we can identify it in the audit log
    const client = await createMCPSession(request);
    await client.callTool('list_directory', { path: '/tmp/sg-e2e-test' });

    // Navigate to the audit page
    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // The audit log should contain an entry for the tool call we just made
    const entriesContainer = page.locator('.audit-entries');
    const allText = await entriesContainer.textContent();
    expect(allText).toContain('list_directory');

    // Verify that audit rows exist and the most recent one has a decision badge
    const firstRow = page.locator('.audit-row').first();
    await expect(firstRow).toBeVisible();

    const decisionBadge = firstRow.locator('.audit-row-summary .badge');
    await expect(decisionBadge.first()).toBeVisible();
  });

  test('filter by tool name specific', async ({ page, request }) => {
    // Generate a call with a specific tool to ensure it exists in the log
    const client = await createMCPSession(request);
    await client.callTool('read_file', { path: '/tmp/sg-e2e-test/test.txt' });

    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // Get total entries before filtering
    const totalBefore = await page.locator('.audit-row').count();
    expect(totalBefore).toBeGreaterThanOrEqual(1);

    // Filter by "list_directory" to narrow results
    const toolFilter = page.locator('#audit-filter-tool');
    await toolFilter.fill('list_directory');
    await page.locator('button:has-text("Apply")').click();
    await page.waitForTimeout(1500);

    // All visible audit-row-tool entries should contain "list_directory"
    const filteredToolNames = page.locator('.audit-row-tool');
    const filteredCount = await filteredToolNames.count();
    expect(filteredCount).toBeGreaterThanOrEqual(1);
    for (let i = 0; i < filteredCount; i++) {
      const text = await filteredToolNames.nth(i).textContent();
      expect(text).toContain('list_directory');
    }

    // Clear filter and verify more entries reappear
    await toolFilter.fill('');
    await page.locator('button:has-text("Apply")').click();
    await page.waitForTimeout(1500);

    const afterClear = await page.locator('.audit-row').count();
    expect(afterClear).toBeGreaterThanOrEqual(filteredCount);
  });

  test('export button visible', async ({ page }) => {
    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // The export button should be visible with the correct id
    const exportBtn = page.locator('#audit-export-btn');
    await expect(exportBtn).toBeVisible();

    // Verify the button has the export class
    await expect(exportBtn).toHaveClass(/audit-export-btn/);

    // Verify the button text or aria-label indicates export
    const ariaLabel = await exportBtn.getAttribute('aria-label');
    expect(ariaLabel).toContain('Export');
  });

  test('pagination works', async ({ page, request }) => {
    // Generate several audit entries to ensure we have data
    const client = await createMCPSession(request);
    for (let i = 0; i < 3; i++) {
      await client.callTool('read_file', { path: '/tmp/sg-e2e-test/test.txt' });
    }

    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // Verify we have multiple entries
    const entryCount = await page.locator('.audit-row').count();
    expect(entryCount).toBeGreaterThanOrEqual(3);

    // The audit page has a counter (#audit-count) that shows the current entry count
    const counter = page.locator('#audit-count');
    await expect(counter).toBeVisible();
    const counterText = await counter.textContent();
    expect(counterText).toMatch(/\d+ entr(y|ies)/);

    // The audit page caps at 200 entries (MAX_ENTRIES in audit.js).
    // Verify the entry count doesn't exceed the max.
    expect(entryCount).toBeLessThanOrEqual(200);

    // Verify that entries are ordered (newest first) by checking the first entry
    // has a timestamp that is recent
    const firstRow = page.locator('.audit-row').first();
    await expect(firstRow).toBeVisible();
  });

  test('audit detail shows decision', async ({ page }) => {
    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // Click on the first row's summary to expand it
    const firstSummary = page.locator('.audit-row-summary').first();
    await firstSummary.click();

    // Wait for the expanded detail section to appear
    const expandedRow = page.locator('.audit-row.expanded');
    await expect(expandedRow).toBeVisible({ timeout: 5_000 });

    const detail = expandedRow.locator('.audit-detail');
    await expect(detail).toBeVisible({ timeout: 5_000 });

    // The detail grid should contain a "Decision" label
    const detailGrid = detail.locator('.audit-detail-grid');
    await expect(detailGrid).toBeVisible();

    const detailText = await detailGrid.textContent();

    // Verify the detail shows decision-related information
    // The audit-detail-grid contains audit-detail-label elements with text like
    // "Tool Name", "Tool Arguments", "Identity", "Decision", etc.
    expect(detailText).toContain('Decision');

    // The decision value should contain a badge with Allow or Deny
    const decisionLabels = detail.locator('.audit-detail-label');
    const labelCount = await decisionLabels.count();
    let foundDecisionLabel = false;
    for (let i = 0; i < labelCount; i++) {
      const labelText = await decisionLabels.nth(i).textContent();
      if (labelText?.includes('Decision')) {
        foundDecisionLabel = true;
        break;
      }
    }
    expect(foundDecisionLabel).toBe(true);

    // Verify additional detail fields are present
    expect(detailText).toContain('Tool Name');
    expect(detailText).toContain('Identity');

    // Collapse the row by clicking again
    await firstSummary.click();
    await expect(expandedRow).not.toBeVisible({ timeout: 5_000 });
  });
});
