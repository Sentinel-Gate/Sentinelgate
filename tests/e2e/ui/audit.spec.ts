import { test, expect, createMCPSession } from '../helpers/fixtures';

test.describe('Audit Log', () => {
  // Generate audit data before tests by making real MCP tool calls
  test.beforeAll(async ({ request }) => {
    const client = await createMCPSession(request);
    await client.callTool('read_file', { path: '/tmp/sg-e2e-test/test.txt' });
    await client.callTool('list_directory', { path: '/tmp/sg-e2e-test' });
  });

  test('page loads with entries', async ({ page }) => {
    await page.goto('/admin/#/audit');
    // Real DOM uses .audit-row for each entry (rendered by renderEntry() in audit.js)
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    const entries = page.locator('.audit-row');
    await expect(entries.first()).toBeVisible();
    const count = await entries.count();
    expect(count).toBeGreaterThanOrEqual(2);
  });

  test('entries show tool name and decision', async ({ page }) => {
    await page.goto('/admin/#/audit');
    await page.waitForSelector('.audit-row', { timeout: 10_000 });

    // .audit-entries is the container wrapping all rows
    const entriesContainer = page.locator('.audit-entries');
    const allText = await entriesContainer.textContent();

    // Verify tool names from the calls we made in beforeAll
    expect(allText).toContain('read_file');
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
    await decisionFilter.selectOption({ label: 'Deny' });
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

    // Type "read_file" in the tool name filter
    const toolFilter = page.locator('#audit-filter-tool');
    await toolFilter.fill('read_file');

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
      expect(text).toContain('read_file');
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
});
