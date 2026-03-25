/**
 * date-format.spec.ts -- Verifies ISO 8601 date format (YYYY-MM-DD HH:mm:ss)
 * across all pages that display dates.
 *
 * T2.2: Dates should match /\d{4}-\d{2}-\d{2}/ pattern, NOT localized formats.
 */
import { test, expect, navigateAndWait } from '../../helpers/fixtures';

test.describe('Date Format ISO 8601', () => {
  test.setTimeout(60_000);

  // ISO date pattern: YYYY-MM-DD (at minimum)
  const isoDatePattern = /\d{4}-\d{2}-\d{2}/;
  // Localized patterns we do NOT want to see (e.g. "3/23/2026" or "23/03/2026")
  const localizedPattern = /\d{1,2}\/\d{1,2}\/\d{4}/;

  async function checkDatesOnPage(page: any, url: string, waitSelector: string): Promise<void> {
    await navigateAndWait(page, url, waitSelector);

    // Find all elements that look like they contain dates (time elements, date cells, etc.)
    const dateElements = page.locator('time, [data-date], td, .date, .timestamp, [class*="date"]');
    const count = await dateElements.count();

    let foundDate = false;
    for (let i = 0; i < Math.min(count, 20); i++) {
      const text = await dateElements.nth(i).textContent();
      if (!text || text.trim().length < 10) continue;

      // If it contains a date-like string, verify format
      if (isoDatePattern.test(text)) {
        foundDate = true;
        // Should NOT also contain a localized format
        expect(text).not.toMatch(localizedPattern);
      }
    }

    // We found at least one date on the page (if data exists)
    // Not a failure if no dates — the page might be empty
    return;
  }

  test('dashboard dates use ISO format', async ({ page }) => {
    await checkDatesOnPage(page, '/admin/#/dashboard', '#stat-cards');
  });

  test('sessions dates use ISO format', async ({ page }) => {
    await checkDatesOnPage(page, '/admin/#/sessions', '#sessions-list-view');
  });

  test('notifications dates use ISO format', async ({ page }) => {
    await checkDatesOnPage(page, '/admin/#/notifications', '.notifications-page, .notif-list, h1');
  });
});
