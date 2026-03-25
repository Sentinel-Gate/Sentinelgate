import { test, expect, navigateAndWait } from '../../helpers/fixtures';

/**
 * Responsive Design Tests for SentinelGate layout.
 *
 * Three breakpoints verified:
 *   Desktop  (>1024px)  — full sidebar 220px, text labels visible
 *   Tablet   (769-1024) — icon-only sidebar 64px, labels hidden
 *   Mobile   (<768px)   — bottom tab bar, only 4 items
 *
 * CSS source of truth: layout.html <style> block + variables.css
 */

const DESKTOP = { width: 1440, height: 900 };
const TABLET = { width: 900, height: 768 };
const MOBILE = { width: 375, height: 812 };
const SMALL_PHONE = { width: 480, height: 812 };

const DASHBOARD_URL = '/admin/#/dashboard';
const SIDEBAR_SELECTOR = '.sidebar';

test.describe('Responsive Design', () => {
  // ─── Desktop (1440x900) ────────────────────────────────────────────

  test.describe('Desktop (1440x900)', () => {
    test('sidebar has ~220px width', async ({ page }) => {
      await page.setViewportSize(DESKTOP);
      await navigateAndWait(page, DASHBOARD_URL, SIDEBAR_SELECTOR);

      const width = await page.locator('.sidebar').evaluate(
        (el) => parseFloat(getComputedStyle(el).width),
      );
      // --sidebar-width is 220px; allow small rounding tolerance
      expect(width).toBeGreaterThanOrEqual(218);
      expect(width).toBeLessThanOrEqual(222);
    });

    test('sidebar nav items show text labels', async ({ page }) => {
      await page.setViewportSize(DESKTOP);
      await navigateAndWait(page, DASHBOARD_URL, SIDEBAR_SELECTOR);

      const navItems = page.locator('.sidebar-nav .nav-item');
      const count = await navItems.count();
      expect(count).toBeGreaterThan(0);

      // Every nav item must have visible text (fontSize > 0, non-empty trimmed text)
      for (let i = 0; i < count; i++) {
        const item = navItems.nth(i);
        const fontSize = await item.evaluate(
          (el) => getComputedStyle(el).fontSize,
        );
        expect(parseFloat(fontSize)).toBeGreaterThan(0);

        const text = await item.evaluate((el) => el.textContent?.trim() ?? '');
        expect(text.length).toBeGreaterThan(0);
      }
    });

    test('sidebar footer shows version text', async ({ page }) => {
      await page.setViewportSize(DESKTOP);
      await navigateAndWait(page, DASHBOARD_URL, '.sidebar-footer');

      const versionEl = page.locator('.sidebar-version');
      await expect(versionEl).toBeVisible();

      const display = await versionEl.evaluate(
        (el) => getComputedStyle(el).display,
      );
      expect(display).not.toBe('none');

      const text = await versionEl.textContent();
      expect(text?.trim().length).toBeGreaterThan(0);
    });

    test('sidebar footer shows upstream count', async ({ page }) => {
      await page.setViewportSize(DESKTOP);
      await navigateAndWait(page, DASHBOARD_URL, '.sidebar-footer');

      const countEl = page.locator('.sidebar-upstream-count');
      await expect(countEl).toBeVisible();

      const display = await countEl.evaluate(
        (el) => getComputedStyle(el).display,
      );
      expect(display).not.toBe('none');

      const text = await countEl.textContent();
      expect(text?.trim()).toContain('servers');
    });
  });

  // ─── Tablet (900x768) ─────────────────────────────────────────────

  test.describe('Tablet (900x768)', () => {
    test('sidebar shrinks to ~64px width', async ({ page }) => {
      await page.setViewportSize(TABLET);
      await navigateAndWait(page, DASHBOARD_URL, SIDEBAR_SELECTOR);

      const width = await page.locator('.sidebar').evaluate(
        (el) => parseFloat(getComputedStyle(el).width),
      );
      expect(width).toBeGreaterThanOrEqual(62);
      expect(width).toBeLessThanOrEqual(66);
    });

    test('nav item text labels are hidden via font-size 0', async ({ page }) => {
      await page.setViewportSize(TABLET);
      await navigateAndWait(page, DASHBOARD_URL, SIDEBAR_SELECTOR);

      const navItems = page.locator('.sidebar-nav .nav-item');
      const count = await navItems.count();
      expect(count).toBeGreaterThan(0);

      // CSS sets font-size: 0 on .nav-item at this breakpoint
      for (let i = 0; i < count; i++) {
        const fontSize = await navItems.nth(i).evaluate(
          (el) => getComputedStyle(el).fontSize,
        );
        expect(parseFloat(fontSize)).toBe(0);
      }
    });

    test('nav item SVG icons remain visible', async ({ page }) => {
      await page.setViewportSize(TABLET);
      await navigateAndWait(page, DASHBOARD_URL, SIDEBAR_SELECTOR);

      const icons = page.locator('.sidebar-nav .nav-item svg');
      const count = await icons.count();
      expect(count).toBeGreaterThan(0);

      for (let i = 0; i < count; i++) {
        const box = await icons.nth(i).boundingBox();
        expect(box).not.toBeNull();
        // Icons must have positive rendered dimensions
        expect(box!.width).toBeGreaterThan(0);
        expect(box!.height).toBeGreaterThan(0);
      }
    });

    test('version and upstream count are hidden', async ({ page }) => {
      await page.setViewportSize(TABLET);
      await navigateAndWait(page, DASHBOARD_URL, SIDEBAR_SELECTOR);

      const versionDisplay = await page.locator('.sidebar-version').evaluate(
        (el) => getComputedStyle(el).display,
      );
      expect(versionDisplay).toBe('none');

      const countDisplay = await page.locator('.sidebar-upstream-count').evaluate(
        (el) => getComputedStyle(el).display,
      );
      expect(countDisplay).toBe('none');
    });
  });

  // ─── Mobile (375x812) ─────────────────────────────────────────────

  test.describe('Mobile (375x812)', () => {
    test('sidebar repositions to bottom of viewport', async ({ page }) => {
      await page.setViewportSize(MOBILE);
      await navigateAndWait(page, DASHBOARD_URL, SIDEBAR_SELECTOR);

      const styles = await page.locator('.sidebar').evaluate((el) => {
        const cs = getComputedStyle(el);
        return {
          position: cs.position,
          bottom: cs.bottom,
          left: cs.left,
          right: cs.right,
          width: cs.width,
        };
      });

      expect(styles.position).toBe('fixed');
      expect(parseFloat(styles.bottom)).toBe(0);
      expect(parseFloat(styles.left)).toBe(0);
      // Width should span the full viewport
      expect(parseFloat(styles.width)).toBeGreaterThanOrEqual(MOBILE.width - 2);
    });

    test('sidebar is horizontal (flex-direction: row)', async ({ page }) => {
      await page.setViewportSize(MOBILE);
      await navigateAndWait(page, DASHBOARD_URL, SIDEBAR_SELECTOR);

      const flexDir = await page.locator('.sidebar').evaluate(
        (el) => getComputedStyle(el).flexDirection,
      );
      expect(flexDir).toBe('row');
    });

    test('only 4 nav items are displayed', async ({ page }) => {
      await page.setViewportSize(MOBILE);
      await navigateAndWait(page, DASHBOARD_URL, SIDEBAR_SELECTOR);

      const allItems = page.locator('.sidebar-nav .nav-item');
      const totalCount = await allItems.count();
      expect(totalCount).toBeGreaterThan(4);

      // Count actually visible items (display != none)
      let visibleCount = 0;
      for (let i = 0; i < totalCount; i++) {
        const display = await allItems.nth(i).evaluate(
          (el) => getComputedStyle(el).display,
        );
        if (display !== 'none') {
          visibleCount++;
        }
      }
      expect(visibleCount).toBe(4);

      // Verify the correct 4 items are shown
      const expectedPages = ['dashboard', 'tools', 'notifications', 'access'];
      for (const pageName of expectedPages) {
        const itemDisplay = await page
          .locator(`.nav-item[data-page="${pageName}"]`)
          .evaluate((el) => getComputedStyle(el).display);
        expect(itemDisplay).not.toBe('none');
      }
    });

    test('logo is hidden', async ({ page }) => {
      await page.setViewportSize(MOBILE);
      await navigateAndWait(page, DASHBOARD_URL, SIDEBAR_SELECTOR);

      const logoDisplay = await page.locator('.sidebar-logo').evaluate(
        (el) => getComputedStyle(el).display,
      );
      expect(logoDisplay).toBe('none');
    });

    test('touch targets meet 44px minimum height', async ({ page }) => {
      await page.setViewportSize(MOBILE);
      await navigateAndWait(page, DASHBOARD_URL, SIDEBAR_SELECTOR);

      // Check each visible nav item meets the 44px touch target
      const expectedPages = ['dashboard', 'tools', 'notifications', 'access'];
      for (const pageName of expectedPages) {
        const item = page.locator(`.nav-item[data-page="${pageName}"]`);
        const minHeight = await item.evaluate(
          (el) => parseFloat(getComputedStyle(el).minHeight),
        );
        expect(minHeight).toBeGreaterThanOrEqual(44);

        // Verify the rendered box is actually >= 44px tall
        const box = await item.boundingBox();
        expect(box).not.toBeNull();
        expect(box!.height).toBeGreaterThanOrEqual(44);
      }
    });
  });

  // ─── Stat Cards Breakpoint (480px) ────────────────────────────────

  test.describe('Stat Cards Grid', () => {
    test('single column at 480px, multi-column at 1440px', async ({ page }) => {
      // Start at small phone size
      await page.setViewportSize(SMALL_PHONE);
      await navigateAndWait(page, DASHBOARD_URL, '#stat-cards');

      // At 480px the grid must be single-column (grid-template-columns: 1fr)
      const smallColumns = await page.locator('.stat-cards-grid').evaluate(
        (el) => getComputedStyle(el).gridTemplateColumns,
      );
      // Single column: the computed value should be one track value
      const smallTrackCount = smallColumns.split(/\s+/).length;
      expect(smallTrackCount).toBe(1);

      // Resize to desktop
      await page.setViewportSize(DESKTOP);
      // Wait for layout reflow
      await page.waitForTimeout(300);

      const largeColumns = await page.locator('.stat-cards-grid').evaluate(
        (el) => getComputedStyle(el).gridTemplateColumns,
      );
      // Multi-column: more than one track value
      const largeTrackCount = largeColumns.split(/\s+/).length;
      expect(largeTrackCount).toBeGreaterThan(1);
    });
  });

  // ─── Resize Recovery ──────────────────────────────────────────────

  test.describe('Viewport Resize Recovery', () => {
    test('resizing from mobile back to desktop restores full sidebar', async ({ page }) => {
      // Start at desktop
      await page.setViewportSize(DESKTOP);
      await navigateAndWait(page, DASHBOARD_URL, SIDEBAR_SELECTOR);

      // Verify initial desktop state
      const desktopWidth = await page.locator('.sidebar').evaluate(
        (el) => parseFloat(getComputedStyle(el).width),
      );
      expect(desktopWidth).toBeGreaterThanOrEqual(218);

      // Shrink to mobile
      await page.setViewportSize(MOBILE);
      await page.waitForTimeout(300);

      const mobileFlexDir = await page.locator('.sidebar').evaluate(
        (el) => getComputedStyle(el).flexDirection,
      );
      expect(mobileFlexDir).toBe('row');

      // Return to desktop
      await page.setViewportSize(DESKTOP);
      await page.waitForTimeout(300);

      const restoredStyles = await page.locator('.sidebar').evaluate((el) => {
        const cs = getComputedStyle(el);
        return {
          width: parseFloat(cs.width),
          flexDirection: cs.flexDirection,
          position: cs.position,
        };
      });

      // Sidebar must return to full 220px column layout
      expect(restoredStyles.width).toBeGreaterThanOrEqual(218);
      expect(restoredStyles.width).toBeLessThanOrEqual(222);
      expect(restoredStyles.flexDirection).toBe('column');
      expect(restoredStyles.position).not.toBe('fixed');

      // Text labels must be visible again
      const firstNavFontSize = await page
        .locator('.sidebar-nav .nav-item')
        .first()
        .evaluate((el) => parseFloat(getComputedStyle(el).fontSize));
      expect(firstNavFontSize).toBeGreaterThan(0);

      // Version text must be visible again
      const versionDisplay = await page.locator('.sidebar-version').evaluate(
        (el) => getComputedStyle(el).display,
      );
      expect(versionDisplay).not.toBe('none');
    });
  });
});
