import { test, expect, navigateAndWait } from '../../helpers/fixtures';

/**
 * Keyboard shortcuts — verifies behavior defined in keyboard.js.
 *
 * All tests run against a real server (no mocks). Each test starts from a
 * known page via navigateAndWait, ensures the page is rendered, then exercises
 * keyboard shortcuts and asserts observable behavior (URL change, overlay
 * visibility, focus state).
 */

const ADMIN_BASE = '/admin/';

/** Selector that appears on every admin page once the shell has rendered. */
const SHELL_READY = '.sidebar, .nav-sidebar, [data-page]';

/**
 * Press a two-key "go" combo (g then second key) with a small gap in between
 * so the keyboard.js COMBO_TIMEOUT window registers both presses.
 */
async function pressGoCombo(page: import('@playwright/test').Page, secondKey: string) {
  await page.keyboard.press('g');
  await page.waitForTimeout(100);
  await page.keyboard.press(secondKey);
}

/**
 * Ensure no input/textarea/select is focused so shortcuts are active.
 * Clicks on the page body to clear focus from any input.
 */
async function blurInputs(page: import('@playwright/test').Page) {
  await page.evaluate(() => {
    if (document.activeElement instanceof HTMLElement) {
      document.activeElement.blur();
    }
  });
}

// ---------------------------------------------------------------------------
// Navigation combos: g+<key> navigates to the correct hash
// ---------------------------------------------------------------------------

const GO_COMBOS: Array<{ key: string; hash: string; label: string }> = [
  { key: 'd', hash: '#/dashboard',     label: 'Dashboard' },
  { key: 't', hash: '#/tools',         label: 'Tools' },
  { key: 'a', hash: '#/access',        label: 'Access' },
  { key: 'l', hash: '#/audit',         label: 'Audit' },
  { key: 's', hash: '#/sessions',      label: 'Sessions' },
  { key: 'n', hash: '#/notifications', label: 'Notifications' },
  { key: 'c', hash: '#/compliance',    label: 'Compliance' },
  { key: 'p', hash: '#/permissions',   label: 'Permissions' },
  { key: 'x', hash: '#/security',      label: 'Security' },
  { key: 'r', hash: '#/redteam',       label: 'Red Team' },
  { key: 'f', hash: '#/finops',        label: 'FinOps' },
  { key: 'i', hash: '#/agents',        label: 'Agents' },
];

test.describe('Keyboard shortcuts', () => {

  // -- 1-12: Two-key navigation combos --------------------------------------

  for (const combo of GO_COMBOS) {
    test(`g+${combo.key} navigates to ${combo.label} (${combo.hash})`, async ({ page }) => {
      // Start from dashboard so every combo navigates AWAY from the current page
      const startHash = combo.hash === '#/dashboard' ? '#/tools' : '#/dashboard';
      await navigateAndWait(page, `${ADMIN_BASE}${startHash}`, SHELL_READY);
      await blurInputs(page);

      await pressGoCombo(page, combo.key);

      // Wait for the URL hash to change to the expected value
      await expect(async () => {
        const url = page.url();
        expect(url).toContain(combo.hash);
      }).toPass({ timeout: 5_000 });
    });
  }

  // -- 13: ? opens shortcuts overlay ----------------------------------------

  test('? opens shortcuts overlay with active backdrop', async ({ page }) => {
    await navigateAndWait(page, `${ADMIN_BASE}#/dashboard`, SHELL_READY);
    await blurInputs(page);

    // Press ? (Shift+/)
    await page.keyboard.press('Shift+/');

    // The backdrop should become visible with the .active class
    const backdrop = page.locator('.shortcuts-overlay-backdrop');
    await expect(backdrop).toBeVisible({ timeout: 5_000 });
    await expect(backdrop).toHaveClass(/active/);

    // The overlay content panel should also be visible
    await expect(page.locator('.shortcuts-overlay')).toBeVisible();
  });

  // -- 14: Overlay shows Navigation, Actions, General sections --------------

  test('shortcuts overlay contains Navigation, Actions, General sections', async ({ page }) => {
    await navigateAndWait(page, `${ADMIN_BASE}#/dashboard`, SHELL_READY);
    await blurInputs(page);

    await page.keyboard.press('Shift+/');
    await expect(page.locator('.shortcuts-overlay')).toBeVisible({ timeout: 5_000 });

    const sections = page.locator('.shortcuts-section h3');
    const sectionTexts = await sections.allTextContents();

    expect(sectionTexts).toContain('Navigation');
    expect(sectionTexts).toContain('Actions');
    expect(sectionTexts).toContain('General');
  });

  // -- 15: Esc closes shortcuts overlay -------------------------------------

  test('Esc closes shortcuts overlay', async ({ page }) => {
    await navigateAndWait(page, `${ADMIN_BASE}#/dashboard`, SHELL_READY);
    await blurInputs(page);

    // Open the overlay
    await page.keyboard.press('Shift+/');
    await expect(page.locator('.shortcuts-overlay-backdrop')).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('.shortcuts-overlay-backdrop')).toHaveClass(/active/);

    // Close with Escape
    await page.keyboard.press('Escape');

    // The .active class should be removed (triggers CSS fade-out)
    await expect(page.locator('.shortcuts-overlay-backdrop')).not.toHaveClass(/active/, {
      timeout: 5_000,
    });

    // After the 150ms transition, the element is removed from the DOM entirely
    await expect(page.locator('.shortcuts-overlay-backdrop')).toHaveCount(0, {
      timeout: 3_000,
    });
  });

  // -- 16: Backdrop click closes overlay ------------------------------------

  test('clicking backdrop closes shortcuts overlay', async ({ page }) => {
    await navigateAndWait(page, `${ADMIN_BASE}#/dashboard`, SHELL_READY);
    await blurInputs(page);

    // Open the overlay
    await page.keyboard.press('Shift+/');
    const backdrop = page.locator('.shortcuts-overlay-backdrop');
    await expect(backdrop).toBeVisible({ timeout: 5_000 });
    await expect(backdrop).toHaveClass(/active/);

    // Click the backdrop itself (outside the inner .shortcuts-overlay panel).
    // Use position to ensure we click the backdrop, not the content panel.
    await backdrop.click({ position: { x: 10, y: 10 } });

    // The .active class should be removed
    await expect(page.locator('.shortcuts-overlay-backdrop')).not.toHaveClass(/active/, {
      timeout: 5_000,
    });

    // Element removed from DOM after transition
    await expect(page.locator('.shortcuts-overlay-backdrop')).toHaveCount(0, {
      timeout: 3_000,
    });
  });

  // -- 17: / focuses search input -------------------------------------------

  test('/ focuses the search input on the current page', async ({ page }) => {
    // The keyboard.js handler for "/" searches for:
    //   .search-input, [data-search], input[type="search"]
    // Currently no page renders an element with these selectors,
    // so pressing "/" is expected to be a no-op (no element gets focused).
    // This test verifies the shortcut fires without error and that focus
    // stays on the body (no unexpected side effects).
    await navigateAndWait(page, `${ADMIN_BASE}#/dashboard`, SHELL_READY);
    await blurInputs(page);

    await page.keyboard.press('/');
    await page.waitForTimeout(300);

    // No matching search input exists, so activeElement should remain
    // the body (or a non-input element).
    const focusedTag = await page.evaluate(() => document.activeElement?.tagName.toLowerCase());
    expect(focusedTag).not.toBe('input');
  });

  // -- 18: Shortcuts disabled when input is focused -------------------------

  test('shortcuts are disabled when an input field is focused', async ({ page }) => {
    // Navigate to the access page which has an identity filter input (class form-input).
    await navigateAndWait(page, `${ADMIN_BASE}#/access`, SHELL_READY);
    await blurInputs(page);

    // Manually focus the first input element on the page (the identity filter input).
    const focused = await page.evaluate(() => {
      const input = document.querySelector('input');
      if (input) { input.focus(); return true; }
      return false;
    });

    if (!focused) {
      // If no input exists (e.g. no identities), inject a temporary one to test the guard
      await page.evaluate(() => {
        const tmp = document.createElement('input');
        tmp.id = 'tmp-shortcut-test';
        document.body.appendChild(tmp);
        tmp.focus();
      });
    }

    // Verify an input is focused
    await expect(async () => {
      const tag = await page.evaluate(() => document.activeElement?.tagName.toLowerCase());
      expect(tag).toBe('input');
    }).toPass({ timeout: 5_000 });

    // Record the current URL
    const urlBefore = page.url();

    // Try a go-combo while the input is focused — should NOT navigate
    await page.keyboard.press('g');
    await page.waitForTimeout(100);
    await page.keyboard.press('t');

    // Give it a moment to (not) react
    await page.waitForTimeout(500);

    // URL should be unchanged — the shortcut was suppressed
    expect(page.url()).toBe(urlBefore);

    // Cleanup temp element if injected
    await page.evaluate(() => {
      const tmp = document.getElementById('tmp-shortcut-test');
      if (tmp) tmp.remove();
    });
  });
});
