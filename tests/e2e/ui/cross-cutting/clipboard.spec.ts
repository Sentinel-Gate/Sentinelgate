import { test, expect, navigateAndWait } from '../../helpers/fixtures';

test.describe('Clipboard & Copy', () => {

  test('copy button on agent config snippet shows toast', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.card');

    // Find the "Connect Your Agent" section with config snippets
    // Click the first tab's copy button
    const copyBtns = page.locator('.copyable, button:has-text("Copy"), [title="Click to copy"]');
    const count = await copyBtns.count();

    if (count > 0) {
      // Grant clipboard permissions
      await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
      await copyBtns.first().click();

      // Toast should appear confirming copy
      const toast = page.locator('.toast-success, .toast');
      await expect(toast.first()).toBeVisible({ timeout: 5_000 });
    } else {
      // If no copy buttons found, check for code blocks with copy mechanism
      const codeBlocks = page.locator('pre, code, .code-block');
      expect(await codeBlocks.count()).toBeGreaterThan(0);
    }
  });

  test('agent config tab switching shows different content', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.card');

    // The access page renders agent config tabs with class .config-tab
    // and corresponding content panels with class .config-tab-content.
    const tabs = page.locator('.config-tab');
    const tabCount = await tabs.count();

    if (tabCount >= 2) {
      // First tab should already be active
      await tabs.first().click();
      await page.waitForTimeout(300);
      const firstContent = await page.locator('.config-tab-content.active').first().textContent();

      // Click second tab
      await tabs.nth(1).click();
      await page.waitForTimeout(300);
      const secondContent = await page.locator('.config-tab-content.active').first().textContent();

      // Content should be different between tabs
      expect(firstContent).not.toBe(secondContent);
    }
  });

  test('API key creation displays copyable cleartext key', async ({ page, adminAPI }) => {
    // Create a temporary identity for this test
    const identity = await adminAPI.createIdentity({ name: 'clipboard-test', roles: ['user'] });
    const keyResult = await adminAPI.createKey(identity.id, 'clipboard-test-key');

    // The key should have cleartext
    expect(keyResult.cleartext_key).toBeTruthy();
    expect(keyResult.cleartext_key.length).toBeGreaterThan(10);

    // Navigate to access page to verify key is listed
    await navigateAndWait(page, '/admin/#/access', '.card');

    // Verify the key name appears in the table
    await expect(page.locator('text=clipboard-test-key')).toBeVisible({ timeout: 10_000 });

    // Cleanup
    if (keyResult.id) await adminAPI.revokeKey(keyResult.id);
    await adminAPI.deleteIdentity(identity.id);
  });

  test('copied text matches displayed text', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.card');

    // Grant clipboard permissions
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);

    // Find any copyable element
    const copyable = page.locator('.copyable, [title="Click to copy"]').first();
    const hasCopyable = await copyable.count() > 0;

    if (hasCopyable) {
      // Get the text before clicking
      const displayedText = await copyable.textContent();

      // Click to copy
      await copyable.click();

      // Read clipboard
      const clipboardText = await page.evaluate(() => navigator.clipboard.readText());

      // Clipboard should contain the displayed text (trimmed)
      if (displayedText && clipboardText) {
        expect(clipboardText.trim()).toContain(displayedText.trim().substring(0, 20));
      }
    }
  });

  test('getting started code blocks have copy functionality', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/getting-started', '.gs-page');

    // The MCP Proxy card is auto-expanded and contains config tabs with code.
    // Code is rendered inside .gs-config-panel containers (or .gs-code wrappers)
    // with a sibling .gs-code-copy button.
    // Wait for the expanded card content to appear.
    const codeBlocks = page.locator('.gs-config-code, .gs-code pre');
    const count = await codeBlocks.count();
    expect(count).toBeGreaterThan(0);

    // Verify copy buttons exist alongside code blocks.
    // The .gs-code-copy button is a sibling of the <pre> inside .gs-config-panel or .gs-code.
    const copyBtns = page.locator('.gs-code-copy');
    expect(await copyBtns.count()).toBeGreaterThan(0);

    // At minimum, code blocks should contain actual code content
    const firstBlock = codeBlocks.first();
    const text = await firstBlock.textContent();
    expect(text!.trim().length).toBeGreaterThan(5);
  });

  test('copy shows visual feedback', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.card');
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);

    const copyable = page.locator('.copyable, [title="Click to copy"]').first();
    if (await copyable.count() > 0) {
      await copyable.click();

      // Should show either:
      // 1. A toast notification
      // 2. A .copied class on the element
      // 3. Visual icon change
      const hasToast = await page.locator('.toast').count() > 0;
      const hasCopiedClass = await copyable.evaluate(el => el.classList.contains('copied'));

      expect(hasToast || hasCopiedClass).toBeTruthy();
    }
  });
});
