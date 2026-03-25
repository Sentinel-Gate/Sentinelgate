import { test, expect, navigateAndWait } from '../../helpers/fixtures';

test.describe('Modal System', () => {
  // Track identity IDs for cleanup
  let createdIdentityIds: string[] = [];

  test.afterEach(async ({ adminAPI }) => {
    // Clean up identities created during tests
    for (const id of createdIdentityIds) {
      try { await adminAPI.deleteIdentity(id); } catch { /* already deleted */ }
    }
    createdIdentityIds = [];
  });

  // ---------------------------------------------------------------------------
  // Helper: open the "Add Identity" modal from the access page
  // ---------------------------------------------------------------------------

  async function openAddIdentityModal(page: import('@playwright/test').Page) {
    await navigateAndWait(page, '/admin/#/access', '.access-header');
    // Wait for the identity section to render
    await page.waitForSelector('[data-action="add-identity"]', { timeout: 10_000 });
    await page.locator('[data-action="add-identity"]').click();
    // Wait for the modal to be visible and animated in
    await page.waitForSelector('.modal-backdrop.active', { timeout: 5_000 });
  }

  // ---------------------------------------------------------------------------
  // Helper: expand identities section if collapsed
  // ---------------------------------------------------------------------------

  async function expandIdentities(page: import('@playwright/test').Page) {
    const collapseBody = page.locator('#identities-table-container');
    const isCollapsed = await collapseBody.evaluate(
      el => el.classList.contains('collapsed'),
    ).catch(() => true);
    if (isCollapsed) {
      await page.locator('.access-collapse-header').click();
      await page.waitForTimeout(500);
    }
  }

  // ---------------------------------------------------------------------------
  // 1. Modal opens with correct structure
  // ---------------------------------------------------------------------------

  test('modal opens with correct structure when triggered via Add Identity button', async ({ page }) => {
    await openAddIdentityModal(page);

    // Verify structural elements exist
    const backdrop = page.locator('.modal-backdrop');
    await expect(backdrop).toBeVisible();
    await expect(backdrop).toHaveClass(/active/);

    const modal = page.locator('.modal');
    await expect(modal).toBeVisible();

    const header = modal.locator('.modal-header');
    await expect(header).toBeVisible();

    const title = modal.locator('.modal-title');
    await expect(title).toBeVisible();

    const closeBtn = modal.locator('.modal-close');
    await expect(closeBtn).toBeVisible();

    const body = modal.locator('.modal-body');
    await expect(body).toBeVisible();

    const footer = modal.locator('.modal-footer');
    await expect(footer).toBeVisible();
  });

  // ---------------------------------------------------------------------------
  // 2. Modal title is set correctly
  // ---------------------------------------------------------------------------

  test('modal title matches the triggering action', async ({ page }) => {
    await openAddIdentityModal(page);

    const title = page.locator('.modal-title');
    await expect(title).toHaveText('Add Identity');
  });

  // ---------------------------------------------------------------------------
  // 3. Esc closes modal
  // ---------------------------------------------------------------------------

  test('pressing Escape key closes the modal', async ({ page }) => {
    await openAddIdentityModal(page);

    // Confirm modal is open
    await expect(page.locator('.modal-backdrop.active')).toBeVisible();

    // Press Escape
    await page.keyboard.press('Escape');

    // Modal backdrop should lose .active class and then be removed from DOM
    await expect(page.locator('.modal-backdrop.active')).not.toBeVisible({ timeout: 5_000 });

    // After animation (200ms), the backdrop should be removed from the DOM
    await page.waitForTimeout(300);
    await expect(page.locator('.modal-backdrop')).toHaveCount(0);
  });

  // ---------------------------------------------------------------------------
  // 4. Backdrop click closes modal
  // ---------------------------------------------------------------------------

  test('clicking the backdrop (outside modal) closes the modal', async ({ page }) => {
    await openAddIdentityModal(page);

    // Click on the backdrop itself (top-left corner, outside the centered modal)
    const backdrop = page.locator('.modal-backdrop');
    await backdrop.click({ position: { x: 5, y: 5 } });

    // Modal should close
    await expect(page.locator('.modal-backdrop.active')).not.toBeVisible({ timeout: 5_000 });
    await page.waitForTimeout(300);
    await expect(page.locator('.modal-backdrop')).toHaveCount(0);
  });

  // ---------------------------------------------------------------------------
  // 5. X button closes modal
  // ---------------------------------------------------------------------------

  test('clicking the X close button closes the modal', async ({ page }) => {
    await openAddIdentityModal(page);

    // Click the X button
    const closeBtn = page.locator('.modal-close');
    await expect(closeBtn).toHaveAttribute('aria-label', 'Close dialog');
    await closeBtn.click();

    // Modal should close
    await expect(page.locator('.modal-backdrop.active')).not.toBeVisible({ timeout: 5_000 });
    await page.waitForTimeout(300);
    await expect(page.locator('.modal-backdrop')).toHaveCount(0);
  });

  // ---------------------------------------------------------------------------
  // 6. Body scroll locked when modal open
  // ---------------------------------------------------------------------------

  test('body scroll is locked (overflow: hidden) when modal is open', async ({ page }) => {
    await openAddIdentityModal(page);

    // Check that document.body has overflow: hidden
    const overflow = await page.evaluate(() => document.body.style.overflow);
    expect(overflow).toBe('hidden');
  });

  // ---------------------------------------------------------------------------
  // 7. Body scroll restored after close
  // ---------------------------------------------------------------------------

  test('body scroll is restored after modal closes', async ({ page }) => {
    await openAddIdentityModal(page);

    // Verify locked
    const overflowWhileOpen = await page.evaluate(() => document.body.style.overflow);
    expect(overflowWhileOpen).toBe('hidden');

    // Close modal via Escape
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);

    // Verify restored (should be empty string, which means default/scroll)
    const overflowAfterClose = await page.evaluate(() => document.body.style.overflow);
    expect(overflowAfterClose).toBe('');
  });

  // ---------------------------------------------------------------------------
  // 8. Cancel button closes without side effect
  // ---------------------------------------------------------------------------

  test('Cancel button closes modal without creating a resource', async ({ page, adminAPI }) => {
    // Get identity count before
    const identitiesBefore = await adminAPI.getIdentities();
    const countBefore = identitiesBefore.length;

    await openAddIdentityModal(page);

    // Fill in the name field to simulate partial input
    const nameInput = page.locator('.modal .modal-body input.form-input');
    await nameInput.fill('should-not-be-created');

    // Click Cancel
    const cancelBtn = page.locator('.modal .modal-footer .btn-secondary');
    await expect(cancelBtn).toHaveText('Cancel');
    await cancelBtn.click();

    // Modal should close
    await expect(page.locator('.modal-backdrop.active')).not.toBeVisible({ timeout: 5_000 });

    // No identity should have been created
    const identitiesAfter = await adminAPI.getIdentities();
    expect(identitiesAfter.length).toBe(countBefore);
  });

  // ---------------------------------------------------------------------------
  // 9. Confirmation dialog: delete triggers confirm modal
  // ---------------------------------------------------------------------------

  test('delete action triggers confirmation modal with Cancel and Delete buttons', async ({ page, adminAPI }) => {
    // Create an identity to delete
    const identity = await adminAPI.createIdentity({ name: 'e2e-modal-confirm-test', roles: ['user'] });
    createdIdentityIds.push(identity.id);

    // Navigate to access page and wait for identity table
    await navigateAndWait(page, '/admin/#/access', '.access-header');
    await page.waitForSelector('#identities-table-container table', { timeout: 15_000 });

    // Expand identities section if collapsed
    await expandIdentities(page);

    // Find the row for our test identity and click its Delete button
    const row = page.locator('#identities-table-container tbody tr', { hasText: 'e2e-modal-confirm-test' });
    await expect(row).toBeVisible({ timeout: 10_000 });
    const deleteBtn = row.locator('.btn-danger', { hasText: 'Delete' });
    await deleteBtn.click();

    // A confirmation modal should open
    await page.waitForSelector('.modal-backdrop.active', { timeout: 5_000 });
    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();

    // Title should mention deleting the identity
    const titleText = await modal.locator('.modal-title').textContent();
    expect(titleText).toContain('Delete');
    expect(titleText).toContain('e2e-modal-confirm-test');

    // Footer should have Cancel and Delete buttons
    const cancelBtn = modal.locator('.modal-footer .btn-secondary');
    await expect(cancelBtn).toHaveText('Cancel');

    const confirmBtn = modal.locator('.modal-footer .btn-danger');
    await expect(confirmBtn).toHaveText('Delete');

    // Close without confirming (click Cancel)
    await cancelBtn.click();
    await expect(page.locator('.modal-backdrop.active')).not.toBeVisible({ timeout: 5_000 });
  });

  // ---------------------------------------------------------------------------
  // 10. Confirm button executes action (delete identity)
  // ---------------------------------------------------------------------------

  test('confirm button executes the delete action and removes identity', async ({ page, adminAPI }) => {
    // Create an identity to delete
    const identity = await adminAPI.createIdentity({ name: 'e2e-modal-delete-exec', roles: ['user'] });
    // Do NOT push to cleanup array since we expect it to be deleted

    // Navigate and wait for identity table
    await navigateAndWait(page, '/admin/#/access', '.access-header');
    await page.waitForSelector('#identities-table-container table', { timeout: 15_000 });

    // Expand identities section
    await expandIdentities(page);

    // Find the identity row and click Delete
    const row = page.locator('#identities-table-container tbody tr', { hasText: 'e2e-modal-delete-exec' });
    await expect(row).toBeVisible({ timeout: 10_000 });
    await row.locator('.btn-danger', { hasText: 'Delete' }).click();

    // Wait for confirmation modal
    await page.waitForSelector('.modal-backdrop.active', { timeout: 5_000 });

    // Click the danger confirm button ("Delete")
    const confirmBtn = page.locator('[role="dialog"] .modal-footer .btn-danger');
    await expect(confirmBtn).toHaveText('Delete');
    await confirmBtn.click();

    // Modal should close
    await expect(page.locator('.modal-backdrop.active')).not.toBeVisible({ timeout: 5_000 });

    // Wait for the delete to propagate
    await page.waitForTimeout(1500);

    // Verify identity was actually deleted via API
    const identities = await adminAPI.getIdentities();
    const found = identities.find((i: any) => i.id === identity.id);
    expect(found).toBeFalsy();
  });

  // ---------------------------------------------------------------------------
  // 11. Modal content is accessible (role, aria-modal)
  // ---------------------------------------------------------------------------

  test('modal has correct ARIA attributes for accessibility', async ({ page }) => {
    await openAddIdentityModal(page);

    const modal = page.locator('.modal');
    await expect(modal).toHaveAttribute('role', 'dialog');
    await expect(modal).toHaveAttribute('aria-modal', 'true');
    await expect(modal).toHaveAttribute('tabindex', '-1');

    // Close button should have aria-label
    const closeBtn = modal.locator('.modal-close');
    await expect(closeBtn).toHaveAttribute('aria-label', 'Close dialog');
  });

  // ---------------------------------------------------------------------------
  // 12. Focus trapped in modal (tab cycles through modal elements)
  // ---------------------------------------------------------------------------

  test('tab key cycles focus within the modal (focus trap behavior)', async ({ page }) => {
    await openAddIdentityModal(page);

    // The Add Identity modal has a setTimeout(nameInput.focus, 100ms) that
    // fires asynchronously. Wait for focus to settle on the name input so
    // the Tab sequence isn't disrupted by a late refocus.
    const nameInput = page.locator('.modal .modal-body input.form-input');
    await expect(nameInput).toBeFocused({ timeout: 3_000 });

    // Collect all visible focusable elements inside the modal
    const focusableSelector =
      'button:not([disabled]), [href], input:not([disabled]), ' +
      'select:not([disabled]), textarea:not([disabled]), ' +
      '[tabindex]:not([tabindex="-1"])';

    const focusInfo = await page.evaluate((sel) => {
      const modal = document.querySelector('.modal');
      if (!modal) return { count: 0, activeIndex: -1 };
      const els = Array.from(modal.querySelectorAll(sel))
        .filter(el => (el as HTMLElement).offsetParent !== null);
      const activeIndex = els.indexOf(document.activeElement as HTMLElement);
      return { count: els.length, activeIndex };
    }, focusableSelector);
    expect(focusInfo.count).toBeGreaterThan(0);
    expect(focusInfo.activeIndex).toBeGreaterThanOrEqual(0);

    // Calculate how many Tabs are needed to reach the last focusable element
    // from the currently focused element.
    const tabsToEnd = focusInfo.count - 1 - focusInfo.activeIndex;

    // Tab through remaining focusable elements — each Tab must stay inside
    for (let i = 0; i < tabsToEnd; i++) {
      await page.keyboard.press('Tab');
      const focusInside = await page.evaluate(() => {
        const modal = document.querySelector('.modal');
        if (!modal) return false;
        return modal.contains(document.activeElement);
      });
      expect(focusInside).toBe(true);
    }

    // Verify we are now on the last focusable element
    const isOnLast = await page.evaluate((sel) => {
      const modal = document.querySelector('.modal');
      if (!modal) return false;
      const els = Array.from(modal.querySelectorAll(sel))
        .filter(el => (el as HTMLElement).offsetParent !== null);
      return els.length > 0 && document.activeElement === els[els.length - 1];
    }, focusableSelector);
    expect(isOnLast).toBe(true);

    // --- Focus trap wrap-around test ---
    // One more Tab past the last focusable element should wrap back to the
    // first focusable element IF a focus trap is implemented.
    await page.keyboard.press('Tab');

    const wrapResult = await page.evaluate((sel) => {
      const modal = document.querySelector('.modal');
      if (!modal) return { inside: false, isFirst: false };
      const inside = modal.contains(document.activeElement);
      const els = Array.from(modal.querySelectorAll(sel))
        .filter(el => (el as HTMLElement).offsetParent !== null);
      const isFirst = els.length > 0 && document.activeElement === els[0];
      return { inside, isFirst };
    }, focusableSelector);

    // Focus trap is implemented in modal.js — verify it works
    expect(wrapResult.inside).toBe(true);
    expect(wrapResult.isFirst).toBe(true);
  });
});
