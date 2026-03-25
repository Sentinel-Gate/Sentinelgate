import { test, expect, navigateAndWait } from '../../helpers/fixtures';

test.describe('Toast System', () => {
  // Track identity IDs for cleanup
  let createdIdentityIds: string[] = [];

  test.afterEach(async ({ adminAPI, page }) => {
    // Clean up identities created during tests
    for (const id of createdIdentityIds) {
      try { await adminAPI.deleteIdentity(id); } catch { /* already deleted */ }
    }
    createdIdentityIds = [];

    // Clear any lingering toasts so they don't leak into the next test
    await page.evaluate(() => {
      const container = document.getElementById('toast-container');
      if (container) container.innerHTML = '';
    }).catch(() => { /* page might have navigated away */ });
  });

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
  // 1. Success toast appears after real action
  // ---------------------------------------------------------------------------

  test('success toast appears after creating an identity via UI', async ({ page, adminAPI }) => {
    // Pre-cleanup: delete any leftover identity from a prior failed run.
    // getIdentities() may return a non-array (error object) on server errors,
    // so guard with Array.isArray before calling .find().
    try {
      const existingIdentities = await adminAPI.getIdentities();
      if (Array.isArray(existingIdentities)) {
        const leftover = existingIdentities.find((i: any) => i.name === 'e2e-toast-success-test');
        if (leftover) {
          await adminAPI.deleteIdentity(leftover.id);
        }
      }
    } catch { /* pre-cleanup is best-effort */ }

    await navigateAndWait(page, '/admin/#/access', '.access-header');
    // Wait for identities table to render — this ensures API data loaded
    // and the CSRF cookie is set in the browser context.
    await page.waitForSelector('#identities-table-container table', { timeout: 15_000 });
    await page.waitForSelector('[data-action="add-identity"]', { timeout: 10_000 });

    // Open Add Identity modal
    await page.locator('[data-action="add-identity"]').click();
    await page.waitForSelector('.modal-backdrop.active', { timeout: 5_000 });

    const modal = page.locator('[role="dialog"]');

    // Fill in identity name — wait for input to be ready
    const nameInput = modal.locator('input.form-input');
    await expect(nameInput).toBeVisible({ timeout: 5_000 });
    await nameInput.fill('e2e-toast-success-test');

    // Submit by clicking the primary button
    const submitBtn = modal.locator('.modal-footer .btn-primary');
    await expect(submitBtn).toBeEnabled({ timeout: 5_000 });
    await submitBtn.click();

    // Wait for the success toast to appear
    const successToast = page.locator('.toast-success.toast-visible');
    await expect(successToast).toBeVisible({ timeout: 10_000 });

    // Verify the toast message mentions the action
    const message = successToast.locator('.toast-message');
    const messageText = await message.textContent();
    expect(messageText).toBeTruthy();
    expect(messageText!.toLowerCase()).toContain('identity');

    // Track for cleanup: fetch identity ID from API.
    // Guard with Array.isArray since the API may return an error object.
    try {
      const identities = await adminAPI.getIdentities();
      if (Array.isArray(identities)) {
        const created = identities.find((i: any) => i.name === 'e2e-toast-success-test');
        if (created) createdIdentityIds.push(created.id);
      }
    } catch { /* cleanup tracking is best-effort */ }
  });

  // ---------------------------------------------------------------------------
  // 2. Error toast appears on failure
  // ---------------------------------------------------------------------------

  test('error toast appears when submitting invalid data', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.access-header');
    await page.waitForSelector('[data-action="add-identity"]', { timeout: 10_000 });

    // Open Add Identity modal
    await page.locator('[data-action="add-identity"]').click();
    await page.waitForSelector('.modal-backdrop.active', { timeout: 5_000 });

    const modal = page.locator('[role="dialog"]');

    // Fill name with a name that already exists (the e2e-tester identity)
    // by first creating it via the UI, then trying to create a duplicate
    const nameInput = modal.locator('input.form-input');
    await nameInput.fill('e2e-tester');

    // Submit
    const submitBtn = modal.locator('.modal-footer .btn-primary');
    await submitBtn.click();

    // Wait for an error toast (duplicate identity should fail)
    const errorToast = page.locator('.toast-error.toast-visible');
    await expect(errorToast).toBeVisible({ timeout: 10_000 });

    // Verify it has an error message
    const message = errorToast.locator('.toast-message');
    const messageText = await message.textContent();
    expect(messageText).toBeTruthy();
    expect(messageText!.length).toBeGreaterThan(0);
  });

  // ---------------------------------------------------------------------------
  // 3. Toast message text matches action
  // ---------------------------------------------------------------------------

  test('toast message text reflects the completed action', async ({ page, adminAPI }) => {
    // Pre-cleanup: delete any leftover identity from a prior failed run.
    // createIdentity() will fail with 409 if the name already exists.
    try {
      const existing = await adminAPI.getIdentities();
      if (Array.isArray(existing)) {
        const leftover = existing.find((i: any) => i.name === 'e2e-toast-msg-test');
        if (leftover) {
          await adminAPI.deleteIdentity(leftover.id);
        }
      }
    } catch { /* pre-cleanup is best-effort */ }

    // Create an identity via API, then delete it via UI to get a known toast message
    const identity = await adminAPI.createIdentity({ name: 'e2e-toast-msg-test', roles: ['user'] });
    // Always track for cleanup — if the UI delete step fails, afterEach will clean up
    if (identity?.id) createdIdentityIds.push(identity.id);

    await navigateAndWait(page, '/admin/#/access', '.access-header');
    await page.waitForSelector('#identities-table-container table', { timeout: 15_000 });
    await expandIdentities(page);

    // Find the identity row and click Delete
    const row = page.locator('#identities-table-container tbody tr', { hasText: 'e2e-toast-msg-test' });
    await expect(row).toBeVisible({ timeout: 10_000 });
    // Ensure the delete button is visible and actionable before clicking
    const deleteBtn = row.locator('.btn-danger', { hasText: 'Delete' });
    await expect(deleteBtn).toBeVisible({ timeout: 5_000 });
    await deleteBtn.click();

    // Confirm the deletion in the modal — wait for confirm button to be ready
    await page.waitForSelector('.modal-backdrop.active', { timeout: 5_000 });
    const confirmBtn = page.locator('[role="dialog"] .modal-footer .btn-danger');
    await expect(confirmBtn).toBeVisible({ timeout: 5_000 });
    await confirmBtn.click();

    // Wait for the success toast
    const toast = page.locator('.toast-success.toast-visible');
    await expect(toast).toBeVisible({ timeout: 10_000 });

    // Message should mention "deleted" or "Identity deleted"
    const messageText = await toast.locator('.toast-message').textContent();
    expect(messageText!.toLowerCase()).toContain('deleted');
  });

  // ---------------------------------------------------------------------------
  // 4. Toast has close button
  // ---------------------------------------------------------------------------

  test('toast has a close button with correct aria-label', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.access-header');

    // Trigger a toast via page.evaluate
    await page.evaluate(() => (window as any).SG.toast.success('Close button test'));

    const toast = page.locator('.toast-success.toast-visible');
    await expect(toast).toBeVisible({ timeout: 5_000 });

    // Verify close button exists
    const closeBtn = toast.locator('.toast-close');
    await expect(closeBtn).toBeVisible();
    await expect(closeBtn).toHaveAttribute('aria-label', 'Close notification');
  });

  // ---------------------------------------------------------------------------
  // 5. Manual close dismisses toast
  // ---------------------------------------------------------------------------

  test('clicking close button dismisses the toast', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.access-header');

    // Clear any pre-existing toasts before testing
    await page.evaluate(() => {
      const container = document.getElementById('toast-container');
      if (container) container.innerHTML = '';
    });

    // Trigger a toast
    await page.evaluate(() => (window as any).SG.toast.success('Dismiss me'));

    // Wait for the toast to appear with its visible class
    const visibleToast = page.locator('.toast-success.toast-visible');
    await expect(visibleToast).toBeVisible({ timeout: 5_000 });

    // Click the close button on the visible toast
    const closeBtn = visibleToast.locator('.toast-close');
    await closeBtn.click();

    // Use Playwright's auto-retry assertion to wait for the toast to be removed
    // from DOM. _dismiss() removes toast-visible immediately, then removes the
    // element after ANIMATION_MS (300ms). toHaveCount retries automatically,
    // which is more reliable than a manual waitForTimeout + snapshot count.
    await expect(page.locator('#toast-container .toast')).toHaveCount(0, { timeout: 5_000 });
  });

  // ---------------------------------------------------------------------------
  // 6. Toast auto-dismisses after ~4 seconds
  // ---------------------------------------------------------------------------

  test('toast auto-dismisses after approximately 4 seconds', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.access-header');

    // Trigger a toast
    await page.evaluate(() => (window as any).SG.toast.info('Auto-dismiss test'));

    const toast = page.locator('.toast.toast-visible').first();
    await expect(toast).toBeVisible({ timeout: 5_000 });

    // Wait for auto-dismiss (4000ms) + animation (300ms) + buffer
    await page.waitForTimeout(5_000);

    // Toast should no longer be visible
    const visibleToasts = await page.locator('#toast-container .toast-visible').count();
    expect(visibleToasts).toBe(0);
  });

  // ---------------------------------------------------------------------------
  // 7. Max 3 toasts visible at once
  // ---------------------------------------------------------------------------

  test('maximum 3 toasts are visible simultaneously', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.access-header');

    // Rapidly trigger 5 toasts
    await page.evaluate(() => {
      (window as any).SG.toast.success('Toast 1');
      (window as any).SG.toast.info('Toast 2');
      (window as any).SG.toast.warning('Toast 3');
      (window as any).SG.toast.error('Toast 4');
      (window as any).SG.toast.success('Toast 5');
    });

    // Give time for DOM insertion and rAF animation
    await page.waitForTimeout(200);

    // Count total toast elements in the container (MAX_VISIBLE enforced on insert)
    const totalToasts = await page.locator('#toast-container .toast').count();
    expect(totalToasts).toBeLessThanOrEqual(3);
  });

  // ---------------------------------------------------------------------------
  // 8. Toast has progress bar
  // ---------------------------------------------------------------------------

  test('toast has a progress bar for auto-dismiss timing', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.access-header');

    // Trigger a toast
    await page.evaluate(() => (window as any).SG.toast.success('Progress bar test'));

    const toast = page.locator('.toast.toast-visible').first();
    await expect(toast).toBeVisible({ timeout: 5_000 });

    // Verify the progress bar element exists inside the toast
    const progressBar = toast.locator('.toast-progress');
    await expect(progressBar).toBeVisible();

    // The progress bar should have an animationDuration matching AUTO_DISMISS_MS
    const animDuration = await progressBar.evaluate(
      el => getComputedStyle(el).animationDuration,
    );
    // Should be '4s' or '4000ms'
    expect(animDuration).toMatch(/4(s|000ms)/);
  });

  // ---------------------------------------------------------------------------
  // 9. Warning toast renders correctly
  // ---------------------------------------------------------------------------

  test('warning toast renders with correct class and structure', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.access-header');

    await page.evaluate(() => (window as any).SG.toast.warning('Warning test message'));

    const toast = page.locator('.toast-warning.toast-visible');
    await expect(toast).toBeVisible({ timeout: 5_000 });

    // Verify structural elements
    const icon = toast.locator('.toast-icon');
    await expect(icon).toBeVisible();

    const message = toast.locator('.toast-message');
    await expect(message).toHaveText('Warning test message');

    const closeBtn = toast.locator('.toast-close');
    await expect(closeBtn).toBeVisible();

    const progress = toast.locator('.toast-progress');
    await expect(progress).toBeVisible();
  });

  // ---------------------------------------------------------------------------
  // 10. Info toast renders correctly
  // ---------------------------------------------------------------------------

  test('info toast renders with correct class and structure', async ({ page }) => {
    await navigateAndWait(page, '/admin/#/access', '.access-header');

    await page.evaluate(() => (window as any).SG.toast.info('Info test message'));

    const toast = page.locator('.toast-info.toast-visible');
    await expect(toast).toBeVisible({ timeout: 5_000 });

    // Verify structural elements
    const icon = toast.locator('.toast-icon');
    await expect(icon).toBeVisible();

    const message = toast.locator('.toast-message');
    await expect(message).toHaveText('Info test message');

    const closeBtn = toast.locator('.toast-close');
    await expect(closeBtn).toBeVisible();

    const progress = toast.locator('.toast-progress');
    await expect(progress).toBeVisible();
  });
});
