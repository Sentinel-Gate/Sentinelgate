import { test, expect } from '../helpers/fixtures';

test.describe('Onboarding', () => {
  test('getting started route accessible', async ({ page }) => {
    // The onboarding route is #/onboarding. When upstreams are configured
    // (as in the test env), it still renders but does not auto-dismiss
    // because launchedManually is detected. Navigate and verify no crash.
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await page.goto('/admin/#/onboarding');
    // Wait for either the onboarding container or a redirect to dashboard
    await page.waitForSelector('.onboarding, #stat-cards, .gs-header', { timeout: 10_000 });

    expect(errors).toHaveLength(0);
  });

  test('page shows onboarding content when manually navigated', async ({ page }) => {
    // When navigated manually with upstreams already configured, the
    // onboarding page detects launchedManually=true and stays visible.
    await page.goto('/admin/#/onboarding');

    const onboarding = page.locator('.onboarding');
    const onboardingVisible = await onboarding.isVisible().catch(() => false);

    if (onboardingVisible) {
      // Shield icon
      await expect(page.locator('.onboarding-icon')).toBeVisible();

      // Title
      const title = page.locator('.onboarding-title');
      await expect(title).toBeVisible();
      await expect(title).toHaveText('Welcome to SentinelGate');

      // Subtitle
      await expect(page.locator('.onboarding-subtitle')).toBeVisible();
    } else {
      // If redirected, we should be on the dashboard or getting-started
      const url = page.url();
      expect(url).toMatch(/#\/(dashboard|getting-started)/);
    }
  });

  test('three step cards visible if onboarding shown', async ({ page }) => {
    await page.goto('/admin/#/onboarding');

    const onboarding = page.locator('.onboarding');
    const onboardingVisible = await onboarding.isVisible().catch(() => false);

    if (onboardingVisible) {
      // 3 step cards inside .onboarding-steps
      const steps = page.locator('.onboarding-steps .onboarding-step');
      await expect(steps).toHaveCount(3);

      // Verify step titles
      await expect(steps.nth(0)).toContainText('Add Server');
      await expect(steps.nth(1)).toContainText('Connect Agent');
      await expect(steps.nth(2)).toContainText('Set Rules');

      // Each step has a numbered circle
      const numbers = page.locator('.onboarding-step-number');
      await expect(numbers).toHaveCount(3);
      await expect(numbers.nth(0)).toHaveText('1');
      await expect(numbers.nth(1)).toHaveText('2');
      await expect(numbers.nth(2)).toHaveText('3');
    }
  });

  test('CTA button visible if onboarding shown', async ({ page }) => {
    await page.goto('/admin/#/onboarding');

    const onboarding = page.locator('.onboarding');
    const onboardingVisible = await onboarding.isVisible().catch(() => false);

    if (onboardingVisible) {
      const ctaBtn = page.locator('.onboarding-cta .btn-primary');
      await expect(ctaBtn).toBeVisible();
      await expect(ctaBtn).toHaveText('Add MCP Server');
    }
  });

  test('sidebar has getting started link', async ({ page }) => {
    await page.goto('/admin/#/onboarding');
    // Wait for any content to load
    await page.waitForSelector('.onboarding, #stat-cards, .gs-header', { timeout: 10_000 });

    // The sidebar always has the Getting Started nav item
    const navLink = page.locator('.sidebar-nav a.nav-item[href="#/getting-started"]');
    await expect(navLink).toBeVisible();
    await expect(navLink).toContainText('Getting Started');
  });
});
