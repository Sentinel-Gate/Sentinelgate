import { test, expect } from '../helpers/fixtures';

test.describe('Getting Started', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/admin/#/getting-started');
    await page.waitForSelector('.gs-header');
  });

  test('page loads with header', async ({ page }) => {
    const heading = page.locator('.gs-header h1');
    await expect(heading).toBeVisible();
    await expect(heading).toHaveText('Getting Started');
  });

  test('MCP Proxy card is auto-expanded', async ({ page }) => {
    const card = page.locator('[data-uc="mcp-proxy"]');
    await expect(card).toBeVisible();
    await expect(card).toHaveClass(/expanded/);
    await expect(card.locator('.gs-step').first()).toBeVisible();
  });

  test('start-here label visible', async ({ page }) => {
    await expect(page.locator('.gs-start-here')).toBeVisible();
    await expect(page.locator('.gs-start-here')).toContainText('Start here');
  });

  test('help inline block visible below MCP Proxy card', async ({ page }) => {
    const helpInline = page.locator('.gs-help-inline');
    await expect(helpInline).toBeVisible();
    await expect(helpInline).toContainText('MCP Proxy');
    await expect(helpInline).toContainText('Connections');
  });

  test('featured cards section with 5 cards', async ({ page }) => {
    const section = page.locator('.gs-featured-section');
    await expect(section).toBeVisible();

    const cards = section.locator('.gs-new-card');
    await expect(cards).toHaveCount(5);
  });

  test('featured cards include Connect Your Agent', async ({ page }) => {
    const section = page.locator('.gs-featured-section');
    const allText = await section.textContent();
    expect(allText).toContain('Connect Your Agent');
    // HTTP Gateway removed per #49
    expect(allText).not.toContain('HTTP Gateway');
  });

  test('MCP Proxy card can be collapsed and re-expanded', async ({ page }) => {
    const card = page.locator('[data-uc="mcp-proxy"]');

    // Click header to collapse
    await card.locator('.gs-card-header').click();
    await expect(card).not.toHaveClass(/expanded/);

    // Click header to re-expand
    await card.locator('.gs-card-header').click();
    await expect(card).toHaveClass(/expanded/);
    await expect(card.locator('.gs-card-content')).toBeVisible();
  });

  test('no references to "run"', async ({ page }) => {
    const bodyText = await page.locator('body').textContent();

    expect(bodyText).not.toContain('sentinel-gate run');
    expect(bodyText).not.toContain('sg run');
  });

  test('page loads without JS errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', (err) => errors.push(err.message));

    await page.goto('/admin/#/getting-started');
    await page.waitForSelector('.gs-header');
    // Give time for any async operations to settle
    await page.waitForTimeout(1000);

    expect(errors).toHaveLength(0);
  });

  test('step items have descriptions', async ({ page }) => {
    // The MCP Proxy card is auto-expanded with 3 steps
    const card = page.locator('[data-uc="mcp-proxy"]');
    await expect(card).toHaveClass(/expanded/);

    const steps = card.locator('.gs-step');
    const stepCount = await steps.count();
    expect(stepCount).toBe(3);

    // Each step should have a number badge and text content
    for (let i = 0; i < stepCount; i++) {
      const step = steps.nth(i);
      await expect(step.locator('.gs-step-num')).toBeVisible();
      await expect(step.locator('.gs-step-text')).toBeVisible();
      const text = await step.locator('.gs-step-text').textContent();
      expect(text!.length).toBeGreaterThan(5);
    }
  });

  test('navigation from getting started works', async ({ page }) => {
    // The featured cards contain links to other pages
    const featuredCards = page.locator('.gs-featured-section .gs-new-card');
    const count = await featuredCards.count();
    expect(count).toBeGreaterThan(0);

    // Each featured card should be an anchor with a valid href
    for (let i = 0; i < count; i++) {
      const href = await featuredCards.nth(i).getAttribute('href');
      expect(href).toBeTruthy();
      expect(href).toMatch(/^#\//);
    }

    // Click the first featured card and verify navigation occurs
    const firstHref = await featuredCards.first().getAttribute('href');
    await featuredCards.first().click();
    await page.waitForTimeout(500);
    expect(page.url()).toContain(firstHref!);
  });

  test('progress tracking via step numbers', async ({ page }) => {
    // Steps in the expanded MCP Proxy card have sequential numbers (1, 2, 3)
    const card = page.locator('[data-uc="mcp-proxy"]');
    const stepNums = card.locator('.gs-step-num');
    const count = await stepNums.count();
    expect(count).toBe(3);

    for (let i = 0; i < count; i++) {
      const numText = await stepNums.nth(i).textContent();
      expect(numText).toBe(String(i + 1));
    }
  });

  test('subtitle explains purpose', async ({ page }) => {
    const subtitle = page.locator('.gs-header p');
    await expect(subtitle).toBeVisible();
    const text = await subtitle.textContent();
    expect(text).toContain('SentinelGate');
  });
});
