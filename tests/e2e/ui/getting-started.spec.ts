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

  test('3 main cards visible', async ({ page }) => {
    const cards = page.locator('.gs-card');
    await expect(cards).toHaveCount(3);

    await expect(page.locator('[data-uc="mcp-proxy"]')).toBeVisible();
    await expect(page.locator('[data-uc="http-gateway"]')).toBeVisible();
    await expect(page.locator('[data-uc="mcp-client-sdk"]')).toBeVisible();
  });

  test('click MCP Proxy card expands', async ({ page }) => {
    const card = page.locator('[data-uc="mcp-proxy"]');
    const header = card.locator('.gs-card-header');
    const content = card.locator('.gs-card-content');

    await header.click();

    await expect(card).toHaveClass(/expanded/);
    await expect(content).toBeVisible();
    await expect(card.locator('.gs-step').first()).toBeVisible();
    await expect(card.locator('.gs-code').first()).toBeVisible();
  });

  test('click HTTP Gateway card expands', async ({ page }) => {
    const card = page.locator('[data-uc="http-gateway"]');
    const header = card.locator('.gs-card-header');
    const content = card.locator('.gs-card-content');

    await header.click();

    await expect(card).toHaveClass(/expanded/);
    await expect(content).toBeVisible();
  });

  test('click MCP Client SDK card expands', async ({ page }) => {
    const card = page.locator('[data-uc="mcp-client-sdk"]');
    const header = card.locator('.gs-card-header');
    const content = card.locator('.gs-card-content');

    await header.click();

    await expect(card).toHaveClass(/expanded/);
    await expect(content).toBeVisible();
  });

  test('copy button works', async ({ page, context }) => {
    // Grant clipboard permission so navigator.clipboard.writeText() succeeds
    await context.grantPermissions(['clipboard-write', 'clipboard-read']);

    // Expand MCP Proxy card to reveal code blocks
    const card = page.locator('[data-uc="mcp-proxy"]');
    await card.locator('.gs-card-header').click();
    await expect(card).toHaveClass(/expanded/);

    const copyBtn = card.locator('.gs-code-copy').first();
    await expect(copyBtn).toBeVisible();

    await copyBtn.click();

    // The JS changes textContent to "Copied!" on successful clipboard write
    await expect(copyBtn).toHaveText('Copied!');
  });

  test('no references to "run"', async ({ page }) => {
    const bodyText = await page.locator('body').textContent();

    expect(bodyText).not.toContain('sentinel-gate run');
    expect(bodyText).not.toContain('sg run');
  });

  test('feature cards link to correct pages', async ({ page }) => {
    const featureCards = page.locator('.gs-new-card');
    await expect(featureCards.first()).toBeVisible();

    // Click the first feature card and verify navigation away from getting-started
    const firstCard = featureCards.first();
    await firstCard.click();

    await page.waitForURL(/\/admin\/#\/(?!getting-started)/);
    expect(page.url()).not.toContain('#/getting-started');
  });
});
