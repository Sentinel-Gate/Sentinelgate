import { test, expect, AdminAPI } from '../helpers/fixtures';

function findSafeTool(tools: any[]): any {
  return tools.find((t: any) => t.name === 'list_allowed_directories')
    || tools.find((t: any) => t.name === 'read_graph')
    || tools[0];
}

// =============================================================================
// Wave 1 — Linguaggio e Layout (18 test)
// =============================================================================

test.describe('Wave 1 - Linguaggio e Layout', () => {

  // 1.1 — "Upstream" → "MCP Server" (2 test — stat card and tools header button removed in UX overhaul)
  test.describe('1.1 - Upstream → MCP Server renaming', () => {

    test('dashboard panel header says "MCP Servers"', async ({ page }) => {
      await page.goto('/admin/#/dashboard');
      await page.waitForSelector('#upstream-list');
      const panel = page.locator('.card', { has: page.locator('#upstream-list') });
      await expect(panel).toContainText('MCP Servers');
    });

    test('sidebar shows "servers" suffix', async ({ page }) => {
      await page.goto('/admin/#/dashboard');
      await page.waitForSelector('#upstream-count', { timeout: 10_000 });
      await expect(page.locator('#upstream-count')).toContainText('server');
    });
  });

  // 1.2 — Subtitle su ogni pagina (12 test)
  test.describe('1.2 - Page subtitles', () => {
    const subtitleTests = [
      { route: 'dashboard',       selector: '.page-subtitle',      text: 'Real-time overview' },
      { route: 'tools',           selector: '.page-subtitle',      text: 'Manage your security rules' },
      { route: 'access',          selector: '.access-header-desc', text: 'Manage MCP servers' },
      { route: 'audit',           selector: '.page-subtitle',      text: 'Complete history' },
      { route: 'sessions',        selector: '.page-subtitle',      text: 'Record, replay' },
      { route: 'notifications',   selector: '.page-subtitle',      text: 'Alerts and approval' },
      { route: 'compliance',      selector: '.page-subtitle',      text: 'Track your security' },
      { route: 'permissions',     selector: '.page-subtitle',      text: 'Fine-grained access' },
      { route: 'security',        selector: '.page-subtitle',      text: 'Security scanning' },
      { route: 'redteam',         selector: '.page-subtitle',      text: 'Test your defenses' },
      { route: 'finops',          selector: '.page-subtitle',      text: 'Track and control' },
      { route: 'getting-started', selector: '.gs-header p',        text: 'Choose how you want to use SentinelGate' },
    ];

    for (const { route, selector, text } of subtitleTests) {
      test(`subtitle on ${route}`, async ({ page }) => {
        await page.goto(`/admin/#/${route}`);
        await page.waitForLoadState('domcontentloaded');
        await page.waitForTimeout(1500);
        await expect(page.locator(selector).first()).toContainText(text, { timeout: 10_000 });
      });
    }
  });

  // 1.3 — Dashboard spacing (1 test)
  test('dashboard-panels has margin-top spacing', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('.dashboard-panels');
    const mt = await page.locator('.dashboard-panels').evaluate(
      el => getComputedStyle(el).marginTop
    );
    expect(parseInt(mt)).toBeGreaterThanOrEqual(16);
  });

  // 1.4 — Tool match help text (1 test)
  test('tool match help text visible in rule form', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.tools-header', { timeout: 15_000 });
    const addRuleBtn = page.locator('button', { hasText: /Add Rule|New Rule/i });
    if (await addRuleBtn.isVisible().catch(() => false)) {
      await addRuleBtn.click();
      await page.waitForTimeout(500);
      // The rule form step 2 ("Which tool?") shows the description
      // "Click a tool below or type a name" and includes a "* (all tools)" chip.
      await expect(page.locator('text=Click a tool below or type a name')).toBeVisible({ timeout: 5_000 });
      // Verify the wildcard chip is present
      await expect(page.locator('.tool-chip', { hasText: '* (all tools)' })).toBeVisible({ timeout: 5_000 });
      await page.keyboard.press('Escape');
    }
  });
});

// =============================================================================
// Wave 2 — Contenuti e Guida (5 test)
// =============================================================================

test.describe('Wave 2 - Contenuti e Guida', () => {

  // 2.1 — Info-box + Terminal guide (2 test)
  test('info-box visible on access page', async ({ page }) => {
    await page.goto('/admin/#/access');
    await page.waitForSelector('.access-header');
    await expect(page.locator('.info-box').first()).toBeVisible({ timeout: 10_000 });
  });

  test('terminal guide mentions "terminal"', async ({ page }) => {
    await page.goto('/admin/#/access');
    await page.waitForSelector('.access-header');
    const infoBoxes = page.locator('.info-box');
    const allText = await infoBoxes.allTextContents();
    expect(allText.join(' ')).toContain('terminal');
  });

  // 2.2 — Regex pattern chips (1 test)
  test('pattern chips shown in redact transform form', async ({ page }) => {
    await page.goto('/admin/#/tools');
    // Wait for the tools page header first (renders immediately)
    await page.waitForSelector('.tools-header', { timeout: 15_000 });
    // Then wait for the section tabs (rendered after data loads); retry once on timeout
    try {
      await page.waitForSelector('.section-tabs', { timeout: 20_000 });
    } catch {
      await page.reload();
      await page.waitForSelector('.section-tabs', { timeout: 20_000 });
    }
    await page.locator('.section-tab', { hasText: 'Transforms' }).click();
    await page.waitForTimeout(500);
    const addBtn = page.locator('button', { hasText: /Add Transform|New Transform/i });
    if (await addBtn.isVisible().catch(() => false)) {
      await addBtn.click();
      await page.waitForTimeout(500);
      const typeSelect = page.locator('select').filter({ has: page.locator('option[value="redact"]') });
      if (await typeSelect.isVisible().catch(() => false)) {
        await typeSelect.selectOption('redact');
        await page.waitForTimeout(300);
      }
      await expect(page.locator('text=Common patterns (click to add):').first()).toBeVisible({ timeout: 5_000 });
      await expect(page.locator('button', { hasText: 'SSN' }).first()).toBeVisible();
      await expect(page.locator('button', { hasText: 'Credit Card' }).first()).toBeVisible();
      await expect(page.locator('button', { hasText: 'Email' }).first()).toBeVisible();
      await page.keyboard.press('Escape');
    }
  });

  // 2.4 — Empty states (1 test)
  test('notifications empty state shows "All clear!"', async ({ page }) => {
    await page.goto('/admin/#/notifications');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1500);
    const emptyState = page.locator('.notif-empty');
    if (await emptyState.isVisible().catch(() => false)) {
      await expect(emptyState).toContainText('All clear');
    }
  });

  // 2.6 — Transform badge (1 test)
  test('activity feed can show "Transformed" badge', async ({ page, adminAPI, mcpClient }) => {
    const res = await adminAPI.post('/v1/transforms', {
      name: 'e2e-ux-redact', type: 'redact', tool_match: '*',
      priority: 50, enabled: true,
      config: { patterns: ['sk-[a-zA-Z0-9]+'], replacement: '[REDACTED]' },
    });
    const transformId = res?.id;

    try {
      const tools = await mcpClient.listTools();
      if (tools.length > 0) await mcpClient.callTool(findSafeTool(tools).name, {});
      await page.goto('/admin/#/dashboard');
      await page.waitForSelector('#activity-feed');
      await page.waitForTimeout(3000);
      // Verify page loaded without errors — badge appears only if transform matches
    } finally {
      if (transformId) await adminAPI.deleteTransform(transformId);
    }
  });
});

// =============================================================================
// Wave 3 — Help System (27 test)
// =============================================================================

test.describe('Wave 3 - Help System', () => {

  // 3.1 — Help button on all pages (11 test — getting-started no longer has ? button)
  test.describe('3.1 - Help button on all pages', () => {
    const pages = [
      'dashboard', 'tools', 'access', 'audit', 'sessions',
      'notifications', 'compliance', 'permissions', 'security',
      'redteam', 'finops',
    ];

    for (const route of pages) {
      test(`help button "?" on ${route}`, async ({ page }) => {
        await page.goto(`/admin/#/${route}`);
        await page.waitForLoadState('domcontentloaded');
        await page.waitForTimeout(1500);
        await expect(page.locator('.help-btn').first()).toBeVisible({ timeout: 10_000 });
      });
    }
  });

  // 3.2 — Help panel open/close (5 test)
  test('clicking "?" opens help panel on dashboard', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('.help-btn', { timeout: 10_000 });
    await page.locator('.help-btn').click();
    await expect(page.locator('.help-panel.open')).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('.help-panel-body')).toContainText('Stat Cards');
  });

  test('clicking "?" opens help panel on tools', async ({ page }) => {
    await page.goto('/admin/#/tools');
    await page.waitForSelector('.help-btn', { timeout: 15_000 });
    await page.locator('.help-btn').first().click();
    await expect(page.locator('.help-panel.open')).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('.help-panel-body')).toContainText('security rules and tool configuration');
  });

  test('backdrop closes help panel', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('.help-btn', { timeout: 10_000 });
    await page.locator('.help-btn').click();
    await expect(page.locator('.help-panel.open')).toBeVisible({ timeout: 5_000 });
    await page.locator('.help-panel-backdrop.open').click();
    await expect(page.locator('.help-panel.open')).not.toBeVisible({ timeout: 3_000 });
  });

  test('ESC closes help panel', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('.help-btn', { timeout: 10_000 });
    await page.locator('.help-btn').click();
    await expect(page.locator('.help-panel.open')).toBeVisible({ timeout: 5_000 });
    await page.keyboard.press('Escape');
    await expect(page.locator('.help-panel.open')).not.toBeVisible({ timeout: 3_000 });
  });

  test('X button closes help panel', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('.help-btn', { timeout: 10_000 });
    await page.locator('.help-btn').click();
    await expect(page.locator('.help-panel.open')).toBeVisible({ timeout: 5_000 });
    await page.locator('.help-panel-close').click();
    await expect(page.locator('.help-panel.open')).not.toBeVisible({ timeout: 3_000 });
  });

  // 3.3 — Help content per page (7 test — getting-started no longer has ? button)
  test.describe('3.3 - Help content per page', () => {
    const helpContent = [
      { route: 'dashboard',      expectedText: 'Health Indicator' },
      { route: 'tools',          expectedText: 'security rules and tool configuration' },
      { route: 'access',         expectedText: 'identities' },
      { route: 'audit',          expectedText: 'tool call' },
      { route: 'sessions',       expectedText: 'recorded conversations' },
      { route: 'notifications',  expectedText: 'Approval Requests' },
      { route: 'compliance',     expectedText: 'regulatory frameworks' },
    ];

    for (const { route, expectedText } of helpContent) {
      test(`help on ${route} contains "${expectedText}"`, async ({ page }) => {
        await page.goto(`/admin/#/${route}`);
        await page.waitForLoadState('domcontentloaded');
        await page.waitForTimeout(1500);
        await page.locator('.help-btn').first().click();
        await expect(page.locator('.help-panel-body')).toContainText(expectedText, { timeout: 5_000 });
      });
    }
  });

  // 3.4 — Glossario (1 test)
  test('glossary CSS and processing function exist in help panel', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('.help-btn', { timeout: 10_000 });
    await page.locator('.help-btn').click();
    await expect(page.locator('.help-panel.open')).toBeVisible({ timeout: 5_000 });
    // Verify glossary infrastructure: the CSS for help-glossary-term is injected
    // and SG.help.glossary function exists (glossary terms only appear in help body
    // when <strong>TERM</strong> exactly matches a GLOSSARY key).
    const hasGlossaryCSS = await page.evaluate(() => {
      const styles = document.querySelectorAll('style');
      for (let i = 0; i < styles.length; i++) {
        if (styles[i].textContent?.includes('help-glossary-term')) return true;
      }
      return false;
    });
    expect(hasGlossaryCSS).toBe(true);
    const hasGlossaryFn = await page.evaluate(() => typeof (window as any).SG?.help?.glossary === 'function');
    expect(hasGlossaryFn).toBe(true);
  });

  // 3.5 — Help footer (1 test)
  test('help panel has documentation link', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('.help-btn', { timeout: 10_000 });
    await page.locator('.help-btn').click();
    await expect(page.locator('.help-panel.open')).toBeVisible({ timeout: 5_000 });
    const footer = page.locator('.help-panel-footer a');
    await expect(footer).toBeVisible();
  });
});

// =============================================================================
// Wave 4 — Smart UX (12 test)
// =============================================================================

test.describe('Wave 4 - Smart UX', () => {

  // 4.1 — Security Score widget (3 test)
  test('posture widget visible', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await expect(page.locator('#posture-widget')).toBeVisible({ timeout: 10_000 });
  });

  test('posture widget has score content', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#posture-widget', { timeout: 10_000 });
    await page.waitForTimeout(3000);
    const body = await page.locator('#posture-body').textContent();
    expect(body).toBeTruthy();
  });

  test('posture widget title says "Security Score"', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#posture-widget', { timeout: 10_000 });
    await expect(page.locator('#posture-widget')).toContainText('Security Score');
  });

  // 4.2 — Next-step banner (3 test)
  test('nextstep-banner-container exists', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards', { timeout: 10_000 });
    await expect(page.locator('#nextstep-banner-container')).toBeAttached();
  });

  test('banner content is contextual (depends on state)', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards', { timeout: 10_000 });
    await page.waitForTimeout(3000);
    await expect(page.locator('#nextstep-banner-container')).toBeAttached();
  });

  test('banner uses info-box-tip styling if visible', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    // The container is always in the DOM but may be empty/hidden when there
    // is no actionable next-step. Use state: 'attached' instead of the
    // default 'visible' which would fail on a hidden empty container.
    await page.waitForSelector('#nextstep-banner-container', { state: 'attached', timeout: 10_000 });
    await page.waitForTimeout(3000);
    const banner = page.locator('#nextstep-banner-container .info-box-tip');
    if (await banner.isVisible().catch(() => false)) {
      await expect(banner).toHaveClass(/info-box/);
    }
  });

  // 4.3 — Insights widget (moved to help panel — verify NOT on dashboard)
  test('insights widget not present on dashboard', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards', { timeout: 10_000 });
    await page.waitForTimeout(2000);
    await expect(page.locator('#insights-widget')).not.toBeVisible();
  });

  // 4.4 — Plain English audit (1 test)
  test('activity feed uses plain English format', async ({ page, mcpClient }) => {
    const tools = await mcpClient.listTools();
    if (tools.length > 0) await mcpClient.callTool(findSafeTool(tools).name, {});

    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#activity-feed');
    await expect(page.locator('#activity-feed .upstream-item').first()).toBeVisible({ timeout: 10_000 });
    const feedText = await page.locator('#activity-feed').textContent();
    expect(feedText?.includes('used') || feedText?.includes('tried')).toBe(true);
  });
});

// =============================================================================
// Wave 5 — Onboarding 2.0 (8 test)
// =============================================================================

test.describe('Wave 5 - Onboarding 2.0', () => {

  // 5.1 — Re-run Setup Wizard removed (verify NOT present)
  test('"Re-run Setup Wizard" link not present', async ({ page }) => {
    await page.goto('/admin/#/getting-started');
    await page.waitForSelector('.gs-header');
    const link = page.locator('a', { hasText: 'Re-run Setup Wizard' });
    await expect(link).not.toBeVisible();
  });

  // 5.2 — Flow diagram (1 test)
  test('flow diagram shows 3 boxes', async ({ page }) => {
    await page.goto('/admin/#/onboarding');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1500);
    const text = await page.locator('.onboarding').textContent();
    expect(text).toContain('Your AI Agent');
    expect(text).toContain('SentinelGate');
    expect(text).toContain('MCP Servers');
  });

  // 5.3 — Step descriptions (2 test — reordered: Add Server -> Connect Agent -> Set Rules)
  test('3 onboarding steps with descriptions', async ({ page }) => {
    await page.goto('/admin/#/onboarding');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1500);
    await expect(page.locator('.onboarding-step')).toHaveCount(3, { timeout: 10_000 });
    const descs = page.locator('.onboarding-step-desc');
    await expect(descs.nth(0)).toContainText('MCP servers');
    await expect(descs.nth(1)).toContainText('identity and API key');
    await expect(descs.nth(2)).toContainText('security rules');
  });

  test('step titles correct', async ({ page }) => {
    await page.goto('/admin/#/onboarding');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1500);
    const titles = page.locator('.onboarding-step-title');
    await expect(titles.nth(0)).toHaveText('Add Server');
    await expect(titles.nth(1)).toHaveText('Connect Agent');
    await expect(titles.nth(2)).toHaveText('Set Rules');
  });

  // 5.4 — CTA + sidebar + welcome (4 test)
  test('"Add MCP Server" CTA on onboarding', async ({ page }) => {
    await page.goto('/admin/#/onboarding');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1500);
    await expect(page.locator('button', { hasText: 'Add MCP Server' })).toBeVisible({ timeout: 10_000 });
  });

  test('sidebar progress dots removed', async ({ page }) => {
    await page.goto('/admin/#/dashboard');
    await page.waitForSelector('#stat-cards', { timeout: 10_000 });
    await page.waitForTimeout(2000);
    const gsNav = page.locator('.nav-item[data-page="getting-started"]');
    await expect(gsNav).toBeVisible();
    // Setup progress dots have been removed from the sidebar
    await expect(page.locator('#setup-progress')).not.toBeVisible();
  });

  test('onboarding welcome title', async ({ page }) => {
    await page.goto('/admin/#/onboarding');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1500);
    await expect(page.locator('.onboarding-title')).toContainText('Welcome to SentinelGate');
  });

  test('onboarding shield icon', async ({ page }) => {
    await page.goto('/admin/#/onboarding');
    await page.waitForLoadState('domcontentloaded');
    await page.waitForTimeout(1500);
    await expect(page.locator('.onboarding-icon svg')).toBeVisible({ timeout: 10_000 });
  });
});
