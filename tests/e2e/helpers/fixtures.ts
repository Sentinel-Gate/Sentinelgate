import { test as base, expect } from '@playwright/test';
import { AdminAPI, getTestEnv, TestEnv } from './api';
import { MCPClient, createMCPSession } from './mcp';

/**
 * Extended test fixtures for SentinelGate E2E tests.
 */
export const test = base.extend<{
  adminAPI: AdminAPI;
  env: TestEnv;
  mcpClient: MCPClient;
}>({
  adminAPI: async ({ request }, use) => {
    const api = new AdminAPI(request);
    await use(api);
  },

  env: async ({}, use) => {
    await use(getTestEnv());
  },

  mcpClient: async ({ request }, use) => {
    const client = await createMCPSession(request);
    await use(client);
  },
});

export { expect } from '@playwright/test';
export { AdminAPI } from './api';
export { MCPClient, createMCPSession } from './mcp';
export { getTestEnv } from './api';
export type { TestEnv } from './api';

/**
 * Navigate to a page and wait for a selector to appear.
 * Retries with page.reload() if the selector doesn't appear within the
 * initial timeout (handles transient 429 rate-limit responses that leave
 * the page in a skeleton/loading state).
 */
export async function navigateAndWait(
  page: import('@playwright/test').Page,
  url: string,
  selector: string,
  opts: { timeout?: number; retries?: number } = {},
): Promise<void> {
  const { timeout = 15_000, retries = 2 } = opts;
  await page.goto(url);

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      await page.waitForSelector(selector, { timeout });
      return;
    } catch {
      if (attempt < retries) {
        // Wait briefly for rate-limit window to reset, then reload
        await page.waitForTimeout(2000);
        await page.reload();
      } else {
        throw new Error(
          `navigateAndWait: '${selector}' not visible after ${retries + 1} attempts on ${url}`,
        );
      }
    }
  }
}
