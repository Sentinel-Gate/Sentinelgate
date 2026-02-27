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
