import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: ['ui/**/*.spec.ts', 'mcp/**/*.spec.ts', 'e2e-flows/**/*.spec.ts'],
  timeout: 60_000,
  expect: { timeout: 10_000 },
  retries: 0,
  workers: 1, // sequential — shared server state
  reporter: [
    ['list'],
    ['html', { open: 'never' }],
  ],
  globalSetup: './global-setup.ts',
  globalTeardown: './global-teardown.ts',
  use: {
    baseURL: 'http://localhost:8080',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    actionTimeout: 10_000,
  },
  projects: [
    {
      name: 'ui',
      testDir: './ui',
      use: {
        browserName: 'chromium',
        viewport: { width: 1440, height: 900 },
      },
    },
    {
      name: 'mcp',
      testDir: './mcp',
      use: {
        browserName: 'chromium', // needed for request context
      },
    },
    {
      name: 'e2e-flows',
      testDir: './e2e-flows',
      use: {
        browserName: 'chromium',
      },
    },
  ],
});
