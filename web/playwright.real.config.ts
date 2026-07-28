import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.NYAUTH_REAL_E2E_BASE_URL;
if (!baseURL) {
  throw new Error('NYAUTH_REAL_E2E_BASE_URL is required; run npm run test:e2e:real');
}

export default defineConfig({
  testDir: './tests/real-e2e',
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  outputDir: 'test-results/real-e2e',
  reporter: [['list']],
  use: {
    baseURL,
    colorScheme: 'light',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium-real-backend',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
