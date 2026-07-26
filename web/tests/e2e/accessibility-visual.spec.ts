import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Route } from '@playwright/test';

async function fulfillJSON(route: Route, status: number, body: unknown) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

async function installPublicMocks(page: Page) {
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/session') {
      await fulfillJSON(route, 401, { error: 'authentication required' });
      return;
    }
    if (path === '/api/providers') {
      await fulfillJSON(route, 200, []);
      return;
    }
    await fulfillJSON(route, 404, { error: 'not found' });
  });
}

async function installAdminMocks(page: Page) {
  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/session') {
      await fulfillJSON(route, 200, {
        user: {
          id: '11111111-1111-1111-1111-111111111111',
          username: 'admin',
          email: 'admin@example.test',
          display_name: 'Nya Admin',
          role: 'admin',
          status: 'active',
          created_at: '2026-01-01T00:00:00Z',
        },
        csrf_token: 'visual-test-csrf',
        must_change_password: false,
        has_password: true,
        email_verified: true,
        authenticated_at: '2026-01-02T00:00:00Z',
      });
      return;
    }
    if (url.pathname === '/api/admin/clients' && route.request().method() === 'GET') {
      await fulfillJSON(route, 200, {
        items: [{
          id: 'visual-client',
          name: 'Visual Regression Client',
          redirect_uris: ['https://app.example.test/callback'],
          post_logout_redirect_uris: ['https://app.example.test/signed-out'],
          grants: ['authorization_code', 'refresh_token'],
          scopes: ['openid', 'profile', 'email'],
          is_public: false,
          secret_hint: 'test1234',
          secret_version: 1,
          owner_id: '11111111-1111-1111-1111-111111111111',
          metadata: {},
          created_at: '2026-01-01T00:00:00Z',
          updated_at: '2026-01-01T00:00:00Z',
        }],
        total: 1,
        page: 1,
        page_size: 20,
        total_pages: 1,
      });
      return;
    }
    await fulfillJSON(route, 404, { error: 'not found' });
  });
}

test.beforeEach(async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: 'light' });
});

test('login page has no automatically detectable accessibility violations', async ({ page }) => {
  await installPublicMocks(page);
  await page.goto('/login');
  await expect(page.getByRole('heading', { name: 'Nya' })).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});

test('login page matches the light-theme visual baseline', async ({ page }) => {
  await installPublicMocks(page);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/login');
  const heading = page.getByRole('heading', { name: 'Nya' });
  await expect(heading).toBeVisible();
  await expect(heading).toHaveCSS('font-size', '38px');

  await expect(page).toHaveScreenshot('login-page.png', {
    animations: 'disabled',
    fullPage: true,
    maxDiffPixelRatio: 0.08,
  });
});

test('authenticated admin client list is accessible and matches its visual baseline', async ({ page }) => {
  await installAdminMocks(page);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('/admin/clients');
  await expect(page.getByRole('heading', { name: '应用管理' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Visual Regression Client' })).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
  await expect(page).toHaveScreenshot('admin-clients-page.png', {
    animations: 'disabled',
    fullPage: true,
    maxDiffPixelRatio: 0.08,
  });
});

test('danger confirmation dialog is accessible and restores trigger focus', async ({ page }) => {
  await installAdminMocks(page);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('/admin/clients');
  const deleteTrigger = page.getByRole('button', { name: '删除', exact: true });
  await deleteTrigger.click();

  const dialog = page.getByRole('dialog', { name: '删除应用' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('button', { name: '永久删除' })).toBeDisabled();
  const results = await new AxeBuilder({ page }).include('[role="dialog"]').analyze();
  expect(results.violations).toEqual([]);
  await expect(page).toHaveScreenshot('admin-client-delete-dialog.png', {
    animations: 'disabled',
    fullPage: true,
    maxDiffPixelRatio: 0.08,
  });

  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(deleteTrigger).toBeFocused();
});
