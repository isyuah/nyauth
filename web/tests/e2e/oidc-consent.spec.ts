import { expect, test, type Page, type Route } from '@playwright/test';

async function fulfillJSON(route: Route, status: number, body: unknown) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function installConsentMocks(page: Page, decision: { body?: unknown }) {
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/api/session') {
      await fulfillJSON(route, 200, {
        user: {
          id: '11111111-1111-1111-1111-111111111111', username: 'alice',
          display_name: 'Alice', role: 'user', status: 'active', created_at: '2026-01-01T00:00:00Z',
        },
        csrf_token: 'consent-csrf', must_change_password: false, has_password: true,
        email_verified: true, authenticated_at: '2026-07-31T00:00:00Z',
      });
      return;
    }
    if (path === '/api/consent' && request.method() === 'GET') {
      await fulfillJSON(route, 200, {
        challenge: 'consent-challenge', client_name: 'Example Workspace', client_id: 'example-client',
        scopes: ['openid', 'profile', 'email', 'offline_access', 'admin.role'],
        permissions: [
          { scope: 'openid', display_name: '确认身份', description: '使用稳定的账户标识完成登录。', risk_level: 'low', required: true, claims: ['sub'] },
          { scope: 'profile', display_name: '基本资料', description: '读取用户名、显示名称和头像。', risk_level: 'personal_data', required: false, claims: ['preferred_username', 'name', 'picture'] },
          { scope: 'email', display_name: '邮箱信息', description: '读取邮箱地址及验证状态。', risk_level: 'personal_data', required: false, claims: ['email', 'email_verified'] },
          { scope: 'offline_access', display_name: '离线访问', description: '允许应用在用户离开后继续访问。', risk_level: 'sensitive', required: false, claims: [] },
          { scope: 'admin.role', display_name: '账户角色', description: '读取当前账户的管理员或普通用户角色。', risk_level: 'sensitive', required: true, claims: ['role'] },
        ],
        redirect_uri: 'https://client.example/callback', redirect_origin: 'https://client.example',
        publisher_type: 'system_managed', verification_status: 'unverified',
      });
      return;
    }
    if (path === '/api/consent/accept' && request.method() === 'POST') {
      decision.body = request.postDataJSON();
      await fulfillJSON(route, 200, { redirect_url: '/test-client?consent=accepted' });
      return;
    }
    if (path === '/api/branding') {
      await fulfillJSON(route, 200, { title: 'Nya', logo_url: '' });
      return;
    }
    if (path === '/api/service-status') {
      await fulfillJSON(route, 200, { state: 'normal', paused_capabilities: [], public_message: '', retry_after_seconds: 0 });
      return;
    }
    if (path === '/api/site-banner') {
      await fulfillJSON(route, 200, { active: false, version: 0 });
      return;
    }
    await fulfillJSON(route, 404, { error: `unmocked endpoint: ${path}` });
  });
}

test('consent separates required permissions and submits only selected optional scopes', async ({ page }) => {
  const decision: { body?: unknown } = {};
  await installConsentMocks(page, decision);
  await page.goto('/consent?challenge=consent-challenge');

  await expect(page.getByRole('heading', { name: '授权确认' })).toBeVisible();
  await expect(page.getByText('必需权限')).toBeVisible();
  await expect(page.getByText('可选权限', { exact: true })).toBeVisible();
  await expect(page.getByText('稳定用户 ID')).toBeVisible();
  await expect(page.getByText('用户名、显示名称、头像')).toBeVisible();
  await expect(page.getByText('账户角色', { exact: true })).toBeVisible();
  await expect(page.getByText('读取当前账户的管理员或普通用户角色。')).toBeVisible();

  const profile = page.getByRole('checkbox', { name: /基本资料/ });
  const email = page.getByRole('checkbox', { name: /邮箱信息/ });
  const offline = page.getByRole('checkbox', { name: /离线访问/ });
  await expect(profile).toBeChecked();
  await expect(email).toBeChecked();
  await expect(offline).toBeChecked();
  await email.uncheck();
  await offline.uncheck();
  await page.getByRole('button', { name: '授权所选权限' }).click();

  await expect.poll(() => decision.body).toEqual({
    challenge: 'consent-challenge', granted_optional_scopes: ['profile'],
  });
});
