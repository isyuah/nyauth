import { expect, test, type Page, type Route } from '@playwright/test';

async function fulfillJSON(route: Route, status: number, body: unknown) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function installConsentMocks(
  page: Page,
  decision: { body?: unknown },
  publisher: { type: 'system_managed' | 'user_registered'; status: 'not_applicable' | 'unverified' | 'verified' } = {
    type: 'system_managed', status: 'not_applicable',
  },
) {
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
          { scope: 'openid', display_name: '确认身份', description: '使用稳定的账户标识完成登录。', risk_level: 'low', required: true, claims: ['sub'], previously_granted: true, newly_requested: false },
          { scope: 'profile', display_name: '基本资料', description: '读取用户名、显示名称和头像。', risk_level: 'personal_data', required: false, claims: ['preferred_username', 'name', 'picture'], previously_granted: false, newly_requested: true },
          { scope: 'email', display_name: '邮箱信息', description: '读取邮箱地址及验证状态。', risk_level: 'personal_data', required: false, claims: ['email', 'email_verified'], previously_granted: true, newly_requested: false },
          { scope: 'offline_access', display_name: '离线访问', description: '允许应用在用户离开后继续访问。', risk_level: 'sensitive', required: false, claims: [], previously_granted: true, newly_requested: false },
          { scope: 'admin.role', display_name: '账户角色', description: '读取当前账户的管理员或普通用户角色。', risk_level: 'sensitive', required: true, claims: ['role'], previously_granted: true, newly_requested: false },
        ],
        redirect_uri: 'https://client.example/callback', redirect_origin: 'https://client.example',
        publisher_type: publisher.type, verification_status: publisher.status,
        logo_url: '', homepage_uri: 'https://client.example',
        privacy_policy_uri: 'https://client.example/privacy', terms_of_service_uri: 'https://client.example/terms',
        previously_authorized: true, application_changed: false, reauthorization_required: false,
        new_scopes: ['profile'], new_claims: ['preferred_username', 'name', 'picture'],
      });
      return;
    }
    if (path === '/api/consent/accept' && request.method() === 'POST') {
      decision.body = request.postDataJSON();
      await fulfillJSON(route, 200, { redirect_url: '/test-client?consent=accepted' });
      return;
    }
    if (path === '/api/branding') {
      await fulfillJSON(route, 200, { title: 'Nya', primary_color: '#704DE8', primary_text_color: 'auto', light_logo_url: '', dark_logo_url: '', favicon_url: '' });
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

	await expect(page.getByRole('heading', { name: 'Example Workspace' })).toBeVisible();
  await expect(page.getByText('必需权限')).toBeVisible();
  await expect(page.getByText('可选权限', { exact: true })).toBeVisible();
  await expect(page.getByText('稳定用户 ID')).toBeVisible();
  await expect(page.getByText('用户名（新增）、显示名称（新增）、头像（新增）')).toBeVisible();
  await expect(page.getByText('账户角色', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('读取当前账户的管理员或普通用户角色。')).toBeVisible();
  await expect(page.getByText('新增请求', { exact: true })).toBeVisible();
	await page.getByRole('button', { name: '应用技术信息' }).click();
	await expect(page.getByRole('link', { name: '应用主页' })).toHaveAttribute('href', 'https://client.example');
  await expect(page.getByRole('link', { name: '隐私政策' })).toHaveAttribute('href', 'https://client.example/privacy');
	await expect(page.getByText('此应用由 Nya 管理员直接配置和管理。')).toBeVisible();
	await expect(page.getByText('Nya 尚未验证此应用的发布者')).toHaveCount(0);

  const profile = page.getByRole('checkbox', { name: /基本资料/ });
  const email = page.getByRole('checkbox', { name: /邮箱信息/ });
  const offline = page.getByRole('checkbox', { name: /离线访问/ });
  await expect(profile).not.toBeChecked();
  await expect(email).toBeChecked();
  await expect(offline).toBeChecked();
	await page.getByText('基本资料', { exact: true }).click();
	await page.getByText('邮箱信息', { exact: true }).click();
	await page.getByText('离线访问', { exact: true }).click();
	await expect(profile).toBeChecked();
	await expect(email).not.toBeChecked();
	await expect(offline).not.toBeChecked();
  await page.getByRole('button', { name: '授权所选权限' }).click();

  await expect.poll(() => decision.body).toEqual({
    challenge: 'consent-challenge', granted_optional_scopes: ['profile'],
  });
});

test('consent distinguishes verified and unverified user-registered publishers', async ({ page }) => {
  const decision: { body?: unknown } = {};
  await installConsentMocks(page, decision, { type: 'user_registered', status: 'verified' });
  await page.goto('/consent?challenge=consent-challenge');
	await expect(page.getByText('已验证发布者', { exact: true })).toBeVisible();
	await expect(page.getByText(/此应用已经由 Nya 管理员审核/)).toBeVisible();

  await page.unrouteAll({ behavior: 'wait' });
  await installConsentMocks(page, decision, { type: 'user_registered', status: 'unverified' });
  await page.reload();
	await expect(page.getByText('发布者未验证', { exact: true })).toBeVisible();
	await expect(page.getByText(/Nya 尚未验证此应用的发布者/)).toBeVisible();
});
