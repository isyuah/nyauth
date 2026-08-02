import { expect, test, type Page, type Route } from '@playwright/test';
import { DEFAULT_CLAIM_ASSIGNMENT_POLICIES, DEFAULT_SCOPE_DEFINITIONS } from '../../src/lib/oauth-catalog';

async function json(route: Route, status: number, body: unknown, headers: Record<string, string> = {}) {
  await route.fulfill({ status, contentType: 'application/json', headers, body: JSON.stringify(body) });
}

async function installShellMocks(page: Page) {
  await page.route('**/api/branding', (route) => json(route, 200, { title: 'Nya', primary_color: '#704DE8', primary_text_color: 'auto', light_logo_url: '', dark_logo_url: '', favicon_url: '' }));
  await page.route('**/api/service-status', (route) => json(route, 200, { state: 'normal', paused_capabilities: [], public_message: '', retry_after_seconds: 0 }));
  await page.route('**/api/site-banner', (route) => json(route, 200, { active: false, version: 0 }));
  await page.route('**/api/session', (route) => json(route, 200, {
	user: { id: '11111111-1111-1111-1111-111111111111', username: 'alice', role: 'admin', status: 'active', created_at: '2026-01-01T00:00:00Z' },
    csrf_token: 'device-csrf', must_change_password: false, has_password: true, email_verified: true,
  }));
  await page.route('**/api/admin/settings/oauth', (route) => json(route, 200, {
    revision: 1,
    self_service_client_creation_enabled: true,
    public_clients_enabled: true,
    allowed_grant_types: ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code', 'refresh_token', 'client_credentials'],
    allowed_scopes: ['openid', 'profile', 'email', 'offline_access'],
    scope_definitions: DEFAULT_SCOPE_DEFINITIONS,
    claim_assignment_policies: DEFAULT_CLAIM_ASSIGNMENT_POLICIES,
    max_redirect_uris: 20,
    max_post_logout_redirect_uris: 20,
  }));
}

test('device verification normalizes the user code and opens the shared consent flow', async ({ page }) => {
  await installShellMocks(page);
  let requestBody: unknown;
  let csrf = '';
  await page.route('**/api/device-authorization/prepare', async (route) => {
    requestBody = route.request().postDataJSON();
    csrf = await route.request().headerValue('x-csrf-token') || '';
    await json(route, 200, { consent_url: '/consent?challenge=device-consent' });
  });
  await page.route('**/api/consent?**', (route) => json(route, 200, {
    challenge: 'device-consent', flow: 'device_authorization', client_name: 'Living Room TV', client_id: 'tv-client',
    scopes: ['openid'], permissions: [{ scope: 'openid', display_name: '确认身份', description: '确认您的账户身份。', risk_level: 'low', required: true, claims: ['sub'], previously_granted: false, newly_requested: false }],
    redirect_uri: '', redirect_origin: '', publisher_type: 'system_managed', verification_status: 'not_applicable',
    previously_authorized: false, application_changed: false, reauthorization_required: false, new_scopes: [], new_claims: [],
  }));

  await page.goto('/device?user_code=abcd%20efgh');
	await expect(page.getByRole('textbox', { name: '设备代码', exact: true })).toHaveValue('ABCD-EFGH');
	await page.getByRole('button', { name: '验证并继续' }).click();

  await expect(page).toHaveURL(/\/consent\?challenge=device-consent$/);
  expect(requestBody).toEqual({ user_code: 'ABCD-EFGH' });
  expect(csrf).toBe('device-csrf');
	await expect(page.getByRole('heading', { name: 'Living Room TV' })).toBeVisible();
	await page.getByRole('button', { name: '应用技术信息' }).click();
	await expect(page.getByText('设备代码授权，不会跳转至第三方回调地址')).toBeVisible();
  await expect(page.getByRole('button', { name: '允许设备访问' })).toBeVisible();
});

test('OAuth test console runs the Device Authorization polling protocol', async ({ page }) => {
  await installShellMocks(page);
  let polls = 0;
  await page.route('**/device_authorization', async (route) => {
    const body = new URLSearchParams(route.request().postData() || '');
    expect(body.get('client_id')).toBe('nya-device-test');
    expect(body.get('scope')).toContain('openid');
    await json(route, 200, {
      device_code: 'opaque-device-code', user_code: 'BCDF-2345',
      verification_uri: 'http://localhost:4173/device',
      verification_uri_complete: 'http://localhost:4173/device?user_code=BCDF-2345',
      expires_in: 600, interval: 1,
    });
  });
  await page.route('**/token', async (route) => {
    polls += 1;
    const body = new URLSearchParams(route.request().postData() || '');
    expect(body.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:device_code');
    expect(body.get('device_code')).toBe('opaque-device-code');
    if (polls === 1) {
      await json(route, 400, { error: 'authorization_pending', error_description: 'pending' }, { 'Retry-After': '1' });
      return;
    }
    await json(route, 200, { access_token: 'device-access-token', token_type: 'Bearer', expires_in: 300, scope: 'openid profile email' });
  });

  await page.goto('/admin/oauth/test?flow=device');
  await expect(page.getByRole('button', { name: 'Device Authorization', exact: true })).toBeVisible();
  await page.getByRole('button', { name: '启动 Device Authorization' }).click();
  await expect(page.getByText('BCDF-2345', { exact: true })).toBeVisible();
  await expect(page.getByRole('link', { name: '打开设备验证页' })).toHaveAttribute('target', '_blank');
  await expect(page.getByText('已取得 Token', { exact: true })).toBeVisible({ timeout: 5_000 });
  await expect(page.locator('pre').filter({ hasText: 'device-access-token' })).toBeVisible();
  expect(polls).toBe(2);
});
