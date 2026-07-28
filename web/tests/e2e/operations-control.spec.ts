import { expect, test, type Page, type Route } from '@playwright/test';
import type { OperationsSettings, ServiceStatus } from '../../src/lib/api';

const session = {
  user: {
    id: '11111111-1111-1111-1111-111111111111',
    username: 'admin',
    email: 'admin@example.test',
    display_name: 'Admin',
    role: 'admin',
    status: 'active',
    created_at: '2026-01-01T00:00:00Z',
  },
  csrf_token: 'operations-csrf',
  must_change_password: false,
  has_password: true,
  email_verified: true,
  authenticated_at: '2026-07-28T10:00:00Z',
};

const normalStatus: ServiceStatus = {
  status: 'normal',
  paused_capabilities: [],
  public_message: '',
  expires_at: null,
  retry_after_seconds: 0,
};

const operationsSettings: OperationsSettings = {
  ...normalStatus,
  revision: 7,
  internal_reason: '',
  updated_at: '2026-07-28T10:00:00Z',
  updated_by: session.user.id,
  application_status: 'applied',
  active_instances: 1,
  applied_instances: 1,
  instances: [{
    instance_id: 'instance-a',
    version: '0.4.0-dev',
    started_at: '2026-07-28T09:00:00Z',
    heartbeat_at: '2026-07-28T10:00:00Z',
    loaded_revision: 7,
    applied_revision: 7,
  }],
};

async function json(route: Route, status: number, body: unknown) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function installOperationsMocks(
  page: Page,
  onPut: (route: Route, body: unknown) => Promise<void>,
  options: { providerReauthentication?: boolean } = {},
) {
  let currentSession = options.providerReauthentication ? { ...session, has_password: false } : session;
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/service-status') return json(route, 200, normalStatus);
    if (path === '/api/branding') return json(route, 200, { title: 'Nya', logo_url: '' });
    if (path === '/api/session') return json(route, 200, currentSession);
    if (path === '/api/admin/settings/operations' && route.request().method() === 'GET') return json(route, 200, operationsSettings);
    if (path === '/api/admin/settings/operations' && route.request().method() === 'PUT') {
      return onPut(route, route.request().postDataJSON());
    }
    if (path === '/api/me/identities') return json(route, 200, options.providerReauthentication ? [{
      id: 'identity-github',
      user_id: session.user.id,
      provider: 'github',
      external_id: 'admin-github',
      created_at: '2026-01-01T00:00:00Z',
    }] : []);
    if (path === '/api/me/mfa') return json(route, 200, { passkeys_enrolled: 0 });
    if (path === '/api/me/reauth/password') return json(route, 200, { ...session, authenticated_at: new Date().toISOString() });
    if (path === '/api/me/reauth/github') {
      currentSession = {
        ...currentSession,
        csrf_token: 'operations-provider-reauthenticated',
        authenticated_at: new Date().toISOString(),
      };
      return json(route, 200, { redirect_url: '/admin/settings/operations' });
    }
    return json(route, 404, { error: 'not found' });
  });
}

test('operations preset survives recent reauthentication and sends the revision contract', async ({ page }) => {
  const bodies: unknown[] = [];
  let putCount = 0;
  await installOperationsMocks(page, async (route, body) => {
    bodies.push(body);
    putCount += 1;
    if (putCount === 1) {
      await json(route, 403, { code: 'auth.recent_authentication_required', error: 'recent authentication is required' });
      return;
    }
    const input = body as Record<string, unknown>;
    await json(route, 200, {
      ...operationsSettings,
      revision: 8,
      status: 'authentication_paused',
      paused_capabilities: input.paused_capabilities,
      public_message: input.public_message,
      internal_reason: input.internal_reason,
      expires_at: input.expires_at,
      application_status: 'applying',
    });
  });

  await page.goto('/admin/settings/operations');
  await expect(page.getByRole('heading', { name: '运行控制' })).toBeVisible();
  await page.getByRole('button', { name: '认证维护' }).click();
  await page.getByLabel('公开提示（可选）').fill('认证系统维护中');
  await page.getByLabel('内部原因').fill('rolling authentication maintenance');
  await page.getByRole('button', { name: '应用运行控制' }).click();

  const dialog = page.getByRole('dialog', { name: '重新验证身份' });
  await expect(dialog).toBeVisible();
  await dialog.getByLabel('当前密码').fill('correct horse battery staple');
  await dialog.getByRole('button', { name: '使用密码验证' }).click();

  await expect.poll(() => bodies.length).toBe(2);
  expect(bodies[1]).toMatchObject({
    expected_revision: 7,
    paused_capabilities: ['self_registration', 'account_mutations', 'admin_mutations', 'auth_issuance', 'media_writes'],
    public_message: '认证系统维护中',
    internal_reason: 'rolling authentication maintenance',
  });
});

test('provider reauthentication restores and retries an operations update once', async ({ page }) => {
  const bodies: unknown[] = [];
  const csrfTokens: Array<string | undefined> = [];
  await installOperationsMocks(page, async (route, body) => {
    bodies.push(body);
    csrfTokens.push(route.request().headers()['x-csrf-token']);
    if (bodies.length === 1) {
      await json(route, 403, { code: 'auth.recent_authentication_required', error: 'recent authentication is required' });
      return;
    }
    await json(route, 200, {
      ...operationsSettings,
      ...(body as object),
      revision: 8,
      status: 'restricted',
    });
  }, { providerReauthentication: true });

  await page.goto('/admin/settings/operations');
  await page.getByRole('button', { name: '只读维护' }).click();
  await page.getByLabel('公开提示（可选）').fill('只读维护中');
  await page.getByLabel('内部原因').fill('provider reauthentication regression test');
  await page.getByRole('button', { name: '应用运行控制' }).click();
  await page.getByRole('button', { name: '使用 github 验证' }).click();

  await expect.poll(() => bodies.length).toBe(2);
  expect(bodies[1]).toMatchObject({
    expected_revision: 7,
    paused_capabilities: ['self_registration', 'account_mutations', 'admin_mutations', 'media_writes'],
    public_message: '只读维护中',
    internal_reason: 'provider reauthentication regression test',
  });
  expect(csrfTokens).toEqual(['operations-csrf', 'operations-provider-reauthenticated']);
  expect(await page.evaluate(() => sessionStorage.getItem('nyauth:reauth:operations-settings'))).toBeNull();
});

test('revision conflicts keep the draft and require an explicit reload', async ({ page }) => {
  await installOperationsMocks(page, async (route) => {
    await json(route, 409, { code: 'service_control.revision_conflict', error: 'service control revision conflict' });
  });
  await page.goto('/admin/settings/operations');
  await page.getByRole('button', { name: '只读维护' }).click();
  await page.getByLabel('内部原因').fill('planned read only maintenance');
  await page.getByRole('button', { name: '应用运行控制' }).click();

  await expect(page.getByRole('alert')).toContainText('已被其他管理员修改');
  await expect(page.getByRole('button', { name: '加载最新状态' })).toBeVisible();
  await expect(page.getByLabel('内部原因')).toHaveValue('planned read only maintenance');
});

test('individual capability switches enforce authentication and mail dependencies', async ({ page }) => {
  await installOperationsMocks(page, async (route, body) => {
    await json(route, 200, { ...operationsSettings, ...(body as object), revision: 8 });
  });
  await page.goto('/admin/settings/operations');

  await page.getByRole('switch', { name: '暂停认证签发' }).click();
  await expect(page.getByRole('switch', { name: '暂停自助注册' })).toBeChecked();
  await expect(page.getByRole('status')).toContainText('自助注册也会一并暂停');

  await page.getByRole('switch', { name: '暂停自助注册' }).click();
  await expect(page.getByRole('switch', { name: '暂停认证签发' })).not.toBeChecked();
});

test('public maintenance status updates the UI immediately when the SSE stream reports recovery', async ({ page }) => {
  const paused: ServiceStatus = {
    status: 'authentication_paused',
    paused_capabilities: ['self_registration', 'auth_issuance'],
    public_message: '认证服务升级中',
    expires_at: '2099-07-28T12:00:00Z',
    retry_after_seconds: 60,
  };
  let releaseRecoveryEvent = () => {};
  const recoveryEventReady = new Promise<void>((resolve) => {
    releaseRecoveryEvent = resolve;
  });
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/service-status') return json(route, 200, paused);
    if (path === '/api/service-status/events') {
      await recoveryEventReady;
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store' },
        body: `event: service-status\ndata: ${JSON.stringify(normalStatus)}\n\n`,
      });
      return;
    }
    if (path === '/api/branding') return json(route, 200, { title: 'Nya', logo_url: '' });
    if (path === '/api/session') return json(route, 401, { error: 'authentication required' });
    if (path === '/api/providers') return json(route, 200, [{ name: 'github', type: 'github' }]);
    if (path === '/api/registration') return json(route, 200, { available: false, mode: 'open', require_email_verification: true, allowed_email_domains: [] });
    return json(route, 404, { error: 'not found' });
  });

  await page.goto('/login');
  await expect(page.locator('aside[role="status"]')).toContainText('认证服务升级中');
  await expect(page.getByRole('button', { name: '登录', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'github' })).toBeDisabled();

  releaseRecoveryEvent();
  await expect(page.locator('aside[role="status"]')).toHaveCount(0);
  await expect(page.getByRole('button', { name: '登录', exact: true })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'github' })).toBeEnabled();
});
