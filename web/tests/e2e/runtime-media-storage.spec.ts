import { expect, test, type Page, type Route } from '@playwright/test';
import type { MediaStorageMigration, MediaStorageProfile, MediaStorageSettings, ServiceStatus } from '../../src/lib/api';

const profileID = '22222222-2222-2222-2222-222222222222';
const migrationID = '33333333-3333-3333-3333-333333333333';

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
  csrf_token: 'media-csrf',
  must_change_password: false,
  has_password: true,
  email_verified: true,
  authenticated_at: '2026-07-29T01:00:00Z',
};

const normalStatus: ServiceStatus = {
  status: 'normal',
  paused_capabilities: [],
  public_message: '',
  expires_at: null,
  retry_after_seconds: 0,
};

const profile: MediaStorageProfile = {
  id: profileID,
  backend: 's3',
  settings: {
    endpoint: 'https://s3.example.test',
    region: 'auto',
    bucket: 'private-media',
    prefix: 'nyauth',
    path_style: true,
  },
  credentials_configured: true,
  session_token_configured: false,
  created_by: session.user.id,
  created_by_name: session.user.username,
  created_at: '2026-07-29T01:05:00Z',
};

function migration(status: MediaStorageMigration['status']): MediaStorageMigration {
  return {
    id: migrationID,
    source_backend: 'local',
    target_profile_id: profileID,
    status,
    total_count: 4,
    copied_count: status === 'failed' ? 2 : status === 'pending' ? 0 : 4,
    completed_count: status === 'failed' ? 2 : status === 'pending' ? 0 : 4,
    failed_count: status === 'failed' ? 1 : 0,
    created_by: session.user.id,
    created_by_name: session.user.username,
    created_at: '2026-07-29T01:10:00Z',
    updated_at: '2026-07-29T01:11:00Z',
    last_error: status === 'failed' ? 'storage connectivity test failed' : undefined,
  };
}

async function json(route: Route, status: number, body: unknown) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

interface MediaMockOptions {
  initial?: MediaStorageSettings;
  reauthentication?: 'password' | 'provider';
}

async function installMediaMocks(page: Page, options: MediaMockOptions = {}) {
  let currentSession = options.reauthentication === 'provider' ? { ...session, has_password: false } : session;
  let current: MediaStorageSettings = options.initial ?? {
    mode: 'fallback',
    revision: 1,
    available: true,
    active: { backend: 'local', credentials_configured: true },
  };
  let saveAttempts = 0;
  let applyingReads = 0;
  let retryCount = 0;
  const saveBodies: Array<Record<string, unknown>> = [];

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();
    if (path === '/api/service-status') return json(route, 200, normalStatus);
    if (path === '/api/branding') return json(route, 200, { title: 'Nya', logo_url: '' });
    if (path === '/api/session') return json(route, 200, currentSession);
    if (path === '/api/admin/settings/protection') {
      return json(route, 200, {
        revision: 1,
        login: { enabled: true }, account: { enabled: true },
        avatar: { enabled: true }, mail: { enabled: true },
        owned_client_default_limit: 10,
      });
    }
    if (path === '/api/admin/settings/media' && method === 'GET') {
      if (current.migration?.status === 'applying') {
        applyingReads += 1;
        if (applyingReads > 1) {
          current = {
            ...current,
            mode: 'dynamic',
            active: { ...profile, test_result: 'success' },
            candidate: undefined,
            migration: migration('completed'),
          };
        }
      }
      return json(route, 200, current);
    }
    if (path === '/api/admin/settings/media/candidate' && method === 'PUT') {
      saveAttempts += 1;
      const body = route.request().postDataJSON() as Record<string, unknown>;
      saveBodies.push(body);
      if (options.reauthentication && saveAttempts === 1) {
        return json(route, 403, { code: 'auth.recent_authentication_required', error: 'recent authentication is required' });
      }
      current = { ...current, revision: 2, candidate: profile };
      return json(route, 201, { candidate: profile, revision: 2 });
    }
    if (path === '/api/admin/settings/media/candidate/test' && method === 'POST') {
      const tested = { ...profile, test_result: 'success' as const, tested_at: '2026-07-29T01:06:00Z' };
      current = { ...current, revision: 3, candidate: tested };
      return json(route, 200, { candidate: tested, revision: 3, result: 'success' });
    }
    if (path === '/api/admin/settings/media/migrations' && method === 'POST') {
      current = { ...current, migration: migration('applying') };
      applyingReads = 0;
      return json(route, 202, { migration: current.migration, revision: current.revision });
    }
    if (path === `/api/admin/settings/media/migrations/${migrationID}/retry` && method === 'POST') {
      retryCount += 1;
      current = { ...current, migration: migration('running') };
      return json(route, 202, { migration: current.migration });
    }
    if (path === '/api/me/identities') {
      return json(route, 200, options.reauthentication === 'provider' ? [{
        id: 'identity-github', user_id: session.user.id, provider: 'github',
        external_id: 'admin-github', created_at: '2026-01-01T00:00:00Z',
      }] : []);
    }
    if (path === '/api/me/mfa') return json(route, 200, { passkeys_enrolled: 0 });
    if (path === '/api/me/reauth/password') {
      currentSession = { ...currentSession, authenticated_at: new Date().toISOString() };
      return json(route, 200, currentSession);
    }
    if (path === '/api/me/reauth/github') {
      currentSession = {
        ...currentSession,
        csrf_token: 'media-provider-reauthenticated',
        authenticated_at: new Date().toISOString(),
      };
      return json(route, 200, { redirect_url: '/admin/settings/media' });
    }
    return json(route, 404, { error: 'not found' });
  });

  return {
    saveBodies,
    saveAttempts: () => saveAttempts,
    retryCount: () => retryCount,
  };
}

async function fillCandidate(page: Page) {
  await page.getByRole('textbox', { name: 'Endpoint（AWS S3 可留空）' }).fill('https://s3.example.test');
  await page.getByLabel('私有 Bucket').fill('private-media');
  await page.getByLabel('Access Key ID').fill('browser-access-key');
  await page.getByLabel('Secret Access Key').fill('browser-secret-key');
}

test('saves, tests and migrates a private S3 candidate without rendering credentials', async ({ page }) => {
  const state = await installMediaMocks(page);
  await page.goto('/admin/settings/media');
  await expect(page.getByRole('heading', { name: '媒体存储' })).toBeVisible();
  await fillCandidate(page);
  await page.getByRole('button', { name: '保存候选配置' }).click();

  await expect.poll(() => state.saveBodies.length).toBe(1);
  expect(state.saveBodies[0]).toMatchObject({
    expected_revision: 1,
    access_key_id: 'browser-access-key',
    secret_access_key: 'browser-secret-key',
  });
  await expect(page.getByText('候选：private-media / nyauth')).toBeVisible();
  await expect(page.getByText('browser-secret-key')).toHaveCount(0);

  await page.getByRole('button', { name: '真实读写测试' }).click();
  await expect(page.getByText('测试通过')).toBeVisible();
  await page.getByRole('button', { name: '排空并开始迁移' }).click();
  const dialog = page.getByRole('dialog', { name: '迁移媒体存储' });
  await dialog.getByLabel('输入“迁移媒体存储”以确认').fill('迁移媒体存储');
  await dialog.getByRole('button', { name: '开始迁移' }).click();

  await expect(page.getByText('applying', { exact: true })).toBeVisible();
  await expect(page.getByText('completed', { exact: true })).toBeVisible({ timeout: 6_000 });
  await expect(page.getByText('运行时配置')).toBeVisible();
});

test('retries a failed migration without replacing the candidate profile', async ({ page }) => {
  const failed = migration('failed');
  const state = await installMediaMocks(page, {
    initial: {
      mode: 'fallback', revision: 3, available: true,
      active: { backend: 'local', credentials_configured: true },
      candidate: { ...profile, test_result: 'success' }, migration: failed,
    },
  });
  await page.goto('/admin/settings/media');
  await expect(page.getByText('迁移暂停：storage connectivity test failed')).toBeVisible();
  await page.getByRole('button', { name: '重试失败项' }).click();
  await expect.poll(() => state.retryCount()).toBe(1);
  await expect(page.getByText('running', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '重试失败项' })).toHaveCount(0);
});

test('password reauthentication retries the original candidate save with its credentials', async ({ page }) => {
  const state = await installMediaMocks(page, { reauthentication: 'password' });
  await page.goto('/admin/settings/media');
  await fillCandidate(page);
  await page.getByRole('button', { name: '保存候选配置' }).click();

  const dialog = page.getByRole('dialog', { name: '重新验证身份' });
  await expect(dialog).toBeVisible();
  await dialog.getByLabel('当前密码').fill('correct horse battery staple');
  await dialog.getByRole('button', { name: '使用密码验证' }).click();

  await expect.poll(() => state.saveBodies.length).toBe(2);
  expect(state.saveBodies[1]).toMatchObject({
    expected_revision: 1,
    access_key_id: 'browser-access-key',
    secret_access_key: 'browser-secret-key',
  });
  await expect(page.getByText('候选：private-media / nyauth')).toBeVisible();
});

test('provider reauthentication never persists or automatically resubmits S3 credentials', async ({ page }) => {
  const state = await installMediaMocks(page, { reauthentication: 'provider' });
  await page.goto('/admin/settings/media');
  await fillCandidate(page);
  await page.getByRole('button', { name: '保存候选配置' }).click();

  const dialog = page.getByRole('dialog', { name: '重新验证身份' });
  await dialog.getByRole('button', { name: '使用 github 验证' }).click();
  await expect(page).toHaveURL(/\/admin\/settings\/media$/);
  await expect(page.getByText('身份验证已完成；凭据不会跨跳转保存，请重新输入后保存。')).toBeVisible();
  expect(state.saveAttempts()).toBe(1);
  await expect(page.getByLabel('Access Key ID')).toHaveValue('');
  await expect(page.getByLabel('Secret Access Key')).toHaveValue('');
  expect(await page.evaluate(() => sessionStorage.getItem('nyauth:reauth:media-settings'))).toBeNull();
});
