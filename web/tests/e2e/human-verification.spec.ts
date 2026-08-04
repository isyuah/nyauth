import { expect, test, type Page, type Route } from '@playwright/test';
import type {
  HumanVerificationPolicy,
  HumanVerificationSettings,
  SaveHumanVerificationCandidateInput,
  ServiceStatus,
  SessionInfo,
} from '../../src/lib/api';

const normalStatus: ServiceStatus = {
  status: 'normal', paused_capabilities: [], public_message: '', expires_at: null, retry_after_seconds: 0,
};

const session: SessionInfo = {
  user: {
    id: '11111111-1111-4111-8111-111111111111', username: 'admin', email: 'admin@example.test',
	display_name: 'Admin', role: 'admin', status: 'active', created_at: '2026-07-31T00:00:00Z',
  },
  csrf_token: 'human-verification-csrf', must_change_password: false, has_password: true, email_verified: true,
  authenticated_at: '2026-07-31T01:00:00Z', session_expires_at: '2099-07-31T01:00:00Z',
  recent_authentication_expires_at: '2099-07-31T01:10:00Z',
};

const policy: HumanVerificationPolicy = {
  registration: false, login_mode: 'adaptive', login_trigger_after: 3,
  password_reset: false, email_verification_resend: false, provider_login: false,
};

const activeVersion = {
  id: '22222222-2222-4222-8222-222222222222', revision: 1,
  provider: 'turnstile' as const, site_key: 'active-site-key', widget_mode: 'managed' as const,
  secret_configured: true, created_at: '2026-07-31T01:00:00Z',
};

const baseSettings: HumanVerificationSettings = {
  mode: 'active', active_version_id: activeVersion.id, candidate_version_id: null, previous_version_id: null,
  policy, revision: 4, updated_at: '2026-07-31T01:00:00Z', active: activeVersion,
  candidate: null, previous: null, candidate_last_test: null,
  runtime: { mode: 'active', configured: true, available: true, provider: 'turnstile', state_revision: 4 },
};

async function json(route: Route, status: number, body: unknown) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function installTurnstileStub(page: Page) {
  await page.route('https://challenges.cloudflare.com/turnstile/v0/api.js**', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/javascript',
      body: `window.turnstile = {
        render: function (_container, options) {
          window.__nyauthTurnstileRenders = window.__nyauthTurnstileRenders || [];
          window.__nyauthTurnstileRenders.push({ appearance: options.appearance, action: options.action });
          setTimeout(function () { options.callback('playwright-turnstile-token'); }, 0);
          return 'playwright-widget';
        },
        reset: function () {},
        remove: function () {}
      };`,
    });
  });
}

async function installCommonMocks(page: Page) {
  await page.addInitScript(() => {
    class QuietEventSource {
      addEventListener() {}
      close() {}
    }
    Object.defineProperty(window, 'EventSource', { configurable: true, value: QuietEventSource });
  });
  await page.route('**/api/service-status', (route) => json(route, 200, normalStatus));
  await page.route('**/api/branding', (route) => json(route, 200, { title: 'Nya', primary_color: '#704DE8', primary_text_color: 'auto', light_logo_url: '', dark_logo_url: '', favicon_url: '' }));
  await page.route('**/api/site-banner', (route) => json(route, 200, { site_banner: null }));
  await page.route('**/api/notifications/unread-count', (route) => json(route, 200, {
    unread_count: 0,
    notification_count: 0,
    announcement_count: 0,
  }));
  await page.route('**/api/site-banner/events', (route) => route.fulfill({
    status: 200, contentType: 'text/event-stream', body: 'event: site_banner\ndata: {"site_banner":null}\n\n',
  }));
}

test('administrator saves, verifies, and activates a Turnstile candidate', async ({ page }) => {
  await installTurnstileStub(page);
  await installCommonMocks(page);
  let settings = structuredClone(baseSettings);
  const candidateBodies: SaveHumanVerificationCandidateInput[] = [];
  const testBodies: unknown[] = [];
  const activationBodies: unknown[] = [];

  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    if (path === '/api/session') return json(route, 200, session);
    if (path === '/api/admin/settings/protection') return json(route, 200, {
      revision: 1, login: { enabled: true }, account: { enabled: true }, avatar: { enabled: true }, mail: { enabled: true }, owned_client_default_limit: 10,
    });
    if (path === '/api/admin/settings/human-verification' && method === 'GET') return json(route, 200, settings);
    if (path === '/api/admin/settings/human-verification/candidate' && method === 'PUT') {
      expect(request.headers()['x-csrf-token']).toBe('human-verification-csrf');
      const body = request.postDataJSON() as SaveHumanVerificationCandidateInput;
      candidateBodies.push(body);
      const candidate = {
        id: '33333333-3333-4333-8333-333333333333', revision: 2,
        provider: 'turnstile' as const, site_key: body.site_key, widget_mode: body.widget_mode,
        secret_configured: true, created_at: new Date().toISOString(),
      };
      settings = {
        ...settings, revision: 5, candidate_version_id: candidate.id, candidate,
        candidate_last_test: null, updated_at: new Date().toISOString(),
      };
      return json(route, 200, { version: candidate, state: settings });
    }
    if (path === '/api/admin/settings/human-verification/candidate/test' && method === 'POST') {
      expect(request.headers()['x-csrf-token']).toBe('human-verification-csrf');
      const body = request.postDataJSON();
      testBodies.push(body);
      const record = {
        id: '44444444-4444-4444-8444-444444444444', version_id: settings.candidate!.id,
        result: 'success' as const, error_code: null, tested_by: session.user.id, created_at: new Date().toISOString(),
      };
      settings = { ...settings, revision: 6, candidate_last_test: record, updated_at: new Date().toISOString() };
      return json(route, 200, { record, state: settings });
    }
    if (path === '/api/admin/settings/human-verification/activate' && method === 'POST') {
      expect(request.headers()['x-csrf-token']).toBe('human-verification-csrf');
      activationBodies.push(request.postDataJSON());
      settings = {
        ...settings, revision: 7, previous: settings.active, previous_version_id: settings.active!.id,
        active: settings.candidate, active_version_id: settings.candidate!.id,
        candidate: null, candidate_version_id: null, candidate_last_test: null,
        runtime: { mode: 'active', configured: true, available: true, provider: 'turnstile', state_revision: 7 },
      };
      return json(route, 200, settings);
    }
    if (path === '/api/admin/settings/human-verification/disable' && method === 'POST') {
      const body = request.postDataJSON() as { expected_revision: number };
      expect(body.expected_revision).toBe(7);
      settings = {
        ...settings, mode: 'disabled', revision: 8, updated_at: new Date().toISOString(),
        runtime: { mode: 'disabled', configured: true, available: true, provider: 'turnstile', state_revision: 8 },
      };
      return json(route, 200, settings);
    }
    if (path === '/api/admin/settings/human-verification/enable' && method === 'POST') {
      const body = request.postDataJSON() as { expected_revision: number };
      expect(body.expected_revision).toBe(8);
      settings = {
        ...settings, mode: 'active', revision: 9, updated_at: new Date().toISOString(),
        runtime: { mode: 'active', configured: true, available: true, provider: 'turnstile', state_revision: 9 },
      };
      return json(route, 200, settings);
    }
    if (path === '/api/me/identities') return json(route, 200, []);
    if (path === '/api/me/mfa') return json(route, 200, { passkeys_enrolled: 0 });
    return route.fallback();
  });

  await page.goto('/admin/settings/human-verification');
  await expect(page.getByRole('link', { name: '人机验证', exact: true })).toHaveAttribute('aria-current', 'page');
  await page.getByRole('button', { name: '查看“自助注册”说明' }).hover();
  await expect(page.getByRole('tooltip')).toContainText('保护公开注册提交');
  await page.locator('#human-site-key').fill('candidate-site-key');
  await page.getByRole('button', { name: '保存候选' }).click();
  await expect(page.getByText('候选配置已保存，请完成真实验证后再激活。')).toBeVisible();
  expect(candidateBodies).toHaveLength(1);
  expect(candidateBodies[0]).not.toHaveProperty('secret');

  await expect.poll(() => page.evaluate(() => (window as typeof window & { __nyauthTurnstileRenders?: Array<{ appearance: string }> }).__nyauthTurnstileRenders?.at(-1)?.appearance)).toBe('interaction-only');
  await expect(page.getByRole('button', { name: '发送验证测试' })).toBeEnabled();
  await page.getByRole('button', { name: '发送验证测试' }).click();
  await expect(page.getByText('候选配置验证成功，可在十分钟内激活。')).toBeVisible();
  expect(testBodies).toHaveLength(1);
  expect(testBodies[0]).toMatchObject({
    expected_revision: 5, version_id: '33333333-3333-4333-8333-333333333333',
    token: 'playwright-turnstile-token',
  });

  const activate = page.getByRole('button', { name: '激活候选与策略' });
  await expect(activate).toBeEnabled();
  await activate.click();
  await expect(page.getByText('人机验证配置与策略已激活。')).toBeVisible();
  expect(activationBodies).toHaveLength(1);

  await page.getByRole('button', { name: '禁用人机验证' }).click();
  await expect(page.getByRole('button', { name: '复制确认文本' })).toBeVisible();
  await page.getByRole('textbox', { name: '输入“DISABLE HUMAN VERIFICATION”以确认', exact: true }).fill('DISABLE HUMAN VERIFICATION');
  await page.getByRole('button', { name: '确认禁用' }).click();
  await expect(page.getByText('人机验证已禁用。')).toBeVisible();
  await expect(page.getByText('Cloudflare Turnstile').first()).toBeVisible();
  await expect(page.locator('#human-site-key')).toHaveValue('candidate-site-key');

  await page.getByRole('button', { name: '重新启用' }).click();
  await page.getByRole('button', { name: '确认启用' }).click();
  await expect(page.getByText('人机验证已重新启用。')).toBeVisible();
});

test('adaptive login renders a challenge after 428 and retries with the one-time proof', async ({ page }) => {
  await installTurnstileStub(page);
  await installCommonMocks(page);
  const loginBodies: Array<Record<string, unknown>> = [];

  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    if (path === '/api/session') return json(route, 401, { code: 'auth.authentication_required', error: 'authentication required' });
    if (path === '/api/providers') return json(route, 200, []);
    if (path === '/api/registration') return json(route, 200, { available: false, mode: 'closed', require_email_verification: true, allowed_email_domains: [] });
    if (path === '/api/human-verification') return json(route, 200, {
      enabled: true, required: false, available: true, provider: 'turnstile', site_key: 'login-site-key',
      widget_mode: 'managed', action: url.searchParams.get('action'),
    });
    if (path === '/api/login' && request.method() === 'POST') {
      const body = request.postDataJSON() as Record<string, unknown>;
      loginBodies.push(body);
      if (loginBodies.length === 1) return json(route, 428, {
        code: 'human_verification.required', error: 'human verification is required',
        challenge: {
          enabled: true, required: true, available: true, provider: 'turnstile', site_key: 'login-site-key',
          widget_mode: 'managed', action: 'login',
        },
      });
      return json(route, 401, { code: 'auth.invalid_credentials', error: 'invalid credentials' });
    }
    return route.fallback();
  });

  await page.goto('/login');
  await page.getByLabel('用户名').fill('alice');
  await page.getByLabel('密码').fill('wrong-password-123');
  await page.getByRole('button', { name: '登录', exact: true }).click();
  await expect(page.getByTestId('human-verification-widget')).toBeAttached();
  await expect(page.getByTestId('human-verification-widget')).toHaveAttribute('data-widget-mode', 'managed');
  await expect.poll(() => page.evaluate(() => (window as typeof window & { __nyauthTurnstileRenders?: Array<{ appearance: string }> }).__nyauthTurnstileRenders?.at(-1)?.appearance)).toBe('interaction-only');
  await page.getByRole('button', { name: '登录', exact: true }).click();
  await expect.poll(() => loginBodies.length).toBe(2);
  expect(loginBodies[0]).not.toHaveProperty('human_verification');
  expect(loginBodies[1].human_verification).toMatchObject({ token: 'playwright-turnstile-token' });
});
