import { expect, test, type Page, type Route } from '@playwright/test';
import type {
  ObservabilitySettings,
  SaveOTLPCandidateInput,
  ServiceStatus,
  SessionInfo,
  UpdateObservabilitySettingsInput,
} from '../../src/lib/api';

const normalStatus: ServiceStatus = {
  status: 'normal', paused_capabilities: [], public_message: '', expires_at: null, retry_after_seconds: 0,
};

const session: SessionInfo = {
  user: {
    id: '11111111-1111-4111-8111-111111111111', username: 'admin', email: 'admin@example.test',
    display_name: 'Admin', role: 'admin', status: 'active', created_at: '2026-07-30T00:00:00Z',
  },
  csrf_token: 'observability-csrf', must_change_password: false, has_password: true, email_verified: true,
  authenticated_at: '2026-07-30T01:00:00Z', session_expires_at: '2099-07-30T01:00:00Z',
  recent_authentication_expires_at: '2099-07-30T01:10:00Z',
};

const activeConfig = {
  id: '22222222-2222-4222-8222-222222222222', revision: 2,
  endpoint: 'https://collector.example/v1/metrics', export_interval: '30s', timeout: '5s',
  authorization_configured: true, created_at: '2026-07-30T02:00:00Z',
};

const baseSettings: ObservabilitySettings = {
  revision: 4,
  observability: {
    log_level: 'info', debug_until: null,
    alerts: {
      mail_backlog_count: 100, mail_oldest_pending_age: '15m',
      audit_outbox_backlog_count: 1000, audit_oldest_pending_age: '10m',
      avatar_cleanup_pending_count: 100,
    },
  },
  effective_log_level: 'info',
  otlp: {
    mode: 'active', state_revision: 7, active: activeConfig, effective: activeConfig,
    runtime: {
      configured: true, available: true, last_success_at: '2026-07-30T03:00:00Z',
    },
  },
  alerts: {
    status: 'ok', checked_at: '2026-07-30T03:00:00Z',
    active: [{ code: 'mail_backlog', current: 120, threshold: 100, unit: 'count' }],
  },
};

interface MockOptions {
  policyConflict?: boolean;
  candidateNeedsReauth?: boolean;
  settingsGetNeedsReauth?: boolean;
}

async function json(route: Route, status: number, body: unknown) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function installMocks(page: Page, options: MockOptions = {}) {
  let current = structuredClone(baseSettings);
  let currentSession = structuredClone(session);
  let candidateSaveAttempts = 0;
  let settingsGetAttempts = 0;
  const policyBodies: UpdateObservabilitySettingsInput[] = [];
  const candidateBodies: SaveOTLPCandidateInput[] = [];
  const operations: string[] = [];

  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    if (path === '/api/service-status') return json(route, 200, normalStatus);
    if (path === '/api/branding') return json(route, 200, { title: 'Nya', logo_url: '' });
    if (path === '/api/site-banner') return json(route, 200, { site_banner: null });
    if (path === '/api/site-banner/events') return route.fulfill({ status: 200, contentType: 'text/event-stream', body: 'event: site_banner\ndata: {"site_banner":null}\n\n' });
    if (path === '/api/session') return json(route, 200, currentSession);
    if (path === '/api/admin/settings/protection') return json(route, 200, {
      revision: 1, login: { enabled: true }, account: { enabled: true }, avatar: { enabled: true }, mail: { enabled: true }, owned_client_default_limit: 10,
    });
    if (path === '/api/admin/settings/observability' && method === 'GET') {
      settingsGetAttempts += 1;
      if (options.settingsGetNeedsReauth && settingsGetAttempts === 1) {
        return json(route, 403, { code: 'auth.recent_authentication_required', error: 'recent authentication is required' });
      }
      return json(route, 200, current);
    }
    if (path === '/api/admin/settings/observability' && method === 'PUT') {
      const body = request.postDataJSON() as UpdateObservabilitySettingsInput;
      policyBodies.push(body);
      if (options.policyConflict) return json(route, 409, { code: 'settings.revision_conflict', error: 'settings revision conflict' });
      current = {
        ...current, revision: body.expected_revision + 1, observability: body.observability,
        effective_log_level: body.observability.debug_until ? 'debug' : body.observability.log_level,
      };
      return json(route, 200, current);
    }
    if (path === '/api/admin/settings/observability/otlp/candidate' && method === 'PUT') {
      candidateSaveAttempts += 1;
      const body = request.postDataJSON() as SaveOTLPCandidateInput;
      candidateBodies.push(body);
      if (options.candidateNeedsReauth && candidateSaveAttempts === 1) {
        return json(route, 403, { code: 'auth.recent_authentication_required', error: 'recent authentication is required' });
      }
      const candidate = {
        id: '33333333-3333-4333-8333-333333333333', revision: 3,
        endpoint: body.endpoint, export_interval: body.export_interval, timeout: body.timeout,
        authorization_configured: body.authorization !== '', created_at: '2026-07-30T04:00:00Z',
      };
      current.otlp.candidate = candidate;
      delete current.otlp.candidate_test;
      current.otlp.state_revision += 1;
      return json(route, 201, { candidate, state_revision: current.otlp.state_revision });
    }
    if (path === '/api/admin/settings/observability/otlp/candidate/test' && method === 'POST') {
      operations.push('test');
      current.otlp.state_revision += 1;
      current.otlp.candidate_test = {
        result: 'success', tested_at: '2026-07-30T04:05:00Z', valid_until: '2099-07-30T04:15:00Z', activation_eligible: true,
      };
      return json(route, 200, { result: 'success', state_revision: current.otlp.state_revision, tested_at: '2026-07-30T04:05:00Z' });
    }
    if (path === '/api/admin/settings/observability/otlp/activate' && method === 'POST') {
      operations.push('activate');
      current.otlp.state_revision += 1;
      if (current.otlp.candidate) {
        current.otlp.previous = current.otlp.active;
        current.otlp.active = current.otlp.candidate;
        current.otlp.effective = current.otlp.candidate;
        delete current.otlp.candidate;
        delete current.otlp.candidate_test;
      }
      return json(route, 200, { state_revision: current.otlp.state_revision, mode: 'active' });
    }
    if (path === '/api/admin/settings/observability/otlp/rollback' && method === 'POST') {
      operations.push('rollback');
      current.otlp.state_revision += 1;
      return json(route, 200, { state_revision: current.otlp.state_revision, mode: 'active' });
    }
    if (path === '/api/admin/settings/observability/otlp/disable' && method === 'POST') {
      operations.push('disable');
      current.otlp.state_revision += 1;
      current.otlp.mode = 'disabled';
      current.otlp.runtime = { configured: false, available: false };
      delete current.otlp.effective;
      return json(route, 200, { state_revision: current.otlp.state_revision, mode: 'disabled' });
    }
    if (path === '/api/me/identities') return json(route, 200, []);
    if (path === '/api/me/mfa') return json(route, 200, { passkeys_enrolled: 0 });
    if (path === '/api/me/reauth/password' && method === 'POST') {
      currentSession = { ...currentSession, csrf_token: 'observability-reauth-csrf', authenticated_at: new Date().toISOString() };
      return json(route, 200, currentSession);
    }
    if (path === '/api/admin/system/status') return json(route, 200, {
      status: 'ok', operating_state: 'normal', version: '0.4.0-dev', disabled_rate_limit_groups: [],
      schema: { status: 'ok', version: 9, required_version: 9 },
      services: {
        postgresql: { status: 'ok', latency_ms: 2 }, redis: { status: 'ok', latency_ms: 1 },
        providers: { status: 'ok', latency_ms: 0, snapshot_revision: 3 }, jwk: { status: 'ok', latency_ms: 1 },
        mail: { status: 'ok', mode: 'active', configured: true, available: true, circuit_state: 'closed' },
        media: { status: 'ok', backend: 'local', configured: true },
        observability: { status: 'ok', log_level: 'debug', debug_until: '2026-07-30T05:00:00Z', otlp_mode: 'active', otlp_configured: true, otlp_available: true, last_export_at: '2026-07-30T04:00:00Z' },
      },
      operational_alerts: baseSettings.alerts,
    });
    return json(route, 404, { error: `unmocked request: ${method} ${path}` });
  });

  return {
    policyBodies, candidateBodies, operations,
    candidateSaveAttempts: () => candidateSaveAttempts,
    settingsGetAttempts: () => settingsGetAttempts,
  };
}

test('loading protected observability details can recover through recent authentication', async ({ page }) => {
  const state = await installMocks(page, { settingsGetNeedsReauth: true });
  await page.goto('/admin/settings/observability');
  const dialog = page.getByRole('dialog', { name: '重新验证身份' });
  await expect(dialog).toBeVisible();
  await dialog.getByLabel('当前密码').fill('correct horse battery staple');
  await dialog.getByRole('button', { name: '使用密码验证' }).click();
  await expect.poll(() => state.settingsGetAttempts()).toBe(2);
  await expect(page.getByRole('heading', { name: '日志与临时调试' })).toBeVisible();
});

test('settings tab is active and policy save sends temporary debug with all thresholds', async ({ page }) => {
  const state = await installMocks(page);
  await page.goto('/admin/settings/observability');
  await expect(page.getByRole('link', { name: '可观测性', exact: true })).toHaveAttribute('aria-current', 'page');
  await page.locator('button#observability-log-level').click();
  await page.getByRole('option', { name: 'Warn' }).click();
  await page.getByRole('switch', { name: '启用临时 Debug' }).click();
  await page.locator('#observability-mail-backlog').fill('250');
  await page.getByRole('button', { name: '保存日志与告警设置' }).click();
  await expect(page.getByText('日志级别与运营告警阈值已更新。')).toBeVisible();
  expect(state.policyBodies).toHaveLength(1);
  expect(state.policyBodies[0].observability.log_level).toBe('warn');
  expect(state.policyBodies[0].observability.debug_until).toBeTruthy();
  expect(state.policyBodies[0].observability.alerts.mail_backlog_count).toBe(250);
});

test('candidate secret inheritance, explicit clear, real test, and activation use the exact contract', async ({ page }) => {
  const state = await installMocks(page);
  await page.goto('/admin/settings/observability');
  await page.locator('#observability-otlp-endpoint').fill('https://new-collector.example/v1/metrics');
  await page.getByRole('button', { name: '保存候选' }).click();
  await expect(page.getByText('OTLP 候选配置已保存，请先执行真实连接测试。')).toBeVisible();
  expect(state.candidateBodies[0]).not.toHaveProperty('authorization');
  await expect(page.getByRole('button', { name: '激活候选' })).toBeDisabled();

  await page.getByRole('button', { name: '真实测试' }).click();
  await expect(page.getByText('Collector 真实连接测试成功，候选配置现在可以激活。')).toBeVisible();
  await expect(page.getByText(/最近一次候选测试：成功，可激活/)).toBeVisible();
  await expect(page.getByRole('button', { name: '激活候选' })).toBeEnabled();
  await page.getByRole('button', { name: '激活候选' }).click();
  await page.getByRole('dialog', { name: '激活 OTLP 候选配置' }).getByRole('button', { name: '激活候选' }).click();
  await expect(page.getByText('OTLP 候选配置已激活。')).toBeVisible();
  expect(state.operations).toEqual(['test', 'activate']);

  await page.getByLabel('明确清空 Authorization').check();
  await page.getByRole('button', { name: '保存候选' }).click();
  expect(state.candidateBodies.at(-1)).toHaveProperty('authorization', '');
});

test('password reauthentication retries a secret-free candidate save', async ({ page }) => {
  const state = await installMocks(page, { candidateNeedsReauth: true });
  await page.goto('/admin/settings/observability');
  await page.locator('#observability-otlp-endpoint').fill('https://reauth-collector.example/v1/metrics');
  await page.getByRole('button', { name: '保存候选' }).click();
  const dialog = page.getByRole('dialog', { name: '重新验证身份' });
  await dialog.getByLabel('当前密码').fill('correct horse battery staple');
  await dialog.getByRole('button', { name: '使用密码验证' }).click();
  await expect.poll(() => state.candidateSaveAttempts()).toBe(2);
  await expect(page.getByText('OTLP 候选配置已保存，请先执行真实连接测试。')).toBeVisible();
});

test('CAS conflict keeps the policy draft while loading the latest revision', async ({ page }) => {
  const state = await installMocks(page, { policyConflict: true });
  await page.goto('/admin/settings/observability');
  await page.locator('#observability-mail-backlog').fill('321');
  await page.getByRole('button', { name: '保存日志与告警设置' }).click();
  await expect(page.getByText(/当前草稿已保留/)).toBeVisible();
  await page.getByRole('button', { name: '加载最新 revision' }).click();
  await expect(page.locator('#observability-mail-backlog')).toHaveValue('321');
  expect(state.policyBodies).toHaveLength(1);
});

test('system status shows observability and operational alerts without degrading readiness health', async ({ page }) => {
  await installMocks(page);
  await page.goto('/admin/system');
  await expect(page.getByRole('heading', { name: '运营信号超过告警阈值' })).toBeVisible();
  await expect(page.getByText('邮件队列积压')).toBeVisible();
  await expect(page.getByRole('heading', { name: '可观测性' })).toBeVisible();
  await expect(page.getByText('这些告警用于提示队列或清理任务积压，不代表依赖故障，也不会改变 readiness。')).toBeVisible();
  await expect(page.getByText('0.4.0-dev').locator('..').getByText('正常')).toBeVisible();
});
