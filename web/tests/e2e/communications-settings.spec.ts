import { expect, test, type Page, type Route } from '@playwright/test';
import type {
  CommunicationsSettings,
  PublicSiteBannerResponse,
  ServiceStatus,
  SessionInfo,
  UpdateCommunicationsSettingsInput,
} from '../../src/lib/api';

const normalStatus: ServiceStatus = {
  status: 'normal', paused_capabilities: [], public_message: '', expires_at: null, retry_after_seconds: 0,
};

const session: SessionInfo = {
  user: {
    id: '11111111-1111-1111-1111-111111111111',
    username: 'admin',
    email: 'admin@example.test',
    display_name: 'Admin',
    role: 'admin',
    status: 'active',
    created_at: '2026-07-29T00:00:00Z',
  },
  csrf_token: 'communications-csrf',
  must_change_password: false,
  has_password: true,
  email_verified: true,
  authenticated_at: '2026-07-29T01:00:00Z',
  session_expires_at: '2099-07-30T01:00:00Z',
  recent_authentication_expires_at: '2099-07-29T01:10:00Z',
};

const communications: CommunicationsSettings = {
  revision: 4,
  email: {
    footer: '由 {{site_name}} 自动发送。',
    templates: {
      'account.email_verification': {
        subject: '[{{site_name}}] 验证邮箱',
        heading: '验证你的邮箱',
        body: '你好，{{username}}。请完成验证。',
        button_label: '验证邮箱',
      },
      'account.password_changed': {
        subject: '[{{site_name}}] 密码已修改',
        heading: '密码已修改',
        body: '你的密码刚刚被修改。',
      },
    },
  },
  site_banner: {
    version: 2,
    enabled: false,
    severity: 'info',
    title: '',
    message: '',
    dismissible: true,
    starts_at: null,
    ends_at: null,
  },
  template_variables: {
    'account.email_verification': {
      subject: ['site_name'], heading: [], body: ['site_name', 'username'], button_label: [], required_body: [],
    },
    'account.password_changed': {
      subject: ['site_name'], heading: [], body: ['site_name'], button_label: [], required_body: [],
    },
  },
};

interface MockOptions {
  siteBanner?: PublicSiteBannerResponse;
  communications?: CommunicationsSettings;
  saveConflict?: boolean;
  reauthenticateTestWith?: 'password' | 'provider';
  verifiedEmail?: boolean;
}

async function json(route: Route, status: number, body: unknown) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function installMocks(page: Page, options: MockOptions = {}) {
  let current = options.communications ?? structuredClone(communications);
  let publicSiteBanner = options.siteBanner ?? { site_banner: null };
  let currentSession = {
    ...session,
    has_password: options.reauthenticateTestWith === 'provider' ? false : session.has_password,
    email_verified: options.verifiedEmail ?? session.email_verified,
  };
  let testAttempts = 0;
  const saveBodies: UpdateCommunicationsSettingsInput[] = [];
  const previewBodies: unknown[] = [];
  const testBodies: unknown[] = [];

  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    if (path === '/api/service-status') return json(route, 200, normalStatus);
    if (path === '/api/branding') return json(route, 200, { title: 'Nya', primary_color: '#704DE8', primary_text_color: 'auto', light_logo_url: '', dark_logo_url: '', favicon_url: '' });
    if (path === '/api/site-banner') return json(route, 200, publicSiteBanner);
    if (path === '/api/site-banner/events') {
      return route.fulfill({
        status: 200,
        contentType: 'text/event-stream',
        headers: { 'Cache-Control': 'no-store' },
        body: `event: site_banner\ndata: ${JSON.stringify(publicSiteBanner)}\n\n`,
      });
    }
    if (path === '/api/session') return json(route, 200, currentSession);
    if (path === '/api/admin/settings/protection') {
      return json(route, 200, {
        revision: 1,
        login: { enabled: true }, account: { enabled: true }, avatar: { enabled: true }, mail: { enabled: true },
        owned_client_default_limit: 10,
      });
    }
    if (path === '/api/admin/settings/communications' && method === 'GET') return json(route, 200, current);
    if (path === '/api/admin/settings/communications' && method === 'PUT') {
      const body = request.postDataJSON() as UpdateCommunicationsSettingsInput;
      saveBodies.push(body);
      if (options.saveConflict) return json(route, 409, { code: 'settings.revision_conflict', error: 'settings revision conflict' });
      current = { ...body, revision: body.expected_revision + 1, template_variables: current.template_variables };
      return json(route, 200, current);
    }
    if (path === '/api/admin/settings/communications/site-banner/preview' && method === 'POST') {
      const body = request.postDataJSON() as { message: string };
      return json(route, 200, { html: `<p>${body.message || '横幅正文支持 Markdown。'}</p>` });
    }
    if (path === '/api/admin/settings/communications/email/preview' && method === 'POST') {
      previewBodies.push(request.postDataJSON());
      return json(route, 200, {
        subject: '[Nya] 验证邮箱',
        text_body: 'Nya 账户安全\n\n验证你的邮箱\n\n你好，示例用户。',
        html_body: '<!doctype html><html><body><h1>验证你的邮箱</h1><p>你好，示例用户。</p></body></html>',
      });
    }
    if (path === '/api/admin/settings/communications/email/test' && method === 'POST') {
      testAttempts += 1;
      testBodies.push(request.postDataJSON());
      if (options.reauthenticateTestWith && testAttempts === 1) {
        return json(route, 403, { code: 'auth.recent_authentication_required', error: 'recent authentication is required' });
      }
      return json(route, 200, { status: 'sent' });
    }
    if (path === '/api/me/identities') {
      return json(route, 200, options.reauthenticateTestWith === 'provider' ? [{
        id: 'identity-github', user_id: session.user.id, provider: 'github', external_id: 'admin-github', created_at: '2026-01-01T00:00:00Z',
      }] : []);
    }
    if (path === '/api/me/mfa') return json(route, 200, { passkeys_enrolled: 0 });
    if (path === '/api/me/reauth/password' && method === 'POST') {
      currentSession = { ...currentSession, csrf_token: 'communications-reauth-csrf', authenticated_at: new Date().toISOString() };
      return json(route, 200, currentSession);
    }
    if (path === '/api/me/reauth/github' && method === 'POST') {
      currentSession = { ...currentSession, csrf_token: 'communications-provider-csrf', authenticated_at: new Date().toISOString() };
      return json(route, 200, { redirect_url: '/admin/settings/communications' });
    }
    return json(route, 404, { error: `unmocked request: ${method} ${path}` });
  });

  return {
    saveBodies,
    previewBodies,
    testBodies,
    testAttempts: () => testAttempts,
    setPublicSiteBanner(value: PublicSiteBannerResponse) { publicSiteBanner = value; },
  };
}

test('site banner events appear and disappear without reloading the page', async ({ page }) => {
  await page.addInitScript(() => {
    const listeners: EventListenerOrEventListenerObject[] = [];
    class ControlledEventSource {
      addEventListener(type: string, listener: EventListenerOrEventListenerObject) {
        if (type === 'site_banner') {
          listeners.push(listener);
          Object.defineProperty(window, '__siteBannerListenerReady', { configurable: true, value: true });
        }
      }

      close() {}
    }
    Object.defineProperty(window, 'EventSource', { configurable: true, value: ControlledEventSource });
    Object.defineProperty(window, '__emitSiteBanner', {
      configurable: true,
      value: (payload: unknown) => {
        const event = new MessageEvent('site_banner', { data: JSON.stringify(payload) });
        for (const listener of listeners) {
          if (typeof listener === 'function') listener(event);
          else listener.handleEvent(event);
        }
      },
    });
  });
  await installMocks(page, { siteBanner: { site_banner: null } });
  await page.goto('/login');
  await expect.poll(() => page.evaluate(() => Boolean((window as typeof window & { __siteBannerListenerReady?: boolean }).__siteBannerListenerReady))).toBe(true);
  await page.evaluate(() => {
    (window as typeof window & { __emitSiteBanner: (payload: unknown) => void }).__emitSiteBanner({
      site_banner: {
        version: 10,
        severity: 'critical',
        title: '紧急通知',
        message_html: '<p>认证服务将在稍后维护。</p>',
        dismissible: false,
      },
    });
  });
  await expect(page.getByText('紧急通知')).toBeVisible();
  await page.evaluate(() => {
    (window as typeof window & { __emitSiteBanner: (payload: unknown) => void }).__emitSiteBanner({ site_banner: null });
  });
  await expect(page.getByText('紧急通知')).toHaveCount(0);
});

test('dismissal is retained for the current version and reset by a new version', async ({ page }) => {
  const state = await installMocks(page, {
    siteBanner: {
      site_banner: { version: 20, severity: 'info', title: '使用提示', message_html: '<p>欢迎使用 Nya。</p>', dismissible: true },
    },
  });
  await page.goto('/login');
  await expect(page.getByText('使用提示')).toBeVisible();
  await page.getByRole('button', { name: '关闭全站横幅' }).click();
  await expect(page.getByText('使用提示')).toHaveCount(0);

  await page.reload();
  await expect(page.getByText('使用提示')).toHaveCount(0);
  state.setPublicSiteBanner({
    site_banner: { version: 21, severity: 'info', title: '新的提示', message_html: '<p>横幅内容已更新。</p>', dismissible: true },
  });
  await page.reload();
  await expect(page.getByText('新的提示')).toBeVisible();
});

test('edits, previews, tests, and saves a structured email template', async ({ page }) => {
  const state = await installMocks(page);
  await page.goto('/admin/settings/communications');
  await expect(page.getByRole('heading', { name: '沟通设置', exact: true })).toBeVisible();
  await page.getByRole('tab', { name: '邮件模板' }).click();
  await expect(page.getByRole('button', { name: '在邮件主题插入变量 site_name' })).toBeVisible();
  await expect(page.getByRole('button', { name: '在邮件主题插入变量 username' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: '在正文插入变量 username' })).toBeVisible();
  await expect(page.getByText('此字段不支持变量')).toHaveCount(2);
  await page.getByRole('textbox', { name: '邮件主题', exact: true }).fill('[{{site_name}}] 请验证邮箱');
  await page.getByRole('button', { name: '生成预览' }).click();
  await expect.poll(() => state.previewBodies.length).toBe(1);
  const frame = page.getByTitle('验证邮箱 HTML 邮件预览');
  await expect(frame).toHaveAttribute('sandbox', '');
  await expect(frame).toHaveAttribute('srcdoc', /验证你的邮箱/);
  await page.getByRole('button', { name: '纯文本' }).click();
  await expect(page.getByText('Nya 账户安全')).toBeVisible();

  await expect(page.getByLabel('测试收件人')).toHaveValue('admin@example.test');
  await expect(page.getByLabel('测试收件人')).toHaveAttribute('readonly');
  await page.getByRole('button', { name: '发送测试邮件' }).click();
  await expect.poll(() => state.testBodies.length).toBe(1);
  expect(state.testBodies[0]).toMatchObject({ template_id: 'account.email_verification', recipient: 'admin@example.test' });

  await page.getByRole('button', { name: '保存沟通设置' }).click();
  await expect.poll(() => state.saveBodies.length).toBe(1);
  expect(state.saveBodies[0].expected_revision).toBe(4);
  expect(state.saveBodies[0].email.templates['account.email_verification'].subject).toBe('[{{site_name}}] 请验证邮箱');
});

test('normalizes null variable arrays before switching templates and saving', async ({ page }) => {
  const withNullArrays = structuredClone(communications) as unknown as {
    template_variables: Record<string, {
      heading: string[] | null;
      button_label: string[] | null;
      required_body: string[] | null;
    }>;
  };
  withNullArrays.template_variables['account.email_verification'].heading = null;
  withNullArrays.template_variables['account.email_verification'].button_label = null;
  withNullArrays.template_variables['account.email_verification'].required_body = null;
  const state = await installMocks(page, { communications: withNullArrays as unknown as CommunicationsSettings });
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));

  await page.goto('/admin/settings/communications');
  await page.getByRole('tab', { name: '邮件模板' }).click();
  await expect(page.getByLabel('邮件类型')).toBeVisible();
  await page.getByRole('button', { name: '保存沟通设置' }).click();
  await expect.poll(() => state.saveBodies.length).toBe(1);
  expect(pageErrors).toEqual([]);
});

test('uses Markdown links and the custom schedule range picker for site banners', async ({ page }) => {
  await installMocks(page);
  await page.goto('/admin/settings/communications');
  await expect(page.getByLabel('链接文字')).toHaveCount(0);
  await expect(page.getByLabel('链接地址')).toHaveCount(0);
  await page.getByLabel('横幅正文（Markdown）').fill('维护期间请查看 [状态页](/status)。');
  await expect(page.getByText('维护期间请查看 [状态页](/status)。')).toBeVisible();

  await page.getByRole('button', { name: '展示时间（可选）' }).click();
  const dialog = page.getByRole('dialog', { name: '设置展示时间' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('button', { name: '最近 1 天' })).toHaveCount(0);
  await expect(dialog.getByRole('checkbox', { name: '不设置结束时间' })).toBeVisible();
});

test('supports all four site banner schedule boundaries', async ({ page }) => {
  const state = await installMocks(page);
  await page.goto('/admin/settings/communications');

  const openSchedule = async () => {
    await page.getByRole('button', { name: '展示时间（可选）' }).click();
    return page.getByRole('dialog', { name: '设置展示时间' });
  };
  const save = async (expectedCount: number) => {
    await page.getByRole('button', { name: '保存沟通设置' }).click();
    await expect.poll(() => state.saveBodies.length).toBe(expectedCount);
    return state.saveBodies[expectedCount - 1].site_banner;
  };

  let dialog = await openSchedule();
  await dialog.getByRole('checkbox', { name: /立即开始/ }).uncheck();
  await dialog.locator('button[aria-current="date"]').click();
  await dialog.getByRole('button', { name: '确认并应用' }).click();
  let saved = await save(1);
  expect(saved.starts_at).not.toBeNull();
  expect(saved.ends_at).toBeNull();

  dialog = await openSchedule();
  await dialog.getByRole('checkbox', { name: /立即开始/ }).check();
  await dialog.getByRole('checkbox', { name: /持续到手动停用/ }).uncheck();
  await dialog.locator('button[aria-current="date"]').click();
  await dialog.getByRole('button', { name: '确认并应用' }).click();
  saved = await save(2);
  expect(saved.starts_at).toBeNull();
  expect(saved.ends_at).not.toBeNull();

  dialog = await openSchedule();
  await dialog.getByRole('checkbox', { name: /持续到手动停用/ }).check();
  await dialog.getByRole('button', { name: '确认并应用' }).click();
  saved = await save(3);
  expect(saved.starts_at).toBeNull();
  expect(saved.ends_at).toBeNull();

  dialog = await openSchedule();
  await dialog.getByRole('checkbox', { name: /立即开始/ }).uncheck();
  await dialog.getByRole('checkbox', { name: /持续到手动停用/ }).uncheck();
  await dialog.locator('button[aria-current="date"]').click();
  await dialog.locator('button[aria-current="date"]').click();
  await dialog.getByRole('button', { name: '确认并应用' }).click();
  saved = await save(4);
  expect(saved.starts_at).not.toBeNull();
  expect(saved.ends_at).not.toBeNull();
});

test('keeps the site banner, desktop sidebar, and sticky topbar aligned while scrolling', async ({ page }) => {
  await installMocks(page, {
    siteBanner: {
      site_banner: {
        version: 30,
        severity: 'warning',
        title: '维护提示',
        message_html: '<p>部分功能暂时不可用。</p>',
        dismissible: false,
      },
    },
  });
  await page.goto('/admin/settings/communications');
  const banner = page.getByTestId('site-wide-banner');
  const sidebar = page.locator('aside[aria-label="管理后台导航"]');
  const topbar = page.locator('header');
  await expect(banner).toBeVisible();

  const assertAligned = async () => {
    const boxes = await Promise.all([banner.boundingBox(), sidebar.boundingBox(), topbar.boundingBox()]);
    expect(boxes.every(Boolean)).toBe(true);
    const [bannerBox, sidebarBox, topbarBox] = boxes as NonNullable<(typeof boxes)[number]>[];
    const bannerBottom = bannerBox.y + bannerBox.height;
    expect(Math.abs(sidebarBox.y - bannerBottom)).toBeLessThanOrEqual(1.5);
    expect(Math.abs(topbarBox.y - bannerBottom)).toBeLessThanOrEqual(1.5);
  };

  await assertAligned();
  await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
  await assertAligned();
});

test('revision conflicts retain the site banner draft until an explicit reload', async ({ page }) => {
  await installMocks(page, { saveConflict: true });
  await page.goto('/admin/settings/communications');
  await page.getByLabel('横幅标题').fill('尚未保存的横幅');
  await page.getByRole('button', { name: '保存沟通设置' }).click();
  await expect(page.getByRole('alert')).toContainText('当前草稿已保留');
  await expect(page.getByLabel('横幅标题')).toHaveValue('尚未保存的横幅');
  await expect(page.getByRole('button', { name: '加载最新设置' })).toBeVisible();
});

test('password reauthentication retries a protected test email', async ({ page }) => {
  const state = await installMocks(page, { reauthenticateTestWith: 'password' });
  await page.goto('/admin/settings/communications');
  await page.getByRole('tab', { name: '邮件模板' }).click();
  await page.getByRole('button', { name: '发送测试邮件' }).click();
  const dialog = page.getByRole('dialog', { name: '重新验证身份' });
  await dialog.getByLabel('当前密码').fill('correct horse battery staple');
  await dialog.getByRole('button', { name: '使用密码验证' }).click();
  await expect.poll(() => state.testAttempts()).toBe(2);
  await expect(page.getByText('测试邮件已发送。')).toBeVisible();
});

test('provider reauthentication restores template drafts without persisting the test recipient', async ({ page }) => {
  const state = await installMocks(page, { reauthenticateTestWith: 'provider' });
  await page.goto('/admin/settings/communications');
  await page.getByRole('tab', { name: '邮件模板' }).click();
  await page.getByRole('textbox', { name: '邮件主题', exact: true }).fill('[{{site_name}}] Provider 恢复草稿');
  await page.getByRole('button', { name: '发送测试邮件' }).click();
  const dialog = page.getByRole('dialog', { name: '重新验证身份' });
  await dialog.getByRole('button', { name: '使用 github 验证' }).click();

  await expect(page).toHaveURL(/\/admin\/settings\/communications$/);
  await expect.poll(() => state.testAttempts()).toBe(2);
  await expect(page.getByRole('textbox', { name: '邮件主题', exact: true })).toHaveValue('[{{site_name}}] Provider 恢复草稿');
  await expect(page.getByLabel('测试收件人')).toHaveValue('admin@example.test');
  expect(await page.evaluate(() => sessionStorage.getItem('nyauth:reauth:communications-settings'))).toBeNull();
});

test('template testing is disabled when the administrator email is not verified', async ({ page }) => {
  await installMocks(page, { verifiedEmail: false });
  await page.goto('/admin/settings/communications');
  await page.getByRole('tab', { name: '邮件模板' }).click();
  await expect(page.getByLabel('测试收件人')).toBeDisabled();
  await expect(page.getByRole('button', { name: '发送测试邮件' })).toBeDisabled();
  await expect(page.getByText('当前管理员没有已验证邮箱，模板测试已禁用。')).toBeVisible();
});
