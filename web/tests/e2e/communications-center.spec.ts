import { expect, test, type Page, type Route } from '@playwright/test';
import type { Announcement, MessageCenterItem, NotificationUnreadCount, SessionInfo, UserNotification } from '../../src/lib/api';

const adminSession: SessionInfo = {
  user: {
    id: '11111111-1111-1111-1111-111111111111', username: 'admin', email: 'admin@example.test',
    display_name: 'Admin', role: 'admin', status: 'active', created_at: '2026-08-04T00:00:00Z',
  },
  csrf_token: 'communications-center-csrf', must_change_password: false, has_password: true,
  email_verified: true, authenticated_at: '2026-08-04T01:00:00Z',
  session_expires_at: '2099-08-05T01:00:00Z', recent_authentication_expires_at: '2099-08-04T01:10:00Z',
};

const announcement: Announcement = {
  id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', status: 'published', severity: 'warning', audience: 'authenticated',
  title: '账户安全更新', summary: '请检查最近登录设备', body_html: '<p>请前往<strong>安全中心</strong>检查设备。</p>',
  pinned: true, revision: 2, created_at: '2026-08-04T00:00:00Z', updated_at: '2026-08-04T01:00:00Z',
  published_at: '2026-08-04T01:00:00Z', read: false,
};

const notification: UserNotification = {
  id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', type: 'security.password_changed', severity: 'warning',
  title: '账户密码已修改', body_html: '<p>如果不是本人操作，请检查账户安全。</p>',
  link_url: '/profile/security', created_at: '2026-08-04T02:00:00Z',
};

async function json(route: Route, status: number, body: unknown) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function installBase(page: Page) {
  await page.addInitScript(() => {
    class QuietEventSource { addEventListener() {} close() {} }
    Object.defineProperty(window, 'EventSource', { configurable: true, value: QuietEventSource });
  });
}

test('user reads persistent announcements and security notifications', async ({ page }) => {
  await installBase(page);
  let announcementRead = false;
  let notificationRead = false;
  const csrfHeaders: Array<string | null> = [];

  await page.route('**/api/**', async (route) => {
    const request = route.request(); const path = new URL(request.url()).pathname; const method = request.method();
    if (path === '/api/session') return json(route, 200, adminSession);
    if (path === '/api/branding') return json(route, 200, { title: 'Nya', primary_color: '#704DE8', primary_text_color: 'auto', light_logo_url: '', dark_logo_url: '', favicon_url: '' });
    if (path === '/api/service-status') return json(route, 200, { status: 'normal', paused_capabilities: [], public_message: '', retry_after_seconds: 0 });
    if (path === '/api/site-banner') return json(route, 200, { site_banner: null });
    if (path === '/api/notifications/unread-count') {
      const value: NotificationUnreadCount = { unread_count: Number(!announcementRead) + Number(!notificationRead), notification_count: Number(!notificationRead), announcement_count: Number(!announcementRead) };
      return json(route, 200, value);
    }
    if (path === '/api/notifications' && method === 'GET') return json(route, 200, { items: [{ ...notification, read_at: notificationRead ? '2026-08-04T03:00:00Z' : undefined }], total: 1, page: 1, page_size: 20, total_pages: 1 });
    if (path === `/api/notifications/${notification.id}/read` && method === 'POST') {
      csrfHeaders.push(await request.headerValue('x-csrf-token')); notificationRead = true; return route.fulfill({ status: 204 });
    }
    if (path === '/api/announcements' && method === 'GET') return json(route, 200, { items: [{ ...announcement, read: announcementRead }], total: 1, page: 1, page_size: 20, total_pages: 1 });
    if (path === `/api/announcements/${announcement.id}` && method === 'GET') return json(route, 200, { ...announcement, read: announcementRead });
    if (path === `/api/announcements/${announcement.id}/read` && method === 'POST') {
      csrfHeaders.push(await request.headerValue('x-csrf-token')); announcementRead = true; return route.fulfill({ status: 204 });
    }
    if (path === '/api/messages' && method === 'GET') {
      const params = new URL(request.url()).searchParams;
      const kind = params.get('kind') || 'all';
      const read = params.get('read') || 'all';
      const values: MessageCenterItem[] = [
        { kind: 'notification', id: notification.id, type: notification.type, severity: notification.severity, title: notification.title, body_html: notification.body_html, link_url: notification.link_url, occurred_at: notification.created_at, read: notificationRead },
        { kind: 'announcement', id: announcement.id, severity: announcement.severity, title: announcement.title, summary: announcement.summary, occurred_at: announcement.updated_at, read: announcementRead, pinned: announcement.pinned },
      ];
      const items = values.filter((item) => (kind === 'all' || item.kind === kind) && (read === 'all' || (read === 'read') === item.read));
      return json(route, 200, { items, total: items.length, page: 1, page_size: 20, total_pages: 1 });
    }
    if (path === '/api/messages/read-all' && method === 'POST') {
      csrfHeaders.push(await request.headerValue('x-csrf-token'));
      const kind = new URL(request.url()).searchParams.get('kind') || 'all';
      if (kind === 'all' || kind === 'notification') notificationRead = true;
      if (kind === 'all' || kind === 'announcement') announcementRead = true;
      return route.fulfill({ status: 204 });
    }
    return json(route, 404, { error: `unmocked request: ${method} ${path}` });
  });

  await page.goto('/dashboard/messages');
  await expect(page.getByRole('heading', { name: '消息中心', exact: true })).toBeVisible();
  await expect(page.getByText('账户密码已修改', { exact: true })).toBeVisible();
  await expect(page.getByText('账户安全更新', { exact: true })).toBeVisible();
  await expect(page.getByLabel('消息中心，2 条未读')).toBeVisible();

  await page.getByRole('tab', { name: /站内消息 1/ }).click();
  await expect(page).toHaveURL(/tab=notifications/);
  await expect(page.getByText('账户密码已修改', { exact: true })).toBeVisible();
  await expect(page.getByText('账户安全更新', { exact: true })).toBeHidden();
  await page.getByRole('tab', { name: /全部 2/ }).click();

  await page.getByLabel('消息中心，2 条未读').click();
  const preview = page.getByRole('dialog', { name: '消息中心预览' });
  await expect(preview).toBeVisible();
  await expect(preview.getByText('账户密码已修改', { exact: true })).toBeVisible();
  await expect(preview.getByText('账户安全更新', { exact: true })).toBeVisible();
  await preview.getByRole('tab', { name: /公告 1/ }).click();
  await preview.getByRole('button', { name: '将“账户安全更新”标为已读' }).click();
  await expect(page.getByLabel('消息中心，1 条未读')).toBeVisible();
  await page.keyboard.press('Escape');

  await page.getByRole('button', { name: '当前分类全部已读' }).click();
  await expect(page.getByLabel('消息中心')).toBeVisible();

  await page.goto(`/dashboard/announcements/${announcement.id}`);
  await expect(page.getByRole('heading', { name: '账户安全更新' })).toBeVisible();
  await expect(page.getByText('请前往安全中心检查设备。')).toBeVisible();
  await expect(page.getByLabel('消息中心')).toBeVisible();
  expect(csrfHeaders).toEqual(['communications-center-csrf', 'communications-center-csrf']);
});

test('administrator creates and publishes an announcement with revision checks', async ({ page }) => {
  await installBase(page);
  let items: Announcement[] = [{ ...announcement, status: 'draft', body_markdown: '草稿正文', body_html: '<p>草稿正文</p>', read: undefined }];
  const requests: Array<{ path: string; body: unknown; csrf: string | null }> = [];

  await page.route('**/api/**', async (route) => {
    const request = route.request(); const path = new URL(request.url()).pathname; const method = request.method();
    if (path === '/api/session') return json(route, 200, adminSession);
    if (path === '/api/branding') return json(route, 200, { title: 'Nya', primary_color: '#704DE8', primary_text_color: 'auto', light_logo_url: '', dark_logo_url: '', favicon_url: '' });
    if (path === '/api/service-status') return json(route, 200, { status: 'normal', paused_capabilities: [], public_message: '', retry_after_seconds: 0 });
    if (path === '/api/site-banner') return json(route, 200, { site_banner: null });
    if (path === '/api/notifications/unread-count') return json(route, 200, { unread_count: 0, notification_count: 0, announcement_count: 0 });
    if (path === '/api/admin/settings/protection') return json(route, 200, { revision: 1, login: { enabled: true }, account: { enabled: true }, avatar: { enabled: true }, mail: { enabled: true }, owned_client_default_limit: 10 });
    if (path === '/api/admin/announcements' && method === 'GET') return json(route, 200, { items, total: items.length, page: 1, page_size: 20, total_pages: 1 });
    if (path === '/api/admin/announcements' && method === 'POST') {
      requests.push({ path, body: request.postDataJSON(), csrf: await request.headerValue('x-csrf-token') });
      const input = request.postDataJSON() as Record<string, unknown>;
      items = [{ ...announcement, ...input, id: 'cccccccc-cccc-cccc-cccc-cccccccccccc', status: 'draft', revision: 1, body_html: '<p>发布说明正文</p>' } as Announcement, ...items];
      return json(route, 201, items[0]);
    }
    if (path === `/api/admin/announcements/${announcement.id}/publish` && method === 'POST') {
      requests.push({ path, body: request.postDataJSON(), csrf: await request.headerValue('x-csrf-token') });
      items[items.length - 1] = { ...items[items.length - 1], status: 'published', revision: 3 };
      return json(route, 200, items[items.length - 1]);
    }
    return json(route, 404, { error: `unmocked request: ${method} ${path}` });
  });

  await page.goto('/admin/announcements');
  await expect(page.getByRole('heading', { name: '公告管理' })).toBeVisible();
  await page.getByRole('button', { name: '新建公告' }).click();
  await page.getByLabel('标题').fill('版本发布说明');
  await page.getByLabel('摘要').fill('本次更新的重点');
  await page.getByLabel('正文（安全 Markdown）').fill('发布说明正文');
  await page.getByRole('button', { name: '创建草稿' }).click();
  await expect(page.getByText('版本发布说明', { exact: true })).toBeVisible();
  await page.locator('article').filter({ hasText: '账户安全更新' }).getByRole('button', { name: '发布' }).click();
  await expect(page.locator('article').filter({ hasText: '账户安全更新' }).getByText('已发布')).toBeVisible();
  expect(requests).toEqual([
    { path: '/api/admin/announcements', body: expect.objectContaining({ title: '版本发布说明', body_markdown: '发布说明正文' }), csrf: 'communications-center-csrf' },
    { path: `/api/admin/announcements/${announcement.id}/publish`, body: { expected_revision: 2 }, csrf: 'communications-center-csrf' },
  ]);
});
