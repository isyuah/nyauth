import { expect, test, type Page, type Route } from '@playwright/test';

type Role = 'admin' | 'user';

interface MockState {
  authenticated: boolean;
  mustChangePassword: boolean;
  role: Role;
  csrfToken: string;
  passwordCSRF?: string | null;
  logoutCSRF?: string | null;
  bindCSRF?: string | null;
  bindBody?: unknown;
  adminRequestSeen?: boolean;
}

const user = {
  id: '11111111-1111-1111-1111-111111111111',
  username: 'alice',
  email: 'alice@example.com',
  display_name: 'Alice',
  avatar_url: null,
  status: 'active',
  role: 'user' as Role,
  created_at: '2026-01-01T00:00:00Z',
  last_login_at: '2026-01-02T00:00:00Z',
};

function sessionResponse(state: MockState) {
  return {
    user: { ...user, role: state.role },
    csrf_token: state.csrfToken,
    must_change_password: state.mustChangePassword,
  };
}

async function fulfillJSON(route: Route, status: number, body: unknown) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

async function installAPIMocks(page: Page, state: MockState) {
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;

    if (path === '/api/session') {
      if (!state.authenticated) {
        await fulfillJSON(route, 401, { error: 'authentication_required' });
        return;
      }
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }

    if (path === '/api/login' && request.method() === 'POST') {
      state.authenticated = true;
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }

    if (path === '/api/logout' && request.method() === 'POST') {
      state.logoutCSRF = await request.headerValue('x-csrf-token');
      state.authenticated = false;
      await route.fulfill({ status: 204 });
      return;
    }

    if (path === '/api/me/password' && request.method() === 'POST') {
      state.passwordCSRF = await request.headerValue('x-csrf-token');
      state.mustChangePassword = false;
      state.csrfToken = 'csrf-rotated';
      await fulfillJSON(route, 200, sessionResponse(state));
      return;
    }

    if (path === '/api/providers') {
      await fulfillJSON(route, 200, [{ name: 'github', type: 'github' }]);
      return;
    }

    if (path === '/api/me/identities') {
      await fulfillJSON(route, 200, []);
      return;
    }

    if (path === '/api/me/identities/github/bind' && request.method() === 'POST') {
      state.bindCSRF = await request.headerValue('x-csrf-token');
      state.bindBody = request.postDataJSON();
      await fulfillJSON(route, 200, { redirect_url: 'https://provider.example/authorize' });
      return;
    }

    if (path === '/api/me') {
      await fulfillJSON(route, 200, { ...user, role: state.role });
      return;
    }

    if (path === '/api/my/clients') {
      await fulfillJSON(route, 200, { items: [], total: 0 });
      return;
    }

    if (path.startsWith('/api/admin/')) {
      state.adminRequestSeen = true;
      await fulfillJSON(route, 403, { error: 'forbidden' });
      return;
    }

    await fulfillJSON(route, 404, { error: `unmocked endpoint: ${path}` });
  });
}

test('login requires first password change and sends CSRF', async ({ page }) => {
  const state: MockState = {
    authenticated: false,
    mustChangePassword: true,
    role: 'user',
    csrfToken: 'csrf-login',
  };
  await installAPIMocks(page, state);

  await page.goto('/login');
  await page.getByLabel('用户名').fill('alice');
  await page.getByLabel('密码').fill('temporary-password');
  await page.getByRole('button', { name: '登录', exact: true }).click();

  await expect(page).toHaveURL(/\/change-password\?return_to=%2Fdashboard$/);
  const passwordInputs = page.locator('input[type="password"]');
  await passwordInputs.nth(0).fill('temporary-password');
  await passwordInputs.nth(1).fill('a-new-password-123');
  await passwordInputs.nth(2).fill('a-new-password-123');
  await page.getByRole('button', { name: '确认修改' }).click();

  await expect(page).toHaveURL(/\/dashboard$/);
  expect(state.passwordCSRF).toBe('csrf-login');
});

test('ordinary users cannot enter the admin area', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);

  await page.goto('/admin');

  await expect(page).toHaveURL(/\/dashboard$/);
  expect(state.adminRequestSeen).not.toBe(true);
});

test('logout sends CSRF and returns to login', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);

  await page.goto('/dashboard');
  await page.getByTitle('退出').click();

  await expect(page).toHaveURL(/\/login$/);
  expect(state.logoutCSRF).toBe('csrf-user');
});

test('identity binding starts from the current session with CSRF', async ({ page }) => {
  const state: MockState = {
    authenticated: true,
    mustChangePassword: false,
    role: 'user',
    csrfToken: 'csrf-user',
  };
  await installAPIMocks(page, state);
  await page.route('https://provider.example/**', (route) => route.fulfill({ status: 200, body: 'provider' }));

  await page.goto('/profile');
  const bindRequest = page.waitForRequest((request) => new URL(request.url()).pathname === '/api/me/identities/github/bind');
  await page.getByRole('button', { name: /github/i }).click();
  await bindRequest;

  expect(state.bindCSRF).toBe('csrf-user');
  expect(state.bindBody).toEqual({ return_to: '/profile' });
});
